"""sing-box config renderer, validator and writer (original code).

Renders a sing-box ``config.json`` from plain dicts (the panel DB rows,
already converted to dicts by the caller) — see DESIGN.md §5.2. The
renderers are pure functions: they take plain dicts and never touch the
database, the filesystem or the network.

Domain-agnostic, with one honest limitation (DESIGN.md §5.2): TUIC,
AnyTLS, Naive, ShadowTLS and Hysteria2 all need TLS, and TLS needs a
certificate. The ``server_name`` is the configured ``domain`` when one
exists, otherwise the ``subscription_host`` / server IP from settings.
The certificate itself must be named in settings — any of
``cert_path`` / ``key_path``, ``tls_cert_path`` / ``tls_key_path``,
``certificate_path`` / ``key_path``, ``fullchain_path`` /
``privkey_path`` or ``self_signed_cert_path`` /
``self_signed_key_path`` (the installer writes a self-signed pair
there when no domain was given). **TLS inbounds without a domain use
that panel self-signed certificate, and clients must allow insecure
(or pin the fingerprint)** — there is no real TLS for a bare IP
without a CA-signed cert. If settings name no certificate at all, the
inbound is **omitted** and the reason is reported in the returned
``warnings`` list — never rendered broken. That is why this renderer,
unlike the Xray one, returns ``(config, warnings)``.

Naive usernames — the rule, defined here once so the link builder can
use the same one: ``client["username"]`` (or
``extra_json["username"]``) when the admin set one explicitly, else
the client's ``uuid`` when present, else the user's display name
(``client["name"]`` / ``extra_json["name"]``), else ``"user"``.

Hysteria2 is served by sing-box only when
``settings["hysteria2_core"] == "singbox"`` (default ``"xray"``), so
UDP/443 is never claimed by both cores at once.

Input shapes mirror :mod:`app.xray`: inbound dicts with ``tag``,
``core``, ``protocol``, ``port``, ``enabled``, ``stream_json``
(may contain ``congestion_control``, ``tls`` with ``sni`` / ``alpn``,
``method``, ``password``, ``inner_port``, ``strict_mode``) and
``remark``; client dicts with ``uuid``, ``password``, ``method``,
``flow``, ``extra_json``; settings as documented above.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

__all__ = [
    "render_singbox_config",
    "validate_singbox_config",
    "write_and_validate",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SS_METHOD = "2022-blake3-aes-128-gcm"
DEFAULT_INNER_SS_PORT = 28388

#: Settings key pairs (cert, key) tried in order. Unlike the Xray
#: renderer, there is NO invented fallback here: when none of these
#: is present the TLS inbound is omitted (see the module docstring).
_CERT_KEY_PAIRS = (
    ("cert_path", "key_path"),
    ("tls_cert_path", "tls_key_path"),
    ("certificate_path", "key_path"),
    ("fullchain_path", "privkey_path"),
    ("self_signed_cert_path", "self_signed_key_path"),
    ("cert_file", "key_file"),
)

#: Protocols this renderer knows how to build (sing-box side, Phase 1).
_SINGBOX_PROTOCOLS = ("tuic", "anytls", "naive", "shadowtls", "hysteria2")


# ---------------------------------------------------------------------------
# Small helpers (plain-dict tolerant)
# ---------------------------------------------------------------------------


def _as_bool(value: Any, default: bool = True) -> bool:
    """Coerce a DB-ish value (bool / int / "0"/"1"/"true") to bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _as_int(value: Any) -> int | None:
    """Coerce ``value`` to int, or ``None`` when it is not a valid port."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a dict-or-JSON-string value to a dict (``{}`` otherwise)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _clean_str(value: Any) -> str | None:
    """Strip a string value; ``None`` when missing/blank/non-string."""
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _first_str(*values: Any) -> str | None:
    """First non-blank string among ``values``."""
    for value in values:
        text = _clean_str(value)
        if text is not None:
            return text
    return None


# ---------------------------------------------------------------------------
# TLS resolution
# ---------------------------------------------------------------------------


def _server_name(
    stream: dict[str, Any], settings: dict[str, Any]
) -> str | None:
    """TLS ``server_name``: domain, else subscription host / server IP.

    Order: inbound ``tls.sni`` / ``sni``, settings ``domain``,
    ``subscription_host``, ``host``, ``server_ip``. ``None`` when
    nothing names the server — a TLS inbound then cannot be built.
    """
    tls = _as_dict(stream.get("tls"))
    return _first_str(
        tls.get("sni"),
        tls.get("server_name"),
        stream.get("sni"),
        settings.get("domain"),
        settings.get("subscription_host"),
        settings.get("host"),
        settings.get("server_ip"),
    )


def _cert_paths(
    stream: dict[str, Any], settings: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Resolve the (certificate, key) paths, or ``(None, None)``.

    Order: the inbound ``stream_json`` (``tls.cert_path`` /
    ``tls.key_path`` or ``tls.certificate_path`` / ``tls.key_path``),
    then any settings pair in :data:`_CERT_KEY_PAIRS`. No fallback
    is invented: a missing pair means "no certificate configured".
    """
    tls = _as_dict(stream.get("tls"))
    cert = _first_str(
        tls.get("cert_path"),
        tls.get("certificate_path"),
        tls.get("cert_file"),
        stream.get("cert_path"),
        stream.get("certificate_path"),
    )
    key = _first_str(
        tls.get("key_path"),
        tls.get("key_file"),
        stream.get("key_path"),
        stream.get("key_file"),
    )
    if cert and key:
        return cert, key
    for cert_key, key_key in _CERT_KEY_PAIRS:
        cert = _clean_str(settings.get(cert_key))
        key = _clean_str(settings.get(key_key))
        if cert and key:
            return cert, key
    return None, None


def _tls_config(
    stream: dict[str, Any],
    settings: dict[str, Any],
    *,
    default_alpn: list[str] | None = None,
) -> dict[str, Any] | None:
    """Build the sing-box ``tls`` object, or ``None`` if impossible.

    Returns ``None`` when there is no server name or no certificate
    configured; the caller then omits the inbound and records a
    warning instead of emitting a TLS inbound that cannot work.
    """
    server_name = _server_name(stream, settings)
    cert, key = _cert_paths(stream, settings)
    if not server_name or not cert or not key:
        return None
    tls = _as_dict(stream.get("tls"))
    alpn = tls.get("alpn")
    if isinstance(alpn, str):
        alpn = [alpn]
    result: dict[str, Any] = {
        "enabled": True,
        "server_name": server_name,
        "certificate_path": cert,
        "key_path": key,
    }
    if isinstance(alpn, list) and alpn:
        result["alpn"] = alpn
    elif default_alpn:
        result["alpn"] = list(default_alpn)
    return result


def _transport_class(in_type: str) -> str:
    """Transport class of a sing-box inbound type.

    ``"udp"`` for TUIC / Hysteria2, ``"both"`` for Shadowsocks
    (listens on TCP and UDP), ``"tcp"`` for the rest. Two inbounds
    may share a ``listen_port`` only when their classes do not
    overlap — so Hysteria2 on UDP 443 and a TCP inbound on 443 can
    coexist, while two TCP inbounds on one port cannot.
    """
    if in_type in ("tuic", "hysteria2"):
        return "udp"
    if in_type == "shadowsocks":
        return "both"
    return "tcp"


def _port_conflicts(
    used: dict[int, set[str]], port: int, cls: str
) -> str | None:
    """Name of the earlier class clashing with ``(port, cls)``, if any."""
    for other in used.get(port, set()):
        if cls == "both" or other == "both" or cls == other:
            return other
    return None


def _listen_address(stream: dict[str, Any]) -> str:
    """Listen address for a public inbound (``::`` by default)."""
    return _clean_str(stream.get("listen")) or "::"


# ---------------------------------------------------------------------------
# Per-protocol inbound builders
# ---------------------------------------------------------------------------


def _usable_clients(
    clients: list[dict[str, Any]], *, need: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Clients carrying every credential named in ``need``.

    ``extra_json`` may be a dict or a JSON string; it is normalised
    on a shallow copy so the caller's data is never mutated.
    """
    usable: list[dict[str, Any]] = []
    for client in clients:
        if not isinstance(client, dict):
            continue
        item = dict(client)
        item["extra_json"] = _as_dict(item.get("extra_json"))
        if all(_clean_str(item.get(key)) for key in need):
            usable.append(item)
    return usable


def _naive_username(client: dict[str, Any]) -> str:
    """Resolve a Naive username (rule defined in the module docstring).

    Explicit ``username`` first, then the client's ``uuid``, then the
    user's display name, then ``"user"``.
    """
    extra = _as_dict(client.get("extra_json"))
    return (
        _first_str(
            client.get("username"),
            extra.get("username"),
            client.get("uuid"),
            client.get("name"),
            extra.get("name"),
        )
        or "user"
    )


def _build_tuic(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """TUIC inbound (sing-box): UUID + password users, BBR, TLS+``h3``."""
    tag = inbound["tag"]
    usable = _usable_clients(clients, need=("uuid", "password"))
    if not usable:
        return [], [f"tuic '{tag}': no usable clients, omitted"]
    stream = _as_dict(inbound.get("stream_json"))
    tls = _tls_config(stream, settings, default_alpn=["h3"])
    if tls is None:
        return [], [
            f"tuic '{tag}': no TLS certificate configured, omitted "
            "(set cert_path/key_path or self_signed_cert_path/"
            "self_signed_key_path in settings)"
        ]
    congestion = _first_str(
        stream.get("congestion_control"),
        usable[0].get("extra_json", {}).get("congestion_control"),
        "bbr",
    )
    return [
        {
            "type": "tuic",
            "tag": tag,
            "listen": _listen_address(stream),
            "listen_port": inbound["port"],
            "users": [
                {"uuid": c["uuid"], "password": c["password"]}
                for c in usable
            ],
            "congestion_control": congestion,
            "tls": tls,
        }
    ], []


def _build_anytls(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """AnyTLS inbound (sing-box ≥ 1.12): password users + TLS."""
    tag = inbound["tag"]
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return [], [f"anytls '{tag}': no usable clients, omitted"]
    stream = _as_dict(inbound.get("stream_json"))
    tls = _tls_config(stream, settings)
    if tls is None:
        return [], [
            f"anytls '{tag}': no TLS certificate configured, omitted "
            "(set cert_path/key_path or self_signed_cert_path/"
            "self_signed_key_path in settings)"
        ]
    return [
        {
            "type": "anytls",
            "tag": tag,
            "listen": _listen_address(stream),
            "listen_port": inbound["port"],
            "users": [{"password": c["password"]} for c in usable],
            "tls": tls,
        }
    ], []


def _build_naive(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Naive inbound: username + password users, TLS mandatory."""
    tag = inbound["tag"]
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return [], [f"naive '{tag}': no usable clients, omitted"]
    stream = _as_dict(inbound.get("stream_json"))
    tls = _tls_config(stream, settings)
    if tls is None:
        return [], [
            f"naive '{tag}': no TLS certificate configured, omitted "
            "(set cert_path/key_path or self_signed_cert_path/"
            "self_signed_key_path in settings)"
        ]
    return [
        {
            "type": "naive",
            "tag": tag,
            "listen": _listen_address(stream),
            "listen_port": inbound["port"],
            "users": [
                {
                    "username": _naive_username(c),
                    "password": c["password"],
                }
                for c in usable
            ],
            "tls": tls,
        }
    ], []


def _build_shadowtls(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
    *,
    inner_port: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """ShadowTLS v3 (``strict_mode``) + inner Shadowsocks detour.

    ShadowTLS carries a single password (the first usable client's,
    or ``stream_json["password"]``), and detours to an inner
    Shadowsocks inbound that listens on ``127.0.0.1`` only, so the
    inner SS port is never exposed to the internet. Returns both
    inbound objects (outer first, inner second).

    ShadowTLS inbounds have NO ``tls`` field (sing-box rejects it:
    ``unknown field "tls"``) and need NO local certificate — the
    ``handshake`` object names the real TLS server the handshake
    mimics (the SNI, else the panel host, else www.microsoft.com),
    on port 443.

    ShadowTLS v3 inbounds carry ``users`` (a list of
    ``{name, password}``), NOT a top-level ``password`` — sing-box
    rejects the inbound at load with "missing users" otherwise.
    The inbound has ONE effective password (the stream password,
    else the first usable client's), so there is exactly one user;
    the inner Shadowsocks detour reuses the same password, which is
    why a ShadowTLS client's password must be a valid SS2022 key
    (see ``app.main._new_client_credentials``).
    """
    tag = inbound["tag"]
    stream = _as_dict(inbound.get("stream_json"))
    usable = _usable_clients(clients, need=("password",))
    password = _first_str(stream.get("password")) or (
        usable[0]["password"] if usable else None
    )
    if not password:
        return [], [f"shadowtls '{tag}': no password configured, omitted"]
    user_name = (
        _clean_str(usable[0].get("user_name")) if usable else ""
    ) or tag
    handshake_server = (
        _server_name(stream, settings) or "www.microsoft.com"
    )
    inner_tag = f"{tag}-inner"
    method = _first_str(
        stream.get("method"),
        usable[0].get("method") if usable else None,
        settings.get("shadowsocks_method"),
        DEFAULT_SS_METHOD,
    )
    strict_mode = stream.get("strict_mode", True)
    if not isinstance(strict_mode, bool):
        strict_mode = _as_bool(strict_mode, True)
    return [
        {
            "type": "shadowtls",
            "tag": tag,
            "listen": _listen_address(stream),
            "listen_port": inbound["port"],
            "version": 3,
            "strict_mode": strict_mode,
            "users": [{"name": user_name, "password": password}],
            "handshake": {
                "server": handshake_server,
                "server_port": 443,
            },
            "detour": inner_tag,
        },
        {
            "type": "shadowsocks",
            "tag": inner_tag,
            "listen": "127.0.0.1",
            "listen_port": inner_port,
            "method": method,
            "password": password,
        },
    ], []


def _build_hysteria2(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Hysteria2 inbound — only when sing-box owns it.

    ``settings["hysteria2_core"]`` decides the owner (default
    ``"xray"``); when it is not ``"singbox"`` this returns no
    inbound and no warning — the Xray renderer serves it instead.
    """
    tag = inbound["tag"]
    if (_clean_str(settings.get("hysteria2_core")) or "xray") != "singbox":
        return [], []
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return [], [f"hysteria2 '{tag}': no usable clients, omitted"]
    stream = _as_dict(inbound.get("stream_json"))
    tls = _tls_config(stream, settings, default_alpn=["h3"])
    if tls is None:
        return [], [
            f"hysteria2 '{tag}': no TLS certificate configured, omitted "
            "(set cert_path/key_path or self_signed_cert_path/"
            "self_signed_key_path in settings)"
        ]
    return [
        {
            "type": "hysteria2",
            "tag": tag,
            "listen": _listen_address(stream),
            "listen_port": inbound["port"],
            "users": [{"password": c["password"]} for c in usable],
            "tls": tls,
        }
    ], []


_BUILDERS = {
    "tuic": _build_tuic,
    "anytls": _build_anytls,
    "naive": _build_naive,
    "hysteria2": _build_hysteria2,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_singbox_config(
    inbounds: list[dict],
    clients_by_tag: dict[str, list[dict]],
    settings: dict,
) -> tuple[dict, list[str]]:
    """Render the sing-box config dict from inbound/client dicts.

    Returns ``(config, warnings)``. The config always has ``log`` and
    ``outbounds`` ``[{"type": "direct", "tag": "direct"}]`` plus one
    inbound object per enabled row with ``core == "singbox"`` and a
    known protocol. Rows with an invalid port, a port clash on the
    same transport (first wins — but a UDP-only inbound such as
    TUIC/Hysteria2 may share a port with a TCP-only inbound),
    an unknown protocol or no usable clients are omitted; a TLS
    inbound with no certificate (or no server name)
    configured is omitted and the reason is appended to ``warnings``.
    A ShadowTLS inbound also emits its inner Shadowsocks inbound on
    ``127.0.0.1`` (port ``stream_json["inner_port"]`` or
    ``28388`` + the number of inner inbounds already created).
    """
    settings = settings or {}
    clients_by_tag = clients_by_tag or {}
    warnings: list[str] = []
    log_level = (
        _clean_str(settings.get("log_level"))
        or _clean_str(settings.get("loglevel"))
        or "info"
    )
    cfg: dict[str, Any] = {
        "log": {"level": log_level},
        "inbounds": [],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }

    seen_ports: dict[int, set[str]] = {}
    inner_count = 0
    for inbound in inbounds or []:
        if not isinstance(inbound, dict):
            continue
        if not _as_bool(inbound.get("enabled"), True):
            continue
        if _clean_str(inbound.get("core")) != "singbox":
            continue
        protocol = _clean_str(inbound.get("protocol"))
        if protocol not in _SINGBOX_PROTOCOLS:
            continue
        tag = _clean_str(inbound.get("tag"))
        if not tag:
            continue
        port = _as_int(inbound.get("port"))
        if port is None or not 1 <= port <= 65535:
            warnings.append(
                f"singbox inbound '{tag}': invalid port "
                f"{inbound.get('port')!r}, omitted"
            )
            continue
        cls = _transport_class(protocol)
        if _port_conflicts(seen_ports, port, cls) is not None:
            warnings.append(
                f"singbox inbound '{tag}': port {port} already in use "
                "on the same transport, omitted"
            )
            continue
        seen_ports.setdefault(port, set()).add(cls)
        row = {**inbound, "tag": tag, "port": port}
        clients = clients_by_tag.get(tag, [])
        if protocol == "shadowtls":
            inner_port = DEFAULT_INNER_SS_PORT + inner_count
            built, warns = _build_shadowtls(
                row, clients, settings, inner_port=inner_port
            )
            if built:
                if (
                    _port_conflicts(seen_ports, inner_port, "both")
                    is not None
                ):
                    warns.append(
                        f"shadowtls '{tag}': inner port {inner_port} "
                        "already in use, omitted"
                    )
                    built = []
                else:
                    seen_ports.setdefault(inner_port, set()).add("both")
                    inner_count += 1
        else:
            built, warns = _BUILDERS[protocol](row, clients, settings)
        warnings.extend(warns)
        cfg["inbounds"].extend(built)
    return cfg, warnings


def validate_singbox_config(cfg: dict) -> tuple[bool, list[str]]:
    """Structural validation of a sing-box config dict.

    Checks: the config is an object with ``inbounds`` and ``outbounds``
    lists (with a ``direct`` outbound); every inbound has a
    non-empty ``type`` / ``tag`` and a ``listen_port`` in 1–65535
    (port 0 is never valid); ``listen_port`` values are unique *per
    transport* (a UDP-only inbound such as TUIC/Hysteria2 may share
    a port with a TCP-only inbound; two TCP inbounds on one port, or
    anything sharing with a Shadowsocks inbound, which binds both,
    is an error);
    users carry the credentials their type needs (``uuid`` +
    ``password`` for TUIC, ``password`` for Hysteria2/AnyTLS,
    ``username`` + ``password`` for Naive); ShadowTLS has a password
    and a ``detour`` pointing at an existing inbound tag; a TLS
    object that is enabled names a ``server_name`` and both
    certificate paths. Returns ``(is_valid, errors)``; structural
    only — it does not run the sing-box binary.
    """
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return False, ["config must be a JSON object"]
    inbounds = cfg.get("inbounds")
    if not isinstance(inbounds, list):
        return False, ["config is missing an 'inbounds' list"]
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list):
        errors.append("config is missing an 'outbounds' list")
    elif not any(
        isinstance(o, dict) and o.get("type") == "direct" for o in outbounds
    ):
        errors.append("config 'outbounds' has no direct outbound")

    tags: set[str] = set()
    seen_ports: dict[int, set[str]] = {}
    seen_tags: dict[int, list[str]] = {}
    for index, inbound in enumerate(inbounds):
        label = f"inbounds[{index}]"
        if not isinstance(inbound, dict):
            errors.append(f"{label} must be an object")
            continue
        tag = inbound.get("tag")
        if not isinstance(tag, str) or not tag.strip():
            errors.append(f"{label} is missing a non-empty 'tag'")
            tag = label
        else:
            tags.add(tag)
        port = inbound.get("listen_port")
        in_type_early = inbound.get("type")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            errors.append(
                f"inbound '{tag}': listen_port must be an integer in "
                f"1-65535 (got {port!r})"
            )
        elif isinstance(in_type_early, str) and in_type_early.strip():
            cls = _transport_class(in_type_early)
            if _port_conflicts(seen_ports, port, cls) is not None:
                errors.append(
                    f"inbound '{tag}': listen_port {port} is already "
                    f"used by '{seen_tags[port][0]}' on the same "
                    "transport"
                )
            else:
                seen_ports.setdefault(port, set()).add(cls)
                seen_tags.setdefault(port, []).append(str(tag))
        in_type = inbound.get("type")
        if not isinstance(in_type, str) or not in_type.strip():
            errors.append(f"inbound '{tag}': missing 'type'")
            continue
        users = inbound.get("users")
        if in_type == "tuic":
            _check_users(users, tag, errors, need=("uuid", "password"))
        elif in_type in ("hysteria2", "anytls"):
            _check_users(users, tag, errors, need=("password",))
        elif in_type == "naive":
            _check_users(users, tag, errors, need=("username", "password"))
        elif in_type == "shadowtls":
            # v3 uses `users` (a top-level `password` is rejected by
            # sing-box with "missing users"); accept the legacy
            # `password` form too so hand-written configs still
            # validate.
            users = inbound.get("users")
            has_user_password = (
                isinstance(users, list)
                and users
                and isinstance(users[0], dict)
                and bool(users[0].get("password"))
            )
            if not has_user_password and not inbound.get("password"):
                errors.append(
                    f"inbound '{tag}': shadowtls needs 'users' with a "
                    "'password'"
                )
            detour = inbound.get("detour")
            if not isinstance(detour, str) or not detour:
                errors.append(
                    f"inbound '{tag}': shadowtls needs a 'detour' tag"
                )
            elif detour == tag:
                errors.append(
                    f"inbound '{tag}': shadowtls detour points to itself"
                )
            version = inbound.get("version")
            if version is not None and version != 3:
                errors.append(
                    f"inbound '{tag}': shadowtls version must be 3 "
                    f"(got {version!r})"
                )
        elif in_type == "shadowsocks":
            if not inbound.get("method"):
                errors.append(
                    f"inbound '{tag}': shadowsocks needs a 'method'"
                )
            if not inbound.get("password"):
                errors.append(
                    f"inbound '{tag}': shadowsocks needs a 'password'"
                )
        tls = inbound.get("tls")
        if isinstance(tls, dict) and tls.get("enabled"):
            if not tls.get("server_name"):
                errors.append(
                    f"inbound '{tag}': tls needs a 'server_name'"
                )
            if not tls.get("certificate_path"):
                errors.append(
                    f"inbound '{tag}': tls needs a 'certificate_path'"
                )
            if not tls.get("key_path"):
                errors.append(f"inbound '{tag}': tls needs a 'key_path'")
    for index, inbound in enumerate(inbounds):
        if isinstance(inbound, dict) and inbound.get("type") == "shadowtls":
            detour = inbound.get("detour")
            if (
                isinstance(detour, str)
                and detour
                and detour not in tags
            ):
                errors.append(
                    f"inbound '{inbound.get('tag')}': shadowtls detour "
                    f"'{detour}' does not match any inbound tag"
                )
    return (not errors), errors


def _check_users(
    users: Any,
    tag: str,
    errors: list[str],
    *,
    need: tuple[str, ...],
) -> None:
    """Append errors for a sing-box inbound's ``users`` list."""
    if not isinstance(users, list) or not users:
        errors.append(f"inbound '{tag}': missing a non-empty 'users' list")
        return
    for index, user in enumerate(users):
        if not isinstance(user, dict):
            errors.append(
                f"inbound '{tag}': user #{index} must be an object"
            )
            continue
        for key in need:
            if not user.get(key):
                errors.append(
                    f"inbound '{tag}': user #{index} is missing "
                    f"'{key}'"
                )


def write_and_validate(
    cfg: dict, path: str | Path, binary: str = "/usr/local/bin/sing-box"
) -> tuple[bool, list[str]]:
    """Write ``cfg`` to ``path`` after validation, atomically.

    Writes ``path + ".tmp.json"``, runs ``sing-box check -c <tmp>`` when
    the binary exists (10 s timeout), and atomically renames the temp
    file into place only on success — a rejected config never
    replaces the live one. When the binary is absent only the JSON
    structure is validated and the file is still written, returning
    ``(True, ["binary not present — JSON validated only"])``. Never
    raises for a missing binary, a failed validation or a bad path:
    those come back as ``(False, errors)``.
    """
    target = Path(path)
    tmp = Path(str(target) + ".tmp.json")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError) as exc:
        return False, [f"cannot write temp config {tmp}: {exc}"]

    ok, errors = validate_singbox_config(cfg)
    if not ok:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, errors

    binary_path = binary
    if not (os.path.isfile(binary_path) and os.access(binary_path, os.X_OK)):
        resolved = shutil.which(binary)
        binary_path = resolved or ""
    if not binary_path:
        try:
            os.replace(tmp, target)
        except OSError as exc:
            return False, [f"cannot move temp config into place: {exc}"]
        return True, ["binary not present — JSON validated only"]

    try:
        proc = subprocess.run(
            [binary_path, "check", "-c", str(tmp)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, ["sing-box validation timed out after 10s"]
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, [f"could not run sing-box binary: {exc}"]

    if proc.returncode == 0:
        try:
            os.replace(tmp, target)
        except OSError as exc:
            return False, [f"cannot move temp config into place: {exc}"]
        return True, []

    detail = (proc.stderr or proc.stdout or "").strip()
    lines = detail.splitlines()[-10:] if detail else []
    try:
        tmp.unlink(missing_ok=True)
    except OSError:
        pass
    message = f"sing-box check failed (exit {proc.returncode})"
    if lines:
        message += ": " + " | ".join(line.strip() for line in lines if line.strip())
    return False, [message]
