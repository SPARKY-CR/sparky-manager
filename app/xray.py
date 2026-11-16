"""Xray-core config renderer, validator and writer (original code).

Renders a full Xray ``config.json`` from plain dicts (the panel DB rows,
already converted to dicts by the caller) — see DESIGN.md §5.1. The
renderers are pure functions: they take plain dicts and never touch the
database, the filesystem or the network, so they are easy to unit-test.

Domain-agnostic: nothing here requires a domain. VLESS+Reality works
with a bare server IP; TLS inbounds (WS/TLS, Trojan, Hysteria2) use the
certificate paths from the inbound ``stream_json`` or from ``settings``
and fall back to the panel's conventional cert location
``<home>/certs/fullchain.pem`` + ``<home>/certs/privkey.pem`` (where the
installer puts the Let's Encrypt pair, or a self-signed pair when no
domain was given).

Input shapes (see DESIGN.md §4/§5):

- inbound dict: ``tag``, ``core``, ``protocol``, ``port``, ``enabled``,
  ``stream_json`` (dict, may contain ``network`` / ``security`` /
  ``reality`` / ``tls`` / ``path`` / ``host`` / ``service_name`` /
  ``mode`` / ``sniffing`` / ``sniffing_dest_override`` /
  ``fallbacks``), ``remark``.
- client dict: ``uuid``, ``password``, ``method``, ``flow``,
  ``extra_json`` (dict), ``user_id`` (int — rendered as the client's
  ``email`` so the Stats API can attribute traffic per user; see
  :func:`client_email`).
- settings dict: ``domain``, ``subscription_host``, ``hysteria2_core``
  (``"xray"`` by default), ``reality_sni``, ``reality_private_key``,
  ``cert_path`` / ``key_path`` (or ``tls_cert_path`` / ``tls_key_path``,
  ``self_signed_cert_path`` / ``self_signed_key_path``), ``home``,
  ``log_level``.

Only inbounds with ``core == "xray"`` and ``enabled`` are rendered.
Clients missing the credential their protocol needs are skipped (the
caller is expected to filter out disabled/expired/over-quota users
first; skipping here is a second line of defence, never a crash).
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

__all__ = [
    "API_LISTEN",
    "API_PORT",
    "client_email",
    "generate_reality_keypair",
    "parse_user_email",
    "reality_public_key",
    "render_xray_config",
    "validate_xray_config",
    "write_and_validate",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_PORT = 10085
API_LISTEN = "127.0.0.1"
DEFAULT_HOME = "/opt/sparky-manager"
DEFAULT_REALITY_SNI = "www.microsoft.com"
DEFAULT_SS_METHOD = "2022-blake3-aes-128-gcm"

#: Settings key pairs (cert, key) tried in order when resolving TLS
#: certificate paths. The first pair with both values present wins.
_CERT_KEY_PAIRS = (
    ("cert_path", "key_path"),
    ("tls_cert_path", "tls_key_path"),
    ("certificate_path", "key_path"),
    ("fullchain_path", "privkey_path"),
    ("self_signed_cert_path", "self_signed_key_path"),
    ("cert_file", "key_file"),
)

#: Protocols this renderer knows how to build (Xray side, Phase 1).
_XRAY_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks", "hysteria2")

#: Email domain for per-user Xray stats. Every rendered client gets
#: ``user-<user_id>@sparky.local`` as its ``email`` so the Stats API
#: reports per-user traffic under
#: ``user>>>user-<id>@sparky.local>>>traffic>>>(uplink|downlink)``.
#: :mod:`app.xray_stats` parses the same format back to a user id —
#: the format lives here, in exactly one place. The domain is
#: synthetic (never resolved); Xray treats ``email`` as an opaque
#: label. A client dict without a usable ``user_id`` gets no email
#: and therefore no per-user stats (see :func:`client_email`).
STATS_EMAIL_DOMAIN = "sparky.local"

_USER_EMAIL_RE = re.compile(r"^user-(\d+)@sparky\.local$")


def client_email(user_id: Any) -> str | None:
    """The Xray ``email`` for a panel user id, or ``None``.

    ``None`` for a missing / non-integer / non-positive id — the
    builders then omit ``email`` (the client still works, it just
    has no per-user stats). Never raises.
    """
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None
    if uid <= 0:
        return None
    return f"user-{uid}@{STATS_EMAIL_DOMAIN}"


def parse_user_email(email: Any) -> int | None:
    """The panel user id encoded in a stats ``email``, or ``None``.

    The inverse of :func:`client_email` — used by
    :mod:`app.xray_stats` to attribute a stat name to a user.
    Foreign emails (anything not in our format) return ``None`` and
    are never attributed. Never raises.
    """
    if not isinstance(email, str):
        return None
    match = _USER_EMAIL_RE.match(email.strip())
    if not match:
        return None
    return int(match.group(1))


def _with_email(entry: dict[str, Any], client: dict[str, Any]) -> dict[str, Any]:
    """Attach the stats ``email`` to a rendered client entry, in place.

    A no-op when the client dict carries no usable ``user_id``.
    """
    email = client_email(client.get("user_id"))
    if email is not None:
        entry["email"] = email
    return entry


def generate_reality_keypair() -> dict[str, str]:
    """Fresh Reality X25519 keypair, same format ``xray x25519`` emits.

    Keys are base64url WITHOUT padding (43 chars) of 32 bytes. The
    public key is derived from the private key with the pure-Python
    X25519 in :mod:`app.wireguard` (verified to match ``xray x25519``
    output for the same private key) — no xray binary is called, so
    this works wherever the panel runs, including the test suite.
    Used by ``ensure_defaults`` (via the ``xray_mod`` hook) and by the
    inbound form, so every VLESS+Reality inbound gets its own keys
    instead of sharing the installer's pair.
    """
    from app import wireguard as _wg

    private_raw = secrets.token_bytes(32)
    public_raw = _wg._x25519(private_raw, _wg._BASE_POINT)
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")  # noqa: E731
    return {"private_key": encode(private_raw), "public_key": encode(public_raw)}


def reality_public_key(private_key: str) -> str | None:
    """Derive the Reality public key from a base64url private key.

    The inbound editor needs this when the admin pastes a private
    key by hand: the public key in the share links must match it,
    or clients cannot connect. Returns ``None`` when the key is
    not 43-char base64url of 32 bytes.
    """
    from app import wireguard as _wg

    text = (private_key or "").strip()
    if not text:
        return None
    padded = text + "=" * (-len(text) % 4)
    try:
        private_raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:  # noqa: BLE001
        return None
    if len(private_raw) != 32:
        return None
    public_raw = _wg._x25519(private_raw, _wg._BASE_POINT)
    return base64.urlsafe_b64encode(public_raw).rstrip(b"=").decode("ascii")


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
# TLS / Reality resolution
# ---------------------------------------------------------------------------


def _cert_paths(
    stream: dict[str, Any], settings: dict[str, Any]
) -> tuple[str, str]:
    """Resolve the (certificate, key) file paths for a TLS inbound.

    Order: the inbound ``stream_json`` (``tls.cert_path`` / ``tls.key_path``
    or ``tls.certificateFile`` / ``tls.keyFile``), then any of the
    settings key pairs in :data:`_CERT_KEY_PAIRS`, then the panel's
    conventional location ``<home>/certs/fullchain.pem`` +
    ``<home>/certs/privkey.pem`` (the installer writes the Let's Encrypt
    pair — or a self-signed pair when no domain was given — there).
    The fallback is always returned so a configured TLS inbound is
    never silently rendered without certificates.
    """
    tls = _as_dict(stream.get("tls"))
    cert = _first_str(
        tls.get("cert_path"),
        tls.get("certificateFile"),
        tls.get("cert_file"),
        stream.get("cert_path"),
        stream.get("certificateFile"),
    )
    key = _first_str(
        tls.get("key_path"),
        tls.get("keyFile"),
        tls.get("key_file"),
        stream.get("key_path"),
        stream.get("keyFile"),
    )
    if cert and key:
        return cert, key
    for cert_key, key_key in _CERT_KEY_PAIRS:
        cert = _clean_str(settings.get(cert_key))
        key = _clean_str(settings.get(key_key))
        if cert and key:
            return cert, key
    home = _clean_str(settings.get("home")) or DEFAULT_HOME
    return (
        os.path.join(home, "certs", "fullchain.pem"),
        os.path.join(home, "certs", "privkey.pem"),
    )


def _reality_settings(
    stream: dict[str, Any], settings: dict[str, Any]
) -> dict[str, Any]:
    """Build the ``realitySettings`` object for a VLESS+Reality inbound."""
    reality = _as_dict(stream.get("reality"))
    sni = _first_str(
        reality.get("sni"),
        reality.get("serverName"),
        stream.get("sni"),
        settings.get("reality_sni"),
        settings.get("domain"),
        DEFAULT_REALITY_SNI,
    )
    dest = _first_str(reality.get("dest"), f"{sni}:443")
    server_names = reality.get("serverNames") or reality.get("server_names")
    if isinstance(server_names, str):
        server_names = [server_names]
    if not isinstance(server_names, list) or not server_names:
        server_names = [sni] if sni else []
    short_ids = reality.get("shortIds") or reality.get("short_ids")
    if isinstance(short_ids, str):
        short_ids = [short_ids]
    if not isinstance(short_ids, list):
        short_ids = []
    short_id = _clean_str(
        _first_str(
            reality.get("short_id"),
            settings.get("reality_short_id"),
            settings.get("reality_shortId"),
        )
    )
    if short_id and short_id not in short_ids:
        short_ids = [*short_ids, short_id]
    private_key = _first_str(
        reality.get("private_key"),
        reality.get("privateKey"),
        settings.get("reality_private_key"),
        settings.get("reality_privateKey"),
    )
    result: dict[str, Any] = dict(_as_dict(stream.get("realitySettings")))
    result["show"] = False
    result["dest"] = dest
    result["xver"] = 0
    result["serverNames"] = server_names
    result["privateKey"] = private_key or ""
    result["shortIds"] = short_ids
    return result


def _tls_settings(
    stream: dict[str, Any],
    settings: dict[str, Any],
    *,
    sni: str | None = None,
    default_alpn: list[str] | None = None,
) -> dict[str, Any]:
    """Build the ``tlsSettings`` object for a TLS inbound."""
    tls = _as_dict(stream.get("tls"))
    cert, key = _cert_paths(stream, settings)
    alpn = tls.get("alpn")
    if isinstance(alpn, str):
        alpn = [alpn]
    if not isinstance(alpn, list) or not alpn:
        alpn = list(default_alpn) if default_alpn else ["h2", "http/1.1"]
    result: dict[str, Any] = dict(_as_dict(stream.get("tlsSettings")))
    result["alpn"] = alpn
    result["certificates"] = [
        {"certificateFile": cert, "keyFile": key},
    ]
    if sni:
        result.setdefault("serverName", sni)
    return result


def _stream_settings(
    inbound: dict[str, Any],
    settings: dict[str, Any],
    *,
    default_network: str = "tcp",
    default_security: str = "none",
) -> dict[str, Any]:
    """Build ``streamSettings`` from an inbound's ``stream_json``.

    ``stream_json`` keys honoured: ``network`` (``tcp``/``ws``/``xhttp``/
    ``grpc``/``httpupgrade``), ``security`` (``reality``/``tls``/
    ``none``), ``reality`` (dict, see :func:`_reality_settings`),
    ``tls`` (dict with ``sni`` / ``alpn`` / cert paths), ``path``
    (WS/XHTTP/HTTPUpgrade path), ``host`` (WS/HTTPUpgrade Host
    header), ``service_name`` (gRPC service name), ``mode`` (XHTTP
    mode). A missing ``path`` for WebSocket defaults to ``/<tag>``.
    """
    stream = _as_dict(inbound.get("stream_json"))
    tag = _clean_str(inbound.get("tag")) or ""
    network = _clean_str(stream.get("network")) or default_network
    security = _clean_str(stream.get("security")) or default_security
    if security == "":
        security = "none"

    result: dict[str, Any] = {"network": network, "security": security}

    if security == "reality":
        result["realitySettings"] = _reality_settings(stream, settings)
    elif security == "tls":
        sni = _first_str(
            _as_dict(stream.get("tls")).get("sni"),
            stream.get("sni"),
            settings.get("domain"),
            settings.get("subscription_host"),
        )
        result["tlsSettings"] = _tls_settings(
            stream, settings, sni=sni, default_alpn=["h2", "http/1.1"]
        )

    if network == "ws":
        path = _clean_str(stream.get("path")) or f"/{tag}"
        ws_settings: dict[str, Any] = dict(_as_dict(stream.get("wsSettings")))
        ws_settings.setdefault("path", path)
        host = _clean_str(stream.get("host"))
        if host:
            headers = dict(ws_settings.get("headers") or {})
            headers.setdefault("Host", host)
            ws_settings["headers"] = headers
        result["wsSettings"] = ws_settings
    elif network == "xhttp":
        xhttp_settings: dict[str, Any] = dict(
            _as_dict(stream.get("xhttpSettings"))
        )
        path = _clean_str(stream.get("path"))
        if path:
            xhttp_settings.setdefault("path", path)
        mode = _clean_str(stream.get("mode"))
        if mode:
            xhttp_settings.setdefault("mode", mode)
        if xhttp_settings:
            result["xhttpSettings"] = xhttp_settings
    elif network == "grpc":
        service_name = _first_str(
            stream.get("service_name"), stream.get("serviceName"), tag
        )
        grpc_settings: dict[str, Any] = dict(
            _as_dict(stream.get("grpcSettings"))
        )
        grpc_settings.setdefault("serviceName", service_name)
        result["grpcSettings"] = grpc_settings
    elif network == "httpupgrade":
        # HTTPUpgrade: an HTTP upgrade handshake, then the raw
        # protocol — Xray's `httpupgradeSettings` takes the same
        # `path` / `host` pair as WebSocket (no `headers` wrapper).
        upgrade_settings: dict[str, Any] = dict(
            _as_dict(stream.get("httpupgradeSettings"))
        )
        path = _clean_str(stream.get("path")) or f"/{tag}"
        upgrade_settings.setdefault("path", path)
        host = _clean_str(stream.get("host"))
        if host:
            upgrade_settings.setdefault("host", host)
        result["httpupgradeSettings"] = upgrade_settings

    # Fallbacks live in streamSettings (Xray ignores them anywhere
    # else) and only apply to raw TCP: the fallback decision is made
    # on the first bytes of the TCP stream, before any HTTP upgrade
    # — with WS/gRPC/XHTTP the handshake has already happened, so a
    # fallback could never trigger. Reality is TCP, so it keeps its
    # fallbacks (the classic "serve a real site on 443" setup).
    if network == "tcp":
        fallbacks = _fallback_list(stream)
        if fallbacks is not None:
            result["fallbacks"] = fallbacks

    return result


def _sniffing_settings(stream: dict[str, Any]) -> dict[str, Any] | None:
    """Build the inbound-level ``sniffing`` object, or ``None``.

    ``stream_json["sniffing"]`` (bool) enables it; the destination
    overrides default to ``["http", "tls", "quic"]`` and may be
    narrowed with ``stream_json["sniffing_dest_override"]`` (a list
    or a comma-separated string). Only the TCP-based builders
    (VLESS / VMess / Trojan) attach it — sniffing is meaningless
    for Shadowsocks / Hysteria2 inbounds, which have no
    ``streamSettings`` to sniff through.
    """
    if not _as_bool(stream.get("sniffing"), False):
        return None
    override = stream.get("sniffing_dest_override")
    if isinstance(override, str):
        override = [item.strip() for item in override.split(",") if item.strip()]
    if not isinstance(override, list) or not override:
        override = ["http", "tls", "quic"]
    return {"enabled": True, "destOverride": [str(item) for item in override]}


def _fallback_list(stream: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Build the streamSettings-level ``fallbacks`` list, or ``None``.

    ``stream_json["fallbacks"]`` is a list of ``{"dest": ..., "xver":
    0|1}`` (``dest`` is ``"host:port"`` or a bare port number) — the
    panel's edit form writes it from one ``host:port[,xver]`` line
    per fallback. Fallbacks let one port serve several protocols
    (e.g. VLESS + Trojan on 443): Xray tries the inbound's own
    protocol first and forwards the rest to the fallback dests.
    Entries without a ``dest`` are dropped; ``xver`` defaults to 0
    (the PROXY protocol header is only sent when the fallback
    target expects it).
    """
    raw = stream.get("fallbacks")
    if not isinstance(raw, list) or not raw:
        return None
    fallbacks: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        dest = entry.get("dest")
        if isinstance(dest, str):
            dest = dest.strip()
            if not dest:
                continue
        elif isinstance(dest, int) and not isinstance(dest, bool):
            if not 1 <= dest <= 65535:
                continue
        else:
            continue
        xver = entry.get("xver", 0)
        try:
            xver = int(xver)
        except (TypeError, ValueError):
            xver = 0
        fallbacks.append({"dest": dest, "xver": 1 if xver else 0})
    return fallbacks or None


def _transport_class(protocol: str) -> str:
    """Transport class of an Xray inbound protocol.

    ``"tcp"`` for VLESS / VMess / Trojan (all their transports ride
    TCP), ``"udp"`` for Hysteria2, ``"both"`` for Shadowsocks (its
    ``network`` is ``tcp,udp``). Two inbounds may share a port number
    only when their classes do not overlap — which is exactly how
    the recommended default pair works: VLESS+Reality on TCP 443
    and Hysteria2 on UDP 443.
    """
    if protocol in ("hysteria2", "hysteria"):
        return "udp"
    if protocol == "shadowsocks":
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


# ---------------------------------------------------------------------------
# Per-protocol inbound builders
# ---------------------------------------------------------------------------


def _usable_clients(
    clients: list[dict[str, Any]], *, need: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Clients that carry every credential named in ``need``.

    ``need`` names client-dict keys (``"uuid"`` / ``"password"``).
    ``extra_json`` may be a dict or a JSON string; it is normalised in
    place on a shallow copy so the caller's data is never mutated.
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


def _build_vless(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """VLESS inbound: Reality, WS+TLS, XHTTP or plain TCP."""
    usable = _usable_clients(clients, need=("uuid",))
    if not usable:
        return None
    stream = _as_dict(inbound.get("stream_json"))
    is_reality = _clean_str(stream.get("security")) == "reality"
    entries = []
    for client in usable:
        entry: dict[str, Any] = {"id": client["uuid"]}
        flow = _clean_str(client.get("flow"))
        if not flow and is_reality:
            flow = "xtls-rprx-vision"
        if flow:
            entry["flow"] = flow
        entries.append(_with_email(entry, client))
    built: dict[str, Any] = {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "vless",
        "settings": {"clients": entries, "decryption": "none"},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="none"
        ),
    }
    sniffing = _sniffing_settings(stream)
    if sniffing is not None:
        built["sniffing"] = sniffing
    # Fallbacks ride inside streamSettings (see _stream_settings).
    return built


def _build_vmess(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """VMess inbound: ``alterId`` 0, client security ``auto``."""
    usable = _usable_clients(clients, need=("uuid",))
    if not usable:
        return None
    entries = [
        _with_email({"id": client["uuid"], "alterId": 0, "security": "auto"}, client)
        for client in usable
    ]
    stream = _as_dict(inbound.get("stream_json"))
    built: dict[str, Any] = {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "vmess",
        "settings": {"clients": entries},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="none"
        ),
    }
    sniffing = _sniffing_settings(stream)
    if sniffing is not None:
        built["sniffing"] = sniffing
    # Fallbacks ride inside streamSettings (see _stream_settings).
    return built


def _build_trojan(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """Trojan inbound: password clients, TLS by default."""
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return None
    entries = [
        _with_email({"password": client["password"]}, client)
        for client in usable
    ]
    stream = _as_dict(inbound.get("stream_json"))
    built: dict[str, Any] = {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "trojan",
        "settings": {"clients": entries},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="tls"
        ),
    }
    sniffing = _sniffing_settings(stream)
    if sniffing is not None:
        built["sniffing"] = sniffing
    # Fallbacks ride inside streamSettings (see _stream_settings).
    return built


def _build_shadowsocks(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """Shadowsocks 2022 inbound (``network`` fixed to ``tcp,udp``).

    Single-client form follows DESIGN.md §5.1
    (``settings: {method, password, network}``); with several clients
    a ``clients`` list is added so each password stays usable.

    The method lives ONLY in ``settings``: Xray 26.11.9 rejects a
    2022 multi-user inbound whose users carry a method
    ("shadowsocks 2022 (multi-user): users must have empty method")
    and the whole config then fails ``xray -test`` — seen on the
    live server 2026-11-14, where a 2-user SS inbound blocked every
    re-render (exit 23). Users here carry just their password.
    """
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return None
    stream = _as_dict(inbound.get("stream_json"))
    method = _first_str(
        usable[0].get("method"),
        stream.get("method"),
        settings.get("shadowsocks_method"),
        DEFAULT_SS_METHOD,
    )
    inbound_settings: dict[str, Any] = {
        "method": method,
        "password": usable[0]["password"],
        "network": "tcp,udp",
    }
    if len(usable) > 1:
        inbound_settings["clients"] = [
            _with_email({"password": client["password"]}, client)
            for client in usable
        ]
    # Single-client form has no ``clients`` list, so its one user
    # gets no per-user stats (the Stats API keys on client email).
    # The whole inbound IS that user, so nothing is misattributed —
    # the traffic is simply uncollected (DESIGN.md §6.4).
    return {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "shadowsocks",
        "settings": inbound_settings,
    }


def _build_hysteria2(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """Hysteria2 inbound — only when Xray owns it.

    ``settings["hysteria2_core"]`` decides the owner (default
    ``"xray"``); when it is ``"singbox"`` this returns ``None`` and
    the sing-box renderer serves Hysteria2 instead, so UDP/443 is
    never claimed by both cores at once. TLS uses the cert paths
    from the inbound / settings, falling back to the panel's
    self-signed pair (see :func:`_cert_paths`).

    Verified against real Xray 26.11.9 (coordinator, 2026-11-11):
    the native inbound is protocol ``"hysteria"`` (not
    ``"hysteria2``), with ``settings.version == 2`` and
    ``streamSettings.network == "hysteria"``. The shapes
    ``protocol="hysteria2"`` and ``network="udp"`` are both
    rejected by this Xray (``unknown config id: hysteria2`` /
    ``unknown transport protocol: udp``), and ``network="quic"``
    is rejected as removed. The client-facing scheme stays
    ``hysteria2://`` — only the server-side Xray shape differs.
    """
    if (_clean_str(settings.get("hysteria2_core")) or "xray") != "xray":
        return None
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return None
    stream = _as_dict(inbound.get("stream_json"))
    inbound_settings: dict[str, Any] = {
        "version": 2,
        "clients": [
            _with_email({"password": client["password"]}, client)
            for client in usable
        ],
    }
    for key in ("upMbps", "downMbps"):
        value = _as_int(stream.get(key)) or _as_int(
            stream.get(key.lower().replace("mbps", "_mbps"))
        )
        if value is not None:
            inbound_settings[key] = value
    return {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "hysteria",
        "settings": inbound_settings,
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": _tls_settings(
                stream, settings, default_alpn=["h3"]
            ),
        },
    }


_BUILDERS = {
    "vless": _build_vless,
    "vmess": _build_vmess,
    "trojan": _build_trojan,
    "shadowsocks": _build_shadowsocks,
    "hysteria2": _build_hysteria2,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_xray_config(
    inbounds: list[dict],
    clients_by_tag: dict[str, list[dict]],
    settings: dict,
) -> dict:
    """Render the full Xray config dict from inbound/client dicts.

    Always present: ``log``, the ``api`` inbound on ``127.0.0.1:10085``
    (loopback-only stats API), ``stats: {}``, per-user stats policy,
    a ``routing`` rule sending the ``api`` inbound to the ``api``
    handler (without it the Stats API is unreachable — the
    dokodemo-door traffic would fall through to ``freedom``),
    ``routing`` blocking private IPs to ``blackhole``, and
    ``outbounds`` ``[freedom, blackhole]``. Every rendered client
    carries an ``email`` (``user-<id>@sparky.local``) when its dict
    has a ``user_id``, so the Stats API attributes traffic per user.
    One inbound object per
    enabled row with ``core == "xray"`` and a known protocol; rows
    with an invalid port, a port clash on the same transport
    (first wins — but a UDP-only inbound such as Hysteria2 may share
    a port with a TCP-only inbound, so VLESS+Reality TCP 443 +
    Hysteria2 UDP 443 both render), an unknown protocol, no usable
    clients, or (for Hysteria2) the wrong core owner are omitted
    rather than rendered broken.
    """
    settings = settings or {}
    clients_by_tag = clients_by_tag or {}
    log_level = (
        _clean_str(settings.get("log_level"))
        or _clean_str(settings.get("loglevel"))
        or "warning"
    )
    cfg: dict[str, Any] = {
        "log": {"loglevel": log_level},
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                # statsUserOnline (Phase C item 20) feeds the
                # GetUsersStats RPC the IP-limit job reads: a user
                # counts as online from an IP while it has had
                # connection activity within the last 20 s. Harmless
                # on Xray versions that predate the RPC (unknown
                # policy keys are ignored) — and the client probes
                # the RPC lazily anyway.
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                    "statsUserOnline": True,
                },
            },
        },
        "routing": {
            "rules": [
                # The API rule MUST come first: Xray routes on first
                # match, and API traffic targets 127.0.0.1 (a
                # private IP), so the geoip rule below would
                # blackhole it. Without this rule the dokodemo-door
                # ``api`` inbound falls through to ``freedom`` and
                # the Stats API is unreachable.
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api",
                },
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "blackhole",
                },
            ],
        },
        "inbounds": [
            {
                "tag": "api",
                "port": API_PORT,
                "listen": API_LISTEN,
                "protocol": "dokodemo-door",
                "settings": {"address": API_LISTEN},
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blackhole"},
        ],
    }

    seen_ports = {API_PORT: {"tcp"}}
    for inbound in inbounds or []:
        if not isinstance(inbound, dict):
            continue
        if not _as_bool(inbound.get("enabled"), True):
            continue
        if _clean_str(inbound.get("core")) != "xray":
            continue
        protocol = _clean_str(inbound.get("protocol"))
        if protocol not in _BUILDERS:
            continue
        tag = _clean_str(inbound.get("tag"))
        if not tag:
            continue
        port = _as_int(inbound.get("port"))
        if port is None or not 1 <= port <= 65535:
            continue
        cls = _transport_class(protocol)
        if _port_conflicts(seen_ports, port, cls) is not None:
            continue  # same port + overlapping transport: first wins
        seen_ports.setdefault(port, set()).add(cls)
        built = _BUILDERS[protocol](
            {**inbound, "tag": tag, "port": port},
            clients_by_tag.get(tag, []),
            settings,
        )
        if built is not None:
            cfg["inbounds"].append(built)
    return cfg


def validate_xray_config(cfg: dict) -> tuple[bool, list[str]]:
    """Structural validation of an Xray config dict.

    Checks: the config is an object with an ``inbounds`` list; every
    inbound has a non-empty ``tag`` / ``protocol`` and a port in
    1–65535 (port 0 is never valid); ports are unique *per transport*
    (a UDP-only inbound such as Hysteria2 may share a port with a
    TCP-only inbound; two TCP inbounds on one port, or anything
    sharing with Shadowsocks, which binds both, is an error);
    clients that are present carry the credential their protocol
    needs (``id`` for VLESS/VMess, ``password`` for
    Trojan/Hysteria2/Shadowsocks). Returns ``(is_valid, errors)``;
    ``errors`` is empty when valid. This is structural only — it
    does not run the Xray binary.
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
        port = inbound.get("port")
        protocol = inbound.get("protocol")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            errors.append(
                f"inbound '{tag}': port must be an integer in 1-65535 "
                f"(got {port!r})"
            )
        elif isinstance(protocol, str) and protocol.strip():
            cls = _transport_class(protocol)
            clash = _port_conflicts(seen_ports, port, cls)
            if clash is not None:
                errors.append(
                    f"inbound '{tag}': port {port} is already used by "
                    f"'{seen_tags[port][0]}' on the same transport"
                )
            else:
                seen_ports.setdefault(port, set()).add(cls)
                seen_tags.setdefault(port, []).append(str(tag))
        if not isinstance(protocol, str) or not protocol.strip():
            errors.append(f"inbound '{tag}': missing 'protocol'")
            continue
        settings_obj = inbound.get("settings")
        if not isinstance(settings_obj, dict):
            continue
        clients = settings_obj.get("clients")
        if isinstance(clients, list):
            for c_index, client in enumerate(clients):
                if not isinstance(client, dict):
                    errors.append(
                        f"inbound '{tag}': client #{c_index} must be "
                        "an object"
                    )
                    continue
                if protocol in ("vless", "vmess") and not client.get("id"):
                    errors.append(
                        f"inbound '{tag}': client #{c_index} is "
                        "missing 'id'"
                    )
                if protocol in ("trojan", "hysteria2", "hysteria") and not client.get(
                    "password"
                ):
                    errors.append(
                        f"inbound '{tag}': client #{c_index} is "
                        "missing 'password'"
                    )
                if protocol == "shadowsocks" and not client.get("password"):
                    errors.append(
                        f"inbound '{tag}': client #{c_index} is "
                        "missing 'password'"
                    )
                # Xray rejects a 2022 multi-user inbound whose users
                # carry a method ("users must have empty method") —
                # catch it here instead of at `xray -test` time.
                if protocol == "shadowsocks" and client.get("method"):
                    errors.append(
                        f"inbound '{tag}': client #{c_index} must not "
                        "carry 'method' (the method lives in settings)"
                    )
        if protocol == "shadowsocks" and not isinstance(clients, list):
            if not settings_obj.get("password"):
                errors.append(
                    f"inbound '{tag}': shadowsocks needs a 'password' "
                    "in settings (or a 'clients' list)"
                )
        # Sniffing / fallbacks (written by the inbound editor): a
        # fallback without a dest, or an xver other than 0/1, is a
        # render mistake — Xray would reject the config at load.
        # Fallbacks live inside streamSettings, not at inbound level.
        stream_settings = inbound.get("streamSettings") or {}
        fallbacks = stream_settings.get("fallbacks") if isinstance(
            stream_settings, dict) else None
        if fallbacks is not None:
            if not isinstance(fallbacks, list) or not fallbacks:
                errors.append(
                    f"inbound '{tag}': 'fallbacks' must be a non-empty list"
                )
            else:
                for f_index, entry in enumerate(fallbacks):
                    if not isinstance(entry, dict) or not entry.get("dest"):
                        errors.append(
                            f"inbound '{tag}': fallback #{f_index} "
                            "is missing a 'dest'"
                        )
                    elif entry.get("xver") not in (0, 1, None):
                        errors.append(
                            f"inbound '{tag}': fallback #{f_index} "
                            "'xver' must be 0 or 1"
                        )
        sniffing = inbound.get("sniffing")
        if sniffing is not None and not isinstance(sniffing, dict):
            errors.append(f"inbound '{tag}': 'sniffing' must be an object")
    return (not errors), errors


def write_and_validate(
    cfg: dict, path: str | Path, binary: str = "/usr/local/bin/xray"
) -> tuple[bool, list[str]]:
    """Write ``cfg`` to ``path`` after validation, atomically (see
    :func:`app.config_io.write_and_validate_config`). Runs
    ``xray run -test -c <tmp>`` when the binary exists (10 s timeout);
    when it is absent only the JSON structure is validated and the
    file is still written."""
    from app.config_io import write_and_validate_config

    return write_and_validate_config(
        cfg,
        path,
        binary=binary,
        name="xray",
        check_label="-test",
        check_cmd=lambda b, t: [b, "run", "-test", "-c", t],
        validate=validate_xray_config,
    )
