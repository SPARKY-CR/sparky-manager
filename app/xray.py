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
  ``reality`` / ``tls`` / ``path`` / ``service_name``), ``remark``.
- client dict: ``uuid``, ``password``, ``method``, ``flow``,
  ``extra_json`` (dict).
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

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

__all__ = [
    "render_xray_config",
    "validate_xray_config",
    "write_and_validate",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_PORT = 10085
API_LISTEN = "127.0.0.1"
DEFAULT_HOME = "/opt/vpn-panel"
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
    ``grpc``), ``security`` (``reality``/``tls``/``none``), ``reality``
    (dict, see :func:`_reality_settings`), ``tls`` (dict with ``sni`` /
    ``alpn`` / cert paths), ``path`` (WS/XHTTP path), ``host`` (WS Host
    header), ``service_name`` (gRPC service name), ``mode`` (XHTTP mode).
    A missing ``path`` for WebSocket defaults to ``/<tag>``.
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

    return result


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
        entries.append(entry)
    return {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "vless",
        "settings": {"clients": entries, "decryption": "none"},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="none"
        ),
    }


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
        {"id": client["uuid"], "alterId": 0, "security": "auto"}
        for client in usable
    ]
    return {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "vmess",
        "settings": {"clients": entries},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="none"
        ),
    }


def _build_trojan(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """Trojan inbound: password clients, TLS by default."""
    usable = _usable_clients(clients, need=("password",))
    if not usable:
        return None
    entries = [{"password": client["password"]} for client in usable]
    return {
        "tag": inbound["tag"],
        "port": inbound["port"],
        "protocol": "trojan",
        "settings": {"clients": entries},
        "streamSettings": _stream_settings(
            inbound, settings, default_network="tcp", default_security="tls"
        ),
    }


def _build_shadowsocks(
    inbound: dict[str, Any],
    clients: list[dict[str, Any]],
    settings: dict[str, Any],
) -> dict[str, Any] | None:
    """Shadowsocks 2022 inbound (``network`` fixed to ``tcp,udp``).

    Single-client form follows DESIGN.md §5.1
    (``settings: {method, password, network}``); with several clients
    a ``clients`` list is added so each password stays usable.
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
            {
                "password": client["password"],
                "method": _clean_str(client.get("method")) or method,
            }
            for client in usable
        ]
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
        "clients": [{"password": client["password"]} for client in usable],
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
    ``routing`` blocking private IPs to ``blackhole``, and
    ``outbounds`` ``[freedom, blackhole]``. One inbound object per
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
                "0": {"statsUserUplink": True, "statsUserDownlink": True},
            },
        },
        "routing": {
            "rules": [
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
        if protocol == "shadowsocks" and not isinstance(clients, list):
            if not settings_obj.get("password"):
                errors.append(
                    f"inbound '{tag}': shadowsocks needs a 'password' "
                    "in settings (or a 'clients' list)"
                )
    return (not errors), errors


def write_and_validate(
    cfg: dict, path: str | Path, binary: str = "/usr/local/bin/xray"
) -> tuple[bool, list[str]]:
    """Write ``cfg`` to ``path`` after validation, atomically.

    Writes ``path + ".tmp.json"``, runs ``xray run -test -c <tmp>`` when
    the binary exists (10 s timeout), and atomically renames the temp
    file into place only on success — a rejected config never
    replaces the live one. When the binary is absent (panel not
    installed yet, or this machine is not the server) only the JSON
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

    ok, errors = validate_xray_config(cfg)
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
            [binary_path, "run", "-test", "-c", str(tmp)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, ["xray validation timed out after 10s"]
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, [f"could not run xray binary: {exc}"]

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
    message = f"xray -test failed (exit {proc.returncode})"
    if lines:
        message += ": " + " | ".join(line.strip() for line in lines if line.strip())
    return False, [message]
