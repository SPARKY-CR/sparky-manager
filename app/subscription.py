"""Dual-format subscriptions for sparky-manager (DESIGN.md §6.1/§6.3).

Pure functions only: no database, no FastAPI, stdlib only.

ZedSecure imports both subscription formats, so the panel emits both
from the same per-user data:

* **v2rayNG** — base64 (standard, padded) of one share link per line.
* **sing-box** — JSON ``{"outbounds": [...]}`` the client imports
  directly (sing-box uses ``type`` + ``server``/``server_port``).

Format selection: an explicit ``?format=`` query value always wins;
otherwise the User-Agent is sniffed (sing-box / SFA / Hiddify ->
sing-box JSON; v2rayNG / v2rayN / NekoBox / Clash -> v2rayNG links);
unknown or missing User-Agent defaults to v2rayNG.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from datetime import datetime, timezone

__all__ = [
    "choose_format",
    "build_v2rayng_feed",
    "build_singbox_feed",
    "outbound_for_client",
    "subscription_userinfo",
    "decode_v2rayng_feed",
    "DEFAULT_REMARK_TEMPLATE",
    "format_data_left",
    "days_left",
    "expand_remark_variables",
    "placeholder_remark",
    "placeholder_feed_links",
    "placeholder_singbox_outbounds",
    "is_browser_user_agent",
]

# Canonical format names returned by choose_format().
FORMAT_V2RAYNG = "v2rayng"
FORMAT_SINGBOX = "singbox"

# Explicit ?format= spellings accepted (case-insensitive).
_V2RAYNG_ALIASES = {"v2rayng", "v2ray"}
_SINGBOX_ALIASES = {"singbox", "sing-box"}

# User-Agent markers, checked in this order (sing-box first: a UA
# naming a sing-box client wins even if it also mentions something else).
_SINGBOX_UA_MARKERS = ("sing-box", "singbox", "sfa", "hiddify")
_V2RAYNG_UA_MARKERS = ("v2rayng", "v2rayn", "nekobox", "clash")

# Extra client markers for the browser check below: a UA naming any
# known VPN client is a client even if it also says "Mozilla" (some
# clients send a browser-like UA).
_CLIENT_UA_MARKERS = _SINGBOX_UA_MARKERS + _V2RAYNG_UA_MARKERS + (
    "mihomo", "stash", "shadowrocket", "surge", "quantumult",
    "v2rayu", "nekoray", "v2ray", "trojan", "hiddify",
)


def is_browser_user_agent(user_agent: str | None) -> bool:
    """True when ``user_agent`` looks like a web browser, not a VPN client.

    A browser UA contains "Mozilla" and names no known VPN client.
    An empty or unknown UA is NOT a browser — subscription clients
    that send no UA must keep getting the raw feed (the previous
    default), and only a real browser gets the copy-only HTML page.
    """
    ua = (user_agent or "").lower()
    if "mozilla" not in ua:
        return False
    return not any(marker in ua for marker in _CLIENT_UA_MARKERS)


# ---------------------------------------------------------------------------
# Remark template variables (Phase A item 2)
# ---------------------------------------------------------------------------

#: Default remark template: the same ``user-inbound`` shape the
#: sing-box feed tags already use. The admin can change it in
#: Settings → General (``sub_remark_template``).
DEFAULT_REMARK_TEMPLATE = "{USER}-{INBOUND}"

#: Variables expandable in a remark template (Marzban/PasarGuard
#: "info host" convention).
REMARK_VARIABLES = ("{USER}", "{INBOUND}", "{DATA_LEFT}", "{DAYS_LEFT}")


def _format_bytes(value: int) -> str:
    """Human size: ``"512 MB"``, ``"3.2 GB"`` (one decimal, trailing
    ``.0`` stripped), ``"0 B"`` for zero/negative."""
    if value <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    index = min(int(math.log(value, 1024)), len(units) - 1)
    scaled = value / (1024 ** index)
    text = f"{scaled:.1f}".rstrip("0").rstrip(".")
    return f"{text} {units[index]}"


def format_data_left(used_bytes: int, limit_bytes: int | None) -> str:
    """Remaining quota for a remark: ``"3.2 GB"``, ``"0 B"`` when
    exhausted, ``"∞"`` when unlimited."""
    if limit_bytes is None:
        return "∞"
    return _format_bytes(max(0, int(limit_bytes) - int(used_bytes or 0)))


def days_left(
    expires_at: datetime | None, now: datetime | None = None
) -> str:
    """Whole days until ``expires_at``: ``"12"``, ``"0"`` when the
    expiry is today or past, ``"∞"`` when the user never expires."""
    if expires_at is None:
        return "∞"
    now = now or datetime.now(timezone.utc)
    exp = expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    remaining = (exp - now).total_seconds()
    if remaining <= 0:
        return "0"
    return str(int(remaining // 86400))


def expand_remark_variables(
    template: str | None,
    user: object,
    inbound_tag: str,
    now: datetime | None = None,
) -> str:
    """Expand a remark template for one (user, inbound) pair.

    ``{USER}`` is the user name, ``{INBOUND}`` the inbound tag,
    ``{DATA_LEFT}`` the remaining quota (``format_data_left``),
    ``{DAYS_LEFT}`` the days until expiry (``days_left``). A blank
    template falls back to :data:`DEFAULT_REMARK_TEMPLATE` (an empty
    remark would be worse than the default); unknown ``{...}``
    spellings are left untouched so a typo is visible instead of
    silently swallowed. ``user`` is duck-typed (``name``,
    ``traffic_used_bytes``, ``traffic_limit_bytes``, ``expires_at``)
    so the function stays pure and testable without the ORM.
    """
    template = (template or "").strip() or DEFAULT_REMARK_TEMPLATE
    values = {
        "{USER}": str(getattr(user, "name", "") or ""),
        "{INBOUND}": str(inbound_tag or ""),
        "{DATA_LEFT}": format_data_left(
            getattr(user, "traffic_used_bytes", 0) or 0,
            getattr(user, "traffic_limit_bytes", None),
        ),
        "{DAYS_LEFT}": days_left(
            getattr(user, "expires_at", None), now=now
        ),
    }
    out = template
    for variable, value in values.items():
        out = out.replace(variable, value)
    return out


# ---------------------------------------------------------------------------
# Placeholder feeds for unusable users (Phase A item 2)
# ---------------------------------------------------------------------------

#: Remark text per unusable state (Marzban/Remnawave convention: the
#: client shows a visible entry instead of a silently empty feed).
#: The entry points at 127.0.0.1:1 — it can never connect, which is
#: honest: the account is dead, and the remark says why.
PLACEHOLDER_REMARKS = {
    "expired": "⏰ Expired — sparky-manager",
    "limited": "📊 Limit reached — sparky-manager",
    "disabled": "🚫 Disabled — sparky-manager",
}

_PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"


def placeholder_remark(state: str) -> str:
    """The placeholder remark for an unusable state (unknown states
    fall back to the disabled text — never an empty remark)."""
    return PLACEHOLDER_REMARKS.get(
        (state or "").strip().lower(), PLACEHOLDER_REMARKS["disabled"]
    )


def placeholder_feed_links(state: str) -> list[str]:
    """A one-link v2rayNG feed for an unusable user: a VMess link
    whose remark names the state, pointing at 127.0.0.1:1."""
    payload = {
        "v": "2",
        "ps": placeholder_remark(state),
        "add": "127.0.0.1",
        "port": "1",
        "id": _PLACEHOLDER_UUID,
        "aid": 0,
        "scy": "auto",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        .encode("utf-8")
    ).decode("ascii")
    return [f"vmess://{encoded}"]


def placeholder_singbox_outbounds(state: str) -> list[dict]:
    """A one-outbound sing-box feed for an unusable user: a SOCKS
    outbound tagged with the state, pointing at 127.0.0.1:1."""
    return [
        {
            "type": "socks",
            "tag": placeholder_remark(state),
            "server": "127.0.0.1",
            "server_port": 1,
        }
    ]


# ---------------------------------------------------------------------------
# Format selection
# ---------------------------------------------------------------------------

def choose_format(
    user_agent: str | None,
    query_format: str | None,
) -> str:
    """Pick the subscription format: ``"v2rayng"`` or ``"singbox"``.

    An explicit ``?format=`` value wins when it is recognised
    (``v2rayng``/``v2ray`` -> v2rayNG, ``singbox``/``sing-box`` ->
    sing-box); an unrecognised explicit value is ignored and the
    User-Agent is sniffed instead. UA sniffing: a UA containing
    ``sing-box``, ``SFA`` or ``Hiddify`` -> sing-box; one containing
    ``v2rayNG``, ``v2rayN``, ``NekoBox`` or ``Clash`` -> v2rayNG.
    Unknown or missing UA -> v2rayNG (the safer default).
    """
    if query_format:
        normalised = query_format.strip().lower()
        if normalised in _V2RAYNG_ALIASES:
            return FORMAT_V2RAYNG
        if normalised in _SINGBOX_ALIASES:
            return FORMAT_SINGBOX
        # Unrecognised explicit value: fall through to UA sniffing.

    ua = (user_agent or "").lower()
    if any(marker in ua for marker in _SINGBOX_UA_MARKERS):
        return FORMAT_SINGBOX
    if any(marker in ua for marker in _V2RAYNG_UA_MARKERS):
        return FORMAT_V2RAYNG
    return FORMAT_V2RAYNG


# ---------------------------------------------------------------------------
# v2rayNG feed (base64 link list)
# ---------------------------------------------------------------------------

def build_v2rayng_feed(links: list[str]) -> bytes:
    """Encode ``links`` as a v2rayNG subscription body.

    Returns standard base64 (with padding) of the links joined with
    ``"\\n"``, one link per line, as bytes.
    """
    body = "\n".join(links).encode("utf-8")
    return base64.b64encode(body)


def decode_v2rayng_feed(body: bytes) -> list[str]:
    """Decode a v2rayNG subscription body back into its share links.

    Helper for tests and for verifying a feed round-trips. Raises
    :class:`ValueError` on invalid base64.
    """
    try:
        decoded = base64.b64decode(body, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ValueError("subscription body is not valid base64") from None
    return [line for line in decoded.split("\n") if line.strip()]


# ---------------------------------------------------------------------------
# sing-box feed (JSON outbounds)
# ---------------------------------------------------------------------------

def build_singbox_feed(outbounds: list[dict]) -> dict:
    """Wrap sing-box objects into a subscription document.

    Returns ``{"outbounds": [...]}`` — and, when any WireGuard
    object is present, ``{"outbounds": [...], "endpoints": [...]}``:
    sing-box removed the WireGuard *outbound* in 1.13.0, so
    WireGuard objects (``type == "wireguard"``) are endpoints and
    must live under ``"endpoints"`` or ``sing-box check`` rejects
    the feed (``unknown field "server"``).
    """
    endpoints = [o for o in outbounds if o.get("type") == "wireguard"]
    plain = [o for o in outbounds if o.get("type") != "wireguard"]
    feed: dict[str, list[dict]] = {"outbounds": list(plain)}
    if endpoints:
        feed["endpoints"] = list(endpoints)
    return feed


def subscription_userinfo(
    used_bytes: int,
    limit_bytes: int | None,
    expires_unix: int | None,
) -> str:
    """Build a ``Subscription-Userinfo`` header value.

    ``"upload=0; download=<used>; total=<limit or 0>; expire=<unix or 0>"``

    ``limit_bytes`` / ``expires_unix`` of ``None`` (unlimited / never)
    are reported as ``0``, which is the convention clients read as
    "no limit".
    """
    total = limit_bytes if limit_bytes is not None else 0
    expire = expires_unix if expires_unix is not None else 0
    return (f"upload=0; download={int(used_bytes)}; "
            f"total={int(total)}; expire={int(expire)}")


# ---------------------------------------------------------------------------
# sing-box outbound objects, one per (client, inbound) pair
# ---------------------------------------------------------------------------

def _stream_value(stream: dict, *keys: str, default=None):
    """Return the first present, non-None value among ``keys`` in ``stream``."""
    for key in keys:
        value = stream.get(key)
        if value is not None:
            return value
    return default


def _reality_info(stream: dict) -> dict:
    """Normalise the Reality settings out of an inbound ``stream_json``.

    Accepts the nested form (``{"reality": {...}}``) and the flat form
    (``{"sni": ..., "pbk": ..., "sid": ...}``), tolerating camelCase
    key spellings.
    """
    reality = stream.get("reality") or {}
    if not isinstance(reality, dict):
        reality = {}
    server_names = reality.get("serverNames") or reality.get("server_names") or []
    sni = (
        reality.get("sni")
        or reality.get("server_name")
        or (server_names[0] if server_names else None)
        or stream.get("sni")
        or stream.get("server_name")
    )
    return {
        "sni": sni,
        "public_key": _stream_value(
            reality, "public_key", "publicKey", "pbk",
            default=stream.get("pbk"),
        ),
        "short_id": _stream_value(
            reality, "short_id", "shortId", "sid",
            default=stream.get("sid"),
        ),
    }


def _tls_sni(stream: dict) -> str | None:
    """Return the TLS server name from an inbound ``stream_json``."""
    tls = stream.get("tls") or {}
    if not isinstance(tls, dict):
        tls = {}
    return (
        tls.get("sni")
        or tls.get("server_name")
        or stream.get("sni")
        or stream.get("server_name")
    )


def _validate_port(port) -> int:
    """Return ``port`` as an int, raising ValueError outside 1-65535."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {port!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _base_outbound(
    outbound_type: str,
    tag: str,
    host: str,
    port: int,
) -> dict:
    """Common sing-box outbound fields: type/tag/server/server_port."""
    if not host:
        raise ValueError("missing required value: host")
    return {
        "type": outbound_type,
        "tag": tag,
        "server": host,
        "server_port": _validate_port(port),
    }


def _tls_block(server_name: str | None, *, reality: dict | None = None,
               alpn: list[str] | None = None,
               fingerprint: str | None = None) -> dict:
    """Build a sing-box ``tls`` object.

    Always ``{"enabled": true, ...}`` with ``server_name`` when known.
    ``reality`` adds the Reality block; ``fingerprint`` adds a uTLS
    block (``{"enabled": true, "fingerprint": ...}``).
    """
    tls: dict = {"enabled": True}
    if server_name:
        tls["server_name"] = server_name
    if alpn:
        tls["alpn"] = list(alpn)
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if reality is not None:
        tls["reality"] = {
            "enabled": True,
            "public_key": reality.get("public_key"),
            "short_id": reality.get("short_id"),
        }
    return tls


def _ws_transport(stream: dict) -> dict | None:
    """Build a sing-box WS ``transport`` object, or None if not WS."""
    if str(stream.get("network") or "").lower() != "ws":
        return None
    transport: dict = {"type": "ws"}
    if stream.get("path"):
        transport["path"] = stream["path"]
    host_header = stream.get("host") or stream.get("host_header")
    if host_header:
        transport["headers"] = {"Host": host_header}
    return transport


def _grpc_transport(stream: dict) -> dict | None:
    """Build a sing-box gRPC ``transport`` object, or None if not gRPC."""
    if str(stream.get("network") or "").lower() != "grpc":
        return None
    transport: dict = {"type": "grpc"}
    service_name = stream.get("service_name") or stream.get("serviceName")
    if service_name:
        transport["service_name"] = service_name
    return transport


def _httpupgrade_transport(stream: dict) -> dict | None:
    """Build a sing-box HTTPUpgrade ``transport`` object, or None."""
    if str(stream.get("network") or "").lower() != "httpupgrade":
        return None
    transport: dict = {"type": "httpupgrade"}
    if stream.get("path"):
        transport["path"] = stream["path"]
    host_header = stream.get("host") or stream.get("host_header")
    if host_header:
        transport["headers"] = {"Host": host_header}
    return transport


def _transport_for(stream: dict) -> dict | None:
    """The sing-box ``transport`` object for the inbound's network.

    WS / gRPC / HTTPUpgrade each have their own shape; plain TCP
    (and XHTTP, which sing-box does not support) return ``None``.
    """
    for builder in (_ws_transport, _grpc_transport, _httpupgrade_transport):
        transport = builder(stream)
        if transport is not None:
            return transport
    return None


def outbound_for_client(
    protocol: str,
    client: dict,
    inbound: dict,
    host: str,
    tag: str,
) -> dict | None:
    """Build the sing-box outbound object for one (client, inbound) pair.

    ``client`` keys: ``uuid``, ``password``, ``method``, ``flow``,
    ``extra_json``. ``inbound`` keys: ``tag``, ``protocol``, ``port``,
    ``stream_json`` (a dict with ``security`` / ``reality`` / ``tls`` /
    ``network`` / ``path`` / ``host`` as applicable).

    Returns ``None`` for:

    * ``ikev2``, ``openvpn`` and ``openconnect`` (no sing-box
      outbound exists — they are exported as files instead);
    * ``amneziawg`` — upstream sing-box has no AmneziaWG support
      (only forks do: Hiddify's ``"type": "awg"`` endpoint,
      sing-box-lx's root-promoted AWG fields); emitting a plain
      WireGuard endpoint would be wrong (it lacks the obfuscation
      parameters), so the protocol is exported as ``vpn://`` + the
      ``.conf`` file instead (see docs/ZEDSECURE.md);
    * unknown protocols (no sing-box outbound exists);
    * VLESS over XHTTP — sing-box does not support XHTTP, so such
      inbounds are emitted in the v2rayNG feed only (DESIGN.md §6.3).

    WireGuard returns an **endpoint** object, not an outbound:
    sing-box removed the WireGuard outbound in 1.13.0 (deprecated
    since 1.11.0), so the feed must carry it under ``"endpoints"``
    — :func:`build_singbox_feed` does that split. ShadowTLS returns
    the outer outbound only; its Shadowsocks detour outbound comes
    from :func:`outbounds_for_client`.
    """
    protocol = (protocol or "").lower().strip()
    port = _validate_port(inbound.get("port"))
    stream = inbound.get("stream_json") or {}
    if not isinstance(stream, dict):
        stream = {}
    extra = client.get("extra_json") or {}
    if not isinstance(extra, dict):
        extra = {}

    if protocol == "vless":
        network = str(stream.get("network") or "tcp").lower()
        if network == "xhttp":
            # sing-box has no XHTTP transport (DESIGN.md §6.3):
            # v2rayNG feed only.
            return None
        security = str(stream.get("security") or "reality").lower()
        outbound = _base_outbound("vless", tag, host, port)
        uuid = client.get("uuid")
        if not uuid:
            raise ValueError("missing required value: uuid")
        outbound["uuid"] = uuid
        if client.get("flow"):
            outbound["flow"] = client["flow"]
        if security == "reality":
            reality = _reality_info(stream)
            outbound["tls"] = _tls_block(
                reality["sni"],
                reality=reality,
                fingerprint="chrome",
            )
        elif security == "tls":
            outbound["tls"] = _tls_block(
                _tls_sni(stream),
                fingerprint="chrome",
            )
        transport = _transport_for(stream)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "vmess":
        network = str(stream.get("network") or "ws").lower()
        security = str(stream.get("security") or "tls").lower()
        outbound = _base_outbound("vmess", tag, host, port)
        uuid = client.get("uuid")
        if not uuid:
            raise ValueError("missing required value: uuid")
        outbound["uuid"] = uuid
        outbound["security"] = "auto"
        outbound["alter_id"] = 0
        if security == "tls":
            outbound["tls"] = _tls_block(_tls_sni(stream))
        transport = _transport_for(stream)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "trojan":
        outbound = _base_outbound("trojan", tag, host, port)
        password = client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        outbound["password"] = password
        outbound["tls"] = _tls_block(_tls_sni(stream) or host)
        transport = _transport_for(stream)
        if transport is not None:
            outbound["transport"] = transport
        return outbound

    if protocol == "shadowsocks":
        outbound = _base_outbound("shadowsocks", tag, host, port)
        method = client.get("method")
        password = client.get("password")
        if not method:
            raise ValueError("missing required value: method")
        if not password:
            raise ValueError("missing required value: password")
        outbound["method"] = method
        outbound["password"] = password
        return outbound

    if protocol == "hysteria2":
        outbound = _base_outbound("hysteria2", tag, host, port)
        password = client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        outbound["password"] = password
        outbound["tls"] = _tls_block(_tls_sni(stream) or host)
        return outbound

    if protocol == "tuic":
        outbound = _base_outbound("tuic", tag, host, port)
        uuid = client.get("uuid")
        password = client.get("password")
        if not uuid:
            raise ValueError("missing required value: uuid")
        if not password:
            raise ValueError("missing required value: password")
        outbound["uuid"] = uuid
        outbound["password"] = password
        outbound["congestion_control"] = (
            stream.get("congestion_control")
            or extra.get("congestion_control")
            or "bbr"
        )
        outbound["tls"] = _tls_block(
            _tls_sni(stream) or host,
            alpn=["h3"],
        )
        return outbound

    if protocol == "anytls":
        outbound = _base_outbound("anytls", tag, host, port)
        password = client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        outbound["password"] = password
        outbound["tls"] = _tls_block(_tls_sni(stream) or host)
        return outbound

    if protocol == "naive":
        outbound = _base_outbound("naive", tag, host, port)
        username = extra.get("username") or client.get("username") or "user"
        password = client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        outbound["username"] = username
        outbound["password"] = password
        outbound["tls"] = _tls_block(_tls_sni(stream) or host)
        return outbound

    if protocol == "shadowtls":
        # Client-side ShadowTLS v3 outbound: the outer handshake
        # layer. The inner Shadowsocks detour outbound is built by
        # outbounds_for_client (the pair is only usable together).
        password = _stream_value(stream, "password") or client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        outbound = _base_outbound("shadowtls", tag, host, port)
        outbound["version"] = 3
        outbound["password"] = password
        outbound["tls"] = _tls_block(_tls_sni(stream) or host)
        return outbound

    if protocol == "wireguard":
        # WireGuard is an ENDPOINT since sing-box 1.13.0 (the old
        # wireguard outbound was removed): `server`/`server_port`
        # become peers[].address/port, `local_address` becomes
        # `address`, `peer_public_key` becomes peers[].public_key.
        # build_singbox_feed moves this object into "endpoints".
        # MTU from the inbound stream when the admin set one (the
        # same value the server config and the .conf export use).
        mtu = stream.get("mtu")
        try:
            mtu = int(mtu) if mtu is not None else 1280
        except (TypeError, ValueError):
            mtu = 1280
        outbound = {
            "type": "wireguard",
            "tag": tag,
            "address": [],
            "private_key": "",
            "peers": [],
            "mtu": mtu,
        }
        # The client's private key: `extra_json["private_key"]` when
        # set, else the client dict's own `private_key` — and, as a
        # last resort, `password`, which is where the panel itself
        # stores a WireGuard client's private key (see
        # app.main._new_client_credentials: private key in `password`,
        # public key in `uuid`).
        private_key = (
            extra.get("private_key")
            or client.get("private_key")
            or client.get("password")
            or ""
        )
        if not private_key:
            raise ValueError("missing required value: private_key "
                             "(client extra_json)")
        peer_public_key = _stream_value(
            stream,
            "peer_public_key", "server_public_key", "public_key",
            "publicKey",
        )
        if not peer_public_key:
            raise ValueError("missing required value: peer_public_key "
                             "(inbound stream_json)")
        # The client's tunnel address: the `allowed_ips` the panel
        # allocated at user creation (one /32 per peer) — NOT the
        # old hardcoded 10.8.0.2/32, which gave every user the same
        # address and broke with a custom subnet. `local_address`
        # is still honoured when set explicitly.
        allowed = str(extra.get("allowed_ips") or "").strip()
        if allowed:
            outbound["address"] = [
                part.strip() for part in allowed.split(",") if part.strip()
            ]
        elif extra.get("local_address"):
            local = extra["local_address"]
            outbound["address"] = (
                list(local) if isinstance(local, list) else [str(local)]
            )
        else:
            outbound["address"] = ["10.8.0.2/32"]
        outbound["private_key"] = private_key
        outbound["peers"] = [{
            "address": host,
            "port": port,
            "public_key": peer_public_key,
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            # Keep the tunnel alive behind NAT (mobile clients).
            # sing-box wants SECONDS as a number (uint16), not a
            # duration string — "25s" is rejected at load.
            "persistent_keepalive_interval": 25,
        }]
        return outbound

    if protocol in ("ikev2", "openvpn", "openconnect", "amneziawg"):
        # No sing-box outbound exists for these protocols (see the
        # docstring): file exports instead (see app.main).
        return None

    # Unknown: no sing-box outbound exists.
    return None


def outbounds_for_client(
    protocol: str,
    client: dict,
    inbound: dict,
    host: str,
    tag: str,
) -> list[dict]:
    """Every sing-box object for one (client, inbound) pair.

    Usually one object (the result of :func:`outbound_for_client`);
    ShadowTLS needs two — the outer outbound plus the inner
    Shadowsocks outbound that detours through it (the detour
    outbound's ``detour`` field points at the ShadowTLS tag, so its
    traffic is wrapped by the handshake layer). Returns ``[]`` when
    the pair has no sing-box representation.
    """
    protocol = (protocol or "").lower().strip()
    if protocol == "shadowtls":
        stream = inbound.get("stream_json") or {}
        if not isinstance(stream, dict):
            stream = {}
        password = _stream_value(stream, "password") or client.get("password")
        if not password:
            raise ValueError("missing required value: password")
        method = (
            _stream_value(stream, "method")
            or client.get("method")
            or "2022-blake3-aes-128-gcm"
        )
        outer = outbound_for_client(protocol, client, inbound, host, tag)
        assert outer is not None  # shadowtls branch above always builds
        port = _validate_port(inbound.get("port"))
        inner = _base_outbound("shadowsocks", f"{tag}-ss", host, port)
        inner["method"] = method
        inner["password"] = password
        inner["detour"] = tag
        return [outer, inner]
    outbound = outbound_for_client(protocol, client, inbound, host, tag)
    return [outbound] if outbound is not None else []
