"""Share-link builders and parsers for vpn-panel.

Pure functions only: no database, no FastAPI, stdlib plus ``qrcode``
(for :func:`make_qr_png`, imported lazily inside the function).

Link shapes follow DESIGN.md §6.2, which restates the public,
client-understood share-link formats (``vless://``, ``vmess://``,
``trojan://``, ``ss://`` SIP002, ``hysteria2://``, ``tuic://``,
``anytls://``, ``naive+https://``). All builders and parsers here are
original code written from those format definitions.

Conventions shared by every builder:

* The ``#name`` fragment and any password containing ``@``, ``#``,
  ``?`` or ``/`` are percent-encoded, so a round-trip through a parser
  recovers the original value.
* ``host`` may be a bare IP or a domain name — the panel is
  domain-agnostic and no builder requires a domain.
* Builders validate their required inputs and raise :class:`ValueError`
  on missing/empty credentials or an out-of-range port, instead of
  emitting a link a client would silently reject.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
from urllib.parse import parse_qs, quote, unquote, urlparse

__all__ = [
    "build_vless_link",
    "build_vmess_link",
    "build_trojan_link",
    "build_ss_link",
    "build_hysteria2_link",
    "build_tuic_link",
    "build_anytls_link",
    "build_naive_link",
    "build_share_link",
    "parse_vless_link",
    "parse_vmess_link",
    "parse_trojan_link",
    "parse_ss_link",
    "make_qr_png",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _validate_port(port: int) -> int:
    """Return ``port`` as an int, raising ValueError outside 1-65535."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"invalid port: {port!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _require(value: str | None, what: str) -> str:
    """Return ``value`` stripped, raising ValueError when empty/missing."""
    if value is None or not str(value).strip():
        raise ValueError(f"missing required value: {what}")
    return str(value)


def _query(params: list[tuple[str, str | None]]) -> str:
    """Build a ``k=v&k=v`` query string, skipping None values.

    Values are percent-encoded with :func:`urllib.parse.quote` (spaces
    become ``%20``, not ``+``), which every client importer accepts.
    """
    return "&".join(
        f"{key}={quote(str(value), safe='')}"
        for key, value in params
        if value is not None
    )


def _fragment(name: str) -> str:
    """Percent-encode a display name for use after ``#`` in a link."""
    return quote(name or "", safe="")


def _b64encode(data: bytes) -> str:
    """Standard base64 (with padding), as used by ``vmess://`` links."""
    return base64.b64encode(data).decode("ascii")


def _b64url_nopad(data: bytes) -> str:
    """URL-safe base64 without padding, as used by SIP002 ``ss://`` links."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode_padded(data: str) -> bytes:
    """Decode base64 (standard or URL-safe), tolerating missing padding."""
    text = data.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text.encode("ascii"))
    except (binascii.Error, ValueError):
        raise ValueError(f"invalid base64 data: {data!r}") from None


def _parse_host_port(parsed, what: str) -> tuple[str, int]:
    """Extract (host, port) from a parsed URL, raising ValueError."""
    host = parsed.hostname
    port = parsed.port
    if not host or port is None:
        raise ValueError(f"{what} link is missing host or port: "
                         f"{parsed.geturl()!r}")
    return host, port


def _single_query(query: dict[str, list[str]], key: str) -> str | None:
    """Return the first value for ``key`` in a parsed query dict."""
    values = query.get(key)
    return values[0] if values else None


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_vless_link(
    uuid: str,
    host: str,
    port: int,
    *,
    flow: str | None = None,
    security: str = "reality",
    sni: str | None = None,
    fp: str = "chrome",
    pbk: str | None = None,
    sid: str | None = None,
    network: str = "tcp",
    path: str | None = None,
    name: str = "",
) -> str:
    """Build a ``vless://`` share link.

    Reality example::

        vless://<uuid>@<host>:443?encryption=none&flow=xtls-rprx-vision
            &security=reality&sni=www.microsoft.com&fp=chrome
            &pbk=<public>&sid=<shortid>&type=tcp#<name>

    WS+TLS example: pass ``security="tls"``, ``network="ws"`` and
    ``path="/<path>"``; the link then carries ``security=tls&type=ws``
    plus ``path`` (and ``host`` is not part of this signature — the WS
    Host header lives in the inbound's ``stream_json`` and is picked up
    by :func:`build_share_link`).
    """
    uuid = _require(uuid, "uuid")
    host = _require(host, "host")
    port = _validate_port(port)
    security = (security or "reality").lower()
    network = (network or "tcp").lower()

    params: list[tuple[str, str | None]] = [
        ("encryption", "none"),
        ("flow", flow),
        ("security", security),
        ("sni", sni),
        ("fp", fp or None),
        ("pbk", pbk),
        ("sid", sid),
        ("type", network),
        ("path", path),
    ]
    query = _query(params)
    link = f"vless://{quote(uuid, safe='')}@{host}:{port}"
    if query:
        link += f"?{query}"
    return f"{link}#{_fragment(name)}"


def build_vmess_link(
    uuid: str,
    host: str,
    port: int,
    *,
    name: str = "",
    network: str = "ws",
    path: str | None = None,
    tls: str = "tls",
    sni: str | None = None,
    host_header: str | None = None,
) -> str:
    """Build a ``vmess://`` share link (base64 JSON, ``v: "2"``).

    The JSON payload is::

        {"v": "2", "ps": name, "add": host, "port": "<port>",
         "id": uuid, "aid": 0, "scy": "auto", "net": network,
         "type": "none", "host": host_header, "path": path,
         "tls": tls, "sni": sni, "fp": "chrome"}
    """
    uuid = _require(uuid, "uuid")
    host = _require(host, "host")
    port = _validate_port(port)

    payload = {
        "v": "2",
        "ps": name or "",
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": 0,
        "scy": "auto",
        "net": (network or "ws").lower(),
        "type": "none",
        "host": host_header or "",
        "path": path or "",
        "tls": (tls or "tls").lower(),
        "sni": sni or "",
        "fp": "chrome",
    }
    encoded = _b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        .encode("utf-8")
    )
    return f"vmess://{encoded}"


def build_trojan_link(
    password: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    name: str = "",
) -> str:
    """Build a ``trojan://`` share link.

    ``trojan://<password>@<host>:<port>?security=tls&type=tcp&sni=<sni>#<name>``

    The password is percent-encoded, so passwords containing ``@``,
    ``#``, ``?`` or ``/`` survive the round-trip. When ``sni`` is not
    given it defaults to ``host`` (the usual TLS case).
    """
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    query = _query([
        ("security", "tls"),
        ("type", "tcp"),
        ("sni", sni or host),
    ])
    return (f"trojan://{quote(password, safe='')}@{host}:{port}"
            f"?{query}#{_fragment(name)}")


def build_ss_link(
    method: str,
    password: str,
    host: str,
    port: int,
    *,
    name: str = "",
) -> str:
    """Build a Shadowsocks share link (SIP002).

    ``ss://<base64url(method:password)>@<host>:<port>#<name>``

    The ``method:password`` part is URL-safe base64 without padding;
    the host/port stay in clear text, which is the SIP002 form every
    modern client (including ZedSecure) expects.
    """
    method = _require(method, "method")
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    userinfo = _b64url_nopad(f"{method}:{password}".encode("utf-8"))
    return f"ss://{userinfo}@{host}:{port}#{_fragment(name)}"


def build_hysteria2_link(
    password: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    name: str = "",
) -> str:
    """Build a ``hysteria2://`` share link.

    ``hysteria2://<password>@<host>:<port>?sni=<sni>#<name>``

    The ``sni`` parameter is included only when given; callers that
    know the TLS server name should pass it (usually the panel domain,
    or the host itself).
    """
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    query = _query([("sni", sni)])
    link = f"hysteria2://{quote(password, safe='')}@{host}:{port}"
    if query:
        link += f"?{query}"
    return f"{link}#{_fragment(name)}"


def build_tuic_link(
    uuid: str,
    password: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    name: str = "",
) -> str:
    """Build a ``tuic://`` share link (TUIC v5).

    ``tuic://<uuid>:<password>@<host>:<port>?congestion_control=bbr&alpn=h3&sni=<sni>#<name>``
    """
    uuid = _require(uuid, "uuid")
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    query = _query([
        ("congestion_control", "bbr"),
        ("alpn", "h3"),
        ("sni", sni),
    ])
    link = f"tuic://{quote(uuid, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if query:
        link += f"?{query}"
    return f"{link}#{_fragment(name)}"


def build_anytls_link(
    password: str,
    host: str,
    port: int,
    *,
    sni: str | None = None,
    name: str = "",
) -> str:
    """Build an ``anytls://`` share link.

    ``anytls://<password>@<host>:<port>?sni=<sni>#<name>``
    """
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    query = _query([("sni", sni)])
    link = f"anytls://{quote(password, safe='')}@{host}:{port}"
    if query:
        link += f"?{query}"
    return f"{link}#{_fragment(name)}"


def build_naive_link(
    username: str,
    password: str,
    host: str,
    port: int,
    *,
    name: str = "",
) -> str:
    """Build a NaiveProxy share link.

    ``naive+https://<user>:<password>@<host>:<port>#<name>``

    Note the ``naive+https`` scheme — plain ``naive://`` is a common
    mistake and most clients will not import it.
    """
    username = _require(username, "username")
    password = _require(password, "password")
    host = _require(host, "host")
    port = _validate_port(port)
    return (f"naive+https://{quote(username, safe='')}:"
            f"{quote(password, safe='')}@{host}:{port}#{_fragment(name)}")


# ---------------------------------------------------------------------------
# Dispatch builder: one client + one inbound -> one share link
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

    Accepts both the nested form (``{"reality": {"sni": ...,
    "public_key": ..., "short_id": ...}}``) and a flat form
    (``{"sni": ..., "pbk": ..., "sid": ...}``), and tolerates the
    camelCase key spellings the core configs use.
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


def build_share_link(
    protocol: str,
    client: dict,
    inbound: dict,
    host: str,
    name: str,
) -> str | None:
    """Build the share link for one (client, inbound) pair.

    ``client`` keys: ``uuid``, ``password``, ``method``, ``flow``,
    ``extra_json``. ``inbound`` keys: ``tag``, ``protocol``, ``port``,
    ``stream_json`` (a dict with ``security`` / ``reality`` / ``tls`` /
    ``network`` / ``path`` / ``host`` as applicable).

    Returns ``None`` for protocols with no share-link standard
    (``wireguard`` and ``ikev2`` — those are exported as ``.conf`` /
    ``.mobileconfig`` files instead) and for unknown protocols.

    ``shadowtls`` has no share link of its own: it is served as a
    Shadowsocks (SIP002) link, with ShadowTLS carried as a detour in
    the server-side sing-box config (see DESIGN.md §5.2).
    """
    protocol = (protocol or "").lower().strip()
    host = _require(host, "host")
    port = _validate_port(inbound.get("port"))
    stream = inbound.get("stream_json") or {}
    if not isinstance(stream, dict):
        stream = {}
    extra = client.get("extra_json") or {}
    if not isinstance(extra, dict):
        extra = {}

    if protocol == "vless":
        reality = _reality_info(stream)
        security = str(stream.get("security") or "reality").lower()
        return build_vless_link(
            client.get("uuid") or "",
            host,
            port,
            flow=client.get("flow"),
            security=security,
            sni=reality["sni"] if security == "reality" else _tls_sni(stream),
            fp=stream.get("fp") or "chrome",
            pbk=reality["public_key"],
            sid=reality["short_id"],
            network=str(stream.get("network") or "tcp"),
            path=stream.get("path"),
            name=name,
        )

    if protocol == "vmess":
        security = str(stream.get("security") or "tls").lower()
        return build_vmess_link(
            client.get("uuid") or "",
            host,
            port,
            name=name,
            network=str(stream.get("network") or "ws"),
            path=stream.get("path"),
            tls="tls" if security == "tls" else "none",
            sni=_tls_sni(stream),
            host_header=stream.get("host") or stream.get("host_header"),
        )

    if protocol == "trojan":
        return build_trojan_link(
            client.get("password") or "",
            host,
            port,
            sni=_tls_sni(stream) or host,
            name=name,
        )

    if protocol in ("shadowsocks", "shadowtls"):
        # ShadowTLS is offered to the client as a plain SS link; the
        # ShadowTLS handshake is a server-side (sing-box) concern.
        return build_ss_link(
            client.get("method") or "",
            client.get("password") or "",
            host,
            port,
            name=name,
        )

    if protocol == "hysteria2":
        return build_hysteria2_link(
            client.get("password") or "",
            host,
            port,
            sni=_tls_sni(stream) or host,
            name=name,
        )

    if protocol == "tuic":
        return build_tuic_link(
            client.get("uuid") or "",
            client.get("password") or "",
            host,
            port,
            sni=_tls_sni(stream) or host,
            name=name,
        )

    if protocol == "anytls":
        return build_anytls_link(
            client.get("password") or "",
            host,
            port,
            sni=_tls_sni(stream) or host,
            name=name,
        )

    if protocol == "naive":
        username = (
            extra.get("username")
            or client.get("username")
            or "user"
        )
        return build_naive_link(
            username,
            client.get("password") or "",
            host,
            port,
            name=name,
        )

    # wireguard / ikev2: no share-link standard (file export instead).
    # Unknown protocols: nothing sensible to build.
    return None


# ---------------------------------------------------------------------------
# Parsers (round-trip: build a link -> parse it back)
# ---------------------------------------------------------------------------

def parse_vless_link(link: str) -> dict:
    """Parse a ``vless://`` link back into its parts.

    Returns a dict with ``uuid``, ``host``, ``port`` (int), ``name``,
    ``flow``, ``security``, ``sni``, ``fp``, ``pbk``, ``sid``,
    ``network`` (from ``type``) and ``path``. Raises :class:`ValueError`
    on a malformed link.
    """
    if not isinstance(link, str) or not link.startswith("vless://"):
        raise ValueError(f"not a vless:// link: {link!r}")
    parsed = urlparse(link)
    if not parsed.username:
        raise ValueError(f"vless link is missing the uuid: {link!r}")
    host, port = _parse_host_port(parsed, "vless")
    query = parse_qs(parsed.query)
    return {
        "uuid": unquote(parsed.username),
        "host": host,
        "port": port,
        "name": unquote(parsed.fragment or ""),
        "flow": _single_query(query, "flow"),
        "security": _single_query(query, "security") or "reality",
        "sni": _single_query(query, "sni"),
        "fp": _single_query(query, "fp"),
        "pbk": _single_query(query, "pbk"),
        "sid": _single_query(query, "sid"),
        "network": _single_query(query, "type") or "tcp",
        "path": _single_query(query, "path"),
        "encryption": _single_query(query, "encryption") or "none",
    }


def parse_vmess_link(link: str) -> dict:
    """Parse a ``vmess://`` link back into its parts.

    Returns a dict with ``uuid`` (from ``id``), ``host`` (from
    ``add``), ``port`` (int), ``name`` (from ``ps``), ``network``
    (from ``net``), ``path``, ``tls``, ``sni``, ``host_header`` (from
    ``host``), ``aid`` and ``scy``. Raises :class:`ValueError` on a
    malformed link.
    """
    if not isinstance(link, str) or not link.startswith("vmess://"):
        raise ValueError(f"not a vmess:// link: {link!r}")
    payload_b64 = link[len("vmess://"):].strip()
    if not payload_b64:
        raise ValueError("vmess link has an empty payload")
    try:
        payload = json.loads(_b64decode_padded(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError(f"vmess link payload is not valid base64 JSON: "
                         f"{link!r}") from None
    if not isinstance(payload, dict):
        raise ValueError(f"vmess link payload is not a JSON object: {link!r}")
    uuid = payload.get("id")
    host = payload.get("add")
    port = payload.get("port")
    if not uuid or not host or port is None:
        raise ValueError(f"vmess link is missing id/add/port: {link!r}")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"vmess link has an invalid port: {port!r}") from None
    _validate_port(port)
    return {
        "uuid": str(uuid),
        "host": str(host),
        "port": port,
        "name": str(payload.get("ps") or ""),
        "network": str(payload.get("net") or "tcp"),
        "path": str(payload.get("path") or ""),
        "tls": str(payload.get("tls") or "none"),
        "sni": str(payload.get("sni") or ""),
        "host_header": str(payload.get("host") or ""),
        "aid": payload.get("aid", 0),
        "scy": str(payload.get("scy") or "auto"),
    }


def parse_trojan_link(link: str) -> dict:
    """Parse a ``trojan://`` link back into its parts.

    Returns a dict with ``password``, ``host``, ``port`` (int),
    ``name``, ``sni``, ``security`` and ``network`` (from ``type``).
    Raises :class:`ValueError` on a malformed link.
    """
    if not isinstance(link, str) or not link.startswith("trojan://"):
        raise ValueError(f"not a trojan:// link: {link!r}")
    parsed = urlparse(link)
    if not parsed.username:
        raise ValueError(f"trojan link is missing the password: {link!r}")
    host, port = _parse_host_port(parsed, "trojan")
    query = parse_qs(parsed.query)
    return {
        "password": unquote(parsed.username),
        "host": host,
        "port": port,
        "name": unquote(parsed.fragment or ""),
        "sni": _single_query(query, "sni"),
        "security": _single_query(query, "security") or "tls",
        "network": _single_query(query, "type") or "tcp",
    }


def parse_ss_link(link: str) -> dict:
    """Parse an ``ss://`` Shadowsocks link back into its parts.

    Handles the SIP002 form (``ss://base64url(method:password)@host:port``)
    and the legacy form (``ss://base64(method:password@host:port)``).
    Returns a dict with ``method``, ``password``, ``host``, ``port``
    (int) and ``name``. Raises :class:`ValueError` on a malformed link.
    """
    if not isinstance(link, str) or not link.startswith("ss://"):
        raise ValueError(f"not an ss:// link: {link!r}")
    rest = link[len("ss://"):]
    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    name = unquote(fragment or "")
    if not rest:
        raise ValueError(f"ss link is empty: {link!r}")

    if "@" in rest:
        # SIP002: base64url(method:password)@host:port
        userinfo_b64, hostport = rest.rsplit("@", 1)
        try:
            userinfo = _b64decode_padded(userinfo_b64).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"ss link userinfo is not valid base64: "
                             f"{link!r}") from None
        if ":" not in userinfo:
            raise ValueError(f"ss link userinfo has no method:password: "
                             f"{link!r}")
        method, password = userinfo.split(":", 1)
        host, port = _split_host_port(hostport, link)
    else:
        # Legacy: base64(method:password@host:port)
        try:
            decoded = _b64decode_padded(rest).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"ss link payload is not valid base64: "
                             f"{link!r}") from None
        if "@" not in decoded or ":" not in decoded:
            raise ValueError(f"ss link payload has no credentials/host: "
                             f"{link!r}")
        userinfo, hostport = decoded.rsplit("@", 1)
        if ":" not in userinfo:
            raise ValueError(f"ss link payload has no method:password: "
                             f"{link!r}")
        method, password = userinfo.split(":", 1)
        host, port = _split_host_port(hostport, link)

    if not method or not password or not host:
        raise ValueError(f"ss link is missing method/password/host: {link!r}")
    return {
        "method": method,
        "password": password,
        "host": host,
        "port": port,
        "name": name,
    }


def _split_host_port(hostport: str, link: str) -> tuple[str, int]:
    """Split a ``host:port`` string, raising ValueError when malformed."""
    if ":" not in hostport:
        raise ValueError(f"link is missing a port: {link!r}")
    host, _, port_text = hostport.rpartition(":")
    host = host.strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        raise ValueError(f"link has an invalid port: {link!r}") from None
    _validate_port(port)
    if not host:
        raise ValueError(f"link is missing a host: {link!r}")
    return host, port


# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------

def make_qr_png(data: str) -> bytes:
    """Render ``data`` (a share link or a config file) as a PNG QR code.

    Returns the PNG bytes. The ``qrcode`` library is imported inside
    this function so the rest of this module stays importable without
    it; if it is not installed, raises :class:`RuntimeError` with a
    clear message (install ``qrcode[pil]``).
    """
    try:
        import qrcode
    except ImportError:
        raise RuntimeError(
            "the 'qrcode' package is not installed; "
            "install it with: pip install 'qrcode[pil]'"
        ) from None
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
