"""WireGuard config rendering and ``wg show`` parsing (original code).

Stdlib only (``secrets`` / ``base64`` / ``re`` / ``time``). No
``wg`` binary and no third-party crypto is used anywhere here.

Keys: :func:`generate_keypair` returns WireGuard-format keys — base64
of 32 raw bytes each. The public key is **derived** from the private
key with a pure-Python X25519 Montgomery ladder (RFC 7748, implemented
here from the RFC, not taken from any other project); the two halves
of a pair are never two independent random values, so a generated
server keypair is a real, working keypair. The private key is the raw
32 random bytes (clamping is applied inside the ladder, exactly as
WireGuard / X25519 do at use time).

``wg show`` parsing accepts both the human-readable output of
``wg show [wg0]`` (``peer: …`` / ``latest handshake: …`` /
``transfer: … received, … sent``) and the tab-separated dump format
of ``wg show wg0 dump``. It is tolerant: empty, truncated or
unrelated text yields ``{}`` (or a partial dict) instead of raising.
"""

from __future__ import annotations

import base64
import re
import secrets
import time
from typing import Any

__all__ = [
    "generate_keypair",
    "render_wg_config",
    "render_peer_config",
    "parse_wg_show",
]

# ---------------------------------------------------------------------------
# X25519 (RFC 7748), pure Python — needed to derive a public key from a
# private key without the `wg` binary or any crypto library.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665  # (486662 - 2) // 4, the Montgomery curve constant
_BASE_POINT = (9).to_bytes(32, "little")


def _cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    """Conditional swap: ``(b, a)`` when ``swap`` is 1, else ``(a, b)``."""
    if swap:
        return b, a
    return a, b


def _x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """X25519 scalar multiplication (RFC 7748 §5).

    ``scalar_bytes`` is clamped as the RFC requires; ``u_bytes`` is
    the 32-byte little-endian u-coordinate. Returns the 32-byte
    little-endian result.
    """
    if len(scalar_bytes) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    x1 = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_int >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    result = x2 * pow(z2, _P - 2, _P) % _P
    return result.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Key generation / config rendering
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    """Generate a WireGuard keypair ``(private_key, public_key)``.

    Both keys are base64 (with padding, 44 chars) of 32 bytes, the
    format ``wg`` itself uses. The private key is 32 fresh random
    bytes from :mod:`secrets`; the public key is derived from it
    with the pure-Python X25519 above — no ``wg`` binary is called.
    """
    private_raw = secrets.token_bytes(32)
    public_raw = _x25519(private_raw, _BASE_POINT)
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def _allowed_ips(value: Any) -> str | None:
    """Normalise an ``allowed_ips`` value (str or list) to one string."""
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (list, tuple)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(parts) or None
    return None


def render_wg_config(
    server_private_key: str,
    peers: list[dict],
    *,
    address: str = "10.8.0.1/24",
    listen_port: int = 51820,
    dns: str = "1.1.1.1",
) -> str:
    """Render a server ``wg0.conf`` as a string.

    One ``[Interface]`` (private key, address, listen port, DNS)
    followed by one ``[Peer]`` per peer dict with ``public_key`` and
    ``allowed_ips`` (``preshared_key`` is included when present).
    Peers missing ``public_key`` or ``allowed_ips`` are skipped —
    a peer without either cannot work and must not break the file.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    for peer in peers or []:
        if not isinstance(peer, dict):
            continue
        public_key = peer.get("public_key")
        allowed_ips = _allowed_ips(peer.get("allowed_ips"))
        if not public_key or not allowed_ips:
            continue
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {public_key}")
        lines.append(f"AllowedIPs = {allowed_ips}")
        preshared_key = peer.get("preshared_key")
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
    return "\n".join(lines) + "\n"


def render_peer_config(
    peer_private_key: str,
    peer_address: str,
    server_public_key: str,
    server_host: str,
    server_port: int = 51820,
    *,
    dns: str = "1.1.1.1",
    mtu: int = 1280,
) -> str:
    """Render a client ``.conf`` for one WireGuard peer.

    Routes all traffic through the server (``AllowedIPs =
    0.0.0.0/0, ::/0``) with a 25 s persistent keepalive so the peer
    stays reachable behind NAT. ``server_host`` may be a bare IP, a
    hostname, or an IPv6 address (bracketed automatically).
    """
    host = server_host.strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    lines = [
        "[Interface]",
        f"PrivateKey = {peer_private_key}",
        f"Address = {peer_address}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    lines.append(f"Endpoint = {host}:{server_port}")
    lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
    lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# `wg show` parsing
# ---------------------------------------------------------------------------

_SIZE_RE = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[KMGT]?i?B)", re.IGNORECASE
)
_TRANSFER_RE = re.compile(
    r"transfer:\s*(?P<rx>[\d.]+\s*[KMGT]?i?B)\s+received,\s*"
    r"(?P<tx>[\d.]+\s*[KMGT]?i?B)\s+sent",
    re.IGNORECASE,
)
_HANDSHAKE_RE = re.compile(
    r"latest handshake:\s*(?P<text>.+)", re.IGNORECASE
)
_DURATION_PART_RE = re.compile(
    r"(?P<n>\d+)\s*(?P<unit>days?|hours?|minutes?|seconds?)",
    re.IGNORECASE,
)
_PEER_RE = re.compile(r"^peer:\s*(?P<key>\S+)\s*$", re.IGNORECASE)
_B64_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

_SIZE_MULTIPLIERS = {
    "B": 1,
    "KB": 1000,
    "KIB": 1024,
    "MB": 1000**2,
    "MIB": 1024**2,
    "GB": 1000**3,
    "GIB": 1024**3,
    "TB": 1000**4,
    "TIB": 1024**4,
}

_DURATION_SECONDS = {
    "day": 86400,
    "days": 86400,
    "hour": 3600,
    "hours": 3600,
    "minute": 60,
    "minutes": 60,
    "second": 1,
    "seconds": 1,
}


def _parse_size(text: str) -> int | None:
    """Parse a human size like ``"1.23 KiB"`` to bytes (``None`` if bad)."""
    match = _SIZE_RE.search(text or "")
    if not match:
        return None
    try:
        value = float(match.group("value"))
    except ValueError:
        return None
    unit = match.group("unit").upper()
    return int(round(value * _SIZE_MULTIPLIERS.get(unit, 1)))


def _parse_handshake_ago(text: str) -> int | None:
    """Parse ``"1 minute, 37 seconds ago"`` to seconds (``None`` if bad)."""
    if not text:
        return None
    total = 0
    found = False
    for match in _DURATION_PART_RE.finditer(text):
        unit = match.group("unit").lower()
        seconds = _DURATION_SECONDS.get(unit)
        if seconds is None:
            continue
        try:
            total += int(match.group("n")) * seconds
        except ValueError:
            continue
        found = True
    return total if found else None


def _parse_human_format(text: str) -> dict[str, dict[str, Any]]:
    """Parse human-readable ``wg show`` output."""
    result: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        peer_match = _PEER_RE.match(line)
        if peer_match:
            current = peer_match.group("key")
            result.setdefault(
                current,
                {
                    "transfer_up": 0,
                    "transfer_down": 0,
                    "latest_handshake_seconds_ago": None,
                },
            )
            continue
        if current is None:
            continue
        transfer = _TRANSFER_RE.search(line)
        if transfer:
            received = _parse_size(transfer.group("rx"))
            sent = _parse_size(transfer.group("tx"))
            # Kernel counters are from the interface's view: bytes
            # received FROM the peer are the peer's upload, bytes sent
            # TO the peer are its download — the same convention as
            # traffic.parse_wg_transfer.
            if received is not None:
                result[current]["transfer_up"] = received
            if sent is not None:
                result[current]["transfer_down"] = sent
            continue
        handshake = _HANDSHAKE_RE.search(line)
        if handshake:
            result[current]["latest_handshake_seconds_ago"] = (
                _parse_handshake_ago(handshake.group("text"))
            )
    return result


def _parse_dump_format(text: str) -> dict[str, dict[str, Any]]:
    """Parse tab-separated ``wg show <iface> dump`` output.

    Dump columns: public key, preshared key, endpoint, allowed IPs,
    latest-handshake unix timestamp, transfer received, transfer
    sent, persistent keepalive. A zero handshake timestamp means
    "never" (``None``).
    """
    result: dict[str, dict[str, Any]] = {}
    now = int(time.time())
    for raw_line in text.splitlines():
        fields = raw_line.split("\t")
        if len(fields) < 7:
            continue
        pubkey = fields[0].strip()
        if not _B64_KEY_RE.match(pubkey):
            continue
        try:
            handshake_ts = int(fields[4])
            received = int(fields[5])
            sent = int(fields[6])
        except (ValueError, IndexError):
            continue
        result[pubkey] = {
            # Dump columns are (..., received, sent): received FROM
            # the peer is its upload, sent TO the peer its download
            # (same convention as traffic.parse_wg_transfer).
            "transfer_up": received,
            "transfer_down": sent,
            "latest_handshake_seconds_ago": (
                max(0, now - handshake_ts) if handshake_ts > 0 else None
            ),
        }
    return result


def parse_wg_show(text: str | None) -> dict[str, dict[str, Any]]:
    """Parse ``wg show`` output to per-peer traffic.

    Returns ``{public_key: {"transfer_up": bytes sent,
    "transfer_down": bytes received,
    "latest_handshake_seconds_ago": int | None}}``. Both the
    human-readable ``wg show`` format and the tab-separated ``wg
    show <iface> dump`` format are accepted. Empty, missing or
    unrelated text returns ``{}``; a peer with no handshake line
    (or a zero dump timestamp) reports ``None`` for the handshake
    age instead of a made-up number.
    """
    if not text or not isinstance(text, str):
        return {}
    if "\t" in text:
        dump = _parse_dump_format(text)
        if dump:
            return dump
    return _parse_human_format(text)
