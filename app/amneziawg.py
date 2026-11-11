"""AmneziaWG config rendering + ``vpn://`` links (written from scratch).

AmneziaWG is a WireGuard fork that adds traffic obfuscation: the
config is a plain WireGuard config plus extra ``[Interface]``
fields — ``Jc`` / ``Jmin`` / ``Jmax`` (junk packets), ``S1``–``S4``
and ``H1``–``H4`` (handshake packet sizes / header offsets),
``I1``–``I5`` (initiation tags), ``HeaderProtectionKey`` and a few
timing / padding fields. The ``S`` / ``H`` values and the header
protection key **must be identical on server and client**; the
``J`` / ``I`` values may differ per peer but the panel uses the
same set everywhere (valid, and simpler).

All-zero / absent obfuscation parameters make an AmneziaWG peer a
plain WireGuard peer, so the parameters are optional in the config
— but the panel always generates them, because an inbound created
without obfuscation would be indistinguishable from WireGuard and
defeat the point.

The server needs the AmneziaWG kernel module (``amneziawg-dkms``)
or the userspace ``amneziawg-go`` binary; upstream Ubuntu has no
package — the installer tries Amnezia's Launchpad PPA (pinned to
the ``noble`` suite on Ubuntu 26.04, which the PPA does not publish
for) and never lets that step break the rest of the install. The
panel detects availability at runtime
(``is_available()`` — ``awg-quick`` on PATH) and the UI / docs say
plainly when the module is missing instead of pretending the
protocol works.

Client export: the ``vpn://`` link is the base64url encoding of
the whole raw ``.conf`` text (the 3x-ui convention; decoders accept
both base64 alphabets, with or without padding) plus the plain
``.conf`` file itself. Upstream sing-box does **not** support
AmneziaWG — only forks do (Hiddify's ``"type": "awg"`` endpoint,
sing-box-lx's root-promoted AWG fields) — so AmneziaWG is omitted
from the sing-box feed; the bundle carries the ``vpn://`` link and
the ``.conf`` text and the docs say which client shape applies.
The apply path (validate → strip → syncconf-or-start) is shared
with WireGuard through ``app.wgapply`` (interface ``awg0``,
binaries ``awg`` / ``awg-quick``).
"""

from __future__ import annotations

import base64
import ipaddress
import secrets
import shutil
import string
from typing import Any

__all__ = [
    "AWG_INTERFACE_KEYS",
    "DEFAULT_NETWORK",
    "DEFAULT_PORT",
    "INTERFACE",
    "build_vpn_link",
    "generate_awg_params",
    "is_available",
    "parse_vpn_link",
    "render_peer_config",
    "render_server_config",
    "validate_awg_params",
]

DEFAULT_PORT = 51821
DEFAULT_NETWORK = "10.8.1.0/24"
INTERFACE = "awg0"

# The extra [Interface] keys AmneziaWG understands (also listed in
# app.wgapply so the shared validator accepts them).
AWG_INTERFACE_KEYS = (
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "headerprotectionkey",
    "contentpaddingaddition",
    "randomtrailers",
    "disablecookies",
    "tcptimer",
    "udptimer",
    "tcpacktimeout",
    "udpacktimeout",
    "handshakejitter",
    "jittertime",
    "jittertime2",
)

_TAG_ALPHABET = string.ascii_letters + string.digits


def _random_tag(length: int = 8) -> str:
    return "".join(secrets.choice(_TAG_ALPHABET) for _ in range(length))


def _random_key_b64() -> str:
    """A random 32-byte key, standard base64 (like a WireGuard key)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def generate_awg_params() -> dict[str, Any]:
    """Fresh obfuscation parameters for one inbound.

    ``S1``–``S4`` are >= 12 (required when a header protection key
    is present) and ``H1``–``H4`` are distinct, non-overlapping
    values. The same dict goes into the server config and every
    client config of the inbound — the ``S`` / ``H`` group and the
    header key must match on both sides.
    """
    return {
        "Jc": 4,
        "Jmin": 40,
        "Jmax": 70,
        "S1": 15,
        "S2": 16,
        "S3": 17,
        "S4": 18,
        "H1": 100,
        "H2": 200,
        "H3": 300,
        "H4": 400,
        "I1": _random_tag(),
        "I2": _random_tag(),
        "I3": _random_tag(),
        "I4": _random_tag(),
        "I5": _random_tag(),
        "HeaderProtectionKey": _random_key_b64(),
    }


def validate_awg_params(params: dict[str, Any]) -> list[str]:
    """Check one obfuscation parameter set; empty list = valid."""
    problems: list[str] = []
    if not isinstance(params, dict):
        return ["amneziawg params are not a dict"]

    def _int(name: str, low: int, high: int) -> int | None:
        value = params.get(name)
        if value is None:
            problems.append(f"amneziawg param {name} is missing")
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            problems.append(f"amneziawg param {name} is not a number: {value!r}")
            return None
        if not low <= number <= high:
            problems.append(
                f"amneziawg param {name} out of range {low}-{high}: {number}"
            )
        return number

    _int("Jc", 0, 65535)
    jmin = _int("Jmin", 0, 65535)
    jmax = _int("Jmax", 0, 65535)
    if jmin is not None and jmax is not None and jmin > jmax:
        problems.append(f"amneziawg Jmin ({jmin}) is greater than Jmax ({jmax})")
    s_values: list[int] = []
    for name in ("S1", "S2", "S3", "S4"):
        value = _int(name, 0, 65535)
        if value is not None:
            s_values.append(value)
    h_values: list[int] = []
    for name in ("H1", "H2", "H3", "H4"):
        value = _int(name, 0, 2**32 - 1)
        if value is not None:
            h_values.append(value)
    if len(set(h_values)) != len(h_values):
        problems.append("amneziawg H1-H4 must not overlap (distinct values)")
    if params.get("HeaderProtectionKey"):
        key = str(params["HeaderProtectionKey"])
        try:
            raw = base64.b64decode(key, validate=True)
        except Exception:  # noqa: BLE001
            problems.append("amneziawg HeaderProtectionKey is not valid base64")
        else:
            if len(raw) != 32:
                problems.append(
                    "amneziawg HeaderProtectionKey is not a 32-byte key"
                )
        if s_values and min(s_values) < 12:
            problems.append(
                "amneziawg S1-S4 must be >= 12 when a HeaderProtectionKey "
                "is set"
            )
    for name in ("I1", "I2", "I3", "I4", "I5"):
        if not str(params.get(name) or "").strip():
            problems.append(f"amneziawg param {name} is missing")
    return problems


def _awg_interface_lines(params: dict[str, Any]) -> list[str]:
    """The extra ``[Interface]`` lines, in a stable order."""
    order = (
        "Jc",
        "Jmin",
        "Jmax",
        "S1",
        "S2",
        "S3",
        "S4",
        "H1",
        "H2",
        "H3",
        "H4",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
        "HeaderProtectionKey",
    )
    lines: list[str] = []
    for key in order:
        value = params.get(key)
        if value is not None and str(value) != "":
            lines.append(f"{key} = {value}")
    return lines


def _allowed_ips(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (list, tuple)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(parts) or None
    return None


def render_server_config(
    server_private_key: str,
    peers: list[dict],
    *,
    address: str = "10.8.1.1/24",
    listen_port: int = DEFAULT_PORT,
    params: dict[str, Any] | None = None,
) -> str:
    """Render a server ``awg0.conf`` (WireGuard shape + AWG fields).

    No DNS line: like the WireGuard server config, DNS only changes
    the server's own resolver and breaks ``awg-quick up`` on systems
    without a resolvconf provider.
    """
    params = dict(params or {})
    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    lines.extend(_awg_interface_lines(params))
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
    server_port: int = DEFAULT_PORT,
    *,
    params: dict[str, Any] | None = None,
    dns: str = "1.1.1.1",
    mtu: int = 1280,
) -> str:
    """Render a client ``.conf`` (same AWG fields as the server)."""
    params = dict(params or {})
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
    lines.extend(_awg_interface_lines(params))
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key}")
    lines.append(f"Endpoint = {host}:{server_port}")
    lines.append("AllowedIPs = 0.0.0.0/0, ::/0")
    lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_vpn_link(conf_text: str) -> str:
    """``vpn://`` link: base64url of the whole raw ``.conf`` text."""
    return "vpn://" + _b64url_nopad(conf_text.encode("utf-8"))


def parse_vpn_link(link: str) -> str:
    """Decode a ``vpn://`` link back to the ``.conf`` text.

    Tolerant of both base64 alphabets and missing padding (decoders
    in the wild accept both).
    """
    text = (link or "").strip()
    if not text.lower().startswith("vpn://"):
        raise ValueError("not a vpn:// link")
    payload = text[len("vpn://") :]
    payload = payload.replace("-", "+").replace("_", "/")
    payload += "=" * (-len(payload) % 4)
    return base64.b64decode(payload).decode("utf-8")


def is_available() -> bool:
    """True when the AmneziaWG tools are installed (``awg-quick``)."""
    return shutil.which("awg-quick") is not None
