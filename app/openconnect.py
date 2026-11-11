"""OpenConnect server (ocserv) config rendering (written from scratch).

Server model: password auth against an ``ocpasswd`` file
(``username:group:crypt-hash``, one line per user — the group is
empty). The panel writes that file itself on every re-render, with
passwords hashed with SHA-512 crypt (``$6$``), which glibc's
``crypt(3)`` — what ocserv uses — accepts. The hash is generated
with the stdlib ``crypt`` module when available (Python <= 3.12)
and falls back to ``openssl passwd -6 -stdin`` otherwise, so the
code keeps working on newer Pythons where ``crypt`` was removed.

The server needs a TLS certificate + key; it uses the panel's
shared server cert (``data/ca/server-cert.pem`` — the same cert
OpenVPN and IKEv2 use), so no extra CA work is needed. TCP and UDP
share the port (ocserv supports that); the default is 4433 because
the panel's default VLESS-Reality + Hysteria2 already occupy TCP
and UDP 443.

There is no standard share-link / URI scheme for OpenConnect and
sing-box has no OpenConnect outbound, so it appears in neither
subscription feed. Export is the AnyConnect profile XML (bundle
entry ``openconnect_profile`` + the token-gated
``/sub/<token>/openconnect.xml`` download) plus host / port /
username / password in the bundle, which is all a client needs.
``StrictCertificateTrust`` is false in the profile because the
server cert chains to the panel's private CA — a client enforcing
strict trust would reject it.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import string
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Optional, Sequence

__all__ = [
    "DEFAULT_NETWORK",
    "DEFAULT_PASSWD_FILE",
    "DEFAULT_PORT",
    "hash_password",
    "render_ocpasswd",
    "render_ocserv_config",
    "render_profile_xml",
    "validate_ocserv_config",
    "verify_password",
]

DEFAULT_PORT = 4433
DEFAULT_NETWORK = "10.10.10.0/24"
DEFAULT_PASSWD_FILE = "/etc/ocserv/ocpasswd"

# Directives the rendered ocserv config must contain.
_REQUIRED_DIRECTIVES = (
    "auth",
    "tcp-port",
    "udp-port",
    "server-cert",
    "server-key",
    "ipv4-network",
    "ipv4-netmask",
)

_SALT_ALPHABET = string.ascii_letters + string.digits + "./"


def _crypt_module_hash(password: str) -> Optional[str]:
    """SHA-512 crypt hash via the stdlib ``crypt`` module (or None)."""
    try:
        import crypt
    except ImportError:
        return None
    salt = crypt.mksalt(crypt.METHOD_SHA512)
    return crypt.crypt(password, salt)


def _openssl_hash(password: str, run: Optional[Callable] = None) -> Optional[str]:
    """SHA-512 crypt hash via ``openssl passwd -6 -stdin`` (or None).

    The password is passed on stdin, never on the command line (it
    would be visible in the process list).
    """
    runner = run or subprocess.run
    try:
        proc = runner(
            ["openssl", "passwd", "-6", "-stdin"],
            input=password.encode("utf-8"),
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    hashed = proc.stdout.decode("utf-8", "replace").strip()
    return hashed if hashed.startswith("$6$") else None


def hash_password(password: str, run: Optional[Callable] = None) -> str:
    """Hash ``password`` for an ocpasswd entry (``$6$`` SHA-512 crypt).

    Raises ``RuntimeError`` when neither the ``crypt`` module nor
    ``openssl`` is available — the caller must surface that instead
    of writing a broken password file.
    """
    hashed = _crypt_module_hash(password)
    if hashed:
        return hashed
    hashed = _openssl_hash(password, run=run)
    if hashed:
        return hashed
    raise RuntimeError(
        "cannot hash an ocserv password: neither the 'crypt' module "
        "nor 'openssl passwd' is available"
    )


def verify_password(password: str, stored: str) -> bool:
    """True when ``password`` matches the stored ``$6$`` hash.

    Uses the ``crypt`` module when available (it re-hashes with the
    stored salt); otherwise re-hashes with ``openssl`` using the
    salt extracted from the stored hash.
    """
    if not stored.startswith("$6$"):
        return False
    try:
        import crypt

        return secrets.compare_digest(crypt.crypt(password, stored), stored)
    except ImportError:
        pass
    match = re.match(r"^\$6\$([^$]+)\$", stored)
    if not match:
        return False
    salt = match.group(1)
    try:
        proc = subprocess.run(
            ["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
            input=password.encode("utf-8"),
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    return secrets.compare_digest(
        proc.stdout.decode("utf-8", "replace").strip(), stored
    )


def render_ocpasswd(
    users: Sequence[tuple[str, str]],
    *,
    run: Optional[Callable] = None,
) -> str:
    """Render the ocpasswd file: ``username::crypt-hash`` per user.

    ``users`` is ``(username, password)`` pairs. Usernames are
    validated (no ``:`` or whitespace — those would break the file
    format); a bad username raises ``ValueError`` instead of writing
    a broken file.
    """
    lines: list[str] = []
    for username, password in users:
        name = (username or "").strip()
        if not name or ":" in name or any(ch.isspace() for ch in name):
            raise ValueError(f"invalid ocserv username: {username!r}")
        if not password:
            raise ValueError(f"empty password for ocserv user {name!r}")
        lines.append(f"{name}::{hash_password(password, run=run)}")
    return "\n".join(lines) + ("\n" if lines else "")


def render_ocserv_config(
    *,
    port: int = DEFAULT_PORT,
    network: str = DEFAULT_NETWORK,
    server_cert: str,
    server_key: str,
    passwd_file: str = DEFAULT_PASSWD_FILE,
    dns: tuple[str, str] = ("1.1.1.1", "1.0.0.1"),
    max_clients: int = 1024,
) -> str:
    """Render a minimal ``ocserv.conf`` (password auth, full tunnel)."""
    net = ipaddress.ip_network(network, strict=False)
    lines = [
        "# ocserv config rendered by sparky-manager — do not hand-edit.",
        f'auth = "plain[passwd={passwd_file}]"',
        f"tcp-port = {int(port)}",
        f"udp-port = {int(port)}",
        "run-as-user = nobody",
        "run-as-group = nogroup",
        f"server-cert = {server_cert}",
        f"server-key = {server_key}",
        f"ipv4-network = {net.network_address}",
        f"ipv4-netmask = {net.netmask}",
    ]
    for server in dns:
        lines.append(f"dns = {server}")
    lines += [
        "route = default",
        "cisco-client-compat = true",
        f"max-clients = {int(max_clients)}",
        "use-occtl = true",
        "socket-file = /run/ocserv/ocserv.sock",
        "pid-file = /run/ocserv/ocserv.pid",
    ]
    return "\n".join(lines) + "\n"


def render_profile_xml(
    *,
    host: str,
    port: int = DEFAULT_PORT,
    name: str = "sparky-manager",
) -> str:
    """Render an AnyConnect profile XML for one server.

    ``HostAddress`` is ``host:port``; the user group is empty (the
    panel does not use groups). ``StrictCertificateTrust`` is false
    because the server cert chains to the panel's private CA.
    """
    host = host.strip()
    profile = ET.Element(
        "AnyConnectProfile",
        {
            "xmlns": "http://schemas.xmlsoap.org/encoding/",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": (
                "http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd"
            ),
        },
    )
    init = ET.SubElement(profile, "ClientInitialization")
    start = ET.SubElement(init, "UseStartBeforeLogon")
    start.set("UserControllable", "false")
    start.text = "false"
    trust = ET.SubElement(init, "StrictCertificateTrust")
    trust.text = "false"
    server_list = ET.SubElement(profile, "ServerList")
    entry = ET.SubElement(server_list, "HostEntry")
    host_name = ET.SubElement(entry, "HostName")
    host_name.text = name
    host_address = ET.SubElement(entry, "HostAddress")
    host_address.text = f"{host}:{int(port)}"
    group = ET.SubElement(entry, "UserGroup")
    group.text = ""
    ET.indent(profile, space="  ")
    return ET.tostring(profile, encoding="unicode", xml_declaration=True) + "\n"


def _directive_values(text: str) -> dict[str, list[str]]:
    """Parse ``key = value`` lines into ``{key: [value...]}``."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        out.setdefault(key.strip().lower(), []).append(value.strip())
    return out


def validate_ocserv_config(
    text: str,
    *,
    passwd_file: str = "",
    server_cert: str = "",
    server_key: str = "",
) -> list[str]:
    """Structural validation of a rendered ocserv config.

    Checks the required directives, the ports, the client subnet,
    and that the referenced passwd / cert / key files exist. The
    real check is ``ocserv -t -c <config>`` (run by the panel before
    replacing the live file); this catches render mistakes first.
    """
    problems: list[str] = []
    if not text.strip():
        return ["config is empty"]
    directives = _directive_values(text)
    for required in _REQUIRED_DIRECTIVES:
        if required not in directives:
            problems.append(f"config is missing the '{required}' directive")
    for key in ("tcp-port", "udp-port"):
        value = (directives.get(key) or [""])[0]
        if value:
            try:
                port_n = int(value)
            except ValueError:
                problems.append(f"{key} is not a number: {value!r}")
            else:
                if not 1 <= port_n <= 65535:
                    problems.append(f"{key} out of range: {port_n}")
    network = (directives.get("ipv4-network") or [""])[0]
    netmask = (directives.get("ipv4-netmask") or [""])[0]
    if network and netmask:
        try:
            ipaddress.ip_network(f"{network}/{netmask}", strict=False)
        except ValueError:
            problems.append(
                f"ipv4-network/netmask invalid: {network} / {netmask}"
            )
    auth = (directives.get("auth") or [""])[0]
    if auth and "plain[passwd=" not in auth:
        problems.append(f"auth is not plain[passwd=...]: {auth!r}")
    for label, expected, path in (
        ("server-cert", server_cert, (directives.get("server-cert") or [""])[0]),
        ("server-key", server_key, (directives.get("server-key") or [""])[0]),
    ):
        if expected and path and path != expected:
            problems.append(
                f"{label} path {path!r} does not match the expected {expected!r}"
            )
        target = path or expected
        if target and not Path(target).is_file():
            problems.append(f"{label} file does not exist: {target}")
    if passwd_file:
        match = re.search(r"passwd=([^\]\"]+)", auth or "")
        target = match.group(1) if match else passwd_file
        if target != passwd_file:
            problems.append(
                f"passwd file {target!r} does not match the expected {passwd_file!r}"
            )
        if not Path(target).is_file():
            problems.append(f"passwd file does not exist: {target}")
    return problems
