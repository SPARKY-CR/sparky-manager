"""Panel settings and paths.

All paths derive from ``SPARKY_HOME`` (default ``/opt/sparky-manager``),
so the panel can be installed anywhere. Nothing here hard-pins a
core version: the installer fetches the latest stable Xray-core /
sing-box and records what it installed in ``versions.env``.

Domain-agnostic by design: ``domain`` and ``subscription_host`` both
default to ``""`` (empty), meaning "no domain — use the request host /
server IP". A domain is only ever an optional extra.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults (overridable by environment at install / runtime time)
# ---------------------------------------------------------------------------

DEFAULT_HOME = "/opt/sparky-manager"
# Dev/run fallback only: the installer randomises the port on a fresh
# install (10000-60000) and passes it via SPARKY_PORT / --port.
DEFAULT_PANEL_PORT = 2053
DEFAULT_PANEL_HOST = "0.0.0.0"
DEFAULT_REALITY_SNI = "www.microsoft.com"

_WEB_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def normalize_web_path(raw: str) -> str:
    """Normalize the secret panel web path: ``""`` (panel at root) or ``"/<segment>"``.

    The installer randomises a 12-character ``[a-z0-9]`` segment on a
    fresh install (like 3X-UI's webBasePath); the panel then only
    answers under ``/<segment>`` and the root returns 404.
    """
    seg = (raw or "").strip().strip("/")
    if not seg:
        return ""
    if not _WEB_PATH_RE.match(seg):
        raise ValueError(
            f"invalid web path: {raw!r} (use letters, digits, '-' or '_')"
        )
    return "/" + seg

# Login-box file written by the installer (root-only, 0600).
LOGIN_FILE = Path("/root/sparky-manager-login.txt")


@dataclass(frozen=True)
class Settings:
    """Resolved panel settings. Frozen: read once, never mutated."""

    home: Path = Path(DEFAULT_HOME)
    panel_port: int = DEFAULT_PANEL_PORT
    panel_host: str = DEFAULT_PANEL_HOST
    domain: str = ""
    subscription_host: str = ""
    reality_sni: str = DEFAULT_REALITY_SNI
    web_path: str = ""

    # -- derived paths ------------------------------------------------------
    @property
    def data_dir(self) -> Path:
        return self.home / "data"

    @property
    def certs_dir(self) -> Path:
        return self.home / "certs"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "panel.db"

    @property
    def versions_file(self) -> Path:
        """versions.env — written by install.sh, never hard-pinned here."""
        return self.home / "versions.env"

    @property
    def xray_config(self) -> Path:
        return Path("/usr/local/etc/xray/config.json")

    @property
    def singbox_config(self) -> Path:
        return Path("/etc/sing-box/config.json")

    @property
    def wg_config(self) -> Path:
        return Path("/etc/wireguard/wg0.conf")

    @property
    def ovpn_config(self) -> Path:
        return Path("/etc/openvpn/server/sparky-manager.conf")

    @property
    def ocserv_config(self) -> Path:
        return Path("/etc/ocserv/ocserv.conf")

    @property
    def ocserv_passwd(self) -> Path:
        return Path("/etc/ocserv/ocpasswd")

    @property
    def awg_config(self) -> Path:
        return Path("/etc/amnezia/amneziawg/awg0.conf")

    @property
    def swanctl_config(self) -> Path:
        return Path("/etc/swanctl/swanctl.conf")

    @property
    def ca_dir(self) -> Path:
        """Dedicated CA + server cert for the VPN servers (OpenVPN /
        ocserv / IKEv2 share one trust anchor)."""
        return self.data_dir / "ca"

    @property
    def ca_cert(self) -> Path:
        return self.ca_dir / "ca-cert.pem"

    @property
    def ca_key(self) -> Path:
        return self.ca_dir / "ca-key.pem"

    @property
    def vpn_server_cert(self) -> Path:
        return self.ca_dir / "server-cert.pem"

    @property
    def vpn_server_key(self) -> Path:
        return self.ca_dir / "server-key.pem"

    @property
    def ovpn_auth_script(self) -> Path:
        return self.home / "scripts" / "ovpn-auth.py"

    @property
    def login_file(self) -> Path:
        return LOGIN_FILE


def _env(name: str, default: str = "") -> str:
    """Read ``SPARKY_<name>``, falling back to the pre-rename
    ``VPN_PANEL_<name>`` (a migrated panel.env may still carry the
    old keys; the installer translates them, but the fallback costs
    nothing and keeps a half-migrated install working)."""
    value = os.environ.get("SPARKY_" + name, "")
    if value:
        return value
    return os.environ.get("VPN_PANEL_" + name, default)


def get_settings() -> Settings:
    """Build Settings from the environment (with the defaults above)."""
    home = Path(_env("HOME", DEFAULT_HOME))
    return Settings(
        home=home,
        panel_port=int(_env("PORT", str(DEFAULT_PANEL_PORT))),
        panel_host=_env("HOST", DEFAULT_PANEL_HOST),
        domain=_env("DOMAIN", ""),
        subscription_host=_env("SUBSCRIPTION_HOST", ""),
        reality_sni=_env(
            "REALITY_SNI", DEFAULT_REALITY_SNI
        ),
        web_path=normalize_web_path(_env("WEB_PATH", "")),
    )


def get_settings_dict() -> dict:
    """Plain-dict view of the defaults, for templates / the settings page.

    ``domain`` and ``subscription_host`` are empty strings by default:
    empty means "no domain configured — use the request host / server IP".
    """
    s = get_settings()
    return {
        "home": str(s.home),
        "data_dir": str(s.data_dir),
        "db_path": str(s.db_path),
        "panel_port": s.panel_port,
        "panel_host": s.panel_host,
        "domain": s.domain,
        "subscription_host": s.subscription_host,
        "reality_sni": s.reality_sni,
        "web_path": s.web_path,
        "xray_config": str(s.xray_config),
        "singbox_config": str(s.singbox_config),
        "wg_config": str(s.wg_config),
        "ovpn_config": str(s.ovpn_config),
        "ocserv_config": str(s.ocserv_config),
        "ocserv_passwd": str(s.ocserv_passwd),
        "awg_config": str(s.awg_config),
        "swanctl_config": str(s.swanctl_config),
        "ca_cert": str(s.ca_cert),
        "ca_key": str(s.ca_key),
        "vpn_server_cert": str(s.vpn_server_cert),
        "vpn_server_key": str(s.vpn_server_key),
        "ovpn_auth_script": str(s.ovpn_auth_script),
        "versions_file": str(s.versions_file),
    }


def read_versions(settings: Settings | None = None) -> dict[str, str]:
    """Read ``versions.env`` (``KEY=value`` lines) if it exists.

    Returns ``{}`` when the file is absent — the installer writes it
    after fetching the latest stable cores; this module never invents
    a version number.
    """
    settings = settings or get_settings()
    versions: dict[str, str] = {}
    try:
        text = settings.versions_file.read_text(encoding="utf-8")
    except OSError:
        return versions
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        versions[key.strip()] = value.strip().strip('"').strip("'")
    return versions


# Module-level convenience accessors (imported by the rest of the app).
SETTINGS = get_settings()
DATA_DIR = SETTINGS.data_dir
DB_PATH = SETTINGS.db_path
PANEL_PORT = SETTINGS.panel_port
PANEL_HOST = SETTINGS.panel_host
XRAY_CONFIG = SETTINGS.xray_config
SINGBOX_CONFIG = SETTINGS.singbox_config
WG_CONFIG = SETTINGS.wg_config
OVPN_CONFIG = SETTINGS.ovpn_config
OCSERV_CONFIG = SETTINGS.ocserv_config
OCSERV_PASSWD = SETTINGS.ocserv_passwd
AWG_CONFIG = SETTINGS.awg_config
SWANCTL_CONFIG = SETTINGS.swanctl_config
CA_CERT = SETTINGS.ca_cert
CA_KEY = SETTINGS.ca_key
VPN_SERVER_CERT = SETTINGS.vpn_server_cert
VPN_SERVER_KEY = SETTINGS.vpn_server_key
OVPN_AUTH_SCRIPT = SETTINGS.ovpn_auth_script
DEFAULT_REALITY_SNI = SETTINGS.reality_sni
WEB_PATH = SETTINGS.web_path

__all__ = [
    "DEFAULT_HOME",
    "DEFAULT_PANEL_PORT",
    "DEFAULT_PANEL_HOST",
    "DEFAULT_REALITY_SNI",
    "LOGIN_FILE",
    "Settings",
    "normalize_web_path",
    "WEB_PATH",
    "get_settings",
    "get_settings_dict",
    "read_versions",
    "SETTINGS",
    "DATA_DIR",
    "DB_PATH",
    "PANEL_PORT",
    "PANEL_HOST",
    "XRAY_CONFIG",
    "SINGBOX_CONFIG",
    "WG_CONFIG",
    "OVPN_CONFIG",
    "OCSERV_CONFIG",
    "OCSERV_PASSWD",
    "AWG_CONFIG",
    "SWANCTL_CONFIG",
    "CA_CERT",
    "CA_KEY",
    "VPN_SERVER_CERT",
    "VPN_SERVER_KEY",
    "OVPN_AUTH_SCRIPT",
]
