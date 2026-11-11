"""Panel settings and paths.

All paths derive from ``VPN_PANEL_HOME`` (default ``/opt/vpn-panel``),
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

DEFAULT_HOME = "/opt/vpn-panel"
# Dev/run fallback only: the installer randomises the port on a fresh
# install (10000-60000) and passes it via VPN_PANEL_PORT / --port.
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
LOGIN_FILE = Path("/root/vpn-panel-login.txt")


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
    def login_file(self) -> Path:
        return LOGIN_FILE


def get_settings() -> Settings:
    """Build Settings from the environment (with the defaults above)."""
    home = Path(os.environ.get("VPN_PANEL_HOME", DEFAULT_HOME))
    return Settings(
        home=home,
        panel_port=int(os.environ.get("VPN_PANEL_PORT", DEFAULT_PANEL_PORT)),
        panel_host=os.environ.get("VPN_PANEL_HOST", DEFAULT_PANEL_HOST),
        domain=os.environ.get("VPN_PANEL_DOMAIN", ""),
        subscription_host=os.environ.get("VPN_PANEL_SUBSCRIPTION_HOST", ""),
        reality_sni=os.environ.get(
            "VPN_PANEL_REALITY_SNI", DEFAULT_REALITY_SNI
        ),
        web_path=normalize_web_path(os.environ.get("VPN_PANEL_WEB_PATH", "")),
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
]
