"""IKEv2 — Phase 1 status display only (DESIGN.md §5.4).

The panel does NOT manage IKEv2 / strongSwan. James already owns
Ikev2-manager (v1.3.0); the panel only shows whether it is present
and running, and deep-links to it. No shared user DB, no writes into
Ikev2-manager's config in Phase 1. UDP 500/4500 are reserved so the
panel's own port plan never clashes with it.
"""

from __future__ import annotations

import os
import subprocess

# Where Ikev2-manager lives / what proves strongSwan is installed.
IKEV2_MANAGER_DIR = "/opt/ikev2"
IPSEC_BINARY = "/usr/local/sbin/ipsec"

# Ports IKEv2 (strongSwan) needs — the panel must never assign them to
# its own inbounds.
RESERVED_PORTS = (500, 4500)


def ikev2_reserved_ports() -> tuple[int, int]:
    """UDP ports reserved for IKEv2: ``(500, 4500)``."""
    return RESERVED_PORTS


def _is_strongswan_active() -> bool | None:
    """True if ``systemctl is-active strongswan`` says ``active``.

    Returns ``None`` (unknown) on any failure — missing systemctl,
    timeout, non-zero exit with an unrecognised state — never raises.
    """
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "strongswan"],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    state = proc.stdout.strip()
    if state == "active":
        return True
    if state in ("inactive", "failed", "activating"):
        return False
    return None


def get_ikev2_status() -> dict:
    """Phase 1 IKEv2 status: presence + service state, nothing more.

    Returns ``{"installed": bool, "running": bool | None,
    "manager_hint": str, "deep_link": "/ikev2"}``. ``running`` is
    ``None`` when it cannot be determined. Never raises.
    """
    installed = os.path.exists(IKEV2_MANAGER_DIR) or os.path.exists(IPSEC_BINARY)
    if installed:
        hint = (
            "Managed by Ikev2-manager — use its CLI/TUI to add or "
            "remove IKEv2 users; this panel only shows its status."
        )
    else:
        hint = (
            "Ikev2-manager not detected on this server. Install it "
            "separately to offer IKEv2; the panel reserves UDP "
            "500/4500 for it."
        )
    return {
        "installed": installed,
        "running": _is_strongswan_active() if installed else None,
        "manager_hint": hint,
        "deep_link": "/ikev2",
    }


__all__ = ["get_ikev2_status", "ikev2_reserved_ports", "RESERVED_PORTS"]
