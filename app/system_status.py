"""Server status — what the panel user can observe WITHOUT new
sudoers rules (Phase 3).

Sources (all unprivileged):
- CPU load, RAM, uptime: ``/proc/loadavg``, ``/proc/meminfo``,
  ``/proc/uptime`` (plain files, world-readable).
- Disk: :func:`shutil.disk_usage` on the panel data dir.
- Service state: ONE unprivileged ``systemctl is-active <units...>``
  call (querying unit state needs no privilege on a standard systemd
  install — no sudo, no new sudoers rule). When systemd is not
  available (or the call fails), the fallback is a ``/proc`` scan for
  the service's process name, or ``/sys/class/net/<iface>`` for the
  kernel interfaces (WireGuard / AmneziaWG have no daemon process).

Honesty rule: a service whose state cannot be determined is
``"unknown"``, never "stopped" — "stopped" is only reported when
systemd positively says the unit is inactive/failed. Every collector
is wrapped so a missing ``/proc`` file (or a non-Linux host) yields
``None`` fields instead of an exception: the settings page must never
break because status collection failed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

# (display name, systemd unit, process comm names, network interface)
SERVICES: tuple[tuple[str, str, tuple[str, ...], Optional[str]], ...] = (
    ("xray", "xray", ("xray",), None),
    ("sing-box", "sing-box", ("sing-box",), None),
    ("wireguard", "wg-quick@wg0", (), "wg0"),
    ("amneziawg", "awg-quick@awg0", (), "awg0"),
    ("openvpn", "openvpn-server@sparky-manager", ("openvpn",), None),
    ("openconnect", "ocserv", ("ocserv",), None),
    ("ikev2", "strongswan", ("charon",), None),
)

STATUS_RUNNING = "running"
STATUS_STOPPED = "stopped"
STATUS_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# /proc readers (paths injectable for tests)
# ---------------------------------------------------------------------------


def read_loadavg(proc_path: str | Path = "/proc/loadavg") -> Optional[tuple[float, float, float]]:
    """1/5/15-minute load averages, or None when unreadable."""
    try:
        parts = Path(proc_path).read_text(encoding="utf-8").split()
        return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, ValueError, IndexError):
        return None


def read_meminfo(proc_path: str | Path = "/proc/meminfo") -> Optional[dict[str, int]]:
    """``{"total": bytes, "available": bytes}`` or None when unreadable."""
    try:
        values: dict[str, int] = {}
        for line in Path(proc_path).read_text(encoding="utf-8").splitlines():
            key, _, rest = line.partition(":")
            key = key.strip()
            if key in ("MemTotal", "MemAvailable"):
                # Values are in kB ("16384000 kB").
                values[key] = int(rest.strip().split()[0]) * 1024
        if "MemTotal" not in values:
            return None
        return {
            "total": values["MemTotal"],
            "available": values.get("MemAvailable", 0),
        }
    except (OSError, ValueError, IndexError):
        return None


def read_uptime(proc_path: str | Path = "/proc/uptime") -> Optional[float]:
    """Uptime in seconds, or None when unreadable."""
    try:
        return float(Path(proc_path).read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return None


def format_uptime(seconds: Optional[float]) -> str:
    """Human uptime: ``"3d 04:12"``, ``"05:37"`` or ``"—"``."""
    if seconds is None or seconds < 0:
        return "—"
    total_minutes = int(seconds // 60)
    days, minutes = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}"
    return f"{hours:02d}:{minutes:02d}"


def disk_usage(path: str | Path) -> Optional[dict[str, int]]:
    """``{"total": bytes, "used": bytes, "free": bytes}`` or None."""
    try:
        usage = shutil.disk_usage(str(path))
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Service state
# ---------------------------------------------------------------------------


def _comm_names(proc_root: str | Path = "/proc") -> set[str]:
    """Set of process names (``/proc/<pid>/comm``), best effort."""
    names: set[str] = set()
    try:
        entries = list(Path(proc_root).iterdir())
    except OSError:
        return names
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            names.add((entry / "comm").read_text(encoding="utf-8").strip())
        except OSError:
            continue
    return names


def _systemctl_is_active(
    units: list[str],
    runner: Optional[Callable[..., object]] = None,
    timeout: int = 5,
) -> Optional[dict[str, str]]:
    """One ``systemctl is-active`` call for all units.

    Returns ``{unit: state}`` (``"active"`` / ``"inactive`` / ``"failed"``
    / ...) or None when systemctl is missing or the call fails. The
    exit code is ignored on purpose: it is non-zero whenever ANY unit
    is inactive, while stdout still carries every unit's state.
    """
    run = runner or subprocess.run
    try:
        proc = run(
            ["systemctl", "is-active", *units],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    stdout = getattr(proc, "stdout", "") or ""
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != len(units):
        return None
    return dict(zip(units, lines))


def service_states(
    proc_root: str | Path = "/proc",
    sys_root: str | Path = "/sys",
    runner: Optional[Callable[..., object]] = None,
) -> dict[str, str]:
    """``{service key: "running" | "stopped" | "unknown"}``.

    Strategy per service: the systemd answer wins when available
    (``active`` → running, ``inactive``/``failed`` → stopped, any
    other state → unknown); otherwise the ``/proc`` process scan (or
    the interface's presence under ``/sys/class/net``) decides
    running vs unknown.
    """
    units = [unit for _key, unit, _procs, _iface in SERVICES]
    systemd = _systemctl_is_active(units, runner=runner)
    comms: Optional[set[str]] = None
    result: dict[str, str] = {}
    for key, unit, procs, iface in SERVICES:
        if systemd is not None:
            state = systemd.get(unit, "")
            if state == "active":
                result[key] = STATUS_RUNNING
                continue
            if state in ("inactive", "failed"):
                result[key] = STATUS_STOPPED
                continue
            result[key] = STATUS_UNKNOWN
            continue
        # No systemd answer: fall back to /proc / /sys.
        if iface is not None:
            if Path(sys_root, "class", "net", iface).exists():
                result[key] = STATUS_RUNNING
            else:
                result[key] = STATUS_UNKNOWN
            continue
        if comms is None:
            comms = _comm_names(proc_root)
        result[key] = (
            STATUS_RUNNING if any(p in comms for p in procs) else STATUS_UNKNOWN
        )
    return result


def collect_server_status(
    data_dir: Optional[str | Path] = None,
    proc_root: str | Path = "/proc",
    sys_root: str | Path = "/sys",
    runner: Optional[Callable[..., object]] = None,
) -> dict:
    """Full status snapshot. Never raises; unavailable values are None."""
    try:
        load = read_loadavg(Path(proc_root) / "loadavg")
    except Exception:  # noqa: BLE001 — status must never break the page
        load = None
    try:
        mem = read_meminfo(Path(proc_root) / "meminfo")
    except Exception:  # noqa: BLE001
        mem = None
    try:
        uptime = read_uptime(Path(proc_root) / "uptime")
    except Exception:  # noqa: BLE001
        uptime = None
    try:
        disk = disk_usage(data_dir) if data_dir is not None else None
    except Exception:  # noqa: BLE001
        disk = None
    try:
        services = service_states(proc_root=proc_root, sys_root=sys_root, runner=runner)
    except Exception:  # noqa: BLE001
        services = {key: STATUS_UNKNOWN for key, *_ in SERVICES}
    return {
        "load": load,
        "memory": mem,
        "uptime_seconds": uptime,
        "uptime": format_uptime(uptime),
        "disk": disk,
        "services": services,
    }


__all__ = [
    "SERVICES",
    "STATUS_RUNNING",
    "STATUS_STOPPED",
    "STATUS_UNKNOWN",
    "read_loadavg",
    "read_meminfo",
    "read_uptime",
    "format_uptime",
    "disk_usage",
    "service_states",
    "collect_server_status",
]
