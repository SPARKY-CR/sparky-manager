"""``vpn-panel`` command-line interface (DESIGN.md §8).

Usable as ``python -m app.panel_cli <command>`` from the install dir,
and installed as the ``vpn-panel`` wrapper by install.sh::

    vpn-panel info | status | restart | update-cores | backup <path>

Every command is tolerant of a missing service / file: it prints what
it knows and returns a non-zero exit code instead of crashing. The
admin password is NEVER printed from anywhere except the installer's
login box (``/root/vpn-panel-login.txt``); it is not stored in the DB
in plaintext and cannot be recovered from anywhere else.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from app import config as _config

LOGIN_FILE = Path("/root/vpn-panel-login.txt")
DEFAULT_ADMIN_USERNAME = "admin"

# Services the panel owns / depends on (checked and restarted here).
PANEL_SERVICES = ("vpn-panel", "xray", "sing-box")
# wg-quick is a template unit (wg-quick@wg0); checked by status only.
WG_SERVICE = "wg-quick@wg0"


def _run_systemctl(*args: str) -> tuple[bool, str]:
    """Run ``systemctl <args>``; returns ``(ok, stripped stdout)``.

    ``ok`` is False on any failure (missing systemctl, timeout, non-zero
    exit) — callers decide how to report it; nothing here raises.
    """
    try:
        proc = subprocess.run(
            ["systemctl", *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, "unknown"
    return proc.returncode == 0, proc.stdout.strip() or "unknown"


# ---------------------------------------------------------------------------
# info — reprint the login box
# ---------------------------------------------------------------------------


def cmd_info() -> int:
    """Print the panel URL + admin username; the password comes ONLY
    from ``/root/vpn-panel-login.txt`` when that file exists.

    The password is generated once at install, saved to that root-only
    file, and never re-randomised — so if the file is gone, the honest
    answer is that the password is only in that file (reinstall /
    reset it via the installer), not a guessed or regenerated one.
    """
    settings = _config.get_settings()
    scheme = "https"
    host = settings.domain or "<server-IP>"
    print(f"Panel:    {scheme}://{host}:{settings.panel_port}")
    print(f"Username: {DEFAULT_ADMIN_USERNAME}")
    if LOGIN_FILE.exists():
        try:
            print(LOGIN_FILE.read_text(encoding="utf-8").rstrip())
        except OSError:
            print("password stored only in /root/vpn-panel-login.txt")
    else:
        print("Password: password stored only in /root/vpn-panel-login.txt")
    return 0


# ---------------------------------------------------------------------------
# status — service states
# ---------------------------------------------------------------------------


def cmd_status() -> int:
    """Print ``active``/``inactive``/``unknown`` for each service.

    Tolerant: a service that cannot be queried prints ``unknown`` and
    the command still exits 0 unless a service is definitively not
    active (then exit 1, so scripts can test it).
    """
    all_active = True
    for service in (*PANEL_SERVICES, WG_SERVICE):
        ok, state = _run_systemctl("is-active", service)
        print(f"{service}: {state}")
        if state != "active":
            all_active = False
    return 0 if all_active else 1


# ---------------------------------------------------------------------------
# restart — restart the panel + cores
# ---------------------------------------------------------------------------


def cmd_restart() -> int:
    """``systemctl restart vpn-panel xray sing-box`` (tolerant).

    Prints a line per service; returns 0 only if every restart
    succeeded, 1 otherwise — but never raises.
    """
    failed: list[str] = []
    for service in PANEL_SERVICES:
        ok, _ = _run_systemctl("restart", service)
        if ok:
            print(f"{service}: restarted")
        else:
            print(f"{service}: restart FAILED", file=sys.stderr)
            failed.append(service)
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# backup — tarball of the data dir + both core configs
# ---------------------------------------------------------------------------


def cmd_backup(path: str | None = None) -> int:
    """Create a ``.tar.gz`` of the data dir + both ``config.json`` files.

    The DB is the source of truth, so restoring the DB + re-rendering
    is enough — the configs are included for convenience only.
    Default path: ``/root/vpn-panel-backup-<UTC timestamp>.tar.gz``.
    """
    settings = _config.get_settings()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = Path(path) if path else Path(f"/root/vpn-panel-backup-{stamp}.tar.gz")
    sources: list[Path] = []
    if settings.data_dir.exists():
        sources.append(settings.data_dir)
    for cfg in (settings.xray_config, settings.singbox_config):
        if cfg.exists():
            sources.append(cfg)
    if not sources:
        print("nothing to back up (no data dir, no core configs)", file=sys.stderr)
        return 1
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tar:
            for src in sources:
                tar.add(src, arcname=src.name)
    except (OSError, tarfile.TarError) as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"backup written to {dest}")
    return 0


# ---------------------------------------------------------------------------
# update-cores — NOT implemented in the MVP
# ---------------------------------------------------------------------------


def cmd_update_cores() -> int:
    """Deliberately unimplemented in the MVP (exit 2).

    Downloading and swapping core binaries is install.sh's job, with
    its SHA256 verification and config validation; a half-implemented
    updater must never take the server down unattended (DESIGN.md §7).
    """
    print(
        "update-cores is not implemented in the MVP — "
        "run install.sh again to update Xray-core / sing-box.",
        file=sys.stderr,
    )
    return 2


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpn-panel",
        description="vpn-panel command-line interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="print the panel URL and login info")
    sub.add_parser("status", help="show panel / core / WireGuard service states")
    sub.add_parser("restart", help="restart the panel, Xray and sing-box")
    sub.add_parser(
        "update-cores",
        help="update Xray-core / sing-box (not implemented in the MVP)",
    )
    backup = sub.add_parser(
        "backup", help="tarball the data dir + both core configs"
    )
    backup.add_argument(
        "path",
        nargs="?",
        default=None,
        help="destination .tar.gz (default: /root/vpn-panel-backup-<ts>.tar.gz)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit code (0 on success)."""
    args = build_parser().parse_args(argv)
    if args.command == "info":
        return cmd_info()
    if args.command == "status":
        return cmd_status()
    if args.command == "restart":
        return cmd_restart()
    if args.command == "backup":
        return cmd_backup(args.path)
    if args.command == "update-cores":
        return cmd_update_cores()
    return 2  # unreachable: argparse enforces a subcommand


if __name__ == "__main__":
    raise SystemExit(main())
