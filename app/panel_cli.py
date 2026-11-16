"""``sparky-manager`` command-line interface (DESIGN.md §8).

Usable as ``python -m app.panel_cli <command>`` from the install dir,
and installed as the ``sparky-manager`` wrapper by install.sh::

    sparky-manager info | status | restart | backup <path> | restore <path>
    sparky-manager users | user-add <name> | user-disable <name> | user-enable <name>
    sparky-manager inbounds | health | totp-disable

Every command is tolerant of a missing service / file: it prints what
it knows and returns a non-zero exit code instead of crashing. The
admin password is NEVER printed from anywhere except the installer's
login box (``/root/sparky-manager-login.txt``); it is not stored in the DB
in plaintext and cannot be recovered from anywhere else.

``update-cores`` was removed in Phase C (item 23): core updates are
install.sh's job, with its SHA256 verification and config
validation — a second updater would duplicate that and could
diverge (DESIGN.md §8). Re-run install.sh to update the cores.
"""

from __future__ import annotations

import argparse
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import config as _config

LOGIN_FILE = Path("/root/sparky-manager-login.txt")
DEFAULT_ADMIN_USERNAME = "admin"

# Services the panel owns / depends on (checked and restarted here).
PANEL_SERVICES = ("sparky-manager", "xray", "sing-box")
# wg-quick is a template unit (wg-quick@wg0); checked by status only.
WG_SERVICE = "wg-quick@wg0"
# v12 protocols: only checked/restarted when their unit exists (the
# package may not be installed — e.g. AmneziaWG on a kernel without
# the module — and status must not fail for a service that was never
# installed).
VPN_SERVICES = (
    "openvpn-server@sparky-manager",
    "ocserv",
    "strongswan",
    "awg-quick@awg0",
)


def _unit_exists(service: str) -> bool:
    """True when systemd knows the unit (``systemctl cat`` succeeds)."""
    ok, _ = _run_systemctl("cat", service)
    return ok


def _run_systemctl(*args: str) -> tuple[bool, str]:
    """Run ``systemctl <args>``; returns ``(ok, stripped stdout)``.

    ``ok`` is False on any failure (missing systemctl, timeout, non-zero
    exit) — callers decide how to report it; nothing here raises.

    ``restart`` / ``stop`` / ``start`` go through ``sudo -n`` when sudo
    exists: the CLI is usually run as root (``sudo sparky-manager
    ...``), but the panel user may run it too, and the installer
    grants that user NOPASSWD sudo for exactly these restarts.
    Read-only queries (``is-active``, ``status``) stay plain — they
    work unprivileged. Note the sudoers block covers ``restart`` for
    the panel but not ``stop``/``start`` — so ``restore`` (which
    stops the panel) needs root; it fails honestly when it cannot
    stop the service.
    """
    argv = ["systemctl", *args]
    if args and args[0] in ("restart", "stop", "start") and shutil.which("sudo"):
        argv = ["sudo", "-n", *argv]
    try:
        proc = subprocess.run(
            argv,
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
    from ``/root/sparky-manager-login.txt`` when that file exists.

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
            print("password stored only in /root/sparky-manager-login.txt")
    else:
        print("Password: password stored only in /root/sparky-manager-login.txt")
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
    for service in VPN_SERVICES:
        if not _unit_exists(service):
            continue
        ok, state = _run_systemctl("is-active", service)
        print(f"{service}: {state}")
        if state != "active":
            all_active = False
    return 0 if all_active else 1


# ---------------------------------------------------------------------------
# restart — restart the panel + cores
# ---------------------------------------------------------------------------


def cmd_restart() -> int:
    """``systemctl restart sparky-manager xray sing-box`` (tolerant).

    Prints a line per service; returns 0 only if every restart
    succeeded, 1 otherwise — but never raises. The v12 services are
    restarted too when their unit exists; a missing/broken one does
    not fail the core restart.
    """
    failed: list[str] = []
    for service in PANEL_SERVICES:
        ok, _ = _run_systemctl("restart", service)
        if ok:
            print(f"{service}: restarted")
        else:
            print(f"{service}: restart FAILED", file=sys.stderr)
            failed.append(service)
    for service in VPN_SERVICES:
        if not _unit_exists(service):
            continue
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
    Default path: ``/root/sparky-manager-backup-<UTC timestamp>.tar.gz``.
    """
    settings = _config.get_settings()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = Path(path) if path else Path(f"/root/sparky-manager-backup-{stamp}.tar.gz")
    sources: list[Path] = []
    if settings.data_dir.exists():
        sources.append(settings.data_dir)
    for cfg in (
        settings.xray_config,
        settings.singbox_config,
        settings.wg_config,
        settings.ovpn_config,
        settings.ocserv_config,
        settings.ocserv_passwd,
        settings.awg_config,
        settings.swanctl_config,
    ):
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
# DB helpers (Phase C item 23)
# ---------------------------------------------------------------------------


def _open_db():
    """Open a session on the panel DB.

    Reuses the already-bound engine when one exists (tests bind
    SessionLocal to a tmp DB); a bare init_db() would create the
    default-path engine and rebind SessionLocal to it.
    """
    from app import db as db_mod

    bound = db_mod.SessionLocal.kw.get("bind")
    if bound is not None:
        db_mod.init_db(bound)
    else:
        db_mod.init_db()
    return db_mod.SessionLocal()


def _rerender(db) -> list[str]:
    """Re-render configs via ``main`` (lazy seam — same as the one in
    :mod:`app.routes.users`, so the CLI never imports the FastAPI
    app at module load)."""
    from app.main import rerender_configs as _main_rerender

    return _main_rerender(db)


def _report_rerender_errors(errors: list[str], command: str) -> int:
    """Report re-render errors; return 1 when any is fatal, else 0.

    The renderers mark routine omissions with a ``warning:`` prefix
    (``sing-box warning: ... no usable clients, omitted``,
    ``... no TLS certificate configured, omitted`` — the only
    ``warning:`` strings the renderers emit, see main.py): an
    inbound with no usable clients after disabling its last user
    is not a failure of the disable. Anything else (a config write
    failure, a validation failure, a restart failure) is fatal.
    """
    warnings = [e for e in errors if "warning:" in e]
    fatal = [e for e in errors if "warning:" not in e]
    for warning in warnings:
        print(f"{command}: re-render warning: {warning}", file=sys.stderr)
    if fatal:
        print(
            f"{command}: config re-render failed: " + "; ".join(fatal),
            file=sys.stderr,
        )
        return 1
    return 0


def _format_bytes(value: int) -> str:
    """A byte count as ``123 B`` / ``4.5 MiB`` / ``2.0 GiB``."""
    number = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(number)} B"
            return f"{number:.1f} {unit}"
        number /= 1024
    return f"{int(number)} B"  # unreachable


# ---------------------------------------------------------------------------
# users — list users
# ---------------------------------------------------------------------------


def cmd_users() -> int:
    """List users: name, state, traffic used/limit, expiry, clients."""
    try:
        db = _open_db()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"users: cannot open the panel database: {exc}", file=sys.stderr)
        return 1
    try:
        from app.models import Client, User

        users = db.query(User).order_by(User.id).all()
        if not users:
            print("no users")
            return 0
        for user in users:
            clients = (
                db.query(Client).filter(Client.user_id == user.id).count()
            )
            state = "enabled" if user.enabled else "disabled"
            limit = (
                _format_bytes(user.traffic_limit_bytes)
                if user.traffic_limit_bytes is not None
                else "unlimited"
            )
            expiry = (
                user.expires_at.date().isoformat()
                if user.expires_at is not None
                else "never"
            )
            print(
                f"{user.name} [{state}] {clients} clients, "
                f"used {_format_bytes(user.traffic_used_bytes)} / {limit}, "
                f"expires {expiry}"
            )
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"users failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


# ---------------------------------------------------------------------------
# user-add — create a user (clients on all enabled inbounds)
# ---------------------------------------------------------------------------


def cmd_user_add(
    name: str,
    traffic_limit_gb: float | None = None,
    expires_days: int | None = None,
) -> int:
    """Create a user with clients on all enabled inbounds (the web
    add-user flow, without a plan — same name rule, same duplicate
    check, same client creation, same re-render). Prints the
    subscription URL when a host is configured."""
    from app import webcommon as webcommon_mod
    from app.models import User

    name = (name or "").strip()
    if not webcommon_mod.NAME_RE.match(name):
        print(
            "user-add: invalid name (1-64 letters, digits, _ or -)",
            file=sys.stderr,
        )
        return 1
    traffic_limit_bytes = None
    if traffic_limit_gb is not None:
        if traffic_limit_gb <= 0:
            print("user-add: --traffic-limit-gb must be positive",
                  file=sys.stderr)
            return 1
        traffic_limit_bytes = int(traffic_limit_gb * 1024**3)
    expires_at = None
    if expires_days is not None:
        if expires_days <= 0:
            print("user-add: --expires-days must be positive",
                  file=sys.stderr)
            return 1
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=expires_days
        )
    try:
        db = _open_db()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"user-add: cannot open the panel database: {exc}",
              file=sys.stderr)
        return 1
    try:
        if db.query(User).filter(User.name == name).first() is not None:
            print(f"user-add: a user named {name!r} already exists",
                  file=sys.stderr)
            return 1
        user = User(
            name=name,
            enabled=True,
            traffic_limit_bytes=traffic_limit_bytes,
            expires_at=expires_at,
        )
        db.add(user)
        db.flush()  # the id is needed for client creation
        webcommon_mod._create_clients_for_user(db, user)
        db.commit()
        client_count = len(user.clients)
        errors = _rerender(db)
        settings = webcommon_mod.get_settings(db)
        host = (settings.get("subscription_host") or "").strip() or (
            settings.get("domain") or ""
        ).strip()
        cfg = _config.get_settings()
        print(f"user {name!r} created with {client_count} clients")
        if host:
            print(
                "subscription: "
                f"https://{host}:{cfg.panel_port}{cfg.web_path}"
                f"/sub/{user.sub_token}"
            )
        else:
            print(
                "subscription: no host configured "
                "(set Subscription host in panel Settings); "
                f"token {user.sub_token}"
            )
        return _report_rerender_errors(errors, "user-add")
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        db.rollback()
        print(f"user-add failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


# ---------------------------------------------------------------------------
# user-disable / user-enable — toggle a user (with re-render)
# ---------------------------------------------------------------------------


def _set_user_enabled(name: str, enabled: bool) -> int:
    """Shared body for user-disable / user-enable (idempotent)."""
    from app.models import User

    verb = "enable" if enabled else "disable"
    state = "enabled" if enabled else "disabled"
    try:
        db = _open_db()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"user-{verb}: cannot open the panel database: {exc}",
              file=sys.stderr)
        return 1
    try:
        user = db.query(User).filter(User.name == name).first()
        if user is None:
            print(f"user-{verb}: no user named {name!r}", file=sys.stderr)
            return 1
        if user.enabled == enabled:
            print(f"user {name!r} is already {state}")
            return 0
        user.enabled = enabled
        db.commit()
        print(f"user {name!r} {state}")
        errors = _rerender(db)
        return _report_rerender_errors(errors, f"user-{verb}")
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        db.rollback()
        print(f"user-{verb} failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


def cmd_user_disable(name: str) -> int:
    """Disable a user (its clients drop out of the configs)."""
    return _set_user_enabled(name, False)


def cmd_user_enable(name: str) -> int:
    """Enable a user (its clients come back into the configs)."""
    return _set_user_enabled(name, True)


# ---------------------------------------------------------------------------
# inbounds — list inbounds
# ---------------------------------------------------------------------------


def cmd_inbounds() -> int:
    """List inbounds: tag, protocol, port, state, client count."""
    try:
        db = _open_db()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"inbounds: cannot open the panel database: {exc}",
              file=sys.stderr)
        return 1
    try:
        from app.models import Client, Inbound

        inbounds = db.query(Inbound).order_by(Inbound.port).all()
        if not inbounds:
            print("no inbounds")
            return 0
        for inbound in inbounds:
            clients = (
                db.query(Client)
                .filter(Client.inbound_id == inbound.id)
                .count()
            )
            state = "enabled" if inbound.enabled else "disabled"
            print(
                f"{inbound.tag} {inbound.protocol} port {inbound.port} "
                f"[{state}] {clients} clients"
            )
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"inbounds failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


# ---------------------------------------------------------------------------
# restore — restore from a backup ZIP or bare .db (needs root)
# ---------------------------------------------------------------------------


def cmd_restore(path: str, preserve_identity: bool = True) -> int:
    """Restore the panel DB from a backup file (ZIP or bare .db).

    Mirrors the web restore (``POST /settings/restore``): validate
    first, back up the current DB, swap atomically, re-apply this
    machine's identity settings (default ON — a backup from another
    install must not take over this panel's domain, bot or webhook
    secret), audit, re-render. The panel is stopped before the swap
    (it holds the engine + WAL open) and started again after — so
    this command needs root (``sudo sparky-manager restore ...``);
    a failed stop aborts before anything is touched.
    """
    from app import backup as backup_mod
    from app import db as db_mod
    from app import webcommon as webcommon_mod
    from app.models import Admin

    src = Path(path)
    if not src.exists():
        print(f"restore: no such file: {path}", file=sys.stderr)
        return 1
    try:
        data = src.read_bytes()
    except OSError as exc:
        print(f"restore: cannot read {path}: {exc}", file=sys.stderr)
        return 1
    if len(data) > backup_mod.BACKUP_MAX_BYTES:
        print("restore: backup is over 200 MiB", file=sys.stderr)
        return 1
    try:
        db = _open_db()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"restore: cannot open the panel database: {exc}",
              file=sys.stderr)
        return 1
    try:
        bind = db.get_bind()
        db_path = Path(str(bind.url.database)) if bind is not None else None
        if db_path is None or not db_path.exists():
            print("restore: cannot locate the live database file",
                  file=sys.stderr)
            return 1
        identity_snapshot: dict[str, str] = {}
        if preserve_identity:
            identity_snapshot = backup_mod.snapshot_identity_settings(
                webcommon_mod.get_settings(db)
            )
        with tempfile.TemporaryDirectory(prefix="sparky-restore-") as tmp:
            try:
                info = backup_mod.validate_backup_bytes(data, tmp)
            except backup_mod.BackupError as exc:
                print(f"restore: invalid backup: {exc.detail or exc.code}",
                      file=sys.stderr)
                return 1
            try:
                pre_backup = backup_mod.backup_current_db(
                    db_path, _config.DATA_DIR / "backups"
                )
            except Exception as exc:  # noqa: BLE001 — CLI must not crash
                print(f"restore: pre-restore backup failed: {exc}",
                      file=sys.stderr)
                return 1
            # Stop the panel BEFORE the swap: it holds the engine
            # and the WAL open. A failed stop aborts the restore —
            # nothing has been touched yet.
            ok, _state = _run_systemctl("stop", "sparky-manager")
            if not ok:
                print(
                    "restore: could not stop sparky-manager — "
                    "restore needs root (run with sudo)",
                    file=sys.stderr,
                )
                return 1
            try:
                db.close()
                db_mod.dispose_engine()
                backup_mod.swap_db_file(db_path, info.db_file)
                db_mod.reset_engine()
                fresh = db_mod.SessionLocal()
                try:
                    if preserve_identity:
                        backup_mod.reapply_identity_settings(
                            fresh, identity_snapshot
                        )
                    admin = fresh.query(Admin).order_by(Admin.id).first()
                    webcommon_mod._audit(
                        fresh,
                        admin.id if admin is not None else None,
                        "settings.restore",
                        f"CLI restore: {info.users} users, "
                        f"{info.inbounds} inbounds",
                    )
                    errors = _rerender(fresh)
                finally:
                    fresh.close()
            except Exception as exc:  # noqa: BLE001 — CLI must not crash
                print(f"restore failed: {exc}", file=sys.stderr)
                _run_systemctl("start", "sparky-manager")
                return 1
            ok, _state = _run_systemctl("start", "sparky-manager")
            if not ok:
                print(
                    "restore: the database was restored but the panel "
                    "did not start — check systemctl status "
                    "sparky-manager",
                    file=sys.stderr,
                )
                return 1
            print(
                f"restored {info.users} users, {info.inbounds} inbounds "
                f"from {path}"
            )
            print(f"pre-restore backup: {pre_backup}")
            return _report_rerender_errors(errors, "restore")
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            db.close()
        except Exception:  # noqa: BLE001 — already closed is fine
            pass
    return 0


# ---------------------------------------------------------------------------
# health — DB + panel + services in one check
# ---------------------------------------------------------------------------


def cmd_health() -> int:
    """Health check: the DB answers, the panel's /health endpoint
    answers, and every managed service is active. One line each;
    exit 0 only when everything is healthy (so scripts can test
    it). The /health probe goes to loopback over HTTPS with an
    unverified context (the panel's certificate is self-signed /
    an IP cert — verification would fail by design, and this is a
    local liveness probe, not an identity check)."""
    healthy = True
    # 1. The database answers.
    try:
        db = _open_db()
        try:
            from app.models import User

            count = db.query(User).count()
        finally:
            db.close()
        print(f"database: ok ({count} users)")
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"database: FAILED ({exc})", file=sys.stderr)
        healthy = False
    # 2. The panel's /health endpoint answers on loopback.
    cfg = _config.get_settings()
    url = f"https://127.0.0.1:{cfg.panel_port}{cfg.web_path}/health"
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, context=context, timeout=5) as resp:
            body = resp.read()
        if resp.status == 200 and b'"ok"' in body:
            print("panel: ok")
        else:
            print(f"panel: FAILED (HTTP {resp.status})", file=sys.stderr)
            healthy = False
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"panel: FAILED ({exc})", file=sys.stderr)
        healthy = False
    # 3. Every managed service is active.
    for service in (*PANEL_SERVICES, WG_SERVICE):
        _ok, state = _run_systemctl("is-active", service)
        print(f"{service}: {state}")
        if state != "active":
            healthy = False
    for service in VPN_SERVICES:
        if not _unit_exists(service):
            continue
        _ok, state = _run_systemctl("is-active", service)
        print(f"{service}: {state}")
        if state != "active":
            healthy = False
    return 0 if healthy else 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def cmd_totp_disable() -> int:
    """Disable TOTP 2FA (Phase B item 13 lockout recovery).

    The ONLY recovery when the admin loses both the authenticator
    device and the recovery codes: it needs server SSH (root), so a
    stolen panel session cannot use it. Prints whether 2FA was on.
    """
    from app import totp as totp_mod

    try:
        db = _open_db()
        try:
            was_enabled = totp_mod.disable_totp(db)
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001 — CLI must not crash
        print(f"totp-disable failed: {exc}", file=sys.stderr)
        return 1
    if was_enabled:
        print("Two-factor authentication disabled.")
    else:
        print("Two-factor authentication was not enabled.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sparky-manager",
        description="sparky-manager command-line interface",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "totp-disable",
        help="disable TOTP 2FA (lockout recovery; needs server access)",
    )
    sub.add_parser("info", help="print the panel URL and login info")
    sub.add_parser("status", help="show panel / core / WireGuard service states")
    sub.add_parser("restart", help="restart the panel, Xray and sing-box")
    sub.add_parser("users", help="list users")
    user_add = sub.add_parser(
        "user-add", help="create a user (clients on all enabled inbounds)"
    )
    user_add.add_argument("name", help="user name (1-64 letters, digits, _ or -)")
    user_add.add_argument(
        "--traffic-limit-gb",
        type=float,
        default=None,
        help="traffic limit in GiB (default: unlimited)",
    )
    user_add.add_argument(
        "--expires-days",
        type=int,
        default=None,
        help="expiry in days from now (default: never)",
    )
    user_disable = sub.add_parser(
        "user-disable", help="disable a user (its clients drop out)"
    )
    user_disable.add_argument("name", help="user name")
    user_enable = sub.add_parser(
        "user-enable", help="enable a user (its clients come back)"
    )
    user_enable.add_argument("name", help="user name")
    sub.add_parser("inbounds", help="list inbounds")
    sub.add_parser(
        "health",
        help="check the DB, the panel /health endpoint and all services",
    )
    backup = sub.add_parser(
        "backup", help="tarball the data dir + both core configs"
    )
    backup.add_argument(
        "path",
        nargs="?",
        default=None,
        help="destination .tar.gz (default: /root/sparky-manager-backup-<ts>.tar.gz)",
    )
    restore = sub.add_parser(
        "restore",
        help="restore the panel DB from a backup ZIP or bare .db (needs root)",
    )
    restore.add_argument("path", help="backup file (.zip or .db)")
    restore.add_argument(
        "--no-preserve-identity",
        action="store_true",
        help="import the backup's machine identity too (domain, bot, "
        "webhook secret) instead of keeping this machine's",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit code (0 on success)."""
    args = build_parser().parse_args(argv)
    if args.command == "totp-disable":
        return cmd_totp_disable()
    if args.command == "info":
        return cmd_info()
    if args.command == "status":
        return cmd_status()
    if args.command == "restart":
        return cmd_restart()
    if args.command == "backup":
        return cmd_backup(args.path)
    if args.command == "restore":
        return cmd_restore(args.path, not args.no_preserve_identity)
    if args.command == "users":
        return cmd_users()
    if args.command == "user-add":
        return cmd_user_add(
            args.name, args.traffic_limit_gb, args.expires_days
        )
    if args.command == "user-disable":
        return cmd_user_disable(args.name)
    if args.command == "user-enable":
        return cmd_user_enable(args.name)
    if args.command == "inbounds":
        return cmd_inbounds()
    if args.command == "health":
        return cmd_health()
    return 2  # unreachable: argparse enforces a subcommand


if __name__ == "__main__":
    raise SystemExit(main())
