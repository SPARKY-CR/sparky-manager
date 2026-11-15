"""Backup / restore of the panel state (Phase 3).

A backup is a ZIP with two members:
- ``panel.db`` — a consistent SQLite snapshot taken with the
  ``sqlite3`` backup API (safe to copy while the panel is running).
- ``meta.json`` — ``{schema_version, created_at, users, inbounds}``.

(Before Phase 2 the ZIP also carried ``settings.json``, a
human-readable dump of the whole settings table — including the bot
token and every private key in plaintext. Restore never read it (the
DB is authoritative), so it was dropped: it only widened the
exposure of a backup that already contains every credential. Old
backups that still carry the member restore fine — validation only
ever reads ``panel.db`` and ``meta.json``.)

A backup is a full credential bundle — the DB holds the admin
password hash, every VPN password and private key, the Telegram bot
token and the webhook secret. Treat backup files like private keys:
never share them, never store them unencrypted in shared places.

Restore accepts the ZIP or a bare ``.db`` file. Validation, in
order: size cap, SQLite header / ZIP structure, ``PRAGMA
integrity_check``, the required panel tables, and the schema-version
guard (a backup from a NEWER schema version is refused — the schema
is versioned through the ``schema_version`` setting row, which
``ensure_defaults`` writes; a backup without one is version 1).

Nothing here touches the running engine: the caller disposes the
engine, calls :func:`swap_db_file`, then rebinds (see
``app.db.reset_engine``). The current DB is always backed up first
(:func:`backup_current_db`).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1
BACKUP_MAX_BYTES = 200 * 1024 * 1024  # 200 MiB upload cap
BACKUPS_KEEP = 5

#: Default scheduled auto-backup settings (Phase A item 4; Hiddify's
#: 6-hourly cadence is the model). Overridable in Settings → Backup
#: (``auto_backup_hours`` / ``auto_backup_keep``).
AUTO_BACKUP_DEFAULT_HOURS = 6
AUTO_BACKUP_DEFAULT_KEEP = 7
#: Prefix for scheduled-backup ZIPs in the backups dir (kept
#: separate from the pre-restore ``panel.db.*.bak`` snapshots so
#: each retention rule prunes only its own files).
AUTO_BACKUP_PREFIX = "auto-"

#: Settings that identify THIS machine/installation (Phase A item 4,
#: 3x-ui's "safe import"). A restore from another install's backup
#: replaces the whole DB — including these rows — unless the admin
#: keeps the "preserve machine identity" box checked (the default),
#: in which case the current values are re-applied after the swap:
#: the panel's own domain/host, its Telegram bot identity (token,
#: chat, transport, topic, event selection) and the webhook secret
#: (Telegram posts to the URL carrying it — importing another
#: install's secret would silently break the webhook). Everything
#: else (users, inbounds, keys, traffic) comes from the backup.
#: The panel port and web path are NOT in this list: they live in
#: the environment (panel.env), not the DB, so a restore can never
#: change them.
IDENTITY_SETTING_KEYS = (
    "domain",
    "subscription_host",
    "telegram_bot_token",
    "telegram_chat_id",
    "telegram_transport",
    "telegram_topic_id",
    "telegram_events",
    "telegram_webhook_secret",
)

REQUIRED_TABLES = (
    "admins",
    "settings",
    "inbounds",
    "users",
    "clients",
    "traffic_daily",
    "audit_log",
    "sessions",
)

_SQLITE_MAGIC = b"SQLite format 3\x00"


class BackupError(ValueError):
    """A backup failed validation. ``code`` is a short UI key."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


@dataclass
class BackupInfo:
    """A validated backup, ready to restore."""

    db_file: Path  # extracted/validated DB file (temp location)
    schema_version: int = 1
    created_at: str = ""
    users: int = 0
    inbounds: int = 0
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Creating a backup
# ---------------------------------------------------------------------------


def _sqlite_backup(src_path: Path, dest_path: Path) -> None:
    """Consistent snapshot of ``src_path`` into ``dest_path``.

    Uses the SQLite backup API (works on a live WAL database; the
    snapshot is a standalone file, no -wal/-shm sidecars).
    """
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(str(dest_path))
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()


def _read_counts(db_path: Path) -> tuple[int, int]:
    """User/inbound counts from a DB file (for ``meta.json``)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        inbounds = conn.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0]
        return int(users), int(inbounds)
    finally:
        conn.close()


def create_backup_zip(db_path: str | Path) -> bytes:
    """Build the backup ZIP for the DB at ``db_path`` (in memory).

    Members: ``panel.db`` + ``meta.json`` only. No ``settings.json``:
    the DB already holds the settings rows (restore reads nothing
    else), and a plaintext dump of every secret only widened the
    exposure of the backup (S5).
    """
    db_path = Path(db_path)
    with tempfile.TemporaryDirectory(prefix="sparky-backup-") as tmp:
        snapshot = Path(tmp) / "panel.db"
        _sqlite_backup(db_path, snapshot)
        users, inbounds = _read_counts(snapshot)
        meta = {
            "panel": "sparky-manager",
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "users": users,
            "inbounds": inbounds,
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(snapshot, "panel.db")
            zf.writestr(
                "meta.json", json.dumps(meta, indent=2, ensure_ascii=False)
            )
        return buf.getvalue()


# ---------------------------------------------------------------------------
# Scheduled auto-backup (Phase A item 4)
# ---------------------------------------------------------------------------


def auto_backup_due(
    settings: dict, now: Optional[datetime] = None
) -> bool:
    """True when a scheduled backup is due.

    ``auto_backup_hours`` (0 = off, default 6) sets the cadence;
    ``auto_backup_last_run`` (ISO timestamp) is the last completed
    run. A missing/unparseable stamp means "never ran" — due now.
    Pure function over the settings dict (no DB access), so the
    loop and the tests share the rule.
    """
    try:
        hours = int(
            (settings.get("auto_backup_hours") or "").strip()
            or str(AUTO_BACKUP_DEFAULT_HOURS)
        )
    except (ValueError, TypeError, AttributeError):
        hours = AUTO_BACKUP_DEFAULT_HOURS
    if hours <= 0:
        return False
    now = now or datetime.now(timezone.utc)
    raw = (settings.get("auto_backup_last_run") or "").strip()
    if not raw:
        return True
    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) >= timedelta(hours=hours)


def run_scheduled_backup(
    db_path: str | Path,
    backups_dir: str | Path,
    keep: int = AUTO_BACKUP_DEFAULT_KEEP,
) -> tuple[Path, bytes]:
    """Take one scheduled backup: a ZIP (SQLite backup API snapshot,
    never a file copy of a live WAL DB) written to ``backups_dir``
    as ``auto-<UTC stamp>.zip``, pruning older auto-backups to
    ``keep`` (pre-restore ``panel.db.*.bak`` files are untouched —
    they have their own retention).

    Returns ``(path, zip_bytes)`` — the bytes go to Telegram delivery
    when enabled, so the file is not re-read. ``keep <= 0`` keeps
    everything (Hiddify's "0 = keep all").
    """
    data = create_backup_zip(db_path)
    backups_dir = Path(backups_dir)
    backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    dest = backups_dir / f"{AUTO_BACKUP_PREFIX}{stamp}.zip"
    dest.write_bytes(data)
    if keep > 0:
        existing = sorted(backups_dir.glob(f"{AUTO_BACKUP_PREFIX}*.zip"))
        for old in existing[: max(0, len(existing) - keep)]:
            try:
                old.unlink()
            except OSError:
                pass
    return dest, data


def snapshot_identity_settings(settings: dict) -> dict[str, str]:
    """The machine-identity rows to preserve across a restore
    (only keys actually present — a missing key stays missing)."""
    return {
        key: str(settings[key])
        for key in IDENTITY_SETTING_KEYS
        if settings.get(key) not in (None, "")
    }


def reapply_identity_settings(db, snapshot: dict[str, str]) -> None:
    """Re-apply a snapshot taken by :func:`snapshot_identity_settings`
    to a (restored) DB. Keys absent from the snapshot are deleted
    from the restored DB — a restore must not resurrect another
    install's bot token or webhook secret by omission.

    Takes a SQLAlchemy session; the caller commits.
    """
    from app.models import Setting

    for key in IDENTITY_SETTING_KEYS:
        row = db.query(Setting).filter(Setting.key == key).first()
        if key in snapshot:
            if row is None:
                db.add(Setting(key=key, value=snapshot[key]))
            else:
                row.value = snapshot[key]
        elif row is not None:
            db.delete(row)
    db.commit()


# ---------------------------------------------------------------------------
# Validating an upload
# ---------------------------------------------------------------------------


def _check_db_file(path: Path) -> tuple[int, int, int]:
    """Integrity + tables + counts for a candidate DB file.

    Returns ``(schema_version, users, inbounds)``. Raises
    :class:`BackupError` for a corrupt file or a DB that is not a
    panel database. A missing ``schema_version`` setting means v1.

    The file is opened read-write on purpose: it is a temp copy, and
    a bare ``panel.db`` upload is a WAL-mode database whose -wal
    sidecar was not uploaded — a read-only open of such a file fails
    (SQLite needs the -shm). Read-write lets SQLite recover the
    checkpointed state, and the checkpoint below makes the file
    fully self-contained before it is copied into place.
    """
    try:
        conn = sqlite3.connect(str(path))
    except sqlite3.Error as exc:
        raise BackupError("corrupt", str(exc)) from exc
    try:
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as exc:
            raise BackupError("corrupt", str(exc)) from exc
        if integrity is None or str(integrity[0]).lower() != "ok":
            raise BackupError("corrupt", "integrity check failed")
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing = [t for t in REQUIRED_TABLES if t not in tables]
        if missing:
            raise BackupError(
                "missing_tables", "missing tables: " + ", ".join(missing)
            )
        row = conn.execute(
            "SELECT value FROM settings WHERE key='schema_version'"
        ).fetchone()
        version = 1
        if row is not None and row[0] not in (None, ""):
            try:
                version = int(row[0])
            except (TypeError, ValueError):
                version = 1
        users = int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        inbounds = int(
            conn.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0]
        )
        try:
            # Fold any WAL content into the file (no-op for a
            # rollback-journal DB) so the copy is self-contained.
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return version, users, inbounds
    finally:
        conn.close()


def validate_backup_bytes(data: bytes, tmp_dir: str | Path) -> BackupInfo:
    """Validate an uploaded backup (ZIP or bare .db).

    ``data`` is the raw upload; ``tmp_dir`` receives the extracted
    candidate DB. Returns :class:`BackupInfo` on success, raises
    :class:`BackupError` otherwise. Only the whitelisted ZIP members
    (``panel.db``, ``meta.json``) are ever read — nothing else in the
    archive is extracted.
    """
    if len(data) > BACKUP_MAX_BYTES:
        raise BackupError("too_large", "backup is over 200 MiB")
    if len(data) < 16:
        raise BackupError("not_a_backup", "file is too small to be a backup")
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    meta: dict = {}
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise BackupError("not_a_backup", str(exc)) from exc
        with zf:
            names = zf.namelist()
            if "panel.db" not in names:
                raise BackupError(
                    "missing_tables", "zip has no panel.db member"
                )
            for info in zf.infolist():
                if info.file_size > BACKUP_MAX_BYTES:
                    raise BackupError("too_large", "zip member too large")
            db_bytes = zf.read("panel.db")
            if "meta.json" in names:
                try:
                    meta = json.loads(zf.read("meta.json").decode("utf-8"))
                    if not isinstance(meta, dict):
                        meta = {}
                except (ValueError, UnicodeDecodeError):
                    meta = {}
    else:
        db_bytes = data

    if not db_bytes.startswith(_SQLITE_MAGIC):
        raise BackupError("not_a_backup", "not a SQLite database")
    db_file = tmp_dir / "restore-candidate.db"
    db_file.write_bytes(db_bytes)
    version, users, inbounds = _check_db_file(db_file)
    # The meta version wins when present (it is written by this
    # panel); otherwise the DB's own setting row decides.
    meta_version = meta.get("schema_version")
    if isinstance(meta_version, int):
        version = meta_version
    if version > SCHEMA_VERSION:
        raise BackupError(
            "newer_schema",
            f"backup schema v{version} is newer than this panel (v{SCHEMA_VERSION})",
        )
    return BackupInfo(
        db_file=db_file,
        schema_version=version,
        created_at=str(meta.get("created_at", "")),
        users=users,
        inbounds=inbounds,
        meta=meta,
    )


# ---------------------------------------------------------------------------
# Swapping the live DB
# ---------------------------------------------------------------------------


def backup_current_db(
    db_path: str | Path,
    backups_dir: str | Path,
    keep: int = BACKUPS_KEEP,
) -> Path:
    """Snapshot the live DB into ``backups_dir``; prune to ``keep``.

    Returns the backup path. The filename carries a UTC timestamp:
    ``panel.db.20261115-073000.bak``.
    """
    db_path = Path(db_path)
    backups_dir = Path(backups_dir)
    backups_dir.mkdir(parents=True, exist_ok=True)
    # Microsecond resolution: two backups in the same second must not
    # share a filename.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    dest = backups_dir / f"panel.db.{stamp}.bak"
    _sqlite_backup(db_path, dest)
    existing = sorted(backups_dir.glob("panel.db.*.bak"))
    for old in existing[: max(0, len(existing) - keep)]:
        try:
            old.unlink()
        except OSError:
            pass
    return dest


def swap_db_file(db_path: str | Path, new_file: str | Path) -> None:
    """Replace the live DB file with ``new_file``, atomically (S6).

    The new file is copied to a temporary name in the SAME directory
    (same filesystem — a rename across filesystems is not atomic,
    which is why the validated file, which may live in ``/tmp``, is
    copied rather than renamed), flushed to disk, and then moved into
    place with ``os.replace``: at no point is the live path missing
    or half-written. On any failure the temp file is removed and the
    current DB is untouched.

    The old ``-wal`` / ``-shm`` sidecars are removed first — the new
    file is a standalone snapshot and must not inherit a stale WAL.
    The caller must have disposed the engine before calling this (WAL
    is checkpointed on close, so no committed data lives in the
    sidecars).
    """
    db_path = Path(db_path)
    new_file = Path(new_file)
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=db_path.parent, prefix=".panel.db.swap-"
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as out:
            with open(new_file, "rb") as src:
                shutil.copyfileobj(src, out)
            out.flush()
            os.fsync(out.fileno())
        for suffix in ("-wal", "-shm"):
            try:
                Path(str(db_path) + suffix).unlink()
            except FileNotFoundError:
                pass
        os.replace(tmp_path, db_path)
        tmp_path = None
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass


__all__ = [
    "SCHEMA_VERSION",
    "BACKUP_MAX_BYTES",
    "BACKUPS_KEEP",
    "AUTO_BACKUP_DEFAULT_HOURS",
    "AUTO_BACKUP_DEFAULT_KEEP",
    "AUTO_BACKUP_PREFIX",
    "IDENTITY_SETTING_KEYS",
    "REQUIRED_TABLES",
    "BackupError",
    "BackupInfo",
    "create_backup_zip",
    "auto_backup_due",
    "run_scheduled_backup",
    "snapshot_identity_settings",
    "reapply_identity_settings",
    "validate_backup_bytes",
    "backup_current_db",
    "swap_db_file",
]
