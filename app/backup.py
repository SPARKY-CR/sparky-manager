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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1
BACKUP_MAX_BYTES = 200 * 1024 * 1024  # 200 MiB upload cap
BACKUPS_KEEP = 5

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
    "REQUIRED_TABLES",
    "BackupError",
    "BackupInfo",
    "create_backup_zip",
    "validate_backup_bytes",
    "backup_current_db",
    "swap_db_file",
]
