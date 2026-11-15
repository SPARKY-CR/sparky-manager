"""Phase A item 4 tests — scheduled auto-backup.

Cadence + retention (keep N auto-backups, delete older), Telegram
delivery split at 49 MB, and the safe-import rule: a restore keeps
this machine's identity (domain, Telegram bot, webhook secret)
unless the admin explicitly unchecks the box.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import backup as backup_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.db import SessionLocal
from app.models import AuditLog, User
from app.webcommon import get_setting, get_settings, set_setting


# ---------------------------------------------------------------------------
# Cadence (pure rule)
# ---------------------------------------------------------------------------

def test_auto_backup_due_without_last_run():
    assert backup_mod.auto_backup_due({}) is True
    assert backup_mod.auto_backup_due({"auto_backup_hours": "6"}) is True


def test_auto_backup_not_due_when_recent():
    now = datetime.now(timezone.utc)
    settings = {
        "auto_backup_hours": "6",
        "auto_backup_last_run": (now - timedelta(hours=1)).isoformat(),
    }
    assert backup_mod.auto_backup_due(settings, now=now) is False


def test_auto_backup_due_after_interval():
    now = datetime.now(timezone.utc)
    settings = {
        "auto_backup_hours": "6",
        "auto_backup_last_run": (now - timedelta(hours=7)).isoformat(),
    }
    assert backup_mod.auto_backup_due(settings, now=now) is True


def test_auto_backup_off_when_hours_zero():
    assert backup_mod.auto_backup_due({"auto_backup_hours": "0"}) is False


def test_auto_backup_bad_values_fall_back_to_defaults():
    # A garbage hours value means "never ran, default cadence" —
    # due now, not an exception.
    assert backup_mod.auto_backup_due(
        {"auto_backup_hours": "banana"}) is True
    # A garbage last-run stamp means "never ran".
    assert backup_mod.auto_backup_due({
        "auto_backup_hours": "6",
        "auto_backup_last_run": "not a timestamp",
    }) is True


# ---------------------------------------------------------------------------
# Scheduled run + retention
# ---------------------------------------------------------------------------

def test_run_scheduled_backup_creates_zip(db_engine, tmp_path):
    db_path = Path(db_engine.url.database)
    backups_dir = tmp_path / "backups"
    path, data = backup_mod.run_scheduled_backup(db_path, backups_dir)
    assert path.name.startswith("auto-")
    assert path.suffix == ".zip"
    assert len(data) == path.stat().st_size > 0
    # It is a valid backup ZIP (SQLite snapshot + meta.json).
    with zipfile.ZipFile(path) as zf:
        assert "panel.db" in zf.namelist()
        assert "meta.json" in zf.namelist()
        assert "settings.json" not in zf.namelist()


def test_run_scheduled_backup_prunes_to_keep(db_engine, tmp_path):
    db_path = Path(db_engine.url.database)
    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    # Nine stale auto-backups (older names sort first).
    for i in range(9):
        (backups_dir / f"auto-2026-01-0{i}T00-00-00Z.zip").write_bytes(b"x")
    # A pre-restore backup must NOT be pruned by the auto rule.
    (backups_dir / "panel.db.2026-01-01T00-00-00Z.bak").write_bytes(b"y")
    path, _ = backup_mod.run_scheduled_backup(db_path, backups_dir, keep=3)
    auto = sorted(backups_dir.glob("auto-*.zip"))
    assert len(auto) == 3
    assert path in auto
    assert (backups_dir / "panel.db.2026-01-01T00-00-00Z.bak").exists()


def test_run_scheduled_backup_keep_zero_keeps_all(db_engine, tmp_path):
    db_path = Path(db_engine.url.database)
    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    for i in range(3):
        (backups_dir / f"auto-2026-01-0{i}T00-00-00Z.zip").write_bytes(b"x")
    backup_mod.run_scheduled_backup(db_path, backups_dir, keep=0)
    assert len(list(backups_dir.glob("auto-*.zip"))) == 4


# ---------------------------------------------------------------------------
# Telegram delivery (split at 49 MB)
# ---------------------------------------------------------------------------

def test_split_document_parts_small_is_single():
    parts = telegram_mod.split_document_parts("backup.zip", b"abc")
    assert parts == [("backup.zip", b"abc")]


def test_split_document_parts_exact_limit_is_single():
    data = b"x" * telegram_mod.DOCUMENT_PART_BYTES
    parts = telegram_mod.split_document_parts("backup.zip", data)
    assert len(parts) == 1
    assert parts[0] == ("backup.zip", data)


def test_split_document_parts_splits_and_names():
    size = telegram_mod.DOCUMENT_PART_BYTES * 2 + 100
    data = b"x" * size
    parts = telegram_mod.split_document_parts("auto-2026.zip", data)
    assert len(parts) == 3
    assert [name for name, _ in parts] == [
        "auto-2026.part1of3.zip",
        "auto-2026.part2of3.zip",
        "auto-2026.part3of3.zip",
    ]
    assert len(parts[0][1]) == telegram_mod.DOCUMENT_PART_BYTES
    assert len(parts[1][1]) == telegram_mod.DOCUMENT_PART_BYTES
    assert len(parts[2][1]) == 100
    assert b"".join(chunk for _, chunk in parts) == data


def test_send_document_parts_all_or_nothing(monkeypatch):
    calls: list = []

    def _fake_post_files(token, method, data=None, files=None, timeout=None):
        calls.append(files)
        return {"ok": True}

    monkeypatch.setattr(telegram_mod, "_post_files", _fake_post_files)
    data = b"x" * (telegram_mod.DOCUMENT_PART_BYTES + 10)
    assert telegram_mod.send_document_parts(
        "tok", "123", "backup.zip", data) is True
    assert len(calls) == 2
    # The part filenames reach Telegram.
    assert calls[0]["document"][0] == "backup.part1of2.zip"


def test_send_document_parts_stops_on_first_failure(monkeypatch):
    calls: list = []

    def _fake_post_files(token, method, data=None, files=None, timeout=None):
        calls.append(files)
        return None  # any transport/API failure surfaces as None

    monkeypatch.setattr(telegram_mod, "_post_files", _fake_post_files)
    data = b"x" * (telegram_mod.DOCUMENT_PART_BYTES + 10)
    assert telegram_mod.send_document_parts(
        "tok", "123", "backup.zip", data) is False
    # The first part failed: later parts are useless orphans, so the
    # send stops instead of uploading them anyway.
    assert len(calls) == 1


def test_send_document_parts_empty_is_false(monkeypatch):
    assert telegram_mod.send_document_parts("tok", "123", "b.zip", b"") is False


# ---------------------------------------------------------------------------
# Safe import (identity snapshot / reapply)
# ---------------------------------------------------------------------------

def test_snapshot_keeps_only_identity_keys():
    snapshot = backup_mod.snapshot_identity_settings({
        "domain": "vpn.example.com",
        "telegram_bot_token": "tok",
        "telegram_chat_id": "123",
        "reality_sni": "www.microsoft.com",
        "auto_backup_hours": "6",
    })
    assert snapshot == {
        "domain": "vpn.example.com",
        "telegram_bot_token": "tok",
        "telegram_chat_id": "123",
    }


def test_reapply_restores_snapshot_and_deletes_absent_keys(db):
    # The restored DB carries another install's bot token; this
    # machine has no bot configured — reapply must DELETE the
    # imported token, not leave it in place.
    set_setting(db, "telegram_bot_token", "other-install-token")
    set_setting(db, "domain", "other.example.com")
    set_setting(db, "reality_sni", "www.microsoft.com")
    backup_mod.reapply_identity_settings(
        db, {"domain": "mine.example.com"})
    assert get_setting(db, "domain") == "mine.example.com"
    assert get_setting(db, "telegram_bot_token") == ""
    # Non-identity settings are untouched.
    assert get_setting(db, "reality_sni") == "www.microsoft.com"


# ---------------------------------------------------------------------------
# Restore with preserve_identity (HTTP round-trip)
# ---------------------------------------------------------------------------

def _db_path_for(db_engine):
    return Path(db_engine.url.database)


def _restore_with_identity(
    authed_client, db, seeded, db_engine, tmp_path, preserve
):
    """Restore a backup taken with domain A while the live DB has
    domain B; returns the fresh session's domain after restore."""
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    set_setting(db, "cert_path", str(cert))
    set_setting(db, "key_path", str(key))
    set_setting(db, "domain", "backup.example.com")
    set_setting(db, "telegram_bot_token", "backup-token")
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    # The live install has its OWN identity now.
    set_setting(db, "domain", "live.example.com")
    set_setting(db, "telegram_bot_token", "live-token")
    form = {"confirm_restore": "yes"}
    if preserve:
        form["preserve_identity"] = "yes"
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", data, "application/zip")},
        data=form,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    fresh = SessionLocal()
    try:
        return (
            get_setting(fresh, "domain"),
            get_setting(fresh, "telegram_bot_token"),
        )
    finally:
        fresh.close()


def test_restore_preserves_identity_when_checked(
        authed_client, db, seeded, db_engine, tmp_path):
    domain, token = _restore_with_identity(
        authed_client, db, seeded, db_engine, tmp_path, preserve=True)
    assert domain == "live.example.com"
    assert token == "live-token"


def test_restore_imports_identity_when_unchecked(
        authed_client, db, seeded, db_engine, tmp_path):
    domain, token = _restore_with_identity(
        authed_client, db, seeded, db_engine, tmp_path, preserve=False)
    assert domain == "backup.example.com"
    assert token == "backup-token"


# ---------------------------------------------------------------------------
# Auto-backup settings round-trip
# ---------------------------------------------------------------------------

def test_save_auto_backup_settings(authed_client, db):
    resp = authed_client.post(
        "/settings",
        data={
            "section": "backup",
            "auto_backup_present": "1",
            "auto_backup_hours": "12",
            "auto_backup_keep": "3",
            "auto_backup_telegram": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert get_setting(db, "auto_backup_hours") == "12"
    assert get_setting(db, "auto_backup_keep") == "3"
    assert get_setting(db, "auto_backup_telegram") == "1"


def test_save_auto_backup_bad_values_keep_previous(authed_client, db):
    set_setting(db, "auto_backup_hours", "6")
    resp = authed_client.post(
        "/settings",
        data={
            "section": "backup",
            "auto_backup_present": "1",
            "auto_backup_hours": "banana",
            "auto_backup_keep": "-4",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert get_setting(db, "auto_backup_hours") == "6"
    # A negative keep clamps to 0 (keep all).
    assert get_setting(db, "auto_backup_keep") == "0"


def test_save_auto_backup_unchecked_telegram_is_off(authed_client, db):
    set_setting(db, "auto_backup_telegram", "1")
    resp = authed_client.post(
        "/settings",
        data={
            "section": "backup",
            "auto_backup_present": "1",
            "auto_backup_hours": "6",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # The checkbox submits nothing when unchecked — the present
    # marker makes that a real "off", not "untouched".
    assert get_setting(db, "auto_backup_telegram") == "0"
