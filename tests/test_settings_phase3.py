"""Phase 3 tests — panel & server settings (DESIGN.md §5.8).

Covers: in-panel password change, Telegram notifications (sender
module + settings + hooks), backup/restore (module + routes),
server status collection, and the server-side traffic charts.
"""

from __future__ import annotations

import io
import json
import sqlite3
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import auth as auth_mod
from app import backup as backup_mod
from app import charts as charts_mod
from app import main as main_mod
from app import system_status as system_status_mod
from app import telegram as telegram_mod
from app.db import SessionLocal, init_db
from app.models import Admin, AuditLog, TrafficDaily, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_telegram(db, token="123456:TEST-TOKEN-abcdef", chat_id="987654321"):
    main_mod.set_setting(db, "telegram_bot_token", token)
    main_mod.set_setting(db, "telegram_chat_id", chat_id)


def _fake_httpx_post(calls, status_code=200, payload=None):
    """A fake httpx.post recording (url, json) calls."""
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )
    return _post


def _seed_traffic(db, user_id, days_values):
    """Add TrafficDaily rows: {date: total_bytes} (split up/down)."""
    for day, total in days_values.items():
        db.add(TrafficDaily(user_id=user_id, date=day,
                            up_bytes=total // 2, down_bytes=total - total // 2))
    db.commit()


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


def test_password_change_wrong_current(authed_client, db, seeded):
    resp = authed_client.post(
        "/settings/password",
        data={"current_password": "wrong-password",
              "new_password": "NewPassword123",
              "confirm_password": "NewPassword123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    admin = db.query(Admin).first()
    assert auth_mod.verify_password(ADMIN_PASSWORD, admin.password_hash)


def test_password_change_too_short(authed_client, db):
    resp = authed_client.post(
        "/settings/password",
        data={"current_password": ADMIN_PASSWORD,
              "new_password": "short",
              "confirm_password": "short"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    admin = db.query(Admin).first()
    assert auth_mod.verify_password(ADMIN_PASSWORD, admin.password_hash)


def test_password_change_mismatch(authed_client, db):
    resp = authed_client.post(
        "/settings/password",
        data={"current_password": ADMIN_PASSWORD,
              "new_password": "NewPassword123",
              "confirm_password": "DifferentPassword123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    admin = db.query(Admin).first()
    assert auth_mod.verify_password(ADMIN_PASSWORD, admin.password_hash)


def test_password_change_success_invalidates_other_sessions(
    authed_client, db, seeded
):
    db.expire_all()
    admin = db.query(Admin).first()
    # A second session (another device) + the current one.
    other_token = auth_mod.create_session(db, admin, ip="203.0.113.99")
    assert auth_mod.get_admin_from_token(db, other_token) is not None

    resp = authed_client.post(
        "/settings/password",
        data={"current_password": ADMIN_PASSWORD,
              "new_password": "BrandNewPass456",
              "confirm_password": "BrandNewPass456"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]

    db.expire_all()
    admin = db.query(Admin).first()
    assert auth_mod.verify_password("BrandNewPass456", admin.password_hash)
    assert not auth_mod.verify_password(ADMIN_PASSWORD, admin.password_hash)
    # The other device is signed out; this session still works.
    assert auth_mod.get_admin_from_token(db, other_token) is None
    assert authed_client.get("/api/users").status_code == 200
    # Audited — without any password in the detail.
    entry = (
        db.query(AuditLog)
        .filter(AuditLog.action == "admin.password_change")
        .first()
    )
    assert entry is not None
    assert "BrandNewPass456" not in (entry.detail or "")


def test_password_change_requires_login(test_client):
    resp = test_client.post(
        "/settings/password",
        data={"current_password": ADMIN_PASSWORD,
              "new_password": "BrandNewPass456",
              "confirm_password": "BrandNewPass456"},
        follow_redirects=False,
    )
    assert resp.status_code in (303, 401)


def test_change_admin_password_helper_rejects_bad_current(db, seeded):
    from app.main import ensure_defaults

    ensure_defaults(db)
    admin = db.query(Admin).first()
    ok, key = main_mod._change_admin_password(
        db, admin, "nope", "NewPassword123", "NewPassword123"
    )
    assert ok is False
    assert key == "wrong_current_password"


# ---------------------------------------------------------------------------
# Telegram sender module
# ---------------------------------------------------------------------------


def test_send_message_success(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls)
    )
    assert telegram_mod.send_message("tok123", "42", "hello") is True
    assert len(calls) == 1
    assert calls[0]["url"] == "https://api.telegram.org/bot" + "tok123/sendMessage"
    assert calls[0]["json"] == {"chat_id": "42", "text": "hello"}
    assert calls[0]["timeout"] == telegram_mod.DEFAULT_TIMEOUT


def test_send_message_http_error(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, status_code=401)
    )
    assert telegram_mod.send_message("tok123", "42", "hello") is False


def test_send_message_api_not_ok(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, payload={"ok": False})
    )
    assert telegram_mod.send_message("tok123", "42", "hello") is False


def test_send_message_exception_never_raises(monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    assert telegram_mod.send_message("tok123", "42", "hello") is False
    # The token must not appear in any log record.
    assert "tok123" not in caplog.text


def test_send_message_missing_args(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.send_message("", "42", "hello") is False
    assert telegram_mod.send_message("tok", "", "hello") is False
    assert telegram_mod.send_message("tok", "42", "  ") is False
    assert calls == []


def test_send_message_truncates_long_text(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.send_message("tok", "42", "x" * 5000) is True
    assert len(calls[0]["json"]["text"]) == telegram_mod.MAX_MESSAGE_LENGTH


def test_mask_token():
    assert telegram_mod.mask_token("") == ""
    assert telegram_mod.mask_token("123456:ABCDefgh") == "••••efgh"
    assert telegram_mod.mask_token("ab") == "••••"


# ---------------------------------------------------------------------------
# Telegram settings + hooks
# ---------------------------------------------------------------------------


def test_save_settings_stores_telegram_and_never_shows_token(
    authed_client, db
):
    resp = authed_client.post(
        "/settings",
        data={"domain": "", "subscription_host": "", "reality_sni": "",
              "log_level": "INFO",
              "telegram_bot_token": "999999:SECRET-TOKEN-xyz",
              "telegram_chat_id": "123456789"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_chat_id") == "123456789"
    assert main_mod.get_setting(db, "telegram_bot_token") == "999999:SECRET-TOKEN-xyz"
    # The settings page shows a "configured" badge, never the token.
    page = authed_client.get("/settings")
    assert page.status_code == 200
    assert "999999:SECRET-TOKEN-xyz" not in page.text
    assert "SECRET-TOKEN" not in page.text


def test_save_settings_blank_token_keeps_current(authed_client, db):
    _configure_telegram(db, token="KEEP-ME-TOKEN")
    resp = authed_client.post(
        "/settings",
        data={"domain": "", "subscription_host": "", "reality_sni": "",
              "log_level": "INFO",
              "telegram_bot_token": "",
              "telegram_chat_id": "123456789"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_bot_token") == "KEEP-ME-TOKEN"


def test_save_settings_invalid_chat_id(authed_client, db):
    resp = authed_client.post(
        "/settings",
        data={"domain": "", "subscription_host": "", "reality_sni": "",
              "log_level": "INFO",
              "telegram_bot_token": "tok",
              "telegram_chat_id": "not-a-number"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert main_mod.get_setting(db, "telegram_chat_id") == ""


def test_telegram_test_route_success(authed_client, db, monkeypatch):
    _configure_telegram(db)
    sent: list = []
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    resp = authed_client.post("/settings/telegram-test",
                              follow_redirects=False)
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    assert len(sent) == 1


def test_telegram_test_route_not_configured(authed_client, db):
    resp = authed_client.post("/settings/telegram-test",
                              follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_telegram_test_route_failure(authed_client, db, monkeypatch):
    _configure_telegram(db)
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda *a, **kw: False,
    )
    resp = authed_client.post("/settings/telegram-test",
                              follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_expiry_notification_sent_once_per_day(db, seeded, monkeypatch):
    _configure_telegram(db)
    soon = User(
        name="soon",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=12),
    )
    db.add(soon)
    db.commit()
    sent: list = []
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    assert main_mod._notify_expiring_users(db) == 1
    assert "soon" in sent[0]
    # Second run the same day: no duplicate.
    assert main_mod._notify_expiring_users(db) == 0
    assert len(sent) == 1


def test_expiry_notification_skips_far_and_expired(db, seeded, monkeypatch):
    _configure_telegram(db)
    far = User(
        name="far",
        expires_at=datetime.now(timezone.utc) + timedelta(days=10),
    )
    db.add(far)
    db.commit()
    sent: list = []
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    # bob is already expired, far expires in 10 days: nobody qualifies.
    assert main_mod._notify_expiring_users(db) == 0
    assert sent == []


def test_user_create_notifies_telegram(authed_client, db, monkeypatch):
    _configure_telegram(db)
    sent: list = []
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    resp = authed_client.post(
        "/users",
        data={"name": "newbie", "note": "", "traffic_limit_gb": "",
              "expires_days": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert len(sent) == 1
    assert "newbie" in sent[0]


def test_rerender_failure_notification_throttled(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent: list = []
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    assert main_mod._notify_rerender_failure(db, ["xray: bad config"]) is True
    assert main_mod._notify_rerender_failure(db, ["xray: bad config"]) is False
    assert len(sent) == 1
    # Backdate the last-notify stamp: the next failure notifies again.
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    main_mod.set_setting(db, "telegram_rerender_notified_at", old)
    assert main_mod._notify_rerender_failure(db, ["xray: bad config"]) is True
    assert len(sent) == 2


def test_notify_telegram_returns_false_when_unconfigured(db, seeded):
    assert main_mod._notify_telegram(db, "hello") is False


# ---------------------------------------------------------------------------
# Backup module
# ---------------------------------------------------------------------------


def _db_path_for(db_engine):
    return Path(db_engine.url.database)


def test_create_backup_zip_contents(db_engine, db, seeded, tmp_path):
    main_mod.ensure_defaults(db)  # seeds the settings rows
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert set(zf.namelist()) == {"panel.db", "settings.json", "meta.json"}
    meta = json.loads(zf.read("meta.json"))
    assert meta["schema_version"] == backup_mod.SCHEMA_VERSION
    assert meta["users"] == 5
    settings = json.loads(zf.read("settings.json"))
    assert "reality_sni" in settings
    # The embedded DB opens (as a file, like the restore path does)
    # and holds the seeded users.
    snap = tmp_path / "snap.db"
    snap.write_bytes(zf.read("panel.db"))
    conn = sqlite3.connect(str(snap))
    try:
        names = {row[0] for row in conn.execute("SELECT name FROM users")}
    finally:
        conn.close()
    assert {"alice", "bob", "carol", "dave", "eve"} <= names


def test_validate_backup_roundtrip(db_engine, db, seeded, tmp_path):
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    info = backup_mod.validate_backup_bytes(data, tmp_path)
    assert info.schema_version == backup_mod.SCHEMA_VERSION
    assert info.users == 5
    assert info.inbounds >= 10
    assert info.db_file.exists()


def test_validate_bare_db_file(db_engine, db, seeded, tmp_path):
    # A bare .db upload must come from a checkpointed database: the
    # live WAL file holds uncheckpointed pages, so a raw read of the
    # running DB would be missing tables. Checkpoint first, as a
    # stopped panel would have.
    with db_engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    data = Path(_db_path_for(db_engine)).read_bytes()
    info = backup_mod.validate_backup_bytes(data, tmp_path)
    assert info.users == 5


def test_validate_rejects_garbage(tmp_path):
    with pytest.raises(backup_mod.BackupError) as excinfo:
        backup_mod.validate_backup_bytes(b"this is not a backup at all", tmp_path)
    assert excinfo.value.code in ("not_a_backup", "corrupt")


def test_validate_rejects_zip_without_db(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "hello")
    with pytest.raises(backup_mod.BackupError) as excinfo:
        backup_mod.validate_backup_bytes(buf.getvalue(), tmp_path)
    assert excinfo.value.code == "missing_tables"


def test_validate_rejects_non_panel_db(tmp_path):
    path = tmp_path / "other.db"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    with pytest.raises(backup_mod.BackupError) as excinfo:
        backup_mod.validate_backup_bytes(path.read_bytes(), tmp_path)
    assert excinfo.value.code == "missing_tables"


def test_validate_rejects_newer_schema(db_engine, db, seeded, tmp_path):
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    zf_in = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf_out:
        for name in zf_in.namelist():
            if name == "meta.json":
                meta = json.loads(zf_in.read(name))
                meta["schema_version"] = 99
                zf_out.writestr(name, json.dumps(meta))
            else:
                zf_out.writestr(name, zf_in.read(name))
    with pytest.raises(backup_mod.BackupError) as excinfo:
        backup_mod.validate_backup_bytes(buf.getvalue(), tmp_path)
    assert excinfo.value.code == "newer_schema"


def test_backup_current_db_and_prune(db_engine, db, seeded, tmp_path):
    backups = tmp_path / "backups"
    first = backup_mod.backup_current_db(
        _db_path_for(db_engine), backups, keep=2
    )
    assert first.exists()
    assert first.name.startswith("panel.db.")
    # Three backups with keep=2 leaves the two newest.
    backup_mod.backup_current_db(_db_path_for(db_engine), backups, keep=2)
    backup_mod.backup_current_db(_db_path_for(db_engine), backups, keep=2)
    assert len(list(backups.glob("panel.db.*.bak"))) == 2


# ---------------------------------------------------------------------------
# Backup / restore routes
# ---------------------------------------------------------------------------


def test_download_backup(authed_client, db, seeded):
    resp = authed_client.get("/settings/backup")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "attachment" in resp.headers["content-disposition"]
    assert "sparky-manager-backup-" in resp.headers["content-disposition"]
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    assert "panel.db" in zf.namelist()
    assert "settings.json" in zf.namelist()
    assert "meta.json" in zf.namelist()


def test_download_backup_requires_login(test_client):
    resp = test_client.get("/settings/backup", follow_redirects=False)
    assert resp.status_code in (303, 401)


def test_restore_requires_confirmation(authed_client, db, seeded, db_engine):
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", data, "application/zip")},
        data={},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_restore_rejects_garbage_and_keeps_db(authed_client, db, seeded):
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", b"garbage bytes here", "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    # The live DB is untouched.
    db.expire_all()
    assert db.query(User).filter(User.name == "alice").first() is not None


def test_restore_roundtrip(authed_client, db, seeded, db_engine, tmp_path):
    # Dummy TLS certs (like the render_settings fixture): without
    # them the post-restore re-render reports the pre-existing
    # sing-box "no TLS certificate" warnings and the route redirects
    # with err= instead of msg=.
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    main_mod.set_setting(db, "cert_path", str(cert))
    main_mod.set_setting(db, "key_path", str(key))
    db_path = _db_path_for(db_engine)
    data = backup_mod.create_backup_zip(db_path)
    # Delete alice from the live DB, then restore the backup.
    db.expire_all()
    alice = db.query(User).filter(User.name == "alice").first()
    db.delete(alice)
    db.commit()
    assert db.query(User).filter(User.name == "alice").first() is None

    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", data, "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]

    # A fresh session on the rebound engine sees the restored DB.
    fresh = SessionLocal()
    try:
        assert fresh.query(User).filter(User.name == "alice").first() is not None
        entry = (
            fresh.query(AuditLog)
            .filter(AuditLog.action == "settings.restore")
            .first()
        )
        assert entry is not None
    finally:
        fresh.close()
    # The pre-restore DB was backed up under the panel data dir.
    backups = Path(main_mod.DATA_DIR) / "backups"
    assert list(backups.glob("panel.db.*.bak"))


def test_restore_rejects_newer_schema(authed_client, db, seeded, db_engine):
    data = backup_mod.create_backup_zip(_db_path_for(db_engine))
    zf_in = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf_out:
        for name in zf_in.namelist():
            if name == "meta.json":
                meta = json.loads(zf_in.read(name))
                meta["schema_version"] = 99
                zf_out.writestr(name, json.dumps(meta))
            else:
                zf_out.writestr(name, zf_in.read(name))
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", buf.getvalue(), "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    assert db.query(User).filter(User.name == "alice").first() is not None


# ---------------------------------------------------------------------------
# System status
# ---------------------------------------------------------------------------


def _fake_proc(tmp_path, *, load="0.50 0.30 0.20 1/123 4567",
               mem="MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\n",
               uptime="123456.78 987654.32"):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text(load)
    (proc / "meminfo").write_text(mem)
    (proc / "uptime").write_text(uptime)
    return proc


def test_read_proc_files(tmp_path):
    proc = _fake_proc(tmp_path)
    assert system_status_mod.read_loadavg(proc / "loadavg") == (0.5, 0.3, 0.2)
    mem = system_status_mod.read_meminfo(proc / "meminfo")
    assert mem == {"total": 16384000 * 1024, "available": 8192000 * 1024}
    assert system_status_mod.read_uptime(proc / "uptime") == 123456.78


def test_read_proc_files_missing_returns_none(tmp_path):
    assert system_status_mod.read_loadavg(tmp_path / "nope") is None
    assert system_status_mod.read_meminfo(tmp_path / "nope") is None
    assert system_status_mod.read_uptime(tmp_path / "nope") is None


def test_format_uptime():
    assert system_status_mod.format_uptime(None) == "—"
    assert system_status_mod.format_uptime(61) == "00:01"
    assert system_status_mod.format_uptime(90061) == "1d 01:01"


def _systemd_runner(states):
    """A fake subprocess.run returning one state line per unit."""
    def _run(cmd, **kwargs):
        assert cmd[0] == "systemctl" and cmd[1] == "is-active"
        assert len(cmd) - 2 == len(states)
        return SimpleNamespace(stdout="\n".join(states) + "\n", returncode=0)
    return _run


def test_service_states_from_systemd():
    states = ["active", "active", "inactive", "failed", "active",
              "inactive", "activating"]
    result = system_status_mod.service_states(runner=_systemd_runner(states))
    assert result["xray"] == "running"
    assert result["sing-box"] == "running"
    assert result["wireguard"] == "stopped"
    assert result["amneziawg"] == "stopped"
    assert result["openvpn"] == "running"
    assert result["openconnect"] == "stopped"
    assert result["ikev2"] == "unknown"  # "activating" is neither


def test_service_states_proc_fallback(tmp_path):
    proc = tmp_path / "proc"
    (proc / "123").mkdir(parents=True)
    (proc / "123" / "comm").write_text("xray\n")
    (proc / "456").mkdir(parents=True)
    (proc / "456" / "comm").write_text("ocserv\n")
    sys_root = tmp_path / "sys"
    (sys_root / "class" / "net" / "wg0").mkdir(parents=True)

    def _no_systemd(*args, **kwargs):
        raise FileNotFoundError("no systemctl here")

    result = system_status_mod.service_states(
        proc_root=proc, sys_root=sys_root, runner=_no_systemd
    )
    assert result["xray"] == "running"
    assert result["openconnect"] == "running"
    assert result["wireguard"] == "running"  # interface exists
    assert result["sing-box"] == "unknown"
    assert result["amneziawg"] == "unknown"
    assert result["openvpn"] == "unknown"
    assert result["ikev2"] == "unknown"


def test_collect_server_status_never_raises(tmp_path):
    status = system_status_mod.collect_server_status(
        data_dir=tmp_path,
        proc_root=tmp_path / "no-proc",
        sys_root=tmp_path / "no-sys",
        runner=lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()),
    )
    assert status["load"] is None
    assert status["memory"] is None
    assert status["uptime_seconds"] is None
    assert status["disk"] is not None  # tmp_path exists
    assert all(v == "unknown" for v in status["services"].values())


def test_collect_server_status_full(tmp_path):
    proc = _fake_proc(tmp_path)
    status = system_status_mod.collect_server_status(
        data_dir=tmp_path, proc_root=proc,
        runner=_systemd_runner(["active"] * 7),
    )
    assert status["load"] == (0.5, 0.3, 0.2)
    assert status["memory"]["total"] == 16384000 * 1024
    assert status["uptime"] == "1d 10:17"
    assert status["disk"]["total"] > 0
    assert all(v == "running" for v in status["services"].values())


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------


def test_daily_series_zero_filled():
    today = date(2026, 11, 15)
    rows = [(date(2026, 11, 13), 1000), (date(2026, 11, 15), 3000)]
    series = charts_mod.daily_traffic_series(rows, days=3, today=today)
    assert series == [
        (date(2026, 11, 13), 1000),
        (date(2026, 11, 14), 0),
        (date(2026, 11, 15), 3000),
    ]


def test_daily_series_sums_same_day_and_defaults_14():
    today = date(2026, 11, 15)
    rows = [(date(2026, 11, 15), 100), (date(2026, 11, 15), 50)]
    series = charts_mod.daily_traffic_series(rows, today=today)
    assert len(series) == 14
    assert series[-1] == (date(2026, 11, 15), 150)
    assert series[0] == (date(2026, 11, 2), 0)


def test_chart_svg_bars_and_labels():
    series = [(date(2026, 11, 13), 0), (date(2026, 11, 14), 500),
              (date(2026, 11, 15), 1000)]
    svg = charts_mod.traffic_chart_svg(series)
    assert svg.startswith("<svg")
    assert svg.count("<rect") == 3
    assert "11-15" in svg
    assert "1000 B" in svg or "1.0 KB" in svg
    assert "<title>2026-11-15:" in svg


def test_chart_svg_empty_and_zero_series():
    assert charts_mod.traffic_chart_svg([]) == ""
    series = [(date(2026, 11, 14), 0), (date(2026, 11, 15), 0)]
    svg = charts_mod.traffic_chart_svg(series)
    assert svg.startswith("<svg")
    assert svg.count("<rect") == 2
    assert 'height="0.0"' in svg


def test_dashboard_shows_traffic_chart(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    today = date.today()
    _seed_traffic(db, alice.id, {
        today: 2 * 1024**3,
        today - timedelta(days=1): 1024**3,
    })
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert "<svg" in resp.text
    assert "chart-svg" in resp.text


def test_user_detail_shows_traffic_chart(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    _seed_traffic(db, alice.id, {date.today(): 512 * 1024**2})
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "<svg" in resp.text
    assert "chart-svg" in resp.text


def test_traffic_chart_helper_totals(db, seeded):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    today = date.today()
    _seed_traffic(db, alice.id, {today: 1000})
    _seed_traffic(db, bob.id, {today: 2000})
    svg, total = main_mod._traffic_chart(db)
    assert total == 3000
    assert svg.startswith("<svg")
    _svg2, user_total = main_mod._traffic_chart(db, user_id=alice.id)
    assert user_total == 1000


# ---------------------------------------------------------------------------
# Settings page (Phase 3 sections)
# ---------------------------------------------------------------------------


def test_settings_page_shows_server_status_and_forms(authed_client, db):
    resp = authed_client.get("/settings")
    assert resp.status_code == 200
    # Server status section with the service names.
    for name in ("Xray", "sing-box", "WireGuard", "AmneziaWG",
                 "OpenVPN", "OpenConnect", "IKEv2"):
        assert name in resp.text
    # Password form, Telegram fields, backup/restore forms.
    assert "/settings/password" in resp.text
    assert "telegram_bot_token" in resp.text
    assert "telegram_chat_id" in resp.text
    assert "/settings/backup" in resp.text
    assert "/settings/restore" in resp.text
    assert "confirm_restore" in resp.text


def test_settings_page_shows_telegram_test_when_configured(
    authed_client, db
):
    _configure_telegram(db)
    resp = authed_client.get("/settings")
    assert resp.status_code == 200
    assert "/settings/telegram-test" in resp.text


def test_ensure_defaults_writes_schema_version(db, seeded):
    from app.main import ensure_defaults

    ensure_defaults(db)
    assert main_mod.get_setting(db, "schema_version") == str(
        backup_mod.SCHEMA_VERSION
    )
