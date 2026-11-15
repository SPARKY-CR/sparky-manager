"""Phase 2 (professional upgrade) security tests: S1 CSRF, S3 headers,
S4 cookie Secure flag, S5 backup contents, S6 atomic restore swap.

The CSRF tests deliberately use ``post_raw()`` (no token injection)
for the negative cases and the plain ``post()`` (browser-like token
injection, see tests/conftest.py) for the positive ones.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from app import auth as auth_mod
from app import backup as backup_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.db import SessionLocal
from app.models import AuditLog, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, CSRFTestClient


# ---------------------------------------------------------------------------
# S1 — CSRF token helpers (unit level)
# ---------------------------------------------------------------------------

def test_csrf_token_derivation_and_verify():
    token_a = auth_mod.csrf_token_for_session("session-token-a")
    token_b = auth_mod.csrf_token_for_session("session-token-b")
    # Deterministic per session, different per session, and it does
    # not leak the session token itself.
    assert token_a == auth_mod.csrf_token_for_session("session-token-a")
    assert token_a != token_b
    assert "session-token-a" not in token_a
    assert len(token_a) == 64  # hex HMAC-SHA256
    assert auth_mod.verify_csrf_token("session-token-a", token_a) is True
    assert auth_mod.verify_csrf_token("session-token-a", token_b) is False
    assert auth_mod.verify_csrf_token("session-token-a", "") is False
    assert auth_mod.verify_csrf_token("session-token-a", None) is False
    assert auth_mod.verify_csrf_token("", token_a) is False


# ---------------------------------------------------------------------------
# S1 — CSRF enforcement on HTML form POSTs
# ---------------------------------------------------------------------------

def _create_user_data(name="newuser"):
    return {"name": name, "note": "", "traffic_limit": "",
            "expires_at": "", "inbounds": "1"}


def test_post_without_csrf_token_rejected(authed_client, db, seeded):
    before = db.query(User).count()
    resp = authed_client.post_raw(
        "/users", data=_create_user_data(), follow_redirects=False)
    assert resp.status_code == 403
    # No state change.
    assert db.query(User).count() == before
    assert db.query(User).filter(User.name == "newuser").first() is None


def test_post_with_wrong_csrf_token_rejected(authed_client, db, seeded):
    before = db.query(User).count()
    data = _create_user_data()
    data["csrf_token"] = "0" * 64  # well-formed, wrong value
    resp = authed_client.post_raw(
        "/users", data=data, follow_redirects=False)
    assert resp.status_code == 403
    assert db.query(User).count() == before


def test_post_with_valid_csrf_token_works(authed_client, db, seeded):
    resp = authed_client.post(
        "/users", data=_create_user_data(), follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    assert db.query(User).filter(User.name == "newuser").first() is not None


def test_csrf_error_page_renders(authed_client, db, seeded):
    resp = authed_client.post_raw(
        "/users", data=_create_user_data(), follow_redirects=False)
    assert resp.status_code == 403
    # A clear error page (Persian by default), not a bare 403.
    assert "text/html" in resp.headers["content-type"]
    assert main_mod.t_for("fa")["csrf_error_title"] in resp.text
    assert main_mod.t_for("fa")["csrf_error_message"] in resp.text


def test_logout_without_csrf_token_rejected(authed_client):
    resp = authed_client.post_raw("/logout", follow_redirects=False)
    assert resp.status_code == 403
    # Still logged in: the logout did not happen.
    assert authed_client.get("/api/users").status_code == 200


# ---------------------------------------------------------------------------
# S1 — CSRF on the JSON API (header token)
# ---------------------------------------------------------------------------

def test_api_post_without_csrf_token_rejected(authed_client, db, seeded):
    resp = authed_client.post_raw(
        "/api/users",
        json={"name": "apiuser", "inbounds": [1]},
        follow_redirects=False)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "CSRF token missing or invalid"
    assert db.query(User).filter(User.name == "apiuser").first() is None


def test_api_post_with_header_token_works(authed_client, db, seeded):
    resp = authed_client.post(
        "/api/users",
        json={"name": "apiuser", "inbounds": [1]},
        follow_redirects=False)
    assert resp.status_code in (200, 201)
    db.expire_all()
    assert db.query(User).filter(User.name == "apiuser").first() is not None


# ---------------------------------------------------------------------------
# S1 — webhook exclusion + every form carries a token
# ---------------------------------------------------------------------------

def test_webhook_works_without_csrf_token(test_client, db, monkeypatch):
    """The Telegram webhook is an unauthenticated external POST —
    authenticated by its path secret, not by a CSRF token (S1)."""
    main_mod.set_setting(db, "telegram_bot_token", "123456:TESTTOKEN")
    main_mod.set_setting(db, "telegram_chat_id", "987654321")
    main_mod.set_setting(db, "telegram_webhook_secret", "test-secret")
    sent = []
    deleted = []
    monkeypatch.setattr(
        telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "send_message_id",
        lambda token, chat_id, text, **kw: sent.append(text) or 99,
    )
    monkeypatch.setattr(
        telegram_mod, "delete_message",
        lambda token, chat_id, mid: deleted.append(mid) or True,
    )
    resp = test_client.post_raw("/telegram/webhook/test-secret", json={
        "update_id": 424242,
        "message": {
            "message_id": 1,
            "chat": {"id": 987654321, "type": "private"},
            "text": "/start",
        },
    })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # /start sends welcome + reply-keyboard hint, then deletes the hint.
    assert len(sent) == 2
    assert "sparky-manager" in sent[0]
    assert deleted == [99]


@pytest.mark.parametrize("path", [
    "/dashboard",
    "/users",
    "/inbounds",
    "/settings",
    "/logs",
])
def test_every_post_form_carries_csrf_token(authed_client, db, seeded, path):
    resp = authed_client.get(path)
    assert resp.status_code == 200
    forms = resp.text.count('<form method="post"')
    tokens = resp.text.count('name="csrf_token"')
    assert forms > 0, f"{path} has no POST forms to check"
    assert tokens == forms, (
        f"{path}: {forms} POST forms but {tokens} CSRF fields")


def test_detail_and_edit_pages_carry_csrf_tokens(
        authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    for path in (f"/users/{alice.id}", f"/users/{alice.id}/edit",
                 f"/inbounds/{vless.id}/edit"):
        resp = authed_client.get(path)
        assert resp.status_code == 200, path
        forms = resp.text.count('<form method="post"')
        tokens = resp.text.count('name="csrf_token"')
        assert forms > 0, f"{path} has no POST forms to check"
        assert tokens == forms, (
            f"{path}: {forms} POST forms but {tokens} CSRF fields")


def test_login_form_has_no_csrf_token(test_client):
    # Documented exclusion (S1): no session exists yet, so there is
    # no token to check against.
    resp = test_client.get("/login")
    assert resp.status_code == 200
    assert '<form method="post"' in resp.text
    assert 'name="csrf_token"' not in resp.text


# ---------------------------------------------------------------------------
# S3 — security headers
# ---------------------------------------------------------------------------

def test_security_headers_present(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    headers = resp.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["strict-transport-security"] == "max-age=31536000"
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    # Inline styles are needed for the dashboard chart widths, so
    # style-src keeps 'unsafe-inline' (no inline scripts exist).
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp


def test_security_headers_present_on_login_page(test_client):
    resp = test_client.get("/login")
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"


# ---------------------------------------------------------------------------
# S4 — session cookie Secure flag
# ---------------------------------------------------------------------------

def _login_set_cookie(client, **kwargs):
    resp = client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
        **kwargs)
    assert resp.status_code == 303
    return resp.headers.get("set-cookie", "")


def test_cookie_not_secure_over_plain_http(test_client):
    cookie = _login_set_cookie(test_client)
    assert main_mod.SESSION_COOKIE in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    assert "secure" not in cookie.lower()


def test_cookie_secure_over_direct_https(test_client):
    https_client = CSRFTestClient(main_mod.app, base_url="https://testserver")
    try:
        cookie = _login_set_cookie(https_client)
    finally:
        https_client.close()
    assert "secure" in cookie.lower()


def test_cookie_secure_with_trusted_forwarded_proto(test_client, monkeypatch):
    monkeypatch.setattr(main_mod, "TRUST_FORWARDED_PROTO", True)
    cookie = _login_set_cookie(
        test_client, headers={"X-Forwarded-Proto": "https"})
    assert "secure" in cookie.lower()


def test_cookie_not_secure_with_untrusted_forwarded_proto(test_client):
    # Default: the flag is off, so a client-spoofed header is ignored.
    assert main_mod.TRUST_FORWARDED_PROTO is False
    cookie = _login_set_cookie(
        test_client, headers={"X-Forwarded-Proto": "https"})
    assert "secure" not in cookie.lower()


# ---------------------------------------------------------------------------
# S5 — backup contents + old-format restore compatibility
# ---------------------------------------------------------------------------

def test_backup_zip_has_no_plaintext_settings(db_engine, db, seeded):
    main_mod.ensure_defaults(db)
    data = backup_mod.create_backup_zip(Path(db_engine.url.database))
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert set(zf.namelist()) == {"panel.db", "meta.json"}
    # The secrets still live in the DB (restore needs them) — they
    # just no longer get a second, human-readable copy.
    assert "settings.json" not in zf.namelist()


def test_restore_accepts_old_format_backup(
        authed_client, db, seeded, db_engine, tmp_path):
    """Backups downloaded before Phase 2 (with settings.json) still
    restore: validation only ever read panel.db + meta.json."""
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    main_mod.set_setting(db, "cert_path", str(cert))
    main_mod.set_setting(db, "key_path", str(key))
    db_path = Path(db_engine.url.database)
    new_data = backup_mod.create_backup_zip(db_path)
    new_zf = zipfile.ZipFile(io.BytesIO(new_data))
    # Rebuild the ZIP in the old format: panel.db + meta.json +
    # settings.json (with fake secrets, like the old exporter wrote).
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("panel.db", new_zf.read("panel.db"))
        zf.writestr("meta.json", new_zf.read("meta.json"))
        zf.writestr("settings.json", json.dumps({
            "telegram_bot_token": "OLD:FAKE-TOKEN",
            "reality_sni": "www.microsoft.com",
        }))
    old_data = buf.getvalue()

    db.expire_all()
    alice = db.query(User).filter(User.name == "alice").first()
    db.delete(alice)
    db.commit()
    assert db.query(User).filter(User.name == "alice").first() is None

    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", old_data, "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]

    fresh = SessionLocal()
    try:
        assert fresh.query(User).filter(User.name == "alice").first() is not None
        entry = (fresh.query(AuditLog)
                 .filter(AuditLog.action == "settings.restore")
                 .first())
        assert entry is not None
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# S6 — atomic DB swap
# ---------------------------------------------------------------------------

def test_swap_db_file_replaces_content_and_sidecars(tmp_path):
    live = tmp_path / "panel.db"
    live.write_bytes(b"OLD DATABASE CONTENT")
    (tmp_path / "panel.db-wal").write_bytes(b"stale wal")
    (tmp_path / "panel.db-shm").write_bytes(b"stale shm")
    new = tmp_path / "validated.db"
    new.write_bytes(b"NEW DATABASE CONTENT")
    backup_mod.swap_db_file(live, new)
    assert live.read_bytes() == b"NEW DATABASE CONTENT"
    assert not (tmp_path / "panel.db-wal").exists()
    assert not (tmp_path / "panel.db-shm").exists()
    # No temp file left behind.
    assert list(tmp_path.glob(".panel.db.swap-*")) == []


def test_swap_db_file_failure_leaves_db_untouched(tmp_path):
    live = tmp_path / "panel.db"
    live.write_bytes(b"OLD DATABASE CONTENT")
    (tmp_path / "panel.db-wal").write_bytes(b"stale wal")
    # A directory is not a readable DB file: the copy fails before
    # any rename, so the live DB must survive untouched.
    bad = tmp_path / "not-a-db"
    bad.mkdir()
    with pytest.raises(IsADirectoryError):
        backup_mod.swap_db_file(live, bad)
    assert live.read_bytes() == b"OLD DATABASE CONTENT"
    assert list(tmp_path.glob(".panel.db.swap-*")) == []
