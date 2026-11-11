"""Auth tests (DESIGN.md §7) — password hashing, sessions, lockout.

Written from scratch against the real ``app.auth`` signatures.
The 15-minute lockout window is tested without sleeping: the module
keeps its failure timestamps in an in-memory dict, so the test
backdates those timestamps to simulate the window passing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import auth
from app.auth import (
    LOCKOUT_SECONDS,
    MAX_FAILED_LOGINS,
    create_session,
    get_admin_from_token,
    hash_password,
    invalidate_session,
    is_locked_out,
    record_failed_login,
    record_successful_login,
    verify_password,
)
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME


# ---------------------------------------------------------------------------
# Password hashing (pbkdf2$iterations$salt$hash)
# ---------------------------------------------------------------------------

def test_hash_format_and_verify():
    stored = hash_password("correct horse", iterations=1000)
    assert stored.startswith("pbkdf2$1000$")
    assert len(stored.split("$")) == 4
    assert verify_password("correct horse", stored) is True
    assert verify_password("correct hors", stored) is False
    assert verify_password("", stored) is False


def test_hash_uses_a_fresh_salt_each_time():
    assert hash_password("same", iterations=1000) != hash_password(
        "same", iterations=1000)


def test_hash_default_iterations_verify():
    stored = hash_password("default-iterations-password")
    assert stored.startswith("pbkdf2$600000$")
    assert verify_password("default-iterations-password", stored) is True


@pytest.mark.parametrize("bad_stored", [
    "",
    "garbage",
    "argon2$1$abcd$efgh",          # unknown scheme
    "pbkdf2$notanumber$abcd$efgh",  # bad iteration count
    "pbkdf2$1000$zzzz$efgh",        # salt is not hex
    "pbkdf2$1000$abcd",             # too few $-separated parts
    "pbkdf2$1000$abcd$efgh$extra",  # too many parts
    None,
    123,
])
def test_verify_malformed_hash_returns_false(bad_stored):
    assert verify_password("anything", bad_stored) is False


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def test_session_create_lookup_invalidate(db, seeded):
    from app.models import Admin
    admin = db.query(Admin).filter(Admin.username == "admin").first()
    if admin is None:
        # The db fixture does not create an admin; make one here.
        admin = Admin(username="admin",
                      password_hash=hash_password("pw", iterations=1000))
        db.add(admin)
        db.commit()
    token = create_session(db, admin, ip="127.0.0.1")
    assert isinstance(token, str) and len(token) > 20
    # Only the token *hash* is stored, never the raw token.
    from app.models import Session as LoginSession
    rows = db.query(LoginSession).all()
    assert len(rows) == 1
    assert rows[0].token_hash != token
    assert get_admin_from_token(db, token).id == admin.id
    assert get_admin_from_token(db, "never-issued-token") is None
    assert get_admin_from_token(db, "") is None
    assert invalidate_session(db, "never-issued-token") is False
    assert invalidate_session(db, token) is True
    assert get_admin_from_token(db, token) is None
    assert invalidate_session(db, token) is False


def test_expired_session_returns_none_and_is_removed(db):
    from app.models import Admin, Session as LoginSession
    admin = Admin(username="admin",
                  password_hash=hash_password("pw", iterations=1000))
    db.add(admin)
    db.commit()
    token = create_session(db, admin)
    row = db.query(LoginSession).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert get_admin_from_token(db, token) is None
    assert db.query(LoginSession).count() == 0


def test_two_sessions_are_independent(db):
    from app.models import Admin
    admin = Admin(username="admin",
                  password_hash=hash_password("pw", iterations=1000))
    db.add(admin)
    db.commit()
    first = create_session(db, admin)
    second = create_session(db, admin)
    assert first != second
    assert invalidate_session(db, first) is True
    assert get_admin_from_token(db, first) is None
    assert get_admin_from_token(db, second) is not None


# ---------------------------------------------------------------------------
# Lockout: 5 failures -> locked; success clears; window expiry unlocks
# ---------------------------------------------------------------------------

def test_lockout_triggers_at_five_failures():
    ip = "198.51.100.11"
    assert is_locked_out(ip) is False
    for _ in range(MAX_FAILED_LOGINS - 1):
        record_failed_login(ip)
        assert is_locked_out(ip) is False
    record_failed_login(ip)
    assert is_locked_out(ip) is True


def test_successful_login_clears_failures():
    ip = "198.51.100.12"
    for _ in range(MAX_FAILED_LOGINS):
        record_failed_login(ip)
    assert is_locked_out(ip) is True
    record_successful_login(ip)
    assert is_locked_out(ip) is False


def test_lockout_expires_after_window_without_sleeping():
    ip = "198.51.100.13"
    for _ in range(MAX_FAILED_LOGINS):
        record_failed_login(ip)
    assert is_locked_out(ip) is True
    # Simulate 15 minutes passing by backdating the stored timestamps
    # (the module's own in-memory record — no sleeping).
    import time
    old = time.time() - LOCKOUT_SECONDS - 1
    auth._failed_logins[ip] = [old] * MAX_FAILED_LOGINS
    assert is_locked_out(ip) is False


def test_lockout_is_per_ip():
    record_failed_login("198.51.100.14")
    for _ in range(MAX_FAILED_LOGINS):
        record_failed_login("198.51.100.15")
    assert is_locked_out("198.51.100.14") is False
    assert is_locked_out("198.51.100.15") is True


# ---------------------------------------------------------------------------
# HTTP login flow
# ---------------------------------------------------------------------------

def test_login_happy_path_and_logout(test_client):
    resp = test_client.post("/login", data={
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert resp.status_code == 200
    assert test_client.get("/dashboard").status_code == 200
    assert test_client.get("/api/users").status_code == 200
    resp = test_client.get("/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert test_client.get("/dashboard",
                           follow_redirects=False).status_code == 303
    assert test_client.get("/api/users").status_code == 401


def test_login_wrong_password_401(test_client):
    resp = test_client.post("/login", data={
        "username": ADMIN_USERNAME, "password": "wrong-password"})
    assert resp.status_code == 401
    assert test_client.get("/api/users").status_code == 401


def test_login_unknown_user_401(test_client):
    resp = test_client.post("/login", data={
        "username": "nobody", "password": "whatever"})
    assert resp.status_code == 401


def test_login_five_failures_lock_out_http(test_client):
    for _ in range(MAX_FAILED_LOGINS):
        resp = test_client.post("/login", data={
            "username": ADMIN_USERNAME, "password": "wrong"})
        assert resp.status_code == 401
    # The 6th attempt — even with the RIGHT password — is locked out.
    resp = test_client.post("/login", data={
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert resp.status_code == 429


def test_protected_pages_redirect_to_login_when_logged_out(test_client):
    for url in ("/dashboard", "/users", "/inbounds", "/settings"):
        resp = test_client.get(url, follow_redirects=False)
        assert resp.status_code == 303, url
        assert resp.headers["location"].startswith("/login"), url
    assert test_client.get("/health").json() == {"status": "ok"}
