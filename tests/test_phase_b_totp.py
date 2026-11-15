"""Phase B item 13 — TOTP 2FA for the admin login.

Pure-stdlib RFC 6238 (no pyotp — no new dependency). The secret +
recovery-code hashes live in the settings table (no schema change);
the pending-login token is HMAC-signed with the admin's password
hash (stateless, 5-minute expiry, dies on password change). The
login failure counter clears only after the TOTP code verifies —
clearing at the password step would let a password-holding attacker
brute-force the 6-digit code without lockout.
"""

from __future__ import annotations

import re
import time

import pytest

from app import panel_cli as cli_mod
from app import totp as totp_mod
from app.models import Admin
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

# RFC 6238 Appendix B test secret ("12345678901234567890"), base32.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
# (unix time, 6-digit code) — the 6-digit code is the last 6 digits
# of the RFC's 8-digit vector (same dynamic truncation, mod 10^6).
RFC_VECTORS = [
    (59, "287082"),  # 8-digit 94287082
    (1111111109, "081804"),  # 8-digit 07081804
    (1234567890, "005924"),  # 8-digit 89005924
    (2000000000, "279037"),  # 8-digit 69279037
    (20000000000, "353130"),  # 8-digit 65353130
]


def _enable_totp(db, secret=RFC_SECRET):
    """Enable TOTP directly (bypassing the setup page)."""
    totp_mod.begin_setup(db)
    # begin_setup generates its own secret — overwrite with the
    # known one, then complete.
    from app.webcommon import set_setting

    set_setting(db, totp_mod.TOTP_PENDING_SECRET_KEY, secret)
    return totp_mod.complete_setup(db, secret)


def _login_to_totp(test_client):
    """POST /login with the right password while TOTP is on:
    returns the response (a redirect to /login/totp)."""
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login/totp")
    return resp


# ---------------------------------------------------------------------------
# The TOTP core against the RFC vectors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("moment,expected", RFC_VECTORS)
def test_totp_code_matches_rfc_6238_vectors(moment, expected):
    assert totp_mod.totp_code(RFC_SECRET, at=float(moment)) == expected


def test_totp_code_rejects_malformed_secret():
    with pytest.raises(ValueError):
        totp_mod.totp_code("not-base32!!")


def test_verify_code_window():
    now = time.time()
    code = totp_mod.totp_code(RFC_SECRET, at=now)
    assert totp_mod.verify_code(RFC_SECRET, code, at=now)
    # One step either side (clock skew) is accepted …
    assert totp_mod.verify_code(
        RFC_SECRET, totp_mod.totp_code(RFC_SECRET, at=now - 30), at=now
    )
    assert totp_mod.verify_code(
        RFC_SECRET, totp_mod.totp_code(RFC_SECRET, at=now + 30), at=now
    )
    # … two steps out is not.
    assert not totp_mod.verify_code(
        RFC_SECRET, totp_mod.totp_code(RFC_SECRET, at=now - 60), at=now
    )
    assert not totp_mod.verify_code(
        RFC_SECRET, totp_mod.totp_code(RFC_SECRET, at=now + 60), at=now
    )


def test_verify_code_rejects_non_digits():
    assert not totp_mod.verify_code(RFC_SECRET, "abcdef")
    assert not totp_mod.verify_code(RFC_SECRET, "12345")
    assert not totp_mod.verify_code(RFC_SECRET, "1234567")
    assert not totp_mod.verify_code(RFC_SECRET, "")
    assert not totp_mod.verify_code(RFC_SECRET, None)


def test_verify_code_accepts_spaced_code():
    now = time.time()
    code = totp_mod.totp_code(RFC_SECRET, at=now)
    assert totp_mod.verify_code(RFC_SECRET, f"{code[:3]} {code[3:]}",
                                at=now)


def test_provisioning_uri_shape():
    uri = totp_mod.provisioning_uri(RFC_SECRET, "admin")
    assert uri.startswith("otpauth://totp/sparky-manager%3Aadmin?")
    assert f"secret={RFC_SECRET}" in uri
    assert "algorithm=SHA1&digits=6&period=30" in uri


# ---------------------------------------------------------------------------
# Setup flow (HTTP)
# ---------------------------------------------------------------------------

def test_setup_page_renders_qr_and_secret(authed_client, db):
    resp = authed_client.get("/settings/totp/setup")
    assert resp.status_code == 200
    assert "/settings/totp/qr" in resp.text
    # The pending secret is shown (and stored) — the admin can type
    # it by hand instead of scanning.
    secret = totp_mod.get_pending_secret(db)
    assert secret
    assert secret in resp.text


def test_setup_page_reuses_pending_secret_on_refresh(authed_client, db):
    authed_client.get("/settings/totp/setup")
    first = totp_mod.get_pending_secret(db)
    authed_client.get("/settings/totp/setup")
    assert totp_mod.get_pending_secret(db) == first


def test_qr_route_404_without_pending_setup(authed_client, db):
    assert totp_mod.get_pending_secret(db) == ""
    resp = authed_client.get("/settings/totp/qr")
    assert resp.status_code == 404


def test_qr_route_serves_png_with_pending_setup(authed_client, db):
    authed_client.get("/settings/totp/setup")
    resp = authed_client.get("/settings/totp/qr")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content.startswith(b"\x89PNG")


def test_setup_submit_wrong_code_rejected(authed_client, db):
    authed_client.get("/settings/totp/setup")
    resp = authed_client.post("/settings/totp/setup",
                              data={"code": "000000"})
    assert resp.status_code == 200  # re-rendered with an error
    assert not totp_mod.is_totp_enabled(db)


def test_setup_submit_correct_code_shows_recovery_codes_once(
    authed_client, db
):
    authed_client.get("/settings/totp/setup")
    secret = totp_mod.get_pending_secret(db)
    code = totp_mod.totp_code(secret)
    resp = authed_client.post("/settings/totp/setup", data={"code": code})
    assert resp.status_code == 200
    assert totp_mod.is_totp_enabled(db)
    assert totp_mod.recovery_codes_remaining(db) == 8
    # The codes are on THIS page (the one-time render) …
    assert "کدهای بازیابی" in resp.text
    codes_on_page = re.findall(
        r"<code dir=\"ltr\">([0-9a-f]{10})</code>", resp.text
    )
    assert len(codes_on_page) == 8
    # … and the pending secret is gone (the setup is complete).
    assert totp_mod.get_pending_secret(db) == ""
    # … and a second visit to the setup page does NOT show them again
    # (only their hashes are stored — this render was the only copy).
    again = authed_client.get("/settings/totp/setup")
    assert again.status_code == 200
    for shown in codes_on_page:
        assert shown not in again.text


# ---------------------------------------------------------------------------
# Login flow with TOTP on
# ---------------------------------------------------------------------------

def test_login_with_totp_requires_second_step(test_client, db):
    _enable_totp(db)
    _login_to_totp(test_client)
    # No session yet — the dashboard still redirects to login.
    resp = test_client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_login_totp_page_without_pending_token_redirects(test_client, db):
    _enable_totp(db)
    resp = test_client.get("/login/totp", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_login_totp_correct_code_creates_session(test_client, db):
    _enable_totp(db)
    _login_to_totp(test_client)
    code = totp_mod.totp_code(RFC_SECRET)
    resp = test_client.post(
        "/login/totp", data={"code": code}, follow_redirects=False
    )
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"].endswith("/dashboard")
    # The session works now.
    page = test_client.get("/dashboard")
    assert page.status_code == 200


def test_login_totp_wrong_code_rejected_no_session(test_client, db):
    _enable_totp(db)
    _login_to_totp(test_client)
    resp = test_client.post("/login/totp", data={"code": "000000"})
    assert resp.status_code == 401  # re-rendered with an error
    page = test_client.get("/dashboard", follow_redirects=False)
    assert page.status_code == 303


def test_login_totp_recovery_code_works_once(test_client, db):
    codes = _enable_totp(db)
    _login_to_totp(test_client)
    resp = test_client.post(
        "/login/totp", data={"code": codes[0]}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"].endswith("/dashboard")
    assert totp_mod.recovery_codes_remaining(db) == 7
    # The same code never works twice (consumed on first use).
    assert not totp_mod.verify_recovery_code(db, codes[0])
    assert totp_mod.recovery_codes_remaining(db) == 7


def test_login_totp_forged_pending_token_rejected(test_client, db):
    _enable_totp(db)
    test_client.cookies.set("sparky_manager_pending", "forged.token.here")
    resp = test_client.get("/login/totp", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_pending_token_expires_and_dies_on_password_change(db, test_client):
    # (test_client creates the admin via ensure_defaults.)
    admin = db.query(Admin).first()
    assert admin is not None
    token = totp_mod.make_pending_token(admin)
    assert totp_mod.verify_pending_token(db, token) is not None
    # Expired (5-minute TTL).
    old = totp_mod.make_pending_token(
        admin, now=time.time() - totp_mod.PENDING_TOKEN_TTL_SECONDS - 1
    )
    assert totp_mod.verify_pending_token(db, old) is None
    # A password change invalidates it (the HMAC key is the hash).
    admin.password_hash = "changed-hash"
    db.commit()
    assert totp_mod.verify_pending_token(db, token) is None


def test_wrong_totp_codes_count_toward_lockout(test_client, db):
    """Five wrong TOTP codes lock the IP out — the failure counter
    is NOT cleared at the password step (a password-holding
    attacker cannot brute-force the 6-digit code for free)."""
    _enable_totp(db)
    for _ in range(5):
        _login_to_totp(test_client)
        resp = test_client.post("/login/totp", data={"code": "000000"})
        assert resp.status_code == 401
    # The sixth password attempt is now locked out (429).
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Disable flow + CLI recovery
# ---------------------------------------------------------------------------

def test_disable_with_code(authed_client, db):
    _enable_totp(db)
    code = totp_mod.totp_code(RFC_SECRET)
    resp = authed_client.post(
        "/settings/totp/disable", data={"code": code},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert not totp_mod.is_totp_enabled(db)


def test_disable_with_wrong_code_rejected(authed_client, db):
    _enable_totp(db)
    resp = authed_client.post(
        "/settings/totp/disable", data={"code": "000000"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert totp_mod.is_totp_enabled(db)


def test_disable_with_recovery_code(authed_client, db):
    codes = _enable_totp(db)
    resp = authed_client.post(
        "/settings/totp/disable", data={"code": codes[0]},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert not totp_mod.is_totp_enabled(db)


def test_cli_totp_disable_recovers_lockout(db, capsys):
    _enable_totp(db)
    assert totp_mod.is_totp_enabled(db)
    assert cli_mod.main(["totp-disable"]) == 0
    assert not totp_mod.is_totp_enabled(db)
    assert "disabled" in capsys.readouterr().out
    # A second run reports that it was already off.
    assert cli_mod.main(["totp-disable"]) == 0
    assert "not enabled" in capsys.readouterr().out


def test_login_without_totp_unchanged(test_client, db):
    """With 2FA off, the login flow is exactly the old one — no
    /login/totp detour."""
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].endswith("/dashboard")
