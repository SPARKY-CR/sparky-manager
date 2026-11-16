"""Best-panel program, Phase C item 22 — passkey / WebAuthn login.

The cryptographic verification lives in the ``webauthn`` library
(Duo Labs) — these tests stub the library boundary (the verify
functions) and prove the panel's own logic: the challenge tokens,
the credential storage, the sign-count update, the routes' auth /
CSRF / lockout behavior, and that password login keeps working.
A real end-to-end ceremony needs a browser + an authenticator and
cannot run here — the manual checklist (DESIGN.md §15.5) covers
the first real registration.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app import passkeys as passkeys_mod
from app.models import Admin, PasskeyCredential
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME


def _admin(db, password_hash="fake-hash-for-hmac"):
    admin = Admin(username="admin", password_hash=password_hash)
    db.add(admin)
    db.commit()
    return admin


def _stored_key(db, admin, credential_id=b"cred-id-1", sign_count=3):
    row = PasskeyCredential(
        admin_id=admin.id,
        credential_id=bytes_to_base64url(credential_id),
        public_key=bytes_to_base64url(b"fake-cose-public-key"),
        sign_count=sign_count,
        name="My phone",
        rp_id="testserver",
    )
    db.add(row)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# Challenge tokens (stateless, HMAC-signed, 5-minute)
# ---------------------------------------------------------------------------


def test_challenge_token_round_trip(db):
    admin = _admin(db)
    token = passkeys_mod.make_challenge_token(
        admin, "login", b"some-challenge", "testserver"
    )
    verified = passkeys_mod.verify_challenge_token(db, token, "login")
    assert verified is not None
    found_admin, challenge, rp_id = verified
    assert found_admin.id == admin.id
    assert challenge == b"some-challenge"
    assert rp_id == "testserver"


def test_challenge_token_wrong_purpose_rejected(db):
    admin = _admin(db)
    token = passkeys_mod.make_challenge_token(
        admin, "register", b"c", "testserver"
    )
    assert passkeys_mod.verify_challenge_token(db, token, "login") is None
    assert (
        passkeys_mod.verify_challenge_token(db, token, "register")
        is not None
    )


def test_challenge_token_expired_rejected(db):
    admin = _admin(db)
    token = passkeys_mod.make_challenge_token(
        admin, "login", b"c", "testserver", now=1000.0
    )
    # Made at t=1000 with a 5-minute TTL — long expired by now.
    assert passkeys_mod.verify_challenge_token(db, token, "login") is None


def test_challenge_token_tampered_rejected(db):
    admin = _admin(db)
    token = passkeys_mod.make_challenge_token(
        admin, "login", b"c", "testserver"
    )
    assert passkeys_mod.verify_challenge_token(db, token + "x", "login") is None
    assert passkeys_mod.verify_challenge_token(db, "garbage", "login") is None
    assert passkeys_mod.verify_challenge_token(db, "", "login") is None


def test_challenge_token_dies_on_password_change(db):
    admin = _admin(db)
    token = passkeys_mod.make_challenge_token(
        admin, "login", b"c", "testserver"
    )
    admin.password_hash = "a-different-hash"
    db.commit()
    assert passkeys_mod.verify_challenge_token(db, token, "login") is None


def test_make_challenge_token_rejects_bad_purpose(db):
    admin = _admin(db)
    with pytest.raises(ValueError):
        passkeys_mod.make_challenge_token(admin, "bogus", b"c", "testserver")


# ---------------------------------------------------------------------------
# Registration (library boundary stubbed)
# ---------------------------------------------------------------------------


def test_begin_registration_returns_options_and_token(db):
    admin = _admin(db)
    _stored_key(db, admin)
    existing = [b"cred-id-1"]
    options, token = passkeys_mod.begin_registration(
        admin, "testserver", existing
    )
    assert options["rp"]["id"] == "testserver"
    assert options["rp"]["name"] == "sparky-manager"
    assert options["user"]["name"] == "admin"
    # The already-registered credential is excluded.
    assert options["excludeCredentials"] == [
        {"id": bytes_to_base64url(b"cred-id-1"), "type": "public-key"}
    ]
    # The token's challenge matches the options' challenge.
    _a, challenge, _r = passkeys_mod.verify_challenge_token(
        db, token, "register"
    )
    assert challenge == base64url_to_bytes(options["challenge"])


def test_finish_registration_stores_credential(db, monkeypatch):
    admin = _admin(db)
    options, token = passkeys_mod.begin_registration(admin, "testserver", [])
    fake = SimpleNamespace(
        credential_id=b"new-cred",
        credential_public_key=b"new-cose-key",
        sign_count=0,
    )
    monkeypatch.setattr(
        passkeys_mod, "verify_registration_response", lambda **kw: fake
    )
    credential = {
        "id": bytes_to_base64url(b"new-cred"),
        "rawId": bytes_to_base64url(b"new-cred"),
        "type": "public-key",
        "response": {"transports": ["internal", "usb"]},
    }
    row = passkeys_mod.finish_registration(
        db, admin, token, credential, "My laptop", "http://testserver"
    )
    assert row.credential_id == bytes_to_base64url(b"new-cred")
    assert row.public_key == bytes_to_base64url(b"new-cose-key")
    assert row.name == "My laptop"
    assert row.rp_id == "testserver"
    assert row.transports == ["internal", "usb"]
    assert db.query(PasskeyCredential).count() == 1


def test_finish_registration_rejects_bad_challenge(db, monkeypatch):
    admin = _admin(db)
    monkeypatch.setattr(
        passkeys_mod,
        "verify_registration_response",
        lambda **kw: (_ for _ in ()).throw(AssertionError("must not verify")),
    )
    with pytest.raises(ValueError):
        passkeys_mod.finish_registration(
            db, admin, "bogus-token", {}, "x", "http://testserver"
        )


def test_finish_registration_rejects_duplicate(db, monkeypatch):
    admin = _admin(db)
    _stored_key(db, admin, credential_id=b"dup-cred")
    options, token = passkeys_mod.begin_registration(admin, "testserver", [])
    fake = SimpleNamespace(
        credential_id=b"dup-cred",
        credential_public_key=b"key",
        sign_count=0,
    )
    monkeypatch.setattr(
        passkeys_mod, "verify_registration_response", lambda **kw: fake
    )
    with pytest.raises(ValueError):
        passkeys_mod.finish_registration(
            db, admin, token, {}, "again", "http://testserver"
        )


def test_finish_registration_verification_failure(db, monkeypatch):
    admin = _admin(db)
    options, token = passkeys_mod.begin_registration(admin, "testserver", [])

    def _fail(**kw):
        raise ValueError("bad signature")

    monkeypatch.setattr(passkeys_mod, "verify_registration_response", _fail)
    with pytest.raises(ValueError):
        passkeys_mod.finish_registration(
            db, admin, token, {}, "x", "http://testserver"
        )
    assert db.query(PasskeyCredential).count() == 0


# ---------------------------------------------------------------------------
# Login (library boundary stubbed)
# ---------------------------------------------------------------------------


def test_begin_login_requires_a_passkey(db):
    admin = _admin(db)
    with pytest.raises(ValueError):
        passkeys_mod.begin_login(admin, "testserver", [])


def test_finish_login_updates_sign_count(db, monkeypatch):
    admin = _admin(db)
    row = _stored_key(db, admin, sign_count=3)
    options, token = passkeys_mod.begin_login(admin, "testserver", [row])
    fake = SimpleNamespace(new_sign_count=4)
    seen = {}
    def _verify(**kw):
        seen.update(kw)
        return fake
    monkeypatch.setattr(passkeys_mod, "verify_authentication_response", _verify)
    credential = {
        "id": row.credential_id,
        "rawId": row.credential_id,
        "type": "public-key",
        "response": {},
    }
    used = passkeys_mod.finish_login(
        db, token, credential, "http://testserver"
    )
    assert used.id == row.id
    assert used.sign_count == 4
    assert used.last_used_at is not None
    # The library got the stored public key + the stored sign count.
    assert seen["credential_public_key"] == b"fake-cose-public-key"
    assert seen["credential_current_sign_count"] == 3
    assert seen["expected_rp_id"] == "testserver"


def test_finish_login_unknown_credential_rejected(db, monkeypatch):
    admin = _admin(db)
    row = _stored_key(db, admin)
    options, token = passkeys_mod.begin_login(admin, "testserver", [row])
    monkeypatch.setattr(
        passkeys_mod,
        "verify_authentication_response",
        lambda **kw: (_ for _ in ()).throw(AssertionError("must not verify")),
    )
    with pytest.raises(ValueError):
        passkeys_mod.finish_login(
            db,
            token,
            {"id": "nobody", "rawId": "nobody"},
            "http://testserver",
        )


# ---------------------------------------------------------------------------
# Routes — login page + passkey login
# ---------------------------------------------------------------------------


def test_login_page_hides_passkey_button_without_keys(test_client):
    resp = test_client.get("/login")
    assert resp.status_code == 200
    assert "passkey-login-btn" not in resp.text
    assert "passkey.js" not in resp.text


def test_login_page_shows_passkey_button_with_keys(test_client, db):
    admin = db.query(Admin).order_by(Admin.id).first()
    _stored_key(db, admin)
    resp = test_client.get("/login")
    assert resp.status_code == 200
    assert "passkey-login-btn" in resp.text
    assert "passkey.js" in resp.text


def test_passkey_js_served(test_client):
    resp = test_client.get("/static/passkey.js")
    assert resp.status_code == 200
    assert "navigator.credentials" in resp.text


def test_login_passkey_begin_no_keys_is_400(test_client):
    resp = test_client.post("/login/passkey/begin", json={})
    assert resp.status_code == 400


def test_login_passkey_begin_with_keys(test_client, db):
    admin = db.query(Admin).order_by(Admin.id).first()
    row = _stored_key(db, admin)
    resp = test_client.post("/login/passkey/begin", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["options"]["rpId"] == "testserver"
    assert data["options"]["allowCredentials"] == [
        {"id": row.credential_id, "type": "public-key"}
    ]
    assert data["challenge_token"]


def test_login_passkey_finish_success_creates_session(
    test_client, db, monkeypatch
):
    admin = db.query(Admin).order_by(Admin.id).first()
    row = _stored_key(db, admin, sign_count=3)
    begin = test_client.post("/login/passkey/begin", json={})
    token = begin.json()["challenge_token"]
    fake = SimpleNamespace(new_sign_count=4)
    monkeypatch.setattr(
        passkeys_mod,
        "verify_authentication_response",
        lambda **kw: fake,
    )
    resp = test_client.post(
        "/login/passkey/finish",
        json={
            "credential": {
                "id": row.credential_id,
                "rawId": row.credential_id,
                "type": "public-key",
                "response": {},
            },
            "challenge_token": token,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["redirect"].endswith("/dashboard")
    # A session cookie was set — the next request is authenticated.
    resp2 = test_client.get("/dashboard")
    assert resp2.status_code == 200
    # And the sign count advanced.
    db.expire_all()
    assert db.get(PasskeyCredential, row.id).sign_count == 4


def test_login_passkey_finish_bad_token_is_401(test_client):
    resp = test_client.post(
        "/login/passkey/finish",
        json={"credential": {}, "challenge_token": "bogus"},
    )
    assert resp.status_code == 401


def test_login_passkey_failures_count_toward_lockout(test_client):
    # Five bad passkey attempts lock the IP out, like five bad passwords.
    for _ in range(5):
        resp = test_client.post(
            "/login/passkey/finish",
            json={"credential": {}, "challenge_token": "bogus"},
        )
        assert resp.status_code == 401
    resp = test_client.post("/login/passkey/begin", json={})
    assert resp.status_code == 429


def test_password_login_still_works_with_passkeys(test_client, db):
    admin = db.query(Admin).order_by(Admin.id).first()
    _stored_key(db, admin)
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].endswith("/dashboard")


# ---------------------------------------------------------------------------
# Routes — registration (admin-only, CSRF-protected JSON)
# ---------------------------------------------------------------------------


def test_register_begin_requires_admin(test_client):
    resp = test_client.post("/settings/passkeys/begin", json={})
    assert resp.status_code == 401


def test_register_begin_requires_csrf(authed_client):
    resp = authed_client.post_raw("/settings/passkeys/begin", json={})
    assert resp.status_code == 403


def test_register_begin_ok(authed_client):
    resp = authed_client.post("/settings/passkeys/begin", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["options"]["rp"]["id"] == "testserver"
    assert data["challenge_token"]


def test_register_finish_ok(authed_client, db, monkeypatch):
    begin = authed_client.post("/settings/passkeys/begin", json={})
    token = begin.json()["challenge_token"]
    fake = SimpleNamespace(
        credential_id=b"reg-cred",
        credential_public_key=b"reg-key",
        sign_count=0,
    )
    monkeypatch.setattr(
        passkeys_mod, "verify_registration_response", lambda **kw: fake
    )
    resp = authed_client.post(
        "/settings/passkeys/finish",
        json={
            "credential": {"id": "x", "response": {}},
            "challenge_token": token,
            "name": "YubiKey",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert db.query(PasskeyCredential).count() == 1
    row = db.query(PasskeyCredential).first()
    assert row.name == "YubiKey"


def test_register_finish_bad_challenge_is_400(authed_client):
    resp = authed_client.post(
        "/settings/passkeys/finish",
        json={"credential": {}, "challenge_token": "bogus", "name": "x"},
    )
    assert resp.status_code == 400


def test_settings_page_lists_passkeys(authed_client, db):
    admin = db.query(Admin).order_by(Admin.id).first()
    _stored_key(db, admin)
    resp = authed_client.get("/settings?section=security")
    assert resp.status_code == 200
    assert "My phone" in resp.text
    assert "passkey.js" in resp.text


def test_register_button_carries_csrf_token(authed_client):
    # passkey.js reads the CSRF token from the register button's
    # data-csrf-token attribute (the form is JS-only, not a POST
    # form, so it carries no hidden csrf_token field — the UI
    # tests require POST forms and CSRF fields to match 1:1).
    # Without the attribute the JS would silently send no token
    # and registration would 403.
    resp = authed_client.get("/settings?section=security")
    assert resp.status_code == 200
    assert 'id="passkey-register-btn"' in resp.text
    assert 'data-csrf-token="' in resp.text
    form = resp.text.split('id="passkey-register-form"')[1].split("</form>")[0]
    assert 'name="csrf_token"' not in form


def test_delete_passkey(authed_client, db):
    admin = db.query(Admin).order_by(Admin.id).first()
    row = _stored_key(db, admin)
    resp = authed_client.post(
        f"/settings/passkeys/{row.id}/delete", data={}
    )
    assert resp.status_code in (200, 303)
    assert db.query(PasskeyCredential).count() == 0


def test_delete_passkey_wrong_id_redirects_with_error(authed_client, db):
    resp = authed_client.post("/settings/passkeys/99999/delete", data={})
    assert resp.status_code in (200, 303)
