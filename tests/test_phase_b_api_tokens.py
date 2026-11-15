"""Phase B item 12 — scoped, expiring API tokens.

Tokens are random (``spk_`` + 32 urlsafe bytes), stored only as a
SHA-256 hash — the plaintext is shown to the admin exactly once, at
creation, and never again. The v1 endpoints are read-only; a
missing/invalid/expired token gets 401, a valid token without the
scope gets 403.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import api_tokens as api_tokens_mod
from app.models import ApiToken


def _make_token(db, scopes=("admin",), **kwargs):
    row, raw = api_tokens_mod.create_token(
        db, "script", list(scopes), **kwargs
    )
    return row, raw


# ---------------------------------------------------------------------------
# Creation + storage
# ---------------------------------------------------------------------------

def test_create_token_returns_prefixed_raw_and_stores_hash(db):
    row, raw = _make_token(db)
    assert raw.startswith("spk_")
    assert len(raw) > 20
    # Only the hash is stored — the raw token appears nowhere in the DB.
    assert row.token_hash == api_tokens_mod.hash_token(raw)
    assert row.token_hash != raw
    assert raw not in (row.name, row.scopes_json)


def test_create_token_drops_unknown_scopes_and_sorts(db):
    row, _raw = _make_token(
        db, scopes=("users:read", "bogus:scope", "status:read")
    )
    assert row.scopes == ["status:read", "users:read"]


def test_create_token_empty_scopes_stay_empty(db):
    row, _raw = _make_token(db, scopes=())
    assert row.scopes == []


def test_create_token_via_post_renders_raw_once(authed_client, db):
    resp = authed_client.post(
        "/api-tokens",
        data={
            "name": "monitor",
            "scopes": ["status:read"],
            "expires_days": "30",
        },
    )
    assert resp.status_code == 200, resp.text
    # The raw token is on THIS page (the one-time render) …
    assert "spk_" in resp.text
    row = db.query(ApiToken).filter_by(name="monitor").one()
    assert row.expires_at is not None
    assert row.scopes == ["status:read"]
    # … and nowhere else: the list page never shows raw tokens.
    page = authed_client.get("/api-tokens")
    assert page.status_code == 200
    assert "spk_" not in page.text
    assert "monitor" in page.text


def test_create_token_bad_expiry_redirects_with_error(authed_client, db):
    resp = authed_client.post(
        "/api-tokens",
        data={"name": "bad", "expires_days": "not-a-number"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(ApiToken).filter_by(name="bad").first() is None


def test_revoke_token_via_post(authed_client, db):
    row, raw = _make_token(db)
    token_id = row.id
    resp = authed_client.post(f"/api-tokens/{token_id}/revoke",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(ApiToken, token_id) is None
    # The raw token no longer verifies (the hash is gone).
    assert api_tokens_mod.verify_token(db, raw) is None


def test_revoke_missing_token_404s(authed_client):
    resp = authed_client.post("/api-tokens/99999/revoke",
                              follow_redirects=False)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_verify_token_valid_stamps_last_used(db):
    row, raw = _make_token(db)
    assert row.last_used_at is None
    verified = api_tokens_mod.verify_token(db, raw)
    assert verified is not None
    assert verified.id == row.id
    assert verified.last_used_at is not None


def test_verify_token_wrong_or_empty_returns_none(db):
    _make_token(db)
    assert api_tokens_mod.verify_token(db, "spk_wrong") is None
    assert api_tokens_mod.verify_token(db, "") is None
    assert api_tokens_mod.verify_token(db, None) is None


def test_verify_token_expired_returns_none_but_keeps_row(db):
    past = datetime.now(timezone.utc) - timedelta(days=1)
    row, raw = _make_token(db, expires_at=past)
    assert api_tokens_mod.verify_token(db, raw) is None
    # An expired token is NOT deleted — the admin can see it expired
    # and revoke it by hand.
    assert db.get(ApiToken, row.id) is not None


def test_token_has_scope_admin_satisfies_all(db):
    row, _raw = _make_token(db, scopes=("admin",))
    assert api_tokens_mod.token_has_scope(row, "status:read")
    assert api_tokens_mod.token_has_scope(row, "users:read")
    assert api_tokens_mod.token_has_scope(row, "inbounds:read")
    row2, _raw2 = _make_token(db, scopes=("status:read",))
    assert api_tokens_mod.token_has_scope(row2, "status:read")
    assert not api_tokens_mod.token_has_scope(row2, "users:read")


# ---------------------------------------------------------------------------
# The v1 endpoints
# ---------------------------------------------------------------------------

def test_api_status_requires_token(test_client):
    resp = test_client.get("/api/v1/status")
    assert resp.status_code == 401


def test_api_status_with_bearer_token(test_client, db, seeded):
    _row, raw = _make_token(db, scopes=("status:read",))
    resp = test_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["users"] == 5  # the seeded users
    assert data["inbounds"] == len(seeded["inbounds"])
    assert data["traffic_used_bytes"] == 1000  # carol's usage


def test_api_key_header_works(test_client, db):
    _row, raw = _make_token(db, scopes=("status:read",))
    resp = test_client.get("/api/v1/status", headers={"X-API-Key": raw})
    assert resp.status_code == 200


def test_api_wrong_scope_gets_403(test_client, db):
    _row, raw = _make_token(db, scopes=("status:read",))
    resp = test_client.get(
        "/api/v1/users", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 403


def test_api_no_scope_token_authenticates_but_authorizes_nothing(
    test_client, db
):
    _row, raw = _make_token(db, scopes=())
    resp = test_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 403  # authenticated, no scope


def test_api_admin_token_reaches_every_endpoint(test_client, db, seeded):
    _row, raw = _make_token(db, scopes=("admin",))
    headers = {"Authorization": f"Bearer {raw}"}
    assert test_client.get("/api/v1/status", headers=headers).status_code == 200
    users = test_client.get("/api/v1/users", headers=headers)
    assert users.status_code == 200
    assert {u["name"] for u in users.json()} == {
        "alice", "bob", "carol", "dave", "eve"
    }
    alice = seeded["users"]["alice"]
    one = test_client.get(f"/api/v1/users/{alice.id}", headers=headers)
    assert one.status_code == 200
    assert one.json()["name"] == "alice"
    missing = test_client.get("/api/v1/users/99999", headers=headers)
    assert missing.status_code == 404
    inbounds = test_client.get("/api/v1/inbounds", headers=headers)
    assert inbounds.status_code == 200
    assert len(inbounds.json()) == len(seeded["inbounds"])


def test_api_expired_token_gets_401(test_client, db):
    past = datetime.now(timezone.utc) - timedelta(days=1)
    _row, raw = _make_token(db, expires_at=past)
    resp = test_client.get(
        "/api/v1/status", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 401


def test_api_token_does_not_need_csrf_or_session(test_client, db):
    """The v1 endpoints take no cookie — a token-only request from
    an unauthenticated client works (CSRF does not apply)."""
    _row, raw = _make_token(db, scopes=("inbounds:read",))
    resp = test_client.get(
        "/api/v1/inbounds", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 200
