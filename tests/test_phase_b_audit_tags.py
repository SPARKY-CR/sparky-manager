"""Phase B items 15–16 — the admin audit-log viewer and per-user tags.

The audit_log table already existed (every admin action writes to
it); item 15 is the viewer page it never had — list, search,
paginate. Item 16 is tags: notes already exist on the user row;
tags are the filterable half (no panel documents per-user tags).
"""

from __future__ import annotations

from app import tags as tags_mod
from app.models import AuditLog, UserTag
from app.webcommon import _audit


# ---------------------------------------------------------------------------
# Audit viewer (item 15)
# ---------------------------------------------------------------------------

def test_audit_page_renders_200(authed_client):
    resp = authed_client.get("/audit")
    assert resp.status_code == 200
    assert "</html>" in resp.text


def test_audit_page_lists_entries_newest_first(authed_client, db, seeded):
    _audit(db, None, "user.create", "alice")
    _audit(db, None, "user.delete", "mallory")
    resp = authed_client.get("/audit")
    assert resp.status_code == 200
    assert "user.create" in resp.text
    assert "user.delete" in resp.text
    # Newest first: the delete (written later) appears first.
    assert resp.text.index("user.delete") < resp.text.index("user.create")
    # A system entry (admin None) shows the "system" actor, not a blank.
    assert "سیستم" in resp.text or "System" in resp.text


def test_audit_page_search_filters_by_action_and_detail(
    authed_client, db
):
    _audit(db, None, "user.create", "alice")
    _audit(db, None, "inbound.delete", "vless-1")
    resp = authed_client.get("/audit?q=inbound")
    assert resp.status_code == 200
    assert "inbound.delete" in resp.text
    assert "user.create" not in resp.text
    resp = authed_client.get("/audit?q=alice")
    assert "user.create" in resp.text
    assert "inbound.delete" not in resp.text


def test_audit_page_paginates(authed_client, db):
    for i in range(30):
        _audit(db, None, f"user.create", f"user-{i:02d}")
    page1 = authed_client.get("/audit")
    assert page1.status_code == 200
    # 25 per page: the newest 25 are on page 1 …
    assert "user-29" in page1.text
    assert "user-00" not in page1.text
    # … the oldest 5 are on page 2.
    page2 = authed_client.get("/audit?page=2")
    assert page2.status_code == 200
    assert "user-00" in page2.text
    assert "user-29" not in page2.text


def test_audit_page_bad_page_clamps(authed_client, db):
    _audit(db, None, "user.create", "alice")
    for bad in ("0", "-3", "abc", "999"):
        resp = authed_client.get(f"/audit?page={bad}")
        assert resp.status_code == 200, bad


def test_audit_page_unauthenticated_redirects(test_client):
    resp = test_client.get("/audit", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# Tags (item 16) — the module
# ---------------------------------------------------------------------------

def test_normalize_tag_lowercases_and_trims(db):
    assert tags_mod.normalize_tag("  VIP  ") == "vip"
    assert tags_mod.normalize_tag("مشتری-ویژه") == "مشتری-ویژه"


def test_normalize_tag_rejects_invalid(db):
    assert tags_mod.normalize_tag("") is None
    assert tags_mod.normalize_tag("has space") is None
    assert tags_mod.normalize_tag("x" * 33) is None
    assert tags_mod.normalize_tag("semi;colon") is None


def test_add_tag_idempotent_and_capped(db, seeded):
    alice = seeded["users"]["alice"]
    assert tags_mod.add_tag(db, alice.id, "vip") == "vip"
    assert tags_mod.add_tag(db, alice.id, "VIP") == "vip"  # same tag
    assert tags_mod.tags_for_user(db, alice.id) == ["vip"]
    assert tags_mod.add_tag(db, alice.id, "bad tag") is None
    for i in range(25):
        tags_mod.add_tag(db, alice.id, f"t{i}")
    # The 20-tag cap holds (1 existing + 19 more).
    assert len(tags_mod.tags_for_user(db, alice.id)) == 20


def test_remove_tag_and_lookup_helpers(db, seeded):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    tags_mod.add_tag(db, alice.id, "vip")
    tags_mod.add_tag(db, alice.id, "trial")
    tags_mod.add_tag(db, bob.id, "vip")
    assert tags_mod.all_tags(db) == ["trial", "vip"]
    assert tags_mod.user_ids_with_tag(db, "vip") == {alice.id, bob.id}
    assert tags_mod.user_ids_with_tag(db, "trial") == {alice.id}
    assert tags_mod.tags_by_user(db) == {
        alice.id: ["trial", "vip"],
        bob.id: ["vip"],
    }
    assert tags_mod.remove_tag(db, alice.id, "vip") is True
    assert tags_mod.remove_tag(db, alice.id, "vip") is False  # already gone
    assert tags_mod.tags_for_user(db, alice.id) == ["trial"]


# ---------------------------------------------------------------------------
# Tags (item 16) — HTTP flows
# ---------------------------------------------------------------------------

def test_add_tag_via_post(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/tags", data={"tag": "VIP"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert tags_mod.tags_for_user(db, alice.id) == ["vip"]
    # The detail page shows the tag chip.
    page = authed_client.get(f"/users/{alice.id}")
    assert page.status_code == 200
    assert "vip" in page.text


def test_add_invalid_tag_via_post_rejected(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/tags", data={"tag": "bad tag"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert tags_mod.tags_for_user(db, alice.id) == []


def test_remove_tag_via_post(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    tags_mod.add_tag(db, alice.id, "vip")
    resp = authed_client.post(
        f"/users/{alice.id}/tags/remove", data={"tag": "vip"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert tags_mod.tags_for_user(db, alice.id) == []


def test_users_page_tag_filter(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    tags_mod.add_tag(db, alice.id, "vip")
    tags_mod.add_tag(db, bob.id, "trial")
    resp = authed_client.get("/users?tag=vip")
    assert resp.status_code == 200
    assert "alice" in resp.text
    assert "bob" not in resp.text
    # The tag filter select lists the real tags.
    assert "trial" in resp.text
    # An unknown tag matches nothing (but still renders).
    resp = authed_client.get("/users?tag=nope")
    assert resp.status_code == 200
    assert "alice" not in resp.text


def test_users_page_shows_tag_chips(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    tags_mod.add_tag(db, alice.id, "vip")
    resp = authed_client.get("/users")
    assert resp.status_code == 200
    assert "vip" in resp.text


def test_deleting_user_deletes_its_tags(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    alice_id = alice.id
    tags_mod.add_tag(db, alice.id, "vip")
    resp = authed_client.post(f"/users/{alice_id}/delete",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    assert (
        db.query(UserTag).filter_by(user_id=alice_id).count() == 0
    )
