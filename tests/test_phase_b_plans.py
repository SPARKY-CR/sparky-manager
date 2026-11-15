"""Phase B item 9 — user templates / plans.

A plan is a reusable preset (traffic quota, expiry mode + days,
reset cycle, inbound selection) an admin defines once and applies
when creating a user. Applying a plan COPIES its values onto the
user — the user never points back at the plan, so editing or
deleting a plan never rewrites existing users.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import lifecycle as lifecycle_mod
from app import plans as plans_mod
from app.models import User, UserLifecycle, UserTemplate


def _make_plan(db, name="basic", inbound_ids=None, **kwargs):
    defaults = {
        "traffic_limit_bytes": 10 * 1024**3,
        "expiry_mode": "fixed",
        "expiry_days": 30,
    }
    defaults.update(kwargs)
    plan = UserTemplate(name=name, **defaults)
    # `inbound_ids` is a property over the JSON column — set it via
    # the property, never as a constructor kwarg.
    plan.inbound_ids = list(inbound_ids or [])
    db.add(plan)
    db.commit()
    return plan


# ---------------------------------------------------------------------------
# The page + create/delete flows
# ---------------------------------------------------------------------------

def test_plans_page_renders_200(authed_client):
    resp = authed_client.get("/plans")
    assert resp.status_code == 200
    assert "</html>" in resp.text


def test_plans_page_unauthenticated_redirects(test_client):
    resp = test_client.get("/plans", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_create_plan_via_post(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    trojan = seeded["inbounds"]["trojan-tls"]
    resp = authed_client.post(
        "/plans",
        data={
            "name": "starter",
            "traffic_limit_gb": "5",
            "expiry_mode": "first_use",
            "expiry_days": "14",
            "reset_cycle": "monthly",
            "inbound_ids": [str(vless.id), str(trojan.id)],
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    plan = db.query(UserTemplate).filter_by(name="starter").one()
    assert plan.traffic_limit_bytes == 5 * 1024**3
    assert plan.expiry_mode == "first_use"
    assert plan.expiry_days == 14
    assert plan.reset_cycle == "monthly"
    assert plans_mod.template_inbound_ids(db, plan) == {vless.id, trojan.id}
    # The list renders with the plan on it (the inbound-count cell
    # must not crash on the JSON-backed ids property).
    page = authed_client.get("/plans")
    assert page.status_code == 200
    assert "starter" in page.text


def test_create_plan_validation_errors(authed_client, db):
    # Empty name.
    resp = authed_client.post("/plans", data={"name": "  "},
                              follow_redirects=False)
    assert resp.status_code == 303
    assert db.query(UserTemplate).count() == 0
    # Bad traffic / days / cycle.
    for data in (
        {"name": "a", "traffic_limit_gb": "not-a-number"},
        {"name": "a", "expiry_days": "not-a-number"},
        {"name": "a", "reset_cycle": "fortnightly"},
    ):
        resp = authed_client.post("/plans", data=data, follow_redirects=False)
        assert resp.status_code == 303, data
    assert db.query(UserTemplate).count() == 0
    # A negative expiry_days is not an error — it means "no expiry"
    # (same rule as the create-user form).
    resp = authed_client.post(
        "/plans", data={"name": "neg", "expiry_days": "-3"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    plan = db.query(UserTemplate).filter_by(name="neg").one()
    assert plan.expiry_days is None
    # An unknown expiry mode is coerced to "fixed", not rejected
    # (the form only offers the two valid modes).
    resp = authed_client.post(
        "/plans", data={"name": "coerced", "expiry_mode": "someday"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    plan = db.query(UserTemplate).filter_by(name="coerced").one()
    assert plan.expiry_mode == "fixed"


def test_create_plan_duplicate_name_rejected(authed_client, db):
    _make_plan(db, name="basic")
    resp = authed_client.post("/plans", data={"name": "basic"},
                              follow_redirects=False)
    assert resp.status_code == 303
    assert db.query(UserTemplate).filter_by(name="basic").count() == 1


def test_delete_plan_via_post(authed_client, db):
    plan = _make_plan(db)
    plan_id = plan.id
    resp = authed_client.post(f"/plans/{plan_id}/delete",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()  # the HTTP request deleted the row in another session
    assert db.get(UserTemplate, plan_id) is None


def test_delete_missing_plan_404s(authed_client):
    resp = authed_client.post("/plans/99999/delete", follow_redirects=False)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Applying a plan at user creation
# ---------------------------------------------------------------------------

def test_create_user_from_plan_applies_quota_expiry_and_inbounds(
    authed_client, db, seeded
):
    vless = seeded["inbounds"]["vless-reality"]
    plan = _make_plan(
        db,
        traffic_limit_bytes=7 * 1024**3,
        expiry_mode="fixed",
        expiry_days=20,
        reset_cycle="weekly",
        inbound_ids=[vless.id],
    )
    before = datetime.now(timezone.utc)
    resp = authed_client.post(
        "/users",
        data={"name": "planned", "template_id": str(plan.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    user = db.query(User).filter_by(name="planned").one()
    assert user.traffic_limit_bytes == 7 * 1024**3
    assert user.expires_at is not None
    assert before + timedelta(days=20) - timedelta(minutes=1) <= (
        user.expires_at.replace(tzinfo=timezone.utc)
    ) <= before + timedelta(days=20, minutes=1)
    # Only the plan's inbound got a client.
    assert {c.inbound_id for c in user.clients} == {vless.id}
    # The reset cycle came along (lifecycle row).
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    assert lifecycle is not None
    assert lifecycle.reset_cycle == "weekly"


def test_create_user_form_values_override_plan(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    plan = _make_plan(
        db,
        traffic_limit_bytes=7 * 1024**3,
        expiry_mode="fixed",
        expiry_days=20,
        inbound_ids=[vless.id],
    )
    resp = authed_client.post(
        "/users",
        data={
            "name": "override",
            "template_id": str(plan.id),
            "traffic_limit_gb": "2",
            "expires_days": "5",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    user = db.query(User).filter_by(name="override").one()
    assert user.traffic_limit_bytes == 2 * 1024**3
    assert user.expires_at is not None
    remaining = user.expires_at.replace(tzinfo=timezone.utc) - datetime.now(
        timezone.utc
    )
    assert timedelta(days=4) < remaining <= timedelta(days=5, minutes=1)
    # The inbound set still came from the plan (no form field for it).
    assert {c.inbound_id for c in user.clients} == {vless.id}


def test_create_user_first_use_plan_starts_on_hold(authed_client, db):
    _make_plan(db, expiry_mode="first_use", expiry_days=10)
    plan = db.query(UserTemplate).one()
    resp = authed_client.post(
        "/users",
        data={"name": "firstuser", "template_id": str(plan.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    user = db.query(User).filter_by(name="firstuser").one()
    assert user.expires_at is None  # no clock until first use
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    assert lifecycle is not None
    assert lifecycle.expiry_strategy == "first_use"
    assert lifecycle.usage_duration_days == 10
    assert lifecycle.first_use_at is None
    assert lifecycle_mod.is_on_hold(lifecycle)


def test_create_user_first_use_via_form_without_plan(authed_client, db):
    resp = authed_client.post(
        "/users",
        data={"name": "firstform", "expiry_mode": "first_use",
              "usage_days": "7"},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    user = db.query(User).filter_by(name="firstform").one()
    assert user.expires_at is None
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    assert lifecycle.expiry_strategy == "first_use"
    assert lifecycle.usage_duration_days == 7


def test_create_user_first_use_without_duration_rejected(
    authed_client, db
):
    resp = authed_client.post(
        "/users",
        data={"name": "noduration", "expiry_mode": "first_use"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(User).filter_by(name="noduration").first() is None


def test_create_user_invalid_template_rejected(authed_client, db):
    resp = authed_client.post(
        "/users",
        data={"name": "badplan", "template_id": "99999"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(User).filter_by(name="badplan").first() is None


def test_changing_plan_never_rewrites_existing_users(
    authed_client, db, seeded
):
    plan = _make_plan(db, traffic_limit_bytes=5 * 1024**3, expiry_days=30)
    authed_client.post(
        "/users",
        data={"name": "snapshot", "template_id": str(plan.id)},
        follow_redirects=False,
    )
    user = db.query(User).filter_by(name="snapshot").one()
    old_limit = user.traffic_limit_bytes
    old_expiry = user.expires_at
    # Change the plan (a later user gets the new values).
    plan.traffic_limit_bytes = 99 * 1024**3
    plan.expiry_days = 1
    db.commit()
    db.refresh(user)
    assert user.traffic_limit_bytes == old_limit
    assert user.expires_at == old_expiry
    # ... and the plan itself is gone-able without touching the user.
    plans_mod.delete_template(db, plan.id)
    db.refresh(user)
    assert user.traffic_limit_bytes == old_limit


def test_apply_drops_missing_and_disabled_inbounds(db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    trojan = seeded["inbounds"]["trojan-tls"]
    trojan.enabled = False
    db.commit()
    plan = _make_plan(
        db, inbound_ids=[vless.id, trojan.id, 99999]
    )
    user = User(name="partial", sub_token="x" * 32)
    db.add(user)
    db.commit()
    chosen = plans_mod.apply_template_to_user(db, user, plan)
    assert chosen == {vless.id}


def test_apply_without_inbounds_means_all_enabled(db, seeded):
    plan = _make_plan(db)
    user = User(name="allin", sub_token="y" * 32)
    db.add(user)
    db.commit()
    chosen = plans_mod.apply_template_to_user(db, user, plan)
    assert chosen is None  # None = "every enabled inbound" downstream


def test_plan_without_expiry_days_means_never_expires(db):
    plan = _make_plan(db, expiry_mode="fixed", expiry_days=None)
    user = User(name="noexpiry", sub_token="z" * 32)
    db.add(user)
    db.commit()
    plans_mod.apply_template_to_user(db, user, plan)
    assert user.expires_at is None
    # No lifecycle row for a plain fixed plan without a reset cycle.
    assert (
        db.query(UserLifecycle).filter_by(user_id=user.id).first() is None
    )
