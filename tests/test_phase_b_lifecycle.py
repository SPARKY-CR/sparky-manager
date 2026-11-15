"""Phase B items 10–11 — start-on-first-use expiry, reset cycles,
calendar renewals + cap + preview, lifetime usage counter.

The reset cycle is per-USER (sparky's accounting unit is the user —
traffic is attributed per user via the ``user-<id>@sparky.local``
Stats emails), which is the honest mapping of 3x-ui's per-client
cycle onto this panel's model.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app import lifecycle as lifecycle_mod
from app.models import User, UserLifecycle

UTC = timezone.utc
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)  # a Sunday

CLIENT_UA = "v2rayNG/1.9.0"
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def _user(db, name, **kwargs):
    user = User(name=name, sub_token=f"{name}-token-0123456789abcdef",
                **kwargs)
    db.add(user)
    db.commit()
    return user


def _lifecycle(db, user, **kwargs):
    row = lifecycle_mod.get_or_create_lifecycle(db, user.id)
    for key, value in kwargs.items():
        setattr(row, key, value)
    db.commit()
    return row


# ---------------------------------------------------------------------------
# First use (item 10)
# ---------------------------------------------------------------------------

def test_record_first_use_starts_clock(db):
    user = _user(db, "clock")
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=10)
    started = lifecycle_mod.record_first_use(db, user, now=T0)
    assert started is True
    db.refresh(user)
    assert user.expires_at is not None
    assert user.expires_at.replace(tzinfo=UTC) == T0 + timedelta(days=10)
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.first_use_at is not None
    assert lifecycle_mod.is_on_hold(row) is False


def test_record_first_use_is_idempotent(db):
    user = _user(db, "once")
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=10)
    assert lifecycle_mod.record_first_use(db, user, now=T0) is True
    first_expiry = user.expires_at
    assert lifecycle_mod.record_first_use(
        db, user, now=T0 + timedelta(days=3)
    ) is False
    db.refresh(user)
    # SQLite drops the tzinfo on read — compare tz-normalised.
    assert user.expires_at.replace(tzinfo=UTC) == first_expiry


def test_record_first_use_respects_manual_expiry(db):
    user = _user(db, "manual", expires_at=T0 + timedelta(days=99))
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=10)
    assert lifecycle_mod.record_first_use(db, user, now=T0) is False
    db.refresh(user)
    # The admin's date stands untouched.
    assert user.expires_at.replace(tzinfo=UTC) == T0 + timedelta(days=99)
    # ... but the first use IS stamped (the "on hold" badge clears).
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.first_use_at is not None


def test_record_first_use_noop_without_row_or_duration(db):
    user = _user(db, "plain")
    assert lifecycle_mod.record_first_use(db, user, now=T0) is False
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=None)
    assert lifecycle_mod.record_first_use(db, user, now=T0) is False
    _lifecycle(db, user, expiry_strategy="fixed",
               usage_duration_days=10)
    assert lifecycle_mod.record_first_use(db, user, now=T0) is False


def test_is_on_hold_only_for_unstarted_first_use(db):
    user = _user(db, "hold")
    assert lifecycle_mod.is_on_hold(None) is False
    row = _lifecycle(db, user, expiry_strategy="first_use",
                     usage_duration_days=5)
    assert lifecycle_mod.is_on_hold(row) is True
    row.first_use_at = T0
    db.commit()
    assert lifecycle_mod.is_on_hold(row) is False


def test_raw_subscription_fetch_starts_clock(test_client, db):
    user = _user(db, "fetcher")
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=7)
    resp = test_client.get(f"/sub/{user.sub_token}",
                           headers={"user-agent": CLIENT_UA})
    assert resp.status_code == 200
    db.refresh(user)
    assert user.expires_at is not None
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.first_use_at is not None


def test_browser_copy_only_page_does_not_start_clock(test_client, db):
    """Previewing the subscription in a browser (the admin checking
    a customer's link) must not start the customer's clock."""
    user = _user(db, "previewer")
    _lifecycle(db, user, expiry_strategy="first_use",
               usage_duration_days=7)
    resp = test_client.get(f"/sub/{user.sub_token}",
                           headers={"user-agent": BROWSER_UA})
    assert resp.status_code == 200
    db.refresh(user)
    assert user.expires_at is None
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.first_use_at is None


# ---------------------------------------------------------------------------
# Reset dates (item 11)
# ---------------------------------------------------------------------------

def test_next_reset_daily_weekly(db):
    user = _user(db, "cycles")
    user.created_at = T0
    db.commit()
    row = _lifecycle(db, user, reset_cycle="daily")
    assert lifecycle_mod.next_reset_date(row, user) == T0 + timedelta(days=1)
    row.reset_cycle = "weekly"
    db.commit()
    assert lifecycle_mod.next_reset_date(row, user) == T0 + timedelta(days=7)


def test_next_reset_monthly_uses_reset_day(db):
    user = _user(db, "monthly")
    user.created_at = T0  # 2026-11-01
    db.commit()
    row = _lifecycle(db, user, reset_cycle="monthly", reset_day=15)
    # Monthly dates land at 00:00 UTC (a calendar day, not a time).
    assert lifecycle_mod.next_reset_date(row, user) == datetime(
        2026, 11, 15, 0, 0, tzinfo=UTC
    )


def test_next_reset_monthly_rolls_to_next_month(db):
    user = _user(db, "monthly2")
    user.created_at = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    db.commit()
    row = _lifecycle(db, user, reset_cycle="monthly", reset_day=15)
    assert lifecycle_mod.next_reset_date(row, user) == datetime(
        2026, 12, 15, 0, 0, tzinfo=UTC
    )


def test_next_reset_month_rolling_uses_creation_day(db):
    user = _user(db, "rolling")
    user.created_at = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    db.commit()
    row = _lifecycle(db, user, reset_cycle="month_rolling")
    assert lifecycle_mod.next_reset_date(row, user) == datetime(
        2026, 12, 20, 0, 0, tzinfo=UTC
    )


def test_next_reset_none_without_cycle(db):
    user = _user(db, "nocycle")
    row = _lifecycle(db, user)
    assert lifecycle_mod.next_reset_date(row, user) is None


def test_next_reset_anchors_on_last_reset(db):
    user = _user(db, "anchored")
    user.created_at = T0
    db.commit()
    row = _lifecycle(
        db, user, reset_cycle="daily",
        last_reset_at=datetime(2026, 11, 5, 9, 0, tzinfo=UTC),
    )
    assert lifecycle_mod.next_reset_date(row, user) == datetime(
        2026, 11, 6, 9, 0, tzinfo=UTC
    )


# ---------------------------------------------------------------------------
# Renewals (item 11)
# ---------------------------------------------------------------------------

def test_next_renewal_rolling(db):
    user = _user(db, "rollrenew", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="rolling",
                     renewal_interval_days=30)
    assert lifecycle_mod.next_renewal_date(row, user, now=T0) == (
        T0 + timedelta(days=60)
    )


def test_next_renewal_rolling_rolls_past_now(db):
    """A long-down panel never burns the cap on a past date: the
    renewal lands strictly after `now`."""
    user = _user(db, "stale", expires_at=T0 - timedelta(days=100))
    row = _lifecycle(db, user, renewal_mode="rolling",
                     renewal_interval_days=30)
    nxt = lifecycle_mod.next_renewal_date(row, user, now=T0)
    assert nxt is not None and nxt > T0
    # From now + 30 (base is max(expiry, now) = now).
    assert nxt == T0 + timedelta(days=30)


def test_next_renewal_calendar_day(db):
    user = _user(db, "calday", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="calendar_day", renewal_day=1)
    # Base is the expiry (2026-12-01 12:00) — the next 1st after it.
    assert lifecycle_mod.next_renewal_date(row, user, now=T0) == datetime(
        2027, 1, 1, 0, 0, tzinfo=UTC
    )


def test_next_renewal_calendar_weekday(db):
    # T0 is a Sunday (weekday 6). Expiry 2026-12-01 is a Tuesday.
    user = _user(db, "calweek", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="calendar_weekday",
                     renewal_weekday=4)  # Friday
    assert lifecycle_mod.next_renewal_date(row, user, now=T0) == datetime(
        2026, 12, 4, 0, 0, tzinfo=UTC
    )


def test_next_renewal_cap_exhausted_returns_none(db):
    user = _user(db, "capped", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="rolling",
                     renewal_interval_days=30, renewal_max=2,
                     renewals_done=2)
    assert lifecycle_mod.next_renewal_date(row, user, now=T0) is None


def test_preview_renewals_three_dates(db):
    user = _user(db, "preview", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="rolling",
                     renewal_interval_days=30)
    dates = lifecycle_mod.preview_renewals(row, user, now=T0)
    assert dates == [
        T0 + timedelta(days=60),
        T0 + timedelta(days=90),
        T0 + timedelta(days=120),
    ]


def test_preview_renewals_limited_by_cap(db):
    user = _user(db, "previewcap", expires_at=T0 + timedelta(days=30))
    row = _lifecycle(db, user, renewal_mode="rolling",
                     renewal_interval_days=30, renewal_max=1)
    dates = lifecycle_mod.preview_renewals(row, user, now=T0)
    assert dates == [T0 + timedelta(days=60)]


# ---------------------------------------------------------------------------
# The sweeper pass (item 11)
# ---------------------------------------------------------------------------

def test_sweeper_resets_due_traffic_and_keeps_lifetime(db):
    user = _user(db, "resetme", traffic_used_bytes=12345)
    user.created_at = T0
    db.commit()
    _lifecycle(db, user, reset_cycle="daily", lifetime_bytes=99999)
    out = lifecycle_mod.run_lifecycle_once(
        db, now=T0 + timedelta(days=1, hours=1)
    )
    assert out["reset_user_ids"] == [user.id]
    db.refresh(user)
    assert user.traffic_used_bytes == 0
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.lifetime_bytes == 99999  # the reset never clears it
    assert row.last_reset_at is not None


def test_sweeper_skips_not_yet_due_reset(db):
    user = _user(db, "notyet", traffic_used_bytes=12345)
    user.created_at = T0
    db.commit()
    _lifecycle(db, user, reset_cycle="daily")
    out = lifecycle_mod.run_lifecycle_once(db, now=T0 + timedelta(hours=12))
    assert out == {"reset_user_ids": [], "renewed_user_ids": []}
    db.refresh(user)
    assert user.traffic_used_bytes == 12345


def test_sweeper_renews_expired_user(db):
    user = _user(db, "renewme", expires_at=T0 - timedelta(days=1))
    _lifecycle(db, user, renewal_mode="rolling",
               renewal_interval_days=30)
    out = lifecycle_mod.run_lifecycle_once(db, now=T0)
    assert out["renewed_user_ids"] == [user.id]
    db.refresh(user)
    assert user.expires_at.replace(tzinfo=UTC) == T0 + timedelta(days=30)
    row = lifecycle_mod.get_lifecycle(db, user.id)
    assert row.renewals_done == 1


def test_sweeper_respects_renewal_cap(db):
    user = _user(db, "capstop", expires_at=T0 - timedelta(days=1))
    _lifecycle(db, user, renewal_mode="rolling",
               renewal_interval_days=30, renewal_max=1, renewals_done=1)
    out = lifecycle_mod.run_lifecycle_once(db, now=T0)
    assert out["renewed_user_ids"] == []
    db.refresh(user)
    assert user.expires_at.replace(tzinfo=UTC) == T0 - timedelta(days=1)


def test_sweeper_never_renews_unexpired_or_never_expiring(db):
    user = _user(db, "fresh", expires_at=T0 + timedelta(days=30))
    _lifecycle(db, user, renewal_mode="rolling",
               renewal_interval_days=30)
    never = _user(db, "neverexp")
    _lifecycle(db, never, renewal_mode="rolling",
               renewal_interval_days=30)
    out = lifecycle_mod.run_lifecycle_once(db, now=T0)
    assert out["renewed_user_ids"] == []


def test_add_lifetime_accumulates(db):
    user = _user(db, "lifer")
    assert lifecycle_mod.lifetime_bytes(db, user.id) == 0
    # The first traffic creates the row (the traffic sync calls this
    # for every user with a delta — the counter must exist even for
    # users with no other lifecycle feature).
    lifecycle_mod.add_lifetime(db, user.id, 1000)
    assert lifecycle_mod.lifetime_bytes(db, user.id) == 1000
    lifecycle_mod.add_lifetime(db, user.id, 500)
    assert lifecycle_mod.lifetime_bytes(db, user.id) == 1500
    # Non-positive counts are ignored.
    lifecycle_mod.add_lifetime(db, user.id, 0)
    lifecycle_mod.add_lifetime(db, user.id, -50)
    assert lifecycle_mod.lifetime_bytes(db, user.id) == 1500


# ---------------------------------------------------------------------------
# The edit page (items 10–11 through the web form)
# ---------------------------------------------------------------------------

def test_edit_user_saves_lifecycle_fields(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data={
            "name": "alice",
            "expiry_strategy": "first_use",
            "usage_days": "14",
            "reset_cycle": "monthly",
            "reset_day": "10",
            "renewal_mode": "rolling",
            "renewal_interval_days": "30",
            "renewal_max": "3",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    row = lifecycle_mod.get_lifecycle(db, alice.id)
    assert row is not None
    assert row.expiry_strategy == "first_use"
    assert row.usage_duration_days == 14
    assert row.reset_cycle == "monthly"
    assert row.reset_day == 10
    assert row.renewal_mode == "rolling"
    assert row.renewal_interval_days == 30
    assert row.renewal_max == 3
    # The edit page renders the renewal preview afterwards (the
    # rolling preview starts 30 days from now).
    page = authed_client.get(f"/users/{alice.id}/edit")
    assert page.status_code == 200
    assert "پیش‌نمایش تمدیدها" in page.text
    expected = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%d")
    assert expected in page.text


def test_edit_user_first_use_clears_typed_expiry_date(
    authed_client, db, seeded
):
    """First-use wins over a typed date while the clock has not
    started — the date field is meaningless until the clock runs."""
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data={
            "name": "alice",
            "expires_date": "2027-01-01",
            "expiry_strategy": "first_use",
            "usage_days": "14",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    db.refresh(alice)
    assert alice.expires_at is None


def test_edit_user_lifecycle_validation_errors(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    bad_forms = [
        {"expiry_strategy": "someday"},
        {"expiry_strategy": "first_use"},  # no duration, clock unstarted
        {"reset_cycle": "fortnightly"},
        {"reset_cycle": "monthly", "reset_day": "29"},
        {"reset_cycle": "monthly", "reset_day": "0"},
        {"renewal_mode": "rolling"},  # no interval
        {"renewal_mode": "calendar_day"},  # no day
        {"renewal_mode": "calendar_day", "renewal_day": "31"},
        {"renewal_mode": "calendar_weekday"},  # no weekday
        {"renewal_mode": "calendar_weekday", "renewal_weekday": "7"},
        {"renewal_mode": "rolling", "renewal_interval_days": "30",
         "renewal_max": "0"},
    ]
    for extra in bad_forms:
        data = {"name": "alice"}
        data.update(extra)
        resp = authed_client.post(
            f"/users/{alice.id}/edit", data=data, follow_redirects=False
        )
        # A validation error re-renders the edit page (200), it does
        # not redirect — and it writes nothing.
        assert resp.status_code == 200, extra
        assert db.query(UserLifecycle).filter_by(
            user_id=alice.id
        ).first() is None, extra
