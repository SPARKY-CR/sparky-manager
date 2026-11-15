"""User lifecycle: start-on-first-use expiry, traffic reset cycles,
calendar renewals and the lifetime usage counter (best-panel
program, Phase B items 10–11).

The mechanics come from Marzneshin (expiry *strategies*), 3x-ui
(per-client reset cycles + calendar renewals with a cap and a
schedule preview) and Remnawave (``MONTH_ROLLING`` resets +
lifetime counter). Sparky's accounting unit is the USER (one
traffic counter per user, not per client — see DESIGN.md §4), so
the reset cycle and the lifetime counter live per user; the
per-client reset cycle of 3x-ui maps onto the per-user counter
here, which is where the quota is enforced.

State lives in the ``user_lifecycle`` table (new in Phase B —
``create_all`` creates it on existing installs; no existing table
gains a column). Users without a row behave exactly as before.

* **Start-on-first-use** (Marzneshin's ``start_on_first_use``):
  the expiry clock starts at the first subscription fetch or the
  first recorded traffic (whichever comes first), not at creation.
  Until then the user is "on hold" (Marzban's status): usable,
  with no expiry date. :func:`record_first_use` is called from the
  subscription feed and from :func:`app.traffic.sync_traffic`.
* **Reset cycles**: ``daily`` / ``weekly`` / ``monthly`` (on
  ``reset_day``, 1–28) / ``month_rolling`` (monthly on the user's
  creation day — Remnawave's correct-for-arbitrary-purchase-dates
  rule; a creation day of 29–31 clamps to 28). A reset zeroes
  ``users.traffic_used_bytes``; the lifetime counter is untouched.
  The sweeper runs :func:`run_lifecycle_once` every 5 minutes; a
  missed reset (panel down) runs once at the next tick — resets
  are idempotent, so catching up one tick late loses nothing.
* **Renewals** (3x-ui's auto-renewal): when an expired user has a
  renewal mode, the sweeper extends the expiry — ``rolling`` (by
  ``renewal_interval_days`` from the expiry), ``calendar_day``
  (next occurrence of ``renewal_day``) or ``calendar_weekday``
  (next occurrence of ``renewal_weekday``, 0=Monday) — until
  ``renewal_max`` renewals are done (NULL = unlimited).
  :func:`preview_renewals` shows the next dates before they happen
  (3x-ui's schedule preview). The computed date is always rolled
  forward past "now", so a long-down panel never burns the cap on
  already-past dates. Renewal only extends the expiry — the
  usage reset is a separate cycle (the report's renewal-ordering
  trap: extend first, reset separately).
* **Lifetime counter**: ``lifetime_bytes`` accumulates every
  traffic delta forever (Marzban's ``lifetime_used_traffic``);
  resets and bulk resets never touch it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session as DbSession

from app.models import User, UserLifecycle
from app.webcommon import _audit

#: Expiry strategies (``user_lifecycle.expiry_strategy``).
EXPIRY_STRATEGIES = ("fixed", "first_use")

#: Traffic reset cycles (``user_lifecycle.reset_cycle``).
RESET_CYCLES = ("daily", "weekly", "monthly", "month_rolling")

#: Auto-renewal modes (``user_lifecycle.renewal_mode``).
RENEWAL_MODES = ("rolling", "calendar_day", "calendar_weekday")

#: Day-of-month values are capped at 28 so every month has the day.
RESET_DAY_MAX = 28

#: How many future renewals the schedule preview shows.
RENEWAL_PREVIEW_COUNT = 3


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    """A stored datetime as timezone-aware UTC (SQLite returns naive)."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def get_lifecycle(db: DbSession, user_id: int) -> Optional[UserLifecycle]:
    """The user's lifecycle row, or None (plain user, no features)."""
    return db.get(UserLifecycle, user_id)


def get_or_create_lifecycle(db: DbSession, user_id: int) -> UserLifecycle:
    """The user's lifecycle row, creating it when missing. Commits."""
    row = db.get(UserLifecycle, user_id)
    if row is None:
        row = UserLifecycle(user_id=user_id)
        db.add(row)
        db.commit()
    return row


def is_on_hold(lifecycle: Optional[UserLifecycle]) -> bool:
    """True when the user waits for first use (Marzban's ``on_hold``
    status): start-on-first-use strategy with no first use yet."""
    return (
        lifecycle is not None
        and lifecycle.expiry_strategy == "first_use"
        and lifecycle.first_use_at is None
    )


def lifetime_bytes(db: DbSession, user_id: int) -> int:
    """The user's lifetime usage (0 when no lifecycle row exists)."""
    row = db.get(UserLifecycle, user_id)
    return int(row.lifetime_bytes or 0) if row is not None else 0


def add_lifetime(db: DbSession, user_id: int, byte_count: int) -> None:
    """Add ``byte_count`` to the user's lifetime counter (creating
    the lifecycle row when missing). Called from
    :func:`app.traffic.sync_traffic` with the same deltas that feed
    ``traffic_used_bytes``. Non-positive counts are ignored.
    Commits."""
    if byte_count <= 0:
        return
    row = get_or_create_lifecycle(db, user_id)
    row.lifetime_bytes = int(row.lifetime_bytes or 0) + int(byte_count)
    db.commit()


# ---------------------------------------------------------------------------
# Start-on-first-use expiry
# ---------------------------------------------------------------------------


def record_first_use(
    db: DbSession, user: Any, now: Optional[datetime] = None
) -> bool:
    """Start the expiry clock for a start-on-first-use user.

    Returns True only when the clock actually started now: the user
    has a lifecycle row with strategy ``first_use``, no
    ``first_use_at`` yet, a positive ``usage_duration_days``, and
    no manually set ``expires_at`` (an admin-set expiry wins over
    the automatic one). Sets ``first_use_at`` and ``expires_at``
    (``now + duration``) and commits. Idempotent — a second call
    returns False. Never raises for a missing row.
    """
    now = _aware(now) or datetime.now(timezone.utc)
    lifecycle = db.get(UserLifecycle, user.id)
    if lifecycle is None:
        return False
    if lifecycle.expiry_strategy != "first_use":
        return False
    if lifecycle.first_use_at is not None:
        return False
    duration = lifecycle.usage_duration_days
    if not duration or int(duration) <= 0:
        return False
    if getattr(user, "expires_at", None) is not None:
        # The admin set an explicit expiry — the automatic clock
        # must not overwrite it. Stamp the first use anyway so the
        # "on hold" badge clears honestly.
        lifecycle.first_use_at = now
        db.commit()
        return False
    lifecycle.first_use_at = now
    user.expires_at = now + timedelta(days=int(duration))
    db.commit()
    _audit(
        db, None, "user.first_use",
        f"{user.name} clock started, {int(duration)} days",
    )
    return True


# ---------------------------------------------------------------------------
# Date arithmetic (pure, testable without the DB)
# ---------------------------------------------------------------------------


def _next_monthly_date(after: datetime, day: int) -> datetime:
    """The next date with day-of-month ``day`` (1–28) strictly after
    ``after``, at 00:00 UTC. ``day`` is clamped to 28 (every month
    has it)."""
    day = max(1, min(RESET_DAY_MAX, int(day)))
    year, month = after.year, after.month
    if after.day < day:
        candidate = datetime(year, month, day, tzinfo=timezone.utc)
        if candidate > after:
            return candidate
    month += 1
    if month > 12:
        month, year = 1, year + 1
    return datetime(year, month, day, tzinfo=timezone.utc)


def _next_weekday_date(after: datetime, weekday: int) -> datetime:
    """The next date with weekday ``weekday`` (0=Monday) strictly
    after ``after``, at 00:00 UTC."""
    weekday = int(weekday) % 7
    days_ahead = (weekday - after.weekday() + 7) % 7
    if days_ahead == 0:
        days_ahead = 7
    base = datetime(after.year, after.month, after.day, tzinfo=timezone.utc)
    return base + timedelta(days=days_ahead)


def _creation_day(user: Any) -> int:
    """The user's creation day-of-month, clamped to 28 (the
    MONTH_ROLLING anchor)."""
    created = _aware(getattr(user, "created_at", None))
    if created is None:
        return 1
    return max(1, min(RESET_DAY_MAX, created.day))


def next_reset_date(
    lifecycle: UserLifecycle, user: Any, now: Optional[datetime] = None
) -> Optional[datetime]:
    """The next traffic-reset moment for the user, or None when no
    reset cycle is configured. ``now`` only matters for the
    daily/weekly roll-forward (a long-down panel's next reset is
    the first interval boundary after the anchor, which may already
    be past — the sweeper treats that as due)."""
    cycle = lifecycle.reset_cycle
    if cycle not in RESET_CYCLES:
        return None
    anchor = _aware(lifecycle.last_reset_at) or _aware(user.created_at)
    if anchor is None:
        return None
    if cycle == "daily":
        return anchor + timedelta(days=1)
    if cycle == "weekly":
        return anchor + timedelta(days=7)
    if cycle == "monthly":
        day = lifecycle.reset_day or _creation_day(user)
        return _next_monthly_date(anchor, day)
    # month_rolling: monthly on the creation day.
    return _next_monthly_date(anchor, _creation_day(user))


def next_renewal_date(
    lifecycle: UserLifecycle, user: Any, now: Optional[datetime] = None
) -> Optional[datetime]:
    """The next auto-renewal date for the user, or None when no
    renewal mode is configured or the cap is exhausted. The date is
    always strictly after ``now``: a rolling renewal extends from
    the expiry (or now, whichever is later) and rolls forward by
    whole intervals until it lands in the future, so a long-down
    panel never burns the cap on already-past dates."""
    mode = lifecycle.renewal_mode
    if mode not in RENEWAL_MODES:
        return None
    if (
        lifecycle.renewal_max is not None
        and int(lifecycle.renewals_done or 0) >= int(lifecycle.renewal_max)
    ):
        return None
    now = _aware(now) or datetime.now(timezone.utc)
    expires = _aware(getattr(user, "expires_at", None))
    base = max(expires, now) if expires is not None else now
    if mode == "rolling":
        interval = lifecycle.renewal_interval_days
        if not interval or int(interval) <= 0:
            return None
        candidate = base + timedelta(days=int(interval))
        while candidate <= now:
            candidate += timedelta(days=int(interval))
        return candidate
    if mode == "calendar_day":
        day = lifecycle.renewal_day
        if not day or not 1 <= int(day) <= RESET_DAY_MAX:
            return None
        candidate = _next_monthly_date(base, int(day))
        while candidate <= now:
            candidate = _next_monthly_date(candidate, int(day))
        return candidate
    # calendar_weekday
    weekday = lifecycle.renewal_weekday
    if weekday is None or not 0 <= int(weekday) <= 6:
        return None
    candidate = _next_weekday_date(base, int(weekday))
    while candidate <= now:
        candidate = _next_weekday_date(candidate, int(weekday))
    return candidate


def preview_renewals(
    lifecycle: UserLifecycle,
    user: Any,
    now: Optional[datetime] = None,
    count: int = RENEWAL_PREVIEW_COUNT,
) -> list[datetime]:
    """The next ``count`` renewal dates (3x-ui's schedule preview),
    each strictly after the previous one. Limited by the remaining
    renewal cap (a cap of 1 previews one date). Empty when no
    renewal mode is configured or the cap is exhausted."""
    now = _aware(now) or datetime.now(timezone.utc)
    remaining = count
    if lifecycle.renewal_max is not None:
        remaining = min(
            remaining,
            max(0, int(lifecycle.renewal_max) - int(lifecycle.renewals_done or 0)),
        )
    if remaining <= 0:
        return []
    dates: list[datetime] = []
    # Walk forward from the first renewal: each next date is
    # computed as if the previous renewal had happened (expiry =
    # previous date). A throwaway namespace carries the moving
    # expiry without touching the real user row.
    probe_user = _ProbeUser(getattr(user, "expires_at", None))
    probe_lifecycle = _ProbeLifecycle(lifecycle)
    for _ in range(remaining):
        candidate = next_renewal_date(probe_lifecycle, probe_user, now=now)
        if candidate is None:
            break
        dates.append(candidate)
        probe_user.expires_at = candidate
    return dates


class _ProbeUser:
    """A stand-in user carrying only ``expires_at`` (preview walk)."""

    def __init__(self, expires_at: Optional[datetime]):
        self.expires_at = expires_at


class _ProbeLifecycle:
    """A stand-in lifecycle row with the cap disabled (the preview
    loop counts the cap itself via ``remaining``)."""

    def __init__(self, lifecycle: UserLifecycle):
        self.renewal_mode = lifecycle.renewal_mode
        self.renewal_interval_days = lifecycle.renewal_interval_days
        self.renewal_day = lifecycle.renewal_day
        self.renewal_weekday = lifecycle.renewal_weekday
        self.renewal_max = None
        self.renewals_done = 0


# ---------------------------------------------------------------------------
# Sweeper entry point
# ---------------------------------------------------------------------------


def run_lifecycle_once(
    db: DbSession, now: Optional[datetime] = None
) -> dict[str, list[int]]:
    """One lifecycle pass (called from the expiry sweeper loop):
    due traffic resets + due auto-renewals. Returns
    ``{"reset_user_ids": [...], "renewed_user_ids": [...]}`` so the
    caller can re-render configs (a reset/renewed user may become
    usable again). Audits every action as the system (admin None).
    Never raises for a single bad row — one broken lifecycle row
    must not stop the rest.
    """
    now = _aware(now) or datetime.now(timezone.utc)
    reset_ids: list[int] = []
    renewed_ids: list[int] = []
    for lifecycle in db.query(UserLifecycle).all():
        user = db.get(User, lifecycle.user_id)
        if user is None:
            continue
        try:
            if _reset_due(lifecycle, user, now):
                user.traffic_used_bytes = 0
                lifecycle.last_reset_at = now
                db.commit()
                reset_ids.append(user.id)
                _audit(
                    db, None, "user.traffic_reset",
                    f"{user.name} cycle={lifecycle.reset_cycle}",
                )
        except Exception:  # noqa: BLE001 — one bad row, not the pass
            db.rollback()
            continue
        try:
            if _renewal_due(lifecycle, user, now):
                new_expiry = next_renewal_date(lifecycle, user, now=now)
                if new_expiry is not None:
                    user.expires_at = new_expiry
                    lifecycle.renewals_done = (
                        int(lifecycle.renewals_done or 0) + 1
                    )
                    db.commit()
                    renewed_ids.append(user.id)
                    _audit(
                        db, None, "user.renewed",
                        f"{user.name} -> {new_expiry.date().isoformat()} "
                        f"({lifecycle.renewals_done})",
                    )
        except Exception:  # noqa: BLE001 — one bad row, not the pass
            db.rollback()
            continue
    return {"reset_user_ids": reset_ids, "renewed_user_ids": renewed_ids}


def _reset_due(
    lifecycle: UserLifecycle, user: Any, now: datetime
) -> bool:
    """True when the user's reset date has arrived."""
    nxt = next_reset_date(lifecycle, user, now=now)
    return nxt is not None and nxt <= now


def _renewal_due(
    lifecycle: UserLifecycle, user: Any, now: datetime
) -> bool:
    """True when the user is expired AND has a renewal mode with
    renewals left. Never-expiring users (``expires_at`` None) have
    nothing to renew."""
    if lifecycle.renewal_mode not in RENEWAL_MODES:
        return False
    if (
        lifecycle.renewal_max is not None
        and int(lifecycle.renewals_done or 0) >= int(lifecycle.renewal_max)
    ):
        return False
    expires = _aware(getattr(user, "expires_at", None))
    return expires is not None and expires <= now


__all__ = [
    "EXPIRY_STRATEGIES",
    "RESET_CYCLES",
    "RENEWAL_MODES",
    "RESET_DAY_MAX",
    "RENEWAL_PREVIEW_COUNT",
    "get_lifecycle",
    "get_or_create_lifecycle",
    "is_on_hold",
    "lifetime_bytes",
    "add_lifetime",
    "record_first_use",
    "next_reset_date",
    "next_renewal_date",
    "preview_renewals",
    "run_lifecycle_once",
]
