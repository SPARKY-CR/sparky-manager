"""User templates / plans (best-panel program, Phase B item 9 —
PasarGuard's User Templates).

A template bundles the defaults for creating a user — traffic
quota, expiry (fixed days from creation, or start-on-first-use),
which inbounds the user gets, and the traffic reset cycle — so
creating a user from a plan is one click instead of four fields.
Templates apply at creation only; changing a template never
rewrites existing users (a plan is a preset, not a live link).

``inbound_ids``: the inbounds the user gets clients on. An empty
list means "every enabled inbound" (the normal new-user
behaviour). Stored ids that no longer exist — or are disabled —
are dropped at apply time (a template must never fail creation
because an inbound was deleted since).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from app import lifecycle as lifecycle_mod
from app.models import Inbound, User, UserTemplate
from app.webcommon import NAME_RE

#: A template name follows the same rule as user/inbound names
#: (it appears in the create-user form's plan picker).
TEMPLATE_NAME_MAX = 64


def create_template(
    db: DbSession,
    name: str,
    traffic_limit_bytes: Optional[int] = None,
    expiry_days: Optional[int] = None,
    expiry_mode: str = "fixed",
    inbound_ids: Optional[list[int]] = None,
    reset_cycle: Optional[str] = None,
) -> Optional[UserTemplate]:
    """Create a template. Returns None (never raises) when the name
    is invalid, already taken, or a value is out of range. Commits
    on success."""
    name = (name or "").strip()
    if not NAME_RE.match(name):
        return None
    if db.query(UserTemplate).filter(UserTemplate.name == name).first():
        return None
    if expiry_mode not in lifecycle_mod.EXPIRY_STRATEGIES:
        return None
    if reset_cycle is not None and reset_cycle not in lifecycle_mod.RESET_CYCLES:
        return None
    if traffic_limit_bytes is not None and int(traffic_limit_bytes) <= 0:
        return None
    if expiry_days is not None and int(expiry_days) <= 0:
        return None
    template = UserTemplate(
        name=name,
        traffic_limit_bytes=traffic_limit_bytes,
        expiry_days=expiry_days,
        expiry_mode=expiry_mode,
        inbound_ids_json="[]",
        reset_cycle=reset_cycle,
    )
    template.inbound_ids = [int(i) for i in (inbound_ids or [])]
    db.add(template)
    db.commit()
    return template


def delete_template(db: DbSession, template_id: int) -> bool:
    """Delete a template. True when one existed."""
    template = db.get(UserTemplate, template_id)
    if template is None:
        return False
    db.delete(template)
    db.commit()
    return True


def template_inbound_ids(db: DbSession, template: UserTemplate) -> Optional[set[int]]:
    """The inbound ids a user created from ``template`` gets clients
    on: the template's list, restricted to inbounds that still exist
    and are enabled. ``None`` when the template lists none (meaning
    "every enabled inbound" — the caller's default)."""
    wanted = template.inbound_ids
    if not wanted:
        return None
    existing = {
        row[0]
        for row in db.query(Inbound.id)
        .filter(Inbound.id.in_(wanted), Inbound.enabled.is_(True))
        .all()
    }
    return existing


def apply_template_to_user(
    db: DbSession,
    user: User,
    template: UserTemplate,
    now: Optional[datetime] = None,
) -> Optional[set[int]]:
    """Apply ``template`` to a freshly created ``user`` (call before
    creating its clients — the return value is the inbound set to
    create them on, or None for "every enabled inbound").

    Sets the traffic limit and the expiry: ``fixed`` mode sets
    ``expires_at = now + expiry_days`` (None days = never expires);
    ``first_use`` mode leaves ``expires_at`` empty and writes a
    lifecycle row (strategy ``first_use``, duration
    ``expiry_days``) so the clock starts at first use. A template
    reset cycle is written to the same lifecycle row. Does not
    commit (the caller commits with the user row).
    """
    now = now or datetime.now(timezone.utc)
    user.traffic_limit_bytes = template.traffic_limit_bytes
    lifecycle = None
    if template.expiry_mode == "first_use" and template.expiry_days:
        lifecycle = lifecycle_mod.get_or_create_lifecycle(db, user.id)
        lifecycle.expiry_strategy = "first_use"
        lifecycle.usage_duration_days = int(template.expiry_days)
        user.expires_at = None
    elif template.expiry_days:
        user.expires_at = now + timedelta(days=int(template.expiry_days))
    else:
        user.expires_at = None
    if template.reset_cycle:
        if lifecycle is None:
            lifecycle = lifecycle_mod.get_or_create_lifecycle(db, user.id)
        lifecycle.reset_cycle = template.reset_cycle
    return template_inbound_ids(db, template)


__all__ = [
    "TEMPLATE_NAME_MAX",
    "create_template",
    "delete_template",
    "template_inbound_ids",
    "apply_template_to_user",
]
