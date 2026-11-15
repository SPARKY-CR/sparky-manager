"""Selectable Telegram event bus (best-panel program, Phase A item 1).

Before this module, Telegram notifications were hardcoded call sites:
user creation, expiry warnings and re-render failures were each sent
unconditionally whenever Telegram was configured — the admin could
not turn one off without turning all of them off. This module is the
single choke point for every notification the panel sends:

* **Selectable events** — each notification carries an event name
  (see :data:`EVENT_CATALOG`); the admin picks which events notify
  in Settings → Telegram. The ``telegram_events`` setting holds the
  enabled names as a JSON list; an absent/empty/unparseable value
  means ALL catalog events (the pre-bus behaviour — nothing the
  panel used to send goes quiet on upgrade).
* **Reminder deduplication** — ``notify_event`` takes an optional
  ``dedup_key`` + ``dedup_seconds``: the same reminder is not
  re-sent inside the window. Dedup state lives in the
  ``telegram_event_dedup`` setting (``{key: ISO timestamp}``) — no
  schema change. The old bespoke mechanisms (``telegram_expiry_notified``,
  ``telegram_rerender_notified_at``) were replaced by this one; their
  setting rows are left untouched on disk (harmless orphans).
* **Forum-topic routing** lives one layer down, in
  :func:`app.webcommon._notify_telegram`: when the
  ``telegram_topic_id`` setting holds a positive integer, every
  notification is sent with ``message_thread_id`` (3x-ui's
  ``chatId:topicId`` shape). A wrong topic id makes Telegram refuse
  the message — there is no silent fallback, so a misconfiguration
  is visible (the settings test button proves the routing works).

Unknown event names are refused (logged, ``False``) — a typo'd event
must never silently spam the admin, and the catalog is the complete
list of what the panel can emit.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from app.webcommon import _notify_telegram, get_setting, get_settings, set_setting

logger = logging.getLogger("sparky-manager")

#: Setting keys (settings table — no schema change).
EVENTS_SETTING_KEY = "telegram_events"
DEDUP_SETTING_KEY = "telegram_event_dedup"

#: Event name -> i18n key for its label in the settings checklist.
#: This is the complete list of events the panel can emit.
EVENT_CATALOG: dict[str, str] = {
    "user.created": "event_user_created",
    "user.expiring": "event_user_expiring",
    "rerender.failed": "event_rerender_failed",
    "login.locked": "event_login_locked",
    "selfcheck.failed": "event_selfcheck_failed",
    "backup.failed": "event_backup_failed",
}

#: Dedup entries older than this are pruned on write, so the
#: setting row never grows without bound.
_DEDUP_PRUNE_AFTER = timedelta(days=7)


def _parse_json_dict(raw: str) -> dict:
    try:
        data = json.loads(raw or "")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def enabled_events(db: DbSession) -> set[str]:
    """The set of event names that may notify.

    An absent/empty/unparseable ``telegram_events`` value means ALL
    catalog events. Unknown names in the stored list are ignored
    (they can only come from a hand-edited setting or a newer panel
    version). Never raises.
    """
    try:
        raw = get_setting(db, EVENTS_SETTING_KEY, "")
        if not (raw or "").strip():
            return set(EVENT_CATALOG)
        data = json.loads(raw)
        if not isinstance(data, list):
            return set(EVENT_CATALOG)
        enabled = {str(name) for name in data if str(name) in EVENT_CATALOG}
        # An explicitly saved empty list means "notify nothing" —
        # but only when the stored value really is a list (an empty
        # string above already returned "all").
        return enabled
    except Exception:  # noqa: BLE001 — bad setting: notify everything
        logger.warning("telegram_events setting unreadable; enabling all events")
        return set(EVENT_CATALOG)


def is_event_enabled(db: DbSession, event: str) -> bool:
    """True when ``event`` is in the catalog and enabled."""
    if event not in EVENT_CATALOG:
        return False
    return event in enabled_events(db)


def _dedup_due(db: DbSession, dedup_key: str, window: int, now: datetime) -> bool:
    """True when ``dedup_key`` has no send inside ``window`` seconds."""
    state = _parse_json_dict(get_setting(db, DEDUP_SETTING_KEY, ""))
    raw = state.get(dedup_key)
    if not raw:
        return True
    try:
        last = datetime.fromisoformat(str(raw))
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) >= timedelta(seconds=window)


def _dedup_stamp(db: DbSession, dedup_key: str, now: datetime) -> None:
    """Record a send for ``dedup_key`` (pruning entries older than
    a week so the setting row stays small)."""
    state = _parse_json_dict(get_setting(db, DEDUP_SETTING_KEY, ""))
    cutoff = now - _DEDUP_PRUNE_AFTER
    pruned: dict[str, str] = {}
    for key, value in state.items():
        try:
            when = datetime.fromisoformat(str(value))
        except ValueError:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when >= cutoff:
            pruned[str(key)] = str(value)
    pruned[dedup_key] = now.isoformat()
    set_setting(db, DEDUP_SETTING_KEY, json.dumps(pruned))


def notify_event(
    db: DbSession,
    event: str,
    text: str,
    *,
    dedup_key: Optional[str] = None,
    dedup_seconds: int = 0,
    now: Optional[datetime] = None,
    payload: Optional[dict] = None,
) -> bool:
    """Send ``text`` as a Telegram notification for ``event``.

    Returns True only when the message was actually sent. False
    when the event is unknown, disabled, deduplicated, Telegram is
    unconfigured, or the send fails. Never raises. ``now`` is
    injectable for tests; it defaults to the current UTC time.

    Phase B item 14 — webhooks fire from here too, INDEPENDENTLY
    of the Telegram channel: an endpoint subscribed to ``event``
    gets the JSON payload even when the Telegram event is disabled
    or Telegram is unconfigured (the two channels have separate
    subscriptions). ``payload`` (extra structured fields) merges
    into the webhook body; the text is always included as
    ``{"text": ...}``. The webhook dispatch runs before the
    Telegram enabled-check on purpose, and never affects the
    return value (a webhook failure must not look like a Telegram
    failure). The import is lazy: ``app.webhooks`` imports this
    module for the catalog.
    """
    if event not in EVENT_CATALOG:
        logger.warning("unknown telegram event %r refused", event)
        return False
    try:
        from app import webhooks as webhooks_mod

        webhook_payload = {"text": text}
        if payload:
            webhook_payload.update(payload)
        webhooks_mod.dispatch_event(db, event, webhook_payload)
    except Exception:  # noqa: BLE001 — webhooks never break the bus
        logger.warning("webhook dispatch failed for %r", event)
    if not text:
        return False
    try:
        if not is_event_enabled(db, event):
            return False
        now = now or datetime.now(timezone.utc)
        if dedup_key and dedup_seconds > 0:
            if not _dedup_due(db, dedup_key, dedup_seconds, now):
                return False
        if _notify_telegram(db, text):
            if dedup_key and dedup_seconds > 0:
                _dedup_stamp(db, dedup_key, now)
            return True
        return False
    except Exception:  # noqa: BLE001 — a notification must never break a request
        logger.warning("telegram event %r notification failed", event)
        return False


__all__ = [
    "EVENT_CATALOG",
    "EVENTS_SETTING_KEY",
    "DEDUP_SETTING_KEY",
    "enabled_events",
    "is_event_enabled",
    "notify_event",
]
