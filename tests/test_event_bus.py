"""Phase A item 1 tests — the selectable Telegram event bus.

The bus (app/events.py) replaces the old all-or-nothing
notifications: the admin picks which events notify, repeated
reminders for the same event are deduplicated, and messages can
be routed into a forum topic (message_thread_id).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app import events as events_mod
from app import main as main_mod
from app.webcommon import get_setting, set_setting


def _configure_telegram(db, token="111111:TESTTOKEN", chat_id="987654321"):
    set_setting(db, "telegram_bot_token", token)
    set_setting(db, "telegram_chat_id", chat_id)


def _capture_send(monkeypatch):
    """Capture telegram.send_message calls; returns the call list."""
    sent: list = []

    def _fake(token, chat_id, text, **kw):
        sent.append({"token": token, "chat_id": chat_id, "text": text, **kw})
        return True

    monkeypatch.setattr(main_mod.telegram_mod, "send_message", _fake)
    return sent


# ---------------------------------------------------------------------------
# Event selection
# ---------------------------------------------------------------------------

def test_default_is_all_events_enabled(db, seeded, monkeypatch):
    # No telegram_events setting at all: every catalog event sends
    # (pre-bus behavior preserved).
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    for event in events_mod.EVENT_CATALOG:
        assert events_mod.notify_event(db, event, f"msg {event}") is True
    assert len(sent) == len(events_mod.EVENT_CATALOG)


def test_saved_list_restricts_events(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(
        db, events_mod.EVENTS_SETTING_KEY,
        json.dumps(["user.expiring", "login.locked"]),
    )
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.expiring", "x") is True
    assert events_mod.notify_event(db, "user.created", "x") is False
    assert events_mod.notify_event(db, "rerender.failed", "x") is False
    assert len(sent) == 1


def test_empty_saved_list_disables_all(db, seeded, monkeypatch):
    # An explicitly saved empty list means "notify nothing" — this
    # is why the settings form carries a hidden *_present marker.
    _configure_telegram(db)
    set_setting(db, events_mod.EVENTS_SETTING_KEY, "[]")
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.expiring", "x") is False
    assert sent == []


def test_unparseable_setting_falls_back_to_all(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(db, events_mod.EVENTS_SETTING_KEY, "not json at all")
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.created", "x") is True
    assert len(sent) == 1


def test_unknown_event_names_in_list_are_ignored(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(
        db, events_mod.EVENTS_SETTING_KEY,
        json.dumps(["user.created", "not.a.real.event"]),
    )
    assert events_mod.enabled_events(db) == {"user.created"}


def test_unknown_event_is_refused(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "no.such.event", "x") is False
    assert sent == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_dedup_suppresses_repeat_within_window(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(
        db, "rerender.failed", "x",
        dedup_key="rerender.failed", dedup_seconds=3600,
    ) is True
    assert events_mod.notify_event(
        db, "rerender.failed", "x",
        dedup_key="rerender.failed", dedup_seconds=3600,
    ) is False
    assert len(sent) == 1


def test_dedup_expires_after_window(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(
        db, "rerender.failed", "x",
        dedup_key="rerender.failed", dedup_seconds=3600,
    ) is True
    # Backdate the dedup stamp past the window: the next event sends.
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    set_setting(
        db, events_mod.DEDUP_SETTING_KEY,
        json.dumps({"rerender.failed": old}),
    )
    assert events_mod.notify_event(
        db, "rerender.failed", "x",
        dedup_key="rerender.failed", dedup_seconds=3600,
    ) is True
    assert len(sent) == 2


def test_dedup_keys_are_independent(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(
        db, "user.expiring", "alice",
        dedup_key="user.expiring:1", dedup_seconds=86400,
    ) is True
    # A different user is a different key — it still sends.
    assert events_mod.notify_event(
        db, "user.expiring", "bob",
        dedup_key="user.expiring:2", dedup_seconds=86400,
    ) is True
    assert len(sent) == 2


def test_dedup_prunes_entries_older_than_seven_days(db, seeded, monkeypatch):
    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    ancient = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    recent = datetime.now(timezone.utc).isoformat()
    set_setting(
        db, events_mod.DEDUP_SETTING_KEY,
        json.dumps({"stale.key": ancient, "fresh.key": recent}),
    )
    assert events_mod.notify_event(
        db, "user.created", "x",
        dedup_key="new.key", dedup_seconds=60,
    ) is True
    stored = json.loads(get_setting(db, events_mod.DEDUP_SETTING_KEY, "{}"))
    assert "stale.key" not in stored
    assert "fresh.key" in stored
    assert "new.key" in stored
    assert sent


def test_failed_send_does_not_stamp_dedup(db, seeded, monkeypatch):
    # A send that fails (Telegram down) must not burn the dedup
    # window — the next attempt must try again.
    _configure_telegram(db)
    monkeypatch.setattr(
        main_mod.telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: False,
    )
    assert events_mod.notify_event(
        db, "rerender.failed", "x",
        dedup_key="rerender.failed", dedup_seconds=3600,
    ) is False
    stored = json.loads(get_setting(db, events_mod.DEDUP_SETTING_KEY, "{}"))
    assert "rerender.failed" not in stored


# ---------------------------------------------------------------------------
# Forum-topic routing
# ---------------------------------------------------------------------------

def test_topic_id_is_passed_to_send_message(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(db, "telegram_topic_id", "42")
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.created", "x") is True
    assert sent[0]["message_thread_id"] == 42


def test_invalid_topic_id_is_ignored(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(db, "telegram_topic_id", "not-a-number")
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.created", "x") is True
    # _notify_telegram passes message_thread_id=None for an invalid
    # topic; send_message omits a None thread id from the payload,
    # so the message goes to the main chat.
    assert sent[0].get("message_thread_id") is None


def test_negative_topic_id_is_ignored(db, seeded, monkeypatch):
    _configure_telegram(db)
    set_setting(db, "telegram_topic_id", "-5")
    sent = _capture_send(monkeypatch)
    assert events_mod.notify_event(db, "user.created", "x") is True
    assert sent[0].get("message_thread_id") is None


# ---------------------------------------------------------------------------
# Settings UI round-trip
# ---------------------------------------------------------------------------

def test_settings_page_shows_event_checklist(authed_client, db):
    resp = authed_client.get("/settings?section=telegram")
    assert resp.status_code == 200
    assert 'name="telegram_events_present"' in resp.text
    for event in events_mod.EVENT_CATALOG:
        assert f'value="{event}"' in resp.text, event
    assert 'name="telegram_topic_id"' in resp.text


def _dummy_certs(db, tmp_path):
    """Dummy TLS certs so the post-save re-render is clean (the
    seeded TLS inbounds warn without cert_path/key_path)."""
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    set_setting(db, "cert_path", str(cert))
    set_setting(db, "key_path", str(key))


def test_save_settings_persists_events_and_topic(
        authed_client, db, tmp_path):
    _dummy_certs(db, tmp_path)
    resp = authed_client.post(
        "/settings",
        data={
            "section": "telegram",
            "telegram_events_present": "1",
            "telegram_events": ["user.created", "login.locked"],
            "telegram_topic_id": "7",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" not in resp.headers["location"]
    assert json.loads(get_setting(db, events_mod.EVENTS_SETTING_KEY)) == [
        "user.created", "login.locked",
    ]
    assert get_setting(db, "telegram_topic_id") == "7"


def test_save_settings_all_events_off_is_saveable(authed_client, db):
    # The present-marker makes "unchecked everything" a real state.
    resp = authed_client.post(
        "/settings",
        data={"section": "telegram", "telegram_events_present": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert json.loads(get_setting(db, events_mod.EVENTS_SETTING_KEY)) == []


def test_save_settings_invalid_topic_id_rejected(authed_client, db):
    resp = authed_client.post(
        "/settings",
        data={"section": "telegram", "telegram_topic_id": "abc"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert get_setting(db, "telegram_topic_id") == ""


def test_save_settings_other_tab_leaves_events_untouched(authed_client, db):
    set_setting(
        db, events_mod.EVENTS_SETTING_KEY, json.dumps(["user.created"])
    )
    resp = authed_client.post(
        "/settings",
        data={"section": "general", "domain": "example.com"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # Partial updates: the general tab never mentions the events
    # group, so it must not clobber it.
    assert json.loads(get_setting(db, events_mod.EVENTS_SETTING_KEY)) == [
        "user.created"
    ]


# ---------------------------------------------------------------------------
# login.locked event (Phase A item 3 wiring)
# ---------------------------------------------------------------------------

def test_lockout_emits_login_locked_event(test_client, db, monkeypatch):
    from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

    _configure_telegram(db)
    sent = _capture_send(monkeypatch)
    for _ in range(5):
        resp = test_client.post("/login", data={
            "username": ADMIN_USERNAME, "password": "wrong"})
        assert resp.status_code == 401
    # The 6th attempt is locked out — and the lockout notifies once.
    resp = test_client.post("/login", data={
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert resp.status_code == 429
    assert len(sent) == 1
    # A second locked attempt inside the block does not re-notify
    # (dedup on the IP for the block length).
    resp = test_client.post("/login", data={
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
    assert resp.status_code == 429
    assert len(sent) == 1
