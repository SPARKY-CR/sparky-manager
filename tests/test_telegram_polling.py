"""Polling transport tests (Phase 4 follow-up — DESIGN.md §5.9).

Covers: the ``get_updates`` / ``delete_webhook`` helpers in
``app/telegram.py``, the ``telegram_transport`` setting (save +
settings page), and the polling loop in ``app/main.py`` (gating,
dispatch through ``handle_update``, offset tracking, backoff,
never-crash).

No real network anywhere: the Bot API helpers are tested with a fake
httpx.post, and the loop runs with ``get_updates`` / ``handle_update``
stubbed (one integration test drives the real dispatcher with the
sender stubbed, like the webhook tests).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.models import AuditLog
from tests.test_telegram_bot import ADMIN_CHAT, TOKEN, _message

POLLING_KEYS = (
    "telegram_transport",
    "telegram_transport_webhook",
    "telegram_transport_polling",
    "telegram_transport_hint",
    "telegram_polling_active",
    "telegram_polling_webhook_failed",
)


def _configure_bot(db, token=TOKEN, chat_id=str(ADMIN_CHAT)):
    main_mod.set_setting(db, "telegram_bot_token", token)
    main_mod.set_setting(db, "telegram_chat_id", chat_id)


def _fake_httpx_post(calls, status_code=200, payload=None):
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )

    return _post


# ---------------------------------------------------------------------------
# i18n contract — every polling key exists in both languages
# ---------------------------------------------------------------------------


def test_transport_keys_exist_in_both_languages():
    for key in POLLING_KEYS:
        assert key in main_mod.STRINGS["fa"], f"missing fa key: {key}"
        assert key in main_mod.STRINGS["en"], f"missing en key: {key}"


# ---------------------------------------------------------------------------
# telegram.py — get_updates / delete_webhook (fake httpx, no network)
# ---------------------------------------------------------------------------


def test_get_updates_success(monkeypatch):
    calls: list = []
    updates = [{"update_id": 101}, {"update_id": 102}]
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(calls, payload={"ok": True, "result": updates}),
    )
    assert telegram_mod.get_updates("tok") == updates
    assert calls[0]["url"] == "https://api.telegram.org/bottok/getUpdates"
    # No offset given: no "offset" key at all.
    assert calls[0]["json"] == {"timeout": 30}
    # The HTTP timeout exceeds the long-poll wait (30 + 5).
    assert calls[0]["timeout"] == 35.0


def test_get_updates_with_offset_and_timeout(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(calls, payload={"ok": True, "result": []}),
    )
    assert telegram_mod.get_updates("tok", 42, 10) == []
    assert calls[0]["json"] == {"timeout": 10, "offset": 42}
    assert calls[0]["timeout"] == 15.0


def test_get_updates_failures_return_empty_list(monkeypatch):
    calls: list = []
    # API error.
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, payload={"ok": False})
    )
    assert telegram_mod.get_updates("tok") == []
    # HTTP error.
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, status_code=500)
    )
    assert telegram_mod.get_updates("tok") == []
    # Non-list result.
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(calls, payload={"ok": True, "result": {"x": 1}}),
    )
    assert telegram_mod.get_updates("tok") == []
    # Transport error.
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    assert telegram_mod.get_updates("tok") == []
    # Missing token never reaches the network.
    before = len(calls)
    assert telegram_mod.get_updates("") == []
    assert telegram_mod.get_updates("   ") == []
    assert len(calls) == before


def test_delete_webhook(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.delete_webhook("tok") == (True, "")
    assert calls[0]["url"] == "https://api.telegram.org/bottok/deleteWebhook"
    assert calls[0]["json"] == {}


def test_delete_webhook_api_error_returns_description(monkeypatch):
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(
            [], payload={"ok": False, "description": "Bad Request: no webhook"}
        ),
    )
    ok, err = telegram_mod.delete_webhook("tok")
    assert ok is False
    assert err == "Bad Request: no webhook"


def test_delete_webhook_failures(monkeypatch):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    assert telegram_mod.delete_webhook("tok") == (False, "")
    assert telegram_mod.delete_webhook("") == (False, "")
    assert telegram_mod.delete_webhook("   ") == (False, "")


def test_polling_helpers_never_log_the_token(monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    telegram_mod.get_updates("tok123")
    telegram_mod.delete_webhook("tok123")
    assert "tok123" not in caplog.text


# ---------------------------------------------------------------------------
# Settings save — transport switching
# ---------------------------------------------------------------------------


@pytest.fixture()
def rerender_ok(monkeypatch):
    """A clean re-render: the seeded inbounds include TLS inbounds
    with no certificate configured, so a real re-render in tests
    always reports errors — stub it out so the transport message
    assertions are deterministic (re-render behavior itself is
    covered by the existing settings tests)."""
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])


def test_save_transport_polling_calls_delete_webhook(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    # Start on an explicit webhook choice: the unset default is
    # polling (upgrade Phase 3), so a switch needs a webhook start.
    main_mod.set_setting(db, "telegram_transport", "webhook")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: called.append(token) or (True, ""),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "polling",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_transport") == "polling"
    assert called == [TOKEN]
    # The switch is confirmed with a message.
    assert "msg=" in resp.headers["location"]
    assert "err=" not in resp.headers["location"]
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.transport_change")
        .count()
        == 1
    )


def test_save_transport_webhook_does_not_call_delete_webhook(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: called.append(token) or (True, ""),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_transport") == "webhook"
    assert called == []
    assert "msg=" not in resp.headers["location"]


def test_switch_to_polling_delete_webhook_failure_is_shown(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    # Start on an explicit webhook choice (the unset default is
    # polling since upgrade Phase 3).
    main_mod.set_setting(db, "telegram_transport", "webhook")
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: (False, "Bad Request: bad webhook"),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "polling",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "err=" in location
    # Telegram's error text is in the redirect.
    assert "bad+webhook" in location or "bad%20webhook" in location
    # The transport choice is still saved (the intent stands; the
    # next save retries the removal silently).
    assert main_mod.get_setting(db, "telegram_transport") == "polling"


def test_polling_failure_survives_rerender_errors(
    authed_client, db, monkeypatch
):
    """With a REAL re-render (which reports errors in tests — the
    seeded TLS inbounds have no certificate), the polling failure
    still reaches the settings page: it is ordered first, before the
    500-char truncation in _redirect."""
    _configure_bot(db)
    # Start on an explicit webhook choice (the unset default is
    # polling since upgrade Phase 3).
    main_mod.set_setting(db, "telegram_transport", "webhook")
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: (False, "Bad Request: bad webhook"),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "polling",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "err=" in location
    assert "bad+webhook" in location or "bad%20webhook" in location


def test_invalid_transport_keeps_previous(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    monkeypatch.setattr(
        telegram_mod, "delete_webhook", lambda token, **kw: (True, "")
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "carrier-pigeon",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_transport") == "polling"
    # No switch happened, so no transport-change audit row.
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.transport_change")
        .count()
        == 0
    )


def test_save_polling_unconfigured_does_not_call_delete_webhook(
    authed_client, db, monkeypatch, rerender_ok
):
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: called.append(token) or (True, ""),
    )
    resp = authed_client.post(
        "/settings",
        data={"telegram_transport": "polling"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_transport") == "polling"
    assert called == []
    assert "err=" not in resp.headers["location"]


def test_repeat_polling_save_delete_failure_not_shown(
    authed_client, db, monkeypatch, rerender_ok
):
    """A failed removal on a later (unchanged) save is a silent retry:
    it cannot re-create a webhook, so showing it would be a false alarm."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "delete_webhook",
        lambda token, **kw: called.append(token) or (False, "boom"),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "polling",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert called == [TOKEN]  # the removal was retried
    assert "err=" not in resp.headers["location"]
    assert main_mod.get_setting(db, "telegram_transport") == "polling"


def test_settings_page_shows_transport_select(authed_client, db):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    page = authed_client.get("/settings")
    assert page.status_code == 200
    assert 'name="telegram_transport"' in page.text
    assert '<option value="polling" selected>' in page.text
    assert '<option value="webhook" selected>' not in page.text
    # The port hint is visible.
    assert "روی هر پورتی کار می‌کند" in page.text


def test_settings_page_defaults_to_polling(authed_client, db):
    # Polling is the default transport (upgrade Phase 3).
    _configure_bot(db)
    page = authed_client.get("/settings")
    assert page.status_code == 200
    assert '<option value="polling" selected>' in page.text
    assert '<option value="webhook" selected>' not in page.text


# ---------------------------------------------------------------------------
# Polling loop — gating
# ---------------------------------------------------------------------------


def test_polling_token_gating(db, monkeypatch):
    # Unconfigured: no token.
    assert main_mod._telegram_polling_token() is None
    _configure_bot(db)
    # Configured but transport unset: the default is polling (upgrade
    # Phase 3), so the loop polls.
    assert main_mod._telegram_polling_token() == TOKEN
    # An explicit webhook choice is honoured (no polling).
    main_mod.set_setting(db, "telegram_transport", "webhook")
    assert main_mod._telegram_polling_token() is None
    # An invalid stored value falls back to the default (polling).
    main_mod.set_setting(db, "telegram_transport", "carrier-pigeon")
    assert main_mod._telegram_polling_token() == TOKEN
    # Polling + configured: the token.
    main_mod.set_setting(db, "telegram_transport", "polling")
    assert main_mod._telegram_polling_token() == TOKEN
    # Polling without a chat ID: no polling.
    main_mod.set_setting(db, "telegram_chat_id", "")
    assert main_mod._telegram_polling_token() is None
    main_mod.set_setting(db, "telegram_chat_id", str(ADMIN_CHAT))
    assert main_mod._telegram_polling_token() == TOKEN
    # Polling without a token: no polling.
    main_mod.set_setting(db, "telegram_bot_token", "")
    assert main_mod._telegram_polling_token() is None
    # Missing modules: no polling.
    main_mod.set_setting(db, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(main_mod, "bot_mod", None)
    assert main_mod._telegram_polling_token() is None
    monkeypatch.setattr(main_mod, "bot_mod", bot_mod)
    monkeypatch.setattr(main_mod, "telegram_mod", None)
    assert main_mod._telegram_polling_token() is None


# ---------------------------------------------------------------------------
# Polling loop — behavior (short real-time runs, stubbed network)
# ---------------------------------------------------------------------------


@pytest.fixture()
def fast_loop(monkeypatch):
    """Shrink the loop's sleeps so a run covers many iterations."""
    monkeypatch.setattr(main_mod, "TELEGRAM_POLL_IDLE_SECONDS", 0.01)
    monkeypatch.setattr(main_mod, "TELEGRAM_POLL_BACKOFF_BASE", 0.01)
    monkeypatch.setattr(main_mod, "TELEGRAM_POLL_BACKOFF_MAX", 0.02)


def _run_loop(seconds=0.4):
    async def _run():
        task = asyncio.create_task(main_mod._telegram_polling_loop())
        await asyncio.sleep(seconds)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())


def test_loop_dispatches_updates_via_handle_update(
    db, monkeypatch, fast_loop
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    update = _message("/start", update_id=101)
    polls: list = []
    dispatched: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        polls.append((token, offset, timeout))
        return [update] if len(polls) == 1 else []

    def _handle_update(db_session, upd, sender):
        dispatched.append((upd, sender))

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", _handle_update)
    _run_loop()
    # One dispatch, through a TelegramSender bound to the bot token.
    assert len(dispatched) == 1
    assert dispatched[0][0] == update
    sender = dispatched[0][1]
    assert isinstance(sender, bot_mod.TelegramSender)
    assert sender.token == TOKEN
    # First poll had no offset; later polls skip the processed update.
    assert polls[0] == (TOKEN, None, 30.0)
    assert polls[1][1] == 102
    assert all(p[0] == TOKEN and p[2] == 30.0 for p in polls)


def test_loop_offset_advances_past_batch(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    polls: list = []
    batch = [_message("/start", update_id=101), _message("/help", update_id=105)]

    def _get_updates(token, offset=None, timeout=30.0):
        polls.append(offset)
        return list(batch) if len(polls) == 1 else []

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", lambda *a, **kw: None)
    _run_loop()
    assert polls[0] is None
    # Offset is max(update_id) + 1 across the whole batch.
    assert polls[1] == 106


def test_loop_idle_when_webhook(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    polls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_updates",
        lambda *a, **kw: polls.append(True) or [],
    )
    _run_loop(0.3)
    assert polls == []


def test_loop_idle_when_unconfigured(db, monkeypatch, fast_loop):
    main_mod.set_setting(db, "telegram_transport", "polling")
    polls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_updates",
        lambda *a, **kw: polls.append(True) or [],
    )
    _run_loop(0.3)
    assert polls == []


def test_loop_starts_polling_after_transport_switch(
    db, monkeypatch, fast_loop
):
    """Switching to polling in the settings page takes effect live —
    the loop re-reads the transport every round, no restart needed."""
    _configure_bot(db)
    # Start on an explicit webhook choice (the unset default is
    # polling since upgrade Phase 3, so it must be set explicitly).
    main_mod.set_setting(db, "telegram_transport", "webhook")
    polls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_updates",
        lambda *a, **kw: polls.append(True) or [],
    )

    async def _run():
        task = asyncio.create_task(main_mod._telegram_polling_loop())
        await asyncio.sleep(0.2)
        assert polls == []  # webhook: idle
        main_mod.set_setting(db, "telegram_transport", "polling")
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())
    assert polls  # polling started without a restart


def test_loop_survives_get_updates_error(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    polls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        polls.append(True)
        raise RuntimeError("telegram down")

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    _run_loop()  # must not raise
    # The loop kept retrying (with backoff) instead of dying.
    assert len(polls) >= 3


def test_loop_survives_dispatch_error(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    update = _message("/start", update_id=101)
    polls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        polls.append(True)
        return [update] if len(polls) == 1 else []

    def _handle_update(db_session, upd, sender):
        raise RuntimeError("dispatch boom")

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", _handle_update)
    _run_loop()  # must not raise
    # The loop kept polling after the failed dispatch.
    assert len(polls) >= 2


def test_loop_dedups_repeated_update(db, monkeypatch, fast_loop):
    """The same update delivered twice in one batch is answered once
    (real dispatcher + stubbed sender — the loop's dedup comes from
    bot.py's _seen_updates, like the webhook path)."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    sent: list = []
    monkeypatch.setattr(
        telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent.append(text) or True,
    )
    update = _message("/start", update_id=201)
    calls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        calls.append(True)
        return [update, update] if len(calls) == 1 else []

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    _run_loop()
    assert len(sent) == 1
    assert "sparky-manager" in sent[0]
