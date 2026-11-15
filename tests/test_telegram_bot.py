"""Phase 4 tests — Telegram management bot (DESIGN.md §5.9).

Covers: the Bot API helpers in app/telegram.py (keyboards, edits,
callback answers, webhook registration/status), the bot dispatcher
(auth, dedup, commands, menus), every user/inbound/status handler,
the guided create-user flow, the webhook route (incl. the secret web
prefix), and the settings-page webhook actions.

No real network anywhere: bot handlers are driven with fake Telegram
update payloads and a fake sender; the webhook route runs through
TestClient with the telegram module's send functions stubbed; the
Bot API helpers are tested with a fake httpx.post.
"""

from __future__ import annotations

import itertools
import json
import time
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import bot as bot_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app import webcommon
from app.models import AuditLog, Client, Inbound, Setting, TrafficDaily, User
from tests.conftest import HOST, ensure_defaults

ADMIN_CHAT = 987654321
OTHER_CHAT = 111222333
TOKEN = "999999:TEST-TOKEN-abcdef"
SECRET = "wh-secret-0123456789abcdef"

_uid_counter = itertools.count(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_bot(db, token=TOKEN, chat_id=str(ADMIN_CHAT), secret=SECRET):
    main_mod.set_setting(db, "telegram_bot_token", token)
    main_mod.set_setting(db, "telegram_chat_id", chat_id)
    if secret is not None:
        main_mod.set_setting(db, "telegram_webhook_secret", secret)


def _message(text, chat_id=ADMIN_CHAT, update_id=None, message_id=10):
    return {
        "update_id": update_id if update_id is not None else next(_uid_counter),
        "message": {
            "message_id": message_id,
            "chat": {"id": chat_id, "type": "private"},
            "text": text,
        },
    }


def _callback(data, chat_id=ADMIN_CHAT, update_id=None, message_id=10,
              callback_id="cb-1"):
    return {
        "update_id": update_id if update_id is not None else next(_uid_counter),
        "callback_query": {
            "id": callback_id,
            "data": data,
            "message": {
                "message_id": message_id,
                "chat": {"id": chat_id, "type": "private"},
            },
        },
    }


class FakeSender:
    """Records bot replies (send / edit / answer / document) instead
    of calling Telegram."""

    def __init__(self, edit_ok=True, document_ok=True):
        self.sent: list = []  # (chat_id, text, reply_markup)
        self.edited: list = []  # (chat_id, message_id, text, reply_markup)
        self.answered: list = []  # (callback_query_id, text)
        self.documents: list = []  # (chat_id, filename, data)
        self.edit_ok = edit_ok
        self.document_ok = document_ok

    def send(self, chat_id, text, reply_markup=None):
        self.sent.append((chat_id, text, reply_markup))
        return True

    def edit(self, chat_id, message_id, text, reply_markup=None):
        self.edited.append((chat_id, message_id, text, reply_markup))
        return self.edit_ok

    def answer(self, callback_query_id, text=None):
        self.answered.append((callback_query_id, text))
        return True

    def document(self, chat_id, filename, data):
        self.documents.append((chat_id, filename, data))
        return self.document_ok


def _button_data(reply_markup):
    """All callback_data strings in a keyboard (depth-first)."""
    out = []
    if not reply_markup:
        return out
    for row in reply_markup.get("inline_keyboard", []):
        for button in row:
            out.append(button.get("callback_data"))
    return out


def _button_texts(reply_markup):
    out = []
    if not reply_markup:
        return out
    for row in reply_markup.get("inline_keyboard", []):
        for button in row:
            out.append(button.get("text"))
    return out


@pytest.fixture()
def sender():
    return FakeSender()


@pytest.fixture()
def rerender_stub(monkeypatch):
    """Record rerender_configs calls (the bot must call it after every
    state change, like the web routes do)."""
    calls: list = []

    def _stub(db):
        calls.append(True)
        return []

    monkeypatch.setattr(main_mod, "rerender_configs", _stub)
    return calls


@pytest.fixture()
def rerender_fails(monkeypatch):
    def _stub(db):
        return ["xray: config invalid"]

    monkeypatch.setattr(main_mod, "rerender_configs", _stub)


def _dispatch(db, update, sender, **kwargs):
    bot_mod.handle_update(db, update, sender, **kwargs)


def _audit_actions(db, action):
    return (
        db.query(AuditLog).filter(AuditLog.action == action).all()
    )


# ---------------------------------------------------------------------------
# i18n contract — every bot key exists in both languages
# ---------------------------------------------------------------------------


def test_bot_string_keys_exist_in_both_languages():
    for key in bot_mod.BOT_STRING_KEYS:
        assert key in main_mod.STRINGS["fa"], f"missing fa key: {key}"
        assert key in main_mod.STRINGS["en"], f"missing en key: {key}"


def test_webhook_settings_keys_exist_in_both_languages():
    keys = (
        "telegram_webhook",
        "telegram_webhook_hint",
        "telegram_webhook_register",
        "telegram_webhook_refresh",
        "telegram_webhook_url",
        "telegram_webhook_registered_at",
        "telegram_webhook_pending",
        "telegram_webhook_last_error",
        "telegram_webhook_not_registered",
        "telegram_webhook_registered",
        "telegram_webhook_failed",
        "telegram_webhook_status_ok",
        "telegram_webhook_status_failed",
        "telegram_domain_required",
        "telegram_webhook_port_warning",
    )
    for key in keys:
        assert key in main_mod.STRINGS["fa"], f"missing fa key: {key}"
        assert key in main_mod.STRINGS["en"], f"missing en key: {key}"


# ---------------------------------------------------------------------------
# telegram.py — new Bot API helpers (fake httpx, no network)
# ---------------------------------------------------------------------------


def _fake_httpx_post(calls, status_code=200, payload=None):
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )

    return _post


def test_send_message_with_reply_markup(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    markup = {"inline_keyboard": [[{"text": "x", "callback_data": "y"}]]}
    assert telegram_mod.send_message("tok", "42", "hi", reply_markup=markup) is True
    assert calls[0]["json"]["reply_markup"] == markup
    assert calls[0]["json"]["text"] == "hi"


def test_send_message_without_markup_keeps_phase3_payload(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.send_message("tok", "42", "hi") is True
    assert calls[0]["json"] == {"chat_id": "42", "text": "hi"}


def test_edit_message_text(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    markup = {"inline_keyboard": []}
    assert telegram_mod.edit_message_text(
        "tok", "42", 7, "new", reply_markup=markup
    ) is True
    assert calls[0]["url"] == "https://api.telegram.org/bottok/editMessageText"
    assert calls[0]["json"] == {
        "chat_id": "42", "message_id": 7, "text": "new", "reply_markup": markup,
    }


def test_edit_message_text_failures(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, status_code=400)
    )
    assert telegram_mod.edit_message_text("tok", "42", 7, "new") is False
    # Missing args never reach the network.
    assert telegram_mod.edit_message_text("", "42", 7, "new") is False
    assert telegram_mod.edit_message_text("tok", "42", 0, "new") is False
    assert telegram_mod.edit_message_text("tok", "42", 7, "  ") is False
    assert len(calls) == 1


def test_answer_callback_query(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.answer_callback_query("tok", "cb-9", "done!") is True
    assert calls[0]["url"] == (
        "https://api.telegram.org/bottok/answerCallbackQuery"
    )
    assert calls[0]["json"] == {"callback_query_id": "cb-9", "text": "done!"}
    # No toast text: no "text" key at all.
    assert telegram_mod.answer_callback_query("tok", "cb-9") is True
    assert calls[1]["json"] == {"callback_query_id": "cb-9"}
    # Toasts are capped at 200 chars (Bot API limit).
    assert telegram_mod.answer_callback_query("tok", "cb-9", "x" * 500) is True
    assert len(calls[2]["json"]["text"]) == 200
    assert telegram_mod.answer_callback_query("tok", "") is False


def test_set_webhook(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    ok, err = telegram_mod.set_webhook("tok", "https://example.com/hook/secret")
    assert (ok, err) == (True, "")
    assert calls[0]["url"] == "https://api.telegram.org/bottok/setWebhook"
    assert calls[0]["json"] == {"url": "https://example.com/hook/secret"}


def test_set_webhook_api_error_returns_description(monkeypatch):
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(
            [],
            payload={"ok": False, "description": "Bad Request: bad webhook"},
        ),
    )
    ok, err = telegram_mod.set_webhook("tok", "https://example.com/hook")
    assert ok is False
    assert err == "Bad Request: bad webhook"


def test_set_webhook_transport_failure(monkeypatch):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    ok, err = telegram_mod.set_webhook("tok", "https://example.com/hook")
    assert (ok, err) == (False, "")
    assert telegram_mod.set_webhook("", "https://example.com/hook") == (False, "")
    assert telegram_mod.set_webhook("tok", "") == (False, "")


def test_get_webhook_info(monkeypatch):
    result = {"url": "https://example.com/hook", "pending_update_count": 3}
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post([], payload={"ok": True, "result": result}),
    )
    assert telegram_mod.get_webhook_info("tok") == result
    # API error -> None.
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post([], payload={"ok": False})
    )
    assert telegram_mod.get_webhook_info("tok") is None
    assert telegram_mod.get_webhook_info("") is None


def test_api_helpers_never_log_the_token(monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    telegram_mod.edit_message_text("tok123", "42", 7, "x")
    telegram_mod.answer_callback_query("tok123", "cb")
    telegram_mod.set_webhook("tok123", "https://example.com/hook")
    telegram_mod.get_webhook_info("tok123")
    assert "tok123" not in caplog.text


def test_telegram_sender_delegates(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: calls.append(("send", token, chat_id, text, kw)) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "edit_message_text",
        lambda token, chat_id, mid, text, **kw: calls.append(("edit", token, chat_id, mid, text, kw)) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "answer_callback_query",
        lambda token, qid, text=None, **kw: calls.append(("answer", token, qid, text)) or True,
    )
    sender = bot_mod.TelegramSender("tok-xyz")
    sender.send(42, "hi", reply_markup={"inline_keyboard": []})
    sender.edit(42, 7, "new")
    sender.answer("cb-1", "toast")
    assert calls[0][0] == "send" and calls[0][1] == "tok-xyz"
    assert calls[1][0] == "edit" and calls[1][3] == 7
    assert calls[2] == ("answer", "tok-xyz", "cb-1", "toast")


# ---------------------------------------------------------------------------
# Dispatcher — auth, dedup, commands
# ---------------------------------------------------------------------------


def test_unconfigured_bot_ignores_everything(db, sender):
    _dispatch(db, _message("/start"), sender)
    assert sender.sent == []


def test_stranger_chat_ignored_silently(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start", chat_id=OTHER_CHAT), sender)
    _dispatch(db, _callback("m:users", chat_id=OTHER_CHAT), sender)
    assert sender.sent == []
    assert sender.edited == []
    assert sender.answered == []


def test_unknown_update_shapes_ignored(db, sender):
    _configure_bot(db)
    _dispatch(db, {}, sender)
    _dispatch(db, {"update_id": 1}, sender)
    _dispatch(db, {"update_id": 2, "edited_message": {"text": "/start"}}, sender)
    _dispatch(db, {"update_id": 3, "channel_post": {"text": "/start"}}, sender)
    _dispatch(db, "not a dict", sender)
    _dispatch(db, None, sender)
    assert sender.sent == []


def test_non_text_message_ignored(db, sender):
    _configure_bot(db)
    update = {
        "update_id": next(_uid_counter),
        "message": {
            "message_id": 5,
            "chat": {"id": ADMIN_CHAT},
            "photo": [{"file_id": "abc"}],
        },
    }
    _dispatch(db, update, sender)
    assert sender.sent == []


def test_duplicate_update_id_processed_once(db, sender):
    _configure_bot(db)
    update = _message("/start", update_id=4242)
    _dispatch(db, update, sender)
    _dispatch(db, update, sender)
    _dispatch(db, dict(update), sender)
    # /start sends 2 messages (welcome + reply-keyboard hint) — the
    # duplicate updates must not add a third or fourth.
    assert len(sender.sent) == 2


def test_distinct_update_ids_all_processed(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start", update_id=1), sender)
    _dispatch(db, _message("/start", update_id=2), sender)
    assert len(sender.sent) == 4


def test_start_shows_main_menu(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert len(sender.sent) == 2
    chat_id, text, markup = sender.sent[0]
    assert chat_id == ADMIN_CHAT
    assert "sparky-manager" in text
    assert _button_data(markup) == ["m:users", "m:inb", "m:status", "m:help", "m:svc", "m:bkp"]
    # Second message installs the persistent reply keyboard.
    assert sender.sent[1][2].get("keyboard")


def test_start_with_bot_suffix(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start@SparkyManagerBot"), sender)
    assert len(sender.sent) == 2
    assert _button_data(sender.sent[0][2]) == ["m:users", "m:inb", "m:status", "m:help", "m:svc", "m:bkp"]


def test_help_and_unknown_command(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/help"), sender)
    assert "/start" in sender.sent[0][1]
    _dispatch(db, _message("/bogus"), sender)
    assert len(sender.sent) == 2
    assert "ناشناخته" in sender.sent[1][1]
    assert _button_data(sender.sent[1][2]) == ["m:users", "m:inb", "m:status", "m:help", "m:svc", "m:bkp"]


def test_plain_text_when_idle_shows_hint(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("hello there"), sender)
    assert len(sender.sent) == 1
    assert "ناشناخته" in sender.sent[0][1]


def test_cancel_when_idle(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/cancel"), sender)
    assert sender.sent[0][1] == main_mod.STRINGS["fa"]["bot_cancelled"]


def test_dispatch_never_raises_on_broken_sender(db):
    _configure_bot(db)

    class _Broken:
        def send(self, *a, **kw):
            raise RuntimeError("boom")

        def edit(self, *a, **kw):
            raise RuntimeError("boom")

        def answer(self, *a, **kw):
            raise RuntimeError("boom")

    # Must return normally, not raise into the webhook route.
    bot_mod.handle_update(db, _message("/start"), _Broken())
    bot_mod.handle_update(db, _callback("m:users"), _Broken())


def test_callback_answer_always_sent(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("m:users", callback_id="cb-99"), sender)
    assert sender.answered == [("cb-99", None)]


def test_malformed_callback_data_answered_safely(db, sender):
    """Malformed/unknown callbacks (upgrade Phase 3) are answered
    with the friendly stale message + a way back to the menu — never
    silence, never a crash, never a new message (the tapped message
    is edited in place)."""
    _configure_bot(db)
    _dispatch(db, _callback("", callback_id="cb-1"), sender)
    _dispatch(db, _callback("zzz:1:2", callback_id="cb-2"), sender)
    _dispatch(db, _callback("u:v:not-a-number", callback_id="cb-3"), sender)
    _dispatch(db, _callback("u:v", callback_id="cb-4"), sender)
    assert sender.sent == []
    assert len(sender.edited) == 4
    for _chat_id, _msg_id, text, markup in sender.edited:
        assert "دیگر معتبر نیست" in text
        assert "m:users" in _button_data(markup)
    assert len(sender.answered) == 4


def test_edit_failure_falls_back_to_send(db, sender):
    _configure_bot(db)
    sender.edit_ok = False
    _dispatch(db, _callback("m:users"), sender)
    # The edit was attempted and failed; the list arrived as a new message.
    assert len(sender.edited) == 1
    assert len(sender.sent) == 1
    assert "کاربران" in sender.sent[0][1]


# ---------------------------------------------------------------------------
# Users — list / view
# ---------------------------------------------------------------------------


def test_users_list_single_page(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("m:users"), sender)
    assert len(sender.edited) == 1
    text = sender.edited[0][2]
    for name in ("alice", "bob", "carol", "dave", "eve"):
        assert name in text
    data = _button_data(sender.edited[0][3])
    assert f"u:v:{seeded['users']['alice'].id}" in data
    assert "u:new" in data
    assert "m:main" in data
    # One page: no prev/next buttons.
    assert not any(d.startswith("u:list:") for d in data)


def test_users_list_pagination(db, sender):
    _configure_bot(db)
    now = datetime.now(timezone.utc)
    for i in range(10):
        db.add(User(name=f"u{i:02d}", sub_token=f"tok-{i}",
                    created_at=now + timedelta(seconds=i)))
    db.commit()
    # 15 users -> 2 pages (8 + 7).
    _dispatch(db, _callback("m:users"), sender)
    text = sender.edited[0][2]
    assert "صفحه 1 از 2" in text
    data = _button_data(sender.edited[0][3])
    assert "u:list:1" in data
    assert "u:list:0" not in data
    _dispatch(db, _callback("u:list:1"), sender)
    text = sender.edited[1][2]
    assert "صفحه 2 از 2" in text
    data = _button_data(sender.edited[1][3])
    assert "u:list:0" in data
    assert "u:list:2" not in data
    # Page numbers clamp instead of crashing.
    _dispatch(db, _callback("u:list:99"), sender)
    assert "صفحه 2 از 2" in sender.edited[2][2]


def test_users_list_empty(db, sender):
    _configure_bot(db)
    db.query(Client).delete()
    db.query(User).delete()
    db.commit()
    _dispatch(db, _callback("m:users"), sender)
    assert "کاربری ساخته نشده" in sender.edited[0][2]
    assert "u:new" in _button_data(sender.edited[0][3])


def test_user_view(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:v:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "alice" in text
    assert "ترافیک" in text
    assert "vless-reality" in text
    data = _button_data(sender.edited[0][3])
    assert f"u:links:{alice.id}" in data
    assert f"u:frz:{alice.id}" in data
    assert f"u:ext:{alice.id}" in data
    assert f"u:rst:{alice.id}" in data
    assert f"u:del:{alice.id}" in data
    assert "u:list:0" in data


def test_user_view_missing_user(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("u:v:99999"), sender)
    assert "پیدا نشد" in sender.edited[0][2]


def test_user_view_shows_frozen_state(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    for client in db.query(Client).filter(Client.user_id == alice.id).all():
        client.extra = {"frozen": True}
    db.commit()
    _dispatch(db, _callback(f"u:v:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "فریز" in text
    data = _button_data(sender.edited[0][3])
    assert f"u:unfrz:{alice.id}" in data
    assert f"u:frz:{alice.id}" not in data


# ---------------------------------------------------------------------------
# Users — freeze / extend / reset / delete
# ---------------------------------------------------------------------------


def test_freeze_and_unfreeze(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:frz:{alice.id}", callback_id="cb-f"), sender)
    db.expire_all()
    assert all(
        (c.extra or {}).get("frozen")
        for c in db.query(Client).filter(Client.user_id == alice.id).all()
    )
    assert len(_audit_actions(db, "user.freeze")) == 1
    assert _audit_actions(db, "user.freeze")[0].detail.endswith("[telegram]")
    assert rerender_stub == [True]
    assert sender.answered == [("cb-f", main_mod.STRINGS["fa"]["bot_frozen"])]
    # The view now offers unfreeze.
    assert f"u:unfrz:{alice.id}" in _button_data(sender.edited[0][3])

    _dispatch(db, _callback(f"u:unfrz:{alice.id}", callback_id="cb-u"), sender)
    db.expire_all()
    assert not any(
        (c.extra or {}).get("frozen")
        for c in db.query(Client).filter(Client.user_id == alice.id).all()
    )
    assert len(_audit_actions(db, "user.unfreeze")) == 1
    assert sender.answered[1] == ("cb-u", main_mod.STRINGS["fa"]["bot_unfrozen"])


def test_freeze_rerender_failure_shown_in_view(db, sender, seeded, rerender_fails):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:frz:{alice.id}"), sender)
    assert "xray: config invalid" in sender.edited[0][2]
    assert "بازسازی کانفیگ‌ها ناموفق بود" in sender.edited[0][2]


def test_delete_flow_with_confirmation(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    bob = seeded["users"]["bob"]
    _dispatch(db, _callback(f"u:del:{bob.id}"), sender)
    assert "قابل بازگشت نیست" in sender.edited[0][2]
    data = _button_data(sender.edited[0][3])
    assert f"u:del:{bob.id}:ok" in data
    assert f"u:v:{bob.id}" in data
    # Not deleted yet.
    assert db.get(User, bob.id) is not None
    _dispatch(db, _callback(f"u:del:{bob.id}:ok", callback_id="cb-d"), sender)
    db.expire_all()
    assert db.get(User, bob.id) is None
    assert db.query(Client).filter(Client.user_id == bob.id).count() == 0
    assert len(_audit_actions(db, "user.delete")) == 1
    assert rerender_stub == [True]
    assert sender.answered[-1][1] == main_mod.STRINGS["fa"]["bot_deleted"]
    # Back on the users list.
    assert "کاربران" in sender.edited[1][2]


def test_delete_cancel_keeps_user(db, sender, seeded):
    _configure_bot(db)
    bob = seeded["users"]["bob"]
    _dispatch(db, _callback(f"u:del:{bob.id}"), sender)
    _dispatch(db, _callback(f"u:v:{bob.id}"), sender)
    assert db.get(User, bob.id) is not None
    assert "bob" in sender.edited[1][2]


def test_extend_flow(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:ext:{alice.id}"), sender)
    data = _button_data(sender.edited[0][3])
    assert f"u:ext:{alice.id}:7" in data
    assert f"u:ext:{alice.id}:30" in data
    assert f"u:ext:{alice.id}:90" in data
    before = datetime.now(timezone.utc)
    _dispatch(db, _callback(f"u:ext:{alice.id}:30", callback_id="cb-e"), sender)
    db.expire_all()
    alice = db.get(User, alice.id)
    assert alice.expires_at is not None
    delta = alice.expires_at.replace(tzinfo=timezone.utc) - before
    assert timedelta(days=29) < delta <= timedelta(days=30, seconds=60)
    assert len(_audit_actions(db, "user.extend")) == 1
    assert rerender_stub == [True]
    assert "30 روز" in sender.answered[-1][1]


def test_extend_expired_user_extends_from_now(db, sender, seeded):
    _configure_bot(db)
    bob = seeded["users"]["bob"]  # expired yesterday
    _dispatch(db, _callback(f"u:ext:{bob.id}:7"), sender)
    db.expire_all()
    bob = db.get(User, bob.id)
    assert bob.expires_at is not None
    assert bob.expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc)


def test_reset_traffic_flow(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    carol = seeded["users"]["carol"]  # used == limit == 1000
    assert carol.traffic_used_bytes == 1000
    _dispatch(db, _callback(f"u:rst:{carol.id}"), sender)
    assert "صفر شود" in sender.edited[0][2]
    assert f"u:rst:{carol.id}:ok" in _button_data(sender.edited[0][3])
    _dispatch(db, _callback(f"u:rst:{carol.id}:ok", callback_id="cb-r"), sender)
    db.expire_all()
    assert db.get(User, carol.id).traffic_used_bytes == 0
    assert len(_audit_actions(db, "user.reset_traffic")) == 1
    assert rerender_stub == [True]
    assert sender.answered[-1][1] == main_mod.STRINGS["fa"]["bot_traffic_reset"]


# ---------------------------------------------------------------------------
# Users — links
# ---------------------------------------------------------------------------


def test_links_send_share_links_and_subscription(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    main_mod.set_setting(db, "domain", "panel.example.com")
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "vless://" in text
    assert "trojan://" in text
    assert f"/sub/{alice.sub_token}" in text
    assert "panel.example.com" in text
    assert f"u:v:{alice.id}" in _button_data(sender.edited[0][3])


def test_links_without_host_is_honest(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    assert "دامنه یا هاست سابسکریپشن" in sender.edited[0][2]
    assert "vless://" not in sender.edited[0][2]


def test_links_for_unusable_user_show_sub_url_only(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    main_mod.set_setting(db, "domain", "panel.example.com")
    dave = seeded["users"]["dave"]  # disabled: no usable clients
    _dispatch(db, _callback(f"u:links:{dave.id}"), sender)
    text = sender.edited[0][2]
    assert "vless://" not in text
    assert f"/sub/{dave.sub_token}" in text


def test_split_text_chunks_on_lines():
    short = "a\nb\nc"
    assert bot_mod._split_text(short) == ["a\nb\nc"]
    long_text = "\n".join(f"line-{i:04d}-{'x' * 100}" for i in range(100))
    chunks = bot_mod._split_text(long_text)
    assert len(chunks) > 1
    assert all(len(c) <= bot_mod.MESSAGE_CHUNK for c in chunks)
    assert "".join(chunks) == long_text
    # A single over-long line goes in a chunk of its own (never split
    # mid-line — the sender truncates at the Bot API limit instead).
    assert bot_mod._split_text("x" * 5000) == ["x" * 5000]


def test_long_links_message_is_chunked(db, sender, seeded, monkeypatch):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    main_mod.set_setting(db, "domain", "panel.example.com")
    # Force tiny chunks to exercise the follow-up path.
    monkeypatch.setattr(bot_mod, "MESSAGE_CHUNK", 300)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    assert len(sender.edited) == 1
    assert len(sender.sent) >= 1  # follow-up chunks
    rebuilt = sender.edited[0][2] + "".join(t for _, t, _ in sender.sent)
    assert "vless://" in rebuilt
    assert f"/sub/{alice.sub_token}" in rebuilt


# ---------------------------------------------------------------------------
# Inbounds — list / view / toggle
# ---------------------------------------------------------------------------


def test_inbounds_list(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("m:inb"), sender)
    text = sender.edited[0][2]
    assert "vless-reality" in text
    assert "wireguard" in text
    assert "vless:443" in text
    data = _button_data(sender.edited[0][3])
    assert f"i:v:{seeded['inbounds']['vless-reality'].id}" in data
    assert "m:main" in data


def test_inbounds_list_empty(db, sender):
    _configure_bot(db)
    db.query(Client).delete()
    db.query(Inbound).delete()
    db.commit()
    _dispatch(db, _callback("m:inb"), sender)
    assert "اینباندی ساخته نشده" in sender.edited[0][2]


def test_inbound_view(db, sender, seeded):
    _configure_bot(db)
    vless = seeded["inbounds"]["vless-reality"]
    _dispatch(db, _callback(f"i:v:{vless.id}"), sender)
    text = sender.edited[0][2]
    assert "vless-reality" in text
    assert "vless" in text
    assert "443" in text
    assert "xray" in text
    data = _button_data(sender.edited[0][3])
    assert f"i:tg:{vless.id}" in data
    assert "i:list" in data
    assert any(
        "غیرفعال کردن" in t for t in _button_texts(sender.edited[0][3])
    )


def test_inbound_view_missing(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:v:99999"), sender)
    assert "پیدا نشد" in sender.edited[0][2]


def test_inbound_toggle(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    vless = seeded["inbounds"]["vless-reality"]
    assert vless.enabled is True
    _dispatch(db, _callback(f"i:tg:{vless.id}", callback_id="cb-t"), sender)
    db.expire_all()
    assert db.get(Inbound, vless.id).enabled is False
    assert len(_audit_actions(db, "inbound.toggle")) == 1
    assert rerender_stub == [True]
    assert "غیرفعال" in sender.answered[-1][1]
    # The view now offers to re-enable.
    assert any("فعال کردن" in t for t in _button_texts(sender.edited[0][3]))
    _dispatch(db, _callback(f"i:tg:{vless.id}"), sender)
    db.expire_all()
    assert db.get(Inbound, vless.id).enabled is True


def test_inbound_toggle_missing(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:tg:99999"), sender)
    assert "پیدا نشد" in sender.edited[0][2]


# ---------------------------------------------------------------------------
# Server status
# ---------------------------------------------------------------------------


def test_server_status(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    today = date.today()
    db.add(TrafficDaily(user_id=alice.id, date=today,
                        up_bytes=1000, down_bytes=3000))
    db.add(TrafficDaily(user_id=alice.id, date=today - timedelta(days=1),
                        up_bytes=500, down_bytes=500))
    db.commit()
    _dispatch(db, _callback("m:status"), sender)
    text = sender.edited[0][2]
    assert "وضعیت سرور" in text
    # 5 users, 4 enabled, 1 expired (bob).
    assert "5" in text and "4" in text
    # Today: 4000 B; 14 days: 5000 B.
    assert "3.9 KB" in text  # 4000 B
    assert "4.9 KB" in text  # 5000 B
    assert "m:main" in _button_data(sender.edited[0][3])


def test_server_status_without_system_status_module(db, sender, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(bot_mod, "system_status_mod", None)
    _dispatch(db, _callback("m:status"), sender)
    # Traffic-only status still arrives; no crash.
    assert "وضعیت سرور" in sender.edited[0][2]
    assert "ترافیک امروز" in sender.edited[0][2]


def test_server_status_traffic_summary_window(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    today = date.today()
    # 20 days ago: outside the 14-day window.
    db.add(TrafficDaily(user_id=alice.id, date=today - timedelta(days=20),
                        up_bytes=10**9, down_bytes=0))
    db.add(TrafficDaily(user_id=alice.id, date=today,
                        up_bytes=1024, down_bytes=0))
    db.commit()
    _dispatch(db, _callback("m:status"), sender)
    text = sender.edited[0][2]
    # Today + 14d are both 1024 B — the 20-day-old gigabyte is excluded
    # (had it counted, the 14d line would read 1.0 GB).
    assert "<b>📈 ترافیک امروز:</b> 1.0 KB" in text
    assert "<b>📈 ترافیک ۱۴ روز گذشته:</b> 1.0 KB" in text


# ---------------------------------------------------------------------------
# Create-user flow
# ---------------------------------------------------------------------------


def _start_flow(db, sender):
    _dispatch(db, _callback("u:new"), sender)
    assert "نام کاربر" in sender.edited[0][2]


def test_create_flow_happy_path(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("botuser"), sender)
    # Inbound picker: every enabled inbound pre-selected.
    picker = sender.sent[0][2]
    assert "اینباندهای این کاربر" in sender.sent[0][1]
    assert all(
        text.startswith("✅") for text in _button_texts(picker)[:-2]
    )
    wg = seeded["inbounds"]["wireguard"]
    _dispatch(db, _callback(f"c:tg:{wg.id}"), sender)
    # WireGuard is now deselected.
    assert any(
        text.startswith("⬜") and "wireguard" in text
        for text in _button_texts(sender.edited[-1][3])
    )
    _dispatch(db, _callback("c:done"), sender)
    assert "گیگابایت" in sender.edited[-1][2]
    _dispatch(db, _message("10"), sender)
    assert "انقضا" in sender.sent[-1][1]
    before = datetime.now(timezone.utc)
    _dispatch(db, _message("30"), sender)
    db.expire_all()
    user = db.query(User).filter(User.name == "botuser").first()
    assert user is not None
    assert user.traffic_limit_bytes == 10 * 1024**3
    assert user.expires_at is not None
    delta = user.expires_at.replace(tzinfo=timezone.utc) - before
    assert timedelta(days=29) < delta <= timedelta(days=30, seconds=60)
    # Clients on every enabled inbound EXCEPT wireguard.
    inbound_ids = {
        c.inbound_id
        for c in db.query(Client).filter(Client.user_id == user.id).all()
    }
    enabled_ids = {
        i.id
        for i in db.query(Inbound).filter(Inbound.enabled.is_(True)).all()
    }
    assert inbound_ids == enabled_ids - {wg.id}
    assert len(_audit_actions(db, "user.create")) == 1
    assert rerender_stub == [True]
    assert "botuser" in sender.sent[-1][1]
    assert f"u:v:{user.id}" in _button_data(sender.sent[-1][2])


def test_create_flow_unlimited_and_never_expiring(db, sender, rerender_stub):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("freeuser"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _message("0"), sender)
    _dispatch(db, _message("0"), sender)
    db.expire_all()
    user = db.query(User).filter(User.name == "freeuser").first()
    assert user is not None
    assert user.traffic_limit_bytes is None
    assert user.expires_at is None


def test_create_flow_invalid_name_then_valid(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("bad name!"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    _dispatch(db, _message("alice"), sender)
    assert "این نام هست" in sender.sent[-1][1]
    _dispatch(db, _message("ok-name_1"), sender)
    assert "اینباندهای این کاربر" in sender.sent[-1][1]


def test_create_flow_invalid_limit_and_expiry(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("limuser"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _message("abc"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    _dispatch(db, _message("-5"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    _dispatch(db, _message("2.5"), sender)
    assert "انقضا" in sender.sent[-1][1]
    _dispatch(db, _message("abc"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    _dispatch(db, _message("0"), sender)
    db.expire_all()
    user = db.query(User).filter(User.name == "limuser").first()
    assert user is not None
    assert user.traffic_limit_bytes == int(2.5 * 1024**3)
    assert user.expires_at is None


def test_create_flow_cancel_command(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("willcancel"), sender)
    _dispatch(db, _message("/cancel"), sender)
    assert sender.sent[-1][1] == main_mod.STRINGS["fa"]["bot_cancelled"]
    assert db.query(User).filter(User.name == "willcancel").first() is None
    # The flow is gone: free text is now just the idle hint.
    _dispatch(db, _message("10"), sender)
    assert "ناشناخته" in sender.sent[-1][1]


def test_create_flow_cancel_button(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _callback("c:cancel"), sender)
    assert "لغو شد" in sender.edited[-1][2]
    assert "m:users" in _button_data(sender.edited[-1][3])


def test_create_flow_done_with_nothing_selected(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("picknone"), sender)
    picker = sender.sent[-1][2]
    for data in _button_data(picker):
        if data and data.startswith("c:tg:"):
            _dispatch(db, _callback(data), sender)
    # Every inbound deselected; "done" toasts instead of advancing.
    _dispatch(db, _callback("c:done", callback_id="cb-done"), sender)
    assert sender.answered[-1][1] == main_mod.STRINGS["fa"]["bot_create_pick_one"]
    assert "اینباندهای این کاربر" in sender.edited[-1][2]
    assert db.query(User).filter(User.name == "picknone").first() is None


def test_create_flow_text_during_picker(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("pickertext"), sender)
    _dispatch(db, _message("some text"), sender)
    assert "دکمه‌ها" in sender.sent[-1][1]


def test_create_flow_no_enabled_inbounds(db, sender):
    _configure_bot(db)
    db.query(Inbound).update({Inbound.enabled: False})
    db.commit()
    _dispatch(db, _callback("u:new"), sender)
    assert "اینباند فعالی نیست" in sender.edited[0][2]


def test_create_flow_expires(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    # Age the conversation past its timeout.
    bot_mod._conversations[ADMIN_CHAT]["expires"] = time.monotonic() - 1
    _dispatch(db, _message("lateuser"), sender)
    assert "ناشناخته" in sender.sent[-1][1]
    assert db.query(User).filter(User.name == "lateuser").first() is None


def test_create_flow_stale_picker_callback(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("staleuser"), sender)
    bot_mod._conversations[ADMIN_CHAT]["expires"] = time.monotonic() - 1
    _dispatch(db, _callback("c:done"), sender)
    assert "منقضی شده" in sender.edited[-1][2]


def test_menu_tap_abandons_create_flow(db, sender):
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _callback("m:users"), sender)
    assert "کاربران" in sender.edited[-1][2]
    _dispatch(db, _message("abandoned"), sender)
    assert "ناشناخته" in sender.sent[-1][1]
    assert db.query(User).filter(User.name == "abandoned").first() is None


def test_create_flow_failure_reports_and_survives(db, sender, monkeypatch):
    _configure_bot(db)

    def _boom(db, user, inbound_ids=None):
        raise RuntimeError("db down")

    monkeypatch.setattr(main_mod, "_create_clients_for_user", _boom)
    _start_flow(db, sender)
    _dispatch(db, _message("failuser"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _message("0"), sender)
    _dispatch(db, _message("0"), sender)
    assert "ناموفق بود" in sender.sent[-1][1]
    assert db.query(User).filter(User.name == "failuser").first() is not None
    # The bot still works afterwards.
    _dispatch(db, _message("/start"), sender)
    # /start sends welcome + reply-keyboard hint — the welcome is
    # among the last two sends.
    assert any("sparky-manager" in s[1] for s in sender.sent[-2:])


# ---------------------------------------------------------------------------
# Webhook route (TestClient, stubbed Telegram sends)
# ---------------------------------------------------------------------------


@pytest.fixture()
def webhook_calls(monkeypatch):
    """Capture TelegramSender's Bot API calls during webhook tests."""
    calls = {"sent": [], "edited": [], "answered": []}
    monkeypatch.setattr(
        telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: calls["sent"].append(
            (token, chat_id, text, kw.get("reply_markup"))) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "edit_message_text",
        lambda token, chat_id, mid, text, **kw: calls["edited"].append(
            (token, chat_id, mid, text)) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "answer_callback_query",
        lambda token, qid, text=None, **kw: calls["answered"].append(
            (token, qid, text)) or True,
    )
    return calls


def test_webhook_unconfigured_404(test_client, db):
    resp = test_client.post(f"/telegram/webhook/{SECRET}", json=_message("/start"))
    assert resp.status_code == 404


def test_webhook_no_secret_stored_404(test_client, db):
    _configure_bot(db, secret=None)
    resp = test_client.post(f"/telegram/webhook/{SECRET}", json=_message("/start"))
    assert resp.status_code == 404


def test_webhook_wrong_secret_404(test_client, db):
    _configure_bot(db)
    resp = test_client.post("/telegram/webhook/wrong-secret", json=_message("/start"))
    assert resp.status_code == 404


# (No "bot module missing" webhook test: since the Phase 5 import
# cleanup app.bot is a plain import — a failed import fails the
# panel at startup instead of 404ing the webhook.)
def test_webhook_admin_start_delivers(test_client, db, webhook_calls):
    _configure_bot(db)
    resp = test_client.post(f"/telegram/webhook/{SECRET}", json=_message("/start"))
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # /start sends welcome + reply-keyboard hint.
    assert len(webhook_calls["sent"]) == 2
    token, chat_id, text, markup = webhook_calls["sent"][0]
    assert token == TOKEN
    assert chat_id == str(ADMIN_CHAT)
    assert "sparky-manager" in text


def test_webhook_stranger_update_200_but_silent(test_client, db, webhook_calls):
    _configure_bot(db)
    resp = test_client.post(
        f"/telegram/webhook/{SECRET}", json=_message("/start", chat_id=OTHER_CHAT)
    )
    assert resp.status_code == 200
    assert webhook_calls["sent"] == []


def test_webhook_malformed_body_200_no_retry_storm(test_client, db, webhook_calls):
    _configure_bot(db)
    resp = test_client.post(
        f"/telegram/webhook/{SECRET}",
        content="{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    resp = test_client.post(f"/telegram/webhook/{SECRET}", json=["not", "a", "dict"])
    assert resp.status_code == 200
    assert webhook_calls["sent"] == []


def test_webhook_callback_roundtrip(test_client, db, webhook_calls):
    _configure_bot(db)
    resp = test_client.post(
        f"/telegram/webhook/{SECRET}", json=_callback("m:users")
    )
    assert resp.status_code == 200
    assert len(webhook_calls["edited"]) == 1
    assert "کاربران" in webhook_calls["edited"][0][3]
    assert len(webhook_calls["answered"]) == 1


@pytest.fixture()
def mounted_client(db, tmp_path, monkeypatch):
    """A TestClient for the panel mounted under /k7x9q2 (logged out)."""
    monkeypatch.setattr(main_mod, "XRAY_CONFIG_PATH", str(tmp_path / "xray.json"))
    monkeypatch.setattr(main_mod, "SINGBOX_CONFIG_PATH", str(tmp_path / "singbox.json"))
    monkeypatch.setattr(main_mod, "WG_CONFIG_PATH", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    ensure_defaults(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    # WEB_PATH lives in app.webcommon now (Phase 5 split); patch the
    # canonical location so templates/redirects render the prefix.
    monkeypatch.setattr(webcommon, "WEB_PATH", "/k7x9q2")
    mounted = main_mod._mount_web_path(main_mod.app, "/k7x9q2")
    return TestClient(mounted)


def test_webhook_respects_web_prefix(mounted_client, db, webhook_calls):
    _configure_bot(db)
    # Root path: hidden (404) like every other panel route.
    resp = mounted_client.post(f"/telegram/webhook/{SECRET}", json=_message("/start"))
    assert resp.status_code == 404
    # Under the prefix: served.
    resp = mounted_client.post(
        f"/k7x9q2/telegram/webhook/{SECRET}", json=_message("/start")
    )
    assert resp.status_code == 200
    assert len(webhook_calls["sent"]) == 2


# ---------------------------------------------------------------------------
# Settings routes — webhook register / status
# ---------------------------------------------------------------------------


def test_register_webhook_success(authed_client, db, monkeypatch):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", "panel.example.com")
    called: list = []

    def _set_webhook(token, url, **kw):
        called.append((token, url))
        return True, ""

    monkeypatch.setattr(telegram_mod, "set_webhook", _set_webhook)
    resp = authed_client.post("/settings/telegram-webhook", follow_redirects=False)
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    assert len(called) == 1
    token, url = called[0]
    assert token == TOKEN
    assert url == (
        f"https://panel.example.com:2053/telegram/webhook/{SECRET}"
    )
    assert main_mod.get_setting(db, "telegram_webhook_url") == url
    assert main_mod.get_setting(db, "telegram_webhook_registered_at") != ""
    assert len(_audit_actions(db, "telegram.webhook_register")) == 1


def test_register_webhook_needs_domain(authed_client, db, monkeypatch):
    _configure_bot(db)
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append(url) or (True, ""),
    )
    resp = authed_client.post("/settings/telegram-webhook", follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert called == []


def test_register_webhook_needs_telegram_configured(authed_client, db):
    resp = authed_client.post("/settings/telegram-webhook", follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_register_webhook_failure_surfaces_error_and_port_warning(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", "panel.example.com")
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: (False, "Bad Request: bad webhook"),
    )
    # English, so the port warning's digits are Latin in the URL.
    authed_client.cookies.set("lang", "en")
    resp = authed_client.post("/settings/telegram-webhook", follow_redirects=False)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "err=" in location
    # Telegram's error text is in the redirect; the test panel port
    # (2053) is not a webhook port, so the warning is appended too.
    assert "bad+webhook" in location or "bad%20webhook" in location
    assert "8443" in location


def test_register_webhook_redacts_secret_from_error(authed_client, db, monkeypatch):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", "panel.example.com")
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: (False, f"bad url {SECRET}"),
    )
    resp = authed_client.post("/settings/telegram-webhook", follow_redirects=False)
    assert SECRET not in resp.headers["location"]
    assert "•" in resp.headers["location"] or "%E2%80%A2" in resp.headers["location"]


def test_refresh_webhook_status(authed_client, db, monkeypatch):
    _configure_bot(db)
    info = {
        "url": f"https://panel.example.com/telegram/webhook/{SECRET}",
        "pending_update_count": 2,
        "last_error_message": "Wrong response from the webhook: 500",
        "last_error_date": 1793000000,
    }
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info", lambda token, **kw: info
    )
    resp = authed_client.post(
        "/settings/telegram-webhook-status", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    stored = json.loads(main_mod.get_setting(db, "telegram_webhook_info"))
    assert stored["pending_update_count"] == 2
    assert stored["last_error_message"] == "Wrong response from the webhook: 500"


def test_refresh_webhook_status_failure(authed_client, db, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(telegram_mod, "get_webhook_info", lambda token, **kw: None)
    resp = authed_client.post(
        "/settings/telegram-webhook-status", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_settings_page_shows_masked_webhook_url(authed_client, db):
    _configure_bot(db)
    url = f"https://panel.example.com:2053/telegram/webhook/{SECRET}"
    main_mod.set_setting(db, "telegram_webhook_url", url)
    main_mod.set_setting(db, "telegram_webhook_registered_at", "2026-11-15T08:00:00")
    main_mod.set_setting(
        db, "telegram_webhook_info",
        json.dumps({"pending_update_count": 0}),
    )
    page = authed_client.get("/settings")
    assert page.status_code == 200
    # The full secret and token never appear; the masked URL does.
    assert SECRET not in page.text
    assert TOKEN not in page.text
    assert "••••" + SECRET[-4:] in page.text
    assert "2026-11-15T08:00:00" in page.text
    assert "telegram-webhook" in page.text


def test_settings_page_without_webhook_shows_not_registered(authed_client, db):
    _configure_bot(db)
    page = authed_client.get("/settings")
    assert page.status_code == 200
    assert "ثبت نشده" in page.text


# ---------------------------------------------------------------------------
# Webhook helpers — secret, public URL, masking
# ---------------------------------------------------------------------------


def test_ensure_webhook_secret_generated_once(db):
    first = main_mod._ensure_webhook_secret(db)
    assert len(first) >= 32
    assert main_mod._ensure_webhook_secret(db) == first
    # Deleting the row rotates the secret on next use.
    db.query(Setting).filter(Setting.key == "telegram_webhook_secret").delete()
    db.commit()
    assert main_mod._ensure_webhook_secret(db) != first


def test_public_panel_url(db, monkeypatch):
    monkeypatch.setattr(main_mod, "WEB_PATH", "")
    monkeypatch.setattr(main_mod, "PANEL_PORT", 2053)
    assert main_mod._public_panel_url({}) is None
    assert main_mod._public_panel_url({"domain": ""}) is None
    assert main_mod._public_panel_url({"domain": "panel.example.com"}) == (
        "https://panel.example.com:2053"
    )
    assert main_mod._public_panel_url(
        {"domain": "panel.example.com"}, "/telegram/webhook/s3cr3t"
    ) == "https://panel.example.com:2053/telegram/webhook/s3cr3t"
    # A scheme the admin typed is stripped.
    assert main_mod._public_panel_url({"domain": "https://panel.example.com/"}) == (
        "https://panel.example.com:2053"
    )
    # Port 443 is omitted; a port in the domain is respected.
    monkeypatch.setattr(main_mod, "PANEL_PORT", 443)
    assert main_mod._public_panel_url({"domain": "panel.example.com"}) == (
        "https://panel.example.com"
    )
    monkeypatch.setattr(main_mod, "PANEL_PORT", 2053)
    assert main_mod._public_panel_url({"domain": "panel.example.com:8443"}) == (
        "https://panel.example.com:8443"
    )
    # The web prefix is included.
    monkeypatch.setattr(main_mod, "WEB_PATH", "/k7x9q2")
    assert main_mod._public_panel_url({"domain": "panel.example.com"}, "/x") == (
        "https://panel.example.com:2053/k7x9q2/x"
    )


def test_mask_webhook_url():
    url = f"https://panel.example.com/telegram/webhook/{SECRET}"
    masked = main_mod._mask_webhook_url(url)
    assert SECRET not in masked
    assert masked.endswith("••••" + SECRET[-4:])
    assert masked.startswith("https://panel.example.com/telegram/webhook/")
    assert main_mod._mask_webhook_url("") == ""
    assert main_mod._mask_webhook_url("https://x/y") == "https://x/y"
