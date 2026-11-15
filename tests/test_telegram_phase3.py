"""Professional upgrade, Phase 3 tests — Telegram rework.

Covers: polling as the default transport; setMyCommands + the new
commands (/menu /status /users /inbounds); the persisted polling
offset + single-worker guard + polling diagnostics; user search and
guided user edit; the guided inbound-create flow + inbound delete;
service status/restart via the bot; backup delivery as a document;
stale-callback handling; the settings-page Telegram diagnostics
section + the register-commands / refresh-identity actions; and the
security re-verification (a stranger gets nothing from the new
commands and callbacks).

No real network anywhere: Bot API helpers are tested with a fake
httpx.post, bot handlers with fake updates + the shared FakeSender,
the polling loop with get_updates / handle_update stubbed, and the
web routes with set_my_commands / get_me stubbed.
"""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.db import SessionLocal
from app.models import AuditLog, Client, Inbound, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.test_telegram_bot import (
    ADMIN_CHAT,
    OTHER_CHAT,
    SECRET,
    TOKEN,
    FakeSender,
    _button_data,
    _callback,
    _configure_bot,
    _dispatch,
    _message,
)

FIXED_NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)

NEW_WEB_KEYS = (
    "telegram_diag",
    "telegram_diag_mode",
    "telegram_diag_bot",
    "telegram_diag_chat",
    "telegram_diag_commands_registered",
    "telegram_diag_polling_last_poll",
    "telegram_diag_polling_last_update",
    "telegram_diag_polling_last_error",
    "telegram_diag_polling_offset",
    "telegram_diag_never",
    "telegram_diag_identity_unknown",
    "telegram_commands_register",
    "telegram_commands_registered",
    "telegram_commands_failed",
    "telegram_identity_refresh",
    "telegram_identity_ok",
    "telegram_identity_failed",
)


@pytest.fixture(autouse=True)
def _reset_polling_flag():
    """The single-worker flag must not leak between loop tests."""
    main_mod._polling_loop_active = False
    yield
    main_mod._polling_loop_active = False


@pytest.fixture()
def sender():
    return FakeSender()


@pytest.fixture()
def rerender_stub(monkeypatch):
    """Record rerender_configs calls (the bot must call it after
    every state change, like the web routes do)."""
    calls: list = []

    def _stub(db):
        calls.append(True)
        return []

    monkeypatch.setattr(main_mod, "rerender_configs", _stub)
    return calls


def _fake_httpx_post(calls, status_code=200, payload=None):
    """Fake httpx.post accepting json/data/files kwargs."""

    def _post(url, json=None, data=None, files=None, timeout=None):
        calls.append(
            {"url": url, "json": json, "data": data, "files": files,
             "timeout": timeout}
        )
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )

    return _post


# ---------------------------------------------------------------------------
# i18n contract — every new web key exists in both languages
# ---------------------------------------------------------------------------


def test_new_web_keys_exist_in_both_languages():
    for key in NEW_WEB_KEYS:
        assert key in main_mod.STRINGS["fa"], f"missing fa key: {key}"
        assert key in main_mod.STRINGS["en"], f"missing en key: {key}"


# ---------------------------------------------------------------------------
# telegram.py — set_my_commands / get_me / send_document (fake httpx)
# ---------------------------------------------------------------------------


def test_set_my_commands_success(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    commands = [
        {"command": "start", "description": "منوی اصلی"},
        {"command": "cancel", "description": "لغو"},
    ]
    assert telegram_mod.set_my_commands("tok", commands) == (True, "")
    assert calls[0]["url"] == "https://api.telegram.org/bottok/setMyCommands"
    assert calls[0]["json"] == {"commands": commands}


def test_set_my_commands_api_error_returns_description(monkeypatch):
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(
            [], payload={"ok": False, "description": "Bad Request: bad command"}
        ),
    )
    ok, err = telegram_mod.set_my_commands("tok", [{"command": "x"}])
    assert ok is False
    assert err == "Bad Request: bad command"


def test_set_my_commands_failures(monkeypatch):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    assert telegram_mod.set_my_commands("tok", [{"command": "x"}]) == (False, "")
    # Empty token or empty command list never reaches the network.
    assert telegram_mod.set_my_commands("", [{"command": "x"}]) == (False, "")
    assert telegram_mod.set_my_commands("tok", []) == (False, "")


def test_get_me_success(monkeypatch):
    result = {"id": 123, "username": "mybot", "first_name": "My Bot"}
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post([], payload={"ok": True, "result": result}),
    )
    assert telegram_mod.get_me("tok") == result


def test_get_me_failures(monkeypatch):
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post([], payload={"ok": False})
    )
    assert telegram_mod.get_me("tok") is None
    assert telegram_mod.get_me("") is None
    assert telegram_mod.get_me("   ") is None


def test_send_document_success(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    data = b"PK\x03\x04fake-zip"
    assert telegram_mod.send_document("tok", "42", "backup.zip", data) is True
    assert calls[0]["url"] == "https://api.telegram.org/bottok/sendDocument"
    assert calls[0]["data"] == {"chat_id": "42"}
    name, payload, content_type = calls[0]["files"]["document"]
    assert name == "backup.zip"
    assert payload == data
    assert content_type == "application/zip"


def test_send_document_too_large_refused_without_network(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    big = b"x" * (telegram_mod.MAX_DOCUMENT_BYTES + 1)
    assert telegram_mod.send_document("tok", "42", "big.zip", big) is False
    assert calls == []


def test_send_document_failures(monkeypatch):
    calls: list = []

    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    assert telegram_mod.send_document("tok", "42", "b.zip", b"data") is False
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, status_code=500)
    )
    assert telegram_mod.send_document("tok", "42", "b.zip", b"data") is False
    # Missing arguments never reach the network.
    before = len(calls)
    assert telegram_mod.send_document("", "42", "b.zip", b"data") is False
    assert telegram_mod.send_document("tok", "", "b.zip", b"data") is False
    assert telegram_mod.send_document("tok", "42", "", b"data") is False
    assert telegram_mod.send_document("tok", "42", "b.zip", b"") is False
    assert len(calls) == before


def test_phase3_helpers_never_log_the_token(monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise ConnectionError("dns down")

    monkeypatch.setattr("httpx.post", _boom)
    telegram_mod.get_me("tok123")
    telegram_mod.set_my_commands("tok123", [{"command": "x"}])
    telegram_mod.send_document("tok123", "42", "b.zip", b"data")
    assert "tok123" not in caplog.text


# ---------------------------------------------------------------------------
# Polling is the default transport
# ---------------------------------------------------------------------------


def test_transport_default_is_polling():
    assert main_mod.TELEGRAM_TRANSPORT_DEFAULT == "polling"
    assert "polling" in main_mod.TELEGRAM_TRANSPORTS
    assert "webhook" in main_mod.TELEGRAM_TRANSPORTS


def test_explicit_webhook_choice_preserved_on_save(
    authed_client, db, monkeypatch
):
    """An install that explicitly chose webhook keeps it: saving the
    settings form without a transport value does not reset it."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])
    resp = authed_client.post(
        "/settings",
        data={"telegram_chat_id": str(ADMIN_CHAT)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert main_mod.get_setting(db, "telegram_transport") == "webhook"


# ---------------------------------------------------------------------------
# Commands — /menu /status /users /inbounds (+ the setMyCommands list)
# ---------------------------------------------------------------------------


def test_bot_commands_list_matches_implemented_commands():
    commands = [c["command"] for c in bot_mod.BOT_COMMANDS]
    assert commands == [
        "start", "help", "menu", "status", "users", "inbounds", "cancel",
    ]
    for entry in bot_mod.BOT_COMMANDS:
        assert entry["description"], f"empty description: {entry}"


def test_menu_command_shows_main_menu(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/menu"), sender)
    assert len(sender.sent) == 2
    text, markup = sender.sent[0][1], sender.sent[0][2]
    assert "sparky-manager" in text
    data = _button_data(markup)
    assert "m:users" in data and "m:inb" in data
    assert "m:svc" in data and "m:bkp" in data  # services + backup


def test_status_command(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/status"), sender)
    assert len(sender.sent) == 1
    assert "وضعیت سرور" in sender.sent[0][1]


def test_users_command(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/users"), sender)
    assert len(sender.sent) == 1
    assert "کاربران" in sender.sent[0][1]
    assert "alice" in sender.sent[0][1]


def test_inbounds_command(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/inbounds"), sender)
    assert len(sender.sent) == 1
    assert "اینباندها" in sender.sent[0][1]
    assert "vless-reality" in sender.sent[0][1]


def test_help_lists_new_commands(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/help"), sender)
    text = sender.sent[0][1]
    for cmd in ("/menu", "/status", "/users", "/inbounds"):
        assert cmd in text


def test_stranger_gets_nothing_from_new_commands(db, sender):
    _configure_bot(db)
    for cmd in ("/menu", "/status", "/users", "/inbounds"):
        _dispatch(db, _message(cmd, chat_id=OTHER_CHAT), sender)
    assert sender.sent == []
    assert sender.edited == []
    assert sender.answered == []


# ---------------------------------------------------------------------------
# Polling loop — persisted offset, single worker, diagnostics
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


def test_loop_polls_when_transport_unset(db, monkeypatch, fast_loop):
    """The default is polling: a configured bot with no transport
    setting polls (no explicit choice needed)."""
    _configure_bot(db)
    polls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_updates",
        lambda *a, **kw: polls.append(True) or [],
    )
    _run_loop(0.3)
    assert polls


def test_loop_persists_offset(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    batch = [_message("/start", update_id=101), _message("/help", update_id=105)]
    calls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        calls.append(offset)
        return list(batch) if len(calls) == 1 else []

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", lambda *a, **kw: None)
    _run_loop()
    # The offset survives in the settings table (max id + 1).
    assert main_mod.get_setting(db, "telegram_polling_offset") == "106"


def test_loop_resumes_from_persisted_offset(db, monkeypatch, fast_loop):
    """A restart resumes where the loop left off — no re-fetch of
    already-processed updates."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    main_mod.set_setting(db, "telegram_polling_offset", "500")
    offsets: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        offsets.append(offset)
        return []

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    _run_loop(0.3)
    assert offsets and offsets[0] == 500


def test_loop_offset_persisted_even_when_dispatch_fails(
    db, monkeypatch, fast_loop
):
    """A failed dispatch still advances the persisted offset:
    Telegram considers the update delivered, and re-fetching it
    after a restart would re-run the failed action."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    update = _message("/start", update_id=77)
    calls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        calls.append(True)
        return [update] if len(calls) == 1 else []

    def _handle_update(*args, **kwargs):
        raise RuntimeError("dispatch boom")

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", _handle_update)
    _run_loop()
    assert main_mod.get_setting(db, "telegram_polling_offset") == "78"


def test_loop_records_polling_status(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    update = _message("/start", update_id=201)
    calls: list = []

    def _get_updates(token, offset=None, timeout=30.0):
        calls.append(True)
        return [update] if len(calls) == 1 else []

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    monkeypatch.setattr(bot_mod, "handle_update", lambda *a, **kw: None)
    _run_loop()
    last_poll = main_mod.get_setting(db, "telegram_polling_last_poll")
    last_update = main_mod.get_setting(db, "telegram_polling_last_update")
    assert last_poll, "last poll was not recorded"
    assert last_update, "last update was not recorded"
    # Both are ISO timestamps from today.
    assert last_poll.startswith("2026-11-15")
    assert last_update.startswith("2026-11-15")


def test_loop_records_polling_error_on_fast_empty(db, monkeypatch, fast_loop):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")

    def _get_updates(token, offset=None, timeout=30.0):
        raise RuntimeError("telegram down")

    monkeypatch.setattr(telegram_mod, "get_updates", _get_updates)
    _run_loop()
    last_error = main_mod.get_setting(db, "telegram_polling_last_error")
    assert last_error, "last error was not recorded"
    assert "getUpdates failed" in last_error


def test_single_polling_worker(db, monkeypatch, fast_loop):
    """Two concurrent loop starts poll exactly once: the second
    invocation returns immediately, and the flag clears on
    shutdown so a later start is allowed."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    polls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_updates",
        lambda *a, **kw: polls.append(True) or [],
    )

    async def _run():
        task1 = asyncio.create_task(main_mod._telegram_polling_loop())
        await asyncio.sleep(0.15)
        assert main_mod._polling_loop_active is True
        # A second worker refuses to start (returns at once).
        task2 = asyncio.create_task(main_mod._telegram_polling_loop())
        await asyncio.wait_for(task2, timeout=1.0)
        assert main_mod._polling_loop_active is True
        task1.cancel()
        try:
            await task1
        except asyncio.CancelledError:
            pass
        assert main_mod._polling_loop_active is False

    asyncio.run(_run())
    assert polls  # the first worker did poll


# ---------------------------------------------------------------------------
# User search
# ---------------------------------------------------------------------------


def _search(db, sender, query, seeded=None):
    _dispatch(db, _callback("u:search"), sender)
    _dispatch(db, _message(query), sender)


def test_user_search_by_name(db, sender, seeded):
    _configure_bot(db)
    _search(db, sender, "ali")
    assert sender.sent, "no search results sent"
    text = sender.sent[-1][1]
    assert "alice" in text
    assert "bob" not in text
    assert "نتایج جستجو" in text


def test_user_search_by_note(db, sender, seeded):
    _configure_bot(db)
    bob = seeded["users"]["bob"]
    bob.note = "test-note-xyz"
    db.commit()
    _search(db, sender, "xyz")
    assert "bob" in sender.sent[-1][1]
    assert "alice" not in sender.sent[-1][1]


def test_user_search_case_insensitive(db, sender, seeded):
    _configure_bot(db)
    _search(db, sender, "ALICE")
    assert "alice" in sender.sent[-1][1]


def test_user_search_no_match(db, sender, seeded):
    _configure_bot(db)
    _search(db, sender, "zzz-no-such-user")
    assert "پیدا نشد" in sender.sent[-1][1]


def test_user_search_pagination_keeps_query(db, sender):
    _configure_bot(db)
    for i in range(10):
        db.add(User(name=f"quser{i}", sub_token=f"tok-{i}"))
    db.commit()
    _search(db, sender, "quser")
    assert "صفحه 1 از 2" in sender.sent[-1][1]
    # Next page: still filtered by the same query.
    _dispatch(db, _callback("u:list:1"), sender)
    assert sender.edited, "pagination did not edit the message"
    text = sender.edited[-1][2]
    assert "quser" in text and "صفحه 2 از 2" in text
    assert "alice" not in text


def test_user_search_empty_query_shows_all(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("u:search"), sender)
    _dispatch(db, _message("   "), sender)
    assert "alice" in sender.sent[-1][1]
    assert "نتایج جستجو" not in sender.sent[-1][1]


def test_search_button_present_in_users_list(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/users"), sender)
    assert "u:search" in _button_data(sender.sent[0][2])


# ---------------------------------------------------------------------------
# User edit
# ---------------------------------------------------------------------------


def _open_edit(db, sender, user_id, field):
    _dispatch(db, _callback(f"u:edit:{user_id}"), sender)
    _dispatch(db, _callback(f"u:edit:{user_id}:{field}"), sender)


def test_user_edit_menu_buttons(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:edit:{alice.id}"), sender)
    data = _button_data(sender.edited[-1][3])
    assert f"u:edit:{alice.id}:name" in data
    assert f"u:edit:{alice.id}:limit" in data
    assert f"u:edit:{alice.id}:expiry" in data


def test_user_edit_name(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "name")
    _dispatch(db, _message("alice2"), sender, now=FIXED_NOW)
    db.expire_all()
    assert db.get(User, alice.id).name == "alice2"
    assert rerender_stub, "edit must re-render configs"
    assert (
        db.query(AuditLog).filter(AuditLog.action == "user.update").count()
        == 1
    )
    assert "ویرایش انجام شد" in sender.sent[-1][1]


def test_user_edit_name_invalid(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "name")
    _dispatch(db, _message("bad name!"), sender)
    db.expire_all()
    assert db.get(User, alice.id).name == "alice"
    assert rerender_stub == []
    assert "معتبر نیست" in sender.sent[-1][1]
    # The flow stays open: a retry works.
    _dispatch(db, _message("alice2"), sender)
    db.expire_all()
    assert db.get(User, alice.id).name == "alice2"


def test_user_edit_name_exists(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "name")
    _dispatch(db, _message("bob"), sender)
    db.expire_all()
    assert db.get(User, alice.id).name == "alice"
    assert "این نام هست" in sender.sent[-1][1]


def test_user_edit_limit(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "limit")
    _dispatch(db, _message("10"), sender)
    db.expire_all()
    assert db.get(User, alice.id).traffic_limit_bytes == 10 * 1024**3
    assert rerender_stub


def test_user_edit_limit_unlimited(db, sender, seeded):
    _configure_bot(db)
    carol = seeded["users"]["carol"]
    assert carol.traffic_limit_bytes is not None
    _open_edit(db, sender, carol.id, "limit")
    _dispatch(db, _message("0"), sender)
    db.expire_all()
    assert db.get(User, carol.id).traffic_limit_bytes is None


def test_user_edit_limit_invalid(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "limit")
    _dispatch(db, _message("abc"), sender)
    db.expire_all()
    assert db.get(User, alice.id).traffic_limit_bytes is None
    assert "معتبر نیست" in sender.sent[-1][1]


def test_user_edit_expiry(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "expiry")
    _dispatch(db, _message("30"), sender, now=FIXED_NOW)
    db.expire_all()
    expires = db.get(User, alice.id).expires_at
    assert expires is not None
    assert expires.replace(tzinfo=timezone.utc) == FIXED_NOW + timedelta(days=30)


def test_user_edit_expiry_never(db, sender, seeded):
    _configure_bot(db)
    bob = seeded["users"]["bob"]
    assert bob.expires_at is not None
    _open_edit(db, sender, bob.id, "expiry")
    _dispatch(db, _message("0"), sender)
    db.expire_all()
    assert db.get(User, bob.id).expires_at is None


def test_user_edit_expiry_invalid(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "expiry")
    _dispatch(db, _message("-5"), sender)
    db.expire_all()
    assert db.get(User, alice.id).expires_at is None
    assert "معتبر نیست" in sender.sent[-1][1]


def test_user_edit_missing_user(db, sender, seeded):
    """The user is deleted mid-flow: the bot says so, never crashes."""
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _open_edit(db, sender, alice.id, "name")
    db.delete(alice)
    db.commit()
    _dispatch(db, _message("alice2"), sender)  # must not raise
    assert "پیدا نشد" in sender.sent[-1][1]


# ---------------------------------------------------------------------------
# Inbound create + delete
# ---------------------------------------------------------------------------


def test_inbound_create_protocol_picker(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new"), sender)
    data = _button_data(sender.edited[-1][3])
    for protocol in ("vless", "vmess", "trojan", "shadowsocks", "wireguard"):
        assert f"i:new:{protocol}" in data
    # Protocols the flow cannot configure are NOT offered.
    assert "i:new:hysteria2" not in data
    assert "i:new:ikev2" not in data


def test_inbound_create_vless_full_flow(db, sender, rerender_stub):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vless"), sender)
    _dispatch(db, _message(""), sender)  # auto port
    _dispatch(db, _message(""), sender)  # default SNI
    inbound = db.query(Inbound).filter(Inbound.protocol == "vless").all()
    # The seeded "vless-reality" inbound is not the created one.
    created = [i for i in inbound if i.tag != "vless-reality"]
    assert len(created) == 1
    assert created[0].core == "xray"
    assert created[0].enabled is True
    stream = json.loads(created[0].stream_json)
    assert stream["security"] == "reality"
    assert stream["reality"]["private_key"]
    assert stream["reality"]["public_key"]
    assert stream["reality"]["short_id"]
    assert stream["tls"]["sni"] == "www.microsoft.com"
    assert rerender_stub
    assert (
        db.query(AuditLog).filter(AuditLog.action == "inbound.create").count()
        == 1
    )
    assert "ساخته شد" in sender.sent[-1][1]


def test_inbound_create_vmess_with_sni(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vmess"), sender)
    _dispatch(db, _message("18001"), sender)
    _dispatch(db, _message("example.com"), sender)
    created = db.query(Inbound).filter(Inbound.port == 18001).first()
    assert created is not None
    assert created.protocol == "vmess"
    stream = json.loads(created.stream_json)
    assert stream["security"] == "tls"
    assert stream["tls"]["sni"] == "example.com"


def test_inbound_create_trojan(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:trojan"), sender)
    _dispatch(db, _message("18002"), sender)
    _dispatch(db, _message(""), sender)
    created = db.query(Inbound).filter(Inbound.port == 18002).first()
    assert created is not None and created.protocol == "trojan"


def test_inbound_create_shadowsocks_skips_sni(db, sender):
    """Shadowsocks has no TLS/SNI step — it is created right after
    the port (the next message is the done message, not an SNI
    prompt)."""
    _configure_bot(db)
    _dispatch(db, _callback("i:new:shadowsocks"), sender)
    before = len(sender.sent)
    _dispatch(db, _message("18003"), sender)
    assert len(sender.sent) == before + 1
    assert "ساخته شد" in sender.sent[-1][1]
    created = db.query(Inbound).filter(Inbound.port == 18003).first()
    assert created is not None and created.protocol == "shadowsocks"


def test_inbound_create_wireguard(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:wireguard"), sender)
    _dispatch(db, _message("18004"), sender)
    created = db.query(Inbound).filter(Inbound.port == 18004).first()
    assert created is not None
    assert created.core == "wireguard"
    assert created.protocol == "wireguard"
    stream = json.loads(created.stream_json)
    assert stream["subnet"] == "10.8.0.0/24"


def test_inbound_create_port_in_use(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vless"), sender)
    _dispatch(db, _message("443"), sender)  # seeded VLESS-Reality, TCP 443
    assert "استفاده شده" in sender.sent[-1][1]
    assert db.query(Inbound).filter(Inbound.port == 443).count() == 2
    # The flow stays open: a retry with a free port works.
    _dispatch(db, _message("18005"), sender)
    _dispatch(db, _message(""), sender)
    assert db.query(Inbound).filter(Inbound.port == 18005).first() is not None


def test_inbound_create_port_invalid(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vmess"), sender)
    _dispatch(db, _message("abc"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    _dispatch(db, _message("70000"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    assert db.query(Inbound).filter(Inbound.protocol == "vmess").count() == 2


def test_inbound_create_port_reserved(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:trojan"), sender)
    _dispatch(db, _message("4500"), sender)  # IKEv2-reserved
    assert "رزرو" in sender.sent[-1][1]


def test_inbound_create_invalid_protocol_shows_stale(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new:hysteria2"), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


def test_inbound_delete_with_confirmation(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    inbound = seeded["inbounds"]["trojan-tls"]
    _dispatch(db, _callback(f"i:v:{inbound.id}"), sender)
    _dispatch(db, _callback(f"i:del:{inbound.id}"), sender)
    assert "حذف شود" in sender.edited[-1][2]
    _dispatch(db, _callback(f"i:del:{inbound.id}:ok"), sender)
    assert db.get(Inbound, inbound.id) is None
    assert (
        db.query(Client).filter(Client.inbound_id == inbound.id).count() == 0
    )
    assert rerender_stub
    assert (
        db.query(AuditLog).filter(AuditLog.action == "inbound.delete").count()
        == 1
    )


def test_inbound_delete_cancel(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    inbound = seeded["inbounds"]["trojan-tls"]
    _dispatch(db, _callback(f"i:del:{inbound.id}"), sender)
    _dispatch(db, _callback(f"i:v:{inbound.id}"), sender)  # "No" goes back
    assert db.get(Inbound, inbound.id) is not None
    assert rerender_stub == []


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_status(monkeypatch):
    """Stub app.system_status inside the bot (deterministic states)."""
    states = {
        "xray": "running",
        "sing-box": "running",
        "wireguard": "stopped",
        "amneziawg": "running",
        "openvpn": "unknown",
        "openconnect": "running",
        "ikev2": "stopped",
    }
    stub = SimpleNamespace(
        collect_server_status=lambda data_dir: {"services": dict(states)},
    )
    monkeypatch.setattr(bot_mod, "system_status_mod", stub)
    return states


def test_services_view_shows_statuses_and_restart_buttons(
    db, sender, fake_status
):
    _configure_bot(db)
    _dispatch(db, _callback("m:svc"), sender)
    text = sender.edited[-1][2]
    assert "سرویس‌ها" in text
    assert "Xray" in text and "WireGuard" in text
    assert "در حال اجرا" in text and "متوقف" in text
    data = _button_data(sender.edited[-1][3])
    for key in ("xray", "sing-box", "wireguard", "openvpn", "openconnect", "ikev2"):
        assert f"s:rst:{key}" in data
    # AmneziaWG has no restart button (no sudoers entry) — and the
    # view says so.
    assert "s:rst:amneziawg" not in data
    assert "AmneziaWG" in text


def test_service_restart_success(db, sender, fake_status, monkeypatch):
    _configure_bot(db)
    restarted: list = []
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: restarted.append(name) or None,
    )
    _dispatch(db, _callback("s:rst:xray"), sender)
    assert "ریستارت شود" in sender.edited[-1][2]
    _dispatch(db, _callback("s:rst:xray:ok"), sender)
    assert restarted == ["xray"]
    assert "ریستارت شد" in sender.edited[-1][2]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "service.restart").count()
        == 1
    )


def test_service_restart_failure(db, sender, fake_status, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: "restart of xray failed: exit 1",
    )
    _dispatch(db, _callback("s:rst:xray:ok"), sender)
    assert "ناموفق بود" in sender.edited[-1][2]
    assert "exit 1" in sender.edited[-1][2]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "service.restart").count()
        == 0
    )


def test_service_restart_stopped_after(db, sender, fake_status, monkeypatch):
    """The restart command succeeds but the service stays stopped —
    that is a failure, not a success."""
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    fake_status["wireguard"] = "stopped"  # still stopped after restart
    _dispatch(db, _callback("s:rst:wireguard:ok"), sender)
    assert "ناموفق بود" in sender.edited[-1][2]


def test_service_restart_unverified(db, sender, fake_status, monkeypatch):
    """The restart command succeeds but the state is unobservable —
    the bot says so honestly instead of claiming success."""
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    _dispatch(db, _callback("s:rst:openvpn:ok"), sender)
    assert "قابل بررسی نیست" in sender.edited[-1][2]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "service.restart").count()
        == 1
    )


def test_service_restart_amneziawg_refused(db, sender, monkeypatch):
    _configure_bot(db)
    restarted: list = []
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: restarted.append(name) or None,
    )
    _dispatch(db, _callback("s:rst:amneziawg:ok"), sender)
    assert restarted == []
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


def test_service_restart_cancel(db, sender, fake_status, monkeypatch):
    _configure_bot(db)
    restarted: list = []
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: restarted.append(name) or None,
    )
    _dispatch(db, _callback("s:rst:xray"), sender)
    _dispatch(db, _callback("s:list"), sender)  # "No" goes back
    assert restarted == []
    assert "سرویس‌ها" in sender.edited[-1][2]


# ---------------------------------------------------------------------------
# Backup via bot
# ---------------------------------------------------------------------------


def test_backup_view(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("m:bkp"), sender)
    text = sender.edited[-1][2]
    assert "بکاپ" in text
    assert "کلید خصوصی" in text
    assert "b:get" in _button_data(sender.edited[-1][3])


def test_backup_send_success(db, sender, db_engine):
    _configure_bot(db)
    _dispatch(db, _callback("b:get"), sender)
    assert len(sender.documents) == 1
    chat_id, filename, data = sender.documents[0]
    assert chat_id == ADMIN_CHAT  # ONLY the admin chat
    assert filename.startswith("sparky-manager-backup-")
    assert filename.endswith(".zip")
    # It is a real backup ZIP (panel.db + meta.json).
    zf = zipfile.ZipFile(io.BytesIO(data))
    assert "panel.db" in zf.namelist()
    assert "meta.json" in zf.namelist()
    assert "بکاپ فرستاده شد" in sender.edited[-1][2]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "settings.backup").count()
        == 1
    )


def test_backup_send_failure(db, monkeypatch):
    _configure_bot(db)
    sender = FakeSender(document_ok=False)
    _dispatch(db, _callback("b:get"), sender)
    # The fake records the failed attempt; what matters is the bot
    # reported the failure and did not audit a success.
    assert len(sender.documents) == 1
    assert "ناموفق بود" in sender.edited[-1][2]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "settings.backup").count()
        == 0
    )


def test_backup_too_large_refused_honestly(db, sender, monkeypatch):
    _configure_bot(db)
    # Shrink the Bot API cap so the real (small) backup exceeds it.
    monkeypatch.setattr(telegram_mod, "MAX_DOCUMENT_BYTES", 10)
    _dispatch(db, _callback("b:get"), sender)
    assert sender.documents == []
    assert "۵۰ مگابایت" in sender.edited[-1][2]


def test_backup_unavailable(db, sender, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "backup_mod", None)
    _dispatch(db, _callback("b:get"), sender)
    assert sender.documents == []
    assert "ناموفق بود" in sender.edited[-1][2]


# ---------------------------------------------------------------------------
# Stale callbacks
# ---------------------------------------------------------------------------


def test_unknown_callback_family_shows_stale(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("zz:whatever"), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]
    # The main menu is one tap away.
    assert "m:users" in _button_data(sender.edited[-1][3])


def test_empty_callback_data_shows_stale(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback(""), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


def test_malformed_user_callback_shows_stale(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("u:v:abc"), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


def test_unknown_menu_action_shows_stale(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("m:zzz"), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


# ---------------------------------------------------------------------------
# Security re-verification — a stranger gets nothing from the new handlers
# ---------------------------------------------------------------------------


def test_stranger_gets_nothing_from_new_callbacks(
    db, sender, seeded, monkeypatch, rerender_stub
):
    _configure_bot(db)
    restarted: list = []
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: restarted.append(name) or None,
    )
    inbound = seeded["inbounds"]["trojan-tls"]
    for data in (
        "u:search",
        f"u:edit:{seeded['users']['alice'].id}",
        "i:new",
        "i:new:vless",
        f"i:del:{inbound.id}:ok",
        "s:rst:xray:ok",
        "b:get",
        "m:svc",
        "m:bkp",
    ):
        _dispatch(db, _callback(data, chat_id=OTHER_CHAT), sender)
    assert sender.sent == []
    assert sender.edited == []
    assert sender.answered == []
    assert sender.documents == []
    # And nothing changed: no restart, no delete, no re-render.
    assert restarted == []
    assert db.get(Inbound, inbound.id) is not None
    assert rerender_stub == []


def test_stranger_free_text_in_flow_gets_nothing(db, sender):
    """A stranger cannot hijack the admin's in-progress flow by
    sending text: the dispatcher drops non-admin messages before
    any flow step runs."""
    _configure_bot(db)
    _dispatch(db, _callback("u:search"), sender)
    _dispatch(db, _message("alice", chat_id=OTHER_CHAT), sender)
    assert sender.sent == []


# ---------------------------------------------------------------------------
# _check_new_inbound (shared web/bot validation)
# ---------------------------------------------------------------------------


def test_check_new_inbound_codes(db, seeded):
    check = main_mod._check_new_inbound
    assert check(db, "vless", 0, "x-1", "tcp") == "invalid_port"
    assert check(db, "vless", 70000, "x-1", "tcp") == "invalid_port"
    assert check(db, "trojan", 4500, "x-1", "tcp") == "port_reserved"
    assert check(db, "ikev2", 500, "x-1", "udp") is None  # the exception
    assert check(db, "vless", 18001, "bad tag!", "tcp") == "invalid_name"
    assert check(db, "vless", 18001, "vless-reality", "tcp") == "tag_exists"
    assert check(db, "vless", 443, "fresh-tag", "tcp") == "port_in_use"
    assert check(db, "vless", 18001, "fresh-tag", "tcp") is None


# ---------------------------------------------------------------------------
# Web panel — Telegram diagnostics + register-commands / identity actions
# ---------------------------------------------------------------------------


def test_settings_page_shows_diagnostics(authed_client, db):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    main_mod.set_setting(db, "telegram_polling_last_poll", "2026-11-15T10:00:00")
    main_mod.set_setting(db, "telegram_polling_last_update", "2026-11-15T09:55:00")
    main_mod.set_setting(db, "telegram_polling_last_error", "2026-11-15T09:00:00 — boom")
    main_mod.set_setting(db, "telegram_polling_offset", "12345")
    main_mod.set_setting(
        db,
        "telegram_bot_identity",
        json.dumps({"id": 777, "username": "mybot", "first_name": "My Bot"}),
    )
    main_mod.set_setting(db, "telegram_commands_registered_at", "2026-11-15T08:00:00")
    page = authed_client.get("/settings")
    assert page.status_code == 200
    text = page.text
    assert "وضعیت اتصال تلگرام" in text
    assert "2026-11-15T10:00:00" in text  # last poll
    assert "2026-11-15T09:55:00" in text  # last update
    assert "boom" in text  # last error
    assert "12345" in text  # offset
    assert "@mybot" in text and "My Bot" in text  # bot identity
    assert str(ADMIN_CHAT) in text  # authorized chat
    assert "2026-11-15T08:00:00" in text  # commands registered at
    assert "/settings/telegram-commands" in text
    assert "/settings/telegram-identity" in text
    # The token itself is never on the page.
    assert TOKEN not in text


def test_settings_page_hides_polling_rows_on_webhook(authed_client, db, monkeypatch):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    main_mod.set_setting(db, "telegram_polling_last_poll", "2026-11-15T10:00:00")
    # The page fetches getWebhookInfo on load in webhook mode — stub
    # it so the test never touches the network.
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info", lambda token, **kw: None
    )
    page = authed_client.get("/settings")
    assert page.status_code == 200
    assert "2026-11-15T10:00:00" not in page.text
    assert "آخرین پولینگ موفق" not in page.text


def test_register_commands_route_success(authed_client, db, monkeypatch):
    _configure_bot(db)
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_my_commands",
        lambda token, cmds, **kw: called.append((token, cmds)) or (True, ""),
    )
    resp = authed_client.post(
        "/settings/telegram-commands", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    assert called[0][0] == TOKEN
    assert [c["command"] for c in called[0][1]] == [
        "start", "help", "menu", "status", "users", "inbounds", "cancel",
    ]
    assert main_mod.get_setting(db, "telegram_commands_registered_at")
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.commands_register")
        .count()
        == 1
    )


def test_register_commands_route_failure(authed_client, db, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(
        telegram_mod, "set_my_commands",
        lambda token, cmds, **kw: (False, "Bad Request: unauthorized"),
    )
    resp = authed_client.post(
        "/settings/telegram-commands", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert "unauthorized" in resp.headers["location"]
    assert main_mod.get_setting(db, "telegram_commands_registered_at") == ""


def test_register_commands_route_requires_csrf(authed_client, db):
    _configure_bot(db)
    resp = authed_client.post_raw("/settings/telegram-commands", data={})
    assert resp.status_code == 403


def test_register_commands_route_unconfigured(authed_client, db):
    resp = authed_client.post(
        "/settings/telegram-commands", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_identity_route_success(authed_client, db, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(
        telegram_mod, "get_me",
        lambda token, **kw: {
            "id": 777, "username": "mybot", "first_name": "My Bot",
            "is_bot": True,
        },
    )
    resp = authed_client.post(
        "/settings/telegram-identity", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]
    stored = json.loads(main_mod.get_setting(db, "telegram_bot_identity"))
    assert stored["id"] == 777
    assert stored["username"] == "mybot"
    assert stored["first_name"] == "My Bot"
    assert stored["fetched_at"]
    assert "is_bot" not in stored  # only the useful fields are kept
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.identity_refresh")
        .count()
        == 1
    )


def test_identity_route_failure(authed_client, db, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(telegram_mod, "get_me", lambda token, **kw: None)
    resp = authed_client.post(
        "/settings/telegram-identity", follow_redirects=False
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert main_mod.get_setting(db, "telegram_bot_identity") == ""


def test_identity_route_requires_csrf(authed_client, db):
    _configure_bot(db)
    resp = authed_client.post_raw("/settings/telegram-identity", data={})
    assert resp.status_code == 403


def test_token_save_registers_commands(authed_client, db, monkeypatch):
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_my_commands",
        lambda token, cmds, **kw: called.append((token, cmds)) or (True, ""),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_bot_token": "111:NEW-TOKEN",
            "telegram_chat_id": str(ADMIN_CHAT),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert called, "saving a token must register the command menu"
    assert called[0][0] == "111:NEW-TOKEN"
    assert main_mod.get_setting(db, "telegram_commands_registered_at")


def test_token_save_commands_failure_shown_but_token_saved(
    authed_client, db, monkeypatch
):
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])
    monkeypatch.setattr(
        telegram_mod, "set_my_commands",
        lambda token, cmds, **kw: (False, "unauthorized"),
    )
    resp = authed_client.post(
        "/settings",
        data={
            "telegram_bot_token": "111:BAD-TOKEN",
            "telegram_chat_id": str(ADMIN_CHAT),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert "unauthorized" in resp.headers["location"]
    # The settings still saved — only the registration failed.
    assert main_mod.get_setting(db, "telegram_bot_token") == "111:BAD-TOKEN"


def test_settings_save_without_token_does_not_register_commands(
    authed_client, db, monkeypatch
):
    """A save that does not submit a new token must not call
    setMyCommands (no redundant Bot API traffic on every save)."""
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_my_commands",
        lambda token, cmds, **kw: called.append(True) or (True, ""),
    )
    resp = authed_client.post(
        "/settings",
        data={"telegram_chat_id": str(ADMIN_CHAT)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert called == []
