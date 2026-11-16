"""Bot polish (Task B) — HTML formatting, escaping, the persistent
reply keyboard, and cleaner inline keyboards (presentation only).

Covers: the ``h()`` / ``_b()`` / ``_titled()`` helpers, the
``parse_mode="HTML"`` contract (telegram.py payload + TelegramSender),
the /start + /menu two-message shape and reply keyboard, label taps
(incl. abandoning an active flow, and stranger rejection), escaping
of user-controlled text in every rendered message (names with <>&,
VLESS links full of &), keyboard layouts (callback data unchanged),
toasts staying plain, and the restart-failure ``{name}`` formatting
regression.

Handlers, flows, callback data and command behavior are unchanged —
these tests pin the presentation, not new behavior.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.i18n import t_for
from app.models import User
from tests.conftest import HOST
from tests.test_telegram_bot import (
    OTHER_CHAT,
    FakeSender,
    _button_data,
    _callback,
    _configure_bot,
    _dispatch,
    _message,
    _start_flow,
)

FA = t_for("fa")
EVIL_NAME = "<b>&test"


@pytest.fixture()
def sender():
    return FakeSender()


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


def _fake_httpx_post(calls, status_code=200, payload=None):
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )

    return _post


def _assert_valid_bot_html(text: str) -> None:
    """No bare <, > or & outside the supported Telegram tags (<b> and
    <pre>) — Telegram rejects a message whose HTML is malformed, so one
    stray character fails the whole reply."""
    stripped = re.sub(r"</?(?:b|pre)>", "", text)
    assert "<" not in stripped, f"bare < in: {text!r}"
    assert ">" not in stripped, f"bare > in: {text!r}"
    assert re.search(r"&(?!amp;|lt;|gt;|quot;)", stripped) is None, (
        f"bare & in: {text!r}"
    )


def _add_user(db, name: str) -> User:
    user = User(name=name, enabled=True)
    db.add(user)
    db.commit()
    return user


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def test_h_escapes_html_specials_but_not_quotes():
    assert bot_mod.h("<a>&") == "&lt;a&gt;&amp;"
    # Quotes are harmless in HTML text content — left alone.
    assert bot_mod.h('"quoted"') == '"quoted"'


def test_h_coerces_to_str():
    assert bot_mod.h(42) == "42"
    assert bot_mod.h(None) == "None"


def test_b_wraps_in_bold():
    assert bot_mod._b("title") == "<b>title</b>"


def test_titled_bolds_header_line_only():
    assert bot_mod._titled("Head\n\nBody") == "<b>Head</b>\n\nBody"
    assert bot_mod._titled("single line") == "single line"
    assert bot_mod._titled("A\nB") == "A\nB"


# ---------------------------------------------------------------------------
# parse_mode contract — telegram.py + TelegramSender
# ---------------------------------------------------------------------------


def test_send_message_parse_mode_payload(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, payload={"ok": True})
    )
    assert telegram_mod.send_message("tok", "123", "hi", parse_mode="HTML")
    assert calls[0]["json"]["parse_mode"] == "HTML"
    calls.clear()
    # Without parse_mode the payload is exactly the Phase 3 shape
    # (notifications stay plain text).
    assert telegram_mod.send_message("tok", "123", "hi")
    assert "parse_mode" not in calls[0]["json"]
    assert calls[0]["json"] == {"chat_id": "123", "text": "hi"}


def test_edit_message_text_parse_mode_payload(monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post(calls, payload={"ok": True})
    )
    assert telegram_mod.edit_message_text(
        "tok", "123", 7, "hi", parse_mode="HTML"
    )
    assert calls[0]["json"]["parse_mode"] == "HTML"
    calls.clear()
    assert telegram_mod.edit_message_text("tok", "123", 7, "hi")
    assert "parse_mode" not in calls[0]["json"]


def test_telegram_sender_passes_html_parse_mode(monkeypatch):
    sent_calls: list = []
    edit_calls: list = []
    monkeypatch.setattr(
        telegram_mod, "send_message",
        lambda token, chat_id, text, **kw: sent_calls.append(kw) or True,
    )
    monkeypatch.setattr(
        telegram_mod, "edit_message_text",
        lambda token, chat_id, message_id, text, **kw: (
            edit_calls.append(kw) or True
        ),
    )
    sender = bot_mod.TelegramSender("tok")
    sender.send(123, "hi")
    sender.edit(123, 1, "hi2")
    assert sent_calls[0]["parse_mode"] == "HTML"
    assert edit_calls[0]["parse_mode"] == "HTML"


# ---------------------------------------------------------------------------
# /start + /menu — welcome + persistent reply keyboard
# ---------------------------------------------------------------------------


def _reply_keyboard_labels(markup):
    return [
        button["text"]
        for row in markup["keyboard"]
        for button in row
    ]


def test_start_sends_welcome_and_reply_keyboard(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert len(sender.sent) == 2
    # Message 1: the welcome (bold title) + inline menu.
    assert sender.sent[0][1].startswith("<b>🤖")
    assert "sparky-manager" in sender.sent[0][1]
    assert _button_data(sender.sent[0][2]) == [
        "m:users", "m:inb", "m:status", "m:help", "m:svc", "m:bkp",
    ]
    # Message 2: the quick-menu hint + persistent reply keyboard.
    assert sender.sent[1][1] == FA["bot_reply_keyboard_hint"]
    markup = sender.sent[1][2]
    assert markup["resize_keyboard"] is True
    assert markup["is_persistent"] is True
    assert _reply_keyboard_labels(markup) == [
        FA["bot_menu_users"],
        FA["bot_menu_inbounds"],
        FA["bot_menu_status"],
        FA["bot_reply_menu"],
    ]
    assert [len(row) for row in markup["keyboard"]] == [2, 2]


def test_menu_command_sends_reply_keyboard_too(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/menu"), sender)
    assert len(sender.sent) == 2
    assert sender.sent[1][1] == FA["bot_reply_keyboard_hint"]
    assert sender.sent[1][2].get("keyboard")


def test_main_menu_inline_keyboard_is_three_rows_of_two(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    rows = sender.sent[0][2]["inline_keyboard"]
    assert [len(row) for row in rows] == [2, 2, 2]


# ---------------------------------------------------------------------------
# Reply-keyboard taps (plain-text messages)
# ---------------------------------------------------------------------------


def test_reply_keyboard_users_tap_shows_users(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _message(FA["bot_menu_users"]), sender)
    assert len(sender.sent) == 1
    text = sender.sent[0][1]
    assert text.startswith("<b>")
    assert "کاربران" in text
    _assert_valid_bot_html(text)


def test_reply_keyboard_inbounds_tap_shows_inbounds(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _message(FA["bot_menu_inbounds"]), sender)
    text = sender.sent[0][1]
    assert text.startswith("<b>")
    assert "اینباند" in text


def test_reply_keyboard_status_tap_shows_status(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _message(FA["bot_menu_status"]), sender)
    text = sender.sent[0][1]
    assert text.startswith("<b>")
    assert "وضعیت سرور" in text
    _assert_valid_bot_html(text)


def test_reply_keyboard_menu_tap_shows_welcome_without_hint(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert len(sender.sent) == 2
    _dispatch(db, _message(FA["bot_reply_menu"]), sender)
    # Exactly one more send (the welcome + inline menu) — the reply
    # keyboard is already in the chat, so no hint is re-sent.
    assert len(sender.sent) == 3
    assert "sparky-manager" in sender.sent[2][1]
    assert sender.sent[2][2].get("inline_keyboard")
    assert FA["bot_reply_keyboard_hint"] not in sender.sent[2][1]


def test_reply_keyboard_tap_abandons_active_flow(db, sender, seeded):
    _configure_bot(db)
    _start_flow(db, sender)  # conversation: "name" step
    _dispatch(db, _message(FA["bot_menu_users"]), sender)
    assert "کاربران" in sender.sent[-1][1]
    # The flow is gone: free text now gets the idle answer, not the
    # flow's next step (which would open the inbound picker).
    _dispatch(db, _message("zzz-not-a-flow-answer"), sender)
    assert sender.sent[-1][1] == FA["bot_unknown_command"]


def test_reply_keyboard_tap_from_stranger_ignored(db, sender):
    _configure_bot(db)
    _dispatch(
        db, _message(FA["bot_menu_users"], chat_id=OTHER_CHAT), sender
    )
    assert sender.sent == []
    assert sender.edited == []


def test_plain_text_that_is_not_a_label_is_idle_answer(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("hello there"), sender)
    assert len(sender.sent) == 1
    assert sender.sent[0][1] == FA["bot_unknown_command"]


# ---------------------------------------------------------------------------
# Escaping — user-controlled text in rendered messages
# ---------------------------------------------------------------------------


def test_users_list_escapes_evil_name(db, sender):
    _configure_bot(db)
    _add_user(db, EVIL_NAME)
    _dispatch(db, _message("/users"), sender)
    text = sender.sent[0][1]
    assert "&lt;b&gt;&amp;test" in text
    assert EVIL_NAME not in text
    _assert_valid_bot_html(text)


def test_user_detail_escapes_name(db, sender):
    _configure_bot(db)
    user = _add_user(db, EVIL_NAME)
    _dispatch(db, _callback(f"u:v:{user.id}"), sender)
    text = sender.edited[0][2]
    assert text.startswith("<b>👤 &lt;b&gt;&amp;test</b>")
    assert EVIL_NAME not in text
    _assert_valid_bot_html(text)


def test_user_detail_bolds_field_labels(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:v:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert text.startswith("<b>👤 alice</b>")
    assert f"<b>{FA['status']}:</b>" in text
    assert f"<b>{FA['bot_traffic']}:</b>" in text


def test_inbound_detail_escapes_tag_and_remark(db, sender, seeded):
    _configure_bot(db)
    inbound = seeded["inbounds"]["vless-reality"]
    inbound.tag = "ta<g>&x"
    inbound.remark = "<i>note</i> & stuff"
    db.commit()
    _dispatch(db, _callback(f"i:v:{inbound.id}"), sender)
    text = sender.edited[0][2]
    assert "<b>📡 ta&lt;g&gt;&amp;x</b>" in text
    assert "&lt;i&gt;note&lt;/i&gt; &amp; stuff" in text
    assert "ta<g>&x" not in text
    _assert_valid_bot_html(text)


def test_inbounds_list_escapes_tags(db, sender, seeded):
    _configure_bot(db)
    inbound = seeded["inbounds"]["vless-reality"]
    inbound.tag = "ta<g>&x"
    db.commit()
    _dispatch(db, _callback("m:inb"), sender)
    text = sender.edited[0][2]
    assert "ta&lt;g&gt;&amp;x" in text
    assert "ta<g>&x" not in text
    _assert_valid_bot_html(text)


def test_links_escape_ampersands(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    main_mod.set_setting(db, "domain", "panel.example.com")
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "vless://" in text
    # VLESS links carry many & params — all escaped to &amp;.
    assert "&amp;" in text
    _assert_valid_bot_html(text)


def test_search_echoes_escaped_query(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("u:search"), sender)
    _dispatch(db, _message("<script>"), sender)
    text = sender.sent[-1][1]
    assert "&lt;script&gt;" in text
    assert "<script>" not in text
    _assert_valid_bot_html(text)


def test_rerender_error_is_escaped(db, sender, seeded, monkeypatch):
    _configure_bot(db)
    monkeypatch.setattr(
        main_mod, "rerender_configs",
        lambda db: ["xray: bad <tag> & stuff"],
    )
    inbound = seeded["inbounds"]["vless-reality"]
    _dispatch(db, _callback(f"i:tg:{inbound.id}"), sender)
    text = sender.edited[-1][2]
    assert "xray: bad &lt;tag&gt; &amp; stuff" in text
    assert "bad <tag>" not in text
    _assert_valid_bot_html(text)


def test_services_view_renders_valid_html(
    db, sender, fake_status
):
    _configure_bot(db)
    _dispatch(db, _callback("m:svc"), sender)
    text = sender.edited[-1][2]
    assert text.startswith(f"<b>{FA['bot_services_title']}</b>")
    assert "<b>Xray</b>" in text
    _assert_valid_bot_html(text)


def test_toasts_stay_plain(db, sender, seeded, monkeypatch):
    """Callback toasts (answer_callback_query) take no parse_mode —
    they must stay plain text, never bold."""
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:frz:{alice.id}"), sender)
    assert sender.answered
    assert sender.answered[-1][1] == FA["bot_frozen"]
    assert "<b>" not in sender.answered[-1][1]


# ---------------------------------------------------------------------------
# Keyboard layouts — callback data unchanged, rows regrouped
# ---------------------------------------------------------------------------


def test_user_detail_keyboard_groups_actions(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:v:{alice.id}"), sender)
    rows = sender.edited[0][3]["inline_keyboard"]
    # Bot parity: the Clients button joined the first row.
    assert [len(row) for row in rows] == [3, 2, 2, 1]
    assert _button_data(sender.edited[0][3]) == [
        f"u:links:{alice.id}",
        f"u:edit:{alice.id}",
        f"u:cl:{alice.id}",
        f"u:frz:{alice.id}",
        f"u:ext:{alice.id}",
        f"u:rst:{alice.id}",
        f"u:del:{alice.id}",
        "u:list:0",
    ]


def test_inbound_detail_keyboard_pairs_toggle_delete(db, sender, seeded):
    _configure_bot(db)
    inbound = seeded["inbounds"]["vless-reality"]
    _dispatch(db, _callback(f"i:v:{inbound.id}"), sender)
    rows = sender.edited[0][3]["inline_keyboard"]
    assert [len(row) for row in rows] == [2, 1]
    assert _button_data(sender.edited[0][3]) == [
        f"i:tg:{inbound.id}",
        f"i:del:{inbound.id}",
        "i:list",
    ]


def test_inbounds_list_pairs_tag_buttons(db, sender, seeded):
    _configure_bot(db)
    _dispatch(db, _callback("m:inb"), sender)
    rows = sender.edited[0][3]["inline_keyboard"]
    # 11 seeded inbounds, 8 per page: page 0 shows 8 tags as 4 pairs,
    # then the nav row (next only), then the new + back rows.
    assert [len(row) for row in rows] == [2, 2, 2, 2, 1, 1, 1]
    data = _button_data(sender.edited[0][3])
    assert data[-3:] == ["i:list:1", "i:new", "m:main"]
    page0 = sorted(data[:-3])
    assert len(page0) == 8
    assert all(d.startswith("i:v:") for d in page0)
    # Page 1: the remaining 3 tags pair as [2, 1], then prev + new + back.
    _dispatch(db, _callback("i:list:1"), sender)
    rows = sender.edited[-1][3]["inline_keyboard"]
    assert [len(row) for row in rows] == [2, 1, 1, 1, 1]
    data = _button_data(sender.edited[-1][3])
    assert data[-3:] == ["i:list:0", "i:new", "m:main"]
    page1 = sorted(data[:-3])
    assert len(page1) == 3
    # Both pages together cover every seeded inbound exactly once.
    assert sorted(page0 + page1) == sorted(
        f"i:v:{inbound.id}" for inbound in seeded["inbounds"].values()
    )


def test_protocol_picker_pairs_buttons(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("i:new"), sender)
    rows = sender.edited[0][3]["inline_keyboard"]
    assert [len(row) for row in rows] == [2, 2, 2, 2, 2, 2, 2, 1]
    assert _button_data(sender.edited[0][3]) == [
        "i:new:vless",
        "i:new:vmess",
        "i:new:trojan",
        "i:new:shadowsocks",
        "i:new:hysteria2",
        "i:new:tuic",
        "i:new:anytls",
        "i:new:naive",
        "i:new:shadowtls",
        "i:new:wireguard",
        "i:new:amneziawg",
        "i:new:openvpn",
        "i:new:openconnect",
        "i:new:ikev2",
        "c:cancel",
    ]


def test_edit_menu_single_row_of_three(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:edit:{alice.id}"), sender)
    rows = sender.edited[0][3]["inline_keyboard"]
    assert [len(row) for row in rows] == [3, 1]
    assert _button_data(sender.edited[0][3]) == [
        f"u:edit:{alice.id}:name",
        f"u:edit:{alice.id}:limit",
        f"u:edit:{alice.id}:expiry",
        f"u:v:{alice.id}",
    ]


# ---------------------------------------------------------------------------
# Restart-failure message names the service (regression)
# ---------------------------------------------------------------------------


def test_restart_failure_names_the_service(
    db, sender, fake_status, monkeypatch
):
    """Pre-polish bug: the failure note built the string WITHOUT
    .format(name=name), so the admin literally saw "{name}"."""
    _configure_bot(db)
    monkeypatch.setattr(
        main_mod, "_restart_service",
        lambda name: "restart of xray failed: exit 1",
    )
    _dispatch(db, _callback("s:rst:xray:ok"), sender)
    text = sender.edited[-1][2]
    assert "ناموفق بود" in text
    assert "Xray" in text
    assert "{name}" not in text
    assert "exit 1" in text


def test_restart_stopped_after_names_the_service(
    db, sender, fake_status, monkeypatch
):
    _configure_bot(db)
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    fake_status["wireguard"] = "stopped"  # still stopped after restart
    _dispatch(db, _callback("s:rst:wireguard:ok"), sender)
    text = sender.edited[-1][2]
    assert "ناموفق بود" in text
    assert "WireGuard" in text
    assert "{name}" not in text
