"""Fix batch (post–Phase B) — three user-reported fixes.

1. Inbound auto-fill bug: the web add-inbound form pre-filled tag
   ``vless-<port>`` (computed once for "vless", never updated on
   protocol change), so an OpenVPN inbound got tag ``vless-54729``;
   the pre-filled port also defeated the preferred-port logic.
   The form now leaves tag/port empty (placeholders only) and the
   server derives both from the SUBMITTED protocol+port; a duplicate
   tag never errors (3X-UI behaviour — the backend re-generates
   ``-2``…``-99``); an empty SNI means the panel default for
   xray/sing-box cores (the bot's create flow already did this).
2. Subscription link without a domain: the bot's Links view omitted
   the subscription URL when no domain was set. The subscription URL
   now falls back to the ``subscription_host`` setting; the webhook
   flow stays domain-only.
3. Bot quick-menu hint: /start and /menu sent a second message
   ("🎛️ منوی سریع:") carrying the persistent reply keyboard. The
   message is now sent and deleted at once — the keyboard persists
   client-side, the hint text is gone. Buttons, _on_text label
   matching and the guided-flow fall-through are untouched.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app import telegram as telegram_mod
from app.i18n import t_for
from app.models import Inbound
from tests.conftest import HOST
from tests.test_telegram_bot import (
    ADMIN_CHAT,
    FakeSender,
    _configure_bot,
    _dispatch,
    _message,
    _callback,
)

FA = t_for("fa")


@pytest.fixture()
def sender():
    return FakeSender()


def _create_inbound(authed_client, **overrides):
    data = {
        "tag": "",
        "core": "xray",
        "protocol": "vless",
        "port": "0",
        "remark": "",
        "sni": "",
        "path": "",
        "network": "tcp",
    }
    data.update(overrides)
    return authed_client.post("/inbounds", data=data, follow_redirects=False)


# ---------------------------------------------------------------------------
# 1. Inbound auto-fill bug
# ---------------------------------------------------------------------------


def test_create_openvpn_empty_form_gets_protocol_tag_and_preferred_port(
    authed_client, db
):
    """The reported bug, end to end: an OpenVPN inbound created from
    the empty form must get tag openvpn-1194 — never vless-<port>."""
    resp = _create_inbound(
        authed_client, core="openvpn", protocol="openvpn", network="tcp"
    )
    assert resp.status_code in (302, 303)
    # (The redirect may carry a re-render err= — the seeded
    # tuic/anytls/naive inbounds have no certs in the test env — but
    # the inbound itself is created; the row assertions below are
    # the real check.)
    row = db.query(Inbound).filter(Inbound.protocol == "openvpn").first()
    assert row is not None
    assert row.port == 1194  # preferred port, not a random pre-fill
    assert row.tag == "openvpn-1194"
    assert not row.tag.startswith("vless-")


def test_create_vless_empty_sni_gets_reality_default(authed_client, db):
    """An empty SNI still means the panel default for xray/sing-box
    cores — one-click VLESS creation keeps getting Reality."""
    resp = _create_inbound(authed_client, tag="vless-def")
    assert resp.status_code in (302, 303)
    row = db.query(Inbound).filter(Inbound.tag == "vless-def").first()
    assert row is not None
    stream = json.loads(row.stream_json)
    assert stream.get("security") == "reality"
    reality = stream.get("reality") or {}
    assert reality.get("sni") == "www.microsoft.com"
    assert len(reality.get("private_key", "")) == 43
    assert len(reality.get("public_key", "")) == 43
    assert len(reality.get("short_id", "")) == 8


def test_create_openvpn_empty_sni_gets_no_security_block(authed_client, db):
    """The SNI default applies only to xray/sing-box cores — a native
    inbound gets no reality/tls block from an empty SNI."""
    resp = _create_inbound(
        authed_client, tag="ovpn-nosni", core="openvpn", protocol="openvpn"
    )
    assert resp.status_code in (302, 303)
    row = db.query(Inbound).filter(Inbound.tag == "ovpn-nosni").first()
    assert row is not None
    stream = json.loads(row.stream_json)
    assert "reality" not in stream
    assert "tls" not in stream
    assert "security" not in stream


def test_create_explicit_sni_is_honored(authed_client, db):
    resp = _create_inbound(
        authed_client, tag="trojan-sni", protocol="trojan", sni="example.com"
    )
    assert resp.status_code in (302, 303)
    row = db.query(Inbound).filter(Inbound.tag == "trojan-sni").first()
    assert row is not None
    stream = json.loads(row.stream_json)
    assert stream.get("security") == "tls"
    assert (stream.get("tls") or {}).get("sni") == "example.com"


def test_create_empty_tag_uses_submitted_protocol(authed_client, db):
    """The tag is derived from the SUBMITTED protocol — a Trojan
    inbound gets a trojan- tag even though the old form defaulted
    everything to vless."""
    resp = _create_inbound(authed_client, protocol="trojan", port="24433")
    assert resp.status_code in (302, 303)
    row = db.query(Inbound).filter(Inbound.tag == "trojan-24433").first()
    assert row is not None


def test_ensure_unique_tag_free_base_unchanged(db):
    assert main_mod.ensure_unique_tag(db, "vless-9999") == "vless-9999"


def test_ensure_unique_tag_regenerates_taken_base(db):
    db.add(Inbound(tag="vless-9999", core="xray", protocol="vless", port=9999))
    db.add(Inbound(tag="vless-9999-2", core="xray", protocol="vless", port=9998))
    db.commit()
    assert main_mod.ensure_unique_tag(db, "vless-9999") == "vless-9999-3"


def test_ensure_unique_tag_truncates_long_base_to_64_chars(db):
    long_tag = "x" * 64
    db.add(Inbound(tag=long_tag, core="xray", protocol="vless", port=9999))
    db.commit()
    out = main_mod.ensure_unique_tag(db, long_tag)
    assert len(out) <= 64
    assert out.endswith("-2")
    assert out != long_tag


# ---------------------------------------------------------------------------
# 2. Subscription link without a domain
# ---------------------------------------------------------------------------


def _sub_url(settings, token="tok123"):
    return main_mod._subscription_panel_url(settings, f"/sub/{token}")


def test_subscription_url_prefers_domain():
    settings = {"domain": "panel.example.com", "subscription_host": HOST}
    url = _sub_url(settings)
    assert url == main_mod._public_panel_url(settings, "/sub/tok123")
    assert url.startswith("https://panel.example.com")
    assert url.endswith("/sub/tok123")


def test_subscription_url_falls_back_to_subscription_host():
    settings = {"domain": "", "subscription_host": HOST}
    url = _sub_url(settings)
    assert url == (
        f"https://{HOST}:{main_mod.PANEL_PORT}{main_mod.WEB_PATH}/sub/tok123"
    )


def test_subscription_url_none_without_domain_or_host():
    assert _sub_url({"domain": "", "subscription_host": ""}) is None
    assert _sub_url({}) is None


def test_subscription_url_strips_scheme_and_keeps_explicit_port():
    settings = {"domain": "", "subscription_host": "https://1.2.3.4:8443/"}
    url = _sub_url(settings)
    assert url == f"https://1.2.3.4:8443{main_mod.WEB_PATH}/sub/tok123"


def test_public_panel_url_still_none_without_domain():
    """The webhook flow stays domain-only: subscription_host must
    never leak into _public_panel_url (telegram_domain_required is
    the honest error there)."""
    settings = {"domain": "", "subscription_host": HOST}
    assert main_mod._public_panel_url(settings, "/telegram/webhook/x") is None


def test_bot_links_include_sub_url_without_domain(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    # No domain set anywhere in this test.
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "vless://" in text
    assert f"/sub/{alice.sub_token}" in text
    assert HOST in text


def test_bot_links_sub_url_uses_domain_when_set(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    main_mod.set_setting(db, "domain", "panel.example.com")
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "panel.example.com" in text
    assert f"/sub/{alice.sub_token}" in text


# ---------------------------------------------------------------------------
# 3. Bot quick-menu hint message
# ---------------------------------------------------------------------------


def test_start_sends_hint_then_deletes_it(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert len(sender.sent) == 2
    # The hint message still carries the persistent reply keyboard.
    hint_text, hint_markup = sender.sent[1][1], sender.sent[1][2]
    assert hint_text == FA["bot_reply_keyboard_hint"]
    assert hint_markup["is_persistent"] is True
    assert hint_markup["keyboard"]
    # ... and it is deleted at once (the keyboard persists client-side).
    assert sender.deleted == [(ADMIN_CHAT, 1)]


def test_menu_sends_hint_then_deletes_it(db, sender):
    _configure_bot(db)
    _dispatch(db, _message("/menu"), sender)
    assert len(sender.sent) == 2
    assert sender.sent[1][1] == FA["bot_reply_keyboard_hint"]
    assert sender.deleted == [(ADMIN_CHAT, 1)]


def test_hint_delete_failure_is_not_fatal(db):
    """A failed delete (message already gone, Telegram unreachable)
    leaves the hint visible — it must never break /start."""
    failing = FakeSender(delete_ok=False)
    _configure_bot(db)
    _dispatch(db, _message("/start"), failing)
    assert len(failing.sent) == 2
    assert failing.deleted == [(ADMIN_CHAT, 1)]
    assert "sparky-manager" in failing.sent[0][1]


class _NoIdSender(FakeSender):
    """send_id fails (Telegram unreachable): no id, no delete."""

    def send_id(self, chat_id, text, reply_markup=None):
        self.sent.append((chat_id, text, reply_markup))
        return None


def test_hint_send_failure_skips_delete(db):
    sender = _NoIdSender()
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert len(sender.sent) == 2
    assert sender.deleted == []


class _RaisingSender(FakeSender):
    """send_id raises: the install must not take /start down."""

    def send_id(self, chat_id, text, reply_markup=None):
        raise RuntimeError("telegram down")


def test_hint_send_exception_does_not_break_start(db):
    sender = _RaisingSender()
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    # The welcome still went out; the keyboard install failed safely.
    assert len(sender.sent) == 1
    assert "sparky-manager" in sender.sent[0][1]
    assert sender.deleted == []


def test_reply_keyboard_tap_still_works_after_start(db, sender, seeded):
    """The delete changes nothing about the keyboard: its labels
    still route, and the guided-flow fall-through still answers."""
    _configure_bot(db)
    _dispatch(db, _message("/start"), sender)
    assert sender.deleted == [(ADMIN_CHAT, 1)]
    _dispatch(db, _message(FA["bot_menu_users"]), sender)
    assert "کاربران" in sender.sent[-1][1]
    _dispatch(db, _message("zzz-not-a-flow-answer"), sender)
    assert sender.sent[-1][1] == FA["bot_unknown_command"]


def _fake_httpx_post(calls, status_code=200, payload=None):
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: payload if payload is not None else {"ok": True},
        )

    return _post


def test_telegram_send_message_id_returns_id(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "httpx.post",
        _fake_httpx_post(
            calls, payload={"ok": True, "result": {"message_id": 42}}
        ),
    )
    assert telegram_mod.send_message_id("tok", "123", "hi") == 42
    assert calls[0]["url"].endswith("/sendMessage")
    assert calls[0]["json"]["text"] == "hi"


def test_telegram_send_message_id_none_on_failure(monkeypatch):
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post([], status_code=500)
    )
    assert telegram_mod.send_message_id("tok", "123", "hi") is None
    assert telegram_mod.send_message_id("", "123", "hi") is None


def test_telegram_delete_message_api(monkeypatch):
    calls = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    assert telegram_mod.delete_message("tok", "123", 42) is True
    assert calls[0]["url"].endswith("/deleteMessage")
    assert calls[0]["json"] == {"chat_id": "123", "message_id": 42}


def test_telegram_delete_message_false_on_failure(monkeypatch):
    monkeypatch.setattr(
        "httpx.post", _fake_httpx_post([], status_code=400)
    )
    assert telegram_mod.delete_message("tok", "123", 42) is False
    assert telegram_mod.delete_message("tok", "123", 0) is False
    assert telegram_mod.delete_message("", "123", 42) is False
