"""Debug-pass tests (2026-11-15, after the bot polish).

Morteza asked for a complete check of the project and a debug pass.
These tests lock in the fixes that came out of it:

- NAME_RE had no length limit (a multi-kilobyte name/tag was accepted
  by the web forms and the bot; SQLite never enforces VARCHAR).
- ``telegram.send_message`` / ``edit_message_text`` truncated HTML
  messages with a dumb cut that could split a ``<b>`` tag or an
  ``&amp;`` entity — Telegram rejects malformed HTML, so the admin
  would see nothing at all.
- The bot's inbound list was unpaginated (one message for all
  inbounds — the 4096-char cap) and issued one COUNT per inbound.
- The logs page labelled its line-limit input "Level / Message".
- The language toggle dropped the page's query params (filters lost
  on every language switch), and the login page had no toggle at all.
"""

from __future__ import annotations

import html
import re
from types import SimpleNamespace

import pytest
from sqlalchemy import event

from app import main as main_mod
from app import telegram as telegram_mod
from app.models import Inbound, User
from app.webcommon import NAME_RE
from tests.test_telegram_bot import (
    FakeSender,
    _button_data,
    _callback,
    _configure_bot,
    _dispatch,
)

_HREF_RE = re.compile(r'''(?:href|src)="([^"]+)"''')

LONG_64 = "n" * 64
LONG_65 = "n" * 65


@pytest.fixture()
def sender():
    return FakeSender()


# ---------------------------------------------------------------------------
# NAME_RE length cap
# ---------------------------------------------------------------------------


def test_name_re_length_cap():
    assert NAME_RE.match("a")
    assert NAME_RE.match(LONG_64)
    assert NAME_RE.match("a-1_B") is not None
    assert NAME_RE.match(LONG_65) is None
    assert NAME_RE.match("") is None
    # Persian names are deliberately not allowed (names appear in
    # subscription URLs and share links).
    assert NAME_RE.match("مرتضی") is None
    assert NAME_RE.match("has space") is None


def test_web_create_user_rejects_long_name(authed_client, db):
    resp = authed_client.post(
        "/users", data={"name": LONG_65}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert db.query(User).filter(User.name == LONG_65).first() is None
    # The 64-char boundary is accepted.
    resp = authed_client.post(
        "/users", data={"name": LONG_64}, follow_redirects=False
    )
    assert resp.status_code in (200, 303)
    assert db.query(User).filter(User.name == LONG_64).first() is not None


def test_check_new_inbound_rejects_long_tag(db):
    assert (
        main_mod._check_new_inbound(db, "vless", 19001, LONG_65, "tcp")
        == "invalid_name"
    )
    assert (
        main_mod._check_new_inbound(db, "vless", 19001, LONG_64, "tcp")
        is None
    )


def test_web_create_inbound_rejects_long_tag(authed_client, db):
    resp = authed_client.post(
        "/inbounds",
        data={
            "tag": LONG_65,
            "core": "xray",
            "protocol": "vless",
            "port": "19001",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert db.query(Inbound).filter(Inbound.tag == LONG_65).first() is None


# ---------------------------------------------------------------------------
# HTML-safe truncation
# ---------------------------------------------------------------------------


def test_truncate_html_safe_short_passthrough():
    assert telegram_mod._truncate_html_safe("hello", 20) == "hello"
    assert telegram_mod._truncate_html_safe("x" * 20, 20) == "x" * 20


def test_truncate_html_safe_plain_cut():
    out = telegram_mod._truncate_html_safe("a" * 100, 20)
    assert len(out) <= 20
    assert out == "a" * 15 + "…"


def test_truncate_html_safe_cut_inside_tag():
    # The cut lands inside "<b" — the partial tag must go, not break.
    out = telegram_mod._truncate_html_safe("a" * 13 + "<b>hi</b>", 20)
    assert "<" not in out
    assert out == "a" * 13 + "…"


def test_truncate_html_safe_cut_inside_entity():
    # The cut lands inside "&amp;" — the partial entity must go.
    out = telegram_mod._truncate_html_safe("a" * 13 + "&amp;rest", 20)
    assert "&" not in out
    assert out == "a" * 13 + "…"


def test_truncate_html_safe_balances_open_tag():
    out = telegram_mod._truncate_html_safe("<b>" + "a" * 30, 20)
    assert len(out) <= 20
    assert out.count("<b>") == out.count("</b>") == 1
    assert out.endswith("…</b>")


def test_truncate_html_safe_never_exceeds_limit():
    # Every cut position of a tag-heavy message stays within the cap
    # and keeps its tags balanced.
    text = "<b>" + "a&b" * 300 + "</b>" + "tail" * 200
    for limit in (50, 100, 4096):
        out = telegram_mod._truncate_html_safe(text, limit)
        assert len(out) <= limit
        assert out.count("<b>") == out.count("</b>")
        # No partial tag or partial entity at the very end.
        assert "<b" not in out.replace("<b>", "")
        assert re.search(r"&[A-Za-z0-9#]+$", out) is None


def _fake_httpx_post(calls):
    def _post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        return SimpleNamespace(
            status_code=200, json=lambda: {"ok": True}
        )

    return _post


def test_send_message_html_truncation_balanced(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    # A long HTML message whose dumb cut would land inside the closing
    # tag region: the payload must stay valid HTML and within 4096.
    text = "<b>" + "x" * 5000 + "</b>"
    assert telegram_mod.send_message(
        "tok", "42", text, parse_mode="HTML"
    ) is True
    payload_text = calls[0]["json"]["text"]
    assert len(payload_text) <= 4096
    assert payload_text.count("<b>") == payload_text.count("</b>") == 1
    assert payload_text.endswith("…</b>")


def test_send_message_plain_truncation_unchanged(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    text = "y" * 5000
    assert telegram_mod.send_message("tok", "42", text) is True
    assert calls[0]["json"]["text"] == "y" * 4095 + "…"


def test_edit_message_text_html_truncation_balanced(monkeypatch):
    calls: list = []
    monkeypatch.setattr("httpx.post", _fake_httpx_post(calls))
    text = "<b>" + "z" * 5000
    assert telegram_mod.edit_message_text(
        "tok", "42", 7, text, parse_mode="HTML"
    ) is True
    payload_text = calls[0]["json"]["text"]
    assert len(payload_text) <= 4096
    assert payload_text.count("<b>") == payload_text.count("</b>") == 1


# ---------------------------------------------------------------------------
# Bot inbound list: pagination + no N+1
# ---------------------------------------------------------------------------


@pytest.fixture()
def statement_counter(db_engine):
    """Record every SQL statement issued on the test engine (same
    pattern as tests/test_phase6_perf.py)."""
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(str(statement))

    event.listen(db_engine, "before_cursor_execute", _record)
    yield statements
    event.remove(db_engine, "before_cursor_execute", _record)


def _count_queries(statements, *needles):
    return sum(
        1
        for s in statements
        if all(n.lower() in s.lower() for n in needles)
    )


def test_inbounds_list_single_count_query(db, sender, statement_counter):
    """The inbound list issues ONE grouped client-count query, however
    many inbounds exist (the per-inbound COUNT was the bot's last N+1)."""
    _configure_bot(db)
    _dispatch(db, _callback("i:list"), sender)
    assert _count_queries(statement_counter, "count", "client") == 1
    # Add 5 more inbounds: still exactly one count query.
    for i in range(5):
        db.add(
            Inbound(
                tag=f"extra-{i}",
                core="xray",
                protocol="vless",
                port=20000 + i,
                stream_json="{}",
            )
        )
    db.commit()
    del statement_counter[:]
    _dispatch(db, _callback("i:list"), sender)
    assert _count_queries(statement_counter, "count", "client") == 1


def test_inbounds_list_page_clamps(db, sender):
    """Out-of-range and non-numeric pages clamp instead of breaking."""
    _configure_bot(db)
    _dispatch(db, _callback("i:list:99"), sender)
    # Last page (wireguard, port 51820, is the final inbound).
    assert "wireguard" in sender.edited[-1][2]
    _dispatch(db, _callback("i:list:abc"), sender)
    assert "vless-reality" in sender.edited[-1][2]
    _dispatch(db, _callback("i:list:-1"), sender)
    assert "vless-reality" in sender.edited[-1][2]


def test_inbounds_list_back_buttons_reset_to_page_zero(db, sender, seeded):
    """Back-to-list buttons ("i:list") still work — they show page 0."""
    _configure_bot(db)
    vless = seeded["inbounds"]["vless-reality"]
    _dispatch(db, _callback(f"i:v:{vless.id}"), sender)
    data = _button_data(sender.edited[-1][3])
    assert "i:list" in data
    _dispatch(db, _callback("i:list"), sender)
    assert "vless-reality" in sender.edited[-1][2]
    assert "صفحه 1 از 2" in sender.edited[-1][2]


# ---------------------------------------------------------------------------
# Logs label, language toggle, login toggle
# ---------------------------------------------------------------------------


def test_logs_page_shows_lines_label(authed_client):
    resp = authed_client.get("/logs")
    assert resp.status_code == 200
    assert "تعداد خط‌ها" in resp.text
    # The old mislabel sat on the limit input ("Level / Message").
    assert "سطح / پیام" not in resp.text
    # The level filter keeps its own label.
    assert "سطح" in resp.text


def test_language_toggle_preserves_query_params(authed_client):
    resp = authed_client.get("/users?q=alice&status=enabled")
    assert resp.status_code == 200
    hrefs = [
        html.unescape(h)
        for h in _HREF_RE.findall(resp.text)
        if "lang=" in h
    ]
    assert hrefs, "no language toggle link found"
    for href in hrefs:
        assert "q=alice" in href, href
        assert "status=enabled" in href, href
        assert "lang=en" in href or "lang=fa" in href, href


def test_login_page_has_language_toggle(test_client):
    resp = test_client.get("/login")
    assert resp.status_code == 200
    hrefs = [
        html.unescape(h)
        for h in _HREF_RE.findall(resp.text)
        if "lang=" in h
    ]
    assert hrefs, "the login page has no language toggle"
    assert any("lang=en" in h for h in hrefs)


def test_login_lang_query_sets_cookie_and_renders_english(test_client):
    resp = test_client.get("/login?lang=en")
    assert resp.status_code == 200
    assert "Sign in to the panel" in resp.text
    assert "lang=en" in resp.headers.get("set-cookie", "")
    # And the toggle back to Persian is there.
    assert "lang=fa" in resp.text
