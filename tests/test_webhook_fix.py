"""Bot polish (Task A) — webhook registration on save, the port
warning, and getWebhookInfo diagnostics on the settings page.

Covers: ``_webhook_port_state`` (blocked / note / ok), set_webhook
being called when transport=webhook is saved (exact URL, flash
message, failure reporting, secret redaction, audit discipline),
the settings-page warning (blocked vs note vs none), and the
diagnostics area (getWebhookInfo on page load, brief cache,
"unavailable" on failure — never a 500).

No real network anywhere: every Bot API call is stubbed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest

from app import main as main_mod
from app import telegram as telegram_mod
from app.i18n import t_for
from app.models import AuditLog
from tests.test_telegram_bot import (
    ADMIN_CHAT,
    SECRET,
    TOKEN,
    _configure_bot,
)

FA = t_for("fa")
DOMAIN = "panel.example.com"


@pytest.fixture()
def rerender_ok(monkeypatch):
    """A clean re-render (same as test_telegram_polling's): the seeded
    TLS inbounds have no certificate, so a real re-render in tests
    always reports errors — stub it out so the message assertions
    are deterministic."""
    monkeypatch.setattr(main_mod, "rerender_configs", lambda db: [])


def _webhook_url() -> str:
    return (
        f"https://{DOMAIN}:{main_mod.PANEL_PORT}"
        f"/telegram/webhook/{SECRET}"
    )


def _save(authed_client, data):
    return authed_client.post(
        "/settings", data=data, follow_redirects=False
    )


def _flash(location: str) -> str:
    """The redirect's msg=/err= text, URL-decoded."""
    return unquote(location)


# ---------------------------------------------------------------------------
# _webhook_port_state
# ---------------------------------------------------------------------------


def test_webhook_port_state_blocked_no_domain():
    # Test env PANEL_PORT (2053) is not a Telegram port, and with no
    # domain no webhook URL can be built at all.
    assert main_mod._webhook_port_state({}) == "blocked"
    assert main_mod._webhook_port_state({"domain": ""}) == "blocked"


def test_webhook_port_state_note_domain_set():
    # A domain is set but the effective port is unsupported: a
    # reverse proxy may still serve 443, so this is a nudge, not a
    # verdict.
    assert (
        main_mod._webhook_port_state({"domain": DOMAIN}) == "note"
    )


def test_webhook_port_state_note_domain_with_scheme():
    assert (
        main_mod._webhook_port_state({"domain": f"https://{DOMAIN}"})
        == "note"
    )


def test_webhook_port_state_note_domain_bad_port_ignored():
    # A non-numeric port on the domain is ignored (PANEL_PORT wins).
    assert (
        main_mod._webhook_port_state({"domain": f"{DOMAIN}:abc"})
        == "note"
    )


def test_webhook_port_state_ok_domain_with_telegram_port():
    for port in (443, 80, 88, 8443):
        assert (
            main_mod._webhook_port_state({"domain": f"{DOMAIN}:{port}"})
            == "ok"
        )


def test_webhook_port_state_ok_panel_port_8443(monkeypatch):
    monkeypatch.setattr(main_mod, "PANEL_PORT", 8443)
    assert main_mod._webhook_port_state({}) == "ok"


def test_webhook_port_state_ok_panel_port_443(monkeypatch):
    monkeypatch.setattr(main_mod, "PANEL_PORT", 443)
    assert main_mod._webhook_port_state({}) == "ok"


# ---------------------------------------------------------------------------
# save_settings — set_webhook on save
# ---------------------------------------------------------------------------


def test_save_switch_to_webhook_registers_with_exact_url(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "polling")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append((token, url)) or (True, ""),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
            "section": "telegram",
        },
    )
    assert resp.status_code == 303
    assert called == [(TOKEN, _webhook_url())]
    assert main_mod.get_setting(db, "telegram_webhook_url") == _webhook_url()
    assert main_mod.get_setting(db, "telegram_webhook_registered_at")
    # The switch is confirmed with a message, no error.
    location = resp.headers["location"]
    assert FA["telegram_webhook_registered"] in _flash(location)
    assert "err=" not in location


def test_save_switch_to_webhook_audits_registration(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "polling")
    monkeypatch.setattr(
        telegram_mod, "set_webhook", lambda token, url, **kw: (True, "")
    )
    _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.webhook_register")
        .count()
        == 1
    )


def test_save_switch_to_webhook_no_domain_errors_but_saves(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append(url) or (True, ""),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert resp.status_code == 303
    # No domain → no URL can be built → set_webhook is not called,
    # but the transport choice is still saved (never blocked).
    assert called == []
    assert main_mod.get_setting(db, "telegram_transport") == "webhook"
    location = resp.headers["location"]
    assert "err=" in location
    assert FA["telegram_domain_required"] in _flash(location)
    assert "msg=" not in location


def test_save_switch_to_webhook_no_token_errors(
    authed_client, db, monkeypatch, rerender_ok
):
    # No bot configured at all (no token stored).
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "polling")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append(url) or (True, ""),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert resp.status_code == 303
    assert called == []
    assert main_mod.get_setting(db, "telegram_transport") == "webhook"
    assert FA["telegram_not_configured"] in _flash(resp.headers["location"])


def test_save_switch_to_webhook_failure_reports_error_and_port_warning(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "polling")
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: (False, "Bad Request: bad webhook"),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert "err=" in location
    flash = _flash(location)
    assert FA["telegram_webhook_failed"] in flash
    assert "bad webhook" in flash
    # The panel port is not a Telegram port — the warning rides along.
    assert FA["telegram_webhook_port_warning"] in flash
    assert main_mod.get_setting(db, "telegram_webhook_url") == ""


def test_save_switch_to_webhook_failure_redacts_secret(
    authed_client, db, monkeypatch, rerender_ok
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "polling")
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: (False, f"refused url {SECRET}"),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    location = resp.headers["location"]
    assert SECRET not in _flash(location)
    assert "••••" in _flash(location)


def test_save_webhook_no_switch_reregisters_silently(
    authed_client, db, monkeypatch, rerender_ok
):
    """Already on webhook: the save still re-registers (self-healing
    after a domain/token change) but says nothing — no msg, no err."""
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append(url) or (True, ""),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert resp.status_code == 303
    assert called == [_webhook_url()]
    location = resp.headers["location"]
    assert "msg=" not in location
    assert "err=" not in location


def test_save_webhook_resave_same_url_does_not_audit(
    authed_client, db, monkeypatch, rerender_ok
):
    """A no-op re-save (same URL) does not spam the audit log."""
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    main_mod.set_setting(db, "telegram_webhook_url", _webhook_url())
    monkeypatch.setattr(
        telegram_mod, "set_webhook", lambda token, url, **kw: (True, "")
    )
    _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "telegram.webhook_register")
        .count()
        == 0
    )


def test_save_webhook_no_switch_failure_is_silent(
    authed_client, db, monkeypatch, rerender_ok
):
    """A failed re-register on a non-switch save is logged only — the
    admin did not take a webhook action, so no false alarm."""
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: (False, "boom"),
    )
    resp = _save(
        authed_client,
        {
            "telegram_chat_id": str(ADMIN_CHAT),
            "telegram_transport": "webhook",
        },
    )
    assert resp.status_code == 303
    assert "err=" not in resp.headers["location"]


def test_save_domain_change_reregisters_webhook(
    authed_client, db, monkeypatch, rerender_ok
):
    """A General-tab domain save re-registers the webhook with the new
    URL (partial update — no transport field in the form)."""
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    main_mod.set_setting(db, "telegram_webhook_url", _webhook_url())
    called: list = []
    monkeypatch.setattr(
        telegram_mod, "set_webhook",
        lambda token, url, **kw: called.append(url) or (True, ""),
    )
    resp = _save(
        authed_client,
        {"domain": "new.example.com", "section": "general"},
    )
    assert resp.status_code == 303
    expected = (
        f"https://new.example.com:{main_mod.PANEL_PORT}"
        f"/telegram/webhook/{SECRET}"
    )
    assert called == [expected]
    assert main_mod.get_setting(db, "telegram_webhook_url") == expected
    # Silent re-register: no flash either way.
    assert "msg=" not in resp.headers["location"]
    assert "err=" not in resp.headers["location"]


# ---------------------------------------------------------------------------
# Settings page — port warning
# ---------------------------------------------------------------------------


def _stub_webhook_info(monkeypatch, result):
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: result,
    )


def test_settings_page_webhook_blocked_warning(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    warning = FA["telegram_webhook_blocked_warning"].format(
        port=main_mod.PANEL_PORT
    )
    # Under the transport select AND in the diagnostics area.
    assert page.text.count(warning) == 2
    assert FA["telegram_webhook_port_note"] not in page.text


def test_settings_page_webhook_note_with_domain(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "domain", DOMAIN)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert FA["telegram_webhook_port_note"] in page.text
    assert FA["telegram_webhook_blocked_warning"].format(
        port=main_mod.PANEL_PORT
    ) not in page.text


def test_settings_page_no_warning_on_polling(authed_client, db, monkeypatch):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "polling")
    # Polling never fetches getWebhookInfo.
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: (_ for _ in ()).throw(
            AssertionError("must not fetch on polling")
        ),
    )
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert FA["telegram_webhook_blocked_warning"].format(
        port=main_mod.PANEL_PORT
    ) not in page.text
    assert FA["telegram_webhook_port_note"] not in page.text


def test_settings_page_no_warning_on_supported_port(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    monkeypatch.setattr(main_mod, "PANEL_PORT", 8443)
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert FA["telegram_webhook_blocked_warning"].format(
        port=8443
    ) not in page.text
    assert FA["telegram_webhook_port_note"] not in page.text


def test_settings_page_warning_without_bot_configured(
    authed_client, db, monkeypatch
):
    """The warning shows under the transport select even before the
    bot is configured (the diagnostics area itself needs a bot)."""
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    warning = FA["telegram_webhook_blocked_warning"].format(
        port=main_mod.PANEL_PORT
    )
    assert page.text.count(warning) == 1


# ---------------------------------------------------------------------------
# Settings page — getWebhookInfo diagnostics
# ---------------------------------------------------------------------------

INFO = {
    "url": f"https://{DOMAIN}/telegram/webhook/{SECRET}",
    "pending_update_count": 3,
    "last_error_date": 1792000000,
    "last_error_message": "Connection refused",
}


def test_settings_page_webhook_diagnostics_show_info(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, dict(INFO))
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    # Masked URL (secret never rendered), pending count, error + date.
    assert f"••••{SECRET[-4:]}" in page.text
    assert SECRET not in page.text
    assert FA["telegram_webhook_pending"] in page.text
    assert "Connection refused" in page.text
    expected_date = datetime.fromtimestamp(
        1792000000, tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")
    assert expected_date in page.text
    # The fetch is cached (with fetched_at) for the next render.
    stored = json.loads(main_mod.get_setting(db, "telegram_webhook_info"))
    assert stored["pending_update_count"] == 3
    assert stored["fetched_at"]


def test_settings_page_webhook_diagnostics_unavailable_on_failure(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert FA["telegram_webhook_info_unavailable"] in page.text
    # No pending/error rows without data.
    assert FA["telegram_webhook_pending"] not in page.text


def test_settings_page_webhook_diagnostics_use_fresh_cache(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    cached = dict(INFO)
    cached["last_error_message"] = "cached error"
    cached["fetched_at"] = datetime.now(timezone.utc).isoformat()
    main_mod.set_setting(db, "telegram_webhook_info", json.dumps(cached))
    calls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: calls.append(token) or dict(INFO),
    )
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert calls == []  # fresh cache: no fetch
    assert "cached error" in page.text


def test_settings_page_webhook_diagnostics_stale_cache_refetches(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    stale = dict(INFO)
    stale["last_error_message"] = "stale error"
    stale["fetched_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    main_mod.set_setting(db, "telegram_webhook_info", json.dumps(stale))
    fresh = dict(INFO)
    fresh["last_error_message"] = "fresh error"
    calls: list = []
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: calls.append(token) or fresh,
    )
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert len(calls) == 1
    assert "fresh error" in page.text
    assert "stale error" not in page.text


def test_settings_page_webhook_diagnostics_stale_cache_on_fetch_failure(
    authed_client, db, monkeypatch
):
    """A failed fetch falls back to the stale cache — the page shows
    the last known data instead of "unavailable"."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    stale = dict(INFO)
    stale["last_error_message"] = "stale error"
    stale["fetched_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    main_mod.set_setting(db, "telegram_webhook_info", json.dumps(stale))
    _stub_webhook_info(monkeypatch, None)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert "stale error" in page.text
    assert FA["telegram_webhook_info_unavailable"] not in page.text


def test_settings_page_webhook_diagnostics_empty_url_means_not_registered(
    authed_client, db, monkeypatch
):
    """getWebhookInfo with an empty URL is a valid result (no webhook
    set) — not a failure."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(
        monkeypatch, {"url": "", "pending_update_count": 0}
    )
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert FA["telegram_webhook_not_registered"] in page.text
    assert FA["telegram_webhook_info_unavailable"] not in page.text


def test_refresh_webhook_status_stores_fetched_at(
    authed_client, db, monkeypatch
):
    _configure_bot(db)
    _stub_webhook_info(monkeypatch, dict(INFO))
    resp = authed_client.post(
        "/settings/telegram-webhook-status",
        data={"section": "telegram"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    stored = json.loads(main_mod.get_setting(db, "telegram_webhook_info"))
    assert stored["pending_update_count"] == 3
    assert stored["fetched_at"]
    # Same shape as the cache — no stray fields leak in.
    assert set(stored) == {
        "url",
        "pending_update_count",
        "last_error_date",
        "last_error_message",
        "fetched_at",
    }


# ---------------------------------------------------------------------------
# Helpers — direct unit tests
# ---------------------------------------------------------------------------


def test_format_webhook_error_date():
    expected = datetime.fromtimestamp(
        1792000000, tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")
    assert main_mod._format_webhook_error_date(1792000000) == expected
    assert main_mod._format_webhook_error_date("1792000000") == expected
    assert main_mod._format_webhook_error_date(None) is None
    assert main_mod._format_webhook_error_date("not-a-date") is None
    assert main_mod._format_webhook_error_date(99999999999999) is None


def test_webhook_info_fields_keeps_only_known():
    kept = main_mod._webhook_info_fields(
        {
            "url": "https://x/hook",
            "pending_update_count": 2,
            "has_custom_certificate": True,
            "ip_address": "1.2.3.4",
        }
    )
    assert kept == {"url": "https://x/hook", "pending_update_count": 2}


def test_get_webhook_info_cached_invalid_json_refetches(db, monkeypatch):
    main_mod.set_setting(db, "telegram_webhook_info", "not json{")
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: dict(INFO),
    )
    info = main_mod._get_webhook_info_cached(db, TOKEN)
    assert info is not None
    assert info["pending_update_count"] == 3
    assert info["fetched_at"]


def test_get_webhook_info_cached_fetch_exception_returns_stale(
    db, monkeypatch
):
    stale = dict(INFO)
    stale["fetched_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).isoformat()
    main_mod.set_setting(db, "telegram_webhook_info", json.dumps(stale))
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: (_ for _ in ()).throw(RuntimeError("down")),
    )
    # Never raises: the stale cache is returned instead.
    info = main_mod._get_webhook_info_cached(db, TOKEN)
    assert info is not None
    assert info["last_error_message"] == "Connection refused"


def test_get_webhook_info_cached_fetch_exception_no_cache_returns_none(
    db, monkeypatch
):
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: (_ for _ in ()).throw(RuntimeError("down")),
    )
    assert main_mod._get_webhook_info_cached(db, TOKEN) is None


def test_get_webhook_info_cached_fresh_cache_skips_fetch(db, monkeypatch):
    cached = dict(INFO)
    cached["fetched_at"] = datetime.now(timezone.utc).isoformat()
    main_mod.set_setting(db, "telegram_webhook_info", json.dumps(cached))
    monkeypatch.setattr(
        telegram_mod, "get_webhook_info",
        lambda token, **kw: (_ for _ in ()).throw(
            AssertionError("must not fetch")
        ),
    )
    info = main_mod._get_webhook_info_cached(db, TOKEN)
    assert info is not None
    assert info["pending_update_count"] == 3
