"""Menu + bot UX polish tests.

Covers: Task A — the bot's guided inbound-create flow for ALL
fourteen protocols the web panel supports (creation succeeds with
the web route's defaults, UDP/TCP coexistence, validation errors
create nothing); Task B — Skip/Back buttons on every guided bot
flow (an empty message cannot be sent on Telegram), the clear-search
button, and the "no 'empty means X' wording" grep test; Task C —
the collapsed Users add form, the mobile filter-search fix, and
the menu-by-menu sweep fixes (logs labels, dashboard empty-state
actions, the deduped webhook diagnostics).

No real network anywhere: bot handlers are driven with fake Telegram
update payloads and the shared FakeSender; web pages render through
TestClient.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app.i18n import t_for
from app.models import Client, Inbound, User
from tests.test_telegram_bot import (
    FakeSender,
    _button_data,
    _callback,
    _configure_bot,
    _dispatch,
    _message,
    _start_flow,
)
from tests.test_webhook_fix import INFO, _stub_webhook_info

FA = t_for("fa")
EN = t_for("en")


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

ALL_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "tuic",
    "anytls",
    "naive",
    "shadowtls",
    "wireguard",
    "amneziawg",
    "openvpn",
    "openconnect",
    "ikev2",
)


def _create_inbound(db, sender, protocol, port):
    """Drive the bot's inbound-create flow to completion (default
    SNI where the protocol has an SNI step) and return the created
    inbound, or None."""
    _dispatch(db, _callback(f"i:new:{protocol}"), sender)
    _dispatch(db, _message(str(port)), sender)
    if protocol in bot_mod.BOT_SNI_PROTOCOLS:
        _dispatch(db, _message(""), sender)  # default SNI
    return (
        db.query(Inbound)
        .filter(Inbound.port == port, Inbound.protocol == protocol)
        .first()
    )


# ---------------------------------------------------------------------------
# Task A — inbound creation for all protocols
# ---------------------------------------------------------------------------


def test_bot_create_protocols_cover_everything():
    assert bot_mod.BOT_CREATE_PROTOCOLS == ALL_PROTOCOLS
    # Every offered protocol maps to exactly one core.
    assert set(bot_mod.BOT_PROTOCOL_CORES) == set(ALL_PROTOCOLS)
    assert bot_mod.BOT_PROTOCOL_CORES["hysteria2"] == "xray"
    assert bot_mod.BOT_PROTOCOL_CORES["tuic"] == "singbox"
    assert bot_mod.BOT_PROTOCOL_CORES["amneziawg"] == "amneziawg"
    assert bot_mod.BOT_PROTOCOL_CORES["ikev2"] == "ikev2"
    # SNI is only meaningful where there is TLS / a handshake target.
    assert set(bot_mod.BOT_SNI_PROTOCOLS) == {
        "vless",
        "vmess",
        "trojan",
        "hysteria2",
        "tuic",
        "anytls",
        "naive",
        "shadowtls",
    }


@pytest.mark.parametrize(
    "protocol,port,core,subnet",
    [
        ("hysteria2", 18101, "xray", None),
        ("tuic", 18102, "singbox", None),
        ("anytls", 18103, "singbox", None),
        ("naive", 18104, "singbox", None),
        ("shadowtls", 18105, "singbox", None),
        ("amneziawg", 18106, "amneziawg", "10.8.1.0/24"),
        ("openvpn", 18107, "openvpn", "10.9.0.0/24"),
        ("openconnect", 18108, "openconnect", "10.10.10.0/24"),
        ("ikev2", 500, "ikev2", "10.20.0.0/24"),
    ],
)
def test_inbound_create_new_protocol(db, sender, protocol, port, core, subnet):
    """Every newly offered protocol creates with the web route's
    defaults (core, subnet, TLS SNI where meaningful)."""
    _configure_bot(db)
    created = _create_inbound(db, sender, protocol, port)
    assert created is not None, f"{protocol} was not created"
    assert created.core == core
    assert created.enabled is True
    stream = json.loads(created.stream_json)
    if subnet is not None:
        assert stream["subnet"] == subnet
    if protocol in bot_mod.BOT_SNI_PROTOCOLS:
        assert stream["tls"]["sni"] == "www.microsoft.com"
        assert stream["security"] == "tls"
    if protocol == "amneziawg":
        assert isinstance(stream["awg_params"], dict)
        assert "Jc" in stream["awg_params"]
    if protocol == "ikev2":
        # Port 500 is IKEv2-reserved — except for an IKEv2 inbound.
        assert created.port == 500


def test_inbound_create_hysteria2_udp_coexists_with_tcp(db, sender, seeded):
    """Hysteria2 (UDP) on the trojan port (TCP 8444) is no clash —
    the same port on different transports may coexist."""
    _configure_bot(db)
    created = _create_inbound(db, sender, "hysteria2", 8444)
    assert created is not None
    stream = json.loads(created.stream_json)
    assert stream["transport"] == "udp"
    assert stream["network"] == "udp"


def test_inbound_create_hysteria2_udp_clashes_with_hysteria2(db, sender, seeded):
    """Hysteria2 (UDP) on 443 clashes with the seeded Hysteria2
    (UDP 443) — the same port on the SAME transport. Nothing is
    created and the flow stays open for a retry."""
    _configure_bot(db)
    _dispatch(db, _callback("i:new:hysteria2"), sender)
    _dispatch(db, _message("443"), sender)
    assert "استفاده شده" in sender.sent[-1][1]
    assert db.query(Inbound).filter(Inbound.port == 443).count() == 2
    _dispatch(db, _message("18111"), sender)
    _dispatch(db, _message(""), sender)
    assert (
        db.query(Inbound)
        .filter(Inbound.port == 18111, Inbound.protocol == "hysteria2")
        .first()
        is not None
    )


def test_inbound_create_wireguard_transport_is_udp(db, sender):
    """Regression: the bot used to store tcp for WireGuard (the
    explicit "tcp" won over the protocol default)."""
    _configure_bot(db)
    created = _create_inbound(db, sender, "wireguard", 18112)
    assert created is not None
    stream = json.loads(created.stream_json)
    assert stream["transport"] == "udp"
    assert stream["network"] == "udp"
    assert stream["subnet"] == "10.8.0.0/24"


def test_inbound_create_new_protocol_bad_input_creates_nothing(db, sender):
    """Validation errors on a new protocol path: no inbound, and
    the error reply carries the step keyboard (Auto / Back /
    Cancel) so the admin is never stranded."""
    _configure_bot(db)
    _dispatch(db, _callback("i:new:tuic"), sender)
    _dispatch(db, _message("abc"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    data = _button_data(sender.sent[-1][2])
    assert "c:skip" in data
    assert "c:back" in data
    assert "c:cancel" in data
    assert db.query(Inbound).filter(Inbound.protocol == "tuic").count() == 1
    # Reserved port (4500 is IKEv2-reserved).
    _dispatch(db, _message("4500"), sender)
    assert "رزرو" in sender.sent[-1][1]
    assert db.query(Inbound).filter(Inbound.protocol == "tuic").count() == 1


# ---------------------------------------------------------------------------
# Task B — Skip / Back on every guided flow
# ---------------------------------------------------------------------------


def test_no_bot_prompt_says_empty():
    """An empty message cannot be sent on Telegram, so no bot
    prompt may say "empty means X" — in either language. (Web form
    labels keep their "empty = ..." wording: empty input works
    fine in a browser form.)"""
    for lang, needle in (("fa", "خالی"), ("en", "empty")):
        for key, value in main_mod.STRINGS[lang].items():
            if key.startswith("bot_"):
                assert needle not in value.lower(), (
                    f"{lang} bot key {key} still says {needle!r}: {value!r}"
                )


def test_skip_buttons_exist_in_both_languages():
    for key in (
        "bot_skip_unlimited",
        "bot_skip_never",
        "bot_skip_auto",
        "bot_skip_default",
        "bot_clear_search",
    ):
        assert key in FA and FA[key]
        assert key in EN and EN[key]
        assert key in bot_mod.BOT_STRING_KEYS


def test_create_flow_skip_limit_and_expiry(db, sender, seeded, rerender_stub):
    """Skip on the limit step means unlimited, Skip on the expiry
    step means never — the user is created with both unset."""
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("skipuser"), sender)
    _dispatch(db, _callback("c:done"), sender)
    # Limit prompt carries Skip / Back / Cancel.
    data = _button_data(sender.edited[-1][3])
    assert "c:skip" in data
    assert "c:back" in data
    assert "c:cancel" in data
    _dispatch(db, _callback("c:skip"), sender)
    # Expiry prompt, again with Skip.
    assert "c:skip" in _button_data(sender.sent[-1][2])
    _dispatch(db, _callback("c:skip"), sender)
    user = db.query(User).filter(User.name == "skipuser").first()
    assert user is not None
    assert user.traffic_limit_bytes is None
    assert user.expires_at is None
    assert rerender_stub


def test_create_flow_back_limit_to_picker_and_picker_to_name(
    db, sender, seeded
):
    """Back from the limit step returns to the inbound picker (with
    the selection kept); Back from the picker returns to the name
    step."""
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("backuser"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _callback("c:back"), sender)
    assert "اینباندهای این کاربر" in sender.edited[-1][2]
    _dispatch(db, _callback("c:back"), sender)
    assert "نام کاربر" in sender.edited[-1][2]
    # The flow is still alive: re-entering the name continues.
    _dispatch(db, _message("backuser"), sender)
    assert "اینباندهای این کاربر" in sender.sent[-1][1]


def test_create_flow_back_expiry_to_limit(db, sender, seeded):
    """Back from the expiry step returns to the limit prompt."""
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("backuser2"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _message("5"), sender)
    assert "انقضا" in sender.sent[-1][1]
    _dispatch(db, _callback("c:back"), sender)
    assert "حجم کاربر" in sender.edited[-1][2]
    assert "c:skip" in _button_data(sender.edited[-1][3])


def test_create_flow_invalid_limit_error_carries_skip_keyboard(
    db, sender, seeded
):
    """After an invalid limit the error message carries the step
    keyboard — the admin can tap Unlimited instead of retyping."""
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _message("badlimit"), sender)
    _dispatch(db, _callback("c:done"), sender)
    _dispatch(db, _message("not-a-number"), sender)
    assert "معتبر نیست" in sender.sent[-1][1]
    data = _button_data(sender.sent[-1][2])
    assert "c:skip" in data
    assert "c:back" in data
    # And Skip still works from the error state.
    _dispatch(db, _callback("c:skip"), sender)
    assert "انقضا" in sender.sent[-1][1]


def test_edit_flow_skip_limit_and_back_to_menu(db, sender, seeded):
    """Edit-limit Skip clears the limit; Back from an edit step
    returns to the edit menu instead of abandoning the user."""
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    alice.traffic_limit_bytes = 5 * 1024**3
    db.commit()
    _dispatch(db, _callback(f"u:edit:{alice.id}:limit"), sender)
    assert "c:skip" in _button_data(sender.edited[-1][3])
    _dispatch(db, _callback("c:skip"), sender)
    db.refresh(alice)
    assert alice.traffic_limit_bytes is None
    # Back from the edit-expiry step shows the edit menu again.
    _dispatch(db, _callback(f"u:edit:{alice.id}:expiry"), sender)
    _dispatch(db, _callback("c:back"), sender)
    assert "ویرایش" in sender.edited[-1][2]


def test_edit_flow_skip_expiry(db, sender, seeded):
    """Edit-expiry Skip clears the expiry date."""
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:edit:{alice.id}:expiry"), sender)
    _dispatch(db, _callback("c:skip"), sender)
    db.refresh(alice)
    assert alice.expires_at is None


def test_search_back_and_clear(db, sender, seeded):
    """Back from the search prompt returns to the user list; the
    results carry a Clear button that drops the filter."""
    _configure_bot(db)
    _dispatch(db, _callback("u:search"), sender)
    assert "c:back" in _button_data(sender.edited[-1][3])
    assert "c:skip" not in _button_data(sender.edited[-1][3])
    _dispatch(db, _callback("c:back"), sender)
    assert "کاربران" in sender.edited[-1][2]
    # Search, then clear.
    _dispatch(db, _callback("u:search"), sender)
    _dispatch(db, _message("alice"), sender)
    data = _button_data(sender.sent[-1][2])
    assert "u:clear" in data
    _dispatch(db, _callback("u:clear"), sender)
    assert "u:clear" not in _button_data(sender.edited[-1][3])
    # The full list is back (both seeded users, not just alice).
    assert "bob" in sender.edited[-1][2]


def test_inbound_flow_skip_port_and_sni(db, sender):
    """Auto (Skip) on the port step picks a port; Default (Skip)
    on the SNI step keeps the panel default."""
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vmess"), sender)
    assert "c:skip" in _button_data(sender.edited[-1][3])
    _dispatch(db, _callback("c:skip"), sender)
    # SNI prompt, again with Skip.
    assert "c:skip" in _button_data(sender.sent[-1][2])
    _dispatch(db, _callback("c:skip"), sender)
    created = (
        db.query(Inbound)
        .filter(Inbound.protocol == "vmess", Inbound.tag != "vmess-ws")
        .all()
    )
    created = [i for i in created if i.tag != "vmess-disabled"]
    assert len(created) == 1
    stream = json.loads(created[0].stream_json)
    assert stream["tls"]["sni"] == "www.microsoft.com"


def test_inbound_flow_back_sni_to_port_and_port_to_picker(db, sender):
    """Back from the SNI step returns to the port prompt; Back
    from the port prompt returns to the protocol picker."""
    _configure_bot(db)
    _dispatch(db, _callback("i:new:vless"), sender)
    _dispatch(db, _message("18121"), sender)
    assert "SNI" in sender.sent[-1][1]
    _dispatch(db, _callback("c:back"), sender)
    assert "پورت اینباند" in sender.edited[-1][2]
    _dispatch(db, _callback("c:back"), sender)
    assert "پروتکل" in sender.edited[-1][2]
    assert "i:new:vless" in _button_data(sender.edited[-1][3])
    # Nothing was created.
    assert db.query(Inbound).filter(Inbound.port == 18121).first() is None


def test_skip_without_flow_shows_stale_not_crash(db, sender):
    """A Skip/Back tap with no active flow (stale keyboard) gets
    the friendly flow-expired answer, never a crash."""
    _configure_bot(db)
    _dispatch(db, _callback("c:skip"), sender)
    assert FA["bot_flow_expired"] in sender.edited[-1][2]
    _dispatch(db, _callback("c:back"), sender)
    assert FA["bot_flow_expired"] in sender.edited[-1][2]


def test_skip_on_name_step_is_stale(db, sender):
    """The name step has no Skip button — a forged Skip tap there
    is a stale tap, not a silent default."""
    _configure_bot(db)
    _start_flow(db, sender)
    _dispatch(db, _callback("c:skip"), sender)
    assert "دیگر معتبر نیست" in sender.edited[-1][2]


# ---------------------------------------------------------------------------
# Task C — web page tidy-up
# ---------------------------------------------------------------------------


def test_users_add_form_collapsed_behind_details(authed_client):
    """The Users add form lives in a closed <details> (like the
    inbounds form): the page shows just a summary button until the
    admin opens it."""
    page = authed_client.get("/users")
    assert page.status_code == 200
    assert '<details class="card add-form" id="add-user">' in page.text
    assert '<summary class="btn btn-primary">' in page.text
    assert 'id="add-user-form"' in page.text
    # The old always-visible heading is gone.
    assert "<h2>" + FA["add_user"] + "</h2>" not in page.text


def test_users_empty_state_links_to_add_form(authed_client, db):
    """With no users, the empty state offers an Add button that
    opens the collapsed form (fragment navigation opens <details>)."""
    db.query(Client).delete()
    db.query(User).delete()
    db.commit()
    page = authed_client.get("/users")
    assert page.status_code == 200
    assert 'href="#add-user-form"' in page.text
    assert FA["no_users"] in page.text


def test_filter_search_fixed_in_mobile_media_query():
    """The 640px media query resets .filter-search's flex-basis —
    in column direction the 220px basis became a 220px-tall empty
    area with the magnifier floating in the middle (Morteza's
    screenshot)."""
    css = (
        Path(main_mod.__file__).parent / "static" / "style.css"
    ).read_text(encoding="utf-8")
    media = css.index("@media (max-width: 640px)")
    fix = css.index(".filter-search { flex: 0 0 auto;")
    assert fix > media


def test_logs_page_button_and_file_status_labels(
    authed_client, tmp_path, monkeypatch
):
    """The logs filter button says Apply (not "Search" again), and
    rotated log files are labelled Archived, not Disabled."""
    from app import panel_log as pl

    monkeypatch.setattr(
        pl,
        "list_log_files",
        lambda data_dir=None: [
            {"name": "panel.log", "size_bytes": 10, "current": True},
            {"name": "panel.log.1", "size_bytes": 5, "current": False},
        ],
    )
    page = authed_client.get("/logs")
    assert page.status_code == 200
    assert f">{FA['filter_apply']}</button>" in page.text
    assert FA["log_file_current"] in page.text
    assert FA["log_file_archived"] in page.text
    # The old misleading badge is gone from the files table.
    assert f">{FA['disabled']}</span>" not in page.text


def test_dashboard_empty_states_offer_add_actions(authed_client, db):
    """An empty dashboard is not a dead end: the inbounds and
    users empty states link to the (collapsed) add forms."""
    db.query(Client).delete()
    db.query(Inbound).delete()
    db.query(User).delete()
    db.commit()
    page = authed_client.get("/dashboard")
    assert page.status_code == 200
    assert 'href="/inbounds#add-inbound-form"' in page.text
    assert 'href="/users#add-user-form"' in page.text


def test_settings_webhook_status_shown_once(
    authed_client, db, monkeypatch
):
    """The webhook pending count / last error appear once — in the
    diagnostics list. The webhook section below shows only the
    registered URL + registration time (no duplication)."""
    _configure_bot(db)
    main_mod.set_setting(db, "telegram_transport", "webhook")
    _stub_webhook_info(monkeypatch, dict(INFO))
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert page.text.count(FA["telegram_webhook_pending"]) == 1
    assert page.text.count(FA["telegram_webhook_last_error"]) == 1
    # The webhook section still shows the registered URL.
    assert FA["telegram_webhook_url"] in page.text


def test_settings_telegram_action_buttons_grouped(
    authed_client, db, monkeypatch
):
    """The Telegram action buttons sit in two wrapping rows
    (diagnostics actions / webhook actions), not five stacked
    single-button rows."""
    _configure_bot(db)
    page = authed_client.get("/settings?section=telegram")
    assert page.status_code == 200
    assert page.text.count('<div class="row-actions">') == 2
