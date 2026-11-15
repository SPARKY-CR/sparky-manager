"""Phase A items 2 + 6 tests — subscription improvements and the
per-user public page.

Remark variables ({USER}/{INBOUND}/{DATA_LEFT}/{DAYS_LEFT}),
the browser copy-only subscription page, placeholder feeds (the
403→placeholder change is asserted in test_subscription.py),
and the data-left/days-left chips on the /u/ page.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import subscription as subscription_mod


def _user(**overrides):
    """A duck-typed user for the pure remark helpers."""
    data = {
        "name": "ali",
        "traffic_used_bytes": 1_000_000_000,
        "traffic_limit_bytes": 5_000_000_000,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=12, hours=3),
    }
    data.update(overrides)
    return SimpleNamespace(**data)


# ---------------------------------------------------------------------------
# Remark variables
# ---------------------------------------------------------------------------

def test_default_template_is_user_dash_inbound():
    assert subscription_mod.expand_remark_variables(
        None, _user(), "vless-1"
    ) == "ali-vless-1"
    assert subscription_mod.expand_remark_variables(
        "", _user(), "vless-1"
    ) == "ali-vless-1"
    assert subscription_mod.expand_remark_variables(
        "   ", _user(), "vless-1"
    ) == "ali-vless-1"


def test_all_four_variables_expand():
    out = subscription_mod.expand_remark_variables(
        "{USER} | {INBOUND} | {DATA_LEFT} | {DAYS_LEFT}d",
        _user(
            traffic_used_bytes=1 * 1024 ** 3,
            traffic_limit_bytes=5 * 1024 ** 3,
        ),
        "vless-1",
    )
    # 5 GiB limit − 1 GiB used = 4 GiB left; 12 days + 3h → 12 days.
    assert out == "ali | vless-1 | 4 GB | 12d"


def test_unlimited_and_never_expire_use_infinity():
    out = subscription_mod.expand_remark_variables(
        "{DATA_LEFT} / {DAYS_LEFT}",
        _user(traffic_limit_bytes=None, expires_at=None), "vless-1",
    )
    assert out == "∞ / ∞"


def test_exhausted_quota_and_past_expiry_show_zero():
    out = subscription_mod.expand_remark_variables(
        "{DATA_LEFT} / {DAYS_LEFT}",
        _user(
            traffic_used_bytes=6_000_000_000,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        ),
        "vless-1",
    )
    assert out == "0 B / 0"


def test_unknown_variable_is_left_untouched():
    # A typo must stay visible, not silently vanish.
    out = subscription_mod.expand_remark_variables(
        "{USER} {DATA_LETF}", _user(), "vless-1"
    )
    assert out == "ali {DATA_LETF}"


def test_format_data_left_units():
    assert subscription_mod.format_data_left(0, 500) == "500 B"
    assert subscription_mod.format_data_left(0, 2_500_000) == "2.4 MB"
    assert subscription_mod.format_data_left(0, None) == "∞"


# ---------------------------------------------------------------------------
# Remark template in the live feeds
# ---------------------------------------------------------------------------

def test_remark_template_applies_to_singbox_tags(
        test_client, seeded, db):
    from app.webcommon import set_setting

    set_setting(db, "sub_remark_template", "{USER} | {DATA_LEFT}")
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}?format=singbox")
    assert resp.status_code == 200
    tags = [o["tag"] for o in resp.json()["outbounds"]]
    assert tags, "alice has no sing-box outbounds in the test feed"
    # alice is unlimited, so {DATA_LEFT} expands to ∞. (ShadowTLS
    # contributes a second outbound tagged "{tag}-ss", hence the
    # prefix check rather than an exact match.)
    assert all(tag.startswith("alice | ∞") for tag in tags), tags


def test_remark_template_default_matches_old_singbox_tags(
        test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}?format=singbox")
    assert resp.status_code == 200
    tags = [o["tag"] for o in resp.json()["outbounds"]]
    assert tags
    assert all(tag.startswith("alice-") for tag in tags), tags


def test_remark_template_setting_round_trips(authed_client, db, tmp_path):
    from app.webcommon import get_setting, set_setting

    # Dummy TLS certs so the post-save re-render is clean.
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    set_setting(db, "cert_path", str(cert))
    set_setting(db, "key_path", str(key))
    resp = authed_client.post(
        "/settings",
        data={
            "section": "general",
            "sub_remark_template": "{USER} ({DAYS_LEFT}d)",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" not in resp.headers["location"]
    assert get_setting(db, "sub_remark_template") == "{USER} ({DAYS_LEFT}d)"


# ---------------------------------------------------------------------------
# Browser copy-only page
# ---------------------------------------------------------------------------

BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"
)
CLIENT_UA = "v2rayNG/1.9.0"


def test_browser_gets_copy_only_page(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}", headers={"user-agent": BROWSER_UA})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "alice" in resp.text
    # Copy buttons + QR images, no raw base64 dump.
    assert 'data-copy="' in resp.text
    assert "/qr?link=" in resp.text
    assert "?view=raw" in resp.text


def test_view_html_forces_copy_page_even_for_client_ua(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(
        f"/sub/{token}?view=html", headers={"user-agent": CLIENT_UA})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_view_raw_forces_raw_feed_even_for_browser_ua(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(
        f"/sub/{token}?view=raw", headers={"user-agent": BROWSER_UA})
    assert resp.status_code == 200
    assert "text/html" not in resp.headers["content-type"]
    links = subscription_mod.decode_v2rayng_feed(resp.content)
    assert links


def test_client_ua_gets_raw_feed(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}", headers={"user-agent": CLIENT_UA})
    assert resp.status_code == 200
    assert "text/html" not in resp.headers["content-type"]
    assert subscription_mod.decode_v2rayng_feed(resp.content)


def test_empty_ua_gets_raw_feed(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}", headers={"user-agent": ""})
    assert resp.status_code == 200
    assert "text/html" not in resp.headers["content-type"]


def test_copy_page_shows_only_this_users_links(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}", headers={"user-agent": BROWSER_UA})
    assert resp.status_code == 200
    # No other user's token or name anywhere on the page.
    for name in ("bob", "carol", "dave", "eve"):
        assert seeded["users"][name].sub_token not in resp.text, name
    assert "bob" not in resp.text
    assert "carol" not in resp.text


def test_copy_page_unknown_token_still_403(test_client):
    resp = test_client.get(
        "/sub/this-token-does-not-exist?view=html",
        headers={"user-agent": BROWSER_UA},
    )
    assert resp.status_code == 403
    assert resp.content == b""


def test_is_browser_user_agent():
    assert subscription_mod.is_browser_user_agent(BROWSER_UA) is True
    assert subscription_mod.is_browser_user_agent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
    ) is True
    assert subscription_mod.is_browser_user_agent(CLIENT_UA) is False
    assert subscription_mod.is_browser_user_agent("testclient") is False
    assert subscription_mod.is_browser_user_agent("") is False
    assert subscription_mod.is_browser_user_agent(None) is False
    # A client that embeds a Mozilla UA still counts as a client.
    assert subscription_mod.is_browser_user_agent(
        "Mozilla/5.0 Hiddify/2.0"
    ) is False


# ---------------------------------------------------------------------------
# Per-user public page (item 6)
# ---------------------------------------------------------------------------

def test_user_page_shows_data_left_and_days_left(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/u/{token}")
    assert resp.status_code == 200
    # alice is unlimited and never expires.
    assert "∞" in resp.text


def test_user_page_shows_remaining_for_limited_user(
        test_client, seeded, db):
    from app.models import User

    # Give eve a limit + an expiry so the chips show real numbers.
    eve = db.query(User).filter(User.name == "eve").first()
    eve.traffic_limit_bytes = 10 * 1024 ** 3
    eve.traffic_used_bytes = 1 * 1024 ** 3
    eve.expires_at = datetime.now(timezone.utc) + timedelta(days=5, hours=1)
    db.commit()
    resp = test_client.get(f"/u/{eve.sub_token}")
    assert resp.status_code == 200
    # 10 GiB − 1 GiB = 9 GiB left; 5 days + 1h → 5 whole days.
    assert ">9 GB<" in resp.text
    assert ">5<" in resp.text


def test_rotated_token_404s_on_user_page(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    old_token = alice.sub_token
    resp = authed_client.post(
        f"/users/{alice.id}/rotate-token", follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    assert authed_client.get(f"/u/{old_token}").status_code == 404
    from app.models import User

    new_token = db.get(User, alice.id).sub_token
    assert new_token != old_token
    assert authed_client.get(f"/u/{new_token}").status_code == 200
