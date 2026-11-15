"""Phase 4 (UI/UX redesign) tests.

Covers the users list search / filter / sort / pagination, the
tabbed settings page (including section-preserving POST redirects),
the dashboard server-status block, nav-link resolution, CSRF tokens
on the touched pages, and i18n parity for the new strings.

No browser or screenshot verification is possible in this
environment — these tests assert on the rendered HTML and the
route behavior, not on pixels.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from app import main as main_mod
from app.main import get_setting, t_for
from app.models import Client, User

FA = t_for("fa")

PHASE4_KEYS = [
    "active_today",
    "nav_overview", "nav_management", "nav_monitoring", "nav_system",
    "nav_collapse", "nav_expand", "nav_menu", "nav_close",
    "search_users", "filter_expired", "expired",
    "sort_by", "sort_newest", "sort_name", "sort_expiry", "sort_traffic",
    "filter_apply", "filter_clear",
    "page_of", "page_prev", "page_next", "users_showing",
    "bulk_page_hint",
    "settings_general", "settings_telegram", "settings_security",
    "settings_backup", "settings_services", "settings_advanced",
    "settings_general_desc", "settings_telegram_desc",
    "settings_security_desc", "settings_backup_desc",
    "settings_services_desc", "settings_advanced_desc",
    "domain_hint", "subscription_host_hint", "reality_sni_hint",
    "server_status_unavailable",
]


def _user_link(text: str, user_id: int) -> bool:
    """True when the users table links to this user (name cell)."""
    return f"/users/{user_id}\"" in text


def _row_position(text: str, name: str) -> int:
    """Position of a user's name link in the rendered table."""
    return text.index(f">{name}<")


def _freeze_user(db, user_id: int) -> None:
    """Freeze every client of one user (the user-level frozen flag)."""
    for client in db.query(Client).filter(Client.user_id == user_id).all():
        extra = dict(client.extra or {})
        extra["frozen"] = True
        client.extra = extra
    db.commit()


def _make_users(db, count: int, prefix: str = "u") -> list[User]:
    """Create `count` extra users (for pagination tests)."""
    users = []
    for i in range(count):
        user = User(
            name=f"{prefix}{i:02d}",
            sub_token=secrets.token_urlsafe(24),
        )
        db.add(user)
        users.append(user)
    db.commit()
    return users


# ---------------------------------------------------------------------------
# i18n parity
# ---------------------------------------------------------------------------

def test_phase4_i18n_keys_exist_in_both_languages():
    for key in PHASE4_KEYS:
        assert key in main_mod.STRINGS["fa"], f"missing fa key: {key}"
        assert key in main_mod.STRINGS["en"], f"missing en key: {key}"
        assert main_mod.STRINGS["fa"][key], f"empty fa value: {key}"
        assert main_mod.STRINGS["en"][key], f"empty en value: {key}"
    # The misleading "online now" label was renamed, not duplicated.
    assert "online_now" not in main_mod.STRINGS["fa"]
    assert "online_now" not in main_mod.STRINGS["en"]


# ---------------------------------------------------------------------------
# Users: search
# ---------------------------------------------------------------------------

def test_users_search_by_name(authed_client, seeded):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    resp = authed_client.get("/users?q=ali")
    assert resp.status_code == 200
    assert _user_link(resp.text, alice.id)
    assert not _user_link(resp.text, bob.id)


def test_users_search_by_note(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    db.get(User, alice.id).note = "VIP customer"
    db.commit()
    resp = authed_client.get("/users?q=vip")
    assert resp.status_code == 200
    assert _user_link(resp.text, alice.id)
    assert not _user_link(resp.text, bob.id)


def test_users_search_no_match_shows_empty_state(authed_client):
    resp = authed_client.get("/users?q=zzz-no-such-user")
    assert resp.status_code == 200
    assert FA["no_matches"] in resp.text
    assert FA["filter_clear"] in resp.text


# ---------------------------------------------------------------------------
# Users: status filter
# ---------------------------------------------------------------------------

def test_users_status_filter_enabled_disabled(authed_client, seeded):
    alice = seeded["users"]["alice"]  # enabled
    dave = seeded["users"]["dave"]    # disabled
    resp = authed_client.get("/users?status=enabled")
    assert resp.status_code == 200
    assert _user_link(resp.text, alice.id)
    assert not _user_link(resp.text, dave.id)
    resp = authed_client.get("/users?status=disabled")
    assert resp.status_code == 200
    assert _user_link(resp.text, dave.id)
    assert not _user_link(resp.text, alice.id)


def test_users_status_filter_expired(authed_client, seeded):
    bob = seeded["users"]["bob"]      # expired yesterday
    alice = seeded["users"]["alice"]  # never expires
    resp = authed_client.get("/users?status=expired")
    assert resp.status_code == 200
    assert _user_link(resp.text, bob.id)
    assert not _user_link(resp.text, alice.id)
    # The expired badge shows on the row.
    assert FA["expired"] in resp.text


def test_users_status_filter_frozen(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    _freeze_user(db, alice.id)
    resp = authed_client.get("/users?status=frozen")
    assert resp.status_code == 200
    assert _user_link(resp.text, alice.id)
    assert not _user_link(resp.text, bob.id)
    assert FA["frozen"] in resp.text


# ---------------------------------------------------------------------------
# Users: sort
# ---------------------------------------------------------------------------

def test_users_sort_by_name(authed_client, db):
    _make_users(db, 1, prefix="zoe")
    zoe = db.query(User).filter(User.name == "zoe00").first()
    aaron = User(name="aaron", sub_token=secrets.token_urlsafe(24))
    db.add(aaron)
    db.commit()
    resp = authed_client.get("/users?sort=name")
    assert resp.status_code == 200
    assert _row_position(resp.text, "aaron") < _row_position(resp.text, "alice")
    assert _row_position(resp.text, "eve") < _row_position(resp.text, "zoe00")
    assert zoe is not None  # keeps the helper honest


def test_users_sort_by_traffic(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    eve = seeded["users"]["eve"]
    db.get(User, alice.id).traffic_used_bytes = 100
    db.get(User, bob.id).traffic_used_bytes = 500
    db.get(User, eve.id).traffic_used_bytes = 50
    db.commit()
    resp = authed_client.get("/users?sort=traffic")
    assert resp.status_code == 200
    # carol is seeded at 1000 (most), then bob 500, alice 100, eve 50.
    assert _row_position(resp.text, "carol") < _row_position(resp.text, "bob")
    assert _row_position(resp.text, "bob") < _row_position(resp.text, "alice")
    assert _row_position(resp.text, "alice") < _row_position(resp.text, "eve")


def test_users_sort_by_expiry(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    carol = seeded["users"]["carol"]
    now = datetime.now(timezone.utc)
    db.get(User, alice.id).expires_at = now + timedelta(days=5)
    db.get(User, carol.id).expires_at = now + timedelta(days=2)
    db.commit()
    resp = authed_client.get("/users?sort=expiry")
    assert resp.status_code == 200
    # bob expired yesterday (soonest), then carol (2d), then alice (5d);
    # never-expiring users sort last.
    assert _row_position(resp.text, "bob") < _row_position(resp.text, "carol")
    assert _row_position(resp.text, "carol") < _row_position(resp.text, "alice")
    assert _row_position(resp.text, "alice") < _row_position(resp.text, "dave")


# ---------------------------------------------------------------------------
# Users: pagination + invalid params
# ---------------------------------------------------------------------------

def test_users_pagination(authed_client, db):
    _make_users(db, 30)  # 5 seeded + 30 = 35 users, 2 pages of 25/10
    page1 = authed_client.get("/users")
    assert page1.status_code == 200
    assert page1.text.count('name="user_ids"') == 25
    assert FA["page_of"].format(page=1, pages=2) in page1.text
    assert "page=2" in page1.text
    page2 = authed_client.get("/users?page=2")
    assert page2.status_code == 200
    assert page2.text.count('name="user_ids"') == 10
    assert FA["page_of"].format(page=2, pages=2) in page2.text
    assert "page=1" in page2.text


def test_users_pagination_preserves_filters(authed_client, db):
    _make_users(db, 30)
    resp = authed_client.get("/users?q=u&status=all&sort=name")
    assert resp.status_code == 200
    # The next-page link keeps the current filters.
    assert "q=u" in resp.text
    assert "status=all" in resp.text
    assert "sort=name" in resp.text
    assert "page=2" in resp.text


@pytest.mark.parametrize("query", [
    "page=abc",
    "page=-3",
    "page=0",
    "page=999",
    "status=bogus",
    "sort=bogus",
    "status=",
    "sort=",
])
def test_users_invalid_params_fall_back_to_defaults(authed_client, query):
    resp = authed_client.get(f"/users?{query}")
    assert resp.status_code == 200
    # The page still renders the table (no 500, no empty crash).
    assert FA["users"] in resp.text


def test_users_page_beyond_last_clamps_to_last_page(authed_client, db):
    _make_users(db, 30)
    resp = authed_client.get("/users?page=999")
    assert resp.status_code == 200
    assert FA["page_of"].format(page=2, pages=2) in resp.text
    assert resp.text.count('name="user_ids"') == 10


def test_users_table_has_card_markup(authed_client):
    resp = authed_client.get("/users")
    assert resp.status_code == 200
    assert 'class="table-cards"' in resp.text
    assert f'data-label="{FA["name"]}"' in resp.text
    assert FA["bulk_page_hint"] in resp.text


# ---------------------------------------------------------------------------
# Inbounds: clients column
# ---------------------------------------------------------------------------

def test_inbounds_table_shows_client_counts(authed_client):
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    assert f'data-label="{FA["clients"]}"' in resp.text
    assert 'class="table-cards"' in resp.text


# ---------------------------------------------------------------------------
# Dashboard: server status
# ---------------------------------------------------------------------------

def test_dashboard_includes_server_status(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert FA["server_status"] in resp.text
    # The collector runs against /proc in this environment, so the
    # services list renders with real service names.
    assert "Xray" in resp.text
    assert "sing-box" in resp.text
    # Honest label: "active today", never "online now".
    assert FA["active_today"] in resp.text
    assert "LIVE" not in resp.text


def test_dashboard_server_status_failure_shows_unavailable(
    authed_client, monkeypatch
):
    def _boom(*args, **kwargs):
        raise RuntimeError("no /proc here")

    monkeypatch.setattr(
        main_mod.system_status_mod, "collect_server_status", _boom
    )
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert FA["server_status_unavailable"] in resp.text


# ---------------------------------------------------------------------------
# Settings: tabbed sections
# ---------------------------------------------------------------------------

SECTION_MARKERS = {
    "general": 'name="domain"',
    "telegram": 'name="telegram_bot_token"',
    "security": 'name="current_password"',
    "backup": 'name="backup_file"',
    "services": FA["server_status"],
    "advanced": 'name="log_level"',
}


@pytest.mark.parametrize("section", list(SECTION_MARKERS))
def test_settings_sections_render(authed_client, section):
    resp = authed_client.get(f"/settings?section={section}")
    assert resp.status_code == 200
    # The section's own form/content is present and its tab is active.
    assert SECTION_MARKERS[section] in resp.text
    assert f'data-section="{section}"' in resp.text
    assert 'class="tab-link active"' in resp.text
    # The active panel is not hidden; the others are.
    assert f'data-panel="{section}" hidden' not in resp.text


def test_settings_invalid_section_falls_back_to_general(authed_client):
    resp = authed_client.get("/settings?section=bogus")
    assert resp.status_code == 200
    assert 'data-section="general"' in resp.text
    assert 'class="tab-link active"' in resp.text
    assert 'data-panel="general" hidden' not in resp.text


def test_settings_tab_links_all_resolve(authed_client):
    resp = authed_client.get("/settings")
    assert resp.status_code == 200
    hrefs = re.findall(r'class="tab-link[^"]*" href="([^"]+)"', resp.text)
    assert len(hrefs) == 6
    for href in hrefs:
        page = authed_client.get(href)
        assert page.status_code == 200, href


def test_settings_post_preserves_section(authed_client):
    # A General-tab save returns to the General tab.
    resp = authed_client.post(
        "/settings",
        data={"domain": "example.com", "section": "general"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "section=general" in resp.headers["location"]
    # A failed password change returns to the Security tab.
    resp = authed_client.post(
        "/settings/password",
        data={
            "current_password": "wrong",
            "new_password": "NewPass123456",
            "confirm_password": "NewPass123456",
            "section": "security",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "section=security" in resp.headers["location"]
    # A restore without a file returns to the Backup tab.
    resp = authed_client.post(
        "/settings/restore",
        data={"section": "backup"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "section=backup" in resp.headers["location"]


def test_settings_partial_update_leaves_other_fields(authed_client, db):
    """Each tab posts only its own fields — absent fields are kept."""
    resp = authed_client.post(
        "/settings",
        data={"domain": "example.com", "section": "general"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert get_setting(db, "domain") == "example.com"
    resp = authed_client.post(
        "/settings",
        data={"log_level": "DEBUG", "section": "advanced"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert get_setting(db, "log_level") == "DEBUG"
    # The Advanced-tab post did not clear the General-tab field.
    assert get_setting(db, "domain") == "example.com"


# ---------------------------------------------------------------------------
# Navigation: every nav href resolves
# ---------------------------------------------------------------------------

def test_every_nav_link_resolves(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    hrefs = re.findall(r'class="nav-link[^"]*" href="([^"]+)"', resp.text)
    # Dashboard, Inbounds, Users, Plans, Logs, Self-check, Audit,
    # Settings, Cores, Tools, API tokens, Webhooks — no dead links.
    # (Phase B added the last four: Plans, Audit, API tokens,
    # Webhooks.)
    assert len(hrefs) == 12, hrefs
    for href in hrefs:
        page = authed_client.get(href)
        assert page.status_code == 200, href


def test_sidebar_cta_and_brand_resolve(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    # The CTA links to the form INSIDE the collapsed <details>:
    # navigating to a fragment inside a closed details opens it.
    assert 'href="/inbounds#add-inbound-form"' in resp.text
    page = authed_client.get("/inbounds")
    assert page.status_code == 200
    assert 'id="add-inbound"' in page.text


# ---------------------------------------------------------------------------
# CSRF tokens on the touched pages (parameterized variants)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/users?q=alice&status=all&sort=name&page=1",
    "/users?status=frozen",
    "/settings?section=telegram",
    "/settings?section=security",
    "/settings?section=backup",
    "/settings?section=services",
    "/settings?section=advanced",
    "/dashboard",
])
def test_phase4_pages_post_forms_carry_csrf_token(
    authed_client, db, seeded, path
):
    resp = authed_client.get(path)
    assert resp.status_code == 200
    forms = resp.text.count('<form method="post"')
    tokens = resp.text.count('name="csrf_token"')
    assert forms > 0, f"{path} has no POST forms to check"
    assert tokens == forms, (
        f"{path}: {forms} POST forms but {tokens} CSRF fields")
