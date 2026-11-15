"""User / quota / expiry / traffic tests (DESIGN.md §4).

Written from scratch against the real ``app.models`` usability
rules, the ``/api/users`` + HTML user routes, and
``app.traffic.sync_traffic`` (deltas only, never overwrites).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.links import parse_vmess_link
from app.models import Client, Inbound, User, client_is_usable, user_is_usable
from app.subscription import decode_v2rayng_feed
from app.traffic import is_online, sync_traffic


def _user(**kwargs):
    defaults = {"name": "u", "enabled": True,
                "traffic_limit_bytes": None, "traffic_used_bytes": 0,
                "expires_at": None}
    defaults.update(kwargs)
    return User(**defaults)


def _inbound(**kwargs):
    defaults = {"tag": "t", "core": "xray", "protocol": "vless",
                "port": 443, "enabled": True}
    defaults.update(kwargs)
    return Inbound(**defaults)


def _client(**kwargs):
    defaults = {"user_id": 1, "inbound_id": 1, "enabled": True}
    defaults.update(kwargs)
    return Client(**defaults)


NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# user_is_usable / client_is_usable
# ---------------------------------------------------------------------------

def test_user_usable_unlimited_never_expires():
    assert user_is_usable(_user(), now=NOW) is True


def test_user_unusable_when_disabled():
    assert user_is_usable(_user(enabled=False), now=NOW) is False


def test_user_unusable_when_expired():
    assert user_is_usable(
        _user(expires_at=NOW - timedelta(seconds=1)), now=NOW) is False
    # Expiring exactly now counts as expired (<= now).
    assert user_is_usable(_user(expires_at=NOW), now=NOW) is False
    # One second left is still usable.
    assert user_is_usable(
        _user(expires_at=NOW + timedelta(seconds=1)), now=NOW) is True


def test_user_unusable_when_over_quota():
    assert user_is_usable(
        _user(traffic_limit_bytes=1000, traffic_used_bytes=1000),
        now=NOW) is False
    assert user_is_usable(
        _user(traffic_limit_bytes=1000, traffic_used_bytes=1001),
        now=NOW) is False
    assert user_is_usable(
        _user(traffic_limit_bytes=1000, traffic_used_bytes=999),
        now=NOW) is True
    # Unlimited users never hit a quota, however much they used.
    assert user_is_usable(
        _user(traffic_limit_bytes=None, traffic_used_bytes=10**12),
        now=NOW) is True


def test_user_expiry_naive_datetime_treated_as_utc():
    # SQLite stores datetimes naive; a naive expiry must compare as UTC,
    # never raise.
    naive_past = datetime(2020, 1, 1)
    assert user_is_usable(_user(expires_at=naive_past), now=NOW) is False


@pytest.mark.parametrize("client_on,user_on,inbound_on,expected", [
    (True, True, True, True),
    (False, True, True, False),   # client disabled
    (True, False, True, False),   # user disabled
    (True, True, False, False),   # inbound disabled
    (False, False, False, False),
])
def test_client_is_usable_matrix(client_on, user_on, inbound_on, expected):
    user = _user(enabled=user_on)
    inbound = _inbound(enabled=inbound_on)
    client = _client(enabled=client_on)
    assert client_is_usable(client, user, inbound, now=NOW) is expected


def test_client_is_usable_follows_user_expiry_and_quota():
    inbound = _inbound()
    client = _client()
    assert client_is_usable(
        client, _user(expires_at=NOW - timedelta(days=1)), inbound,
        now=NOW) is False
    assert client_is_usable(
        client,
        _user(traffic_limit_bytes=10, traffic_used_bytes=10), inbound,
        now=NOW) is False


# ---------------------------------------------------------------------------
# Inbound uniqueness is (port, protocol) — DESIGN.md §4 / §3
# ---------------------------------------------------------------------------

def test_inbound_port_443_shared_by_vless_and_hysteria2(db):
    vless = db.query(Inbound).filter(
        Inbound.tag == "vless-reality").first()
    hy2 = db.query(Inbound).filter(Inbound.tag == "hysteria2").first()
    assert vless.port == hy2.port == 443
    assert vless.protocol != hy2.protocol


def test_inbound_same_port_and_protocol_rejected(db):
    db.add(Inbound(tag="vless-copy", core="xray", protocol="vless",
                   port=443, stream_json="{}"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_ensure_defaults_creates_no_inbounds(db_engine):
    """A fresh install seeds no inbounds — only the admin + keys.

    ``ensure_defaults()`` used to create the four default inbounds
    (vless-reality, hysteria2, shadowsocks, wireguard). A fresh
    install now starts empty; the admin adds inbounds from the panel.
    """
    from app.db import SessionLocal
    from app.main import ensure_defaults
    from app.models import Admin

    session = SessionLocal()
    try:
        ensure_defaults(session)
        assert session.query(Admin).count() == 1
        assert session.query(Inbound).count() == 0
        # Idempotent: a second run still creates nothing.
        ensure_defaults(session)
        assert session.query(Admin).count() == 1
        assert session.query(Inbound).count() == 0
    finally:
        session.close()


def test_user_detail_page_renders_copy_label(authed_client, seeded):
    """The copy buttons show the translated label, not a method repr.

    Regression: the template used ``{{ t.copy }}``, which Jinja2
    resolves to the dict's ``copy`` *method* (``<built-in method copy
    of dict object at 0x...>``) instead of the ``"copy"`` translation
    key — the buttons rendered the repr and broke the mobile layout.
    """
    user = next(iter(seeded["users"].values()))
    resp = authed_client.get(f"/users/{user.id}")
    assert resp.status_code == 200, resp.text
    assert "built-in method" not in resp.text
    assert "کپی" in resp.text


# ---------------------------------------------------------------------------
# Creating / toggling / deleting users (API + HTML)
# ---------------------------------------------------------------------------

def test_api_create_user(authed_client, db, seeded):
    resp = authed_client.post("/api/users", json={
        "name": "newbie", "traffic_limit_gb": 10, "expires_days": 30})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "newbie"
    assert body["traffic_limit_bytes"] == 10 * 1024**3
    assert body["expires_at"] is not None
    assert body["sub_token"]
    # One client per enabled inbound (11 seeded inbounds, 1 disabled).
    user = db.query(User).filter(User.name == "newbie").first()
    assert user is not None
    clients = db.query(Client).filter(Client.user_id == user.id).all()
    assert len(clients) == 10
    tags = {db.get(Inbound, c.inbound_id).tag for c in clients}
    assert "vmess-disabled" not in tags
    assert "wireguard" in tags
    # The new user is usable and its subscription answers.
    assert authed_client.get(f"/sub/{user.sub_token}").status_code == 200


def test_api_create_user_duplicate_name_rejected(authed_client):
    assert authed_client.post(
        "/api/users", json={"name": "alice"}).status_code == 409


def test_api_create_user_invalid_name_rejected(authed_client):
    # Pydantic pattern ^[a-zA-Z0-9_-]+$ (names appear in share-link
    # fragments and file names).
    assert authed_client.post(
        "/api/users", json={"name": "bad name!"}).status_code == 422
    assert authed_client.post(
        "/api/users", json={"name": ""}).status_code == 422


def test_api_requires_auth(test_client):
    assert test_client.get("/api/users").status_code == 401
    assert test_client.post(
        "/api/users", json={"name": "x"}).status_code == 401
    assert test_client.get("/api/inbounds").status_code == 401


def test_api_list_users_and_inbounds(authed_client, seeded):
    users = authed_client.get("/api/users").json()
    assert {u["name"] for u in users} == {
        "alice", "bob", "carol", "dave", "eve"}
    assert next(u for u in users if u["name"] == "alice")["enabled"] is True
    inbounds = authed_client.get("/api/inbounds").json()
    assert {i["tag"] for i in inbounds} == set(seeded["inbounds"])


def test_html_create_user(authed_client, db):
    resp = authed_client.post("/users", data={
        "name": "htmluser", "note": "via form",
        "traffic_limit_gb": "5", "expires_days": "7"})
    assert resp.status_code in (200, 303)
    user = db.query(User).filter(User.name == "htmluser").first()
    assert user is not None
    assert user.traffic_limit_bytes == 5 * 1024**3
    assert user.expires_at is not None
    assert user.note == "via form"


def test_html_create_user_duplicate_name_redirects_with_error(authed_client):
    resp = authed_client.post("/users", data={"name": "alice"},
                              follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_toggle_user_flips_enabled(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    assert alice.enabled is True
    resp = authed_client.post(f"/users/{alice.id}/toggle",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, alice.id).enabled is False
    # Phase A item 2 (intentional behavior change): a disabled
    # user gets a 200 with a visible "disabled" placeholder entry
    # in the feed instead of a silent 403.
    resp = authed_client.get(f"/sub/{alice.sub_token}")
    assert resp.status_code == 200
    links = decode_v2rayng_feed(resp.content)
    assert len(links) == 1
    assert "Disabled" in parse_vmess_link(links[0])["name"]
    authed_client.post(f"/users/{alice.id}/toggle", follow_redirects=False)
    db.expire_all()
    assert db.get(User, alice.id).enabled is True
    assert authed_client.get(f"/sub/{alice.sub_token}").status_code == 200


def test_delete_user_removes_user_and_clients(authed_client, db, seeded):
    eve = seeded["users"]["eve"]
    eve_id = eve.id
    assert db.query(Client).filter(Client.user_id == eve_id).count() == 2
    resp = authed_client.post(f"/users/{eve_id}/delete",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()  # the HTTP request deleted the row in another
    # session; this session's identity map still holds the object.
    assert db.get(User, eve_id) is None
    assert db.query(Client).filter(Client.user_id == eve_id).count() == 0
    assert authed_client.post(
        f"/users/{eve_id}/delete").status_code == 404


def test_toggle_and_delete_unknown_user_404(authed_client):
    assert authed_client.post("/users/99999/toggle").status_code == 404


# ---------------------------------------------------------------------------
# Traffic sync: deltas only, never overwrites (DESIGN.md §4/§6.4)
# ---------------------------------------------------------------------------

def test_sync_traffic_applies_xray_deltas(db, seeded):
    alice = seeded["users"]["alice"]
    assert alice.traffic_used_bytes == 0
    summary = sync_traffic(db, xray_stats={alice.id: (1000, 2000)})
    assert summary["users_updated"] == {alice.id: (1000, 2000)}
    assert summary["total_up"] == 1000 and summary["total_down"] == 2000
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 3000
    from app.models import TrafficDaily
    daily = db.query(TrafficDaily).filter(
        TrafficDaily.user_id == alice.id,
        TrafficDaily.date == date.today()).first()
    assert daily is not None
    assert (daily.up_bytes, daily.down_bytes) == (1000, 2000)
    # A second identical delta adds again (deltas accumulate); the
    # daily row is upserted, not duplicated.
    sync_traffic(db, xray_stats={alice.id: (500, 500)})
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 4000
    daily = db.query(TrafficDaily).filter(
        TrafficDaily.user_id == alice.id,
        TrafficDaily.date == date.today()).all()
    assert len(daily) == 1
    assert (daily[0].up_bytes, daily[0].down_bytes) == (1500, 2500)


def test_sync_traffic_wg_baselines_then_deltas(db, seeded):
    alice = seeded["users"]["alice"]
    pub = seeded["alice_wg_public"]
    mapping = {pub: alice.id}
    # First sighting only establishes the baseline: nothing applied.
    first = f"{pub}\t10000\t20000\n"
    summary = sync_traffic(db, wg_text=first, wg_pubkey_to_user_id=mapping)
    assert summary["users_updated"] == {}
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 0
    # Second tick applies only the difference.
    second = f"{pub}\t10100\t20300\n"
    summary = sync_traffic(db, wg_text=second, wg_pubkey_to_user_id=mapping)
    assert summary["users_updated"] == {alice.id: (100, 300)}
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 400
    # Unknown peers and unknown users are ignored, never guessed at.
    summary = sync_traffic(
        db, wg_text=f"unknownkey\t999\t999\n",
        wg_pubkey_to_user_id={"unknownkey": 424242})
    assert summary["users_updated"] == {}


def test_sync_traffic_nft_baselines_then_deltas(db, seeded):
    alice = seeded["users"]["alice"]
    mapping = {8445: alice.id}
    first = "tcp dport 8445 counter packets 10 bytes 5000 accept\n"
    assert sync_traffic(db, nft_text=first,
                        nft_port_to_user_id=mapping)["users_updated"] == {}
    second = "tcp dport 8445 counter packets 12 bytes 5300 accept\n"
    summary = sync_traffic(db, nft_text=second,
                           nft_port_to_user_id=mapping)
    # nft gives one combined byte counter: the delta goes to download.
    assert summary["users_updated"] == {alice.id: (0, 300)}
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 300


def test_sync_traffic_never_overwrites_or_goes_negative(db, seeded):
    alice = seeded["users"]["alice"]
    alice.traffic_used_bytes = 5000
    db.commit()
    # A negative delta (counter reset) is skipped, not subtracted.
    summary = sync_traffic(db, xray_stats={alice.id: (-100, 50)})
    assert summary["users_updated"] == {}
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 5000
    # Unknown user ids are skipped.
    assert sync_traffic(db, xray_stats={999999: (1, 1)})[
        "users_updated"] == {}


def test_is_online_window():
    user = _user(enabled=True)
    assert is_online(user, 60) is True
    assert is_online(user, 180) is True
    assert is_online(user, 181) is False
    assert is_online(user, None) is False
    assert is_online(_user(enabled=False), 10) is False


# ---------------------------------------------------------------------------
# Obsidian Telemetry UI (Stitch design): dashboard + inbounds pages
# ---------------------------------------------------------------------------

def test_dashboard_renders_inbound_nodes_and_distribution(authed_client, seeded):
    """The Stitch dashboard layout renders with real data: inbound
    node cards, the protocol distribution bar, and the activity
    timeline — no fake servers or numbers."""
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200, resp.text
    # Metric cards (real stats).
    assert "metric-card" in resp.text
    # Inbound node cards for the seeded inbounds.
    assert "node-card" in resp.text
    assert "vless-reality" in resp.text
    assert "hysteria2" in resp.text
    # Protocol distribution (bar + legend rows).
    assert "dist-bar" in resp.text
    assert "توزیع پروتکل‌ها" in resp.text
    # Recent activity section (empty state when no audit rows yet).
    assert "فعالیت‌های اخیر" in resp.text
    # No fake Stitch demo data leaks in.
    assert "1,428" not in resp.text
    assert "US-East" not in resp.text


def test_dashboard_activity_shows_audit_entries(authed_client, db, seeded):
    from app.models import AuditLog

    db.add(AuditLog(action="user.create", detail="alice"))
    db.commit()
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200, resp.text
    assert "user.create" in resp.text
    assert "alice" in resp.text


def test_inbounds_page_renders_filter_and_stats(authed_client, seeded):
    """The Stitch configuration screen: filter strip, stats ribbon,
    protocol chips and icon actions — all from the real inbounds."""
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200, resp.text
    assert 'id="inbound-search"' in resp.text
    assert 'id="filter-protocol"' in resp.text
    assert 'id="filter-status"' in resp.text
    assert 'id="inbounds-table"' in resp.text
    # Protocol chips + filter data attributes on the rows.
    assert "chip-proto" in resp.text
    assert 'data-protocol="vless"' in resp.text
    assert 'data-tag="vless-reality"' in resp.text
    # Icon action buttons (toggle/delete) keep their forms.
    assert 'class="icon-btn' in resp.text
    assert "/toggle" in resp.text
    assert "/delete" in resp.text
    # The add form is still on the page (anchor target of the CTA).
    assert 'id="add-inbound"' in resp.text
    assert 'id="add-inbound-form"' in resp.text
    # No fake Stitch data leaks in.
    assert "1,428" not in resp.text
    assert "US-East" not in resp.text


def test_inbounds_page_empty_state_has_no_filter(authed_client, db, seeded):
    """With no inbounds the filter strip and stats hide; the empty
    state and the add form stay."""
    db.query(Client).delete()
    db.query(Inbound).delete()
    db.commit()
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200, resp.text
    assert "هنوز اینباندی ساخته نشده است." in resp.text
    assert 'id="inbound-search"' not in resp.text
    assert 'id="add-inbound-form"' in resp.text
