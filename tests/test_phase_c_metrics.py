"""Best-panel program, Phase C item 21 — Prometheus /metrics.

The endpoint is admin-gated (admin session or a ``status:read``
API token) and exposes aggregate counts only — no per-user data,
no credentials, no tokens.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from app import api_tokens as api_tokens_mod
from app import metrics as metrics_mod
from app.models import Client, IpBan, TrafficDaily


def _make_token(db, scopes=("status:read",)):
    row, raw = api_tokens_mod.create_token(db, "scraper", list(scopes))
    return row, raw


# ---------------------------------------------------------------------------
# Formatter (unit level)
# ---------------------------------------------------------------------------


def test_render_metrics_counts_match_seeded_db(db, seeded):
    # Seeded: 5 users (alice usable, bob expired, carol over quota,
    # dave disabled, eve usable), 11 inbounds, 1000 bytes used (carol).
    body = metrics_mod.render_metrics(db)
    assert "sparky_users_total 5" in body
    assert "sparky_users_enabled 4" in body
    assert "sparky_users_active 2" in body
    assert "sparky_inbounds_total 11" in body
    assert 'sparky_inbounds_by_protocol{protocol="vless"} 1' in body
    assert 'sparky_inbounds_by_protocol{protocol="vmess"} 2' in body
    assert 'sparky_inbounds_by_protocol{protocol="wireguard"} 1' in body
    assert "sparky_traffic_used_bytes_total 1000" in body
    assert 'sparky_traffic_today_bytes{direction="up"} 0' in body
    assert 'sparky_traffic_today_bytes{direction="down"} 0' in body
    assert "sparky_ip_bans_active 0" in body
    # HELP + TYPE lines precede every family.
    assert "# HELP sparky_users_total" in body
    assert "# TYPE sparky_users_total gauge" in body


def test_render_metrics_today_traffic_and_bans(db, seeded):
    alice = seeded["users"]["alice"]
    today = date.today()
    db.add(
        TrafficDaily(
            user_id=alice.id,
            date=today,
            up_bytes=123,
            down_bytes=456,
        )
    )
    now = datetime.now(timezone.utc)
    db.add(
        IpBan(
            user_id=alice.id,
            ip="10.0.0.1",
            banned_at=now,
            expires_at=now + timedelta(minutes=30),
        )
    )
    db.add(
        IpBan(
            user_id=alice.id,
            ip="10.0.0.2",
            banned_at=now - timedelta(hours=1),
            expires_at=now - timedelta(minutes=1),
        )
    )
    db.commit()
    body = metrics_mod.render_metrics(db, today=today, now=now)
    assert 'sparky_traffic_today_bytes{direction="up"} 123' in body
    assert 'sparky_traffic_today_bytes{direction="down"} 456' in body
    assert "sparky_ip_bans_active 1" in body  # the expired ban is not counted


def test_render_metrics_core_states(db):
    body = metrics_mod.render_metrics(
        db,
        core_states={"xray": "running", "sing-box": "stopped", "wg0": "unknown"},
    )
    assert 'sparky_core_up{unit="sing-box"} 0' in body
    assert 'sparky_core_up{unit="wg0"} 0' in body
    assert 'sparky_core_up{unit="xray"} 1' in body
    # No states injected: the family is omitted, not invented.
    assert "sparky_core_up" not in metrics_mod.render_metrics(db)


def test_escape_label_value():
    assert metrics_mod.escape_label_value('a"b\\c\nd') == 'a\\"b\\\\c\\nd'
    assert metrics_mod.escape_label_value("plain") == "plain"


def test_render_metrics_exposes_no_per_user_data(db, seeded):
    alice = seeded["users"]["alice"]
    body = metrics_mod.render_metrics(db)
    assert alice.name not in body
    assert alice.sub_token not in body
    # No credential-shaped value at all: no UUIDs, no tokens.
    assert "spk_" not in body


# ---------------------------------------------------------------------------
# Route (auth + content type)
# ---------------------------------------------------------------------------


def test_metrics_unauthenticated_is_401(test_client):
    resp = test_client.get("/metrics")
    assert resp.status_code == 401


def test_metrics_wrong_scope_token_is_403(test_client, db):
    _row, raw = _make_token(db, scopes=("users:read",))
    resp = test_client.get(
        "/metrics", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 403


def test_metrics_invalid_token_is_401(test_client):
    resp = test_client.get(
        "/metrics", headers={"Authorization": "Bearer spk_bogus"}
    )
    assert resp.status_code == 401


def test_metrics_status_token_ok(test_client, db):
    _row, raw = _make_token(db, scopes=("status:read",))
    resp = test_client.get(
        "/metrics", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in resp.headers["content-type"]
    assert "sparky_users_total 5" in resp.text


def test_metrics_admin_token_ok(test_client, db):
    # The admin scope satisfies every check, including status:read.
    _row, raw = _make_token(db, scopes=("admin",))
    resp = test_client.get(
        "/metrics", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 200


def test_metrics_admin_session_ok(authed_client):
    resp = authed_client.get("/metrics")
    assert resp.status_code == 200
    assert "sparky_users_total 5" in resp.text


def test_metrics_never_exposes_credentials(authed_client, db, seeded):
    resp = authed_client.get("/metrics")
    assert resp.status_code == 200
    alice = seeded["users"]["alice"]
    assert alice.name not in resp.text
    assert alice.sub_token not in resp.text
    for client in db.query(Client).all():
        if client.uuid:
            assert client.uuid not in resp.text
        if client.password:
            assert client.password not in resp.text
