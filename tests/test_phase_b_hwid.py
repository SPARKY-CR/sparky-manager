"""Phase B items 17 + 19 — HWID device limits and last-fetch stamps.

The device limit ships OFF by default (no limit = the feature is
off for that client). Enforcement happens ONLY at subscription
fetch: a device over the limit has its client OMITTED from the feed
(not a whole-feed 404). Clients that send no HWID header are NEVER
registered or limited — v2rayNG / Hiddify send no HWID, so a limit
must never lock them out (the documented 404 trap).

Item 19: ``last_fetch_at`` is stamped (ISO UTC, in the client's
``extra_json``) on every client a raw feed actually served — the
browser copy-only page does not stamp, and HWID-excluded clients
are not stamped either.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import devices as devices_mod
from app.models import Client, Device

UTC = timezone.utc
CLIENT_UA = "v2rayNG/1.9.0"
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def _vless_links(resp) -> list[str]:
    """The vless:// lines in a v2rayng feed response."""
    body = base64.b64decode(resp.content).decode("utf-8", "replace")
    return [line for line in body.splitlines() if line.startswith("vless://")]


def _set_limit(db, client, limit):
    devices_mod.set_hwid_limit(client, limit)
    db.commit()


# ---------------------------------------------------------------------------
# Limit parsing + storage (item 17)
# ---------------------------------------------------------------------------

def test_parse_hwid_limit():
    assert devices_mod.parse_hwid_limit("") is None
    assert devices_mod.parse_hwid_limit("  ") is None
    assert devices_mod.parse_hwid_limit("0") is None
    assert devices_mod.parse_hwid_limit("1") == 1
    assert devices_mod.parse_hwid_limit("100") == 100
    for bad in ("101", "-1", "abc", "1.5"):
        with pytest.raises(ValueError):
            devices_mod.parse_hwid_limit(bad)


def test_get_set_hwid_limit_roundtrip(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    assert devices_mod.get_hwid_limit(client) is None  # off by default
    _set_limit(db, client, 3)
    db.refresh(client)
    assert devices_mod.get_hwid_limit(client) == 3
    _set_limit(db, client, None)
    db.refresh(client)
    assert devices_mod.get_hwid_limit(client) is None


def test_get_hwid_limit_ignores_garbage(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    client.extra_json = json.dumps({"hwid_limit": "nonsense"})
    db.commit()
    assert devices_mod.get_hwid_limit(client) is None
    client.extra_json = json.dumps({"hwid_limit": 500})
    db.commit()
    assert devices_mod.get_hwid_limit(client) is None  # over the max


# ---------------------------------------------------------------------------
# Registration + first-come-first-served enforcement (item 17)
# ---------------------------------------------------------------------------

def test_register_device_upserts(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    first = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    device = devices_mod.register_device(
        db, client, "hwid-1", "Android", "Pixel", now=first
    )
    assert device.first_seen_at.replace(tzinfo=UTC) == first
    assert device.os == "Android"
    later = first + timedelta(days=2)
    same = devices_mod.register_device(
        db, client, "hwid-1", "Android", "Pixel 8", now=later
    )
    assert same.id == device.id
    assert same.first_seen_at.replace(tzinfo=UTC) == first
    assert same.last_seen_at.replace(tzinfo=UTC) == later
    assert same.model == "Pixel 8"
    assert db.query(Device).count() == 1


def test_check_and_register_first_come_first_served(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    _set_limit(db, client, 1)
    # First device: allowed.
    assert devices_mod.check_and_register(db, [client], "hwid-A") == set()
    # Second device: over the limit — the client is excluded.
    assert devices_mod.check_and_register(db, [client], "hwid-B") == {
        client.id
    }
    # The first device fetching again is still allowed (a blocked
    # device cannot displace an allowed one by re-fetching).
    assert devices_mod.check_and_register(db, [client], "hwid-A") == set()


def test_check_and_register_no_hwid_registers_nothing(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    _set_limit(db, client, 1)
    assert devices_mod.check_and_register(db, [client], None) == set()
    assert devices_mod.check_and_register(db, [client], "  ") == set()
    assert db.query(Device).count() == 0


def test_check_and_register_no_limit_never_excludes(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    for i in range(5):
        assert devices_mod.check_and_register(
            db, [client], f"hwid-{i}"
        ) == set()
    # Devices are still TRACKED without a limit (the table records
    # devices whether or not a limit is set).
    assert db.query(Device).count() == 5


def test_remove_device_frees_slot_and_checks_ownership(db, seeded):
    alice_vless = seeded["clients"][("alice", "vless-reality")]
    bob_vless = seeded["clients"][("bob", "vless-reality")]
    _set_limit(db, alice_vless, 1)
    devices_mod.check_and_register(db, [alice_vless], "hwid-A")
    devices_mod.check_and_register(db, [alice_vless], "hwid-B")
    # Another user's device id cannot be removed through this user.
    bob_device = devices_mod.register_device(db, bob_vless, "hwid-X")
    assert devices_mod.remove_device(
        db, bob_device.id, seeded["users"]["alice"].id
    ) is False
    assert db.get(Device, bob_device.id) is not None
    # Removing the blocked device frees nothing (it was not using a
    # slot); removing the allowed one lets the blocked one in.
    device_a = (
        db.query(Device)
        .filter(Device.client_id == alice_vless.id, Device.hwid == "hwid-A")
        .one()
    )
    assert devices_mod.remove_device(
        db, device_a.id, seeded["users"]["alice"].id
    ) is True
    assert devices_mod.check_and_register(db, [alice_vless], "hwid-B") == set()


def test_devices_for_user_marks_allowed(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    _set_limit(db, client, 1)
    devices_mod.check_and_register(db, [client], "hwid-A")
    devices_mod.check_and_register(db, [client], "hwid-B")
    rows = devices_mod.devices_for_user(db, seeded["users"]["alice"].id)
    by_hwid = {row["device"].hwid: row for row in rows}
    assert by_hwid["hwid-A"]["allowed"] is True
    assert by_hwid["hwid-B"]["allowed"] is False
    assert by_hwid["hwid-A"]["inbound"].tag == "vless-reality"


# ---------------------------------------------------------------------------
# TTL cleanup (item 17)
# ---------------------------------------------------------------------------

def test_prune_devices_removes_only_stale(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    now = datetime.now(UTC)
    devices_mod.register_device(
        db, client, "old", now=now - timedelta(days=100)
    )
    devices_mod.register_device(db, client, "fresh", now=now)
    assert devices_mod.prune_devices(db, ttl_days=90, now=now) == 1
    remaining = [d.hwid for d in db.query(Device).all()]
    assert remaining == ["fresh"]


def test_prune_devices_zero_ttl_never_prunes(db, seeded):
    client = seeded["clients"][("alice", "vless-reality")]
    devices_mod.register_device(
        db, client, "ancient",
        now=datetime.now(UTC) - timedelta(days=3650),
    )
    assert devices_mod.prune_devices(db, ttl_days=0) == 0
    assert db.query(Device).count() == 1


def test_get_ttl_days_default_and_bad_value(db):
    from app.webcommon import set_setting

    assert devices_mod.get_ttl_days(db) == 90
    set_setting(db, "hwid_device_ttl_days", "30")
    assert devices_mod.get_ttl_days(db) == 30
    set_setting(db, "hwid_device_ttl_days", "not-a-number")
    assert devices_mod.get_ttl_days(db) == 90
    set_setting(db, "hwid_device_ttl_days", "-5")
    assert devices_mod.get_ttl_days(db) == 90
    set_setting(db, "hwid_device_ttl_days", "0")
    assert devices_mod.get_ttl_days(db) == 0


# ---------------------------------------------------------------------------
# HTTP: the feed omits over-limit clients, never 404s (item 17)
# ---------------------------------------------------------------------------

def test_feed_omits_over_limit_client(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    _set_limit(db, vless, 1)
    headers_a = {"user-agent": CLIENT_UA, "x-hwid": "device-A"}
    resp = test_client.get(f"/sub/{alice.sub_token}", headers=headers_a)
    assert resp.status_code == 200
    assert len(_vless_links(resp)) == 1  # device A is allowed
    headers_b = {"user-agent": CLIENT_UA, "x-hwid": "device-B"}
    resp = test_client.get(f"/sub/{alice.sub_token}", headers=headers_b)
    assert resp.status_code == 200  # still 200 — never a 404
    assert _vless_links(resp) == []  # device B is over the limit
    # … but the rest of the feed is intact (other protocols served).
    body = base64.b64decode(resp.content).decode("utf-8", "replace")
    assert "trojan://" in body


def test_feed_without_hwid_header_serves_everything(test_client, db, seeded):
    """The 404 trap, inverted: a client that sends no HWID (v2rayNG,
    Hiddify) gets the WHOLE feed even when limits are set."""
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    _set_limit(db, vless, 1)
    devices_mod.check_and_register(db, [vless], "device-A")
    resp = test_client.get(
        f"/sub/{alice.sub_token}", headers={"user-agent": CLIENT_UA}
    )
    assert resp.status_code == 200
    assert len(_vless_links(resp)) == 1
    # No device was registered by the header-less fetch.
    assert db.query(Device).count() == 1


def test_feed_registers_device_os_and_model(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    resp = test_client.get(
        f"/sub/{alice.sub_token}",
        headers={
            "user-agent": CLIENT_UA,
            "x-hwid": "phone-1",
            "x-device-os": "Android",
            "x-device-model": "Pixel 8",
        },
    )
    assert resp.status_code == 200
    device = db.query(Device).filter_by(hwid="phone-1").first()
    assert device is not None
    assert device.os == "Android"
    assert device.model == "Pixel 8"


def test_device_remove_via_post(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    client = seeded["clients"][("alice", "vless-reality")]
    device = devices_mod.register_device(db, client, "hwid-1")
    device_id = device.id
    resp = authed_client.post(
        f"/users/{alice.id}/devices/{device_id}/delete",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(Device, device_id) is None


def test_edit_user_saves_hwid_limit(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data={"name": "alice", f"hwid_limit_{vless.id}": "2"},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    db.refresh(vless)
    assert devices_mod.get_hwid_limit(vless) == 2


def test_edit_user_rejects_bad_hwid_limit(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data={"name": "alice", f"hwid_limit_{vless.id}": "101"},
        follow_redirects=False,
    )
    assert resp.status_code == 200  # re-rendered with an error
    db.refresh(vless)
    assert devices_mod.get_hwid_limit(vless) is None


def test_user_detail_shows_devices(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    client = seeded["clients"][("alice", "vless-reality")]
    devices_mod.register_device(db, client, "hwid-1", "Android", "Pixel")
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "Android" in resp.text
    assert "Pixel" in resp.text


# ---------------------------------------------------------------------------
# Last fetch (item 19)
# ---------------------------------------------------------------------------

def test_raw_feed_stamps_last_fetch(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    assert vless.extra.get("last_fetch_at") is None
    resp = test_client.get(
        f"/sub/{alice.sub_token}", headers={"user-agent": CLIENT_UA}
    )
    assert resp.status_code == 200
    db.expire_all()
    client = db.get(Client, vless.id)
    stamp = client.extra.get("last_fetch_at")
    assert stamp is not None
    # ISO UTC, within the last minute.
    parsed = datetime.fromisoformat(stamp)
    assert datetime.now(UTC) - parsed < timedelta(minutes=1)


def test_browser_page_does_not_stamp_last_fetch(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    resp = test_client.get(
        f"/sub/{alice.sub_token}", headers={"user-agent": BROWSER_UA}
    )
    assert resp.status_code == 200
    db.expire_all()
    client = db.get(Client, vless.id)
    assert client.extra.get("last_fetch_at") is None


def test_excluded_client_is_not_stamped(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    trojan = seeded["clients"][("alice", "trojan-tls")]
    # Give the VLESS client a known old stamp FIRST (writing
    # extra_json directly replaces the whole dict — the limit is
    # set after, via the merging setter, so it survives).
    vless.extra_json = json.dumps({"last_fetch_at": "2020-01-01T00:00:00+00:00"})
    db.commit()
    _set_limit(db, vless, 1)
    devices_mod.check_and_register(db, [vless], "device-A")
    resp = test_client.get(
        f"/sub/{alice.sub_token}",
        headers={"user-agent": CLIENT_UA, "x-hwid": "device-B"},
    )
    assert resp.status_code == 200
    db.expire_all()
    assert (
        db.get(Client, vless.id).extra.get("last_fetch_at")
        == "2020-01-01T00:00:00+00:00"
    )
    # The served clients got a fresh stamp.
    assert db.get(Client, trojan.id).extra.get("last_fetch_at") is not None


def test_last_fetch_shown_on_user_detail(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    vless.extra_json = json.dumps({"last_fetch_at": "2026-11-16T10:30:00+00:00"})
    db.commit()
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "2026-11-16 10:30" in resp.text
