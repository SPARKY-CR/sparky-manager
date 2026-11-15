"""Phase B item 18 — managed hosts (per-inbound endpoint overrides).

A managed host replaces the address (and optionally the port and
SNI) an inbound's generated links and feeds use — the first enabled
host wins. The server-side configs never carry hosts (only links
and feeds do), so adding a host needs no re-render. File exports
(.conf / .ovpn / .mobileconfig) always use the default host — a
documented limitation, not an oversight: those files are generated
from the inbound alone.
"""

from __future__ import annotations

import pytest

from app import hosts as hosts_mod
from app import main as main_mod
from app.models import ManagedHost


def _host(db, inbound_id, address="cdn.example.com", **kwargs):
    host = hosts_mod.create_host(db, inbound_id, address, **kwargs)
    assert host is not None
    return host


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_validate_host_accepts_domain_ip_and_ipv6():
    assert hosts_mod.validate_host("cdn.example.com", None, None) is None
    assert hosts_mod.validate_host("203.0.113.10", 8443, None) is None
    assert hosts_mod.validate_host("2001:db8::1", None, None) is None
    assert hosts_mod.validate_host("a-b.example.com", 1, "sni.example.com") is None
    assert hosts_mod.validate_host("host", 65535, None) is None


def test_validate_host_rejects_bad_values():
    assert hosts_mod.validate_host("", None, None) == "invalid_host_address"
    assert hosts_mod.validate_host("has space", None, None) == "invalid_host_address"
    assert hosts_mod.validate_host("bad;char", None, None) == "invalid_host_address"
    assert hosts_mod.validate_host("ok.com", 0, None) == "invalid_host_port"
    assert hosts_mod.validate_host("ok.com", 65536, None) == "invalid_host_port"
    assert hosts_mod.validate_host("ok.com", -1, None) == "invalid_host_port"
    assert hosts_mod.validate_host("ok.com", None, "bad sni") == "invalid_host_sni"
    assert hosts_mod.validate_host("ok.com", None, "bad:sni") == "invalid_host_sni"


# ---------------------------------------------------------------------------
# Precedence: first enabled host wins
# ---------------------------------------------------------------------------

def test_active_host_is_first_enabled(db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    first = _host(db, vless.id, "first.example.com")
    second = _host(db, vless.id, "second.example.com")
    assert hosts_mod.active_host_for_inbound(db, vless.id).id == first.id
    first.enabled = False
    db.commit()
    assert hosts_mod.active_host_for_inbound(db, vless.id).id == second.id
    second.enabled = False
    db.commit()
    assert hosts_mod.active_host_for_inbound(db, vless.id) is None


def test_hosts_ordered_by_sort_order_then_id(db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    late = _host(db, vless.id, "late.example.com", sort_order=10)
    early = _host(db, vless.id, "early.example.com", sort_order=1)
    hosts = hosts_mod.hosts_for_inbound(db, vless.id)
    assert [h.id for h in hosts] == [early.id, late.id]
    assert hosts_mod.active_host_for_inbound(db, vless.id).id == early.id


def test_active_hosts_batched(db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    trojan = seeded["inbounds"]["trojan-tls"]
    h1 = _host(db, vless.id, "one.example.com")
    h2 = _host(db, trojan.id, "two.example.com")
    mapping = hosts_mod.active_hosts_for_inbounds(db, [vless.id, trojan.id, 99999])
    assert mapping[vless.id].id == h1.id
    assert mapping[trojan.id].id == h2.id
    assert 99999 not in mapping


# ---------------------------------------------------------------------------
# The override itself
# ---------------------------------------------------------------------------

def test_apply_override_changes_host_port_sni_not_reality_keys():
    inbound = {
        "tag": "vless-reality",
        "protocol": "vless",
        "port": 443,
        "stream_json": {
            "sni": "www.microsoft.com",
            "tls": {"sni": "www.microsoft.com"},
            "reality": {
                "sni": "www.microsoft.com",
                "public_key": "PUBKEY",
                "short_id": "abcd1234",
            },
        },
    }
    host = ManagedHost(
        address="cdn.example.com", port=8443, sni="cdn.example.com"
    )
    link_host, out = hosts_mod.apply_host_override(inbound, host, "203.0.113.10")
    assert link_host == "cdn.example.com"
    assert out["port"] == 8443
    assert out["stream_json"]["sni"] == "cdn.example.com"
    assert out["stream_json"]["tls"]["sni"] == "cdn.example.com"
    assert out["stream_json"]["reality"]["sni"] == "cdn.example.com"
    # The Reality identity is untouched — only the server name changes.
    assert out["stream_json"]["reality"]["public_key"] == "PUBKEY"
    assert out["stream_json"]["reality"]["short_id"] == "abcd1234"
    # The input dict is not mutated (a copy is returned).
    assert inbound["port"] == 443
    assert inbound["stream_json"]["sni"] == "www.microsoft.com"


def test_apply_override_without_host_passes_through():
    inbound = {"tag": "x", "port": 443}
    link_host, out = hosts_mod.apply_host_override(inbound, None, "203.0.113.10")
    assert link_host == "203.0.113.10"
    assert out is inbound


def test_apply_override_empty_port_keeps_inbound_port():
    inbound = {"tag": "x", "port": 443, "stream_json": {}}
    host = ManagedHost(address="cdn.example.com", port=None, sni=None)
    _link_host, out = hosts_mod.apply_host_override(inbound, host, "h")
    assert out["port"] == 443


# ---------------------------------------------------------------------------
# Links + feeds use the override (HTTP-level)
# ---------------------------------------------------------------------------

def test_share_link_uses_managed_host(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    _host(db, vless.id, "cdn.example.com", port=8443)
    resp = test_client.get(
        f"/sub/{alice.sub_token}?format=v2rayng",
        headers={"user-agent": "v2rayNG/1.9.0"},
    )
    assert resp.status_code == 200
    import base64

    body = base64.b64decode(resp.content).decode("utf-8", "replace")
    vless_lines = [l for l in body.splitlines() if l.startswith("vless://")]
    assert len(vless_lines) == 1
    assert "cdn.example.com:8443" in vless_lines[0]


def test_singbox_feed_uses_managed_host(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    _host(db, vless.id, "cdn.example.com")
    resp = test_client.get(
        f"/sub/{alice.sub_token}?format=singbox",
        headers={"user-agent": "SFI/1.0"},
    )
    assert resp.status_code == 200
    feed = resp.json()
    servers = [
        ob.get("server")
        for ob in feed.get("outbounds", [])
        if ob.get("type") == "vless"
    ]
    assert servers == ["cdn.example.com"]


def test_disabled_host_is_ignored_in_feed(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    host = _host(db, vless.id, "cdn.example.com")
    host.enabled = False
    db.commit()
    resp = test_client.get(
        f"/sub/{alice.sub_token}?format=singbox",
        headers={"user-agent": "SFI/1.0"},
    )
    assert resp.status_code == 200
    feed = resp.json()
    servers = [
        ob.get("server")
        for ob in feed.get("outbounds", [])
        if ob.get("type") == "vless"
    ]
    # The default host (the test IP) is used, not the disabled host.
    assert servers == ["203.0.113.10"]


# ---------------------------------------------------------------------------
# HTTP management flows
# ---------------------------------------------------------------------------

def test_create_host_via_post(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/inbounds/{vless.id}/hosts",
        data={
            "address": "cdn.example.com",
            "port": "8443",
            "sni": "cdn.example.com",
            "remark": "CDN",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    host = db.query(ManagedHost).filter_by(inbound_id=vless.id).one()
    assert host.address == "cdn.example.com"
    assert host.port == 8443
    assert host.sni == "cdn.example.com"
    assert host.remark == "CDN"
    # The edit page shows the host.
    page = authed_client.get(f"/inbounds/{vless.id}/edit")
    assert page.status_code == 200
    assert "cdn.example.com" in page.text


def test_create_host_validation_errors(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    for data in (
        {"address": ""},
        {"address": "bad host"},
        {"address": "ok.com", "port": "99999"},
        {"address": "ok.com", "port": "abc"},
        {"address": "ok.com", "sni": "bad sni"},
    ):
        resp = authed_client.post(
            f"/inbounds/{vless.id}/hosts", data=data,
            follow_redirects=False,
        )
        assert resp.status_code == 303, data
    assert db.query(ManagedHost).count() == 0


def test_toggle_and_delete_host(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    host = _host(db, vless.id)
    host_id = host.id
    resp = authed_client.post(
        f"/inbounds/{vless.id}/hosts/{host_id}/toggle",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.refresh(host)
    assert host.enabled is False
    resp = authed_client.post(
        f"/inbounds/{vless.id}/hosts/{host_id}/delete",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(ManagedHost, host_id) is None


def test_host_toggle_wrong_inbound_404s(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    trojan = seeded["inbounds"]["trojan-tls"]
    host = _host(db, vless.id)
    # The host belongs to vless — toggling it through trojan 404s.
    resp = authed_client.post(
        f"/inbounds/{trojan.id}/hosts/{host.id}/toggle",
        follow_redirects=False,
    )
    assert resp.status_code == 404


def test_deleting_inbound_deletes_its_hosts(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    vless_id = vless.id
    _host(db, vless_id)
    resp = authed_client.post(
        f"/inbounds/{vless_id}/delete", follow_redirects=False
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.query(ManagedHost).filter_by(inbound_id=vless_id).count() == 0
