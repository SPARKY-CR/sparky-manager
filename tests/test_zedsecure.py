"""ZedSecure bundle (v11): one JSON document per user with all of
their configs — share links, sing-box outbounds, WireGuard .conf —
at ``GET /sub/<token>/zedsecure.json``. Same access rules as the
other feeds: unknown / disabled / expired / over-quota → 403 empty.
"""

from __future__ import annotations


def _bundle_url(client, token: str) -> str:
    return f"/sub/{token}/zedsecure.json"


def test_bundle_alice(authed_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = authed_client.get(_bundle_url(authed_client, token))
    assert resp.status_code == 200
    assert "Subscription-Userinfo" in resp.headers
    body = resp.json()
    assert body["format"] == "zedsecure-bundle"
    assert body["version"] == 1
    assert body["user"]["name"] == "alice"
    assert body["user"]["traffic_unlimited"] is True
    assert body["server"]["host"] == "203.0.113.10"

    by_tag = {c["tag"]: c for c in body["configs"]}
    # VLESS+Reality: share link + sing-box outbound.
    vless = by_tag["vless-reality"]
    assert vless["protocol"] == "vless" and vless["port"] == 443
    assert vless["share_link"].startswith("vless://")
    assert "security=reality" in vless["share_link"]
    assert vless["singbox_outbound"]["type"] == "vless"
    # WireGuard: no share link, but a .conf and a sing-box endpoint
    # (not an outbound — sing-box 1.13+).
    wg = by_tag["wireguard"]
    assert "share_link" not in wg
    assert "singbox_outbound" not in wg
    assert wg["singbox_endpoint"]["type"] == "wireguard"
    assert wg["singbox_endpoint"]["peers"][0]["port"] == 51820
    assert wg["wireguard_conf"].startswith("[Interface]\nPrivateKey = ")
    assert "Endpoint = 203.0.113.10:51820" in wg["wireguard_conf"]
    # ShadowTLS: outer outbound on the config, detour SS outbound
    # in the feed's outbounds.
    st = by_tag["shadowtls"]
    assert st["singbox_outbound"]["type"] == "shadowtls"
    assert st["singbox_outbound"]["version"] == 3
    assert {o["tag"] for o in body["singbox"]["outbounds"]} >= {
        "alice-shadowtls", "alice-shadowtls-ss"}
    # Flat lists carry the same content.
    assert any(link.startswith("vless://") for link in body["links"])
    assert any(o["type"] == "vless" for o in body["singbox"]["outbounds"])
    assert any(e["type"] == "wireguard"
               for e in body["singbox"]["endpoints"])


def test_bundle_forbidden_users(authed_client, seeded):
    for name in ("bob", "carol", "dave"):
        token = seeded["users"][name].sub_token
        resp = authed_client.get(_bundle_url(authed_client, token))
        assert resp.status_code == 403, name
        assert resp.content == b""
    resp = authed_client.get("/sub/does-not-exist/zedsecure.json")
    assert resp.status_code == 403
    assert resp.content == b""


def test_bundle_token_rotation_invalidates(authed_client, seeded, db):
    from app.models import User

    alice = seeded["users"]["alice"]
    old_token = alice.sub_token
    resp = authed_client.post(f"/users/{alice.id}/rotate-token",
                              follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert authed_client.get(_bundle_url(authed_client, old_token)).status_code == 403
    db.expire_all()
    new_token = db.query(User).filter_by(id=alice.id).first().sub_token
    assert new_token != old_token
    assert authed_client.get(_bundle_url(authed_client, new_token)).status_code == 200


def test_user_page_links_bundle(authed_client, seeded):
    alice = seeded["users"]["alice"]
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert f"/sub/{alice.sub_token}/zedsecure.json" in resp.text
    assert "ZedSecure" in resp.text
    # The public page shows it too (same template).
    resp = authed_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    assert f"/sub/{alice.sub_token}/zedsecure.json" in resp.text
