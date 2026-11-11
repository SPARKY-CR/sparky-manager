"""Subscription tests (DESIGN.md §6) — dual format, UA sniffing,
per-user endpoints.

Written from scratch against the real ``app.subscription`` signatures
and the live ``/sub/<token>`` routes (via TestClient).
"""

from __future__ import annotations

import base64
import json

import pytest

from app import subscription
from app.links import build_share_link
from app.main import _client_dict, _inbound_dict, _links_for_user
from app.subscription import (
    build_singbox_feed,
    build_v2rayng_feed,
    choose_format,
    decode_v2rayng_feed,
    outbound_for_client,
    subscription_userinfo,
)
from tests.conftest import HOST


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alice_links(db, seeded):
    """Alice's share links, exactly as the panel builds them."""
    user = seeded["users"]["alice"]
    return [entry["link"] for entry in _links_for_user(db, user, HOST)]


def _client_inbound(seeded, tag):
    user = seeded["users"]["alice"]
    return (_client_dict(seeded["clients"][("alice", tag)], user),
            _inbound_dict(seeded["inbounds"][tag]))


# ---------------------------------------------------------------------------
# choose_format: UA sniffing + ?format= override
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ua,query,expected", [
    ("sing-box/1.12.0", None, "singbox"),
    ("SFA/1.0", None, "singbox"),
    ("Hiddify/2.0", None, "singbox"),
    ("v2rayNG/1.9.0", None, "v2rayng"),
    ("v2rayN/6.0", None, "v2rayng"),
    ("NekoBox/1.0", None, "v2rayng"),
    ("Clash/1.0", None, "v2rayng"),
    ("Mozilla/5.0", None, "v2rayng"),   # unknown UA -> v2rayNG default
    ("", None, "v2rayng"),
    (None, None, "v2rayng"),
    # Explicit ?format= always wins over the UA.
    ("sing-box/1.12.0", "v2rayng", "v2rayng"),
    ("v2rayNG/1.9.0", "singbox", "singbox"),
    ("v2rayNG/1.9.0", "sing-box", "singbox"),
    ("sing-box/1.12.0", "v2ray", "v2rayng"),
    ("sing-box/1.12.0", "SingBox", "singbox"),  # case-insensitive
    ("sing-box/1.12.0", " singbox ", "singbox"),  # surrounding spaces
    # An unrecognised ?format= is ignored; the UA is sniffed instead.
    ("sing-box/1.12.0", "clash-yaml", "singbox"),
    ("v2rayNG/1.9.0", "bogus", "v2rayng"),
    ("Mozilla/5.0", "bogus", "v2rayng"),
])
def test_choose_format(ua, query, expected):
    assert choose_format(ua, query) == expected


# ---------------------------------------------------------------------------
# v2rayNG feed
# ---------------------------------------------------------------------------

def test_v2rayng_feed_round_trips(db, seeded):
    links = _alice_links(db, seeded)
    assert len(links) == 9  # every protocol except WireGuard (file export)
    body = build_v2rayng_feed(links)
    assert isinstance(body, bytes)
    # Standard base64 with padding, as the spec requires.
    assert body == base64.b64encode("\n".join(links).encode())
    assert decode_v2rayng_feed(body) == links


def test_v2rayng_feed_empty_and_invalid():
    assert decode_v2rayng_feed(build_v2rayng_feed([])) == []
    with pytest.raises(ValueError):
        decode_v2rayng_feed(b"!!!not-base64!!!")


def test_v2rayng_feed_link_order(db, seeded):
    """Links come out ordered by inbound port (the panel's
    ``_usable_clients`` orders by ``Inbound.port``): 443 first,
    the ShadowTLS/SS link (port 8447) last."""
    links = _alice_links(db, seeded)
    schemes = [link.split("://", 1)[0] for link in links]
    assert sorted(schemes) == sorted(
        ["vless", "vmess", "trojan", "ss", "hysteria2",
         "tuic", "anytls", "naive+https", "ss"])
    assert schemes[0] == "vless"      # TCP 443, the lowest port
    assert schemes[-1] == "ss"        # ShadowTLS on 8447, the highest
    assert schemes.count("ss") == 2   # Shadowsocks + ShadowTLS-as-SS


# ---------------------------------------------------------------------------
# sing-box feed
# ---------------------------------------------------------------------------

def test_build_singbox_feed_wraps_outbounds():
    outbounds = [{"type": "vless", "tag": "a"}, {"type": "tuic", "tag": "b"}]
    feed = build_singbox_feed(outbounds)
    assert feed == {"outbounds": outbounds}
    assert feed["outbounds"] is not outbounds  # a fresh list


@pytest.mark.parametrize("tag,protocol", [
    ("vless-reality", "vless"),
    ("vmess-ws", "vmess"),
    ("trojan-tls", "trojan"),
    ("shadowsocks", "shadowsocks"),
    ("hysteria2", "hysteria2"),
    ("tuic", "tuic"),
    ("anytls", "anytls"),
    ("naive", "naive"),
    ("wireguard", "wireguard"),
])
def test_outbound_for_client_every_protocol(seeded, tag, protocol):
    client, inbound = _client_inbound(seeded, tag)
    outbound = outbound_for_client(protocol, client, inbound, HOST,
                                   f"alice-{tag}")
    assert outbound is not None, protocol
    assert outbound["type"] == protocol
    assert outbound["server"] == HOST
    assert outbound["server_port"] == inbound["port"]
    assert outbound["tag"] == f"alice-{tag}"
    if protocol == "vless":
        assert outbound["uuid"] == client["uuid"]
        assert outbound["flow"] == "xtls-rprx-vision"
        assert outbound["tls"]["reality"]["enabled"] is True
        assert (outbound["tls"]["reality"]["public_key"]
                == seeded["reality_public"])
        assert (outbound["tls"]["reality"]["short_id"]
                == seeded["reality_short_id"])
    elif protocol == "vmess":
        assert outbound["uuid"] == client["uuid"]
        assert outbound["security"] == "auto"
        assert outbound["alter_id"] == 0
        assert outbound["transport"]["type"] == "ws"
        assert outbound["transport"]["path"] == "/vmess-ws"
    elif protocol in ("trojan", "hysteria2", "anytls"):
        assert outbound["password"] == client["password"]
        assert outbound["tls"]["enabled"] is True
    elif protocol == "shadowsocks":
        assert outbound["method"] == "2022-blake3-aes-128-gcm"
        assert outbound["password"] == client["password"]
    elif protocol == "tuic":
        assert outbound["uuid"] == client["uuid"]
        assert outbound["password"] == client["password"]
        assert outbound["congestion_control"] == "bbr"
        assert outbound["tls"]["alpn"] == ["h3"]
    elif protocol == "naive":
        assert outbound["username"] == "alice-naive"
        assert outbound["password"] == client["password"]
    elif protocol == "wireguard":
        assert outbound["private_key"] == seeded["alice_wg_private"]
        assert outbound["peer_public_key"] == seeded["wg_server_public"]
        assert outbound["local_address"] == ["10.8.0.2/32"]
        assert outbound["mtu"] == 1280


def test_outbound_for_client_none_cases(seeded):
    client, inbound = _client_inbound(seeded, "shadowtls")
    # ShadowTLS is a server-side inbound/detour, not a client outbound.
    assert outbound_for_client("shadowtls", client, inbound, HOST,
                               "alice-shadowtls") is None
    # IKEv2 and unknown protocols have no sing-box outbound.
    assert outbound_for_client("ikev2", client, inbound, HOST, "x") is None
    assert outbound_for_client("bogus", client, inbound, HOST, "x") is None
    # VLESS over XHTTP is v2rayNG-only: sing-box has no XHTTP transport.
    vless_client, vless_inbound = _client_inbound(seeded, "vless-reality")
    vless_inbound = dict(vless_inbound)
    vless_inbound["stream_json"] = dict(vless_inbound["stream_json"])
    vless_inbound["stream_json"]["network"] = "xhttp"
    assert outbound_for_client("vless", vless_client, vless_inbound, HOST,
                               "x") is None


def test_outbound_for_client_rejects_missing_credentials(seeded):
    client, inbound = _client_inbound(seeded, "vless-reality")
    with pytest.raises(ValueError):
        outbound_for_client("vless", {"uuid": ""}, inbound, HOST, "x")
    with pytest.raises(ValueError):
        outbound_for_client("trojan", {"password": ""}, inbound, HOST, "x")
    with pytest.raises(ValueError):
        outbound_for_client("vless", client, {"port": 0,
                                              "stream_json": {}}, HOST, "x")


# ---------------------------------------------------------------------------
# Subscription-Userinfo header
# ---------------------------------------------------------------------------

def test_subscription_userinfo_format():
    assert (subscription_userinfo(12345, 10 * 1024**3, 1790000000)
            == "upload=0; download=12345; total=10737418240; "
               "expire=1790000000")
    # Unlimited / never-expire are reported as 0 (the "no limit"
    # convention clients read).
    assert (subscription_userinfo(0, None, None)
            == "upload=0; download=0; total=0; expire=0")


# ---------------------------------------------------------------------------
# HTTP: /sub/<token>
# ---------------------------------------------------------------------------

def test_sub_v2rayng_default_decodes_to_same_links(test_client, db, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert decode_v2rayng_feed(resp.content) == _alice_links(db, seeded)
    assert "Subscription-Userinfo" in resp.headers
    assert resp.headers["Subscription-Userinfo"].startswith(
        "upload=0; download=0; total=0; expire=0")


def test_sub_singbox_feed_via_format_param(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}?format=singbox")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    feed = resp.json()
    assert set(feed) == {"outbounds"}
    types = {o["type"] for o in feed["outbounds"]}
    # Every protocol with a sing-box outbound (ShadowTLS is
    # server-side only; XHTTP is not in the seed).
    assert types == {"vless", "vmess", "trojan", "shadowsocks",
                     "hysteria2", "tuic", "anytls", "naive", "wireguard"}
    for outbound in feed["outbounds"]:
        assert outbound["server"] == HOST
        assert 1 <= outbound["server_port"] <= 65535
    json.dumps(feed)  # valid JSON


def test_sub_format_by_user_agent(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/sub/{token}",
                           headers={"User-Agent": "sing-box/1.12.0"})
    assert resp.status_code == 200
    assert resp.json()["outbounds"]
    resp = test_client.get(f"/sub/{token}",
                           headers={"User-Agent": "v2rayNG/1.9.0"})
    assert resp.status_code == 200
    assert decode_v2rayng_feed(resp.content)
    # Explicit ?format= beats the User-Agent.
    resp = test_client.get(f"/sub/{token}?format=v2rayng",
                           headers={"User-Agent": "sing-box/1.12.0"})
    assert decode_v2rayng_feed(resp.content)


def test_sub_userinfo_header_reports_quota_and_expiry(
        test_client, db, seeded):
    from datetime import datetime, timezone

    # A fresh usable user with a limit (carol is over quota, so she
    # would 403 instead of showing a header).
    from app.models import User
    import secrets as _secrets
    expires = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    limited = User(name="limited", enabled=True,
                   traffic_limit_bytes=5 * 1024**3,
                   traffic_used_bytes=123456,
                   expires_at=expires,
                   sub_token=_secrets.token_urlsafe(24))
    db.add(limited)
    db.commit()
    resp = test_client.get(f"/sub/{limited.sub_token}")
    assert resp.status_code == 200
    assert (resp.headers["Subscription-Userinfo"]
            == "upload=0; download=123456; total=5368709120; "
               f"expire={int(expires.timestamp())}")


@pytest.mark.parametrize("name", ["bob", "carol", "dave"])
def test_sub_unusable_user_gets_403_empty(test_client, seeded, name):
    token = seeded["users"][name].sub_token
    for url in (f"/sub/{token}", f"/sub/{token}?format=singbox"):
        resp = test_client.get(url)
        assert resp.status_code == 403, (name, url)
        assert resp.content == b"", (name, url)


def test_sub_unknown_token_gets_403_empty(test_client):
    resp = test_client.get("/sub/this-token-does-not-exist")
    assert resp.status_code == 403
    assert resp.content == b""


def test_sub_singbox_feed_includes_wireguard_for_api_created_user(
        authed_client, db):
    """WireGuard must appear in the sing-box feed for a user created
    through the panel itself (whose client stores the private key in
    `password` and no `private_key` in extra_json)."""
    resp = authed_client.post("/api/users", json={"name": "wguser"})
    assert resp.status_code == 201, resp.text
    token = resp.json()["sub_token"]
    feed = authed_client.get(f"/sub/{token}?format=singbox").json()
    types = {o["type"] for o in feed["outbounds"]}
    assert "wireguard" in types
    wg = next(o for o in feed["outbounds"] if o["type"] == "wireguard")
    assert wg["server_port"] == 51820
    assert wg["peer_public_key"]
    assert wg["private_key"]
    assert wg["local_address"] == ["10.8.0.2/32"]


def test_token_rotation_invalidates_old_token(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    old_token = alice.sub_token
    assert authed_client.get(f"/sub/{old_token}").status_code == 200
    resp = authed_client.post(f"/users/{alice.id}/rotate-token")
    assert resp.status_code in (200, 303)
    db.expire_all()
    new_token = db.get(type(alice), alice.id).sub_token
    assert new_token != old_token
    assert authed_client.get(f"/sub/{old_token}").status_code == 403
    assert authed_client.get(f"/sub/{old_token}").content == b""
    assert authed_client.get(f"/sub/{new_token}").status_code == 200


# ---------------------------------------------------------------------------
# HTTP: /u/<token> human page
# ---------------------------------------------------------------------------

def test_user_page_shows_links(test_client, seeded):
    token = seeded["users"]["alice"].sub_token
    resp = test_client.get(f"/u/{token}")
    assert resp.status_code == 200
    assert "alice" in resp.text
    assert "/sub/" in resp.text


def test_user_page_unknown_token_404(test_client):
    assert test_client.get("/u/no-such-token").status_code == 404


def test_user_page_unusable_user_shows_error_not_links(test_client, seeded):
    token = seeded["users"]["bob"].sub_token
    resp = test_client.get(f"/u/{token}")
    assert resp.status_code == 200
    assert "vless://" not in resp.text
