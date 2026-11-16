"""ZedSecure sing-box fragment subscription.

The app does NOT understand the panel's 'zedsecure-bundle' JSON
(verified against its source, CluvexStudio/ZedSecure commit
201e82ce — zero code references), but it parses sing-box JSON
fragments (one profile per outbound/endpoint) and offers one-tap
import via the zedsecure://import deep link. This batch:

1. The sing-box feed is a FRAGMENT: link protocols as outbounds,
   WireGuard / OpenVPN / OpenConnect as endpoints (the native
   protocols carry username/password in the endpoint object).
   AmneziaWG and IKEv2 stay out (no endpoint exists for them —
   documented in docs/ZEDSECURE.md, not faked).
2. ZedSecure's own User-Agent gets the fragment (UA negotiation on
   the same /sub/<token> URL); the v2rayNG link feed and the
   browser copy-only page are untouched.
3. "Add to ZedSecure" deep-link button (zedsecure://import) on the
   user detail page, the public /u/ page, the /sub/ browser view,
   and the bot Links view.
4. The /sub/<token>/zedsecure.json bundle endpoint stays as a file
   export, with a warning next to it: never add the bundle URL as
   a subscription (a failed update wipes the sub's servers).
"""

from __future__ import annotations

import pytest

from app import main as main_mod
from app.links import zedsecure_deep_link
from app.models import Client
from app.subscription import (
    build_singbox_feed,
    choose_format,
    decode_v2rayng_feed,
    outbound_for_client,
)
from tests.conftest import HOST
from tests.test_protocols import ca, proto  # noqa: F401 — fixtures
from tests.test_telegram_bot import (
    FakeSender,
    _callback,
    _configure_bot,
    _dispatch,
)


@pytest.fixture()
def sender():
    return FakeSender()


# The app's SingBoxJson proxy outbound types (SingBoxJson.kt) — the
# fragment's outbounds must stay inside this set, and its endpoints
# inside ENDPOINT_TYPES below, or the app's shapeOf() rejects them.
APP_OUTBOUND_TYPES = {
    "socks", "http", "shadowsocks", "vmess", "trojan", "naive",
    "hysteria", "shadowtls", "vless", "tuic", "hysteria2", "anytls",
    "tor", "ssh", "snell", "shadowsocksr",
}
APP_ENDPOINT_TYPES = {
    "wireguard", "tailscale", "openvpn-client", "openconnect", "openvpn",
}


def _native_client(password="alice-ovpn-pw-001"):
    return {
        "user_name": "alice",
        "uuid": None,
        "password": password,
        "method": None,
        "flow": None,
        "extra_json": {},
    }


def _native_inbound(protocol, port, stream=None):
    return {
        "tag": protocol,
        "protocol": protocol,
        "port": port,
        "stream_json": stream or {},
    }


# ---------------------------------------------------------------------------
# Format selection: ZedSecure's User-Agent gets the fragment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ua,query,expected", [
    ("ZedSecure/3.1.8", None, "singbox"),
    ("SFA/1.14.4 (sing-box 1.14.4)", None, "singbox"),
    ("v2rayNG/1.9.0", None, "v2rayng"),  # default UA: link list
    # An explicit ?format= still wins over the UA.
    ("ZedSecure/3.1.8", "v2rayng", "v2rayng"),
    ("v2rayNG/1.9.0", "singbox", "singbox"),
])
def test_choose_format_zedsecure_ua(ua, query, expected):
    assert choose_format(ua, query) == expected


# ---------------------------------------------------------------------------
# Endpoint builders: OpenVPN / OpenConnect
# ---------------------------------------------------------------------------

def test_outbound_for_client_openvpn_endpoint():
    endpoint = outbound_for_client(
        "openvpn",
        _native_client(),
        _native_inbound("openvpn", 1194, {"transport": "udp"}),
        HOST,
        "alice-openvpn",
    )
    assert endpoint["type"] == "openvpn-client"
    assert endpoint["tag"] == "alice-openvpn"
    assert endpoint["server"] == HOST
    assert endpoint["server_port"] == 1194
    assert endpoint["network"] == "udp"
    assert endpoint["username"] == "alice"
    assert endpoint["password"] == "alice-ovpn-pw-001"


def test_outbound_for_client_openvpn_transport():
    # TCP inbounds say so; a bogus transport falls back to UDP
    # (the OpenVPN default) instead of emitting a broken value.
    tcp = outbound_for_client(
        "openvpn",
        _native_client(),
        _native_inbound("openvpn", 1194, {"transport": "tcp"}),
        HOST,
        "alice-openvpn",
    )
    assert tcp["network"] == "tcp"
    bogus = outbound_for_client(
        "openvpn",
        _native_client(),
        _native_inbound("openvpn", 1194, {"transport": "quic"}),
        HOST,
        "alice-openvpn",
    )
    assert bogus["network"] == "udp"
    # No transport at all: UDP default.
    default = outbound_for_client(
        "openvpn",
        _native_client(),
        _native_inbound("openvpn", 1194),
        HOST,
        "alice-openvpn",
    )
    assert default["network"] == "udp"


def test_outbound_for_client_openconnect_endpoint():
    endpoint = outbound_for_client(
        "openconnect",
        _native_client(),
        _native_inbound("openconnect", 4433, {"transport": "tcp"}),
        HOST,
        "alice-openconnect",
    )
    assert endpoint["type"] == "openconnect"
    assert endpoint["tag"] == "alice-openconnect"
    assert endpoint["server"] == HOST
    assert endpoint["server_port"] == 4433
    assert endpoint["username"] == "alice"
    assert endpoint["password"] == "alice-ovpn-pw-001"
    # ocserv binds TCP and UDP on the same port: no `network` field.
    assert "network" not in endpoint


def test_outbound_for_client_native_rejects_missing_credentials():
    inbound = _native_inbound("openvpn", 1194)
    with pytest.raises(ValueError):
        outbound_for_client(
            "openvpn",
            {"user_name": "", "password": "pw", "extra_json": {}},
            inbound, HOST, "x",
        )
    with pytest.raises(ValueError):
        outbound_for_client(
            "openvpn",
            {"user_name": "alice", "password": "", "extra_json": {}},
            inbound, HOST, "x",
        )
    with pytest.raises(ValueError):
        outbound_for_client(
            "openconnect",
            {"user_name": "alice", "password": "", "extra_json": {}},
            _native_inbound("openconnect", 4433), HOST, "x",
        )


def test_outbound_for_client_amneziawg_and_ikev2_still_none():
    # No endpoint exists for these protocols (upstream sing-box has
    # no AmneziaWG endpoint; IKEv2 is ZedLink-only in the app) —
    # file exports stay their path (docs/ZEDSECURE.md).
    client = _native_client()
    assert outbound_for_client(
        "amneziawg", client, _native_inbound("amneziawg", 51821),
        HOST, "x",
    ) is None
    assert outbound_for_client(
        "ikev2", client, _native_inbound("ikev2", 500), HOST, "x",
    ) is None


# ---------------------------------------------------------------------------
# Feed split: endpoints under "endpoints"
# ---------------------------------------------------------------------------

def test_build_singbox_feed_splits_all_endpoint_types():
    objects = [
        {"type": "vless", "tag": "a"},
        {"type": "wireguard", "tag": "wg"},
        {"type": "openvpn-client", "tag": "ovpn"},
        {"type": "openconnect", "tag": "oc"},
        {"type": "trojan", "tag": "b"},
    ]
    feed = build_singbox_feed(objects)
    assert [o["type"] for o in feed["outbounds"]] == ["vless", "trojan"]
    assert [o["type"] for o in feed["endpoints"]] == [
        "wireguard", "openvpn-client", "openconnect",
    ]
    # No endpoints at all: no "endpoints" key (like before).
    assert build_singbox_feed([{"type": "vless", "tag": "a"}]) == {
        "outbounds": [{"type": "vless", "tag": "a"}],
    }


# ---------------------------------------------------------------------------
# Deep link builder
# ---------------------------------------------------------------------------

def test_zedsecure_deep_link():
    link = zedsecure_deep_link("https://203.0.113.10:8443/sub/abc123", "alice")
    assert link == (
        "zedsecure://import?url="
        "https%3A%2F%2F203.0.113.10%3A8443%2Fsub%2Fabc123&name=alice"
    )
    # A name with a space is percent-encoded (the app's parser
    # percent-decodes the name parameter).
    assert zedsecure_deep_link("https://example.com/sub/t", "ali reza").endswith(
        "&name=ali%20reza"
    )
    with pytest.raises(ValueError):
        zedsecure_deep_link("", "alice")


# ---------------------------------------------------------------------------
# HTTP: the fragment, served to ZedSecure
# ---------------------------------------------------------------------------

def test_sub_fragment_via_zedsecure_ua(test_client, db, seeded, proto):
    """ZedSecure's UA gets the fragment: one entry per usable
    (client, inbound), native protocols as endpoints with
    credentials; AmneziaWG and IKEv2 honestly absent."""
    alice = seeded["users"]["alice"]
    resp = test_client.get(
        f"/sub/{alice.sub_token}",
        headers={"User-Agent": "ZedSecure/3.1.8"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    feed = resp.json()
    assert set(feed) == {"outbounds", "endpoints"}
    # Outbounds: the 9 link protocols + the ShadowTLS SS detour.
    assert {o["type"] for o in feed["outbounds"]} == {
        "vless", "vmess", "trojan", "shadowsocks", "hysteria2",
        "tuic", "anytls", "naive", "shadowtls",
    }
    assert len(feed["outbounds"]) == 10
    # Endpoints: WireGuard + the two native protocols.
    by_type = {e["type"]: e for e in feed["endpoints"]}
    assert set(by_type) == {"wireguard", "openvpn-client", "openconnect"}
    # The endpoint passwords are the clients' stored passwords
    # (the same ones the .ovpn embeds and ocserv checks).
    ovpn_client = (
        db.query(Client)
        .filter(Client.user_id == alice.id,
                Client.inbound_id == proto["inbounds"]["openvpn"].id)
        .first()
    )
    oc_client = (
        db.query(Client)
        .filter(Client.user_id == alice.id,
                Client.inbound_id == proto["inbounds"]["openconnect"].id)
        .first()
    )
    assert ovpn_client is not None and oc_client is not None
    ovpn = by_type["openvpn-client"]
    assert ovpn["server"] == HOST
    assert ovpn["server_port"] == 1194
    assert ovpn["username"] == "alice"
    assert ovpn["password"] == ovpn_client.password
    oc = by_type["openconnect"]
    assert oc["server"] == HOST
    assert oc["server_port"] == 4433
    assert oc["username"] == "alice"
    assert oc["password"] == oc_client.password
    # AmneziaWG and IKEv2 have no fragment entry.
    tags = {o["tag"] for o in feed["outbounds"]} | {
        e["tag"] for e in feed["endpoints"]
    }
    assert "alice-amneziawg" not in tags
    assert "alice-ikev2" not in tags


def test_sub_fragment_one_entry_per_config(test_client, seeded, proto):
    """One entry per usable (client, inbound) — no duplicates, no
    missing configs. A duplicate tag would make the app's dedup
    drop a config silently."""
    alice = seeded["users"]["alice"]
    feed = test_client.get(
        f"/sub/{alice.sub_token}?format=singbox",
    ).json()
    tags = [o["tag"] for o in feed["outbounds"]] + [
        e["tag"] for e in feed["endpoints"]
    ]
    assert len(tags) == len(set(tags)), tags
    # 10 outbounds (9 protocols + ShadowTLS detour) + 3 endpoints.
    assert len(tags) == 13


def test_sub_fragment_shape_is_app_compatible(test_client, seeded, proto):
    """The fragment must be what the app's SingBoxJson.shapeOf
    recognises as a Fragment: an object with outbounds/endpoints
    arrays, every entry carrying type+tag, and NO "protocol" key
    anywhere (that key is what marks Xray JSON for the app)."""
    alice = seeded["users"]["alice"]
    feed = test_client.get(
        f"/sub/{alice.sub_token}",
        headers={"User-Agent": "SFA/1.14.4 (sing-box 1.14.4)"},
    ).json()
    assert set(feed) <= {"outbounds", "endpoints"}
    for outbound in feed["outbounds"]:
        assert outbound["type"] in APP_OUTBOUND_TYPES, outbound
        assert outbound["tag"]
        assert "protocol" not in outbound
    for endpoint in feed["endpoints"]:
        assert endpoint["type"] in APP_ENDPOINT_TYPES, endpoint
        assert endpoint["tag"]
        assert "protocol" not in endpoint


def test_sub_v2rayng_ua_still_gets_links(test_client, seeded, proto):
    """The default v2rayNG UA is untouched: the base64 link list,
    including the AmneziaWG vpn:// link the fragment cannot carry
    (the app merges the two fetches)."""
    alice = seeded["users"]["alice"]
    resp = test_client.get(
        f"/sub/{alice.sub_token}",
        headers={"User-Agent": "v2rayNG/1.9.0"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    links = decode_v2rayng_feed(resp.content)
    assert any(link.startswith("vpn://") for link in links)
    assert any(link.startswith("vless://") for link in links)


def test_sub_browser_view_has_deeplink_button(test_client, seeded):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/sub/{alice.sub_token}?view=html")
    assert resp.status_code == 200
    assert "zedsecure://import?url=" in resp.text
    assert "افزودن به ZedSecure" in resp.text
    # The copy-only page still shows the links.
    assert "vless://" in resp.text


# ---------------------------------------------------------------------------
# Pages: deep-link button + bundle warning
# ---------------------------------------------------------------------------

def test_user_detail_page_has_deeplink_and_bundle_warning(
    authed_client, seeded
):
    alice = seeded["users"]["alice"]
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "zedsecure://import?url=" in resp.text
    assert "افزودن به ZedSecure" in resp.text
    # The bundle warning (fa): never add the bundle as a subscription.
    assert "به‌عنوان سابسکریپشن در اپ وارد نکنید" in resp.text


def test_public_user_page_has_deeplink_and_bundle_warning(
    test_client, seeded
):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    assert "zedsecure://import?url=" in resp.text
    assert "افزودن به ZedSecure" in resp.text
    assert "به‌عنوان سابسکریپشن در اپ وارد نکنید" in resp.text


# ---------------------------------------------------------------------------
# The bundle endpoint stays (as a file export)
# ---------------------------------------------------------------------------

def test_bundle_endpoint_unchanged(test_client, seeded, proto):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/sub/{alice.sub_token}/zedsecure.json")
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["format"] == "zedsecure-bundle"
    assert bundle["version"] == 1
    # The bundle's own sing-box feed now carries the endpoints too,
    # and native entries are labelled singbox_endpoint (not
    # singbox_outbound — the schema stays honest).
    assert "endpoints" in bundle["singbox"]
    assert {
        e["type"] for e in bundle["singbox"]["endpoints"]
    } == {"wireguard", "openvpn-client", "openconnect"}
    by_tag = {entry["tag"]: entry for entry in bundle["configs"]}
    assert "singbox_endpoint" in by_tag["openvpn"]
    assert "singbox_outbound" not in by_tag["openvpn"]
    assert "singbox_endpoint" in by_tag["openconnect"]


# ---------------------------------------------------------------------------
# Bot: Links view carries the deep-link URL button
# ---------------------------------------------------------------------------

def _url_buttons(reply_markup):
    """All (text, url) URL buttons in a keyboard."""
    out = []
    if not reply_markup:
        return out
    for row in reply_markup.get("inline_keyboard", []):
        for button in row:
            if "url" in button:
                out.append((button["text"], button["url"]))
    return out


def test_links_view_has_zedsecure_deeplink_button(db, sender, seeded):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    assert sender.edited, "Links view should edit the message"
    markup = sender.edited[0][3]
    urls = _url_buttons(markup)
    assert len(urls) == 1, urls
    text, url = urls[0]
    assert text == "افزودن به ZedSecure"
    assert url.startswith("zedsecure://import?url=")
    assert f"%2Fsub%2F{alice.sub_token}" in url
    assert url.endswith("&name=alice")


def test_links_view_without_host_has_no_deeplink(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    assert sender.edited, "no-host case should still answer"
    assert "zedsecure://import" not in sender.edited[0][2]
    assert _url_buttons(sender.edited[0][3]) == []
