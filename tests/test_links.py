"""Share-link tests (DESIGN.md §6.2) — build -> parse round-trips.

Written from scratch against the real ``app.links`` signatures.
For schemes with no parser in the app (hysteria2 / tuic / anytls /
naive) the test parses the link back with stdlib ``urllib.parse``,
which is the same check a client importer would do.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from app import links
from app.links import (
    build_anytls_link,
    build_hysteria2_link,
    build_naive_link,
    build_share_link,
    build_ss_link,
    build_trojan_link,
    build_tuic_link,
    build_vless_link,
    build_vmess_link,
    make_qr_png,
    parse_ss_link,
    parse_trojan_link,
    parse_vless_link,
    parse_vmess_link,
)
from tests.conftest import HOST, SS_METHOD

UUID = "11111111-2222-4333-8444-555555555555"
UUID2 = "66666666-7777-4888-9999-000000000000"
REALITY_PBK = "cHVibGljLWtleS1mb3ItdGVzdHMtdGhhdC1pcy0zMi1ieXRlcw"
REALITY_SID = "a1b2c3d4"
NAME = "alice test"


# ---------------------------------------------------------------------------
# Round-trips with a parser in the app
# ---------------------------------------------------------------------------

def test_vless_reality_round_trip():
    link = build_vless_link(
        UUID, HOST, 443, flow="xtls-rprx-vision", security="reality",
        sni="www.microsoft.com", fp="chrome", pbk=REALITY_PBK,
        sid=REALITY_SID, network="tcp", name=NAME)
    assert link.startswith("vless://")
    back = parse_vless_link(link)
    assert back["uuid"] == UUID
    assert back["host"] == HOST
    assert back["port"] == 443
    assert back["flow"] == "xtls-rprx-vision"
    assert back["security"] == "reality"
    assert back["sni"] == "www.microsoft.com"
    assert back["fp"] == "chrome"
    assert back["pbk"] == REALITY_PBK
    assert back["sid"] == REALITY_SID
    assert back["network"] == "tcp"
    assert back["name"] == NAME


def test_vless_ws_tls_round_trip():
    link = build_vless_link(
        UUID, HOST, 8443, flow=None, security="tls", sni=HOST,
        network="ws", path="/vless-ws", name=NAME)
    back = parse_vless_link(link)
    assert back["security"] == "tls"
    assert back["network"] == "ws"
    assert back["path"] == "/vless-ws"
    assert back["sni"] == HOST
    assert back["flow"] is None


def test_vmess_round_trip():
    link = build_vmess_link(
        UUID, HOST, 8443, name=NAME, network="ws", path="/vmess-ws",
        tls="tls", sni=HOST, host_header=HOST)
    assert link.startswith("vmess://")
    back = parse_vmess_link(link)
    assert back["uuid"] == UUID
    assert back["host"] == HOST
    assert back["port"] == 8443
    assert back["name"] == NAME
    assert back["network"] == "ws"
    assert back["path"] == "/vmess-ws"
    assert back["tls"] == "tls"
    assert back["sni"] == HOST
    assert back["host_header"] == HOST
    assert back["aid"] == 0
    assert back["scy"] == "auto"


def test_vmess_payload_is_v2_json():
    link = build_vmess_link(UUID, HOST, 8443, name=NAME)
    payload = json.loads(base64.b64decode(link[len("vmess://"):]))
    assert payload["v"] == "2"
    assert payload["id"] == UUID
    assert payload["ps"] == NAME
    assert payload["port"] == "8443"


def test_trojan_round_trip():
    link = build_trojan_link("s3cret-pw", HOST, 8444, sni=HOST, name=NAME)
    assert link.startswith("trojan://")
    back = parse_trojan_link(link)
    assert back["password"] == "s3cret-pw"
    assert back["host"] == HOST
    assert back["port"] == 8444
    assert back["sni"] == HOST
    assert back["security"] == "tls"
    assert back["name"] == NAME


def test_ss_sip002_round_trip():
    link = build_ss_link(SS_METHOD, "ss-password-001", HOST, 8388,
                         name=NAME)
    assert link.startswith("ss://")
    # SIP002: base64url(method:password)@host:port — host stays clear.
    assert f"@{HOST}:8388" in link
    back = parse_ss_link(link)
    assert back["method"] == SS_METHOD
    assert back["password"] == "ss-password-001"
    assert back["host"] == HOST
    assert back["port"] == 8388
    assert back["name"] == NAME


def test_ss_password_with_colon_round_trip():
    # A password containing ":" must survive: userinfo splits on the
    # FIRST colon only.
    link = build_ss_link(SS_METHOD, "pass:with:colons", HOST, 8388)
    assert parse_ss_link(link)["password"] == "pass:with:colons"


def test_ss_legacy_form_parses():
    # Legacy form: ss://base64(method:password@host:port)
    raw = f"{SS_METHOD}:legacy-pw@{HOST}:8388"
    legacy = "ss://" + base64.b64encode(raw.encode()).decode() + "#legacy"
    back = parse_ss_link(legacy)
    assert back["method"] == SS_METHOD
    assert back["password"] == "legacy-pw"
    assert back["host"] == HOST
    assert back["port"] == 8388
    assert back["name"] == "legacy"


# ---------------------------------------------------------------------------
# Round-trips parsed back with stdlib (no parser in the app)
# ---------------------------------------------------------------------------

def _parts(link: str):
    parsed = urlparse(link)
    return parsed, parse_qs(parsed.query)


def test_hysteria2_round_trip():
    link = build_hysteria2_link("hy2-pw", HOST, 443, sni=HOST, name=NAME)
    parsed, query = _parts(link)
    assert parsed.scheme == "hysteria2"
    assert unquote(parsed.username) == "hy2-pw"
    assert parsed.hostname == HOST
    assert parsed.port == 443
    assert query["sni"] == [HOST]
    assert unquote(parsed.fragment) == NAME


def test_tuic_round_trip():
    link = build_tuic_link(UUID, "tuic-pw", HOST, 8443, sni=HOST, name=NAME)
    parsed, query = _parts(link)
    assert parsed.scheme == "tuic"
    assert unquote(parsed.username) == UUID
    assert unquote(parsed.password) == "tuic-pw"
    assert parsed.hostname == HOST
    assert parsed.port == 8443
    assert query["congestion_control"] == ["bbr"]
    assert query["alpn"] == ["h3"]
    assert query["sni"] == [HOST]
    assert unquote(parsed.fragment) == NAME


def test_anytls_round_trip():
    link = build_anytls_link("anytls-pw", HOST, 8444, sni=HOST, name=NAME)
    parsed, query = _parts(link)
    assert parsed.scheme == "anytls"
    assert unquote(parsed.username) == "anytls-pw"
    assert parsed.hostname == HOST
    assert parsed.port == 8444
    assert query["sni"] == [HOST]
    assert unquote(parsed.fragment) == NAME


def test_naive_round_trip():
    # NOTE the scheme: naive+https, not plain naive:// (a common
    # gotcha — most clients will not import naive://).
    link = build_naive_link("alice-naive", "naive-pw", HOST, 8445,
                            name=NAME)
    assert link.startswith("naive+https://")
    parsed, _ = _parts(link)
    assert unquote(parsed.username) == "alice-naive"
    assert unquote(parsed.password) == "naive-pw"
    assert parsed.hostname == HOST
    assert parsed.port == 8445
    assert unquote(parsed.fragment) == NAME


# ---------------------------------------------------------------------------
# build_share_link dispatch (one client + one inbound -> one link)
# ---------------------------------------------------------------------------

def _dispatch(protocol, client, inbound, name=NAME):
    return build_share_link(protocol, client, inbound, HOST, name)


def test_dispatch_vless_reality(seeded):
    from app.main import _client_dict, _inbound_dict

    db_user = seeded["users"]["alice"]
    client = _client_dict(seeded["clients"][("alice", "vless-reality")],
                          db_user)
    inbound = _inbound_dict(seeded["inbounds"]["vless-reality"])
    link = _dispatch("vless", client, inbound)
    back = parse_vless_link(link)
    assert back["uuid"] == client["uuid"]
    assert back["security"] == "reality"
    assert back["pbk"] == seeded["reality_public"]
    assert back["sid"] == seeded["reality_short_id"]
    assert back["name"] == NAME


@pytest.mark.parametrize("tag,protocol", [
    ("vmess-ws", "vmess"),
    ("trojan-tls", "trojan"),
    ("shadowsocks", "shadowsocks"),
    ("hysteria2", "hysteria2"),
    ("tuic", "tuic"),
    ("anytls", "anytls"),
    ("naive", "naive"),
    ("shadowtls", "shadowtls"),
])
def test_dispatch_every_protocol(seeded, tag, protocol):
    from app.main import _client_dict, _inbound_dict

    user = seeded["users"]["alice"]
    client = _client_dict(seeded["clients"][("alice", tag)], user)
    inbound = _inbound_dict(seeded["inbounds"][tag])
    link = _dispatch(protocol, client, inbound)
    assert link, f"no link built for {protocol}"
    parsed = urlparse(link)
    if protocol == "shadowtls":
        # ShadowTLS has no link of its own: it is served as a plain
        # SS (SIP002) link; ShadowTLS lives server-side as a detour.
        assert parsed.scheme == "ss"
        assert parse_ss_link(link)["password"] == client["password"]
    elif protocol == "vmess":
        assert parsed.scheme == "vmess"
        assert parse_vmess_link(link)["uuid"] == client["uuid"]
    elif protocol == "trojan":
        assert parsed.scheme == "trojan"
        assert parse_trojan_link(link)["password"] == client["password"]
    elif protocol == "shadowsocks":
        assert parsed.scheme == "ss"
        assert parse_ss_link(link)["method"] == SS_METHOD
    elif protocol == "naive":
        # The scheme is naive+https, not plain naive://.
        assert parsed.scheme == "naive+https"
        assert parsed.hostname == HOST
    else:
        assert parsed.scheme == protocol
        assert parsed.hostname == HOST


def test_dispatch_wireguard_and_ikev2_return_none(seeded):
    from app.main import _client_dict, _inbound_dict

    user = seeded["users"]["alice"]
    wg_client = _client_dict(seeded["clients"][("alice", "wireguard")], user)
    wg_inbound = _inbound_dict(seeded["inbounds"]["wireguard"])
    # No share-link standard for WireGuard / IKEv2: .conf /
    # .mobileconfig file export instead.
    assert _dispatch("wireguard", wg_client, wg_inbound) is None
    assert _dispatch("ikev2", wg_client, wg_inbound) is None
    assert _dispatch("not-a-protocol", wg_client, wg_inbound) is None


def test_dispatch_naive_username_from_extra(seeded):
    from app.main import _client_dict, _inbound_dict

    user = seeded["users"]["alice"]
    client = _client_dict(seeded["clients"][("alice", "naive")], user)
    inbound = _inbound_dict(seeded["inbounds"]["naive"])
    link = _dispatch("naive", client, inbound)
    assert urlparse(link).username == "alice-naive"


# ---------------------------------------------------------------------------
# Encoding: names / passwords with URL-special characters
# ---------------------------------------------------------------------------

def test_name_with_spaces_unicode_and_hash_round_trips():
    tricky = "علی تست #1?"
    link = build_vless_link(UUID, HOST, 443, name=tricky)
    assert parse_vless_link(link)["name"] == tricky
    link = build_vmess_link(UUID, HOST, 8443, name=tricky)
    assert parse_vmess_link(link)["name"] == tricky


def test_password_with_url_special_chars_round_trips():
    tricky = "p@ss#w?rd/x&y=z"
    link = build_trojan_link(tricky, HOST, 8444, name=NAME)
    assert parse_trojan_link(link)["password"] == tricky
    link = build_hysteria2_link(tricky, HOST, 443, name=NAME)
    parsed, _ = _parts(link)
    assert unquote(parsed.username) == tricky
    link = build_tuic_link(UUID, tricky, HOST, 8443, name=NAME)
    parsed, _ = _parts(link)
    assert unquote(parsed.password) == tricky
    link = build_naive_link("user", tricky, HOST, 8445, name=NAME)
    parsed, _ = _parts(link)
    assert unquote(parsed.password) == tricky


# ---------------------------------------------------------------------------
# Malformed input raises ValueError (never a link a client rejects)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builder,kwargs", [
    (build_vless_link, {"uuid": "", "host": HOST, "port": 443}),
    (build_vless_link, {"uuid": UUID, "host": HOST, "port": 0}),
    (build_vless_link, {"uuid": UUID, "host": HOST, "port": 70000}),
    (build_vmess_link, {"uuid": "", "host": HOST, "port": 8443}),
    (build_trojan_link, {"password": "", "host": HOST, "port": 8444}),
    (build_ss_link, {"method": "", "password": "pw",
                      "host": HOST, "port": 8388}),
    (build_hysteria2_link, {"password": "", "host": HOST, "port": 443}),
    (build_tuic_link, {"uuid": "", "password": "pw",
                        "host": HOST, "port": 8443}),
    (build_anytls_link, {"password": "", "host": HOST, "port": 8444}),
    (build_naive_link, {"username": "", "password": "pw",
                         "host": HOST, "port": 8445}),
])
def test_builders_reject_bad_input(builder, kwargs):
    with pytest.raises(ValueError):
        builder(**kwargs)


@pytest.mark.parametrize("bad", [
    "http://example.com/",
    "vless://",
    "vless://uuid-only-no-host",
    "vless://11111111-2222-4333-8444-555555555555@203.0.113.10",
    "VLESS://11111111-2222-4333-8444-555555555555@203.0.113.10:443",
    "",
    None,
    123,
])
def test_parse_vless_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_vless_link(bad)


@pytest.mark.parametrize("bad", [
    "vmess://",
    "vmess://!!!not-base64!!!",
    "vmess://" + base64.b64encode(b"not json").decode(),
    "vmess://" + base64.b64encode(b"{}").decode(),
    "vmess://" + base64.b64encode(
        json.dumps({"id": UUID, "add": HOST}).encode()).decode(),
])
def test_parse_vmess_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_vmess_link(bad)


@pytest.mark.parametrize("bad", [
    "trojan://",
    "trojan://:8444",
    "ss://",
    "ss://@@@",
    "ss://aGVsbG8",  # base64 "hello" — no method:password
    "trojan://pw@203.0.113.10",  # no port
])
def test_parse_trojan_and_ss_reject_malformed(bad):
    if bad.startswith("trojan"):
        with pytest.raises(ValueError):
            parse_trojan_link(bad)
    else:
        with pytest.raises(ValueError):
            parse_ss_link(bad)


def test_dispatch_rejects_missing_credentials():
    with pytest.raises(ValueError):
        build_share_link("vless", {"uuid": ""},
                         {"port": 443, "stream_json": {}}, HOST, NAME)
    with pytest.raises(ValueError):
        build_share_link("trojan", {"password": ""},
                         {"port": 8444, "stream_json": {}}, HOST, NAME)


# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------

def test_make_qr_png_is_a_png():
    png = make_qr_png("vless://example-link")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(png) > 100


def test_make_qr_png_differs_per_link():
    assert (make_qr_png("vless://aaa")
            != make_qr_png("vless://bbb"))


def test_links_module_exports_expected_builders():
    for name in ("build_vless_link", "build_vmess_link",
                 "build_trojan_link", "build_ss_link",
                 "build_hysteria2_link", "build_tuic_link",
                 "build_anytls_link", "build_naive_link",
                 "build_share_link", "parse_vless_link",
                 "parse_vmess_link", "parse_trojan_link",
                 "parse_ss_link", "make_qr_png"):
        assert callable(getattr(links, name)), name
