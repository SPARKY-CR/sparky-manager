"""Config-render tests (DESIGN.md §5) — render -> validate.

Written from scratch against the real ``app.xray`` / ``app.singbox`` /
``app.wireguard`` / ``app.traffic`` signatures. Renderers take plain
dicts built from the seeded DB, exactly as ``app.main`` feeds them.
"""

from __future__ import annotations

import base64
import json
import re
import time

import pytest

from app import singbox, traffic, wireguard, xray
from app.main import rerender_configs
from tests.conftest import (
    HOST, SS_METHOD, all_inbound_dicts, usable_clients_by_tag,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inbound_tags(cfg: dict, key: str = "tag") -> list[str]:
    return [i[key] for i in cfg["inbounds"]]


def _all_client_ids(cfg: dict) -> set[str]:
    ids = set()
    for inbound in cfg["inbounds"]:
        for client in inbound.get("settings", {}).get("clients", []):
            if client.get("id"):
                ids.add(client["id"])
    return ids


def _all_client_passwords(cfg: dict) -> set[str]:
    passwords = set()
    for inbound in cfg["inbounds"]:
        settings = inbound.get("settings", {})
        if settings.get("password"):
            passwords.add(settings["password"])
        for client in settings.get("clients", []):
            if client.get("password"):
                passwords.add(client["password"])
    return passwords


def _render_xray(db, settings):
    return xray.render_xray_config(
        all_inbound_dicts(db), usable_clients_by_tag(db), settings)


def _render_singbox(db, settings):
    return singbox.render_singbox_config(
        all_inbound_dicts(db), usable_clients_by_tag(db), settings)


# ---------------------------------------------------------------------------
# Xray
# ---------------------------------------------------------------------------

def test_xray_renders_valid_json_config(db, render_settings):
    cfg = _render_xray(db, render_settings)
    text = json.dumps(cfg, ensure_ascii=False)
    assert json.loads(text) == cfg  # JSON-serialisable, round-trips
    ok, errors = xray.validate_xray_config(cfg)
    assert ok, errors


def test_xray_always_has_api_stats_routing_outbounds(db, render_settings):
    cfg = _render_xray(db, render_settings)
    assert cfg["api"]["services"] == [
        "HandlerService", "LoggerService", "StatsService"]
    assert cfg["stats"] == {}
    assert any(i["tag"] == "api" and i["port"] == 10085
               and i["listen"] == "127.0.0.1" for i in cfg["inbounds"])
    tags = {o["tag"] for o in cfg["outbounds"]}
    assert {"direct", "blackhole"} <= tags


def test_xray_reality_tcp443_and_hysteria2_udp443_coexist(db, render_settings):
    """The default first pair shares port 443 (TCP vs UDP, §3)."""
    cfg = _render_xray(db, render_settings)
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    reality = by_tag["vless-reality"]
    hy2 = by_tag["hysteria2"]
    assert reality["port"] == 443 and hy2["port"] == 443
    assert reality["protocol"] == "vless"
    # Verified against real Xray 26.11.9 (xray run -test): the native
    # inbound is protocol "hysteria" with settings.version == 2 and
    # streamSettings.network == "hysteria" — "hysteria2"/"udp" are
    # rejected by this Xray. The DB/client-facing name stays hysteria2.
    assert hy2["protocol"] == "hysteria"
    assert hy2["settings"]["version"] == 2
    reality_settings = reality["streamSettings"]["realitySettings"]
    assert reality_settings["serverNames"] == ["www.microsoft.com"]
    assert reality_settings["dest"] == "www.microsoft.com:443"
    assert reality["streamSettings"]["security"] == "reality"
    assert hy2["streamSettings"]["network"] == "hysteria"
    ok, errors = xray.validate_xray_config(cfg)
    assert ok, errors


def test_xray_vless_clients_carry_vision_flow(db, render_settings):
    cfg = _render_xray(db, render_settings)
    vless = next(i for i in cfg["inbounds"]
                 if i["tag"] == "vless-reality")
    assert vless["settings"]["decryption"] == "none"
    assert vless["settings"]["clients"]
    assert all(c.get("flow") == "xtls-rprx-vision"
               for c in vless["settings"]["clients"])


def test_xray_vmess_and_trojan_render(db, render_settings):
    cfg = _render_xray(db, render_settings)
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    vmess = by_tag["vmess-ws"]
    assert vmess["streamSettings"]["network"] == "ws"
    assert vmess["streamSettings"]["wsSettings"]["path"] == "/vmess-ws"
    assert all(c["alterId"] == 0 and c["security"] == "auto"
               for c in vmess["settings"]["clients"])
    trojan = by_tag["trojan-tls"]
    assert trojan["streamSettings"]["security"] == "tls"
    assert trojan["settings"]["clients"]


def test_xray_shadowsocks_2022_renders(db, render_settings):
    cfg = _render_xray(db, render_settings)
    ss = next(i for i in cfg["inbounds"] if i["tag"] == "shadowsocks")
    assert ss["settings"]["method"] == SS_METHOD
    assert ss["settings"]["network"] == "tcp,udp"
    assert ss["settings"]["password"]


def test_render_omits_unusable_clients(db, render_settings, seeded):
    """Expired / over-quota / disabled users (and a disabled client)
    never reach the rendered configs — DESIGN.md §4."""
    xcfg = _render_xray(db, render_settings)
    scfg, _ = _render_singbox(db, render_settings)

    alice = seeded["users"]["alice"]
    alice_uuid = seeded["clients"][("alice", "vless-reality")].uuid
    assert alice_uuid in _all_client_ids(xcfg)

    for name in ("bob", "carol", "dave"):
        user_uuid = seeded["clients"][(name, "vless-reality")].uuid
        assert user_uuid not in _all_client_ids(xcfg), name
    # Bob's Trojan password must not appear anywhere in the Xray config.
    assert "bob-trojan-pw" not in _all_client_passwords(xcfg)
    # Eve's disabled VLESS client is omitted, her Trojan client stays.
    eve_uuid = seeded["clients"][("eve", "vless-reality")].uuid
    assert eve_uuid not in _all_client_ids(xcfg)
    assert "eve-trojan-pw" in _all_client_passwords(xcfg)
    # Same story on the sing-box side: only Alice's TUIC uuid renders.
    tuic = next(i for i in scfg["inbounds"] if i["tag"] == "tuic")
    tuic_uuids = {u["uuid"] for u in tuic["users"]}
    assert seeded["clients"][("alice", "tuic")].uuid in tuic_uuids
    assert len(tuic_uuids) == 1


def test_render_omits_disabled_inbound(db, render_settings):
    xcfg = _render_xray(db, render_settings)
    assert "vmess-disabled" not in _inbound_tags(xcfg)


def test_rerender_configs_writes_xray_without_unusable_users(
        db, tmp_path, monkeypatch):
    """End-to-end pipeline: main.rerender_configs() writes a config
    file that contains Alice and no expired/over-quota user."""
    from app import main as main_mod

    monkeypatch.setattr(main_mod, "XRAY_CONFIG_PATH",
                        str(tmp_path / "xray.json"))
    monkeypatch.setattr(main_mod, "SINGBOX_CONFIG_PATH",
                        str(tmp_path / "singbox.json"))
    monkeypatch.setattr(main_mod, "WG_CONFIG_PATH",
                        str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    errors = rerender_configs(db)
    # sing-box TLS inbounds are omitted (no cert in the DB settings),
    # which surfaces as warnings — the Xray write itself must succeed.
    assert (tmp_path / "xray.json").exists()
    cfg = json.loads((tmp_path / "xray.json").read_text())
    ok, val_errors = xray.validate_xray_config(cfg)
    assert ok, val_errors
    assert "vless-reality" in _inbound_tags(cfg)
    assert "hysteria2" in _inbound_tags(cfg)
    text = json.dumps(cfg)
    assert "bob-trojan-pw" not in text


def test_xray_validator_rejects_bad_configs():
    base = {"inbounds": [{"tag": "a", "port": 443, "protocol": "vless",
                          "settings": {"clients": [{"id": "x"}]}}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]}
    # Two TCP inbounds on one port.
    bad = json.loads(json.dumps(base))
    bad["inbounds"].append(
        {"tag": "b", "port": 443, "protocol": "vmess",
         "settings": {"clients": [{"id": "y"}]}})
    ok, errors = xray.validate_xray_config(bad)
    assert not ok and errors
    # VLESS client without an id.
    bad2 = json.loads(json.dumps(base))
    bad2["inbounds"][0]["settings"]["clients"] = [{"flow": "x"}]
    ok, errors = xray.validate_xray_config(bad2)
    assert not ok and errors
    # Port 0 is never valid; missing inbounds list is invalid.
    bad3 = json.loads(json.dumps(base))
    bad3["inbounds"][0]["port"] = 0
    assert not xray.validate_xray_config(bad3)[0]
    assert not xray.validate_xray_config({"outbounds": []})[0]
    assert not xray.validate_xray_config("not-a-dict")[0]


def test_xray_write_and_validate_round_trip(tmp_path):
    cfg = xray.render_xray_config(
        [{"tag": "vless-reality", "core": "xray", "protocol": "vless",
          "port": 443, "enabled": True,
          "stream_json": {"network": "tcp", "security": "reality",
                          "reality": {"sni": "www.microsoft.com"}}}],
        {"vless-reality": [{"uuid": "11111111-2222-4333-8444-555555555555",
                            "flow": "xtls-rprx-vision"}]},
        {})
    target = tmp_path / "xray.json"
    ok, messages = xray.write_and_validate(cfg, target,
                                           binary="/nonexistent/xray")
    assert ok
    assert messages == ["binary not present — JSON validated only"]
    assert json.loads(target.read_text()) == cfg
    # An invalid config is refused and never replaces the good file.
    bad = json.loads(json.dumps(cfg))
    bad["inbounds"][1]["port"] = 0
    ok, errors = xray.write_and_validate(bad, target,
                                         binary="/nonexistent/xray")
    assert not ok and errors
    assert json.loads(target.read_text()) == cfg


# ---------------------------------------------------------------------------
# sing-box
# ---------------------------------------------------------------------------

def test_singbox_renders_valid_config(db, render_settings):
    cfg, warnings = _render_singbox(db, render_settings)
    assert json.loads(json.dumps(cfg)) == cfg  # JSON-serialisable
    ok, errors = singbox.validate_singbox_config(cfg)
    assert ok, errors
    assert warnings == []
    assert {"type": "direct", "tag": "direct"} in cfg["outbounds"]
    assert cfg["log"]["level"] == "info"


def test_singbox_all_tls_inbounds_present_with_cert(db, render_settings):
    cfg, _ = _render_singbox(db, render_settings)
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    assert by_tag["tuic"]["type"] == "tuic"
    assert by_tag["tuic"]["congestion_control"] == "bbr"
    assert by_tag["tuic"]["tls"]["alpn"] == ["h3"]
    assert by_tag["anytls"]["type"] == "anytls"
    assert by_tag["naive"]["type"] == "naive"
    assert by_tag["naive"]["users"][0]["username"] == "alice-naive"
    for tag in ("tuic", "anytls", "naive"):
        assert by_tag[tag]["tls"]["server_name"] == HOST
        assert by_tag[tag]["tls"]["certificate_path"]
        assert by_tag[tag]["tls"]["key_path"]
    # ShadowTLS needs no local certificate (it mimics a remote
    # handshake), so it carries a `handshake`, not a `tls` block.
    assert by_tag["shadowtls"]["handshake"]["server"] == HOST
    assert "tls" not in by_tag["shadowtls"]


def test_singbox_tls_inbounds_omitted_without_cert(db, no_cert_settings):
    """No domain / no certificate -> TLS inbounds are omitted with a
    warning, never rendered broken (DESIGN.md §5.2). Reality +
    WireGuard carry the install instead. ShadowTLS is the exception:
    it needs no local certificate (handshake only), so it still
    renders."""
    cfg, warnings = _render_singbox(db, no_cert_settings)
    tags = _inbound_tags(cfg)
    for tag in ("tuic", "anytls", "naive"):
        assert tag not in tags, tag
    assert "shadowtls" in tags
    assert warnings, "expected warnings for the omitted TLS inbounds"
    assert any("certificate" in w for w in warnings)
    ok, errors = singbox.validate_singbox_config(cfg)
    assert ok, errors


def test_singbox_shadowtls_detour_present(db, render_settings):
    cfg, _ = _render_singbox(db, render_settings)
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    outer = by_tag["shadowtls"]
    assert outer["type"] == "shadowtls"
    assert outer["version"] == 3
    assert outer["strict_mode"] is True
    assert outer["users"][0]["password"]
    assert outer["users"][0]["name"]
    assert "password" not in outer  # v3 uses `users`, not `password`
    # sing-box shadowtls inbounds have NO "tls" field (rejected as
    # an unknown field); the handshake names the mimicked server.
    assert "tls" not in outer
    assert outer["handshake"]["server"] == HOST
    assert outer["handshake"]["server_port"] == 443
    inner_tag = outer["detour"]
    assert inner_tag == "shadowtls-inner"
    inner = by_tag[inner_tag]
    assert inner["type"] == "shadowsocks"
    assert inner["listen"] == "127.0.0.1"  # never exposed to the internet
    assert inner["listen_port"] == 28388
    assert inner["method"] == SS_METHOD
    assert inner["password"] == outer["users"][0]["password"]
    ok, errors = singbox.validate_singbox_config(cfg)
    assert ok, errors


def test_singbox_hysteria2_stays_with_xray_by_default(db, render_settings):
    """hysteria2_core defaults to "xray": sing-box must not also
    claim UDP/443."""
    cfg, warnings = _render_singbox(db, render_settings)
    assert "hysteria2" not in _inbound_tags(cfg)
    assert warnings == []


def test_singbox_validator_rejects_bad_configs():
    good = {"inbounds": [{"type": "tuic", "tag": "tuic", "listen": "::",
                          "listen_port": 8443,
                          "users": [{"uuid": "u", "password": "p"}],
                          "tls": {"enabled": True, "server_name": HOST,
                                  "certificate_path": "/c.pem",
                                  "key_path": "/k.pem"}}],
            "outbounds": [{"type": "direct", "tag": "direct"}]}
    assert singbox.validate_singbox_config(good)[0]
    # ShadowTLS detour pointing nowhere.
    bad = json.loads(json.dumps(good))
    bad["inbounds"].append(
        {"type": "shadowtls", "tag": "st", "listen": "::",
         "listen_port": 8447, "version": 3,
         "users": [{"name": "u", "password": "pw"}],
         "detour": "no-such-inbound",
         "handshake": {"server": HOST, "server_port": 443}})
    ok, errors = singbox.validate_singbox_config(bad)
    assert not ok and any("detour" in e for e in errors)
    # TUIC user without a password.
    bad2 = json.loads(json.dumps(good))
    bad2["inbounds"][0]["users"] = [{"uuid": "u"}]
    assert not singbox.validate_singbox_config(bad2)[0]
    # Two TCP inbounds on one port (TUIC is UDP, so it may share a
    # port with a TCP inbound — use two TCP types to force a clash).
    bad3 = json.loads(json.dumps(good))
    bad3["inbounds"].append(
        {"type": "anytls", "tag": "at", "listen": "::",
         "listen_port": 8444, "users": [{"password": "p"}],
         "tls": {"enabled": True, "server_name": HOST,
                 "certificate_path": "/c.pem", "key_path": "/k.pem"}})
    bad3["inbounds"].append(
        {"type": "naive", "tag": "nv", "listen": "::",
         "listen_port": 8444,
         "users": [{"username": "u", "password": "p"}],
         "tls": {"enabled": True, "server_name": HOST,
                 "certificate_path": "/c.pem", "key_path": "/k.pem"}})
    assert not singbox.validate_singbox_config(bad3)[0]


def test_singbox_write_and_validate_round_trip(tmp_path):
    cfg, _ = singbox.render_singbox_config(
        [{"tag": "anytls", "core": "singbox", "protocol": "anytls",
          "port": 8444, "enabled": True,
          "stream_json": {"tls": {"sni": HOST}}}],
        {"anytls": [{"password": "pw-001"}]},
        {"domain": HOST, "cert_path": "/c.pem", "key_path": "/k.pem"})
    target = tmp_path / "singbox.json"
    ok, messages = singbox.write_and_validate(
        cfg, target, binary="/nonexistent/sing-box")
    assert ok
    assert messages == ["binary not present — JSON validated only"]
    assert json.loads(target.read_text()) == cfg


# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------

def test_generate_keypair_format():
    priv, pub = wireguard.generate_keypair()
    assert priv != pub
    for key in (priv, pub):
        assert len(key) == 44  # base64 of 32 bytes, with padding
        assert len(base64.b64decode(key)) == 32
    # Fresh randomness: two pairs never coincide.
    assert wireguard.generate_keypair() != (priv, pub)


def test_render_wg_config(db, seeded):
    server_priv = seeded["wg_server_private"]
    alice_pub = seeded["alice_wg_public"]
    text = wireguard.render_wg_config(
        server_priv,
        [{"public_key": alice_pub, "allowed_ips": "10.8.0.2/32"},
         {"public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          "allowed_ips": "10.8.0.3/32",
          "preshared_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
         {"allowed_ips": "10.8.0.4/32"},  # no key -> skipped
         {"public_key": alice_pub}],       # no IPs -> skipped
        address="10.8.0.1/24", listen_port=51820)
    assert "[Interface]" in text
    assert f"PrivateKey = {server_priv}" in text
    assert "Address = 10.8.0.1/24" in text
    assert "ListenPort = 51820" in text
    assert text.count("[Peer]") == 2
    assert f"PublicKey = {alice_pub}" in text
    assert "AllowedIPs = 10.8.0.2/32" in text
    assert "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in text


def test_render_peer_config_round_trip():
    peer_priv, peer_pub = wireguard.generate_keypair()
    server_priv, server_pub = wireguard.generate_keypair()
    text = wireguard.render_peer_config(
        peer_priv, "10.8.0.2/32", server_pub, HOST, 51820)
    # Parse the rendered .conf back and check every field survived.
    assert f"PrivateKey = {peer_priv}" in text
    assert "Address = 10.8.0.2/32" in text
    assert f"PublicKey = {server_pub}" in text
    assert f"Endpoint = {HOST}:51820" in text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
    assert "PersistentKeepalive = 25" in text
    assert "MTU = 1280" in text
    # The peer config is itself a valid wg config: the server can
    # render a matching [Peer] from the peer's public key.
    server_cfg = wireguard.render_wg_config(
        server_priv, [{"public_key": peer_pub,
                       "allowed_ips": "10.8.0.2/32"}])
    assert f"PublicKey = {peer_pub}" in server_cfg


def test_render_peer_config_brackets_ipv6_host():
    peer_priv, _ = wireguard.generate_keypair()
    _, server_pub = wireguard.generate_keypair()
    text = wireguard.render_peer_config(
        peer_priv, "10.8.0.2/32", server_pub, "2001:db8::1")
    assert "Endpoint = [2001:db8::1]:51820" in text


def test_parse_wg_show_human_format(seeded):
    pub = seeded["alice_wg_public"]
    text = (
        f"interface: wg0\n"
        f"  public key: {seeded['wg_server_public']}\n"
        f"peer: {pub}\n"
        f"  endpoint: 198.51.100.7:51820\n"
        f"  latest handshake: 1 minute, 37 seconds ago\n"
        f"  transfer: 1.23 KiB received, 4.56 KiB sent\n"
    )
    parsed = wireguard.parse_wg_show(text)
    assert pub in parsed
    # `transfer` counters are from the interface's view: bytes
    # received FROM the peer are the peer's upload, bytes sent TO the
    # peer are its download — the same convention as
    # traffic.parse_wg_transfer.
    assert parsed[pub]["transfer_up"] == 1260  # 1.23 KiB received
    assert parsed[pub]["transfer_down"] == 4669  # 4.56 KiB sent
    assert parsed[pub]["latest_handshake_seconds_ago"] == 97


def test_parse_wg_show_dump_format(seeded):
    pub = seeded["alice_wg_public"]
    now = int(time.time())
    dump = (
        f"{seeded['wg_server_public']}\t(none)\t(none)\t10.8.0.1/32\t"
        f"{now - 60}\t100\t200\toff\n"
        f"{pub}\t(none)\t198.51.100.7:51820\t10.8.0.2/32\t"
        f"{now - 30}\t5000\t7000\toff\n"
    )
    parsed = wireguard.parse_wg_show(dump)
    assert parsed[pub]["transfer_up"] == 5000
    assert parsed[pub]["transfer_down"] == 7000
    assert 25 <= parsed[pub]["latest_handshake_seconds_ago"] <= 35


@pytest.mark.parametrize("text", ["", None, "nothing to see here\n",
                                  "interface: wg0\n  public key: abc\n"])
def test_parse_wg_show_tolerates_garbage(text):
    assert wireguard.parse_wg_show(text) == {}


# ---------------------------------------------------------------------------
# Traffic parsers (app.traffic)
# ---------------------------------------------------------------------------

def test_parse_wg_transfer(seeded):
    pub = seeded["alice_wg_public"]
    text = f"{pub}\t12345\t67890\n" "bad line\n" f"otherkey 1 2\n"
    parsed = traffic.parse_wg_transfer(text)
    assert parsed[pub] == (12345, 67890)  # (up, down)
    assert parsed["otherkey"] == (1, 2)
    assert traffic.parse_wg_transfer("") == {}
    assert traffic.parse_wg_transfer(None) == {}


def test_parse_wg_handshakes(seeded):
    pub = seeded["alice_wg_public"]
    text = f"{pub}\t42\nneverkey\t0\n"
    parsed = traffic.parse_wg_handshakes(text)
    assert parsed[pub] == 42
    assert parsed["neverkey"] is None  # 0 means "never handshaked"


def test_parse_nft_counters():
    text = (
        "table inet filter {\n"
        "  chain input {\n"
        "    tcp dport 8443 counter packets 10 bytes 1234 accept\n"
        "    udp dport 8443 counter packets 5 bytes 500 accept\n"
        "    tcp dport 8445 counter packets 2 bytes 99 accept\n"
        "  }\n"
        "}\n"
    )
    parsed = traffic.parse_nft_counters(text)
    assert parsed[8443] == (5, 500)  # later rule wins for the same port
    assert parsed[8445] == (2, 99)
    assert traffic.parse_nft_counters("") == {}
    assert traffic.parse_nft_counters("counter packets 1 bytes 2") == {}


def test_inject_panel_cert_warns_only_for_self_signed(tmp_path):
    """The render warning "(clients must allow insecure)" must only
    fire for the self-signed pair — a Let's Encrypt certificate in
    the same paths is trusted and needs no such warning (v8.1)."""
    import importlib.util
    import subprocess
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "render_configs", Path(__file__).resolve().parent.parent / "scripts" / "render_configs.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    home = tmp_path / "panel"
    certs = home / "certs"
    certs.mkdir(parents=True)
    cert, key = certs / "fullchain.pem", certs / "privkey.pem"
    for subj, trusted in (
        ("/CN=203.0.113.7", False),
        ("/C=US/O=Let's Encrypt/CN=203.0.113.7", True),
    ):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "2",
             "-subj", subj],
            check=True, capture_output=True,
        )
        settings: dict[str, str] = {"home": str(home)}
        warnings: list[str] = []
        mod._inject_panel_cert_paths(settings, warnings=warnings)
        assert settings["self_signed_cert_path"] == str(cert)
        assert settings["self_signed_key_path"] == str(key)
        insecure = [w for w in warnings if "allow insecure" in w]
        assert (not insecure) is trusted, (subj, warnings)
