"""Auto-generation + privilege fixes (v11).

- Inbound form pre-fill: free port, unique tag, Reality keypair.
- ``_restart_service`` / ``wg show`` go through ``sudo -n`` when
  sudo exists (the panel runs as an unprivileged user; the installer
  grants NOPASSWD sudo for exactly those commands).
- Env-var fallback: ``SPARKY_*`` wins, pre-rename ``VPN_PANEL_*``
  still works.
"""

from __future__ import annotations

import base64
import socket

import pytest

from app import main as main_mod
from app import wireguard as wg_mod
from app import xray as xray_mod


# ---------------------------------------------------------------------------
# Reality keypair
# ---------------------------------------------------------------------------

def test_generate_reality_keypair_format():
    pair = xray_mod.generate_reality_keypair()
    assert set(pair) == {"private_key", "public_key"}
    for value in pair.values():
        # base64url WITHOUT padding (43 chars), same as `xray x25519`.
        assert len(value) == 43
        assert all(c.isalnum() or c in "-_" for c in value)
        assert len(base64.urlsafe_b64decode(value + "=")) == 32


def test_generate_reality_keypair_derives():
    """The public key is the X25519 of the private key (verified
    against the real `xray x25519` output during development)."""
    pair = xray_mod.generate_reality_keypair()

    def dec(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    derived = base64.urlsafe_b64encode(
        wg_mod._x25519(dec(pair["private_key"]), wg_mod._BASE_POINT)
    ).rstrip(b"=").decode()
    assert derived == pair["public_key"]


def test_generate_reality_keypair_differs():
    assert xray_mod.generate_reality_keypair() != xray_mod.generate_reality_keypair()


# ---------------------------------------------------------------------------
# Free-port suggestion
# ---------------------------------------------------------------------------

def test_port_is_bindable_roundtrip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    assert main_mod._port_is_bindable(port) is False
    sock.close()
    assert main_mod._port_is_bindable(port) is True


def test_suggest_free_port_rules(db):
    port = main_mod.suggest_free_port(db, "tcp")
    assert 10000 <= port <= 60000
    assert port not in (500, 4500)
    assert port != main_mod.PANEL_PORT
    used_tcp = {i.port for i in db.query(main_mod.Inbound).all()
                if main_mod._stream_transport(i.stream, i.protocol) == "tcp"}
    assert port not in used_tcp


def test_suggest_free_port_differs(db):
    assert main_mod.suggest_free_port(db, "tcp") != main_mod.suggest_free_port(db, "tcp")


def test_suggest_free_port_avoids_used_udp(db):
    """A UDP inbound's port must not be suggested for a UDP inbound,
    but a TCP inbound may share it (VLESS TCP 443 + Hysteria2 UDP 443)."""
    port = main_mod.suggest_free_port(db, "udp")
    used_udp = {i.port for i in db.query(main_mod.Inbound).all()
                if main_mod._stream_transport(i.stream, i.protocol) == "udp"}
    assert port not in used_udp


def test_suggest_inbound_tag_unique(db):
    from app.models import Inbound
    # "vmess-9999" is free in the seed, so it is suggested as-is.
    assert main_mod.suggest_inbound_tag(db, "vmess", 9999) == "vmess-9999"
    # Once it is taken, the suggestion gets a -2 suffix.
    db.add(Inbound(tag="vmess-9999", core="xray", protocol="vmess", port=9999))
    db.commit()
    assert main_mod.suggest_inbound_tag(db, "vmess", 9999) == "vmess-9999-2"


# ---------------------------------------------------------------------------
# Inbound form: pre-fill + auto-generation on POST
# ---------------------------------------------------------------------------

def test_inbounds_page_prefills(authed_client):
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    html = resp.text
    assert 'id="inbound-port"' in html
    assert "🎲" in html  # regenerate button
    # The pre-filled port is a free one in range.
    import re
    m = re.search(r'id="inbound-port"[^>]*value="(\d+)"', html)
    assert m, "port input has no pre-filled value"
    assert 10000 <= int(m.group(1)) <= 60000


def test_create_inbound_auto_port_and_tag(authed_client, db):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "", "core": "xray", "protocol": "vmess",
              "port": "0", "network": "tcp", "sni": "", "path": "", "remark": ""},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    row = db.query(main_mod.Inbound).filter(
        main_mod.Inbound.protocol == "vmess",
        main_mod.Inbound.port != 8443).order_by(main_mod.Inbound.id.desc()).first()
    assert row is not None
    assert 10000 <= row.port <= 60000
    assert row.tag == f"vmess-{row.port}"


def test_create_inbound_vless_reality_gets_keypair(authed_client, db):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "vless-auto", "core": "xray", "protocol": "vless",
              "port": "0", "network": "tcp", "sni": "www.microsoft.com",
              "path": "", "remark": ""},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    row = db.query(main_mod.Inbound).filter(
        main_mod.Inbound.tag == "vless-auto").first()
    assert row is not None
    reality = row.stream.get("reality") or {}
    assert len(reality.get("private_key", "")) == 43
    assert len(reality.get("public_key", "")) == 43
    assert len(reality.get("short_id", "")) == 8
    assert row.stream.get("security") == "reality"


def test_create_inbound_reserved_port_still_rejected(authed_client):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "bad-port", "core": "xray", "protocol": "vless",
              "port": "500", "network": "tcp", "sni": "", "path": "", "remark": ""},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)


def test_create_inbound_taken_tag_still_rejected(authed_client):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "vless-reality", "core": "xray", "protocol": "vless",
              "port": "0", "network": "tcp", "sni": "", "path": "", "remark": ""},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)


# ---------------------------------------------------------------------------
# Privileged commands go through sudo -n
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_restart_service_uses_sudo(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return _FakeProc(0)

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(main_mod.shutil, "which", lambda name: "/usr/bin/sudo")
    assert main_mod._restart_service("xray") is None
    assert seen["argv"] == ["sudo", "-n", "systemctl", "restart", "xray"]


def test_restart_service_without_sudo(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return _FakeProc(0)

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(main_mod.shutil, "which", lambda name: None)
    assert main_mod._restart_service("xray") is None
    assert seen["argv"] == ["systemctl", "restart", "xray"]


def test_restart_service_sudo_denied_reports_error(monkeypatch):
    def fake_run(argv, **kwargs):
        return _FakeProc(1, stderr="sudo: a password is required")

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(main_mod.shutil, "which", lambda name: "/usr/bin/sudo")
    err = main_mod._restart_service("xray")
    assert err is not None and "password is required" in err


def test_privileged_cmd_wg(monkeypatch):
    monkeypatch.setattr(main_mod.shutil, "which", lambda name: "/usr/bin/sudo")
    assert main_mod._privileged_cmd("wg", "show", "wg0", "transfer") == [
        "sudo", "-n", "wg", "show", "wg0", "transfer"]
    monkeypatch.setattr(main_mod.shutil, "which", lambda name: None)
    assert main_mod._privileged_cmd("wg", "show", "wg0", "transfer") == [
        "wg", "show", "wg0", "transfer"]


# ---------------------------------------------------------------------------
# Env fallback + rename
# ---------------------------------------------------------------------------

def test_env_fallback_old_keys(monkeypatch):
    from app import config as cfg
    monkeypatch.setenv("SPARKY_HOME", "")
    monkeypatch.setenv("VPN_PANEL_HOME", "/tmp/fallback-home")
    monkeypatch.delenv("SPARKY_PORT", raising=False)
    monkeypatch.delenv("VPN_PANEL_PORT", raising=False)
    assert cfg.get_settings().home.as_posix() == "/tmp/fallback-home"
    monkeypatch.setenv("SPARKY_HOME", "/tmp/new-home")
    assert cfg.get_settings().home.as_posix() == "/tmp/new-home"


def test_session_cookie_renamed():
    assert main_mod.SESSION_COOKIE == "sparky_manager_session"
