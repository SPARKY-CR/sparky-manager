"""Inbound-editor tests (Phase 1 of the professional-panel expansion).

Covers the value parsers, the per-inbound address allocators, the
GET/POST edit routes (including re-rendering the live configs) and
the three regenerate routes.
"""

from __future__ import annotations

import json

import pytest

from app import amneziawg, main as main_mod
from app.main import (
    _build_stream_from_form,
    _edit_form_values,
    _fallbacks_text,
    _next_awg_address,
    _next_wg_address,
    _parse_dns_list,
    _parse_fallbacks,
    _parse_mtu,
    _parse_reality_private_key,
    _parse_short_id,
    _parse_subnet,
    _subnet_server_address,
    t_for,
)
from app.models import Inbound

T = t_for("en")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_inbound(db, *, tag, core, protocol, port, stream=None, remark=""):
    inbound = Inbound(
        tag=tag, core=core, protocol=protocol, port=port, remark=remark,
        stream_json=json.dumps(stream or {}),
    )
    db.add(inbound)
    db.commit()
    return inbound


@pytest.fixture()
def vpn_certs(tmp_path, monkeypatch):
    """Dummy CA / server cert / key / auth-script files so the
    OpenVPN + ocserv validators (which check the files exist) pass,
    and a stubbed `ocserv -t` (the binary is absent in the VM)."""
    ca = tmp_path / "ca-cert.pem"
    cert = tmp_path / "server-cert.pem"
    key = tmp_path / "server-key.pem"
    script = tmp_path / "auth.sh"
    for path in (ca, cert, key, script):
        path.write_text("dummy")
    # The OpenVPN validator requires the auth script to be executable.
    script.chmod(0o755)
    monkeypatch.setattr(main_mod, "CA_CERT_PATH", str(ca))
    monkeypatch.setattr(main_mod, "VPN_SERVER_CERT_PATH", str(cert))
    monkeypatch.setattr(main_mod, "VPN_SERVER_KEY_PATH", str(key))
    monkeypatch.setattr(main_mod, "OVPN_AUTH_SCRIPT_PATH", str(script))
    monkeypatch.setattr(main_mod, "_run_privileged", lambda *a, **kw: (0, "", ""))
    return tmp_path


def _edit_form(inbound, **overrides):
    """A complete valid edit POST for ``inbound`` (defaults from the
    current stream), with ``overrides`` applied."""
    values = _edit_form_values(inbound)
    data = {
        "tag": values["tag"],
        "port": str(values["port"]),
        "remark": values["remark"],
        "enabled": "on" if values["enabled"] else "",
        "network": values["network"],
        "security": values["security"],
        "path": values["path"],
        "host": values["host"],
        "service_name": values["service_name"],
        "mode": values["mode"],
        "fp": values["fp"],
        "sniffing": "on" if values["sniffing"] else "",
        "fallbacks": values["fallbacks"],
        "reality_dest": values["reality_dest"],
        "reality_sni": values["reality_sni"],
        "reality_server_names": values["reality_server_names"],
        "reality_short_id": values["reality_short_id"],
        "reality_private_key": values["reality_private_key"],
        "tls_sni": values["tls_sni"],
        "tls_alpn": values["tls_alpn"],
        "tls_cert_path": values["tls_cert_path"],
        "tls_key_path": values["tls_key_path"],
        "up_mbps": str(values["up_mbps"]),
        "down_mbps": str(values["down_mbps"]),
        "congestion_control": values["congestion_control"],
        "zero_rtt": "on" if values["zero_rtt"] else "",
        "strict_mode": "on" if values["strict_mode"] else "",
        "shadowtls_password": values["shadowtls_password"],
        "method": values["method"],
        "inner_port": str(values["inner_port"]),
        "subnet": values["subnet"],
        "mtu": str(values["mtu"]),
        "dns": values["dns"],
        "proto": values["proto"],
        "max_clients": str(values["max_clients"]),
    }
    for key in ("awg_jc", "awg_jmin", "awg_jmax", "awg_s1", "awg_s2",
                "awg_s3", "awg_s4", "awg_h1", "awg_h2", "awg_h3",
                "awg_h4", "awg_i1", "awg_i2", "awg_i3", "awg_i4",
                "awg_i5", "awg_header_key"):
        data[key] = str(values[key])
    data.update({key: str(value) for key, value in overrides.items()})
    # An empty checkbox value means "unchecked" — drop the key, the
    # way a browser does for an unchecked checkbox.
    return {key: value for key, value in data.items() if value != ""}


# ---------------------------------------------------------------------------
# Value parsers
# ---------------------------------------------------------------------------

def test_parse_subnet_ok_and_normalised():
    assert _parse_subnet("10.8.0.0/24") == "10.8.0.0/24"
    assert _parse_subnet("10.8.0.5/24") == "10.8.0.0/24"  # host bits dropped
    assert _parse_subnet("  192.168.1.0/24 ") == "192.168.1.0/24"


@pytest.mark.parametrize("bad", [
    "", "not-a-subnet", "10.8.0.0/33", "10.8.0.0/31", "10.8.0.1/32",
    "2001:db8::/32", "10.8.0.0", "10.8.0.0/-1",
])
def test_parse_subnet_rejects(bad):
    with pytest.raises(ValueError):
        _parse_subnet(bad)


def test_subnet_server_address():
    assert _subnet_server_address("10.8.0.0/24") == "10.8.0.1/24"
    assert _subnet_server_address("10.20.5.0/24") == "10.20.5.1/24"
    assert _subnet_server_address("10.8.0.0/30") == "10.8.0.1/30"


def test_parse_dns_list():
    assert _parse_dns_list("1.1.1.1") == ("1.1.1.1",)
    assert _parse_dns_list("1.1.1.1, 8.8.8.8") == ("1.1.1.1", "8.8.8.8")
    assert _parse_dns_list("2606:4700:4700::1111") == ("2606:4700:4700::1111",)


@pytest.mark.parametrize("bad", ["", "1.1.1.1, 8.8.8.8, 9.9.9.9", "not-an-ip", "1.1.1.1, x"])
def test_parse_dns_list_rejects(bad):
    with pytest.raises(ValueError):
        _parse_dns_list(bad)


def test_parse_mtu():
    assert _parse_mtu("") is None
    assert _parse_mtu("  ") is None
    assert _parse_mtu("1400") == 1400
    assert _parse_mtu("576") == 576
    assert _parse_mtu("9000") == 9000


@pytest.mark.parametrize("bad", ["abc", "575", "9001", "0", "-1"])
def test_parse_mtu_rejects(bad):
    with pytest.raises(ValueError):
        _parse_mtu(bad)


def test_parse_fallbacks():
    assert _parse_fallbacks("") == []
    assert _parse_fallbacks("127.0.0.1:8080") == [
        {"dest": "127.0.0.1:8080", "xver": 0}]
    assert _parse_fallbacks("127.0.0.1:8080,1\n8443") == [
        {"dest": "127.0.0.1:8080", "xver": 1},
        {"dest": 8443, "xver": 0}]
    assert _parse_fallbacks("# comment\n\n  127.0.0.1:8080  ") == [
        {"dest": "127.0.0.1:8080", "xver": 0}]


@pytest.mark.parametrize("bad", [
    "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:8080,2",
    "127.0.0.1:8080,x", "127.0.0.1:abc", ":8080",
])
def test_parse_fallbacks_rejects(bad):
    with pytest.raises(ValueError):
        _parse_fallbacks(bad)


def test_fallbacks_text_round_trip():
    fallbacks = [{"dest": "127.0.0.1:8080", "xver": 0},
                 {"dest": "127.0.0.1:8443", "xver": 1},
                 {"dest": 8443, "xver": 0}]
    assert _fallbacks_text(fallbacks) == (
        "127.0.0.1:8080\n127.0.0.1:8443,1\n8443")
    assert _parse_fallbacks(_fallbacks_text(fallbacks)) == fallbacks
    assert _fallbacks_text(None) == ""
    assert _fallbacks_text("not-a-list") == ""


def test_parse_short_id():
    assert _parse_short_id("") == ""
    assert _parse_short_id("A1B2C3D4") == "a1b2c3d4"
    assert _parse_short_id("0123456789abcdef") == "0123456789abcdef"


@pytest.mark.parametrize("bad", ["a", "abc", "zz", "0123456789abcdef01"])
def test_parse_short_id_rejects(bad):
    with pytest.raises(ValueError):
        _parse_short_id(bad)


def test_parse_reality_private_key():
    key = "a" * 43
    assert _parse_reality_private_key(key) == key
    assert _parse_reality_private_key("A-_" + "b" * 40) == "A-_" + "b" * 40


@pytest.mark.parametrize("bad", ["", "short", "a" * 42, "a" * 44, "a" * 43 + "=",
                                 "a" * 42 + "+"])
def test_parse_reality_private_key_rejects(bad):
    with pytest.raises(ValueError):
        _parse_reality_private_key(bad)


# ---------------------------------------------------------------------------
# Address allocation inside an inbound's subnet
# ---------------------------------------------------------------------------

def test_next_wg_address_uses_inbound_subnet(db, seeded):
    # Alice holds 10.8.0.2/32 on the default pool; a custom subnet
    # starts its own pool at .2.
    assert _next_wg_address(db, "10.9.0.0/24") == "10.9.0.2/32"
    assert _next_awg_address(db, "10.9.1.0/24") == "10.9.1.2/32"


def test_next_wg_address_default_keeps_old_behaviour(db, seeded):
    # Old no-arg call: alice holds .2, so the next one is .3.
    assert _next_wg_address(db) == "10.8.0.3/32"
    assert _next_awg_address(db) == "10.8.1.2/32"


def test_next_wg_address_per_inbound_scan(db, seeded):
    wg = seeded["inbounds"]["wireguard"]
    # Scoped to this inbound: alice's .2 is on it, so .3 is next.
    assert _next_wg_address(db, "10.8.0.0/24", inbound_id=wg.id) == "10.8.0.3/32"
    # Scoped to a nonexistent inbound: nothing is used, .2 is free.
    assert _next_wg_address(db, "10.8.0.0/24", inbound_id=99999) == "10.8.0.2/32"


def test_next_pool_address_exhaustion(db, seeded):
    # A /30 has exactly one peer address (.2 — .1 is the server).
    assert _next_wg_address(db, "10.9.9.0/30") == "10.9.9.2/32"
    # Fill it: a client holding .2 exhausts the pool (bob has no WG
    # client yet, so the (user, inbound) pair is free).
    wg = seeded["inbounds"]["wireguard"]
    bob = seeded["users"]["bob"]
    from app.models import Client
    db.add(Client(user_id=bob.id, inbound_id=wg.id, uuid="x",
                  extra_json=json.dumps({"allowed_ips": "10.9.9.2/32"})))
    db.commit()
    with pytest.raises(ValueError, match="exhausted"):
        _next_wg_address(db, "10.9.9.0/30")


# ---------------------------------------------------------------------------
# GET /inbounds/{id}/edit
# ---------------------------------------------------------------------------

def test_get_edit_vless_prefilled(authed_client, seeded):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
    assert resp.status_code == 200
    assert "vless-reality" in resp.text
    assert 'value="www.microsoft.com:443"' in resp.text  # reality dest
    assert f'value="{seeded["reality_short_id"]}"' in resp.text  # short id
    assert 'name="reality_private_key"' in resp.text
    assert 'name="sniffing"' in resp.text
    assert 'name="fallbacks"' in resp.text
    assert "regenerate-reality" in resp.text


def test_get_edit_wg_prefilled(authed_client, seeded):
    inbound = seeded["inbounds"]["wireguard"]
    resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
    assert resp.status_code == 200
    assert 'name="subnet"' in resp.text
    assert 'value="10.8.0.0/24"' in resp.text  # default for old inbounds
    assert 'name="mtu"' in resp.text
    assert 'name="dns"' in resp.text
    assert "regenerate-server-key" in resp.text
    # The server public key is shown (seeded in settings by ensure_defaults).
    assert seeded["wg_server_public"] in resp.text


def test_get_edit_tuic_prefilled(authed_client, seeded):
    inbound = seeded["inbounds"]["tuic"]
    resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
    assert resp.status_code == 200
    assert 'name="congestion_control"' in resp.text
    assert 'name="zero_rtt"' in resp.text
    assert 'name="tls_sni"' in resp.text
    # No security select for always-TLS protocols.
    assert 'name="security"' not in resp.text


def test_get_edit_shadowtls_prefilled(authed_client, seeded):
    inbound = seeded["inbounds"]["shadowtls"]
    resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
    assert resp.status_code == 200
    assert 'name="method"' in resp.text
    assert 'name="shadowtls_password"' in resp.text
    assert 'name="inner_port"' in resp.text
    assert 'name="strict_mode"' in resp.text


def test_get_edit_hysteria2_prefilled(authed_client, seeded):
    inbound = seeded["inbounds"]["hysteria2"]
    resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
    assert resp.status_code == 200
    assert 'name="up_mbps"' in resp.text
    assert 'name="down_mbps"' in resp.text
    assert 'name="tls_sni"' in resp.text


def test_get_edit_ovpn_ocserv_ikev2_prefilled(authed_client, db):
    ovpn = _add_inbound(db, tag="ovpn", core="openvpn", protocol="openvpn",
                        port=1194, stream={"subnet": "10.9.0.0/24",
                                           "transport": "udp"})
    ocserv = _add_inbound(db, tag="oc", core="openconnect",
                          protocol="openconnect", port=4433,
                          stream={"subnet": "10.10.10.0/24"})
    ikev2 = _add_inbound(db, tag="ike", core="ikev2", protocol="ikev2",
                         port=500, stream={"subnet": "10.20.0.0/24"})
    for inbound, extra in ((ovpn, 'name="proto"'),
                           (ocserv, 'name="max_clients"'),
                           (ikev2, 'name="subnet"')):
        resp = authed_client.get(f"/inbounds/{inbound.id}/edit")
        assert resp.status_code == 200, inbound.protocol
        assert 'name="subnet"' in resp.text
        assert 'name="dns"' in resp.text
        assert extra in resp.text


def test_get_edit_awg_prefilled(authed_client, db):
    awg = _add_inbound(db, tag="awg", core="amneziawg", protocol="amneziawg",
                       port=51821,
                       stream={"subnet": "10.8.1.0/24",
                               "awg_params": amneziawg.generate_awg_params()})
    resp = authed_client.get(f"/inbounds/{awg.id}/edit")
    assert resp.status_code == 200
    for field in ("awg_jc", "awg_jmin", "awg_jmax", "awg_s1", "awg_h1",
                  "awg_i1", "awg_header_key"):
        assert f'name="{field}"' in resp.text
    assert "regenerate-awg-params" in resp.text


def test_get_edit_unknown_id_404(authed_client):
    assert authed_client.get("/inbounds/99999/edit").status_code == 404


def test_get_edit_requires_login(test_client, seeded):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = test_client.get(f"/inbounds/{inbound.id}/edit",
                           follow_redirects=False)
    assert resp.status_code in (303, 401)


def test_inbounds_list_has_edit_button(authed_client, seeded):
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    for inbound in seeded["inbounds"].values():
        assert f"/inbounds/{inbound.id}/edit" in resp.text


# ---------------------------------------------------------------------------
# POST /inbounds/{id}/edit — happy paths (DB + re-render)
# ---------------------------------------------------------------------------

def test_post_edit_vless_to_ws_tls_rerenders(authed_client, seeded, db, tmp_path):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, network="ws", security="tls",
                        path="/ws-path", host="example.com",
                        fp="firefox", sniffing="on",
                        fallbacks="127.0.0.1:8080\n127.0.0.1:8443,1",
                        tls_sni="example.com", tls_alpn="h2, http/1.1",
                        remark="edited"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    row = db.get(Inbound, inbound.id)
    stream = row.stream
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"
    assert stream["path"] == "/ws-path"
    assert stream["host"] == "example.com"
    assert stream["fp"] == "firefox"
    assert stream["sniffing"] is True
    assert stream["fallbacks"] == [{"dest": "127.0.0.1:8080", "xver": 0},
                                   {"dest": "127.0.0.1:8443", "xver": 1}]
    assert stream["tls"]["sni"] == "example.com"
    assert stream["tls"]["alpn"] == ["h2", "http/1.1"]
    assert row.remark == "edited"
    # The re-render wrote the new settings into xray.json.
    cfg = json.loads((tmp_path / "xray.json").read_text())
    vless = [i for i in cfg["inbounds"] if i["tag"] == "vless-reality"][0]
    assert vless["streamSettings"]["network"] == "ws"
    assert vless["streamSettings"]["wsSettings"]["path"] == "/ws-path"
    assert vless["streamSettings"]["wsSettings"]["headers"]["Host"] == "example.com"
    assert vless["streamSettings"]["security"] == "tls"
    assert vless["sniffing"]["enabled"] is True
    # Fallbacks are stored in the stream but only render for raw
    # TCP — with WS the HTTP handshake has already happened, so a
    # fallback could never trigger.
    assert "fallbacks" not in vless["streamSettings"]


def test_post_edit_vless_tcp_fallbacks_render(authed_client, seeded, db, tmp_path):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, network="tcp", security="reality",
                        fallbacks="127.0.0.1:8080\n127.0.0.1:8443,1"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    cfg = json.loads((tmp_path / "xray.json").read_text())
    vless = [i for i in cfg["inbounds"] if i["tag"] == "vless-reality"][0]
    assert vless["streamSettings"]["fallbacks"] == [
        {"dest": "127.0.0.1:8080", "xver": 0},
        {"dest": "127.0.0.1:8443", "xver": 1}]


def test_post_edit_vless_to_grpc_rerenders(authed_client, seeded, db, tmp_path):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, network="grpc", security="none",
                        service_name="vless-grpc"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    cfg = json.loads((tmp_path / "xray.json").read_text())
    vless = [i for i in cfg["inbounds"] if i["tag"] == "vless-reality"][0]
    assert vless["streamSettings"]["network"] == "grpc"
    assert vless["streamSettings"]["grpcSettings"]["serviceName"] == "vless-grpc"
    assert vless["streamSettings"]["security"] == "none"


def test_post_edit_reality_private_key_derives_public_key(
        authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    from app import xray as xray_mod
    new_private = "c" * 43
    expected_public = xray_mod.reality_public_key(new_private)
    assert expected_public is not None
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, reality_private_key=new_private,
                        reality_short_id="deadbeef"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    reality = db.get(Inbound, inbound.id).stream["reality"]
    assert reality["private_key"] == new_private
    assert reality["public_key"] == expected_public
    assert reality["short_id"] == "deadbeef"


def test_post_edit_wg_subnet_mtu_dns_rerenders(
        authed_client, seeded, db, tmp_path, monkeypatch):
    inbound = seeded["inbounds"]["wireguard"]
    # The test fixture stubs _apply_wireguard_config (it owns the
    # atomic wg0.conf replace + syncconf); capture the rendered
    # content instead of reading the file.
    captured: dict[str, str] = {}

    def _capture(content, config_path="", **kw):
        captured[config_path] = content
        return None

    monkeypatch.setattr(main_mod, "_apply_wireguard_config", _capture)
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, subnet="10.77.0.0/24", mtu="1400",
                        dns="8.8.8.8, 8.8.4.4"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, inbound.id).stream
    assert stream["subnet"] == "10.77.0.0/24"
    assert stream["mtu"] == 1400
    assert stream["dns"] == ["8.8.8.8", "8.8.4.4"]
    wg_conf = captured[str(tmp_path / "wg0.conf")]
    assert "Address = 10.77.0.1/24" in wg_conf
    assert "MTU = 1400" in wg_conf
    # Existing peers keep their old addresses (no re-allocation).
    assert "10.8.0.2/32" in wg_conf


def test_post_edit_wg_subnet_new_user_uses_new_subnet(
        authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, subnet="10.77.0.0/24"),
        follow_redirects=False,
    )
    resp = authed_client.post("/api/users", json={"name": "newbie"})
    assert resp.status_code == 201, resp.text
    db.expire_all()
    from app.models import Client, User
    user = db.query(User).filter(User.name == "newbie").one()
    client = db.query(Client).filter(
        Client.user_id == user.id, Client.inbound_id == inbound.id).one()
    assert json.loads(client.extra_json)["allowed_ips"] == "10.77.0.2/32"


def test_post_edit_tuic_congestion_and_zero_rtt(
        authed_client, seeded, db, tmp_path):
    inbound = seeded["inbounds"]["tuic"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, congestion_control="cubic", zero_rtt="on"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, inbound.id).stream
    assert stream["congestion_control"] == "cubic"
    assert stream["zero_rtt_handshake"] is True


def test_post_edit_shadowtls_options(authed_client, seeded, db):
    inbound = seeded["inbounds"]["shadowtls"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, method="2022-blake3-aes-256-gcm",
                        shadowtls_password="new-pw", inner_port="12345",
                        strict_mode="on"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, inbound.id).stream
    assert stream["method"] == "2022-blake3-aes-256-gcm"
    assert stream["password"] == "new-pw"
    assert stream["inner_port"] == 12345
    assert stream["strict_mode"] is True


def test_post_edit_hysteria2_mbps(authed_client, seeded, db):
    inbound = seeded["inbounds"]["hysteria2"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/edit",
        data=_edit_form(inbound, up_mbps="100", down_mbps="200"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, inbound.id).stream
    assert stream["up_mbps"] == 100
    assert stream["down_mbps"] == 200


def test_post_edit_ovpn_proto_subnet_dns_rerenders(
        authed_client, db, tmp_path, vpn_certs):
    ovpn = _add_inbound(db, tag="ovpn", core="openvpn", protocol="openvpn",
                        port=1194, stream={"subnet": "10.9.0.0/24",
                                           "transport": "udp"})
    resp = authed_client.post(
        f"/inbounds/{ovpn.id}/edit",
        data=_edit_form(ovpn, proto="tcp", subnet="10.99.0.0/24",
                        dns="8.8.8.8"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, ovpn.id).stream
    assert stream["transport"] == "tcp"
    assert stream["subnet"] == "10.99.0.0/24"
    assert stream["dns"] == ["8.8.8.8"]
    conf = (tmp_path / "openvpn.conf").read_text()
    assert "proto tcp" in conf
    assert "10.99.0.0" in conf
    assert 'push "dhcp-option DNS 8.8.8.8"' in conf


def test_post_edit_ocserv_dns_max_clients_rerenders(
        authed_client, db, tmp_path, vpn_certs):
    ocserv = _add_inbound(db, tag="oc", core="openconnect",
                          protocol="openconnect", port=4433,
                          stream={"subnet": "10.10.10.0/24"})
    resp = authed_client.post(
        f"/inbounds/{ocserv.id}/edit",
        data=_edit_form(ocserv, subnet="10.11.0.0/24", dns="9.9.9.9",
                        max_clients="50"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, ocserv.id).stream
    assert stream["subnet"] == "10.11.0.0/24"
    assert stream["dns"] == ["9.9.9.9"]
    assert stream["max_clients"] == 50
    conf = (tmp_path / "ocserv.conf").read_text()
    assert "max-clients = 50" in conf
    assert "dns = 9.9.9.9" in conf
    assert "10.11.0.0" in conf


def test_post_edit_ikev2_subnet_dns_rerenders(
        authed_client, db, tmp_path, vpn_certs):
    ikev2 = _add_inbound(db, tag="ike", core="ikev2", protocol="ikev2",
                         port=500, stream={"subnet": "10.20.0.0/24"})
    resp = authed_client.post(
        f"/inbounds/{ikev2.id}/edit",
        data=_edit_form(ikev2, subnet="10.21.0.0/24", dns="8.8.4.4"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, ikev2.id).stream
    assert stream["subnet"] == "10.21.0.0/24"
    assert stream["dns"] == ["8.8.4.4"]
    conf = (tmp_path / "swanctl.conf").read_text()
    assert "10.21.0.0/24" in conf
    assert "8.8.4.4" in conf


def test_post_edit_awg_params_and_subnet_rerenders(
        authed_client, db, tmp_path):
    params = amneziawg.generate_awg_params()
    awg = _add_inbound(db, tag="awg", core="amneziawg", protocol="amneziawg",
                       port=51821,
                       stream={"subnet": "10.8.1.0/24", "awg_params": params})
    resp = authed_client.post(
        f"/inbounds/{awg.id}/edit",
        data=_edit_form(awg, subnet="10.88.0.0/24", mtu="1300",
                        awg_jc="5", awg_jmin="50", awg_jmax="80"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    stream = db.get(Inbound, awg.id).stream
    assert stream["subnet"] == "10.88.0.0/24"
    assert stream["mtu"] == 1300
    assert stream["awg_params"]["Jc"] == 5
    assert stream["awg_params"]["Jmin"] == 50
    assert stream["awg_params"]["Jmax"] == 80
    # I1–I5 (tags) and the header key survive the round-trip.
    assert stream["awg_params"]["I1"] == params["I1"]
    assert stream["awg_params"]["HeaderProtectionKey"] == params["HeaderProtectionKey"]
    conf = (tmp_path / "awg0.conf").read_text()
    assert "Address = 10.88.0.1/24" in conf
    assert "MTU = 1300" in conf
    assert "Jc = 5" in conf


def test_post_edit_can_disable_inbound(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    data = _edit_form(inbound)
    data.pop("enabled", None)  # unchecked checkbox is absent from the POST
    resp = authed_client.post(f"/inbounds/{inbound.id}/edit", data=data,
                              follow_redirects=False)
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(Inbound, inbound.id).enabled is False


# ---------------------------------------------------------------------------
# POST /inbounds/{id}/edit — validation errors (form shown again)
# ---------------------------------------------------------------------------

def _assert_form_reshown(authed_client, inbound, data, db):
    """POST invalid data: 200 with the edit form, DB untouched."""
    before = db.get(Inbound, inbound.id)
    before_stream = dict(before.stream)
    before_port = before.port
    resp = authed_client.post(f"/inbounds/{inbound.id}/edit", data=data)
    assert resp.status_code == 200, resp.text[:400]
    assert 'id="edit-inbound-form"' in resp.text
    assert "flash-err" in resp.text
    db.expire_all()
    after = db.get(Inbound, inbound.id)
    assert after.port == before_port
    assert after.stream == before_stream
    return resp


def test_post_edit_invalid_port(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, port="70000"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, port="abc"), db)


def test_post_edit_duplicate_tag(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, tag="vmess-ws"), db)


def test_post_edit_bad_tag(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, tag="bad tag!"), db)


def test_post_edit_port_clash_same_transport(authed_client, seeded, db):
    # vmess-ws is TCP 8443; moving VLESS (TCP) there must fail.
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, port="8443"), db)


def test_post_edit_port_clash_udp_ok(authed_client, seeded, db):
    # Hysteria2 is UDP 443 — VLESS (TCP) may share port 443 already,
    # so re-saving VLESS on 443 is fine (no clash with itself).
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(f"/inbounds/{inbound.id}/edit",
                              data=_edit_form(inbound),
                              follow_redirects=False)
    assert resp.status_code == 303, resp.text[:400]


def test_post_edit_reserved_port(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, port="4500"), db)


def test_post_edit_invalid_subnet(authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, subnet="not-a-subnet"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, subnet="10.8.0.0/31"), db)


def test_post_edit_invalid_dns(authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, dns="not-an-ip"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, dns="1.1.1.1, 8.8.8.8, 9.9.9.9"),
                         db)


def test_post_edit_invalid_mtu(authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, mtu="100"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, mtu="abc"), db)


def test_post_edit_invalid_fallbacks(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, fallbacks="127.0.0.1"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, fallbacks="127.0.0.1:8080,2"), db)


def test_post_edit_invalid_short_id(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, reality_short_id="abc"), db)


def test_post_edit_invalid_reality_key(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, reality_private_key="short"),
                         db)


def test_post_edit_reality_needs_tcp(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, security="reality",
                                    network="ws"), db)


def test_post_edit_invalid_xhttp_mode(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, network="xhttp", mode="weird"),
                         db)


def test_post_edit_invalid_mbps(authed_client, seeded, db):
    inbound = seeded["inbounds"]["hysteria2"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, up_mbps="0"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, down_mbps="-5"), db)


def test_post_edit_invalid_congestion(authed_client, seeded, db):
    inbound = seeded["inbounds"]["tuic"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, congestion_control="reno"), db)


def test_post_edit_invalid_shadowtls(authed_client, seeded, db):
    inbound = seeded["inbounds"]["shadowtls"]
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, method="aes-128-gcm"), db)
    _assert_form_reshown(authed_client, inbound,
                         _edit_form(inbound, inner_port="70000"), db)


def test_post_edit_invalid_max_clients(authed_client, db):
    ocserv = _add_inbound(db, tag="oc", core="openconnect",
                          protocol="openconnect", port=4433,
                          stream={"subnet": "10.10.10.0/24"})
    _assert_form_reshown(authed_client, ocserv,
                         _edit_form(ocserv, max_clients="0"), db)
    _assert_form_reshown(authed_client, ocserv,
                         _edit_form(ocserv, max_clients="abc"), db)


def test_post_edit_invalid_awg_params(authed_client, db):
    awg = _add_inbound(db, tag="awg", core="amneziawg", protocol="amneziawg",
                       port=51821,
                       stream={"subnet": "10.8.1.0/24",
                               "awg_params": amneziawg.generate_awg_params()})
    # Jmin > Jmax is rejected by the panel's own validator.
    _assert_form_reshown(authed_client, awg,
                         _edit_form(awg, awg_jmin="80", awg_jmax="50"), db)
    # Overlapping H values are rejected too.
    _assert_form_reshown(authed_client, awg,
                         _edit_form(awg, awg_h1="100", awg_h2="100"), db)


def test_post_edit_unknown_id_404(authed_client):
    resp = authed_client.post("/inbounds/99999/edit",
                              data={"tag": "x", "port": "443"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Regenerate routes
# ---------------------------------------------------------------------------

def test_regenerate_reality(authed_client, seeded, db):
    inbound = seeded["inbounds"]["vless-reality"]
    before = dict(inbound.stream["reality"])
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/regenerate-reality",
        follow_redirects=False)
    assert resp.status_code == 303, resp.text[:400]
    assert f"/inbounds/{inbound.id}/edit" in resp.headers["location"]
    db.expire_all()
    after = db.get(Inbound, inbound.id).stream["reality"]
    assert after["private_key"] != before["private_key"]
    assert after["public_key"] != before["public_key"]
    assert after["short_id"] != before["short_id"]
    # SNI / dest survive the regeneration.
    assert after["sni"] == before["sni"]
    assert after["dest"] == before["dest"]


def test_regenerate_reality_wrong_protocol(authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/regenerate-reality",
        follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_regenerate_awg_params(authed_client, db):
    params = amneziawg.generate_awg_params()
    awg = _add_inbound(db, tag="awg", core="amneziawg", protocol="amneziawg",
                       port=51821,
                       stream={"subnet": "10.8.1.0/24", "awg_params": params})
    resp = authed_client.post(
        f"/inbounds/{awg.id}/regenerate-awg-params",
        follow_redirects=False)
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    after = db.get(Inbound, awg.id).stream["awg_params"]
    assert after != params
    assert amneziawg.validate_awg_params(after) == []


def test_regenerate_server_key_wireguard(authed_client, seeded, db):
    inbound = seeded["inbounds"]["wireguard"]
    before_pub = main_mod.get_setting(db, "wireguard_public_key")
    before_priv = main_mod.get_setting(db, "wireguard_private_key")
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/regenerate-server-key",
        follow_redirects=False)
    assert resp.status_code == 303, resp.text[:400]
    assert f"/inbounds/{inbound.id}/edit" in resp.headers["location"]
    db.expire_all()
    new_pub = main_mod.get_setting(db, "wireguard_public_key")
    new_priv = main_mod.get_setting(db, "wireguard_private_key")
    assert new_pub != before_pub
    assert new_priv != before_priv
    # The new pair is a real keypair (public derives from private).
    from app import wireguard as wg_mod
    import base64
    priv_raw = base64.b64decode(new_priv)
    derived = base64.b64encode(
        wg_mod._x25519(priv_raw, wg_mod._BASE_POINT)).decode()
    assert derived == new_pub


def test_regenerate_server_key_wrong_protocol(authed_client, seeded):
    inbound = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/inbounds/{inbound.id}/regenerate-server-key",
        follow_redirects=False)
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]


def test_regenerate_unknown_id_404(authed_client):
    for route in ("regenerate-reality", "regenerate-awg-params",
                  "regenerate-server-key"):
        assert authed_client.post(f"/inbounds/99999/{route}").status_code == 404


# ---------------------------------------------------------------------------
# _build_stream_from_form unit tests (no HTTP)
# ---------------------------------------------------------------------------

def test_build_stream_from_form_keeps_unrelated_keys(db, seeded):
    inbound = seeded["inbounds"]["vless-reality"]
    values = _edit_form_values(inbound)
    data = {key: str(value) for key, value in values.items()
            if value not in ("", None)}
    # Switch the security to TLS: the old reality block must survive
    # (switching back restores it instead of losing the keypair).
    data["security"] = "tls"
    data["tls_sni"] = "example.com"
    stream, error = _build_stream_from_form(inbound, data, T)
    assert error is None
    assert stream["security"] == "tls"
    assert stream["tls"]["sni"] == "example.com"
    assert "reality" in stream
    assert stream["reality"]["private_key"] == seeded["reality_private"]


def test_build_stream_from_form_reality_needs_tcp(db, seeded):
    inbound = seeded["inbounds"]["vless-reality"]
    values = _edit_form_values(inbound)
    data = {key: str(value) for key, value in values.items()
            if value not in ("", None)}
    data["security"] = "reality"
    data["network"] = "grpc"
    stream, error = _build_stream_from_form(inbound, data, T)
    assert stream is None
    assert "TCP" in error
