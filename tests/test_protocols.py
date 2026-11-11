"""Tests for the v12 protocols: OpenVPN, OpenConnect (ocserv),
AmneziaWG, native IKEv2 (strongSwan).

None of the real server binaries (openvpn, ocserv, swanctl, awg)
exists in this environment (apt was declined by the user), so the
renderers are validated against their documented schemas and the
generated configs are parsed back (plist for .mobileconfig, XML for
the AnyConnect profile, crypt round-trip for ocpasswd). The report
states exactly which protocol was NOT validated against a real
binary. The panel-side apply paths are exercised with stubs /
monkeypatched privileged calls, never real system services.
"""

import base64
import json
import plistlib
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import amneziawg, ikev2, links, openconnect, openvpn, subscription, wireguard
from app import main as main_mod
from app.models import Client, Inbound, User

HOST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Fixtures: a CA + server cert, and the four new inbounds + alice clients
# ---------------------------------------------------------------------------


def _make_ca_and_server_cert(tmp_path):
    """A CA + server cert (SAN IP 203.0.113.10) via cryptography.

    Returns (ca_pem, server_pem, server_key_pem). Written to the
    temp home's data/ca/ so the panel builders find them.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sparky-manager CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
        )
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(__import__("ipaddress").ip_address(HOST))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    server_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    ca_dir = Path(main_mod.DATA_DIR) / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "ca-cert.pem").write_text(ca_pem, encoding="utf-8")
    (ca_dir / "server-cert.pem").write_text(server_pem, encoding="utf-8")
    (ca_dir / "server-key.pem").write_text(server_key_pem, encoding="utf-8")
    return ca_pem, server_pem, server_key_pem


@pytest.fixture()
def ca(tmp_path):
    return _make_ca_and_server_cert(tmp_path)


@pytest.fixture()
def proto(db, seeded, tmp_path):
    """The seeded DB plus the four v12 inbounds and alice clients."""
    alice = seeded["users"]["alice"]
    awg_private, awg_public = wireguard.generate_keypair()
    main_mod.set_setting(db, "amneziawg_private_key", awg_private)
    main_mod.set_setting(db, "amneziawg_public_key", awg_public)
    specs = [
        ("openvpn", "openvpn", "openvpn", 1194,
         {"subnet": "10.9.0.0/24", "transport": "udp"}),
        ("openconnect", "openconnect", "openconnect", 4433,
         {"subnet": "10.10.10.0/24", "transport": "tcp"}),
        ("amneziawg", "amneziawg", "amneziawg", 51821,
         {"subnet": "10.8.1.0/24", "transport": "udp",
          "awg_params": amneziawg.generate_awg_params()}),
        ("ikev2", "ikev2", "ikev2", 500,
         {"subnet": "10.20.0.0/24", "transport": "udp"}),
    ]
    inbounds = {}
    for tag, core, protocol, port, stream in specs:
        inbound = Inbound(
            tag=tag, core=core, protocol=protocol, port=port, enabled=True,
            stream_json=json.dumps(stream),
        )
        db.add(inbound)
        db.commit()
        inbounds[tag] = inbound
        creds = main_mod._new_client_credentials(inbound)
        extra = None
        if protocol == "amneziawg":
            extra = json.dumps({"allowed_ips": main_mod._next_awg_address(db)})
        db.add(Client(
            user_id=alice.id, inbound_id=inbound.id,
            uuid=creds.get("uuid"), password=creds.get("password"),
            method=creds.get("method"), flow=creds.get("flow"),
            extra_json=extra, enabled=True,
        ))
        db.commit()
    return {"inbounds": inbounds, "alice": alice,
            "awg_private": awg_private, "awg_public": awg_public}


# ---------------------------------------------------------------------------
# OpenVPN
# ---------------------------------------------------------------------------


def test_openvpn_server_config_renders_and_validates(tmp_path, ca):
    ca_pem, server_pem, server_key_pem = ca
    auth_script = Path(__file__).resolve().parent.parent / "scripts" / "ovpn-auth.py"
    content = openvpn.render_server_config(
        port=1194, proto="udp", network="10.9.0.0/24",
        ca_cert=str(Path(main_mod.DATA_DIR) / "ca" / "ca-cert.pem"),
        server_cert=str(Path(main_mod.DATA_DIR) / "ca" / "server-cert.pem"),
        server_key=str(Path(main_mod.DATA_DIR) / "ca" / "server-key.pem"),
        auth_script=str(auth_script),
    )
    assert "port 1194" in content
    assert "proto udp" in content
    assert "server 10.9.0.0 255.255.255.0" in content
    assert "client-cert-not-required" in content
    assert "auth-user-pass-verify" in content
    assert "cipher AES-256-GCM" in content
    problems = openvpn.validate_server_config(
        content,
        ca_cert=str(Path(main_mod.DATA_DIR) / "ca" / "ca-cert.pem"),
        server_cert=str(Path(main_mod.DATA_DIR) / "ca" / "server-cert.pem"),
        server_key=str(Path(main_mod.DATA_DIR) / "ca" / "server-key.pem"),
        auth_script=str(auth_script),
    )
    assert problems == [], problems


def test_openvpn_server_config_rejects_bad_subnet():
    content = openvpn.render_server_config(
        port=1194, network="10.9.0.0/24",
        ca_cert="/nonexistent/ca.pem", server_cert="/nonexistent/cert.pem",
        server_key="/nonexistent/key.pem",
    )
    problems = openvpn.validate_server_config(content)
    assert problems  # the cert files do not exist


def test_openvpn_client_config_embeds_ca(tmp_path, ca):
    ca_pem, _server_pem, _key = ca
    text = openvpn.render_client_config(
        host=HOST, port=1194, proto="udp", ca_cert_pem=ca_pem
    )
    assert "client" in text
    assert f"remote {HOST} 1194" in text
    assert "auth-user-pass" in text
    assert "<ca>" in text and "</ca>" in text
    assert "BEGIN CERTIFICATE" in text
    # The embedded CA is the panel CA (parseable back to DER).
    assert ikev2.pem_to_der(ca_pem) is not None


def test_ovpn_auth_script(tmp_path):
    """scripts/ovpn-auth.py against a minimal panel DB (subprocess)."""
    script = Path(__file__).resolve().parent.parent / "scripts" / "ovpn-auth.py"
    db_path = tmp_path / "panel.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER)")
    conn.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, protocol TEXT, core TEXT, enabled INTEGER)")
    conn.execute(
        "CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER, "
        "inbound_id INTEGER, password TEXT, enabled INTEGER)"
    )
    conn.execute("INSERT INTO users VALUES (1, 'alice', 1)")
    conn.execute("INSERT INTO users VALUES (2, 'mallory', 0)")
    conn.execute("INSERT INTO inbounds VALUES (1, 'openvpn', 'openvpn', 1)")
    conn.execute("INSERT INTO clients VALUES (1, 1, 1, 'secret-pw', 1)")
    conn.commit()
    conn.close()
    env = dict(__import__("os").environ)
    env["SPARKY_DB"] = str(db_path)
    creds = tmp_path / "creds.txt"

    def run(username, password):
        creds.write_text(f"{username}\n{password}\n", encoding="utf-8")
        proc = subprocess.run(
            ["python3", str(script), str(creds)],
            capture_output=True, text=True, env=env, timeout=15,
        )
        return proc.returncode

    assert run("alice", "secret-pw") == 0
    assert run("alice", "wrong-pw") == 1
    assert run("mallory", "secret-pw") == 1
    assert run("nobody", "secret-pw") == 1


# ---------------------------------------------------------------------------
# OpenConnect (ocserv)
# ---------------------------------------------------------------------------


def test_ocserv_config_renders_and_validates(tmp_path, ca):
    content = openconnect.render_ocserv_config(
        port=4433, network="10.10.10.0/24",
        server_cert=str(Path(main_mod.DATA_DIR) / "ca" / "server-cert.pem"),
        server_key=str(Path(main_mod.DATA_DIR) / "ca" / "server-key.pem"),
        passwd_file=str(tmp_path / "ocpasswd"),
    )
    assert "tcp-port = 4433" in content
    assert "udp-port = 4433" in content
    assert "ipv4-network = 10.10.10.0" in content
    assert "route = default" in content
    assert "cisco-client-compat = true" in content
    (tmp_path / "ocpasswd").write_text("", encoding="utf-8")
    problems = openconnect.validate_ocserv_config(
        content,
        passwd_file=str(tmp_path / "ocpasswd"),
        server_cert=str(Path(main_mod.DATA_DIR) / "ca" / "server-cert.pem"),
        server_key=str(Path(main_mod.DATA_DIR) / "ca" / "server-key.pem"),
    )
    assert problems == [], problems


def test_ocpasswd_crypt_round_trip():
    text = openconnect.render_ocpasswd([("alice", "secret-pw"), ("bob", "pw2")])
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 2
    for line in lines:
        username, _group, hashed = line.split(":")
        assert username in ("alice", "bob")
        assert hashed.startswith("$6$")
    stored = dict((line.split(":")[0], line.split(":")[2]) for line in lines)
    assert openconnect.verify_password("secret-pw", stored["alice"])
    assert not openconnect.verify_password("wrong", stored["alice"])
    with pytest.raises(ValueError):
        openconnect.render_ocpasswd([("bad:name", "pw")])


def test_openconnect_profile_xml_parses():
    text = openconnect.render_profile_xml(host=HOST, port=4433)
    root = ET.fromstring(text)
    assert root.tag.endswith("AnyConnectProfile")
    ns = "{http://schemas.xmlsoap.org/encoding/}"
    address = root.find(f".//{ns}HostAddress")
    assert address is not None and address.text == f"{HOST}:4433"
    trust = root.find(f".//{ns}StrictCertificateTrust")
    assert trust is not None and trust.text == "false"


# ---------------------------------------------------------------------------
# AmneziaWG
# ---------------------------------------------------------------------------


def test_amneziawg_server_and_client_configs_match(proto):
    params = json.loads(proto["inbounds"]["amneziawg"].stream_json)["awg_params"]
    server = amneziawg.render_server_config(
        proto["awg_private"],
        [{"public_key": "x", "allowed_ips": "10.8.1.2/32"}],
        params=params,
    )
    assert "Jc = 4" in server
    assert "S1 = 15" in server
    assert "HeaderProtectionKey = " in server
    # Server and client carry the same S/H/header values (they must match).
    client = amneziawg.render_peer_config(
        "priv", "10.8.1.2/32", proto["awg_public"], HOST, params=params
    )
    for key in ("S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey"):
        assert f"{key} = {params[key]}" in server
        assert f"{key} = {params[key]}" in client


# ---------------------------------------------------------------------------
# IKEv2 (strongSwan)
# ---------------------------------------------------------------------------


def test_swanctl_config_renders_and_validates():
    content = ikev2.render_swanctl_config(
        users=[(1, "alice", "secret-pw"), (2, "bob", "pw2")],
        server_id=HOST,
        network="10.20.0.0/24",
    )
    assert "pools {" in content
    assert "addrs = 10.20.0.0/24" in content
    assert "connections {" in content
    assert "remote-access" in content
    assert "version = 2" in content
    assert "auth = eap-mschapv2" in content
    assert "eap-user-1" in content
    assert 'id = "alice"' in content
    assert 'secret = "secret-pw"' in content
    assert ikev2.validate_swanctl_config(content) == []
    assert ikev2.validate_swanctl_config("garbage {")  # unbalanced / missing


def test_server_id_from_cert_pem(tmp_path, ca):
    _ca_pem, server_pem, _key = ca
    assert ikev2.server_id_from_cert_pem(server_pem) == HOST
    assert ikev2.server_id_from_cert_pem("not a cert") is None


def test_mobileconfig_parses_and_links_ca(tmp_path, ca):
    ca_pem, _server_pem, _key = ca
    ca_der = ikev2.pem_to_der(ca_pem)
    assert ca_der is not None
    blob = ikev2.render_mobileconfig(
        user_name="alice", eap_password="secret-pw",
        server_host=HOST, server_id=HOST, ca_cert_der=ca_der,
    )
    profile = plistlib.loads(blob)
    assert profile["PayloadType"] == "Configuration"
    assert profile["PayloadVersion"] == 1
    payloads = profile["PayloadContent"]
    assert len(payloads) == 2
    vpn = payloads[0]
    assert vpn["PayloadType"] == "com.apple.vpn.managed"
    assert vpn["VPNType"] == "IKEv2"
    ike = vpn["IKEv2"]
    assert ike["RemoteAddress"] == HOST
    assert ike["RemoteIdentifier"] == HOST
    assert ike["LocalIdentifier"] == "alice"
    assert ike["AuthenticationMethod"] == "Certificate"
    assert ike["ExtendedAuthEnabled"] is True
    assert ike["AuthName"] == "alice"
    assert ike["AuthPassword"] == "secret-pw"
    sa = ike["IKESecurityAssociationParameters"]
    assert sa["EncryptionAlgorithm"] == "AES-256"
    assert sa["IntegrityAlgorithm"] == "SHA2-256"
    assert sa["DiffieHellmanGroup"] == 14
    root = payloads[1]
    assert root["PayloadType"] == "com.apple.security.root"
    assert root["PayloadContent"] == ca_der
    # The VPN payload links to the CA payload by UUID.
    assert ike["PayloadCertificateUUID"] == root["PayloadUUID"]


# ---------------------------------------------------------------------------
# Credentials, ports, inbound creation
# ---------------------------------------------------------------------------


def test_new_client_credentials_per_protocol(db, seeded, proto):
    inbounds = proto["inbounds"]
    for tag in ("openvpn", "openconnect", "ikev2"):
        creds = main_mod._new_client_credentials(inbounds[tag])
        assert creds["password"] and len(creds["password"]) >= 16
        assert "uuid" not in creds or not creds.get("uuid")
    awg_creds = main_mod._new_client_credentials(inbounds["amneziawg"])
    assert awg_creds["password"] and awg_creds["uuid"]
    # AWG keypair is a real X25519 pair (public derives from private).
    derived = base64.b64encode(
        wireguard._x25519(
            base64.b64decode(awg_creds["password"]), wireguard._BASE_POINT
        )
    ).decode("ascii")
    assert awg_creds["uuid"] == derived


def test_awg_address_pool_is_separate_from_wg(db, seeded, proto):
    alice = seeded["users"]["alice"]
    first = main_mod._next_awg_address(db)
    assert first.startswith("10.8.1.")
    # alice already holds 10.8.1.2/32 (from the fixture) — the next one
    # must not reuse it, and must never come from the WG pool.
    assert first != "10.8.1.2/32"
    assert not first.startswith("10.8.0.")


def test_suggest_protocol_port(db, seeded):
    assert main_mod.suggest_protocol_port(db, "openvpn", "udp") == 1194
    assert main_mod.suggest_protocol_port(db, "openconnect", "tcp") == 4433
    assert main_mod.suggest_protocol_port(db, "amneziawg", "udp") == 51821
    assert main_mod.suggest_protocol_port(db, "ikev2", "udp") == 500


def test_create_inbound_ikev2_port_500_allowed(authed_client, db, seeded):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "ikev2-main", "core": "ikev2", "protocol": "ikev2",
              "port": 500, "remark": "", "sni": "", "path": "",
              "network": "udp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    inbound = db.query(Inbound).filter(Inbound.tag == "ikev2-main").first()
    assert inbound is not None and inbound.port == 500
    assert json.loads(inbound.stream_json)["subnet"] == "10.20.0.0/24"


def test_create_inbound_rejects_reserved_4500(authed_client, db, seeded):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "bad4500", "core": "xray", "protocol": "vless",
              "port": 4500, "remark": "", "sni": "", "path": "",
              "network": "tcp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(Inbound).filter(Inbound.tag == "bad4500").first() is None


def test_create_inbound_openconnect_blocks_both_transports(
    authed_client, db, seeded, proto
):
    # The fixture already has an openconnect inbound on 4433 (TCP+UDP).
    # A UDP inbound on the same port must clash even though the
    # single-transport check would allow it.
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "udp4433", "core": "xray", "protocol": "vless",
              "port": 4433, "remark": "", "sni": "", "path": "",
              "network": "udp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(Inbound).filter(Inbound.tag == "udp4433").first() is None


def test_create_inbound_openvpn_stores_subnet_and_awg_params(
    authed_client, db, seeded
):
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "ovpn1", "core": "openvpn", "protocol": "openvpn",
              "port": 0, "remark": "", "sni": "", "path": "",
              "network": "udp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    inbound = db.query(Inbound).filter(Inbound.tag == "ovpn1").first()
    assert inbound is not None
    assert inbound.port == 1194  # preferred port, empty port field
    assert json.loads(inbound.stream_json)["subnet"] == "10.9.0.0/24"
    resp = authed_client.post(
        "/inbounds",
        data={"tag": "awg1", "core": "amneziawg", "protocol": "amneziawg",
              "port": 0, "remark": "", "sni": "", "path": "",
              "network": "udp"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    inbound = db.query(Inbound).filter(Inbound.tag == "awg1").first()
    assert inbound is not None
    assert inbound.port == 51821
    stream = json.loads(inbound.stream_json)
    assert amneziawg.validate_awg_params(stream["awg_params"]) == []


# ---------------------------------------------------------------------------
# Feeds, bundle, file exports
# ---------------------------------------------------------------------------


def test_new_protocols_absent_from_singbox_feed(db, seeded, proto):
    alice = seeded["users"]["alice"]
    settings = main_mod.get_settings(db)
    for client, inbound in main_mod._usable_clients(db, alice):
        if inbound.protocol in ("openvpn", "openconnect", "ikev2", "amneziawg"):
            outbounds = subscription.outbounds_for_client(
                inbound.protocol,
                main_mod._client_dict(client, alice),
                main_mod._inbound_dict(inbound),
                HOST,
                f"{alice.name}-{inbound.tag}",
            )
            assert outbounds == [], inbound.protocol


def test_amneziawg_vpn_link_in_v2rayng_feed(db, seeded, proto):
    alice = seeded["users"]["alice"]
    settings = main_mod.get_settings(db)
    links = [e["link"] for e in main_mod._links_for_user(db, alice, HOST, settings)]
    vpn_links = [link for link in links if link.startswith("vpn://")]
    assert len(vpn_links) == 1
    conf = amneziawg.parse_vpn_link(vpn_links[0])
    assert "PrivateKey = " in conf
    assert "Jc = 4" in conf


def test_bundle_carries_file_exports(db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    settings = main_mod.get_settings(db)
    bundle = main_mod._build_zedsecure_bundle(db, alice, HOST, settings)
    by_tag = {entry["tag"]: entry for entry in bundle["configs"]}
    assert "openvpn_config" in by_tag["openvpn"]
    assert by_tag["openvpn"]["openvpn_config"].startswith("# sparky-manager")
    assert "BEGIN CERTIFICATE" in by_tag["openvpn"]["openvpn_config"]
    oc = by_tag["openconnect"]["openconnect"]
    assert oc["host"] == HOST and oc["port"] == 4433
    assert oc["username"] == "alice" and oc["password"]
    assert "<AnyConnectProfile" in oc["profile_xml"]
    assert "Jc = 4" in by_tag["amneziawg"]["amneziawg_conf"]
    assert by_tag["amneziawg"]["share_link"].startswith("vpn://")
    mobileconfig = by_tag["ikev2"]["ikev2_mobileconfig"]
    profile = plistlib.loads(mobileconfig.encode("utf-8"))
    assert profile["PayloadContent"][0]["IKEv2"]["RemoteAddress"] == HOST
    # No new protocol leaked into the sing-box feed.
    singbox_tags = {
        obj.get("tag") for obj in bundle["singbox"].get("outbounds", [])
    }
    assert not ({"openvpn", "openconnect", "amneziawg", "ikev2"} & singbox_tags)


def test_file_export_endpoints(test_client, db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    token = alice.sub_token
    for path, marker in (
        (f"/sub/{token}/openvpn.ovpn", "BEGIN CERTIFICATE"),
        (f"/sub/{token}/openconnect.xml", "AnyConnectProfile"),
        (f"/sub/{token}/amneziawg.conf", "Jc = 4"),
        (f"/sub/{token}/ikev2.mobileconfig", "com.apple.vpn.managed"),
    ):
        resp = test_client.get(path)
        assert resp.status_code == 200, path
        assert marker in resp.text, path
        assert "attachment" in resp.headers.get("content-disposition", "")
    # Unknown token -> 403 with an empty body (same rule as the feeds).
    assert test_client.get("/sub/nope/openvpn.ovpn").status_code == 403
    # No usable inbound of that protocol -> 404.
    bob = seeded["users"]["bob"]
    assert test_client.get(f"/sub/{bob.sub_token}/openvpn.ovpn").status_code in (403, 404)


def test_user_detail_shows_file_export_urls(authed_client, db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert f"/sub/{alice.sub_token}/openvpn.ovpn" in resp.text
    assert f"/sub/{alice.sub_token}/ikev2.mobileconfig" in resp.text


# ---------------------------------------------------------------------------
# Re-render of the new cores (privileged calls stubbed)
# ---------------------------------------------------------------------------


def test_rerender_new_protocols(db, seeded, proto, ca, tmp_path, monkeypatch):
    """The four new cores render + write their server configs.

    OpenVPN / ocserv / IKEv2 apply paths are stubbed (no real
    services here); AmneziaWG reports honestly that its tools are
    missing in this environment — the config is still written.
    """
    auth_script = tmp_path / "ovpn-auth.py"
    auth_script.write_text(
        (Path(__file__).resolve().parent.parent / "scripts" / "ovpn-auth.py")
        .read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    auth_script.chmod(0o755)
    monkeypatch.setattr(main_mod, "XRAY_CONFIG_PATH", str(tmp_path / "xray.json"))
    monkeypatch.setattr(main_mod, "SINGBOX_CONFIG_PATH", str(tmp_path / "singbox.json"))
    monkeypatch.setattr(main_mod, "WG_CONFIG_PATH", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(main_mod, "OVPN_CONFIG_PATH", str(tmp_path / "openvpn.conf"))
    monkeypatch.setattr(main_mod, "OCSERV_CONFIG_PATH", str(tmp_path / "ocserv.conf"))
    monkeypatch.setattr(main_mod, "OCSERV_PASSWD_PATH", str(tmp_path / "ocpasswd"))
    monkeypatch.setattr(main_mod, "AWG_CONFIG_PATH", str(tmp_path / "awg0.conf"))
    monkeypatch.setattr(main_mod, "SWANCTL_CONFIG_PATH", str(tmp_path / "swanctl.conf"))
    monkeypatch.setattr(
        main_mod, "CA_CERT_PATH",
        str(Path(main_mod.DATA_DIR) / "ca" / "ca-cert.pem"),
    )
    monkeypatch.setattr(
        main_mod, "VPN_SERVER_CERT_PATH",
        str(Path(main_mod.DATA_DIR) / "ca" / "server-cert.pem"),
    )
    monkeypatch.setattr(
        main_mod, "VPN_SERVER_KEY_PATH",
        str(Path(main_mod.DATA_DIR) / "ca" / "server-key.pem"),
    )
    monkeypatch.setattr(main_mod, "OVPN_AUTH_SCRIPT_PATH", str(auth_script))
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    monkeypatch.setattr(main_mod, "_apply_wireguard_config",
                        lambda content, **kw: None)
    monkeypatch.setattr(main_mod, "_apply_ikev2_config", lambda: None)
    monkeypatch.setattr(
        main_mod, "_run_privileged", lambda *a, **kw: (0, "", "")
    )
    errors = main_mod.rerender_configs(db)
    # The only expected error: AmneziaWG tools are absent here.
    assert [e for e in errors if "openvpn" in e.lower()] == []
    assert [e for e in errors if "ocserv" in e.lower()] == []
    assert [e for e in errors if "ikev2" in e.lower()] == []
    awg_errors = [e for e in errors if "amneziawg" in e.lower()]
    assert len(awg_errors) == 1 and "not installed" in awg_errors[0]
    ovpn = (tmp_path / "openvpn.conf").read_text(encoding="utf-8")
    assert "port 1194" in ovpn and "server 10.9.0.0 255.255.255.0" in ovpn
    ocserv = (tmp_path / "ocserv.conf").read_text(encoding="utf-8")
    assert "tcp-port = 4433" in ocserv
    passwd = (tmp_path / "ocpasswd").read_text(encoding="utf-8")
    assert passwd.startswith("alice::")
    assert "$6$" in passwd
    awg = (tmp_path / "awg0.conf").read_text(encoding="utf-8")
    assert "ListenPort = 51821" in awg and "Jc = 4" in awg
    swanctl = (tmp_path / "swanctl.conf").read_text(encoding="utf-8")
    assert "remote-access" in swanctl and 'id = "alice"' in swanctl
    assert HOST in swanctl  # server id from the server cert SAN
