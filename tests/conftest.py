"""Shared fixtures for the sparky-manager test suite.

Everything here is written from scratch for this project, against the
real interfaces in ``app/`` (see DESIGN.md §4/§6).

Environment ordering matters: ``app.config`` reads ``SPARKY_HOME``
(and friends) at import time, so this module sets the test env vars
*before* importing any ``app.*`` module. The home points at a fresh
temp dir, the admin password and the Reality / WireGuard keys come
from the installer env vars the app prefers
(``SPARKY_ADMIN_PASSWORD``, ``SPARKY_REALITY_*``,
``SPARKY_WG_*``), so ``ensure_defaults()`` never has to generate
(and print) secrets during tests.

Each test gets a *fresh* SQLite file: the fixture creates its own
engine, calls ``init_db(engine)`` (which rebinds ``SessionLocal`` to
it), and seeds the standard inbounds / users / clients. The app's
singleton engine (bound to the temp home) is created eagerly at
import time so ``app.db.get_session()`` never rebinds ``SessionLocal``
away from the per-test engine mid-test.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Test environment — set BEFORE any app.* import (app.config reads env
# at import time).
# ---------------------------------------------------------------------------

_TEST_HOME = tempfile.mkdtemp(prefix="sparky-manager-test-home-")

# Reality keys are X25519 keys in base64url WITHOUT padding (43 chars) —
# that is the only format `xray x25519` emits and the only format real
# Xray accepts in realitySettings.privateKey (standard base64 with
# '=' padding is rejected at load). Generate them with the app's own
# generator so the test seeds match production keys exactly.
from app import xray as _xray_mod  # noqa: E402  (env-independent)

_REALITY_KEYS = _xray_mod.generate_reality_keypair()
_REALITY_PRIVATE = _REALITY_KEYS["private_key"]
_REALITY_PUBLIC = _REALITY_KEYS["public_key"]
_REALITY_SHORT_ID = secrets.token_hex(4)  # 8 hex chars

ADMIN_PASSWORD = "TestAdminPass123!"
ADMIN_USERNAME = "admin"

# Host used in share links / subscriptions: a bare TEST-NET IP, so the
# suite stays domain-agnostic (no domain is ever configured).
HOST = "203.0.113.10"

os.environ["SPARKY_HOME"] = _TEST_HOME
os.environ["SPARKY_ADMIN_PASSWORD"] = ADMIN_PASSWORD
os.environ["SPARKY_REALITY_PRIVATE_KEY"] = _REALITY_PRIVATE
os.environ["SPARKY_REALITY_PUBLIC_KEY"] = _REALITY_PUBLIC
os.environ["SPARKY_REALITY_SHORT_ID"] = _REALITY_SHORT_ID

# WireGuard server keypair: a real pair from the app's own generator
# (public key derived from the private key, like `wg` would produce).
from app import wireguard as _wireguard_mod  # noqa: E402  (env-independent)

_WG_SERVER_PRIVATE, _WG_SERVER_PUBLIC = _wireguard_mod.generate_keypair()
os.environ["SPARKY_WG_PRIVATE_KEY"] = _WG_SERVER_PRIVATE
os.environ["SPARKY_WG_PUBLIC_KEY"] = _WG_SERVER_PUBLIC

# ---------------------------------------------------------------------------
# App imports (env is set now).
# ---------------------------------------------------------------------------

from app import auth as auth_mod  # noqa: E402
from app import main as main_mod  # noqa: E402
from app import traffic as traffic_mod  # noqa: E402
from app.db import SessionLocal, get_engine, init_db  # noqa: E402
from app.main import ensure_defaults  # noqa: E402
from app.models import Client, Inbound, User, client_is_usable  # noqa: E402

# Create the singleton engine eagerly (bound to the temp home DB) so
# app.db.get_session() never rebinds SessionLocal mid-test.
get_engine()

SS_METHOD = "2022-blake3-aes-128-gcm"
# Valid 2022-blake3-aes-128-gcm key: base64 of 16 bytes ("1234567890123456").
# A random token string is NOT a valid key — real Xray rejects it at load
# ("bad key"), so test seeds must use a real key too.
SS_PASSWORD = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
# ShadowTLS stream password: also a valid SS2022 key (base64 of
# "shadowtls-key-01", 16 bytes) — the inner Shadowsocks detour reuses
# the ShadowTLS password as its own, so an arbitrary token string
# breaks the inner SS inbound at load ("illegal base64 data").
SHADOWTLS_STREAM_PASSWORD = "c2hhZG93dGxzLWtleS0wMQ=="


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _inbound_rows() -> list[dict]:
    """Inbound rows covering every Phase 1 protocol.

    Ports follow DESIGN.md §3: VLESS-Reality (TCP 443) and Hysteria2
    (UDP 443) share port 443 — legal because Inbound uniqueness is
    (port, protocol).
    """
    reality_stream = {
        "network": "tcp",
        "security": "reality",
        "reality": {
            "sni": "www.microsoft.com",
            "dest": "www.microsoft.com:443",
            "public_key": _REALITY_PUBLIC,
            "private_key": _REALITY_PRIVATE,
            "short_id": _REALITY_SHORT_ID,
        },
    }
    tls_stream = {"network": "tcp", "security": "tls", "tls": {"sni": HOST}}
    return [
        {"tag": "vless-reality", "core": "xray", "protocol": "vless",
         "port": 443, "remark": "VLESS + Reality",
         "stream_json": json.dumps(reality_stream)},
        {"tag": "hysteria2", "core": "xray", "protocol": "hysteria2",
         "port": 443, "remark": "Hysteria2 (UDP 443)",
         "stream_json": json.dumps(tls_stream)},
        {"tag": "vmess-ws", "core": "xray", "protocol": "vmess",
         "port": 8443, "remark": "VMess + WS + TLS",
         "stream_json": json.dumps(
             {"network": "ws", "security": "tls", "path": "/vmess-ws",
              "tls": {"sni": HOST}})},
        {"tag": "trojan-tls", "core": "xray", "protocol": "trojan",
         "port": 8444, "remark": "Trojan + TLS",
         "stream_json": json.dumps(tls_stream)},
        {"tag": "shadowsocks", "core": "xray", "protocol": "shadowsocks",
         "port": 8388, "remark": "Shadowsocks 2022",
         "stream_json": json.dumps({"method": SS_METHOD})},
        {"tag": "tuic", "core": "singbox", "protocol": "tuic",
         "port": 8443, "remark": "TUIC v5",
         "stream_json": json.dumps({"tls": {"sni": HOST}})},
        {"tag": "anytls", "core": "singbox", "protocol": "anytls",
         "port": 8445, "remark": "AnyTLS",
         "stream_json": json.dumps({"tls": {"sni": HOST}})},
        {"tag": "naive", "core": "singbox", "protocol": "naive",
         "port": 8446, "remark": "Naive",
         "stream_json": json.dumps({"tls": {"sni": HOST}})},
        {"tag": "shadowtls", "core": "singbox", "protocol": "shadowtls",
         "port": 8447, "remark": "ShadowTLS v3 + inner SS",
         "stream_json": json.dumps(
             {"tls": {"sni": HOST}, "method": SS_METHOD,
              "password": SHADOWTLS_STREAM_PASSWORD})},
        {"tag": "wireguard", "core": "wireguard", "protocol": "wireguard",
         "port": 51820, "remark": "WireGuard (native)",
         "stream_json": json.dumps(
             {"transport": "udp", "peer_public_key": _WG_SERVER_PUBLIC})},
        # Disabled inbound: must never render, even with a client.
        {"tag": "vmess-disabled", "core": "xray", "protocol": "vmess",
         "port": 8449, "remark": "disabled VMess", "enabled": False,
         "stream_json": json.dumps(
             {"network": "ws", "security": "tls", "path": "/off",
              "tls": {"sni": HOST}})},
    ]


def seed_all(db) -> dict:
    """Seed inbounds + users + clients; return them keyed for tests.

    Users:
    - ``alice``: usable (enabled, unlimited, never expires), a client
      on every inbound.
    - ``bob``: expired yesterday.
    - ``carol``: over quota (used == limit).
    - ``dave``: disabled.
    - ``eve``: usable user whose VLESS client is disabled (client-level
      exclusion) but whose Trojan client is fine.
    """
    now = datetime.now(timezone.utc)
    inbounds: dict[str, Inbound] = {}
    for row in _inbound_rows():
        inbound = Inbound(**row)
        db.add(inbound)
        inbounds[row["tag"]] = inbound
    db.flush()

    users: dict[str, User] = {}
    specs = [
        ("alice", {"enabled": True}),
        ("bob", {"enabled": True,
                 "expires_at": now - timedelta(days=1)}),
        ("carol", {"enabled": True, "traffic_limit_bytes": 1000,
                   "traffic_used_bytes": 1000}),
        ("dave", {"enabled": False}),
        ("eve", {"enabled": True}),
    ]
    for name, kwargs in specs:
        user = User(name=name, sub_token=secrets.token_urlsafe(24), **kwargs)
        db.add(user)
        users[name] = user
    db.flush()

    # Alice's WireGuard keypair (private in `password`, public in
    # `uuid` — the layout app.main._new_client_credentials uses).
    alice_wg_priv, alice_wg_pub = _wireguard_mod.generate_keypair()

    def _client(user_name: str, tag: str, **kwargs) -> Client:
        client = Client(user_id=users[user_name].id,
                        inbound_id=inbounds[tag].id, **kwargs)
        db.add(client)
        return client

    clients: dict[tuple[str, str], Client] = {}
    for tag in inbounds:
        kwargs: dict = {"enabled": True}
        protocol = inbounds[tag].protocol
        if protocol in ("vless", "vmess", "tuic"):
            kwargs["uuid"] = str(uuid.uuid4())
            kwargs["password"] = secrets.token_urlsafe(12)
        elif protocol in ("trojan", "hysteria2", "anytls", "naive",
                          "shadowtls"):
            kwargs["password"] = f"alice-{tag}-pw-001"
            if protocol == "shadowtls":
                # ShadowTLS is served as an SS link, so its client
                # needs a cipher method like any Shadowsocks client.
                kwargs["method"] = SS_METHOD
        elif protocol == "shadowsocks":
            kwargs["password"] = SS_PASSWORD
            kwargs["method"] = SS_METHOD
        elif protocol == "wireguard":
            kwargs["uuid"] = alice_wg_pub
            kwargs["password"] = alice_wg_priv
            kwargs["extra_json"] = json.dumps(
                {"allowed_ips": "10.8.0.2/32",
                 "private_key": alice_wg_priv})
        if protocol == "vless":
            kwargs["flow"] = "xtls-rprx-vision"
        if protocol == "naive":
            kwargs["extra_json"] = json.dumps({"username": "alice-naive"})
        clients[("alice", tag)] = _client("alice", tag, **kwargs)

    # Unusable users: one VLESS client each (plus a Trojan one for bob).
    clients[("bob", "vless-reality")] = _client(
        "bob", "vless-reality", uuid=str(uuid.uuid4()),
        flow="xtls-rprx-vision")
    clients[("bob", "trojan-tls")] = _client(
        "bob", "trojan-tls", password="bob-trojan-pw")
    clients[("carol", "vless-reality")] = _client(
        "carol", "vless-reality", uuid=str(uuid.uuid4()),
        flow="xtls-rprx-vision")
    clients[("dave", "vless-reality")] = _client(
        "dave", "vless-reality", uuid=str(uuid.uuid4()),
        flow="xtls-rprx-vision")
    # Eve: disabled VLESS client, enabled Trojan client.
    clients[("eve", "vless-reality")] = _client(
        "eve", "vless-reality", uuid=str(uuid.uuid4()),
        flow="xtls-rprx-vision", enabled=False)
    clients[("eve", "trojan-tls")] = _client(
        "eve", "trojan-tls", password="eve-trojan-pw")

    db.commit()
    return {
        "inbounds": inbounds,
        "users": users,
        "clients": clients,
        "reality_private": _REALITY_PRIVATE,
        "reality_public": _REALITY_PUBLIC,
        "reality_short_id": _REALITY_SHORT_ID,
        "wg_server_private": _WG_SERVER_PRIVATE,
        "wg_server_public": _WG_SERVER_PUBLIC,
        "alice_wg_private": alice_wg_priv,
        "alice_wg_public": alice_wg_pub,
    }


# ---------------------------------------------------------------------------
# Renderer inputs (plain dicts, as the renderers / link builders take)
# ---------------------------------------------------------------------------

def all_inbound_dicts(db) -> list[dict]:
    """Every inbound row as a plain dict (``stream_json`` parsed)."""
    return [main_mod._inbound_dict(i)
            for i in db.query(Inbound).order_by(Inbound.id).all()]


def usable_clients_by_tag(db) -> dict[str, list[dict]]:
    """Clients grouped by inbound tag, keeping only *usable* ones.

    This mirrors the pipeline in ``app.main.rerender_configs``: the
    renderers themselves only skip clients missing a credential, so
    usability filtering (expired / over-quota / disabled) is the
    caller's job — and this is the helper the render tests use.
    """
    by_tag: dict[str, list[dict]] = {}
    for client in db.query(Client).all():
        user = db.get(User, client.user_id)
        inbound = db.get(Inbound, client.inbound_id)
        if user is None or inbound is None:
            continue
        if client_is_usable(client, user, inbound):
            by_tag.setdefault(inbound.tag, []).append(
                main_mod._client_dict(client, user))
    return by_tag


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_engine(tmp_path):
    """A fresh SQLite engine (own file) with all tables created."""
    from sqlalchemy import create_engine, event
    from app.db import _set_wal

    path = tmp_path / "panel.db"
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    event.listen(engine, "connect", _set_wal)
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db(db_engine):
    """A session on a fresh, seeded DB (inbounds + users + clients)."""
    session = SessionLocal()
    try:
        seed_all(session)
        yield session
    finally:
        session.close()


@pytest.fixture()
def seeded(db):
    """The seed dict (inbounds / users / clients / keys) for ``db``."""
    return _seeded_for(db)


def _seeded_for(db) -> dict:
    """Re-read the seeded rows as a lookup dict (no re-seeding)."""
    inbounds = {i.tag: i for i in db.query(Inbound).all()}
    users = {u.name: u for u in db.query(User).all()}
    clients = {}
    for c in db.query(Client).all():
        user = db.get(User, c.user_id)
        inbound = db.get(Inbound, c.inbound_id)
        clients[(user.name, inbound.tag)] = c
    alice_wg = clients[("alice", "wireguard")]
    return {
        "inbounds": inbounds,
        "users": users,
        "clients": clients,
        "reality_private": _REALITY_PRIVATE,
        "reality_public": _REALITY_PUBLIC,
        "reality_short_id": _REALITY_SHORT_ID,
        "wg_server_private": _WG_SERVER_PRIVATE,
        "wg_server_public": _WG_SERVER_PUBLIC,
        "alice_wg_private": alice_wg.password,
        "alice_wg_public": alice_wg.uuid,
    }


@pytest.fixture()
def render_settings(tmp_path):
    """Settings dict for the renderers *with* a TLS certificate.

    The cert files are dummy files — the renderers only need the
    paths to be configured, not a real CA-signed pair.
    """
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    return {
        "domain": "",
        "subscription_host": HOST,
        "reality_sni": "www.microsoft.com",
        "reality_private_key": _REALITY_PRIVATE,
        "reality_public_key": _REALITY_PUBLIC,
        "reality_short_id": _REALITY_SHORT_ID,
        "cert_path": str(cert),
        "key_path": str(key),
        "home": str(tmp_path),
        "hysteria2_core": "xray",
    }


@pytest.fixture()
def no_cert_settings():
    """Settings dict with NO domain and NO certificate configured."""
    return {
        "domain": "",
        "subscription_host": "",
        "reality_sni": "www.microsoft.com",
        "reality_private_key": _REALITY_PRIVATE,
        "reality_public_key": _REALITY_PUBLIC,
        "reality_short_id": _REALITY_SHORT_ID,
        "home": "/tmp",
        "hysteria2_core": "xray",
    }


@pytest.fixture()
def test_client(db, tmp_path, monkeypatch):
    """A TestClient bound to the seeded test DB, logged-out.

    Config re-rendering is kept hermetic: rendered configs go to tmp
    files and ``systemctl restart`` is stubbed out (the panel is not
    installed on this machine).
    """
    from fastapi.testclient import TestClient

    monkeypatch.setattr(main_mod, "XRAY_CONFIG_PATH",
                        str(tmp_path / "xray.json"))
    monkeypatch.setattr(main_mod, "SINGBOX_CONFIG_PATH",
                        str(tmp_path / "singbox.json"))
    monkeypatch.setattr(main_mod, "WG_CONFIG_PATH",
                        str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    ensure_defaults(db)  # creates the admin from the env password
    # The panel derives the subscription host from settings, else from
    # the request host ("testserver" under TestClient). Pin it to the
    # test IP so HTTP feeds use the same host as the unit-level links.
    main_mod.set_setting(db, "subscription_host", HOST)
    # NOTE: deliberately NOT used as a context manager. Entering the
    # context runs the app lifespan, whose init_db() (no args) would
    # rebind SessionLocal to the singleton (home) engine and the
    # client would then talk to the wrong database. Without the
    # context manager, requests still work and SessionLocal stays
    # bound to this test's engine.
    client = TestClient(main_mod.app)
    yield client
    client.close()


@pytest.fixture()
def authed_client(test_client):
    """A TestClient logged in as admin (cookie session)."""
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    assert test_client.get("/api/users").status_code == 200, (
        f"login failed, last response: {resp.status_code}")
    return test_client


@pytest.fixture(autouse=True)
def _isolate_process_globals():
    """Clear in-memory global state between tests.

    The login rate limiter (per-IP failure counters) and the traffic
    syncer's cumulative baselines are process-global; a test that
    fills them must not leak into the next test.
    """
    auth_mod._failed_logins.clear()
    traffic_mod._last_wg.clear()
    traffic_mod._last_nft.clear()
    yield
    auth_mod._failed_logins.clear()
    traffic_mod._last_wg.clear()
    traffic_mod._last_nft.clear()
