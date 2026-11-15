"""Add user to any inbound + detach + edit-page nits (post-upgrade batch).

The web UI had no way to add an EXISTING user to another inbound:
new users get one client per enabled inbound, but an inbound created
after the user left them without a client on it. This batch adds
attach (any protocol, incl. shared inbounds) and detach (one inbound
only) on the user detail page, plus the edit-page hint fixes.

One client per (user, inbound) stays — the UniqueConstraint is
untouched and no schema change is involved.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app import main as main_mod
from app.main import t_for
from app.models import AuditLog, Client, Inbound, User
from tests.conftest import HOST


# ---------------------------------------------------------------------------
# i18n: every new key exists in both languages
# ---------------------------------------------------------------------------

NEW_KEYS = [
    "add_to_inbound", "add_inbound_hint", "add_inbound_none",
    "user_inbound_added", "user_inbound_detached", "already_on_inbound",
    "invalid_inbound", "add_inbound_address_exhausted", "detach",
    "confirm_detach", "confirm_detach_last", "move_no_targets",
]


def test_add_to_inbound_keys_exist_in_both_languages():
    fa, en = t_for("fa"), t_for("en")
    for key in NEW_KEYS:
        assert fa.get(key), f"missing fa key: {key}"
        assert en.get(key), f"missing en key: {key}"
        assert fa[key] != en[key], f"untranslated key: {key}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_inbound(db, *, tag, core, protocol, port, stream=None,
                 remark="", enabled=True):
    inbound = Inbound(
        tag=tag, core=core, protocol=protocol, port=port, remark=remark,
        enabled=enabled, stream_json=json.dumps(stream or {}),
    )
    db.add(inbound)
    db.commit()
    return inbound


def _add_user(db, name):
    user = User(name=name, sub_token=uuid.uuid4().hex, enabled=True)
    db.add(user)
    db.commit()
    return user


def _client_of(db, user_id, inbound_id):
    return (
        db.query(Client)
        .filter(Client.user_id == user_id, Client.inbound_id == inbound_id)
        .first()
    )


def _clients_of(db, user_id):
    return db.query(Client).filter(Client.user_id == user_id).all()


def _latest_audit(db, action):
    return (
        db.query(AuditLog)
        .filter(AuditLog.action == action)
        .order_by(AuditLog.id.desc())
        .first()
    )


def _xray_config(tmp_path):
    return json.loads((tmp_path / "xray.json").read_text())


def _inbound_cfg(cfg, tag):
    for inbound in cfg.get("inbounds", []):
        if inbound.get("tag") == tag:
            return inbound
    return None


# ---------------------------------------------------------------------------
# Add to inbound — fresh credentials per protocol
# ---------------------------------------------------------------------------

def test_add_bob_to_hysteria2_creates_fresh_client(
        authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    hy2 = seeded["inbounds"]["hysteria2"]
    assert _client_of(db, bob.id, hy2.id) is None
    resp = authed_client.post(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(hy2.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = _client_of(db, bob.id, hy2.id)
    assert client is not None
    assert client.enabled
    assert client.password  # hysteria2 = password auth
    # Fresh — not a copy of alice's credential on the same inbound.
    alice_pw = seeded["clients"][("alice", "hysteria2")].password
    assert client.password != alice_pw
    audit = _latest_audit(db, "user.add_inbound")
    assert audit is not None
    assert "bob" in (audit.detail or "")
    assert "hysteria2" in (audit.detail or "")


def test_add_carol_to_shared_trojan_inbound(authed_client, seeded, db):
    # trojan-tls already serves alice, bob and eve — a shared inbound
    # must still accept a new user.
    carol = seeded["users"]["carol"]
    trojan = seeded["inbounds"]["trojan-tls"]
    before = (
        db.query(Client)
        .filter(Client.inbound_id == trojan.id)
        .count()
    )
    assert before == 3
    resp = authed_client.post(
        f"/users/{carol.id}/add-inbound",
        data={"inbound_id": str(trojan.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = _client_of(db, carol.id, trojan.id)
    assert client is not None
    assert client.password
    assert (
        db.query(Client).filter(Client.inbound_id == trojan.id).count()
        == before + 1
    )


def test_add_dave_to_openvpn_native_protocol(authed_client, seeded, db):
    # Native protocols (username/password auth) get a fresh password;
    # the username is the panel user name at render time.
    dave = seeded["users"]["dave"]
    ovpn = _add_inbound(
        db, tag="openvpn-test", core="openvpn", protocol="openvpn",
        port=1194, stream={"subnet": "10.9.0.0/24"},
    )
    resp = authed_client.post(
        f"/users/{dave.id}/add-inbound",
        data={"inbound_id": str(ovpn.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = _client_of(db, dave.id, ovpn.id)
    assert client is not None
    assert client.enabled
    assert client.password
    assert client.uuid is None


def test_add_dave_to_wireguard_allocates_address(
        authed_client, seeded, db):
    # Alice holds 10.8.0.2/32 on this inbound; the next peer gets .3.
    dave = seeded["users"]["dave"]
    wg = seeded["inbounds"]["wireguard"]
    resp = authed_client.post(
        f"/users/{dave.id}/add-inbound",
        data={"inbound_id": str(wg.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = _client_of(db, dave.id, wg.id)
    assert client is not None
    assert client.uuid  # public key
    assert client.password  # private key
    assert client.extra.get("allowed_ips") == "10.8.0.3/32"


def test_add_calls_rerender(authed_client, seeded, db, monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        main_mod, "rerender_configs", lambda _db: calls.append(1) or []
    )
    bob = seeded["users"]["bob"]
    vmess = seeded["inbounds"]["vmess-ws"]
    resp = authed_client.post(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(vmess.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    assert len(calls) == 1


def test_add_renders_new_client_into_xray_config(
        authed_client, seeded, db, tmp_path):
    # End to end: the new client shows up in the rendered config.
    frank = _add_user(db, "frank")
    vless = seeded["inbounds"]["vless-reality"]
    resp = authed_client.post(
        f"/users/{frank.id}/add-inbound",
        data={"inbound_id": str(vless.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = _client_of(db, frank.id, vless.id)
    assert client is not None and client.uuid
    cfg = _xray_config(tmp_path)
    inbound_cfg = _inbound_cfg(cfg, "vless-reality")
    assert inbound_cfg is not None
    ids = {
        c.get("id")
        for c in inbound_cfg.get("settings", {}).get("clients", [])
    }
    assert client.uuid in ids


# ---------------------------------------------------------------------------
# Add to inbound — rejections
# ---------------------------------------------------------------------------

def test_add_rejected_when_already_on_inbound(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    trojan = seeded["inbounds"]["trojan-tls"]
    before = len(_clients_of(db, bob.id))
    resp = authed_client.post(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(trojan.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    assert len(_clients_of(db, bob.id)) == before


def test_add_rejected_for_disabled_inbound(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    off = seeded["inbounds"]["vmess-disabled"]
    resp = authed_client.post(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(off.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    db.expire_all()
    assert _client_of(db, bob.id, off.id) is None


def test_add_rejected_for_missing_or_empty_inbound(
        authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    for data in ({"inbound_id": "99999"}, {"inbound_id": ""}, {}):
        resp = authed_client.post(
            f"/users/{bob.id}/add-inbound",
            data=data,
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "err=" in resp.headers["location"]
    db.expire_all()
    assert len(_clients_of(db, bob.id)) == 2


def test_add_to_missing_user_404(authed_client, seeded, db):
    hy2 = seeded["inbounds"]["hysteria2"]
    resp = authed_client.post(
        "/users/99999/add-inbound",
        data={"inbound_id": str(hy2.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Detail page — picker vs. already-on-all state
# ---------------------------------------------------------------------------

def test_detail_page_picker_for_bob_all_inbounds_state_for_alice(
        authed_client, seeded, db):
    t = t_for("fa")
    bob = seeded["users"]["bob"]
    resp = authed_client.get(f"/users/{bob.id}")
    assert resp.status_code == 200
    assert f"/users/{bob.id}/add-inbound" in resp.text
    # hysteria2 is one of bob's addable inbounds (an <option> for it).
    assert "hysteria2" in resp.text
    assert t["add_inbound_none"] not in resp.text

    alice = seeded["users"]["alice"]  # a client on every inbound
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert t["add_inbound_none"] in resp.text
    assert f"/users/{alice.id}/add-inbound" not in resp.text


# ---------------------------------------------------------------------------
# Detach
# ---------------------------------------------------------------------------

def test_detach_removes_only_that_client(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    # Capture ids up front: after expire_all() the deleted row's
    # object raises ObjectDeletedError on attribute access.
    trojan_id = seeded["clients"][("bob", "trojan-tls")].id
    vless_id = seeded["clients"][("bob", "vless-reality")].id
    alice_trojan_id = seeded["clients"][("alice", "trojan-tls")].id
    resp = authed_client.post(
        f"/users/{bob.id}/detach/{trojan_id}",
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(Client, trojan_id) is None
    assert db.get(Client, vless_id) is not None
    assert db.get(Client, alice_trojan_id) is not None
    audit = _latest_audit(db, "user.detach_inbound")
    assert audit is not None
    assert "bob" in (audit.detail or "")
    assert "trojan-tls" in (audit.detail or "")


def test_detach_calls_rerender(authed_client, seeded, db, monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        main_mod, "rerender_configs", lambda _db: calls.append(1) or []
    )
    bob = seeded["users"]["bob"]
    trojan_client = seeded["clients"][("bob", "trojan-tls")]
    resp = authed_client.post(
        f"/users/{bob.id}/detach/{trojan_client.id}",
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    assert len(calls) == 1


def test_detach_last_client_allowed_with_warning(
        authed_client, seeded, db):
    # Carol has exactly one client. Zero-client users are a normal
    # state (fresh installs start with no inbounds; deleting an
    # inbound can leave users at zero), and add-to-inbound makes the
    # detach reversible — so it is allowed, with a distinct warning.
    t = t_for("fa")
    carol = seeded["users"]["carol"]
    client = seeded["clients"][("carol", "vless-reality")]
    resp = authed_client.get(f"/users/{carol.id}")
    assert resp.status_code == 200
    assert t["confirm_detach_last"] in resp.text
    resp = authed_client.post(
        f"/users/{carol.id}/detach/{client.id}",
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert _clients_of(db, carol.id) == []
    assert db.get(User, carol.id) is not None  # the user survives
    # The detail page still renders, with the add picker available.
    resp = authed_client.get(f"/users/{carol.id}")
    assert resp.status_code == 200
    assert f"/users/{carol.id}/add-inbound" in resp.text


def test_detach_other_users_client_404(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    alice_vless = seeded["clients"][("alice", "vless-reality")]
    resp = authed_client.post(
        f"/users/{bob.id}/detach/{alice_vless.id}",
        follow_redirects=False,
    )
    assert resp.status_code == 404
    db.expire_all()
    assert db.get(Client, alice_vless.id) is not None


def test_detach_missing_client_404(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    resp = authed_client.post(
        f"/users/{bob.id}/detach/99999",
        follow_redirects=False,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth + CSRF on the new routes
# ---------------------------------------------------------------------------

def test_new_routes_require_csrf(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    hy2 = seeded["inbounds"]["hysteria2"]
    trojan_client = seeded["clients"][("bob", "trojan-tls")]
    resp = authed_client.post_raw(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(hy2.id)},
    )
    assert resp.status_code == 403
    resp = authed_client.post_raw(
        f"/users/{bob.id}/detach/{trojan_client.id}",
    )
    assert resp.status_code == 403
    db.expire_all()
    assert _client_of(db, bob.id, hy2.id) is None
    assert db.get(Client, trojan_client.id) is not None


def test_new_routes_require_login(test_client, seeded, db):
    bob = seeded["users"]["bob"]
    hy2 = seeded["inbounds"]["hysteria2"]
    trojan_client = seeded["clients"][("bob", "trojan-tls")]
    resp = test_client.post_raw(
        f"/users/{bob.id}/add-inbound",
        data={"inbound_id": str(hy2.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]
    resp = test_client.post_raw(
        f"/users/{bob.id}/detach/{trojan_client.id}",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


# ---------------------------------------------------------------------------
# Edit-page nits — move hint + hints next to fields
# ---------------------------------------------------------------------------

def test_move_dropdown_explains_no_targets(authed_client, seeded, db):
    # Carol's only client is VLESS and there is no other enabled
    # VLESS inbound — the cell explains why instead of a bare "—".
    t = t_for("fa")
    carol = seeded["users"]["carol"]
    resp = authed_client.get(f"/users/{carol.id}/edit")
    assert resp.status_code == 200
    assert t["move_no_targets"] in resp.text
    assert 'name="move_' not in resp.text  # no select without targets


def test_move_dropdown_shows_targets_and_hint_when_available(
        authed_client, seeded, db):
    t = t_for("fa")
    carol = seeded["users"]["carol"]
    _add_inbound(
        db, tag="vless-2", core="xray", protocol="vless", port=8443,
        stream={"network": "tcp", "security": "none"},
    )
    resp = authed_client.get(f"/users/{carol.id}/edit")
    assert resp.status_code == 200
    assert t["move_no_targets"] not in resp.text
    assert 'name="move_' in resp.text
    assert "vless-2" in resp.text
    assert t["move_hint"] in resp.text


def test_hints_sit_next_to_their_fields(authed_client, seeded, db):
    # With one client row and a move target available, each hint
    # appears exactly once — inside the table, next to its field,
    # not detached at the bottom of the card.
    t = t_for("fa")
    carol = seeded["users"]["carol"]
    _add_inbound(
        db, tag="vless-2", core="xray", protocol="vless", port=8443,
        stream={"network": "tcp", "security": "none"},
    )
    resp = authed_client.get(f"/users/{carol.id}/edit")
    assert resp.status_code == 200
    table_end = resp.text.index("</table>")
    for key in ("ip_limit_hint", "freeze_hint", "move_hint"):
        hint = t[key]
        assert resp.text.count(hint) == 1, f"{key} count"
        assert resp.text.index(hint) < table_end, f"{key} outside table"
