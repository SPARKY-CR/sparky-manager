"""Per-client management tests (Phase 2, DESIGN.md §5.7).

Covers the user editor (GET/POST /users/{id}/edit), freeze/unfreeze,
per-inbound moves, bulk ops, and the frozen usability rule — against
the real routes, renderers and link builders.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app import main as main_mod
from app.main import (
    _client_flow_options,
    _parse_expiry_date,
    _parse_ip_limit,
    _user_client_rows,
    _user_edit_values,
    t_for,
)
from app.models import (
    Client,
    Inbound,
    TrafficDaily,
    User,
    client_is_frozen,
    client_is_usable,
)
from tests.conftest import HOST


# ---------------------------------------------------------------------------
# i18n: every new key exists in both languages
# ---------------------------------------------------------------------------

NEW_KEYS = [
    "edit_user", "back_to_user", "expiry_date", "expiry_date_hint",
    "flow", "flow_none", "ip_limit", "ip_limit_hint", "frozen",
    "freeze", "unfreeze", "freeze_hint", "move_to", "keep_inbound",
    "move_hint", "per_client_settings", "no_clients", "bulk_actions",
    "bulk_enable", "bulk_disable", "bulk_delete", "bulk_reset_traffic",
    "bulk_extend_expiry", "extend_days", "extend_days_hint",
    "reset_traffic", "no_users_selected", "invalid_action",
    "invalid_extend_days", "invalid_expiry_date", "invalid_ip_limit",
    "invalid_flow", "flow_needs_tls", "flow_needs_vision",
    "move_invalid_target", "move_address_exhausted", "user_updated",
    "user_frozen", "user_unfrozen", "bulk_done", "confirm_bulk_delete",
    "select_all", "traffic_reset_hint",
]


def test_phase2_keys_exist_in_both_languages():
    fa, en = t_for("fa"), t_for("en")
    # Technical terms that are legitimately identical in both languages.
    same_ok = {"flow"}
    for key in NEW_KEYS:
        assert fa.get(key), f"missing fa key: {key}"
        assert en.get(key), f"missing en key: {key}"
        if key not in same_ok:
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


def _add_client(db, user, inbound, **kwargs):
    client = Client(user_id=user.id, inbound_id=inbound.id, **kwargs)
    db.add(client)
    db.commit()
    return client


def _edit_form(user, rows, **overrides):
    """A complete valid edit POST for ``user`` (defaults from the
    current values), with ``overrides`` applied. Empty text values
    are kept (a browser submits empty inputs as ``""``); only an
    unchecked frozen checkbox is dropped."""
    values = _user_edit_values(user, rows)
    data = {
        "name": values["name"],
        "note": values["note"],
        "traffic_limit_gb": values["traffic_limit_gb"],
        "expires_date": values["expires_date"],
    }
    for row in rows:
        cid = row["client"].id
        if row["flow_options"]:
            data[f"flow_{cid}"] = values[f"flow_{cid}"]
        data[f"ip_limit_{cid}"] = values[f"ip_limit_{cid}"]
        if values[f"frozen_{cid}"]:
            data[f"frozen_{cid}"] = "on"
        data[f"move_{cid}"] = values[f"move_{cid}"]
    data.update({key: str(value) for key, value in overrides.items()})
    return data


def _rows(db, user):
    return _user_client_rows(db, user)


def _client_id(seeded, user_name, tag):
    return seeded["clients"][(user_name, tag)].id


def _xray_config(tmp_path):
    return json.loads((tmp_path / "xray.json").read_text())


def _inbound_cfg(cfg, tag):
    for inbound in cfg.get("inbounds", []):
        if inbound.get("tag") == tag:
            return inbound
    return None


NOW = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def _aware(value):
    """A datetime read back from SQLite is naive; treat it as UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Frozen usability rule (models)
# ---------------------------------------------------------------------------

def _usable_triple():
    user = User(name="u", enabled=True, traffic_limit_bytes=None,
                traffic_used_bytes=0, expires_at=None)
    inbound = Inbound(tag="t", core="xray", protocol="vless", port=443,
                      enabled=True)
    client = Client(user_id=1, inbound_id=1, enabled=True)
    return client, user, inbound


def test_frozen_client_is_unusable():
    client, user, inbound = _usable_triple()
    client.extra = {"frozen": True}
    assert client_is_usable(client, user, inbound, now=NOW) is False
    assert client_is_frozen(client) is True


def test_unfrozen_client_is_usable():
    client, user, inbound = _usable_triple()
    assert client_is_usable(client, user, inbound, now=NOW) is True
    client.extra = {"frozen": False}
    assert client_is_usable(client, user, inbound, now=NOW) is True
    client.extra = {"ip_limit": 3}
    assert client_is_usable(client, user, inbound, now=NOW) is True


def test_client_is_frozen_defensive_on_bad_extra():
    client, _, _ = _usable_triple()
    client.extra_json = "not json{"
    assert client_is_frozen(client) is False
    client.extra_json = None
    assert client_is_frozen(client) is False


def test_frozen_client_dropped_from_usable_map(db, seeded):
    from tests.conftest import usable_clients_by_tag

    alice_vless = seeded["clients"][("alice", "vless-reality")]
    assert "vless-reality" in usable_clients_by_tag(db)
    alice_vless.extra = {"frozen": True}
    db.commit()
    by_tag = usable_clients_by_tag(db)
    assert all(
        c["uuid"] != alice_vless.uuid
        for c in by_tag.get("vless-reality", [])
    )


# ---------------------------------------------------------------------------
# Value parsers
# ---------------------------------------------------------------------------

def test_parse_expiry_date():
    assert _parse_expiry_date("") is None
    assert _parse_expiry_date("   ") is None
    parsed = _parse_expiry_date("2026-12-31")
    assert parsed == datetime(2026, 12, 31, 23, 59, 59,
                              tzinfo=timezone.utc)
    # A past date parses fine — it expires the user immediately.
    assert _parse_expiry_date("2020-01-01").year == 2020


@pytest.mark.parametrize("bad", [
    "2026-13-01", "2026-02-30", "31/12/2026", "2026-12-31T00:00",
    "tomorrow", "2026-12",
])
def test_parse_expiry_date_rejects(bad):
    with pytest.raises(ValueError):
        _parse_expiry_date(bad)


def test_parse_ip_limit():
    assert _parse_ip_limit("") is None
    assert _parse_ip_limit("0") is None
    assert _parse_ip_limit("1") == 1
    assert _parse_ip_limit("1000") == 1000


@pytest.mark.parametrize("bad", ["-1", "1001", "abc", "1.5"])
def test_parse_ip_limit_rejects(bad):
    with pytest.raises(ValueError):
        _parse_ip_limit(bad)


def test_client_flow_options_by_security(db, seeded):
    vless_reality = seeded["inbounds"]["vless-reality"]
    assert _client_flow_options(vless_reality) == [
        "xtls-rprx-vision", "xtls-rprx-vision-udp443"]
    tls = _add_inbound(db, tag="vless-tls", core="xray", protocol="vless",
                       port=9443, stream={"network": "tcp", "security": "tls"})
    assert _client_flow_options(tls) == [
        "", "xtls-rprx-vision", "xtls-rprx-vision-udp443"]
    plain = _add_inbound(db, tag="vless-plain", core="xray",
                         protocol="vless", port=9444,
                         stream={"network": "tcp", "security": "none"})
    assert _client_flow_options(plain) == [""]
    # Flow is VLESS-only.
    assert _client_flow_options(seeded["inbounds"]["vmess-ws"]) == []
    assert _client_flow_options(seeded["inbounds"]["trojan-tls"]) == []


# ---------------------------------------------------------------------------
# GET edit page
# ---------------------------------------------------------------------------

def test_edit_page_renders_prefilled(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.get(f"/users/{alice.id}/edit")
    assert resp.status_code == 200
    assert "{{" not in resp.text and "{%" not in resp.text
    assert 'name="name" ' in resp.text and 'value="alice"' in resp.text
    assert 'type="date" name="expires_date"' in resp.text
    vless_id = _client_id(seeded, "alice", "vless-reality")
    assert f'name="flow_{vless_id}"' in resp.text
    assert "xtls-rprx-vision" in resp.text
    wg_id = _client_id(seeded, "alice", "wireguard")
    assert f'name="ip_limit_{wg_id}"' in resp.text
    assert f'name="frozen_{wg_id}"' in resp.text


def test_edit_page_404(authed_client):
    assert authed_client.get("/users/99999/edit").status_code == 404


def test_edit_page_requires_login(test_client, seeded):
    alice = seeded["users"]["alice"]
    resp = test_client.get(f"/users/{alice.id}/edit",
                           follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


def test_edit_page_no_clients_shows_note(authed_client, db):
    user = User(name="lonely", sub_token="lonely-token")
    db.add(user)
    db.commit()
    resp = authed_client.get(f"/users/{user.id}/edit")
    assert resp.status_code == 200
    assert t_for("fa")["no_clients"] in resp.text


# ---------------------------------------------------------------------------
# POST edit — user fields
# ---------------------------------------------------------------------------

def test_post_edit_rename_ok(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), name="alice2"),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(User, alice.id).name == "alice2"


def test_post_edit_duplicate_name_rejected_values_preserved(
        authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), name="bob",
                        note="keep-me"),
    )
    assert resp.status_code == 200  # re-rendered with error
    assert t_for("fa")["name_exists"] in resp.text
    assert 'value="bob"' in resp.text  # submitted name preserved
    assert 'value="keep-me"' in resp.text
    db.expire_all()
    assert db.get(User, alice.id).name == "alice"


def test_post_edit_invalid_name_rejected(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), name="bad name!"),
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_name"] in resp.text


def test_post_edit_expiry_date_set_and_cleared(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        expires_date="2027-01-15"),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert _aware(db.get(User, alice.id).expires_at) == datetime(
        2027, 1, 15, 23, 59, 59, tzinfo=timezone.utc)
    # Clear it again (empty date = never expires).
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(db.get(User, alice.id),
                        _rows(db, db.get(User, alice.id)),
                        expires_date=""),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, alice.id).expires_at is None


def test_post_edit_expiry_date_invalid(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        expires_date="15/01/2027"),
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_expiry_date"] in resp.text
    db.expire_all()
    assert db.get(User, alice.id).expires_at is None


def test_post_edit_traffic_limit(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), traffic_limit_gb="5"),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, alice.id).traffic_limit_bytes == 5 * 1024**3
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(db.get(User, alice.id),
                        _rows(db, db.get(User, alice.id)),
                        traffic_limit_gb="abc"),
    )
    assert resp.status_code == 200
    assert t_for("fa")["traffic_limit_gb"] in resp.text


def test_post_edit_404(authed_client):
    resp = authed_client.post("/users/99999/edit", data={"name": "x"},
                              follow_redirects=False)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST edit — per-client flow / IP limit / freeze
# ---------------------------------------------------------------------------

def test_post_edit_flow_change_rerenders_and_links(
        authed_client, seeded, db, tmp_path):
    alice = seeded["users"]["alice"]
    vless_id = _client_id(seeded, "alice", "vless-reality")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"flow_{vless_id}": "xtls-rprx-vision-udp443"}),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(Client, vless_id).flow == "xtls-rprx-vision-udp443"
    # The rendered config and the share link carry the new flow.
    cfg = _xray_config(tmp_path)
    entry = _inbound_cfg(cfg, "vless-reality")
    assert entry is not None
    flows = {c.get("flow") for c in entry["settings"]["clients"]}
    assert "xtls-rprx-vision-udp443" in flows
    detail = authed_client.get(f"/users/{alice.id}")
    assert "flow=xtls-rprx-vision-udp443" in detail.text


def test_post_edit_flow_none_rejected_for_reality(
        authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    vless_id = _client_id(seeded, "alice", "vless-reality")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), **{f"flow_{vless_id}": ""}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_flow"] in resp.text
    db.expire_all()
    assert db.get(Client, vless_id).flow == "xtls-rprx-vision"


def test_post_edit_flow_none_ok_for_tls_vless(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    tls = _add_inbound(db, tag="vless-tls", core="xray", protocol="vless",
                       port=9443, stream={"network": "tcp", "security": "tls",
                                          "tls": {"sni": HOST}})
    client = _add_client(db, alice, tls, uuid=str(uuid.uuid4()),
                         flow="xtls-rprx-vision")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), **{f"flow_{client.id}": ""}),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(Client, client.id).flow is None


def test_post_edit_flow_cleared_for_plain_vless(authed_client, seeded, db):
    # A stale Vision flow on a security=none inbound is cleared on
    # save (the only offered option is "no flow").
    alice = seeded["users"]["alice"]
    plain = _add_inbound(db, tag="vless-plain", core="xray",
                         protocol="vless", port=9444,
                         stream={"network": "tcp", "security": "none"})
    client = _add_client(db, alice, plain, uuid=str(uuid.uuid4()),
                         flow="xtls-rprx-vision")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice)),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert db.get(Client, client.id).flow is None


def test_post_edit_ip_limit_set_clear_invalid(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    wg_id = _client_id(seeded, "alice", "wireguard")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), **{f"ip_limit_{wg_id}": "3"}),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    client = db.get(Client, wg_id)
    assert client.extra.get("ip_limit") == 3
    # allowed_ips survived the read-modify-write.
    assert client.extra.get("allowed_ips") == "10.8.0.2/32"
    # Clear it (empty = unlimited).
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), **{f"ip_limit_{wg_id}": ""}),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert "ip_limit" not in db.get(Client, wg_id).extra
    # Invalid value: error, DB unchanged.
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"ip_limit_{wg_id}": "1001"}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_ip_limit"] in resp.text


def test_post_edit_freeze_one_client(authed_client, seeded, db, tmp_path):
    alice = seeded["users"]["alice"]
    trojan_id = _client_id(seeded, "alice", "trojan-tls")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"frozen_{trojan_id}": "on"}),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    assert client_is_frozen(db.get(Client, trojan_id)) is True
    # Frozen client drops out of the rendered config and the links.
    cfg = _xray_config(tmp_path)
    trojan = _inbound_cfg(cfg, "trojan-tls")
    passwords = {c.get("password") for c in trojan["settings"]["clients"]}
    assert "alice-trojan-tls-pw-001" not in passwords
    # The share link is gone too (the clients table still lists the
    # inbound — only links/configs omit frozen clients).
    detail = authed_client.get(f"/users/{alice.id}")
    assert "alice-trojan-tls-pw-001" not in detail.text
    # Unfreeze via the same form restores it — unchecking the box
    # means the key is absent from the POST, like a real browser.
    data = _edit_form(alice, _rows(db, alice))
    del data[f"frozen_{trojan_id}"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=data,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert client_is_frozen(db.get(Client, trojan_id)) is False


def test_post_edit_validation_is_all_or_nothing(authed_client, seeded, db):
    # A bad per-client field must not save the good user fields.
    alice = seeded["users"]["alice"]
    wg_id = _client_id(seeded, "alice", "wireguard")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice), name="renamed",
                        **{f"ip_limit_{wg_id}": "nope"}),
    )
    assert resp.status_code == 200
    db.expire_all()
    assert db.get(User, alice.id).name == "alice"


# ---------------------------------------------------------------------------
# Freeze / unfreeze routes
# ---------------------------------------------------------------------------

def test_freeze_user_drops_all_clients(authed_client, seeded, db, tmp_path):
    alice = seeded["users"]["alice"]
    alice_uuid = seeded["clients"][("alice", "vless-reality")].uuid
    resp = authed_client.post(f"/users/{alice.id}/freeze",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    clients = db.query(Client).filter(Client.user_id == alice.id).all()
    assert clients and all(client_is_frozen(c) for c in clients)
    # No usable clients left: the vless inbound renders without her,
    # and her detail page shows no share links.
    cfg = _xray_config(tmp_path)
    vless = _inbound_cfg(cfg, "vless-reality")
    assert vless is None or all(
        c.get("id") != alice_uuid for c in vless["settings"]["clients"])
    detail = authed_client.get(f"/users/{alice.id}")
    assert t_for("fa")["frozen"] in detail.text
    assert t_for("fa")["unfreeze"] in detail.text


def test_unfreeze_user_restores(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    authed_client.post(f"/users/{alice.id}/freeze")
    resp = authed_client.post(f"/users/{alice.id}/unfreeze",
                              follow_redirects=False)
    assert resp.status_code == 303
    db.expire_all()
    clients = db.query(Client).filter(Client.user_id == alice.id).all()
    assert all(not client_is_frozen(c) for c in clients)
    detail = authed_client.get(f"/users/{alice.id}")
    assert t_for("fa")["freeze"] in detail.text


def test_freeze_unfreeze_404(authed_client):
    assert authed_client.post("/users/99999/freeze").status_code == 404
    assert authed_client.post("/users/99999/unfreeze").status_code == 404


def test_freeze_keeps_traffic_history(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    alice.traffic_used_bytes = 12345
    db.add(TrafficDaily(user_id=alice.id, date=datetime.now(timezone.utc).date(),
                        up_bytes=100, down_bytes=200))
    db.commit()
    authed_client.post(f"/users/{alice.id}/freeze")
    authed_client.post(f"/users/{alice.id}/unfreeze")
    db.expire_all()
    assert db.get(User, alice.id).traffic_used_bytes == 12345
    rows = db.query(TrafficDaily).filter(
        TrafficDaily.user_id == alice.id).all()
    assert len(rows) == 1 and rows[0].up_bytes == 100


# ---------------------------------------------------------------------------
# Move client to another inbound
# ---------------------------------------------------------------------------

def test_move_vless_client(authed_client, seeded, db, tmp_path):
    alice = seeded["users"]["alice"]
    alice.traffic_used_bytes = 777
    db.commit()
    target = _add_inbound(
        db, tag="vless-2", core="xray", protocol="vless", port=9443,
        stream={"network": "tcp", "security": "reality",
                "reality": {"sni": "www.microsoft.com",
                            "dest": "www.microsoft.com:443",
                            "public_key": seeded["reality_public"],
                            "private_key": seeded["reality_private"],
                            "short_id": seeded["reality_short_id"]}})
    vless_id = _client_id(seeded, "alice", "vless-reality")
    old_uuid = seeded["clients"][("alice", "vless-reality")].uuid
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{vless_id}": str(target.id)}),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = db.get(Client, vless_id)
    assert client.inbound_id == target.id
    assert client.uuid == old_uuid  # credentials kept
    assert db.get(User, alice.id).traffic_used_bytes == 777
    # Rendered config: the client moved with its uuid.
    cfg = _xray_config(tmp_path)
    new = _inbound_cfg(cfg, "vless-2")
    assert new is not None
    assert old_uuid in {c.get("id") for c in new["settings"]["clients"]}
    old = _inbound_cfg(cfg, "vless-reality")
    assert old is None or old_uuid not in {
        c.get("id") for c in old["settings"]["clients"]}
    # Links regenerated against the new inbound (her uuid, port 9443).
    detail = authed_client.get(f"/users/{alice.id}")
    assert "vless-2" in detail.text
    assert f"{old_uuid}@{HOST}:9443" in detail.text


def test_move_rejected_for_wrong_protocol(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    vless_id = _client_id(seeded, "alice", "vless-reality")
    trojan = seeded["inbounds"]["trojan-tls"]
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{vless_id}": str(trojan.id)}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["move_invalid_target"] in resp.text
    db.expire_all()
    assert db.get(Client, vless_id).inbound_id == (
        seeded["inbounds"]["vless-reality"].id)


def test_move_rejected_when_user_has_client_there(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    target = _add_inbound(db, tag="vless-2", core="xray", protocol="vless",
                          port=8443, stream={"network": "tcp",
                                             "security": "reality"})
    _add_client(db, alice, target, uuid=str(uuid.uuid4()),
                flow="xtls-rprx-vision")
    vless_id = _client_id(seeded, "alice", "vless-reality")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{vless_id}": str(target.id)}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["move_invalid_target"] in resp.text


def test_move_rejected_for_disabled_target(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    target = _add_inbound(db, tag="vless-off", core="xray", protocol="vless",
                          port=8443, stream={"network": "tcp",
                                             "security": "reality"},
                          enabled=False)
    vless_id = _client_id(seeded, "alice", "vless-reality")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{vless_id}": str(target.id)}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["move_invalid_target"] in resp.text


def test_move_two_clients_to_same_target_rejected(
        authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    second = _add_inbound(db, tag="vless-2", core="xray", protocol="vless",
                          port=8443, stream={"network": "tcp",
                                             "security": "reality"})
    _add_client(db, alice, second, uuid=str(uuid.uuid4()),
                flow="xtls-rprx-vision")
    target = _add_inbound(db, tag="vless-3", core="xray", protocol="vless",
                          port=8444, stream={"network": "tcp",
                                             "security": "reality"})
    first_id = _client_id(seeded, "alice", "vless-reality")
    second_id = db.query(Client).filter(
        Client.user_id == alice.id,
        Client.inbound_id == second.id).first().id
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{first_id}": str(target.id),
                           f"move_{second_id}": str(target.id)}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["move_invalid_target"] in resp.text
    db.expire_all()
    assert db.get(Client, first_id).inbound_id == (
        seeded["inbounds"]["vless-reality"].id)
    assert db.get(Client, second_id).inbound_id == second.id


def test_move_wireguard_allocates_from_target_subnet(
        authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    target = _add_inbound(
        db, tag="wireguard-2", core="wireguard", protocol="wireguard",
        port=51821, stream={"transport": "udp", "subnet": "10.9.0.0/24",
                            "peer_public_key": seeded["wg_server_public"]})
    wg_id = _client_id(seeded, "alice", "wireguard")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{wg_id}": str(target.id)}),
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text[:400]
    db.expire_all()
    client = db.get(Client, wg_id)
    assert client.inbound_id == target.id
    assert client.extra.get("allowed_ips") == "10.9.0.2/32"
    # The old address is freed: the next allocation on the old
    # inbound starts at .2 again.
    assert main_mod._next_wg_address(db, "10.8.0.0/24",
                                     inbound_id=seeded["inbounds"][
                                         "wireguard"].id) == "10.8.0.2/32"


def test_move_wireguard_pool_exhausted(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    # A /30 has only one usable peer address (.2); take it first.
    target = _add_inbound(
        db, tag="wireguard-2", core="wireguard", protocol="wireguard",
        port=51821, stream={"transport": "udp", "subnet": "10.9.0.0/30",
                            "peer_public_key": seeded["wg_server_public"]})
    _add_client(db, seeded["users"]["bob"], target,
                uuid="bob-wg-pub", password="bob-wg-priv",
                extra_json=json.dumps({"allowed_ips": "10.9.0.2/32"}))
    wg_id = _client_id(seeded, "alice", "wireguard")
    resp = authed_client.post(
        f"/users/{alice.id}/edit",
        data=_edit_form(alice, _rows(db, alice),
                        **{f"move_{wg_id}": str(target.id)}),
    )
    assert resp.status_code == 200
    assert t_for("fa")["move_address_exhausted"] in resp.text
    db.expire_all()
    client = db.get(Client, wg_id)
    assert client.inbound_id == seeded["inbounds"]["wireguard"].id
    assert client.extra.get("allowed_ips") == "10.8.0.2/32"


# ---------------------------------------------------------------------------
# Bulk ops
# ---------------------------------------------------------------------------

def test_bulk_disable_then_enable(authed_client, seeded, db):
    bob = seeded["users"]["bob"]
    carol = seeded["users"]["carol"]
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id), str(carol.id)],
              "action": "disable"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, bob.id).enabled is False
    assert db.get(User, carol.id).enabled is False
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id)], "action": "enable"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, bob.id).enabled is True
    assert db.get(User, carol.id).enabled is False


def test_bulk_delete(authed_client, seeded, db):
    # Capture ids first: after the delete, touching the expired ORM
    # objects raises ObjectDeletedError.
    bob_id = seeded["users"]["bob"].id
    carol_id = seeded["users"]["carol"].id
    alice_id = seeded["users"]["alice"].id
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob_id), str(carol_id)], "action": "delete"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, bob_id) is None
    assert db.get(User, carol_id) is None
    assert db.query(Client).filter(Client.user_id == bob_id).count() == 0
    assert db.get(User, alice_id) is not None


def test_bulk_reset_traffic_keeps_history(authed_client, seeded, db):
    carol = seeded["users"]["carol"]
    db.add(TrafficDaily(user_id=carol.id,
                        date=datetime.now(timezone.utc).date(),
                        up_bytes=500, down_bytes=500))
    db.commit()
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(carol.id)], "action": "reset-traffic"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(User, carol.id).traffic_used_bytes == 0
    rows = db.query(TrafficDaily).filter(
        TrafficDaily.user_id == carol.id).all()
    assert len(rows) == 1 and rows[0].up_bytes == 500


def test_bulk_extend_expiry(authed_client, seeded, db):
    bob = seeded["users"]["bob"]      # expired yesterday
    alice = seeded["users"]["alice"]  # never expires
    carol = seeded["users"]["carol"]
    future = datetime.now(timezone.utc) + timedelta(days=10)
    carol.expires_at = future
    db.commit()
    before = datetime.now(timezone.utc)
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id), str(alice.id), str(carol.id)],
              "action": "extend-expiry", "extend_days": "30"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    # Expired user: extended from now, not from the stale expiry.
    bob_exp = _aware(db.get(User, bob.id).expires_at)
    assert before + timedelta(days=29) < bob_exp < (
        before + timedelta(days=31))
    # Never-expiring user: now + 30 days.
    alice_exp = _aware(db.get(User, alice.id).expires_at)
    assert before + timedelta(days=29) < alice_exp < (
        before + timedelta(days=31))
    # Future expiry: +30 days on top of the current one.
    assert _aware(db.get(User, carol.id).expires_at) == (
        future + timedelta(days=30))


def test_bulk_no_selection(authed_client):
    resp = authed_client.post("/users/bulk", data={"action": "disable"})
    assert resp.status_code == 200  # redirected back to /users with error
    assert t_for("fa")["no_users_selected"] in resp.text


def test_bulk_unknown_ids_only(authed_client):
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": ["99998", "99999"], "action": "disable"},
    )
    assert resp.status_code == 200
    assert t_for("fa")["no_users_selected"] in resp.text


def test_bulk_invalid_action(authed_client, seeded):
    bob = seeded["users"]["bob"]
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id)], "action": "explode"},
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_action"] in resp.text


@pytest.mark.parametrize("days", ["0", "3651", "-5", "abc", ""])
def test_bulk_extend_invalid_days(authed_client, seeded, days):
    bob = seeded["users"]["bob"]
    resp = authed_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id)], "action": "extend-expiry",
              "extend_days": days},
    )
    assert resp.status_code == 200
    assert t_for("fa")["invalid_extend_days"] in resp.text


def test_bulk_requires_login(test_client, seeded):
    bob = seeded["users"]["bob"]
    resp = test_client.post(
        "/users/bulk",
        data={"user_ids": [str(bob.id)], "action": "disable"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]


# ---------------------------------------------------------------------------
# Pages show the new fields
# ---------------------------------------------------------------------------

def test_users_page_has_bulk_form(authed_client, seeded):
    resp = authed_client.get("/users")
    assert resp.status_code == 200
    assert 'id="bulk-form"' in resp.text
    assert 'id="select-all-users"' in resp.text
    bob = seeded["users"]["bob"]
    assert f'name="user_ids" value="{bob.id}"' in resp.text
    for value in ("enable", "disable", "delete", "reset-traffic",
                  "extend-expiry"):
        assert f'value="{value}"' in resp.text


def test_detail_page_shows_new_fields(authed_client, seeded, db):
    alice = seeded["users"]["alice"]
    wg_id = _client_id(seeded, "alice", "wireguard")
    db.get(Client, wg_id).extra = {"allowed_ips": "10.8.0.2/32",
                                   "ip_limit": 2}
    db.commit()
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert f"/users/{alice.id}/edit" in resp.text  # Edit button
    assert "xtls-rprx-vision" in resp.text          # flow column
    # Phase 4: the cell carries a data-label for the card-table
    # layout, so match the cell content, not the bare tag.
    assert ">2</td>" in resp.text                   # IP limit cell
    assert t_for("fa")["unlimited"] in resp.text   # other clients: no limit
    assert f"/users/{alice.id}/freeze" in resp.text
