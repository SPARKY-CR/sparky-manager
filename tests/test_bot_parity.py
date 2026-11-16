"""Bot client parity + native configs batch.

1. Bot client parity: per-client management in the bot — the clients
   list, add-to-inbound, detach, per-client move, per-client freeze,
   XTLS flow edit — with the web's validation and semantics.
2. Native config downloads: the bot Links view sends OpenVPN /
   OpenConnect / AmneziaWG / IKEv2 configs as files (they have no
   share link). The web download buttons (user detail + public /u/
   page) already exist — the tests below pin them.
3. Credentials: the OpenVPN .ovpn embeds the username/password in
   an inline <auth-user-pass> block (file endpoint + ZedSecure
   bundle); the OpenVPN/OpenConnect credentials are shown on the
   user detail page (per-client, admin only) and in the bot
   (per-client view + Links view). OpenConnect's .xml cannot carry
   a password (AnyConnect format) — the limitation is documented
   and hinted near the download button, not worked around.
"""

from __future__ import annotations

import json
import secrets

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app import openvpn as openvpn_mod
from app.models import AuditLog, Client, Inbound, User
from tests.conftest import HOST
from tests.test_protocols import ca, proto  # noqa: F401 — fixtures
from tests.test_telegram_bot import (
    OTHER_CHAT,
    FakeSender,
    _audit_actions,
    _button_data,
    _callback,
    _configure_bot,
    _dispatch,
)


@pytest.fixture()
def sender():
    return FakeSender()


@pytest.fixture()
def rerender_stub(monkeypatch):
    """Record rerender_configs calls (the bot must call it after every
    state change, like the web routes do)."""
    calls: list = []

    def _stub(db):
        calls.append(True)
        return []

    monkeypatch.setattr(main_mod, "rerender_configs", _stub)
    return calls


def _all_texts(sender):
    """Every message text the fake sender saw (sent + edited)."""
    texts = [text for _chat, text, _kb in sender.sent]
    texts += [text for _chat, _mid, text, _kb in sender.edited]
    return "\n".join(texts)


def _make_user(db, name):
    user = User(
        name=name,
        enabled=True,
        traffic_limit_bytes=None,
        traffic_used_bytes=0,
        expires_at=None,
        sub_token=secrets.token_urlsafe(24),
    )
    db.add(user)
    db.commit()
    return user


def _make_inbound(db, tag, protocol, port, stream=None, core="xray"):
    inbound = Inbound(
        tag=tag,
        core=core,
        protocol=protocol,
        port=port,
        enabled=True,
        stream_json=json.dumps(stream or {"network": "tcp", "security": "none"}),
    )
    db.add(inbound)
    db.commit()
    return inbound


# ---------------------------------------------------------------------------
# Per-client views
# ---------------------------------------------------------------------------


def test_user_view_has_clients_button(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:v:{alice.id}"), sender)
    assert f"u:cl:{alice.id}" in _button_data(sender.edited[0][3])


def test_clients_list(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:cl:{alice.id}"), sender)
    text = sender.edited[0][2]
    assert "alice" in text
    data = _button_data(sender.edited[0][3])
    vless = seeded["clients"][("alice", "vless-reality")]
    trojan = seeded["clients"][("alice", "trojan-tls")]
    assert f"u:cv:{vless.id}" in data
    assert f"u:cv:{trojan.id}" in data
    assert f"u:add:{alice.id}" in data
    assert f"u:v:{alice.id}" in data


def test_clients_list_marks_frozen(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    vless.extra = {"frozen": True}
    db.commit()
    _dispatch(db, _callback(f"u:cl:{alice.id}"), sender)
    buttons = sender.edited[0][3]["inline_keyboard"]
    labels = [b["text"] for row in buttons for b in row]
    assert any("🧊" in label and "vless-reality" in label for label in labels)


def test_clients_list_empty_user(db, sender, seeded):
    _configure_bot(db)
    zoe = _make_user(db, "zoe")
    _dispatch(db, _callback(f"u:cl:{zoe.id}"), sender)
    assert "هیچ کلاینتی ندارد" in sender.edited[0][2]
    assert f"u:add:{zoe.id}" in _button_data(sender.edited[0][3])


def test_client_view_vless(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    _dispatch(db, _callback(f"u:cv:{vless.id}"), sender)
    text = sender.edited[0][2]
    assert "vless-reality" in text
    assert "vless" in text
    assert "443" in text
    assert "Flow" in text
    data = _button_data(sender.edited[0][3])
    assert f"u:cfrz:{vless.id}" in data
    assert f"u:det:{vless.id}" in data
    assert f"u:cfl:{vless.id}" in data
    # Only one VLESS inbound exists — no move button is offered.
    assert f"u:mv:{vless.id}" not in data
    assert f"u:cl:{alice.id}" in data


def test_client_view_openvpn_shows_credentials(db, sender, seeded, proto, ca):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    # The `seeded` dict was built before `proto` added the native
    # inbounds — read the client fresh from the DB.
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    assert ovpn is not None
    _dispatch(db, _callback(f"u:cv:{ovpn.id}"), sender)
    text = sender.edited[0][2]
    assert "openvpn" in text
    assert "Flow" not in text
    assert "<code>alice</code>" in text
    assert f"<code>{ovpn.password}</code>" in text


def test_client_not_found(db, sender):
    _configure_bot(db)
    _dispatch(db, _callback("u:cv:99999"), sender)
    assert "پیدا نشد" in sender.edited[0][2]


def test_stranger_client_callbacks_ignored(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:cl:{alice.id}", chat_id=OTHER_CHAT), sender)
    assert not sender.sent and not sender.edited and not sender.answered


# ---------------------------------------------------------------------------
# Add to inbound
# ---------------------------------------------------------------------------


def test_add_inbound_flow(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    zoe = _make_user(db, "zoe")
    _dispatch(db, _callback(f"u:add:{zoe.id}"), sender)
    data = _button_data(sender.edited[0][3])
    vless = seeded["inbounds"]["vless-reality"]
    assert f"u:add:{zoe.id}:{vless.id}" in data
    _dispatch(db, _callback(f"u:add:{zoe.id}:{vless.id}"), sender)
    client = (
        db.query(Client)
        .filter(Client.user_id == zoe.id, Client.inbound_id == vless.id)
        .first()
    )
    assert client is not None
    assert client.uuid  # fresh credentials, like the web flow
    assert len(_audit_actions(db, "user.add_inbound")) == 1
    assert rerender_stub  # configs re-rendered after the add
    assert "vless-reality" in _all_texts(sender)


def test_add_inbound_duplicate_is_idempotent(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    before = db.query(Client).filter(Client.user_id == alice.id).count()
    _dispatch(db, _callback(f"u:add:{alice.id}:{vless.id}"), sender)
    after = db.query(Client).filter(Client.user_id == alice.id).count()
    assert after == before
    assert not _audit_actions(db, "user.add_inbound")
    assert not rerender_stub


def test_add_inbound_none_when_on_all(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    _dispatch(db, _callback(f"u:add:{alice.id}"), sender)
    assert "اینباندی برای اضافه کردن نیست" in sender.edited[0][2]


def test_add_inbound_disabled_target_is_stale(db, sender, seeded):
    _configure_bot(db)
    zoe = _make_user(db, "zoe")
    disabled = seeded["inbounds"]["vmess-disabled"]
    _dispatch(db, _callback(f"u:add:{zoe.id}:{disabled.id}"), sender)
    assert (
        db.query(Client)
        .filter(Client.user_id == zoe.id, Client.inbound_id == disabled.id)
        .first()
        is None
    )


# ---------------------------------------------------------------------------
# Detach
# ---------------------------------------------------------------------------


def test_detach_flow(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    trojan = seeded["clients"][("alice", "trojan-tls")]
    _dispatch(db, _callback(f"u:det:{trojan.id}"), sender)
    assert "trojan-tls" in sender.edited[0][2]
    assert "آخرین اینباند" not in sender.edited[0][2]
    assert f"u:det:{trojan.id}:ok" in _button_data(sender.edited[0][3])
    _dispatch(db, _callback(f"u:det:{trojan.id}:ok"), sender)
    assert db.get(Client, trojan.id) is None
    # Only that client is gone.
    assert db.query(Client).filter(Client.user_id == alice.id).count() > 0
    assert len(_audit_actions(db, "user.detach_inbound")) == 1
    assert rerender_stub


def test_detach_last_client_warns_and_works(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    zoe = _make_user(db, "zoe")
    vless = seeded["inbounds"]["vless-reality"]
    main_mod._create_clients_for_user(db, zoe, inbound_ids={vless.id})
    client = (
        db.query(Client)
        .filter(Client.user_id == zoe.id)
        .first()
    )
    _dispatch(db, _callback(f"u:det:{client.id}"), sender)
    assert "آخرین اینباند" in sender.edited[0][2]
    _dispatch(db, _callback(f"u:det:{client.id}:ok"), sender)
    assert db.get(Client, client.id) is None
    assert db.query(Client).filter(Client.user_id == zoe.id).count() == 0
    assert "هیچ کلاینتی ندارد" in _all_texts(sender)


def test_detach_cancel_keeps_client(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    trojan = seeded["clients"][("alice", "trojan-tls")]
    _dispatch(db, _callback(f"u:det:{trojan.id}"), sender)
    _dispatch(db, _callback(f"u:cv:{trojan.id}"), sender)
    assert db.get(Client, trojan.id) is not None


# ---------------------------------------------------------------------------
# Move
# ---------------------------------------------------------------------------


def test_move_flow(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    target = _make_inbound(db, "vless-2", "vless", 9443)
    _dispatch(db, _callback(f"u:mv:{vless.id}"), sender)
    assert f"u:mv:{vless.id}:{target.id}" in _button_data(sender.edited[0][3])
    uuid_before = vless.uuid
    _dispatch(db, _callback(f"u:mv:{vless.id}:{target.id}"), sender)
    moved = db.get(Client, vless.id)
    assert moved.inbound_id == target.id
    assert moved.uuid == uuid_before  # credentials stay
    assert len(_audit_actions(db, "user.update")) == 1
    assert rerender_stub
    assert "vless-2" in _all_texts(sender)


def test_move_none_when_no_target(db, sender, seeded):
    _configure_bot(db)
    trojan = seeded["clients"][("alice", "trojan-tls")]
    _dispatch(db, _callback(f"u:mv:{trojan.id}"), sender)
    assert "هم‌پروتکلی" in _all_texts(sender)


def test_move_invalid_target_is_stale(db, sender, seeded):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    trojan_inbound = seeded["inbounds"]["trojan-tls"]
    _dispatch(db, _callback(f"u:mv:{vless.id}:{trojan_inbound.id}"), sender)
    assert db.get(Client, vless.id).inbound_id == vless.inbound_id


# ---------------------------------------------------------------------------
# Per-client freeze + flow
# ---------------------------------------------------------------------------


def test_per_client_freeze(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    vless = seeded["clients"][("alice", "vless-reality")]
    trojan = seeded["clients"][("alice", "trojan-tls")]
    _dispatch(db, _callback(f"u:cfrz:{vless.id}"), sender)
    assert db.get(Client, vless.id).extra.get("frozen") is True
    assert db.get(Client, trojan.id).extra.get("frozen") is not True
    assert len(_audit_actions(db, "user.freeze")) == 1
    assert rerender_stub
    _dispatch(db, _callback(f"u:cunfrz:{vless.id}"), sender)
    assert db.get(Client, vless.id).extra.get("frozen") is not True
    assert len(_audit_actions(db, "user.unfreeze")) == 1


def test_flow_picker_reality_offers_vision_only(db, sender, seeded):
    _configure_bot(db)
    vless = seeded["clients"][("alice", "vless-reality")]
    _dispatch(db, _callback(f"u:cfl:{vless.id}"), sender)
    data = _button_data(sender.edited[0][3])
    assert f"u:cfl:{vless.id}:xtls-rprx-vision" in data
    assert f"u:cfl:{vless.id}:xtls-rprx-vision-udp443" in data
    assert f"u:cfl:{vless.id}:none" not in data


def test_flow_set_and_clear(db, sender, seeded, rerender_stub):
    _configure_bot(db)
    alice = seeded["users"]["alice"]
    tls_inbound = _make_inbound(
        db, "vless-tls", "vless", 9444,
        {"network": "tcp", "security": "tls", "tls": {"sni": HOST}},
    )
    main_mod._create_clients_for_user(db, alice, inbound_ids={tls_inbound.id})
    client = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == tls_inbound.id)
        .first()
    )
    _dispatch(db, _callback(f"u:cfl:{client.id}:xtls-rprx-vision"), sender)
    assert db.get(Client, client.id).flow == "xtls-rprx-vision"
    assert len(_audit_actions(db, "user.update")) == 1
    assert rerender_stub
    _dispatch(db, _callback(f"u:cfl:{client.id}:none"), sender)
    assert db.get(Client, client.id).flow is None
    assert "حذف شد" in _all_texts(sender)


def test_flow_invalid_rejected(db, sender, seeded):
    _configure_bot(db)
    vless = seeded["clients"][("alice", "vless-reality")]
    flow_before = vless.flow
    _dispatch(db, _callback(f"u:cfl:{vless.id}:bogus-flow"), sender)
    assert db.get(Client, vless.id).flow == flow_before
    # A non-VLESS client has no flow options at all.
    trojan = seeded["clients"][("alice", "trojan-tls")]
    _dispatch(db, _callback(f"u:cfl:{trojan.id}"), sender)
    assert "دیگر معتبر نیست" in _all_texts(sender)


# ---------------------------------------------------------------------------
# Links view: native files + credentials
# ---------------------------------------------------------------------------


def test_links_send_native_files(db, sender, seeded, proto, ca):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    alice = seeded["users"]["alice"]
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    by_name = {name: data for _chat, name, data in sender.documents}
    assert "openvpn.ovpn" in by_name
    assert "openconnect.xml" in by_name
    assert "amneziawg.conf" in by_name
    assert "ikev2.mobileconfig" in by_name
    ovpn_text = by_name["openvpn.ovpn"].decode("utf-8")
    assert "<auth-user-pass>" in ovpn_text
    assert "alice" in ovpn_text
    assert ovpn.password in ovpn_text
    assert "AnyConnectProfile" in by_name["openconnect.xml"].decode("utf-8")
    text = _all_texts(sender)
    assert "openvpn.ovpn" in text
    assert "اطلاعات ورود" in text
    assert "<code>alice</code>" in text
    assert f"<code>{ovpn.password}</code>" in text


def test_links_without_ca_skips_ovpn_but_keeps_rest(
    db, sender, seeded, proto, ca, monkeypatch
):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    alice = seeded["users"]["alice"]
    # Simulate "no CA for OpenVPN" — the .ovpn cannot be rendered,
    # so it is skipped instead of breaking the whole Links view.
    # (The CA file itself still exists for IKEv2, which reads the
    # file directly rather than through _ca_cert_pem.)
    monkeypatch.setattr(main_mod, "_ca_cert_pem", lambda: None)
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    names = {name for _chat, name, _data in sender.documents}
    assert "openvpn.ovpn" not in names
    assert "openconnect.xml" in names
    assert "ikev2.mobileconfig" in names


def test_links_file_send_failure_noted(db, sender, seeded, proto, ca):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    alice = seeded["users"]["alice"]
    sender.document_ok = False
    _dispatch(db, _callback(f"u:links:{alice.id}"), sender)
    assert "ناموفق بود" in _all_texts(sender)
    assert "openvpn.ovpn" in _all_texts(sender)


def test_links_only_native_client_still_shows(db, sender, seeded, proto, ca):
    _configure_bot(db)
    main_mod.set_setting(db, "subscription_host", HOST)
    zoe = _make_user(db, "zoe")
    ovpn_inbound = proto["inbounds"]["openvpn"]
    main_mod._create_clients_for_user(db, zoe, inbound_ids={ovpn_inbound.id})
    _dispatch(db, _callback(f"u:links:{zoe.id}"), sender)
    text = _all_texts(sender)
    # No share links exist for this user — but the view still shows
    # (files + credentials), not the "no links" message.
    assert "لینکی نیست" not in text
    assert f"/sub/{zoe.sub_token}" in text
    names = {name for _chat, name, _data in sender.documents}
    assert "openvpn.ovpn" in names


# ---------------------------------------------------------------------------
# Web: credentials on the user detail page + download buttons
# ---------------------------------------------------------------------------


def test_user_detail_shows_credentials(authed_client, db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "نام کاربری / رمز عبور" in resp.text
    assert f"alice / {ovpn.password}" in resp.text
    # The OpenConnect limitation is hinted next to the downloads.
    assert "فرمت AnyConnect جایی برای رمز ندارد" in resp.text


def test_user_detail_no_credentials_for_link_protocols(
    authed_client, db, seeded
):
    alice = seeded["users"]["alice"]
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    # The credentials column exists; link-protocol rows show "—".
    assert "نام کاربری / رمز عبور" in resp.text
    assert '<td data-label="نام کاربری / رمز عبور">' in resp.text


def test_public_page_hides_credentials_but_keeps_downloads(
    test_client, db, seeded, proto, ca
):
    alice = seeded["users"]["alice"]
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    resp = test_client.get(f"/u/{alice.sub_token}")
    assert resp.status_code == 200
    # Admin-only: no credentials table, no OpenConnect hint.
    assert ovpn.password not in resp.text
    assert "فرمت AnyConnect جایی برای رمز ندارد" not in resp.text
    # But the file downloads ARE linked on the public page.
    assert f"/sub/{alice.sub_token}/openvpn.ovpn" in resp.text
    assert f"/sub/{alice.sub_token}/ikev2.mobileconfig" in resp.text


# ---------------------------------------------------------------------------
# OpenVPN credential embedding
# ---------------------------------------------------------------------------


def test_openvpn_client_config_embeds_credentials(ca):
    ca_pem, _server_pem, _key = ca
    text = openvpn_mod.render_client_config(
        host=HOST, port=1194, proto="udp", ca_cert_pem=ca_pem,
        username="alice", password="s3cret-pw",
    )
    assert "auth-user-pass" in text
    assert "<auth-user-pass>\nalice\ns3cret-pw\n</auth-user-pass>" in text


def test_openvpn_client_config_prompt_without_credentials(ca):
    ca_pem, _server_pem, _key = ca
    text = openvpn_mod.render_client_config(
        host=HOST, port=1194, proto="udp", ca_cert_pem=ca_pem
    )
    assert "auth-user-pass" in text
    assert "<auth-user-pass>" not in text


def test_openvpn_client_config_rejects_newline_credentials(ca):
    ca_pem, _server_pem, _key = ca
    text = openvpn_mod.render_client_config(
        host=HOST, port=1194, proto="udp", ca_cert_pem=ca_pem,
        username="alice", password="bad\npassword",
    )
    # A newline would break the block — fall back to the prompt form.
    assert "<auth-user-pass>" not in text
    assert "auth-user-pass" in text


def test_ovpn_file_export_embeds_credentials(test_client, db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    resp = test_client.get(f"/sub/{alice.sub_token}/openvpn.ovpn")
    assert resp.status_code == 200
    assert "<auth-user-pass>" in resp.text
    assert "alice" in resp.text
    assert ovpn.password in resp.text


def test_bundle_ovpn_embeds_credentials(db, seeded, proto, ca):
    alice = seeded["users"]["alice"]
    ovpn_inbound = proto["inbounds"]["openvpn"]
    ovpn = (
        db.query(Client)
        .filter(Client.user_id == alice.id, Client.inbound_id == ovpn_inbound.id)
        .first()
    )
    settings = main_mod.get_settings(db)
    bundle = main_mod._build_zedsecure_bundle(db, alice, HOST, settings)
    by_tag = {entry["tag"]: entry for entry in bundle["configs"]}
    config = by_tag["openvpn"]["openvpn_config"]
    assert "<auth-user-pass>" in config
    assert "alice" in config
    assert ovpn.password in config
