"""Cores management page tests (start / stop / restart / journal).

Covers: the page renders all seven cores with live states and
state-appropriate actions; the enabled-inbound count + on-demand
hint; the on-demand journal tail; start/stop/restart with the
actual state re-checked afterwards (success, failure, mismatch,
unverified); 404s for unknown cores/actions; CSRF + auth guards;
and the shared ``_control_service`` helper (``_restart_service``
delegates to it, keeping its old error format).
"""

from __future__ import annotations

import pytest

from app import main as main_mod
from app.models import AuditLog

STATES = {
    "xray": "running",
    "sing-box": "running",
    "wireguard": "stopped",
    "amneziawg": "unknown",
    "openvpn": "stopped",
    "openconnect": "running",
    "ikev2": "unknown",
}


@pytest.fixture()
def core_states(monkeypatch):
    """Deterministic service states (the real collector needs systemd)."""
    states = dict(STATES)
    monkeypatch.setattr(
        main_mod.system_status_mod, "service_states", lambda: dict(states)
    )
    return states


@pytest.fixture()
def control_stub(monkeypatch, core_states):
    """Stub ``_control_service``: records calls, flips the state like
    systemctl would (unless told to fail for a unit)."""
    calls: list = []
    failures: dict = {}

    def _control(name, action):
        calls.append((name, action))
        if name in failures:
            return failures[name]
        units = main_mod._core_units()
        key = next(k for k, u in units.items() if u == name)
        core_states[key] = "stopped" if action == "stop" else "running"
        return None

    monkeypatch.setattr(main_mod, "_control_service", _control)
    return {"calls": calls, "failures": failures}


def test_cores_page_renders_all_seven_cores(authed_client, core_states):
    resp = authed_client.get("/cores")
    assert resp.status_code == 200
    for name, unit in (
        ("Xray", "xray"),
        ("sing-box", "sing-box"),
        ("WireGuard", "wg-quick@wg0"),
        ("AmneziaWG", "awg-quick@awg0"),
        ("OpenVPN", "openvpn-server@sparky-manager"),
        ("OpenConnect", "ocserv"),
        ("IKEv2", "strongswan"),
    ):
        assert name in resp.text
        assert unit in resp.text


def test_cores_page_linked_from_nav_and_dashboard(
    authed_client, core_states
):
    assert "/cores" in authed_client.get("/dashboard").text
    assert "/cores" in authed_client.get("/settings?section=services").text


def test_cores_page_actions_match_state(authed_client, core_states):
    resp = authed_client.get("/cores")
    text = resp.text
    # xray is running: no Start, Stop + Restart present.
    assert "/cores/xray/start" not in text
    assert "/cores/xray/stop" in text
    assert "/cores/xray/restart" in text
    # wireguard is stopped: Start only (restart would just be start).
    assert "/cores/wireguard/start" in text
    assert "/cores/wireguard/stop" not in text
    assert "/cores/wireguard/restart" not in text
    # amneziawg is unknown: all three (the result is re-checked).
    assert "/cores/amneziawg/start" in text
    assert "/cores/amneziawg/stop" in text
    assert "/cores/amneziawg/restart" in text


def test_cores_page_inbound_counts_and_hint(
    authed_client, core_states, seeded
):
    resp = authed_client.get("/cores")
    # Seed: 5 enabled xray inbounds, 4 sing-box, 1 wireguard, none
    # for the other cores (the disabled vmess one does not count).
    assert "اینباندهای فعال: 5" in resp.text
    assert "اینباندهای فعال: 4" in resp.text
    assert "اینباندهای فعال: 1" in resp.text
    assert "هیچ اینباند فعالی از این هسته استفاده نمی‌کند" in resp.text


def test_cores_page_log_view(authed_client, core_states, monkeypatch):
    monkeypatch.setattr(
        main_mod, "_journal_tail",
        lambda unit, lines=50: f"fake journal for {unit}\nline two",
    )
    resp = authed_client.get("/cores?log=openvpn")
    assert resp.status_code == 200
    assert "fake journal for openvpn-server@sparky-manager" in resp.text
    assert "line two" in resp.text
    assert "پنهان کردن لاگ" in resp.text


def test_cores_page_log_unknown_key_ignored(
    authed_client, core_states, monkeypatch
):
    seen = []
    monkeypatch.setattr(
        main_mod, "_journal_tail",
        lambda unit, lines=50: seen.append(unit) or "x",
    )
    resp = authed_client.get("/cores?log=bogus")
    assert resp.status_code == 200
    assert seen == []  # no journal call for an unknown key
    assert "log-output" not in resp.text


def test_cores_page_log_unavailable(authed_client, core_states, monkeypatch):
    monkeypatch.setattr(main_mod, "_journal_tail", lambda unit, lines=50: "")
    resp = authed_client.get("/cores?log=xray")
    assert "لاگ در دسترس نیست" in resp.text


def test_core_start_success(authed_client, core_states, control_stub, db):
    resp = authed_client.post("/cores/wireguard/start", follow_redirects=False)
    assert resp.status_code == 303
    assert "/cores?msg=" in resp.headers["location"]
    assert control_stub["calls"] == [("wg-quick@wg0", "start")]
    assert (
        db.query(AuditLog).filter(AuditLog.action == "service.start").count()
        == 1
    )
    followed = authed_client.get(resp.headers["location"])
    assert "شروع شد و در حال اجراست" in followed.text


def test_core_stop_success(authed_client, core_states, control_stub, db):
    resp = authed_client.post("/cores/xray/stop", follow_redirects=False)
    assert resp.status_code == 303
    assert control_stub["calls"] == [("xray", "stop")]
    followed = authed_client.get(resp.headers["location"])
    assert "متوقف شد" in followed.text


def test_core_restart_success(authed_client, core_states, control_stub, db):
    resp = authed_client.post("/cores/sing-box/restart", follow_redirects=False)
    assert resp.status_code == 303
    assert control_stub["calls"] == [("sing-box", "restart")]
    followed = authed_client.get(resp.headers["location"])
    assert "ریستارت شد و در حال اجراست" in followed.text


def test_core_action_failure_redirects_to_log(
    authed_client, core_states, control_stub, db, monkeypatch
):
    control_stub["failures"]["openvpn-server@sparky-manager"] = (
        "restart of openvpn-server@sparky-manager failed: exit 1"
    )
    monkeypatch.setattr(
        main_mod, "_journal_tail", lambda unit, lines=50: "journal tail here"
    )
    resp = authed_client.post("/cores/openvpn/restart", follow_redirects=False)
    assert resp.status_code == 303
    assert "/cores?log=openvpn" in resp.headers["location"]
    followed = authed_client.get(resp.headers["location"])
    assert "ناموفق بود" in followed.text
    assert "journal tail here" in followed.text
    entry = (
        db.query(AuditLog)
        .filter(AuditLog.action == "service.restart")
        .first()
    )
    assert entry is not None and "failed" in (entry.detail or "")


def test_core_action_mismatch_reported(
    authed_client, core_states, monkeypatch
):
    # The command succeeds but the service stays stopped — the page
    # must not claim success.
    monkeypatch.setattr(main_mod, "_control_service", lambda name, action: None)
    resp = authed_client.post("/cores/wireguard/start", follow_redirects=False)
    assert resp.status_code == 303
    followed = authed_client.get(resp.headers["location"])
    assert "در وضعیت مورد انتظار نیست" in followed.text


def test_core_action_unverified(authed_client, core_states, monkeypatch):
    # amneziawg is unknown and stays unknown after the action.
    monkeypatch.setattr(main_mod, "_control_service", lambda name, action: None)
    resp = authed_client.post(
        "/cores/amneziawg/restart", follow_redirects=False
    )
    assert resp.status_code == 303
    followed = authed_client.get(resp.headers["location"])
    assert "قابل بررسی نیست" in followed.text


def test_core_action_unknown_key_or_action_404(authed_client, core_states):
    assert authed_client.post("/cores/bogus/start").status_code == 404
    assert authed_client.post("/cores/xray/bogus").status_code == 404


def test_core_action_requires_csrf(authed_client, core_states):
    resp = authed_client.post_raw(
        "/cores/xray/restart", data={}, follow_redirects=False
    )
    assert resp.status_code == 403


def test_cores_page_requires_auth(test_client, core_states):
    resp = test_client.get("/cores", follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers["location"]
    resp = test_client.post("/cores/xray/restart", follow_redirects=False)
    assert resp.status_code == 303


def test_control_service_success_and_failure(monkeypatch):
    monkeypatch.setattr(
        main_mod, "_run_privileged", lambda *a, **kw: (0, "", "")
    )
    assert main_mod._control_service("xray", "start") is None
    monkeypatch.setattr(
        main_mod, "_run_privileged", lambda *a, **kw: (1, "", "boom")
    )
    monkeypatch.setattr(
        main_mod, "_journal_tail", lambda unit, lines=50: "j-line"
    )
    assert main_mod._control_service("xray", "stop") == (
        "stop of xray failed: boom\njournal (xray):\nj-line"
    )


def test_restart_service_delegates_to_control_service(monkeypatch):
    monkeypatch.setattr(
        main_mod, "_run_privileged", lambda *a, **kw: (1, "out", "")
    )
    monkeypatch.setattr(main_mod, "_journal_tail", lambda unit, lines=50: "")
    # Same error string as before the refactor (re-render callers
    # and bot messages depend on the format).
    assert main_mod._restart_service("ocserv") == "restart of ocserv failed: out"
    assert main_mod._control_service("ocserv", "restart") == (
        "restart of ocserv failed: out"
    )
