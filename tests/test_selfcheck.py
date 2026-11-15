"""Phase A item 7 tests — the client-eye self-check.

The panel probes its own inbounds (TCP connect) and fetches its
own subscription the way a client would. The honesty rules are
the point: a refused connection is "down" (real evidence), a
timeout or a UDP port is "unknown" (no evidence either way).
"""

from __future__ import annotations

import base64
import json
import socket
from datetime import datetime, timedelta, timezone

from app import selfcheck as selfcheck_mod
from app.webcommon import get_setting

# A dummy subscription value for the pure-function tests (any
# non-empty string proves the fetch path is taken).
_SUB = "test-subscription-value"


def _inbound(**overrides):
    data = {
        "enabled": True,
        "tag": "vless-1",
        "protocol": "vless",
        "port": 443,
        "stream_json": {},
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# TCP probe
# ---------------------------------------------------------------------------

def test_probe_tcp_port_ok_on_listening_socket():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        status, _ = selfcheck_mod.probe_tcp_port("127.0.0.1", port)
        assert status == "ok"
    finally:
        server.close()


def test_probe_tcp_port_down_on_closed_port():
    # Bind a socket, close it, then probe the (now free) port:
    # nothing listens, so the connect is refused — real evidence.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()
    status, reason = selfcheck_mod.probe_tcp_port("127.0.0.1", port)
    assert status == "down"
    assert "refused" in reason


def test_probe_tcp_port_unknown_on_timeout(monkeypatch):
    def _timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(
        socket, "create_connection", _timeout)
    status, reason = selfcheck_mod.probe_tcp_port("127.0.0.1", 443)
    assert status == "unknown"
    assert "timed out" in reason


def test_probe_tcp_port_unknown_on_bad_port():
    status, _ = selfcheck_mod.probe_tcp_port("127.0.0.1", 99999)
    assert status == "unknown"


# ---------------------------------------------------------------------------
# Inbound port checks
# ---------------------------------------------------------------------------

def test_udp_inbound_is_unknown_never_faked():
    results = selfcheck_mod.check_inbound_ports([
        _inbound(tag="hysteria2-1", protocol="hysteria2", port=8443),
        _inbound(tag="wg-1", protocol="wireguard", port=51820),
        _inbound(tag="ikev2-1", protocol="ikev2", port=500),
    ])
    assert len(results) == 3
    for result in results:
        assert result["status"] == "unknown", result
        assert "UDP" in result["reason"], result


def test_disabled_inbound_is_skipped():
    results = selfcheck_mod.check_inbound_ports([
        _inbound(tag="off-1", enabled=False),
        _inbound(tag="on-1", port=1),
    ], probe=lambda host, port: ("ok", ""))
    assert [r["tag"] for r in results] == ["on-1"]


def test_openvpn_honours_stream_transport():
    # OpenVPN over UDP is unprobeable; over TCP it is probed.
    udp = _inbound(
        tag="ovpn-udp", protocol="openvpn", port=1194,
        stream_json={"transport": "udp"},
    )
    tcp = _inbound(
        tag="ovpn-tcp", protocol="openvpn", port=1194,
        stream_json={"transport": "tcp"},
    )
    results = selfcheck_mod.check_inbound_ports(
        [udp, tcp], probe=lambda host, port: ("ok", ""))
    assert results[0]["status"] == "unknown"
    assert results[1]["status"] == "ok"


# ---------------------------------------------------------------------------
# Subscription fetch
# ---------------------------------------------------------------------------

def _good_feed():
    links = "vless://example-uuid@203.0.113.10:443?x=y#tag"
    return 200, base64.b64encode(links.encode())


def test_fetch_own_subscription_ok():
    status, _ = selfcheck_mod.fetch_own_subscription(
        "https://203.0.113.10:8443/panel", "tok",
        fetch=lambda url: _good_feed())
    assert status == "ok"


def test_fetch_own_subscription_403_is_down():
    status, reason = selfcheck_mod.fetch_own_subscription(
        "https://203.0.113.10:8443/panel", "tok",
        fetch=lambda url: (403, b""))
    assert status == "down"
    assert "403" in reason


def test_fetch_own_subscription_empty_feed_is_down():
    status, _ = selfcheck_mod.fetch_own_subscription(
        "https://203.0.113.10:8443/panel", "tok",
        fetch=lambda url: (200, base64.b64encode(b"")))
    assert status == "down"


def test_fetch_own_subscription_unparseable_feed_is_down():
    status, _ = selfcheck_mod.fetch_own_subscription(
        "https://203.0.113.10:8443/panel", "tok",
        fetch=lambda url: (200, b"not base64 at all {{{"))
    assert status == "down"


def test_fetch_own_subscription_transport_failure_is_unknown():
    def _boom(url):
        raise ConnectionError("unreachable")

    status, _ = selfcheck_mod.fetch_own_subscription(
        "https://203.0.113.10:8443/panel", "tok", fetch=_boom)
    assert status == "unknown"


# ---------------------------------------------------------------------------
# Full run + overall logic
# ---------------------------------------------------------------------------

def test_run_self_check_all_ok():
    result = selfcheck_mod.run_self_check(
        [_inbound(tag="vless-1", port=443)],
        base_url="https://203.0.113.10:8443/panel", sub_token=_SUB,
        probe=lambda host, port: ("ok", ""),
        fetch=lambda url: _good_feed(),
    )
    assert result["overall"] == "ok"
    assert result["checks"][0]["status"] == "ok"
    assert result["checks"][1]["kind"] == "subscription"
    assert result["checks"][1]["status"] == "ok"
    assert "run_at" in result


def test_run_self_check_one_down_means_down():
    result = selfcheck_mod.run_self_check(
        [_inbound(tag="vless-1", port=443)],
        base_url="https://203.0.113.10:8443/panel", sub_token=_SUB,
        probe=lambda host, port: ("down", "connection refused"),
        fetch=lambda url: _good_feed(),
    )
    assert result["overall"] == "down"


def test_run_self_check_unknown_without_down_means_unknown():
    result = selfcheck_mod.run_self_check(
        [_inbound(tag="hy-1", protocol="hysteria2", port=8443)],
        base_url="https://203.0.113.10:8443/panel", sub_token=_SUB,
        fetch=lambda url: _good_feed(),
    )
    assert result["overall"] == "unknown"


def test_run_self_check_without_token_is_unknown():
    result = selfcheck_mod.run_self_check(
        [], base_url="https://203.0.113.10:8443/panel", sub_token=None,
    )
    assert result["overall"] == "unknown"
    assert result["checks"][0]["kind"] == "subscription"
    assert "no usable user" in result["checks"][0]["reason"]


def test_run_self_check_without_base_url_is_unknown():
    result = selfcheck_mod.run_self_check(
        [], base_url=None, sub_token=_SUB,
    )
    assert result["overall"] == "unknown"
    assert "no panel URL" in result["checks"][0]["reason"]


# ---------------------------------------------------------------------------
# Cadence
# ---------------------------------------------------------------------------

def test_selfcheck_due_rules():
    now = datetime.now(timezone.utc)
    assert selfcheck_mod.selfcheck_due({}, now=now) is False  # 0 = off
    assert selfcheck_mod.selfcheck_due(
        {"selfcheck_interval_minutes": "60"}, now=now) is True
    recent = {"selfcheck_interval_minutes": "60",
              "selfcheck_last": json.dumps(
                  {"run_at": (now - timedelta(minutes=5)).isoformat()})}
    assert selfcheck_mod.selfcheck_due(recent, now=now) is False
    stale = {"selfcheck_interval_minutes": "60",
             "selfcheck_last": json.dumps(
                 {"run_at": (now - timedelta(minutes=61)).isoformat()})}
    assert selfcheck_mod.selfcheck_due(stale, now=now) is True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def test_selfcheck_page_renders(authed_client):
    resp = authed_client.get("/selfcheck")
    assert resp.status_code == 200
    assert "selfcheck/run" in resp.text
    assert "selfcheck/interval" in resp.text
    # Never run yet: the page says so honestly (default lang is fa).
    assert "هرگز اجرا نشده" in resp.text


def test_selfcheck_page_requires_login(test_client):
    resp = test_client.get("/selfcheck", follow_redirects=False)
    assert resp.status_code == 303


def test_selfcheck_run_persists_result(authed_client, db, seeded):
    resp = authed_client.post("/selfcheck/run", follow_redirects=False)
    assert resp.status_code == 303
    stored = get_setting(db, selfcheck_mod.SELFCHECK_LAST_KEY)
    assert stored
    result = json.loads(stored)
    assert result["overall"] in ("ok", "down", "unknown")
    assert result["checks"]
    # The page now shows the run.
    page = authed_client.get("/selfcheck")
    assert page.status_code == 200
    assert result["run_at"] in page.text


def test_selfcheck_run_requires_csrf(authed_client):
    resp = authed_client.post(
        "/selfcheck/run", data={"csrf_token": "wrong-token"})
    assert resp.status_code == 403


def test_selfcheck_interval_round_trip(authed_client, db):
    resp = authed_client.post(
        "/selfcheck/interval", data={"interval": "30"},
        follow_redirects=False)
    assert resp.status_code == 303
    assert get_setting(db, selfcheck_mod.SELFCHECK_INTERVAL_KEY) == "30"
    # A bad value keeps the previous one.
    resp = authed_client.post(
        "/selfcheck/interval", data={"interval": "banana"},
        follow_redirects=False)
    assert resp.status_code == 303
    assert get_setting(db, selfcheck_mod.SELFCHECK_INTERVAL_KEY) == "30"


def test_dashboard_shows_selfcheck_summary(authed_client, db):
    # Before any run: the summary card shows "never run" and links
    # to the full page.
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert "/selfcheck" in resp.text
    assert "هرگز اجرا نشده" in resp.text
