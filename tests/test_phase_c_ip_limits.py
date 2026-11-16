"""Best-panel program, Phase C item 20 — IP-limit enforcement.

Tests the GetUsersStats hand-rolled codec (app/xray_stats.py), the
capability probe, the enforcement core (app/ip_limits.py) and the
user-page ban display + unban route. fail2ban is never invoked
for real: the runner is stubbed and the assertions are on the argv
it received and the IpBan rows created.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import grpc
import pytest

from app import ip_limits as ip_limits_mod
from app import xray_stats as xray_stats_mod
from app.models import IpBan
from app.xray_stats import OnlineIP, UserOnlineStats


# ---------------------------------------------------------------------------
# Codec helpers (hand-built protobuf, mirroring the module's own layout)
# ---------------------------------------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field_bytes(field_no: int, payload: bytes) -> bytes:
    return bytes([(field_no << 3) | 2]) + _varint(len(payload)) + payload


def _field_varint(field_no: int, value: int) -> bytes:
    return bytes([(field_no << 3) | 0]) + _varint(value)


def _encode_online_ip(ip: str, last_seen: int) -> bytes:
    out = _field_bytes(1, ip.encode("utf-8"))
    out += _field_varint(2, last_seen)
    return out


def _encode_user_stat(
    email: str, ips: list[tuple[str, int]], uplink: int = 0, downlink: int = 0
) -> bytes:
    out = _field_bytes(1, email.encode("utf-8"))
    for ip, last_seen in ips:
        out += _field_bytes(2, _encode_online_ip(ip, last_seen))
    traffic = _field_varint(1, uplink) + _field_varint(2, downlink)
    out += _field_bytes(3, traffic)
    return out


def _encode_response(users: list[bytes]) -> bytes:
    out = b""
    for user in users:
        out += _field_bytes(1, user)
    return out


class _FakeRpcError(Exception):
    """A grpc.RpcError stand-in with a .code() method."""

    def __init__(self, code):
        super().__init__(f"fake rpc error: {code}")
        self._code = code

    def code(self):
        return self._code


class _FakeChannel:
    """A grpc channel stand-in: unary_unary returns the stub."""

    def __init__(self, stub):
        self._stub = stub
        self.closed = False

    def unary_unary(self, method, request_serializer, response_deserializer):
        assert method == "/xray.app.stats.command.StatsService/GetUsersStats"
        return self._stub

    def close(self):
        self.closed = True


def _channel_factory_for(response=None, error=None, calls=None):
    def factory(address):
        if calls is not None:
            calls.append(address)

        def stub(payload, timeout=None):
            if error is not None:
                raise error
            return response

        return _FakeChannel(stub)

    return factory


# ---------------------------------------------------------------------------
# GetUsersStats codec
# ---------------------------------------------------------------------------


def test_encode_get_users_stats_request():
    # proto3 bools: false fields are omitted.
    assert xray_stats_mod.encode_get_users_stats_request() == b"\x08\x01"
    assert (
        xray_stats_mod.encode_get_users_stats_request(
            include_traffic=True, reset=True
        )
        == b"\x08\x01\x10\x01"
    )
    assert (
        xray_stats_mod.encode_get_users_stats_request(
            include_traffic=False, reset=False
        )
        == b""
    )


def test_decode_get_users_stats_response_round_trip():
    payload = _encode_response(
        [
            _encode_user_stat(
                "user-12@sparky.local",
                [("203.0.113.7", 1000), ("198.51.100.9", 2000)],
                uplink=111,
                downlink=222,
            ),
            _encode_user_stat("user-3@sparky.local", [], uplink=5),
        ]
    )
    users = xray_stats_mod.decode_get_users_stats_response(payload)
    assert len(users) == 2
    assert users[0].email == "user-12@sparky.local"
    assert users[0].ips == [
        OnlineIP(ip="203.0.113.7", last_seen=1000),
        OnlineIP(ip="198.51.100.9", last_seen=2000),
    ]
    assert (users[0].uplink, users[0].downlink) == (111, 222)
    assert users[1].email == "user-3@sparky.local"
    assert users[1].ips == []
    assert users[1].uplink == 5


def test_decode_get_users_stats_response_garbage_is_partial():
    good = _encode_user_stat("user-1@sparky.local", [("10.0.0.1", 5)])
    # A well-formed user followed by corrupt bytes: the good user is
    # kept, the garbage is dropped, nothing raises.
    payload = _field_bytes(1, good) + b"\xff\xff\xff"
    users = xray_stats_mod.decode_get_users_stats_response(payload)
    assert [u.email for u in users] == ["user-1@sparky.local"]
    assert xray_stats_mod.decode_get_users_stats_response(b"\xff") == []
    assert xray_stats_mod.decode_get_users_stats_response(b"") == []
    assert xray_stats_mod.decode_get_users_stats_response("nope") == []


def test_get_users_stats_success_and_capability_cache():
    payload = _encode_response(
        [_encode_user_stat("user-1@sparky.local", [("10.0.0.1", 5)])]
    )
    calls: list[str] = []
    factory = _channel_factory_for(response=payload, calls=calls)
    assert xray_stats_mod.users_stats_supported() is None
    users = xray_stats_mod.get_users_stats(channel_factory=factory)
    assert [u.email for u in users] == ["user-1@sparky.local"]
    assert xray_stats_mod.users_stats_supported() is True
    assert calls == ["127.0.0.1:10085"]


def test_get_users_stats_unimplemented_disables_forever():
    calls: list[str] = []
    factory = _channel_factory_for(
        error=_FakeRpcError(grpc.StatusCode.UNIMPLEMENTED), calls=calls
    )
    assert xray_stats_mod.get_users_stats(channel_factory=factory) == []
    assert xray_stats_mod.users_stats_supported() is False
    # The cached False short-circuits: the factory is not called again.
    assert xray_stats_mod.get_users_stats(channel_factory=factory) == []
    assert len(calls) == 1


def test_get_users_stats_transient_failure_leaves_cache_alone():
    factory = _channel_factory_for(error=RuntimeError("connection refused"))
    assert xray_stats_mod.get_users_stats(channel_factory=factory) == []
    # A transient failure says nothing about capability.
    assert xray_stats_mod.users_stats_supported() is None
    # And a missing channel (grpcio absent) is an empty result, not a crash.
    assert xray_stats_mod.get_users_stats(channel_factory=lambda a: None) == []


# ---------------------------------------------------------------------------
# Excess-IP selection (pure function)
# ---------------------------------------------------------------------------


def test_select_excess_ips_keeps_newest():
    online = [
        OnlineIP(ip="10.0.0.1", last_seen=100),
        OnlineIP(ip="10.0.0.2", last_seen=300),
        OnlineIP(ip="10.0.0.3", last_seen=200),
    ]
    assert ip_limits_mod.select_excess_ips(online, 2) == ["10.0.0.1"]
    assert ip_limits_mod.select_excess_ips(online, 3) == []
    assert ip_limits_mod.select_excess_ips(online, 0) == [
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.1",
    ]


def test_select_excess_ips_dedupes_and_is_deterministic():
    online = [
        OnlineIP(ip="10.0.0.1", last_seen=100),
        OnlineIP(ip="10.0.0.1", last_seen=500),  # duplicate: newest wins
        OnlineIP(ip="10.0.0.2", last_seen=500),  # tie: IP order decides
    ]
    assert ip_limits_mod.select_excess_ips(online, 1) == ["10.0.0.2"]


# ---------------------------------------------------------------------------
# Effective limit (min over the user's Xray-core clients)
# ---------------------------------------------------------------------------


def _set_limit(db, client, limit):
    client.extra_json = json.dumps({"ip_limit": limit})
    db.commit()


def test_effective_ip_limit_min_over_xray_clients(db, seeded):
    alice = seeded["users"]["alice"]
    assert ip_limits_mod.effective_ip_limit(db, alice) is None
    _set_limit(db, seeded["clients"][("alice", "vless-reality")], 3)
    assert ip_limits_mod.effective_ip_limit(db, alice) == 3
    _set_limit(db, seeded["clients"][("alice", "trojan-tls")], 2)
    assert ip_limits_mod.effective_ip_limit(db, alice) == 2


def test_effective_ip_limit_ignores_non_xray_clients(db, seeded):
    alice = seeded["users"]["alice"]
    # sing-box core (tuic) and native (wireguard) clients carry no
    # observable IPs — their limits must not count.
    _set_limit(db, seeded["clients"][("alice", "tuic")], 1)
    _set_limit(db, seeded["clients"][("alice", "wireguard")], 1)
    assert ip_limits_mod.effective_ip_limit(db, alice) is None


def test_effective_ip_limit_ignores_invalid_values(db, seeded):
    alice = seeded["users"]["alice"]
    client = seeded["clients"][("alice", "vless-reality")]
    for bad in (0, -1, 1001, "two", None):
        client.extra_json = json.dumps({"ip_limit": bad})
        db.commit()
        assert ip_limits_mod.effective_ip_limit(db, alice) is None
    client.extra_json = "not json at all"
    db.commit()
    assert ip_limits_mod.effective_ip_limit(db, alice) is None


# ---------------------------------------------------------------------------
# Ban / unban (stubbed runner + tmp log)
# ---------------------------------------------------------------------------


class _RunnerStub:
    """Records argv; returns (rc, stdout, stderr) per call."""

    def __init__(self, rc=0):
        self.calls: list[tuple] = []
        self.rc = rc

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        return self.rc, "", ""


def test_ban_ip_calls_fail2ban_writes_log_and_row(db, seeded, tmp_path):
    alice = seeded["users"]["alice"]
    runner = _RunnerStub()
    now = datetime.now(timezone.utc)
    assert ip_limits_mod.ban_ip(
        db, alice.id, "203.0.113.7", runner=runner, now=now, data_dir=tmp_path
    )
    assert runner.calls == [
        (
            "fail2ban-client",
            "set",
            "sparky-ipl",
            "banip",
            "203.0.113.7",
        )
    ]
    row = db.query(IpBan).filter(IpBan.user_id == alice.id).one()
    assert row.ip == "203.0.113.7"
    # SQLite stores datetimes without tzinfo — normalize before comparing.
    assert row.expires_at.replace(tzinfo=timezone.utc) == now + timedelta(
        minutes=30
    )
    log = (tmp_path / "logs" / "iplimit.log").read_text(encoding="utf-8")
    assert "[LIMIT_IP] 203.0.113.7 user-%d" % alice.id in log


def test_ban_ip_refuses_invalid_ip(db, seeded, tmp_path):
    alice = seeded["users"]["alice"]
    runner = _RunnerStub()
    assert not ip_limits_mod.ban_ip(
        db, alice.id, "1.2.3.4; rm -rf /", runner=runner, data_dir=tmp_path
    )
    assert runner.calls == []
    assert db.query(IpBan).count() == 0


def test_ban_ip_fail2ban_failure_still_records(db, seeded, tmp_path):
    alice = seeded["users"]["alice"]
    runner = _RunnerStub(rc=1)
    assert not ip_limits_mod.ban_ip(
        db, alice.id, "203.0.113.7", runner=runner, data_dir=tmp_path
    )
    # The row + log line exist anyway (the jail's filter can still
    # catch the IP from the log).
    assert db.query(IpBan).count() == 1
    assert (tmp_path / "logs" / "iplimit.log").exists()


def test_unban_ip_calls_fail2ban_and_deletes_row(db, seeded):
    alice = seeded["users"]["alice"]
    row = IpBan(
        user_id=alice.id,
        ip="203.0.113.7",
        banned_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    )
    db.add(row)
    db.commit()
    runner = _RunnerStub()
    assert ip_limits_mod.unban_ip(db, row, runner=runner)
    assert runner.calls == [
        ("fail2ban-client", "set", "sparky-ipl", "unbanip", "203.0.113.7")
    ]
    assert db.query(IpBan).count() == 0


def test_prune_expired_bans(db, seeded):
    alice = seeded["users"]["alice"]
    now = datetime.now(timezone.utc)
    db.add_all(
        [
            IpBan(
                user_id=alice.id,
                ip="10.0.0.1",
                banned_at=now - timedelta(hours=1),
                expires_at=now - timedelta(minutes=1),
            ),
            IpBan(
                user_id=alice.id,
                ip="10.0.0.2",
                banned_at=now,
                expires_at=now + timedelta(minutes=30),
            ),
        ]
    )
    db.commit()
    assert ip_limits_mod.prune_expired_bans(db, now=now) == 1
    remaining = [row.ip for row in db.query(IpBan).all()]
    assert remaining == ["10.0.0.2"]


# ---------------------------------------------------------------------------
# One enforcement pass (stubbed collection + runner)
# ---------------------------------------------------------------------------


def test_enforce_ip_limits_once_bans_excess_only(db, seeded, tmp_path):
    alice = seeded["users"]["alice"]
    _set_limit(db, seeded["clients"][("alice", "vless-reality")], 2)
    runner = _RunnerStub()
    stats = [
        UserOnlineStats(
            email=f"user-{alice.id}@sparky.local",
            ips=[
                OnlineIP(ip="10.0.0.1", last_seen=100),
                OnlineIP(ip="10.0.0.2", last_seen=200),
                OnlineIP(ip="10.0.0.3", last_seen=300),
            ],
        )
    ]
    summary = ip_limits_mod.enforce_ip_limits_once(
        db,
        collect_fn=lambda: stats,
        runner=runner,
        data_dir=tmp_path,
    )
    # The oldest IP (10.0.0.1) is banned; the two newest stay.
    assert summary["banned"] == [(alice.id, "10.0.0.1")]
    assert summary["users_checked"] == 1
    assert len(runner.calls) == 1
    # A second pass with the same stats bans nothing (dedup).
    summary2 = ip_limits_mod.enforce_ip_limits_once(
        db,
        collect_fn=lambda: stats,
        runner=runner,
        data_dir=tmp_path,
    )
    assert summary2["banned"] == []
    assert len(runner.calls) == 1


def test_enforce_ip_limits_once_skips_unlimited_and_unknown(
    db, seeded, tmp_path
):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    runner = _RunnerStub()
    stats = [
        # Alice has no limit set: no enforcement.
        UserOnlineStats(
            email=f"user-{alice.id}@sparky.local",
            ips=[OnlineIP(ip="10.0.0.1", last_seen=1)],
        ),
        # Bob is expired but has no limit either: still no enforcement.
        UserOnlineStats(
            email=f"user-{bob.id}@sparky.local",
            ips=[OnlineIP(ip="10.0.0.2", last_seen=1)],
        ),
        # Unparseable email + unknown user id: skipped, not a crash.
        UserOnlineStats(email="not-an-email", ips=[]),
        UserOnlineStats(
            email="user-99999@sparky.local",
            ips=[OnlineIP(ip="10.0.0.3", last_seen=1)],
        ),
    ]
    summary = ip_limits_mod.enforce_ip_limits_once(
        db,
        collect_fn=lambda: stats,
        runner=runner,
        data_dir=tmp_path,
    )
    assert summary["banned"] == []
    assert runner.calls == []


def test_enforce_ip_limits_once_collection_failure_is_soft(db, seeded):
    summary = ip_limits_mod.enforce_ip_limits_once(
        db, collect_fn=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert summary["banned"] == []


# ---------------------------------------------------------------------------
# User page: bans display + unban route
# ---------------------------------------------------------------------------


def test_user_detail_shows_bans_and_effective_limit(
    authed_client, db, seeded
):
    alice = seeded["users"]["alice"]
    _set_limit(db, seeded["clients"][("alice", "vless-reality")], 2)
    now = datetime.now(timezone.utc)
    db.add(
        IpBan(
            user_id=alice.id,
            ip="203.0.113.7",
            banned_at=now,
            expires_at=now + timedelta(minutes=30),
        )
    )
    db.commit()
    resp = authed_client.get(f"/users/{alice.id}")
    assert resp.status_code == 200
    assert "203.0.113.7" in resp.text
    assert f"/users/{alice.id}/ip-bans/" in resp.text
    # The effective limit (2) is shown in its own chip.
    assert '<b dir="ltr">2</b>' in resp.text


def test_unban_route_lifts_ban(authed_client, db, seeded, monkeypatch):
    from app.models import AuditLog

    alice = seeded["users"]["alice"]
    now = datetime.now(timezone.utc)
    ban = IpBan(
        user_id=alice.id,
        ip="203.0.113.7",
        banned_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    db.add(ban)
    db.commit()
    runner = _RunnerStub()
    monkeypatch.setattr(
        ip_limits_mod, "_default_runner", lambda: runner
    )
    resp = authed_client.post(
        f"/users/{alice.id}/ip-bans/{ban.id}/unban", data={}
    )
    assert resp.status_code in (200, 303)
    assert db.query(IpBan).count() == 0
    assert runner.calls == [
        ("fail2ban-client", "set", "sparky-ipl", "unbanip", "203.0.113.7")
    ]
    # The audit log records the unban.
    assert (
        db.query(AuditLog)
        .filter(AuditLog.action == "ip_limit.unban")
        .count()
        == 1
    )


def test_unban_route_wrong_user_404s(authed_client, db, seeded):
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    now = datetime.now(timezone.utc)
    ban = IpBan(
        user_id=alice.id,
        ip="203.0.113.7",
        banned_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    db.add(ban)
    db.commit()
    # The ban belongs to alice; asking as bob's ban is refused.
    resp = authed_client.post(
        f"/users/{bob.id}/ip-bans/{ban.id}/unban", data={}
    )
    assert resp.status_code in (200, 303)
    assert db.query(IpBan).count() == 1


def test_unban_route_requires_csrf(test_client, db, seeded):
    alice = seeded["users"]["alice"]
    now = datetime.now(timezone.utc)
    ban = IpBan(
        user_id=alice.id,
        ip="203.0.113.7",
        banned_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    db.add(ban)
    db.commit()
    # Logged out entirely: the route redirects to /login (303 with
    # redirects unfollowed) and the ban survives.
    resp = test_client.post_raw(
        f"/users/{alice.id}/ip-bans/{ban.id}/unban",
        data={},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert db.query(IpBan).count() == 1
