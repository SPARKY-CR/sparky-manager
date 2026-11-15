"""Tests for the Xray Stats API client (F1 fix, Phase 5).

Covers: the hand-rolled protobuf wire codec, the per-user email
format in the renderer, the Stats API query path (fake channel —
no real Xray is needed), delta collection (baselining, counter
resets, attribution), the ``sync_traffic`` integration (usage rolls
up and traffic limits start working for Xray users), the rendered
config (stats blocks + API routing rule + emails), and the traffic
sync loop tolerating a dead API.
"""

from __future__ import annotations

import asyncio

import pytest

from app import main as main_mod
from app import traffic as traffic_mod
from app import xray as xray_mod
from app import xray_stats as stats_mod

# ---------------------------------------------------------------------------
# Wire codec — an independent encoder builds the bytes, so the test
# does not just re-run the module's own encoder.
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


def _field_string(field: int, text: str) -> bytes:
    encoded = text.encode("utf-8")
    return bytes([(field << 3) | 2]) + _varint(len(encoded)) + encoded


def _field_varint(field: int, value: int) -> bytes:
    return bytes([(field << 3) | 0]) + _varint(value)


def _encode_stat(name: str, value: int) -> bytes:
    body = _field_string(1, name) + _field_varint(2, value)
    return bytes([(1 << 3) | 2]) + _varint(len(body)) + body


def _encode_response(stats: list[tuple[str, int]]) -> bytes:
    return b"".join(_encode_stat(name, value) for name, value in stats)


def test_encode_request_pattern_only():
    encoded = stats_mod.encode_query_stats_request("user>>>traffic>>>")
    # field 1 (0x0a), length 17, then the pattern bytes.
    assert encoded == b"\x0a\x11" + b"user>>>traffic>>>"


def test_encode_request_with_reset():
    encoded = stats_mod.encode_query_stats_request("x", reset=True)
    assert encoded == b"\x0a\x01x\x10\x01"


def test_decode_response_round_trip():
    stats = [
        ("user>>>user-1@sparky.local>>>traffic>>>uplink", 123456),
        ("user>>>user-1@sparky.local>>>traffic>>>downlink", 789012),
        ("user>>>user-2@sparky.local>>>traffic>>>uplink", 0),
        ("user>>>user-3@sparky.local>>>traffic>>>downlink", 2**40),
    ]
    assert stats_mod.decode_query_stats_response(_encode_response(stats)) == dict(
        stats
    )


def test_decode_response_malformed():
    assert stats_mod.decode_query_stats_response(b"") == {}
    assert stats_mod.decode_query_stats_response(b"\xff\xff\xff") == {}
    assert stats_mod.decode_query_stats_response(b"\x0a\x05ab") == {}
    assert stats_mod.decode_query_stats_response(None) == {}  # type: ignore[arg-type]
    assert stats_mod.decode_query_stats_response("not-bytes") == {}  # type: ignore[arg-type]
    # A good stat followed by corrupt bytes: the good one survives.
    good = _encode_stat("user>>>a>>>traffic>>>uplink", 7)
    assert stats_mod.decode_query_stats_response(good + b"\x0a\x09zz") == {
        "user>>>a>>>traffic>>>uplink": 7
    }
    # A Stat missing its value is dropped, not invented.
    body = _field_string(1, "user>>>a>>>traffic>>>uplink")
    assert stats_mod.decode_query_stats_response(
        bytes([0x0A]) + _varint(len(body)) + body
    ) == {}


# ---------------------------------------------------------------------------
# Email format (xray.py) + stat-name parsing
# ---------------------------------------------------------------------------


def test_client_email_format():
    assert xray_mod.client_email(12) == "user-12@sparky.local"
    assert xray_mod.client_email("7") == "user-7@sparky.local"


def test_client_email_invalid():
    assert xray_mod.client_email(None) is None
    assert xray_mod.client_email(0) is None
    assert xray_mod.client_email(-3) is None
    assert xray_mod.client_email("abc") is None
    assert xray_mod.client_email("") is None


def test_parse_user_email_round_trip():
    assert xray_mod.parse_user_email("user-12@sparky.local") == 12
    assert xray_mod.parse_user_email("user-12@example.com") is None
    assert xray_mod.parse_user_email("alice") is None
    assert xray_mod.parse_user_email("user-abc@sparky.local") is None
    assert xray_mod.parse_user_email(None) is None
    assert xray_mod.parse_user_email(12) is None


def test_parse_traffic_stat_name():
    parse = stats_mod.parse_traffic_stat_name
    assert parse("user>>>user-12@sparky.local>>>traffic>>>uplink") == (
        12,
        "uplink",
    )
    assert parse("user>>>user-12@sparky.local>>>traffic>>>downlink") == (
        12,
        "downlink",
    )
    assert parse("inbound>>>vless-reality>>>traffic>>>uplink") == (None, None)
    assert parse("user>>>alice@example.com>>>traffic>>>uplink") == (None, None)
    assert parse("user>>>user-12@sparky.local>>>traffic>>>total") == (None, None)
    assert parse("user>>>user-12@sparky.local>>>traffic") == (None, None)
    assert parse("") == (None, None)
    assert parse(None) == (None, None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Query path — fake channel, no real Xray / grpc server.
# ---------------------------------------------------------------------------


class _FakeChannel:
    """A grpc channel stand-in: records the call, returns canned bytes."""

    def __init__(self, response: bytes, *, error: Exception | None = None):
        self.response = response
        self.error = error
        self.calls: list[tuple[bytes, float | None]] = []
        self.closed = False

    def unary_unary(self, method, request_serializer=None, response_deserializer=None):
        assert method == "/xray.app.stats.command.StatsService/QueryStats"
        assert request_serializer is not None
        assert response_deserializer is not None

        def _call(payload: bytes, timeout=None):
            self.calls.append((payload, timeout))
            if self.error is not None:
                raise self.error
            return self.response

        return _call

    def close(self):
        self.closed = True


@pytest.fixture()
def _fake_stats_response():
    return _encode_response(
        [
            ("user>>>user-1@sparky.local>>>traffic>>>uplink", 100),
            ("user>>>user-1@sparky.local>>>traffic>>>downlink", 200),
        ]
    )


def test_query_stats_returns_parsed_map(_fake_stats_response):
    channel = _FakeChannel(_fake_stats_response)
    result = stats_mod.query_stats(channel_factory=lambda address: channel)
    assert result == {
        "user>>>user-1@sparky.local>>>traffic>>>uplink": 100,
        "user>>>user-1@sparky.local>>>traffic>>>downlink": 200,
    }
    assert channel.closed  # the client closes the channel it opened
    payload, timeout = channel.calls[0]
    assert payload == stats_mod.encode_query_stats_request("user>>>traffic>>>")
    assert timeout == stats_mod.DEFAULT_TIMEOUT


def test_query_stats_uses_configured_api_address():
    seen: list[str] = []

    def _factory(address: str):
        seen.append(address)
        return _FakeChannel(b"")

    stats_mod.query_stats(channel_factory=_factory)
    assert seen == ["127.0.0.1:10085"]


def test_query_stats_api_down_returns_empty():
    channel = _FakeChannel(b"", error=ConnectionRefusedError("no xray"))
    assert stats_mod.query_stats(channel_factory=lambda a: channel) == {}
    assert channel.closed


def test_query_stats_factory_returns_none():
    assert stats_mod.query_stats(channel_factory=lambda a: None) == {}


def test_query_stats_malformed_response_returns_empty():
    channel = _FakeChannel(b"\xff\xff\xff\xff")
    assert stats_mod.query_stats(channel_factory=lambda a: channel) == {}


# ---------------------------------------------------------------------------
# Delta collection
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_snapshots():
    stats_mod.reset_snapshots()
    yield
    stats_mod.reset_snapshots()


def _stats_for(values: dict[int, tuple[int, int]]) -> dict[str, int]:
    """Cumulative counters for {user_id: (up, down)}."""
    out: dict[str, int] = {}
    for user_id, (up, down) in values.items():
        base = f"user>>>user-{user_id}@sparky.local>>>traffic>>>"
        out[base + "uplink"] = up
        out[base + "downlink"] = down
    return out


def test_collect_first_call_baselines_only():
    query = lambda: _stats_for({1: (1000, 2000)})  # noqa: E731
    assert stats_mod.collect_xray_deltas(query_fn=query) == {}
    # Second call with the same counters: still no delta.
    assert stats_mod.collect_xray_deltas(query_fn=query) == {}


def test_collect_returns_deltas_per_user():
    state = {"values": {1: (1000, 2000), 2: (500, 500)}}
    query = lambda: _stats_for(state["values"])  # noqa: E731
    stats_mod.collect_xray_deltas(query_fn=query)
    state["values"] = {1: (1500, 2600), 2: (500, 900)}
    assert stats_mod.collect_xray_deltas(query_fn=query) == {
        1: (500, 600),
        2: (0, 400),
    }


def test_collect_counter_reset_rebaselines():
    state = {"values": {1: (1000, 2000)}}
    query = lambda: _stats_for(state["values"])  # noqa: E731
    stats_mod.collect_xray_deltas(query_fn=query)
    # Xray restarted: counters start from zero — no negative delta,
    # no phantom usage, just a fresh baseline.
    state["values"] = {1: (10, 20)}
    assert stats_mod.collect_xray_deltas(query_fn=query) == {}
    state["values"] = {1: (110, 220)}
    assert stats_mod.collect_xray_deltas(query_fn=query) == {1: (100, 200)}


def test_collect_ignores_foreign_and_malformed_stats():
    def _query():
        return {
            "user>>>alice@example.com>>>traffic>>>uplink": 999,
            "inbound>>>vless-reality>>>traffic>>>uplink": 999,
            "user>>>user-1@sparky.local>>>traffic>>>uplink": 100,
            "user>>>user-1@sparky.local>>>traffic>>>downlink": "junk",
            "user>>>user-1@sparky.local>>>traffic>>>uplink2": 50,
        }

    stats_mod.collect_xray_deltas(query_fn=_query)
    assert stats_mod.collect_xray_deltas(query_fn=_query) == {}


def test_collect_query_failure_returns_empty():
    def _boom():
        raise RuntimeError("API exploded")

    assert stats_mod.collect_xray_deltas(query_fn=_boom) == {}
    assert stats_mod.collect_xray_deltas(query_fn=lambda: None) == {}  # type: ignore[arg-type]
    assert stats_mod.collect_xray_deltas(query_fn=lambda: "junk") == {}  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# sync_traffic integration — limits now work for Xray users
# ---------------------------------------------------------------------------


def test_xray_deltas_roll_into_usage_and_trigger_limits(db, seeded):
    alice = seeded["users"]["alice"]
    alice.traffic_limit_bytes = 1000
    alice.traffic_used_bytes = 900
    db.commit()
    from app.models import user_is_usable

    assert user_is_usable(alice) is True  # under quota before the deltas
    result = traffic_mod.sync_traffic(db, xray_stats={alice.id: (50, 60)})
    assert result["users_updated"][alice.id] == (50, 60)
    db.refresh(alice)
    assert alice.traffic_used_bytes == 1010
    # Over quota now: the usability rule (used by the renderers and
    # the sweeper) excludes her — this is what "limits trigger" means.
    assert user_is_usable(alice) is False


def test_xray_deltas_upsert_traffic_daily(db, seeded):
    alice = seeded["users"]["alice"]
    traffic_mod.sync_traffic(db, xray_stats={alice.id: (100, 200)})
    traffic_mod.sync_traffic(db, xray_stats={alice.id: (10, 20)})
    from datetime import date

    from app.models import TrafficDaily

    row = (
        db.query(TrafficDaily)
        .filter(TrafficDaily.user_id == alice.id, TrafficDaily.date == date.today())
        .first()
    )
    assert row is not None
    assert (row.up_bytes, row.down_bytes) == (110, 220)


# ---------------------------------------------------------------------------
# Rendered config — stats blocks, API routing rule, emails
# ---------------------------------------------------------------------------


def _vless_inbound(**overrides):
    inbound = {
        "tag": "vless-test",
        "core": "xray",
        "protocol": "vless",
        "port": 1443,
        "enabled": True,
        "stream_json": {"network": "tcp", "security": "none"},
    }
    inbound.update(overrides)
    return inbound


def _clients_for(user_ids, **kwargs):
    return [
        {"uuid": f"00000000-0000-4000-8000-{uid:012d}", "user_id": uid, **kwargs}
        for uid in user_ids
    ]


def test_rendered_config_has_stats_api_blocks():
    cfg = xray_mod.render_xray_config(
        [_vless_inbound()],
        {"vless-test": _clients_for([1])},
        {},
    )
    assert cfg["api"] == {
        "tag": "api",
        "services": ["HandlerService", "LoggerService", "StatsService"],
    }
    assert cfg["stats"] == {}
    assert cfg["policy"]["levels"]["0"] == {
        "statsUserUplink": True,
        "statsUserDownlink": True,
    }
    api_inbound = cfg["inbounds"][0]
    assert api_inbound["tag"] == "api"
    assert api_inbound["port"] == 10085
    assert api_inbound["listen"] == "127.0.0.1"
    assert api_inbound["protocol"] == "dokodemo-door"


def test_rendered_config_routes_api_inbound_first():
    cfg = xray_mod.render_xray_config([], {}, {})
    rules = cfg["routing"]["rules"]
    # The API rule must precede the geoip:private rule — first match
    # wins, and API traffic targets 127.0.0.1 (a private IP).
    assert rules[0] == {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api",
    }
    assert rules[1]["outboundTag"] == "blackhole"


def test_rendered_clients_carry_stats_email():
    cfg = xray_mod.render_xray_config(
        [_vless_inbound()],
        {"vless-test": _clients_for([1, 2])},
        {},
    )
    inbound = next(i for i in cfg["inbounds"] if i["tag"] == "vless-test")
    emails = [c["email"] for c in inbound["settings"]["clients"]]
    assert emails == ["user-1@sparky.local", "user-2@sparky.local"]


def test_rendered_emails_across_protocols():
    inbounds = [
        _vless_inbound(),
        {
            "tag": "vmess-test", "core": "xray", "protocol": "vmess",
            "port": 1444, "enabled": True,
            "stream_json": {"network": "tcp", "security": "none"},
        },
        {
            "tag": "trojan-test", "core": "xray", "protocol": "trojan",
            "port": 1445, "enabled": True,
            "stream_json": {"network": "tcp", "security": "tls",
                            "tls": {"sni": "example.com"}},
        },
        {
            "tag": "ss-test", "core": "xray", "protocol": "shadowsocks",
            "port": 1446, "enabled": True, "stream_json": {},
        },
        {
            "tag": "hy2-test", "core": "xray", "protocol": "hysteria2",
            "port": 1447, "enabled": True,
            "stream_json": {"network": "tcp", "security": "tls",
                            "tls": {"sni": "example.com"}},
        },
    ]
    clients = {
        "vless-test": _clients_for([1]),
        "vmess-test": _clients_for([2]),
        "trojan-test": [{"password": "pw-3", "user_id": 3}],
        # Shadowsocks needs 2+ clients for the clients list (the
        # single-client form has no per-user entry by design).
        "ss-test": [
            {"password": "MTIzNDU2Nzg5MDEyMzQ1Ng==", "user_id": 4},
            {"password": "YWJjZGVmZ2hpamtsbW5vcA==", "user_id": 5},
        ],
        "hy2-test": [{"password": "pw-6", "user_id": 6}],
    }
    cfg = xray_mod.render_xray_config(inbounds, clients, {})
    by_tag = {i["tag"]: i for i in cfg["inbounds"]}
    assert by_tag["vmess-test"]["settings"]["clients"][0]["email"] == (
        "user-2@sparky.local"
    )
    assert by_tag["trojan-test"]["settings"]["clients"][0]["email"] == (
        "user-3@sparky.local"
    )
    ss_emails = [c["email"] for c in by_tag["ss-test"]["settings"]["clients"]]
    assert ss_emails == ["user-4@sparky.local", "user-5@sparky.local"]
    assert by_tag["hy2-test"]["settings"]["clients"][0]["email"] == (
        "user-6@sparky.local"
    )


def test_rendered_clients_without_user_id_have_no_email():
    cfg = xray_mod.render_xray_config(
        [_vless_inbound()],
        {"vless-test": [{"uuid": "00000000-0000-4000-8000-000000000001"}]},
        {},
    )
    inbound = next(i for i in cfg["inbounds"] if i["tag"] == "vless-test")
    assert "email" not in inbound["settings"]["clients"][0]


def test_rendered_config_still_validates(tmp_path):
    cfg = xray_mod.render_xray_config(
        [_vless_inbound()],
        {"vless-test": _clients_for([1])},
        {},
    )
    ok, errors = xray_mod.validate_xray_config(cfg)
    assert ok, errors
    # write_and_validate with no xray binary: JSON validation only,
    # file still written.
    path = tmp_path / "config.json"
    ok, messages = xray_mod.write_and_validate(cfg, path)
    assert ok
    assert path.exists()
    assert any("binary not present" in m for m in messages)


def test_user_inbound_cannot_claim_api_port():
    cfg = xray_mod.render_xray_config(
        [_vless_inbound(port=10085)],
        {"vless-test": _clients_for([1])},
        {},
    )
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert tags == ["api"]  # the user inbound is dropped, not rendered broken


# ---------------------------------------------------------------------------
# Sync loop — Xray deltas flow through; a dead API is tolerated
# ---------------------------------------------------------------------------


def _run_traffic_loop(seconds=0.3):
    async def _run():
        task = asyncio.create_task(main_mod._traffic_sync_loop())
        await asyncio.sleep(seconds)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())


def test_loop_passes_xray_deltas_to_sync(db, seeded, monkeypatch):
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    alice = seeded["users"]["alice"]
    calls: list[dict] = []
    real_sync = traffic_mod.sync_traffic

    def _recording_sync(db_session, **kwargs):
        calls.append(kwargs)
        return real_sync(db_session, **kwargs)

    monkeypatch.setattr(traffic_mod, "sync_traffic", _recording_sync)
    monkeypatch.setattr(
        stats_mod,
        "collect_xray_deltas",
        lambda *a, **k: {alice.id: (1000, 2000)},
    )
    _run_traffic_loop()
    assert calls, "the loop never ticked"
    assert all(c["xray_stats"] == {alice.id: (1000, 2000)} for c in calls)
    db.refresh(alice)
    assert alice.traffic_used_bytes >= 3000


def test_loop_tolerates_dead_api(db, seeded, monkeypatch):
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    calls: list[dict] = []
    real_sync = traffic_mod.sync_traffic

    def _recording_sync(db_session, **kwargs):
        calls.append(kwargs)
        return real_sync(db_session, **kwargs)

    monkeypatch.setattr(traffic_mod, "sync_traffic", _recording_sync)
    # A dead API: the collector fails soft and returns {}.
    monkeypatch.setattr(stats_mod, "collect_xray_deltas", lambda *a, **k: {})
    _run_traffic_loop()
    assert calls, "the loop never ticked"
    assert all(c["xray_stats"] == {} for c in calls)
