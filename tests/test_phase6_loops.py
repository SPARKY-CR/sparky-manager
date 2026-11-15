"""Phase 6 (professional upgrade) background-loop tests.

The traffic sync loop and the expiry sweeper are the panel's two
always-running background tasks. The polling loop is already covered
(tests/test_telegram_polling.py); this file covers the other two —
including the one test the Phase 5 report left open: the traffic
loop end to end, from a (fake) Xray Stats API through the real
gRPC client, the real loop, the real ``sync_traffic`` and the real
DB. Phase 5 tested each hop separately (``collect_xray_deltas``
was monkeypatched in the loop tests); this file wires them together
with only the network faked.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import date

from app import main as main_mod
from app import traffic as traffic_mod
from app import xray_stats as stats_mod
from app.models import TrafficDaily, user_is_usable

# ---------------------------------------------------------------------------
# Independent protobuf encoder (same shape as test_xray_stats.py's —
# deliberately duplicated, not imported: the encoder is the check).
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


def _encode_stat(name: str, value: int) -> bytes:
    name_b = name.encode("utf-8")
    body = (
        bytes([0x0A]) + _varint(len(name_b)) + name_b  # field 1: name
        + bytes([0x10]) + _varint(value)  # field 2: value
    )
    return bytes([0x0A]) + _varint(len(body)) + body


def _encode_response(stats: list[tuple[str, int]]) -> bytes:
    return b"".join(_encode_stat(name, value) for name, value in stats)


# ---------------------------------------------------------------------------
# Fake gRPC channel — cumulative counters that grow on every call,
# like a real Xray Stats API under load.
# ---------------------------------------------------------------------------


class _FakeStatsChannel:
    """A ``grpc.insecure_channel`` stand-in: ``unary_unary`` returns
    a stub that answers with an encoded QueryStatsResponse whose
    cumulative counters grow by (up_step, down_step) per call."""

    def __init__(self, user_id: int, up_step: int = 1000, down_step: int = 2000):
        self.user_id = user_id
        self.up_step = up_step
        self.down_step = down_step
        self.calls = 0
        self.closed = 0
        self._lock = threading.Lock()

    def unary_unary(self, method, request_serializer=None,
                    response_deserializer=None):
        assert method == "/xray.app.stats.command.StatsService/QueryStats"

        def _stub(payload, timeout=None):
            with self._lock:
                self.calls += 1
                n = self.calls
            up = f"user>>>user-{self.user_id}@sparky.local>>>traffic>>>uplink"
            down = (f"user>>>user-{self.user_id}@sparky.local"
                    f">>>traffic>>>downlink")
            return _encode_response([
                (up, n * self.up_step),
                (down, n * self.down_step),
            ])

        return _stub

    def close(self):
        self.closed += 1


def _run_loop(coro_fn, seconds=0.6):
    async def _run():
        task = asyncio.create_task(coro_fn())
        await asyncio.sleep(seconds)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Traffic loop end to end: fake Stats API -> real client -> real loop
# -> real sync_traffic -> real DB
# ---------------------------------------------------------------------------

def test_loop_end_to_end_xray_traffic_reaches_db(
    db, seeded, monkeypatch
):
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    alice = seeded["users"]["alice"]
    channel = _FakeStatsChannel(alice.id)
    monkeypatch.setattr(
        stats_mod, "_default_channel", lambda address: channel)
    _run_loop(main_mod._traffic_sync_loop)
    assert channel.calls >= 3, "the loop never ticked"
    db.refresh(alice)
    # Tick 1 baselines; every later tick adds 3000 bytes (1000 up +
    # 2000 down). With >= 3 calls, at least 2 ticks produced deltas.
    assert alice.traffic_used_bytes >= 6000
    row = (
        db.query(TrafficDaily)
        .filter(TrafficDaily.user_id == alice.id,
                TrafficDaily.date == date.today())
        .first()
    )
    assert row is not None
    assert (row.up_bytes or 0) + (row.down_bytes or 0) >= 6000
    assert row.up_bytes == alice.traffic_used_bytes - (row.down_bytes or 0)


def test_loop_end_to_end_traffic_limit_triggers(
    db, seeded, monkeypatch
):
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    alice = seeded["users"]["alice"]
    alice.traffic_limit_bytes = 5000
    alice.traffic_used_bytes = 0
    db.commit()
    assert user_is_usable(alice) is True
    channel = _FakeStatsChannel(alice.id)
    monkeypatch.setattr(
        stats_mod, "_default_channel", lambda address: channel)
    _run_loop(main_mod._traffic_sync_loop)
    db.refresh(alice)
    assert alice.traffic_used_bytes >= 6000
    # Over quota: the usability rule (used by the renderers and the
    # sweeper) now excludes her — traffic limits work for Xray users.
    assert user_is_usable(alice) is False


def test_loop_end_to_end_malformed_stats_response_is_ignored(
    db, seeded, monkeypatch
):
    """A Stats API returning garbage must not corrupt the DB: the
    decoder drops it, the tick is a no-op, the loop keeps running."""

    class _GarbageChannel(_FakeStatsChannel):
        def unary_unary(self, method, request_serializer=None,
                        response_deserializer=None):
            def _stub(payload, timeout=None):
                with self._lock:
                    self.calls += 1
                return b"\xff\xff\xff\xffgarbage"
            return _stub

    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    alice = seeded["users"]["alice"]
    channel = _GarbageChannel(alice.id)
    monkeypatch.setattr(
        stats_mod, "_default_channel", lambda address: channel)
    _run_loop(main_mod._traffic_sync_loop)
    assert channel.calls >= 3
    db.refresh(alice)
    assert alice.traffic_used_bytes == 0
    assert db.query(TrafficDaily).count() == 0


def test_loop_dead_api_leaves_db_untouched(db, seeded, monkeypatch):
    """The Phase 5 dead-API test proved ``xray_stats == {}`` reaches
    ``sync_traffic``; this proves the stronger claim: with a dead
    API (and no WireGuard data in the test env), no tick writes
    anything to the DB at all."""
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    alice = seeded["users"]["alice"]
    before = alice.traffic_used_bytes
    monkeypatch.setattr(stats_mod, "collect_xray_deltas", lambda *a, **k: {})
    _run_loop(main_mod._traffic_sync_loop)
    db.refresh(alice)
    assert alice.traffic_used_bytes == before
    assert db.query(TrafficDaily).count() == 0


def test_loop_survives_sync_exception(db, seeded, monkeypatch):
    """One failing tick (a DB error inside sync_traffic) must not
    kill the loop: later ticks still run."""
    monkeypatch.setattr(main_mod, "TRAFFIC_SYNC_INTERVAL_SECONDS", 0.01)
    calls = {"n": 0}

    def _boom_once(db_session, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return traffic_mod.sync_traffic(db_session, **kwargs)

    monkeypatch.setattr(traffic_mod, "sync_traffic", _boom_once)
    monkeypatch.setattr(stats_mod, "collect_xray_deltas", lambda *a, **k: {})
    _run_loop(main_mod._traffic_sync_loop)
    assert calls["n"] >= 3, "the loop died after the first failure"


# ---------------------------------------------------------------------------
# Expiry sweeper loop — wiring: each tick re-renders, then notifies
# ---------------------------------------------------------------------------

def test_sweeper_loop_ticks_render_then_notify(db, monkeypatch):
    monkeypatch.setattr(main_mod, "EXPIRY_SWEEPER_INTERVAL_SECONDS", 0.01)
    order: list[str] = []

    def _render(db_session):
        order.append("render")
        return []

    def _notify(db_session):
        order.append("notify")
        return 0

    monkeypatch.setattr(main_mod, "rerender_configs", _render)
    monkeypatch.setattr(main_mod, "_notify_expiring_users", _notify)
    _run_loop(main_mod._expiry_sweeper_loop)
    assert len(order) >= 4, f"the sweeper never ticked: {order}"
    # Every tick is render-then-notify, in that order. (Truncate to
    # an even length: a cancellation landing between the two halves
    # of a tick would leave a dangling final "render".)
    even = order[: len(order) // 2 * 2]
    assert even[0::2] == ["render"] * (len(even) // 2)
    assert even[1::2] == ["notify"] * (len(even) // 2)


def test_sweeper_loop_survives_render_failure(db, monkeypatch):
    """A failing re-render is logged and notified (not raised): the
    loop keeps ticking, and the admin still gets the failure
    notification."""
    monkeypatch.setattr(main_mod, "EXPIRY_SWEEPER_INTERVAL_SECONDS", 0.01)
    ticks = {"render": 0, "notify_fail": 0, "notify_exp": 0}

    def _render(db_session):
        ticks["render"] += 1
        return ["xray render failed"]

    def _notify_fail(db_session, errors):
        ticks["notify_fail"] += 1

    def _notify_exp(db_session):
        ticks["notify_exp"] += 1
        return 0

    monkeypatch.setattr(main_mod, "rerender_configs", _render)
    monkeypatch.setattr(main_mod, "_notify_rerender_failure", _notify_fail)
    monkeypatch.setattr(main_mod, "_notify_expiring_users", _notify_exp)
    _run_loop(main_mod._expiry_sweeper_loop)
    assert ticks["render"] >= 2
    assert ticks["notify_fail"] == ticks["render"]
    assert ticks["notify_exp"] == ticks["render"]
