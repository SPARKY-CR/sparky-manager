"""Re-render lock tests (Phase 5, item 5).

``rerender_configs`` is a sync function called from the expiry
sweeper, admin POSTs (FastAPI threadpool) and the Telegram bot
polling thread. Concurrent renders serialize on a ``threading.RLock``
(an ``asyncio.Lock`` cannot be acquired from sync code and cannot
serialize threads); the lock is re-entrant so a render that itself
triggers a re-render cannot deadlock.
"""
from __future__ import annotations

import threading
import time

from app import main as main_mod


def test_concurrent_rerenders_serialize(db, monkeypatch):
    """Two threads rendering at once: the second waits (max 1 inside)."""
    state = {"active": 0, "max_active": 0}
    guard = threading.Lock()

    def _slow_impl(session):
        with guard:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
        time.sleep(0.2)
        with guard:
            state["active"] -= 1
        return []

    monkeypatch.setattr(main_mod, "_rerender_configs_impl", _slow_impl)
    barrier = threading.Barrier(2)
    results: list[list[str]] = []

    def _render():
        barrier.wait(timeout=5)
        results.append(main_mod.rerender_configs(db))

    threads = [threading.Thread(target=_render) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive(), "re-render thread hung"
    assert results == [[], []]
    assert state["max_active"] == 1


def test_rerender_is_reentrant(db, monkeypatch):
    """A render that itself calls rerender_configs does not deadlock
    (RLock, not a plain Lock)."""
    entered = {"count": 0}

    def _reentrant_impl(session):
        entered["count"] += 1
        if entered["count"] == 1:
            # Nested call: must acquire the same lock again.
            main_mod.rerender_configs(session)
        return []

    monkeypatch.setattr(main_mod, "_rerender_configs_impl", _reentrant_impl)
    done: list[list[str]] = []
    thread = threading.Thread(
        target=lambda: done.append(main_mod.rerender_configs(db))
    )
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive(), "nested re-render deadlocked"
    assert done == [[]]
    assert entered["count"] == 2
