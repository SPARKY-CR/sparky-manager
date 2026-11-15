"""Phase 6 (professional upgrade) performance regression tests.

The Phase 1 audit (§6, Q6) found N+1 query patterns on the dashboard
(full user table loaded 3 times, one COUNT per inbound) and the users
page, plus an unbounded ``traffic_daily`` scan in the chart helper.
These tests lock in the fixes with a SQL statement counter: they
assert the statement count does NOT grow with the number of inbounds
/ users, which is the property that makes an N+1 a regression rather
than a one-off count.

Static asset sizes are bounded too (a guard against accidental
bloat — the panel is offline-first, every byte ships to the admin).
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import event

from app import webcommon as webcommon_mod
from app.models import Inbound, TrafficDaily, User

STATIC_DIR = Path(__file__).resolve().parent.parent / "app" / "static"


@pytest.fixture()
def statement_counter(db_engine):
    """Record every SQL statement issued on the test engine.

    Returns a list of statement strings; the listener is removed
    after the test. ``before_cursor_execute`` sees SELECT/INSERT/
    UPDATE/DELETE (COMMITs go through the DBAPI connection, not the
    cursor, so they are not counted — this measures queries, which
    is what N+1 is about).
    """
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):
        statements.append(str(statement))

    event.listen(db_engine, "before_cursor_execute", _record)
    yield statements
    event.remove(db_engine, "before_cursor_execute", _record)


def _count_matching(statements, *needles):
    # SQLAlchemy renders count(*) in lowercase; match case-insensitively.
    return sum(
        1 for s in statements
        if all(n.lower() in s.lower() for n in needles)
    )


def _add_inbounds(db, count, start_port=30000):
    for i in range(count):
        db.add(Inbound(
            tag=f"perf-extra-{i}",
            core="xray",
            protocol="vless",
            port=start_port + i,
            stream_json='{"network": "tcp", "security": "none"}',
        ))
    db.commit()


# ---------------------------------------------------------------------------
# Dashboard — no per-inbound queries, one user load
# ---------------------------------------------------------------------------

def test_dashboard_client_counts_are_one_query(
    authed_client, db, seeded, statement_counter
):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    # The per-inbound client counts must come from ONE grouped query,
    # not one COUNT per inbound (11 seeded inbounds would be 11).
    counts = _count_matching(
        statement_counter, "COUNT", "clients")
    assert counts == 1, (
        f"expected 1 grouped client-count query, got {counts}: "
        f"{[s for s in statement_counter if 'COUNT' in s][:3]}")


def test_dashboard_query_count_independent_of_inbound_count(
    authed_client, db, seeded, statement_counter
):
    authed_client.get("/dashboard")
    before = len(statement_counter)
    _add_inbounds(db, 10)  # 11 -> 21 inbounds
    del statement_counter[:]  # clear the seeding INSERTs
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    after = len(statement_counter)
    assert after == before, (
        f"dashboard issued {before} statements with 11 inbounds but "
        f"{after} with 21 — a per-inbound query remains")


def test_dashboard_loads_users_once(
    authed_client, db, seeded, statement_counter
):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    # One full user load (active + traffic + total all derive from
    # it) plus the recent-10 list — never the old three full loads.
    # The recent-10 query also selects FROM users (with LIMIT);
    # count statements WITHOUT a LIMIT clause as full loads.
    full_loads = sum(
        1 for s in statement_counter
        if "FROM users" in s and "LIMIT" not in s and "COUNT" not in s
    )
    assert full_loads == 1, (
        f"expected 1 full user load, got {full_loads}")


# ---------------------------------------------------------------------------
# Inbounds page — same grouped count
# ---------------------------------------------------------------------------

def test_inbounds_client_counts_are_one_query(
    authed_client, db, seeded, statement_counter
):
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    counts = _count_matching(
        statement_counter, "COUNT", "clients")
    assert counts == 1, f"expected 1 grouped client-count query, got {counts}"


def test_inbounds_query_count_independent_of_inbound_count(
    authed_client, db, seeded, statement_counter
):
    authed_client.get("/inbounds")
    before = len(statement_counter)
    _add_inbounds(db, 10)
    del statement_counter[:]  # clear the seeding INSERTs
    resp = authed_client.get("/inbounds")
    assert resp.status_code == 200
    assert len(statement_counter) == before, (
        f"inbounds page issued {before} statements with 11 inbounds "
        f"but {len(statement_counter)} with 21")


# ---------------------------------------------------------------------------
# Users page — one user load
# ---------------------------------------------------------------------------

def test_users_page_loads_users_once(
    authed_client, db, seeded, statement_counter
):
    resp = authed_client.get("/users")
    assert resp.status_code == 200
    # The expired-ids set used to re-query the whole user table; it
    # now derives from the same load as the list itself.
    full_loads = sum(
        1 for s in statement_counter
        if "FROM users" in s and "LIMIT" not in s and "COUNT" not in s
    )
    assert full_loads == 1, (
        f"expected 1 full user load, got {full_loads}")


# ---------------------------------------------------------------------------
# Traffic chart — bounded date range, not a full-table scan
# ---------------------------------------------------------------------------

def test_traffic_chart_queries_only_recent_days(db, seeded, statement_counter):
    alice = seeded["users"]["alice"]
    today = date.today()
    # 60 days of history for one user: the chart only shows 14.
    for i in range(60):
        db.add(TrafficDaily(
            user_id=alice.id,
            date=today - timedelta(days=i),
            up_bytes=100,
            down_bytes=100,
        ))
    db.commit()
    del statement_counter[:]
    svg, total = webcommon_mod._traffic_chart(db)
    assert total == 14 * 200  # 14 days x (100 up + 100 down)
    assert svg
    chart_statements = [
        s for s in statement_counter if "traffic_daily" in s
    ]
    assert len(chart_statements) == 1
    # The query must filter by date at the DB level (not load 60
    # rows and discard 46 in Python).
    assert "traffic_daily.date >=" in chart_statements[0] or (
        "date" in chart_statements[0] and ">=" in chart_statements[0]
    ), chart_statements[0]


def test_traffic_chart_old_rows_do_not_change_series(db, seeded):
    alice = seeded["users"]["alice"]
    today = date.today()
    db.add(TrafficDaily(
        user_id=alice.id, date=today, up_bytes=1000, down_bytes=2000))
    db.commit()
    _svg, total_before = webcommon_mod._traffic_chart(db)
    # A year of old history must not change the 14-day total.
    for i in range(14, 365):
        db.add(TrafficDaily(
            user_id=alice.id,
            date=today - timedelta(days=i),
            up_bytes=10_000,
            down_bytes=10_000,
        ))
    db.commit()
    _svg, total_after = webcommon_mod._traffic_chart(db)
    assert total_after == total_before == 3000


# ---------------------------------------------------------------------------
# Static assets — bounded sizes (offline-first: every byte ships)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name, max_bytes", [
    ("style.css", 100_000),
    ("app.js", 50_000),
])
def test_static_asset_size_bounded(name, max_bytes):
    path = STATIC_DIR / name
    assert path.exists(), f"missing static asset: {name}"
    assert path.stat().st_size <= max_bytes, (
        f"{name} is {path.stat().st_size} bytes (bound {max_bytes}) — "
        "the panel ships every byte to the admin; keep assets small")


def test_font_files_bounded():
    fonts = list((STATIC_DIR / "fonts").glob("*.woff2"))
    assert fonts, "no bundled fonts found"
    total = sum(f.stat().st_size for f in fonts)
    assert total <= 500_000, f"bundled fonts total {total} bytes"
