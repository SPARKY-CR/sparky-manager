"""Traffic charts — inline SVG generated server-side (Phase 3).

Offline-first: no chart CDN, no JS library — the dashboard and user
detail pages get a plain ``<svg>`` built here. Days with no recorded
traffic show a zero-height bar, never an invented value.
"""

from __future__ import annotations

import html
from datetime import date, timedelta
from typing import Iterable

CHART_DAYS = 14
CHART_COLOR = "#8b7cff"  # Obsidian primary violet
CHART_WIDTH = 640
CHART_HEIGHT = 160
CHART_BAR_GAP = 6


def daily_traffic_series(
    rows: Iterable[tuple[date, int]],
    days: int = CHART_DAYS,
    today: date | None = None,
) -> list[tuple[date, int]]:
    """Zero-filled ``[(day, total_bytes)]`` for the last ``days`` days.

    ``rows`` is ``(day, bytes)`` pairs (e.g. summed ``traffic_daily``
    rows); days with no row get 0. The series ends at ``today``
    (default: the current local date) and is oldest-first.
    """
    today = today or date.today()
    by_day: dict[date, int] = {}
    for day, total in rows:
        by_day[day] = by_day.get(day, 0) + int(total)
    first = today - timedelta(days=days - 1)
    return [
        (first + timedelta(days=i), by_day.get(first + timedelta(days=i), 0))
        for i in range(days)
    ]


def _format_bytes(n: int) -> str:
    """Short human size for chart labels (``"1.5 GB"``, ``"850 MB"``)."""
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # unreachable; keeps type checkers calm


def traffic_chart_svg(
    series: list[tuple[date, int]],
    *,
    width: int = CHART_WIDTH,
    height: int = CHART_HEIGHT,
    color: str = CHART_COLOR,
) -> str:
    """Inline SVG bar chart for a ``daily_traffic_series`` result.

    One bar per day, height proportional to the series maximum (a
    zero-max series renders an empty chart with a baseline, not a
    crash). Every bar carries a ``<title>`` with the exact day + total
    (hover tooltip, no JS). Labels are day/month numbers; values are
    ints and dates, so no user-controlled text reaches the markup —
    the day strings are still escaped out of caution.
    """
    if not series:
        return ""
    max_value = max(total for _day, total in series)
    pad_left, pad_right, pad_top, pad_bottom = 8, 8, 22, 24
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    n = len(series)
    bar_w = max(4.0, (plot_w - CHART_BAR_GAP * (n - 1)) / n)

    parts: list[str] = [
        f'<svg class="chart-svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" '
        f'aria-label="traffic chart">'
    ]
    # Max-value label (top-left) and baseline.
    parts.append(
        f'<text x="{pad_left}" y="14" class="chart-max" dir="ltr">'
        f"{html.escape(_format_bytes(max_value))}</text>"
    )
    baseline_y = pad_top + plot_h
    parts.append(
        f'<line x1="{pad_left}" y1="{baseline_y}" '
        f'x2="{width - pad_right}" y2="{baseline_y}" class="chart-base" />'
    )
    for i, (day, total) in enumerate(series):
        x = pad_left + i * (bar_w + CHART_BAR_GAP)
        bar_h = (total / max_value * plot_h) if max_value > 0 else 0
        y = pad_top + plot_h - bar_h
        label = html.escape(day.strftime("%m-%d"))
        tip = html.escape(f"{day.isoformat()}: {_format_bytes(total)}")
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
            f'height="{max(bar_h, 0):.1f}" rx="2" fill="{color}">'
            f"<title>{tip}</title></rect>"
        )
        # Day label under every bar (sparse: every 2nd on narrow charts).
        if n <= 14 or i % 2 == 0:
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{height - 6}" '
                f'class="chart-label" text-anchor="middle" dir="ltr">'
                f"{label}</text>"
            )
    parts.append("</svg>")
    return "".join(parts)


__all__ = [
    "CHART_DAYS",
    "CHART_COLOR",
    "CHART_WIDTH",
    "CHART_HEIGHT",
    "daily_traffic_series",
    "traffic_chart_svg",
]
