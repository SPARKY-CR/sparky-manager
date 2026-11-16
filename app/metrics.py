"""Prometheus ``/metrics`` (Phase C item 21).

Hand-rolled Prometheus exposition format (``text/plain;
version=0.0.4``) — no ``prometheus_client`` dependency: the format
is one line per sample (``name{labels} value``), the project
already hand-rolls its gRPC codec to stay lean, and a client
library would add a dependency + a global registry for ~10 gauges.
The route (``GET /metrics`` in :mod:`app.routes.phase_b`) is
admin-gated (admin session or an API token with ``status:read``).

Privacy: aggregate counts only. No per-user data — no names,
tokens, credentials or IPs — ever appears in the output (a
scraper is a lower-trust reader than the admin UI, and a leaked
metrics endpoint must not leak users).
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Inbound, IpBan, TrafficDaily, User, user_is_usable

__all__ = ["escape_label_value", "render_metrics"]

#: The content type the route serves (Prometheus exposition format).
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def escape_label_value(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote,
    newline — the three characters the exposition format requires
    escaped, in that order so the backslash escape doesn't
    double-escape the others)."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _gauge(
    lines: list[str], name: str, help_text: str, value: Any
) -> None:
    """Append a gauge (``# HELP`` + ``# TYPE`` + sample)."""
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name} {value}")


def _gauge_labeled(
    lines: list[str],
    name: str,
    help_text: str,
    samples: list[tuple[dict[str, str], Any]],
) -> None:
    """Append a labeled gauge (one ``# HELP``/``# TYPE`` pair, one
    sample line per label set)."""
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    for labels, value in samples:
        rendered = ",".join(
            f'{key}="{escape_label_value(val)}"'
            for key, val in labels.items()
        )
        lines.append(f"{name}{{{rendered}}} {value}")


def render_metrics(
    db: Session,
    *,
    core_states: Optional[dict[str, str]] = None,
    today: Optional[date] = None,
    now: Optional[datetime] = None,
) -> str:
    """Render the full metrics exposition for the current DB state.

    ``core_states`` is the ``{service key: "running" | "stopped" |
    "unknown"}`` map from :func:`app.system_status.service_states`
    (injected so tests don't need systemctl; ``None`` omits the
    ``sparky_core_up`` family). ``today`` / ``now`` exist for tests
    (default: the real current date / UTC time).
    """
    lines: list[str] = []
    users = db.query(User).all()
    _gauge(
        lines,
        "sparky_users_total",
        "Total users in the panel.",
        len(users),
    )
    _gauge(
        lines,
        "sparky_users_enabled",
        "Users with the enabled flag set.",
        sum(1 for u in users if u.enabled),
    )
    _gauge(
        lines,
        "sparky_users_active",
        "Usable users (enabled, not expired, under quota).",
        sum(1 for u in users if user_is_usable(u, now=now)),
    )
    _gauge(
        lines,
        "sparky_inbounds_total",
        "Total inbounds in the panel.",
        db.query(Inbound).count(),
    )
    by_protocol = (
        db.query(Inbound.protocol, func.count(Inbound.id))
        .group_by(Inbound.protocol)
        .order_by(Inbound.protocol)
        .all()
    )
    _gauge_labeled(
        lines,
        "sparky_inbounds_by_protocol",
        "Inbounds by protocol.",
        [
            ({"protocol": protocol}, count)
            for protocol, count in by_protocol
        ],
    )
    _gauge(
        lines,
        "sparky_traffic_used_bytes_total",
        "Total traffic used by all users, in bytes.",
        sum(u.traffic_used_bytes or 0 for u in users),
    )
    today = today or date.today()
    today_totals = (
        db.query(
            func.coalesce(func.sum(TrafficDaily.up_bytes), 0),
            func.coalesce(func.sum(TrafficDaily.down_bytes), 0),
        )
        .filter(TrafficDaily.date == today)
        .one()
    )
    _gauge_labeled(
        lines,
        "sparky_traffic_today_bytes",
        "Traffic used today, in bytes, by direction.",
        [
            ({"direction": "up"}, today_totals[0]),
            ({"direction": "down"}, today_totals[1]),
        ],
    )
    if core_states is not None:
        _gauge_labeled(
            lines,
            "sparky_core_up",
            "Whether a managed core/service is running (1) or not (0).",
            [
                ({"unit": key}, 1 if state == "running" else 0)
                for key, state in sorted(core_states.items())
            ],
        )
    now = now or datetime.now(timezone.utc)
    _gauge(
        lines,
        "sparky_ip_bans_active",
        "Active IP-limit bans (fail2ban jail sparky-ipl).",
        db.query(IpBan).filter(IpBan.expires_at > now).count(),
    )
    return "\n".join(lines) + "\n"
