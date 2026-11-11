"""Traffic accounting — pure parsers + delta sync, no grpc dependency.

Sources (DESIGN.md §6.4):
- Xray: gRPC Stats API (queried by the caller — this module only
  *applies* the per-user deltas it is handed, see :func:`sync_traffic`).
- WireGuard: ``wg show wg0 transfer`` / ``latest-handshakes``.
- sing-box: nftables counters, one per dedicated user port.

Honesty rule, applied everywhere: a missing source means *no update*,
never an invented number. Shared-port sing-box inbounds cannot be
attributed per user, so the UI must say "traffic: n/a (shared port)"
rather than guess — this module never fabricates attribution.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from app.models import TrafficDaily, User

# A peer counts as "online" if it had traffic / a handshake within this
# window (WireGuard: latest handshake < 3 min, DESIGN.md §6.4).
ONLINE_WINDOW_SECONDS = 180

# ---------------------------------------------------------------------------
# WireGuard parsers (``wg show`` output)
# ---------------------------------------------------------------------------

_WG_TRANSFER_RE = re.compile(r"^(\S+)\s+(\d+)\s+(\d+)\s*$")
_WG_HANDSHAKE_RE = re.compile(r"^(\S+)\s+(\d+)\s*$")


def parse_wg_transfer(text: str | None) -> dict[str, tuple[int, int]]:
    """Parse ``wg show <iface> transfer`` output.

    Each line is ``<pubkey>\\t<received>\\t<sent>`` (tab- or space-
    separated). Returns ``{pubkey: (up, down)}`` where *up* is bytes
    the peer sent to the server (its upload) and *down* is bytes the
    server sent to the peer (its download). Malformed lines and empty
    input are skipped silently (``{}``).
    """
    result: dict[str, tuple[int, int]] = {}
    for line in (text or "").splitlines():
        match = _WG_TRANSFER_RE.match(line.strip())
        if not match:
            continue
        pubkey, received, sent = match.groups()
        result[pubkey] = (int(received), int(sent))
    return result


def parse_wg_handshakes(text: str | None) -> dict[str, Optional[int]]:
    """Parse ``wg show <iface> latest-handshakes`` output.

    Each line is ``<pubkey>\\t<seconds-ago>``; ``0`` means "never had a
    handshake". Returns ``{pubkey: seconds_ago or None}``. Empty or
    malformed input yields ``{}``.
    """
    result: dict[str, Optional[int]] = {}
    for line in (text or "").splitlines():
        match = _WG_HANDSHAKE_RE.match(line.strip())
        if not match:
            continue
        pubkey, seconds = match.groups()
        seconds_ago = int(seconds)
        result[pubkey] = seconds_ago if seconds_ago > 0 else None
    return result


# ---------------------------------------------------------------------------
# nftables parser (sing-box per-port counters)
# ---------------------------------------------------------------------------

_PORT_RE = re.compile(r"\b[ds]port\s+(\d+)\b")
_COUNTER_RE = re.compile(r"\bcounter\s+packets\s+(\d+)\s+bytes\s+(\d+)\b")


def parse_nft_counters(text: str | None) -> dict[int, tuple[int, int]]:
    """Best-effort parse of ``nft list ruleset`` output.

    A rule line mentioning ``dport <N>`` (or ``sport``) followed by —
    or on the same line as — ``counter packets P bytes B`` attributes
    that counter to port ``N``. Counters with no port seen yet are
    ignored (no attribution is invented). Empty input yields ``{}``.
    Later rules for the same port overwrite earlier ones: nftables
    counters are cumulative snapshots, not deltas.
    """
    result: dict[int, tuple[int, int]] = {}
    last_port: Optional[int] = None
    for line in (text or "").splitlines():
        port_match = _PORT_RE.search(line)
        if port_match:
            last_port = int(port_match.group(1))
        counter_match = _COUNTER_RE.search(line)
        if counter_match and last_port is not None:
            packets, byte_count = counter_match.groups()
            result[last_port] = (int(packets), int(byte_count))
    return result


# ---------------------------------------------------------------------------
# Delta sync
# ---------------------------------------------------------------------------

# Previous cumulative snapshots, used to turn ``wg show transfer`` /
# nftables counters into deltas. In-process only: a panel restart
# re-baselines (first tick after restart applies nothing), which is
# safe — it can only under-count one tick, never double-count.
_last_wg: dict[str, tuple[int, int]] = {}
_last_nft: dict[int, int] = {}


def sync_traffic(
    db: DbSession,
    *,
    xray_stats: Optional[dict[int, tuple[int, int]]] = None,
    wg_text: Optional[str] = None,
    nft_text: Optional[str] = None,
    wg_pubkey_to_user_id: Optional[dict[str, int]] = None,
    nft_port_to_user_id: Optional[dict[int, int]] = None,
) -> dict:
    """Apply traffic *deltas* to users and today's :class:`TrafficDaily`.

    ``xray_stats`` maps ``user_id -> (up_bytes, down_bytes)`` deltas
    since the last poll (the caller gets them from Xray's gRPC Stats
    API). ``wg_text`` / ``nft_text`` are raw ``wg show`` / ``nft list``
    outputs; they are attributed only through the optional
    ``wg_pubkey_to_user_id`` / ``nft_port_to_user_id`` maps — without a
    map, that source is parsed and ignored, never guessed at.

    Only *deltas* are added: ``users.traffic_used_bytes`` is incremented
    and today's ``traffic_daily`` row is upserted. Nothing is ever
    overwritten, so a panel restart cannot double-count or lose usage.
    ``xray_stats`` deltas are applied directly. ``wg show transfer``
    and nftables counters are *cumulative*, so this module keeps the
    previous snapshot in memory and applies only the difference; the
    first sighting of a peer/port only establishes the baseline.
    Unknown user ids and negative deltas are skipped. Commits.

    Returns a summary: ``{"users_updated": {user_id: (up, down)},
    "total_up": ..., "total_down": ...}`` (totals are the applied deltas).
    """
    deltas: dict[int, list[int]] = {}

    def _add(user_id: int, up: int, down: int) -> None:
        if up < 0 or down < 0:
            return
        entry = deltas.setdefault(user_id, [0, 0])
        entry[0] += up
        entry[1] += down

    for user_id, (up, down) in (xray_stats or {}).items():
        _add(int(user_id), int(up), int(down))

    if wg_text is not None and wg_pubkey_to_user_id:
        # ``wg show transfer`` counters are cumulative: diff against the
        # previous snapshot (first sighting only establishes the baseline
        # and applies nothing — a restart must never double-count).
        current = parse_wg_transfer(wg_text)
        for pubkey, (up, down) in current.items():
            user_id = wg_pubkey_to_user_id.get(pubkey)
            previous = _last_wg.get(pubkey)
            _last_wg[pubkey] = (up, down)
            if user_id is not None and previous is not None:
                _add(int(user_id), up - previous[0], down - previous[1])

    if nft_text is not None and nft_port_to_user_id:
        # Same cumulative-snapshot rule for nftables counters. The byte
        # counter is the traffic measure; packets are informational only.
        current = parse_nft_counters(nft_text)
        for port, (_packets, byte_count) in current.items():
            user_id = nft_port_to_user_id.get(port)
            previous = _last_nft.get(port)
            _last_nft[port] = byte_count
            if user_id is not None and previous is not None:
                # nft gives one combined byte counter per port: attribute
                # the whole delta to download (direction is not tracked
                # by a plain counter rule).
                _add(int(user_id), 0, byte_count - previous)

    today = date.today()
    applied: dict[int, tuple[int, int]] = {}
    total_up = total_down = 0
    for user_id, (up, down) in deltas.items():
        user = db.get(User, user_id)
        if user is None or (up == 0 and down == 0):
            continue
        user.traffic_used_bytes = (user.traffic_used_bytes or 0) + up + down
        row = (
            db.query(TrafficDaily)
            .filter(
                TrafficDaily.user_id == user_id, TrafficDaily.date == today
            )
            .first()
        )
        if row is None:
            row = TrafficDaily(
                user_id=user_id, date=today, up_bytes=up, down_bytes=down
            )
            db.add(row)
        else:
            row.up_bytes = (row.up_bytes or 0) + up
            row.down_bytes = (row.down_bytes or 0) + down
        applied[user_id] = (up, down)
        total_up += up
        total_down += down
    db.commit()
    return {
        "users_updated": applied,
        "total_up": total_up,
        "total_down": total_down,
    }


# ---------------------------------------------------------------------------
# Online status / optional gRPC
# ---------------------------------------------------------------------------


def is_online(user: User, last_seen_seconds: Optional[int]) -> bool:
    """True if an enabled user had activity within the online window.

    ``last_seen_seconds`` is seconds since the last traffic delta /
    WireGuard handshake (``None`` = never seen). sing-box has no live
    sessions API, so its users only get "last seen" from traffic deltas
    — never a faked "online".
    """
    if not user.enabled:
        return False
    if last_seen_seconds is None:
        return False
    return 0 <= last_seen_seconds <= ONLINE_WINDOW_SECONDS


def try_import_grpc_stats():
    """Best-effort import of ``grpc`` for the Xray Stats API client.

    Returns the ``grpc`` module when grpcio is installed, otherwise
    ``{}``. Never raises — callers must check the return value and
    skip Xray gRPC polling when it is falsy::

        grpc = try_import_grpc_stats()
        if not grpc:
            return  # no Xray stats this tick; nothing is invented
    """
    try:
        import grpc  # type: ignore[import-not-found]
    except ImportError:
        return {}
    return grpc


__all__ = [
    "ONLINE_WINDOW_SECONDS",
    "parse_wg_transfer",
    "parse_wg_handshakes",
    "parse_nft_counters",
    "sync_traffic",
    "is_online",
    "try_import_grpc_stats",
]
