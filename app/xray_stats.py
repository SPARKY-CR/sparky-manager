"""Xray Stats API client (gRPC) — per-user traffic collection.

This is the F1 fix (Phase 1 audit §7): before it, the traffic sync
loop only read WireGuard counters, so traffic limits never triggered
for Xray users and charts showed WireGuard only. :func:`sync_traffic`
in :mod:`app.traffic` already accepted ``xray_stats`` deltas — this
module is what feeds it.

How it works
------------
Xray's ``StatsService`` (``xray.app.stats.command``) answers
``QueryStats`` with the cumulative counters for every stat name
matching a pattern. The panel renders every Xray client with an
``email`` (``user-<id>@sparky.local`` — see :func:`app.xray.client_email`),
so one query with pattern ``user>>>traffic>>>`` returns, per user::

    user>>>user-12@sparky.local>>>traffic>>>uplink   -> 123456
    user>>>user-12@sparky.local>>>traffic>>>downlink -> 789012

:func:`collect_xray_deltas` turns those cumulative counters into
per-tick deltas (same first-sighting-baselines rule as the
WireGuard path in :mod:`app.traffic`: a restart can only under-count
one tick, never double-count) and returns them keyed by panel user
id, ready for ``sync_traffic``.

No generated stubs
------------------
The two protobuf messages are tiny (``QueryStatsRequest``:
``pattern`` string + ``reset`` bool; ``QueryStatsResponse``:
repeated ``Stat{name, value}``), so the wire codec is hand-rolled
here (~60 lines) instead of vendoring Xray's ``.proto`` files and
depending on ``grpcio-tools`` at build time. ``grpcio`` itself is a
runtime dependency (pinned in ``requirements.txt``); the call goes
through ``channel.unary_unary`` with identity serializers, i.e. raw
bytes in and out.

Fail-soft, always
-----------------
Every public function here returns an empty result on ANY failure
(grpcio missing, API down, timeout, malformed response) and never
raises into the sync loop — a dead Stats API means "no Xray update
this tick", never a crashed panel or an invented number. The only
state is the in-memory previous snapshot (``_last``); a panel
restart re-baselines, exactly like the WireGuard path.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from app.xray import API_LISTEN, API_PORT, parse_user_email

logger = logging.getLogger(__name__)

try:
    import grpc  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - grpcio is a pinned dependency
    grpc = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_TIMEOUT",
    "USER_TRAFFIC_PATTERN",
    "collect_xray_deltas",
    "decode_query_stats_response",
    "encode_query_stats_request",
    "parse_traffic_stat_name",
    "query_stats",
    "reset_snapshots",
]

#: gRPC method for Xray's StatsService (xray-core
#: ``app/stats/command/command.proto``).
_QUERY_STATS_METHOD = "/xray.app.stats.command.StatsService/QueryStats"

#: One pattern matches every user's uplink + downlink counters
#: (Xray matches the pattern as a regex against stat names).
USER_TRAFFIC_PATTERN = "user>>>traffic>>>"

#: Seconds to wait for the Stats API per tick (the sync loop ticks
#: every 60 s; a hung API must never stall the panel).
DEFAULT_TIMEOUT = 5.0

# Previous cumulative snapshots, used to turn Xray's cumulative
# counters into deltas. In-process only (see module docstring).
_last: dict[str, int] = {}


# ---------------------------------------------------------------------------
# Protobuf wire codec (hand-rolled; see module docstring)
# ---------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    """A non-negative int as a protobuf varint."""
    if value < 0:
        raise ValueError("varint value must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Read a varint at ``pos``; returns ``(value, new_pos)``.

    Raises ``ValueError`` on truncation or on a varint longer than
    10 bytes (the 64-bit maximum).
    """
    result = 0
    shift = 0
    while True:
        if pos >= len(data) or shift >= 70:
            raise ValueError("truncated or oversized varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def encode_query_stats_request(pattern: str, reset: bool = False) -> bytes:
    """Encode a ``QueryStatsRequest`` (field 1 ``pattern``, field 2 ``reset``)."""
    encoded = pattern.encode("utf-8")
    out = bytearray(b"\x0a")  # field 1, wire type 2 (length-delimited)
    out += _encode_varint(len(encoded))
    out += encoded
    if reset:
        out += b"\x10\x01"  # field 2, wire type 0 (varint), value 1
    return bytes(out)


def _decode_stat(data: bytes) -> tuple[str, int] | None:
    """Decode one embedded ``Stat`` message; ``None`` when malformed."""
    name: Optional[str] = None
    value: Optional[int] = None
    pos = 0
    try:
        while pos < len(data):
            tag, pos = _decode_varint(data, pos)
            field = tag >> 3
            wire = tag & 0x07
            if wire == 0:  # varint
                number, pos = _decode_varint(data, pos)
                if field == 2:
                    value = number
            elif wire == 2:  # length-delimited
                length, pos = _decode_varint(data, pos)
                end = pos + length
                if end > len(data):
                    return None
                if field == 1:
                    name = data[pos:end].decode("utf-8", "replace")
                pos = end
            else:  # groups (3/4) and fixed32/fixed64 (1/5) never
                # occur in a Stat — a tag claiming one is corrupt.
                return None
    except ValueError:
        return None
    if name is None or value is None:
        return None
    return name, value


def decode_query_stats_response(data: bytes) -> dict[str, int]:
    """Decode a ``QueryStatsResponse`` into ``{stat_name: value}``.

    Malformed trailing bytes stop the parse; stats decoded before
    the corruption are kept (each Stat is independent). Never raises:
    garbage in means ``{}`` (or a partial map) out.
    """
    result: dict[str, int] = {}
    if not isinstance(data, (bytes, bytearray)):
        return result
    data = bytes(data)
    pos = 0
    try:
        while pos < len(data):
            tag, pos = _decode_varint(data, pos)
            field = tag >> 3
            wire = tag & 0x07
            if wire == 0:  # varint field: skip
                _, pos = _decode_varint(data, pos)
            elif wire == 2:  # length-delimited field
                length, pos = _decode_varint(data, pos)
                end = pos + length
                if end > len(data):
                    break
                if field == 1:  # repeated Stat
                    stat = _decode_stat(data[pos:end])
                    if stat is not None:
                        result[stat[0]] = stat[1]
                pos = end
            elif wire == 5:  # fixed32: skip 4 bytes
                pos += 4
                if pos > len(data):
                    break
            elif wire == 1:  # fixed64: skip 8 bytes
                pos += 8
                if pos > len(data):
                    break
            else:  # groups are not used by this message: corrupt
                break
    except ValueError:
        pass
    return result


# ---------------------------------------------------------------------------
# Stat-name parsing
# ---------------------------------------------------------------------------


def parse_traffic_stat_name(name: str) -> tuple[Optional[int], Optional[str]]:
    """Parse ``user>>><email>>>>traffic>>>(uplink|downlink)``.

    Returns ``(user_id, direction)``; anything else — another stat
    family, a foreign email, a malformed name — returns ``(None,
    None)`` and is never attributed. Never raises.
    """
    if not isinstance(name, str):
        return None, None
    parts = name.split(">>>")
    if len(parts) != 4:
        return None, None
    if parts[0] != "user" or parts[2] != "traffic":
        return None, None
    if parts[3] not in ("uplink", "downlink"):
        return None, None
    user_id = parse_user_email(parts[1])
    if user_id is None:
        return None, None
    return user_id, parts[3]


# ---------------------------------------------------------------------------
# gRPC query + delta collection
# ---------------------------------------------------------------------------


def _default_channel(address: str):  # type: ignore[no-untyped-def]
    """An insecure channel to the loopback Stats API (or ``None``)."""
    if grpc is None:
        return None
    return grpc.insecure_channel(address)


def query_stats(
    address: Optional[str] = None,
    pattern: str = USER_TRAFFIC_PATTERN,
    timeout: float = DEFAULT_TIMEOUT,
    channel_factory: Optional[Callable[[str], object]] = None,
) -> dict[str, int]:
    """Query the Stats API; ``{stat_name: cumulative_value}``.

    ``address`` defaults to the loopback API the renderer configures
    (``127.0.0.1:10085``). ``channel_factory`` exists for tests: it
    receives the address and must return an object with
    ``unary_unary(method, request_serializer, response_deserializer)``
    (the real one is ``grpc.insecure_channel``). Any failure —
    grpcio missing, connection refused, timeout, malformed response —
    logs a warning and returns ``{}``. Never raises.
    """
    if address is None:
        address = f"{API_LISTEN}:{API_PORT}"
    factory = channel_factory or _default_channel
    channel = None
    try:
        channel = factory(address)
        if channel is None:
            return {}
        stub = channel.unary_unary(
            _QUERY_STATS_METHOD,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda payload: payload,
        )
        response = stub(
            encode_query_stats_request(pattern), timeout=timeout
        )
        return decode_query_stats_response(response)
    except Exception as exc:  # noqa: BLE001 — fail soft by design
        logger.warning("Xray Stats API query failed: %s", exc)
        return {}
    finally:
        close = getattr(channel, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001 — close must never raise
                pass


def collect_xray_deltas(
    query_fn: Optional[Callable[[], dict[str, int]]] = None,
    *,
    address: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[int, tuple[int, int]]:
    """Poll the Stats API and return per-user traffic *deltas*.

    Returns ``{user_id: (up_bytes, down_bytes)}`` since the last
    call, ready to pass as ``xray_stats=...`` to
    :func:`app.traffic.sync_traffic`. ``query_fn`` injects the raw
    cumulative map for tests (default: a live :func:`query_stats`
    call). Rules, mirroring the WireGuard path: the first sighting
    of a counter only establishes the baseline (delta 0); a counter
    that went *backwards* (Xray restarted) re-baselines with delta
    0; users with a zero delta are omitted. Never raises — any
    failure means ``{}`` (no Xray update this tick).
    """
    try:
        if query_fn is None:
            current = query_stats(address=address, timeout=timeout)
        else:
            current = query_fn()
    except Exception as exc:  # noqa: BLE001 — fail soft by design
        logger.warning("Xray stats collection failed: %s", exc)
        return {}
    if not isinstance(current, dict):
        return {}
    deltas: dict[int, list[int]] = {}
    for name, value in current.items():
        user_id, direction = parse_traffic_stat_name(name)
        if user_id is None or direction is None:
            continue
        try:
            value = int(value)
        except (TypeError, ValueError):
            continue
        if value < 0:
            continue
        previous = _last.get(name)
        _last[name] = value
        if previous is None or value < previous:
            continue  # first sighting / Xray restart: baseline only
        delta = value - previous
        if delta == 0:
            continue
        entry = deltas.setdefault(user_id, [0, 0])
        if direction == "uplink":
            entry[0] += delta
        else:
            entry[1] += delta
    return {uid: (up, down) for uid, (up, down) in deltas.items()}


def reset_snapshots() -> None:
    """Clear the previous-snapshot state (tests; panel restart)."""
    _last.clear()
