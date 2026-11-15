"""Client-eye self-check (best-panel program, Phase A item 7;
Mistgate's best idea).

The panel verifies its own service the way a client would:

* **Inbound ports** — for every enabled inbound whose transport is
  TCP, open a TCP connection to 127.0.0.1:port. A successful connect
  is "ok"; a refused connection is "down" (evidence: nothing is
  listening); a timeout or other error is "unknown" — never "down"
  without evidence. UDP inbounds (Hysteria2, TUIC, WireGuard,
  AmneziaWG, IKEv2) cannot be probed this way — a UDP "connect"
  succeeds even when nothing listens — so they are honestly reported
  "unknown" with the reason, not faked as ok.
* **Own subscription** — fetch the panel's own ``/sub/<token>`` URL
  for one usable user over HTTP(S) and check the body parses and is
  non-empty (v2rayNG: base64 decodes to >= 1 link; sing-box: JSON
  with >= 1 outbound). A 403 for a usable user's token, an empty
  feed or an unparseable body is "down" with the reason; a
  connection error is "unknown" (the panel may be behind a proxy
  or the self-fetch may be blocked — that is not evidence the
  subscription is broken for real clients). No usable user, or no
  panel URL to fetch, is "unknown" with the reason.

The check never claims more than it measured: every result is one
of ``ok`` / ``down`` / ``unknown`` with a human reason, and the
overall result is ``down`` only when at least one check is down,
``unknown`` when any check is unknown (and none down), else ``ok``.

Results are persisted by the caller in the ``selfcheck_last``
setting (JSON) and shown on the ``/selfcheck`` page; a scheduled
loop runs the check hourly (``selfcheck_interval_minutes``, 0 =
off) and notifies on ``selfcheck.failed`` (deduped by the event
bus). The HTTP fetch uses ``verify=False`` on purpose: the check
validates the *feed*, not the TLS chain — the panel's own
certificate (self-signed or a Let's Encrypt IP cert) would fail a
normal verification from inside the panel, and failing the check
for that would be a false alarm. The fetch goes to the panel's own
loopback address only.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("sparky-manager")

#: Setting keys (settings table — no schema change).
SELFCHECK_LAST_KEY = "selfcheck_last"
SELFCHECK_INTERVAL_KEY = "selfcheck_interval_minutes"

#: Default cadence for the scheduled loop (minutes); 0 disables it.
SELFCHECK_DEFAULT_INTERVAL_MINUTES = 60

#: Per-probe timeouts (seconds). A manual run stays bounded: with N
#: TCP inbounds the port phase costs at most N * 2 s.
TCP_PROBE_TIMEOUT = 2.0
SUBSCRIPTION_FETCH_TIMEOUT = 8.0

#: Protocols whose transport is always UDP (never TCP-probed).
_UDP_PROTOCOLS = {"hysteria2", "tuic", "wireguard", "amneziawg", "ikev2"}


def _transport_of(inbound: Any) -> str:
    """``"tcp"`` or ``"udp"`` for an inbound row/dict.

    UDP-only protocols are UDP; OpenVPN honours its stream
    transport (``tcp``/``udp``); everything else is TCP.
    """
    if isinstance(inbound, dict):
        protocol = str(inbound.get("protocol") or "").lower()
        stream = inbound.get("stream_json") or {}
    else:
        protocol = str(getattr(inbound, "protocol", "") or "").lower()
        try:
            stream = getattr(inbound, "stream") or {}
        except Exception:  # noqa: BLE001 — a bad stream_json is {}
            stream = {}
    if not isinstance(stream, dict):
        stream = {}
    if protocol in _UDP_PROTOCOLS:
        return "udp"
    if protocol == "openvpn":
        transport = str(stream.get("transport") or "tcp").lower()
        return "udp" if transport == "udp" else "tcp"
    return "tcp"


def probe_tcp_port(
    host: str, port: int, timeout: float = TCP_PROBE_TIMEOUT
) -> tuple[str, str]:
    """Probe one TCP port: ``("ok"|"down"|"unknown", reason)``.

    ``ok`` — the connect succeeded. ``down`` — connection refused
    (nothing listens: real evidence). ``unknown`` — timeout or any
    other error (no evidence either way). A port outside 1–65535
    is "unknown" with a "bad port" reason, never "down" — a port
    that cannot exist is not evidence that nothing listens.
    """
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        return "unknown", f"bad port: {exc}"
    if not 1 <= port_int <= 65535:
        return "unknown", "bad port: out of range 1-65535"
    try:
        with socket.create_connection((host, port_int), timeout=timeout):
            return "ok", ""
    except ConnectionRefusedError:
        return "down", "connection refused"
    except (socket.timeout, TimeoutError):
        return "unknown", "connect timed out"
    except OSError as exc:
        return "unknown", f"probe error: {exc}"
    except (TypeError, ValueError) as exc:
        return "unknown", f"bad port: {exc}"


def check_inbound_ports(
    inbounds: list[Any],
    probe: Callable[[str, int], tuple[str, str]] = probe_tcp_port,
) -> list[dict[str, Any]]:
    """Port check for every enabled inbound in ``inbounds``.

    Returns one dict per inbound: ``{kind: "port", tag, protocol,
    port, status, reason}``. Disabled inbounds are skipped (a
    disabled inbound is *meant* to be down). UDP inbounds report
    ``unknown`` with the reason — UDP cannot be probed by connect.
    ``probe`` is injectable for tests.
    """
    results: list[dict[str, Any]] = []
    for inbound in inbounds:
        if isinstance(inbound, dict):
            enabled = inbound.get("enabled", True)
            tag = str(inbound.get("tag") or "?")
            protocol = str(inbound.get("protocol") or "?")
            port = inbound.get("port")
        else:
            enabled = getattr(inbound, "enabled", True)
            tag = str(getattr(inbound, "tag", "?") or "?")
            protocol = str(getattr(inbound, "protocol", "?") or "?")
            port = getattr(inbound, "port", None)
        if not enabled:
            continue
        if _transport_of(inbound) == "udp":
            results.append(
                {
                    "kind": "port",
                    "tag": tag,
                    "protocol": protocol,
                    "port": port,
                    "status": "unknown",
                    "reason": "UDP cannot be probed by connect",
                }
            )
            continue
        try:
            port_int = int(port)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            results.append(
                {
                    "kind": "port",
                    "tag": tag,
                    "protocol": protocol,
                    "port": port,
                    "status": "unknown",
                    "reason": "bad port",
                }
            )
            continue
        status, reason = probe("127.0.0.1", port_int)
        results.append(
            {
                "kind": "port",
                "tag": tag,
                "protocol": protocol,
                "port": port_int,
                "status": status,
                "reason": reason,
            }
        )
    return results


def _feed_is_usable(body: bytes, fmt: str) -> tuple[bool, str]:
    """True when a subscription body parses and is non-empty."""
    from app import subscription as subscription_mod

    if not body or not body.strip():
        return False, "empty feed"
    if fmt == "singbox":
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False, "feed is not valid JSON"
        if not isinstance(data, dict):
            return False, "feed is not a JSON object"
        count = len(data.get("outbounds") or []) + len(
            data.get("endpoints") or []
        )
        if count == 0:
            return False, "feed has no outbounds"
        return True, ""
    try:
        links = subscription_mod.decode_v2rayng_feed(body)
    except ValueError:
        return False, "feed is not valid base64"
    if not links:
        return False, "feed has no links"
    return True, ""


def fetch_own_subscription(
    base_url: str,
    token: str,
    *,
    timeout: float = SUBSCRIPTION_FETCH_TIMEOUT,
    fetch: Optional[Callable[[str], tuple[int, bytes]]] = None,
) -> tuple[str, str]:
    """Fetch ``base_url/sub/<token>`` like a client would.

    Returns ``("ok"|"down"|"unknown", reason)``. ``fetch`` is
    injectable for tests (``(status_code, body)``); the default uses
    httpx with ``verify=False`` (see the module docstring) and a
    v2rayNG User-Agent. A transport failure is "unknown" — the panel
    being unreachable from itself is not evidence the subscription
    is broken for real clients.
    """
    url = f"{base_url.rstrip('/')}/sub/{token}"
    try:
        if fetch is not None:
            status_code, body = fetch(url)
        else:
            import httpx

            with httpx.Client(
                timeout=timeout, verify=False, follow_redirects=False
            ) as client:
                resp = client.get(
                    url, headers={"User-Agent": "v2rayNG/self-check"}
                )
            status_code, body = resp.status_code, resp.content
    except Exception:  # noqa: BLE001 — any transport failure: unknown
        logger.warning("self-check subscription fetch failed")
        return "unknown", "could not reach the panel"
    if status_code == 403:
        return "down", "subscription returned 403 for a usable user"
    if status_code != 200:
        return "down", f"subscription returned HTTP {status_code}"
    ok, reason = _feed_is_usable(body, "v2rayng")
    if not ok:
        return "down", reason
    return "ok", ""


def selfcheck_due(settings: dict, now: Optional[datetime] = None) -> bool:
    """True when the scheduled self-check is due (same shape as the
    auto-backup rule: ``selfcheck_interval_minutes``, 0 = off;
    ``selfcheck_last`` carries the last run's timestamp)."""
    try:
        minutes = int(
            (settings.get(SELFCHECK_INTERVAL_KEY) or "").strip() or "0"
        )
    except (ValueError, TypeError, AttributeError):
        minutes = 0
    if minutes <= 0:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        last = json.loads(settings.get(SELFCHECK_LAST_KEY, "") or "")
        raw = last.get("run_at", "") if isinstance(last, dict) else ""
        last_dt = datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return True
    if last_dt.tzinfo is None:
        last_dt = last_dt.replace(tzinfo=timezone.utc)
    return (now - last_dt) >= timedelta(minutes=minutes)


def run_self_check(
    inbounds: list[Any],
    *,
    base_url: Optional[str] = None,
    sub_token: Optional[str] = None,
    probe: Callable[[str, int], tuple[str, str]] = probe_tcp_port,
    fetch: Optional[Callable[[str], tuple[int, bytes]]] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """Run the full self-check. Returns the result dict that is
    persisted in the ``selfcheck_last`` setting and shown on the
    ``/selfcheck`` page::

        {"run_at": ISO, "overall": "ok"|"down"|"unknown",
         "checks": [{kind, tag/protocol/port or "subscription",
                     status, reason}, ...]}

    ``inbounds`` are the panel's inbound rows; ``base_url`` +
    ``sub_token`` drive the subscription fetch (omitted → that
    check is "unknown" with the reason). ``probe``/``fetch`` are
    injectable for tests. Never raises — a crashed check reports
    "unknown", it does not take the page down.
    """
    now = now or datetime.now(timezone.utc)
    checks: list[dict[str, Any]] = []
    try:
        checks.extend(check_inbound_ports(inbounds, probe=probe))
    except Exception:  # noqa: BLE001
        logger.exception("self-check port phase failed")
        checks.append(
            {
                "kind": "port",
                "tag": "—",
                "protocol": "—",
                "port": None,
                "status": "unknown",
                "reason": "port check failed",
            }
        )
    if not base_url or not sub_token:
        reason = (
            "no panel URL configured"
            if not base_url
            else "no usable user to check with"
        )
        checks.append(
            {
                "kind": "subscription",
                "tag": "—",
                "protocol": "—",
                "port": None,
                "status": "unknown",
                "reason": reason,
            }
        )
    else:
        try:
            status, reason = fetch_own_subscription(
                base_url, sub_token, fetch=fetch
            )
        except Exception:  # noqa: BLE001
            status, reason = "unknown", "subscription check failed"
        checks.append(
            {
                "kind": "subscription",
                "tag": "—",
                "protocol": "—",
                "port": None,
                "status": status,
                "reason": reason,
            }
        )
    if any(c["status"] == "down" for c in checks):
        overall = "down"
    elif any(c["status"] == "unknown" for c in checks):
        overall = "unknown"
    else:
        overall = "ok"
    return {"run_at": now.isoformat(), "overall": overall, "checks": checks}


__all__ = [
    "SELFCHECK_LAST_KEY",
    "SELFCHECK_INTERVAL_KEY",
    "SELFCHECK_DEFAULT_INTERVAL_MINUTES",
    "TCP_PROBE_TIMEOUT",
    "SUBSCRIPTION_FETCH_TIMEOUT",
    "probe_tcp_port",
    "check_inbound_ports",
    "fetch_own_subscription",
    "selfcheck_due",
    "run_self_check",
]
