"""HMAC-signed outgoing webhooks for panel events (best-panel
program, Phase B item 14 — Remnawave's model).

Sales bots, Mini Apps and monitoring tools sit on top of panel
APIs + webhooks (the research report's §6/§12 finding: no panel
bundles payments itself — external bots do it over the API). The
panel therefore emits its events (see
:data:`app.events.EVENT_CATALOG`) as signed JSON POSTs to
admin-configured endpoints, in parallel with the Telegram event
bus — the two channels are independent: an endpoint subscribed to
``user.created`` fires even when the Telegram event is off.

Signing (Remnawave's ``WEBHOOK_SECRET_HEADER`` shape): the raw
JSON body is HMAC-SHA256'd with the endpoint's secret and sent as
``X-Sparky-Signature: sha256=<hex>``; the event name travels in
``X-Sparky-Event``. The receiver recomputes the HMAC over the
exact bytes it received — no canonicalization, no timestamp
header (delivery retries would break a timestamp check; the
secret alone authenticates the sender).

Delivery is best-effort and never breaks a request: a 10-second
timeout, 2xx = delivered, anything else (or a network error) is
recorded on the endpoint (``last_status`` / ``last_error`` /
``last_delivered_at``) and the failure is logged — there is no
retry queue (a dead endpoint must not pile up work in the panel;
the admin sees the failure on the webhooks page and fixes the
URL). A "Send test" button posts a ``webhook.test`` event so the
admin can prove the signature verifies before relying on it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session as DbSession

from app import events as events_mod
from app.models import WebhookEndpoint

logger = logging.getLogger("sparky-manager")

#: The test event (not in the Telegram event catalog — it only
#: exists for the "Send test" button).
WEBHOOK_TEST_EVENT = "webhook.test"

#: Signature header (``sha256=<hex>`` value).
SIGNATURE_HEADER = "X-Sparky-Signature"
#: Event-name header.
EVENT_HEADER = "X-Sparky-Event"

#: Delivery timeout (a slow receiver must not stall a request).
DELIVERY_TIMEOUT_SECONDS = 10.0

#: Error text kept on the endpoint row (truncated — a hostile
#: receiver could return megabytes).
LAST_ERROR_MAX = 500


def sign_payload(secret: str, body: bytes) -> str:
    """``sha256=<hex>`` HMAC-SHA256 of the raw body with ``secret``."""
    digest = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """True when ``signature`` is the HMAC of ``body`` under
    ``secret`` (constant-time). Helper for receivers — and for
    tests proving the signature round-trips."""
    expected = sign_payload(secret, body)
    return hmac.compare_digest(expected, (signature or "").strip())


def subscribed_events(endpoint: WebhookEndpoint) -> list[str]:
    """The events an endpoint wants: its stored list, or the whole
    catalog when the list is empty (empty = all). Unknown names are
    dropped (they can only come from a hand-edited row)."""
    wanted = endpoint.events
    if not wanted:
        return list(events_mod.EVENT_CATALOG)
    return [e for e in wanted if e in events_mod.EVENT_CATALOG]


def _default_sender(
    url: str, headers: dict[str, str], body: bytes
) -> tuple[int, str]:
    """POST ``body`` to ``url`` with httpx. Returns
    ``(status_code, error)`` — ``error`` is "" on success."""
    import httpx

    try:
        resp = httpx.post(
            url, content=body, headers=headers,
            timeout=DELIVERY_TIMEOUT_SECONDS,
        )
        return resp.status_code, ""
    except Exception as exc:  # noqa: BLE001 — network failure, recorded
        return 0, str(exc)[:LAST_ERROR_MAX]


def _deliver_one(
    db: DbSession,
    endpoint: WebhookEndpoint,
    event: str,
    payload: dict[str, Any],
    sender: Optional[Callable[[str, dict[str, str], bytes], tuple[int, str]]] = None,
) -> bool:
    """Deliver one event to one endpoint. Records the outcome on
    the endpoint row and returns True only on a 2xx response.
    Never raises."""
    body = json.dumps(
        {"event": event, "at": datetime.now(timezone.utc).isoformat(), **payload},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        EVENT_HEADER: event,
        SIGNATURE_HEADER: sign_payload(endpoint.secret, body),
    }
    send = sender or _default_sender
    try:
        status, error = send(endpoint.url, headers, body)
    except Exception as exc:  # noqa: BLE001 — a broken sender, recorded
        status, error = 0, str(exc)[:LAST_ERROR_MAX]
    ok = 200 <= status < 300
    endpoint.last_status = "delivered" if ok else "failed"
    endpoint.last_error = (
        "" if ok else (error or f"HTTP {status}")[:LAST_ERROR_MAX]
    )
    endpoint.last_delivered_at = datetime.now(timezone.utc)
    db.commit()
    if not ok:
        logger.warning(
            "webhook %r (%s) delivery failed: %s",
            endpoint.name, event, endpoint.last_error,
        )
    return ok


def dispatch_event(
    db: DbSession,
    event: str,
    payload: Optional[dict[str, Any]] = None,
    sender: Optional[Callable[[str, dict[str, str], bytes], tuple[int, str]]] = None,
) -> list[tuple[int, bool]]:
    """Deliver ``event`` to every enabled endpoint subscribed to
    it. Returns ``[(endpoint_id, delivered)]``. Unknown events are
    refused (logged, empty list) — the catalog is the complete list
    of what the panel can emit, same rule as the Telegram bus.
    Never raises."""
    if event not in events_mod.EVENT_CATALOG:
        logger.warning("unknown webhook event %r refused", event)
        return []
    payload = dict(payload or {})
    results: list[tuple[int, bool]] = []
    for endpoint in db.query(WebhookEndpoint).filter(
        WebhookEndpoint.enabled.is_(True)
    ).all():
        if event not in subscribed_events(endpoint):
            continue
        try:
            delivered = _deliver_one(db, endpoint, event, payload, sender)
        except Exception:  # noqa: BLE001 — one endpoint, not the batch
            logger.exception("webhook delivery failed for %s", endpoint.name)
            delivered = False
        results.append((endpoint.id, delivered))
    return results


def send_test(
    db: DbSession,
    endpoint: WebhookEndpoint,
    sender: Optional[Callable[[str, dict[str, str], bytes], tuple[int, str]]] = None,
) -> tuple[bool, str]:
    """Send a ``webhook.test`` event to ONE endpoint (the "Send
    test" button). Returns ``(ok, detail)`` — the detail is the
    HTTP status on success, the failure reason otherwise. Works
    even when the endpoint is disabled (a disabled endpoint still
    needs its URL provable). Never raises."""
    try:
        delivered = _deliver_one(
            db, endpoint, WEBHOOK_TEST_EVENT, {"test": True}, sender
        )
    except Exception as exc:  # noqa: BLE001 — reported, not raised
        return False, str(exc)[:LAST_ERROR_MAX]
    if delivered:
        return True, "delivered"
    return False, (endpoint.last_error or "delivery failed")[:LAST_ERROR_MAX]


__all__ = [
    "WEBHOOK_TEST_EVENT",
    "SIGNATURE_HEADER",
    "EVENT_HEADER",
    "DELIVERY_TIMEOUT_SECONDS",
    "LAST_ERROR_MAX",
    "sign_payload",
    "verify_signature",
    "subscribed_events",
    "dispatch_event",
    "send_test",
]
