"""Phase B item 14 — HMAC-signed outgoing webhooks.

Panel events (the Phase A event-bus catalog) are POSTed as JSON to
the admin's URLs, signed HMAC-SHA256 (``X-Sparky-Signature:
sha256=<hex>``) so the receiver can verify them. Dispatch is hooked
into ``events.notify_event`` INDEPENDENT of Telegram enablement —
webhooks are their own channel. An empty event list means "all
catalog events". There is no retry queue: failures are recorded on
the endpoint row (last status / error / time).
"""

from __future__ import annotations

import json

from app import events as events_mod
from app import webhooks as webhooks_mod
from app.models import WebhookEndpoint


def _endpoint(db, name="hook", events=None, **kwargs):
    defaults = {
        "url": "https://example.com/hook",
        "secret": "s3cr3t",
        "enabled": True,
    }
    defaults.update(kwargs)
    endpoint = WebhookEndpoint(name=name, **defaults)
    # `events` is a property over the JSON column — set it via the
    # property, never as a constructor kwarg.
    endpoint.events = list(events or [])
    db.add(endpoint)
    db.commit()
    return endpoint


class _FakeSender:
    """Records every delivery; returns the configured status."""

    def __init__(self, status=200, error=""):
        self.status = status
        self.error = error
        self.calls: list[tuple[str, dict, bytes]] = []

    def __call__(self, url, headers, body):
        self.calls.append((url, dict(headers), body))
        return self.status, self.error


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def test_sign_and_verify_roundtrip():
    body = b'{"event":"user.created","at":"2026-11-16T00:00:00Z"}'
    sig = webhooks_mod.sign_payload("s3cr3t", body)
    assert sig.startswith("sha256=")
    assert webhooks_mod.verify_signature("s3cr3t", body, sig)


def test_verify_rejects_tampered_body_or_wrong_secret():
    body = b'{"event":"user.created"}'
    sig = webhooks_mod.sign_payload("s3cr3t", body)
    assert not webhooks_mod.verify_signature("s3cr3t", b'{"event":"x"}', sig)
    assert not webhooks_mod.verify_signature("other", body, sig)
    assert not webhooks_mod.verify_signature("s3cr3t", body, "sha256=deadbeef")
    assert not webhooks_mod.verify_signature("s3cr3t", body, "")


def test_signing_is_deterministic():
    body = b"hello"
    assert webhooks_mod.sign_payload("k", body) == webhooks_mod.sign_payload(
        "k", body
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_dispatch_sends_signed_json_with_event_header(db):
    endpoint = _endpoint(db)
    sender = _FakeSender(status=200)
    results = webhooks_mod.dispatch_event(
        db, "user.created", {"user": "alice"}, sender=sender
    )
    assert results == [(endpoint.id, True)]
    assert len(sender.calls) == 1
    url, headers, body = sender.calls[0]
    assert url == "https://example.com/hook"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Sparky-Event"] == "user.created"
    assert webhooks_mod.verify_signature(
        "s3cr3t", body, headers["X-Sparky-Signature"]
    )
    payload = json.loads(body)
    assert payload["event"] == "user.created"
    assert payload["user"] == "alice"
    assert "at" in payload


def test_dispatch_records_success_on_endpoint_row(db):
    endpoint = _endpoint(db)
    webhooks_mod.dispatch_event(db, "user.created", sender=_FakeSender(200))
    db.refresh(endpoint)
    assert endpoint.last_status == "delivered"
    assert endpoint.last_error == ""
    assert endpoint.last_delivered_at is not None


def test_dispatch_records_failure_on_endpoint_row(db):
    endpoint = _endpoint(db)
    webhooks_mod.dispatch_event(
        db, "user.created", sender=_FakeSender(500, "boom")
    )
    db.refresh(endpoint)
    assert endpoint.last_status == "failed"
    assert endpoint.last_error == "boom"


def test_dispatch_http_error_without_message_records_status(db):
    endpoint = _endpoint(db)
    webhooks_mod.dispatch_event(db, "user.created", sender=_FakeSender(404))
    db.refresh(endpoint)
    assert endpoint.last_status == "failed"
    assert endpoint.last_error == "HTTP 404"


def test_dispatch_skips_disabled_endpoints(db):
    _endpoint(db, name="off", enabled=False)
    sender = _FakeSender()
    results = webhooks_mod.dispatch_event(
        db, "user.created", sender=sender
    )
    assert results == []
    assert sender.calls == []


def test_dispatch_respects_event_subscription(db):
    sub = _endpoint(db, name="sub", events=["user.created"])
    _endpoint(db, name="other", events=["rerender.failed"])
    sender = _FakeSender()
    results = webhooks_mod.dispatch_event(
        db, "user.created", sender=sender
    )
    assert results == [(sub.id, True)]
    assert len(sender.calls) == 1


def test_dispatch_empty_event_list_means_all_events(db):
    endpoint = _endpoint(db)  # no events set
    sender = _FakeSender()
    for event in ("user.created", "user.expiring", "rerender.failed"):
        results = webhooks_mod.dispatch_event(db, event, sender=sender)
        assert results == [(endpoint.id, True)], event
    assert len(sender.calls) == 3


def test_dispatch_unknown_event_refused(db):
    _endpoint(db)
    sender = _FakeSender()
    assert webhooks_mod.dispatch_event(db, "bogus.event", sender=sender) == []
    assert sender.calls == []


def test_dispatch_broken_sender_recorded_not_raised(db):
    endpoint = _endpoint(db)

    def _broken(url, headers, body):
        raise RuntimeError("network down")

    results = webhooks_mod.dispatch_event(
        db, "user.created", sender=_broken
    )
    assert results == [(endpoint.id, False)]
    db.refresh(endpoint)
    assert endpoint.last_status == "failed"
    assert "network down" in endpoint.last_error


def test_event_bus_dispatches_to_webhooks_without_telegram(db, monkeypatch):
    """notify_event delivers to webhooks even when Telegram is not
    configured at all — the channels are independent."""
    endpoint = _endpoint(db)
    sender = _FakeSender()
    monkeypatch.setattr(webhooks_mod, "_default_sender", sender)
    events_mod.notify_event(db, "user.created", "Alice created")
    assert len(sender.calls) == 1
    assert sender.calls[0][1]["X-Sparky-Event"] == "user.created"
    db.refresh(endpoint)
    assert endpoint.last_status == "delivered"


def test_send_test_event(db):
    endpoint = _endpoint(db)
    sender = _FakeSender()
    ok, detail = webhooks_mod.send_test(db, endpoint, sender=sender)
    assert ok is True
    assert detail == "delivered"
    assert len(sender.calls) == 1
    assert sender.calls[0][1]["X-Sparky-Event"] == "webhook.test"
    payload = json.loads(sender.calls[0][2])
    assert payload["test"] is True


def test_send_test_works_on_disabled_endpoint(db):
    """A disabled endpoint still needs its URL provable."""
    endpoint = _endpoint(db, enabled=False)
    sender = _FakeSender()
    ok, _detail = webhooks_mod.send_test(db, endpoint, sender=sender)
    assert ok is True
    assert len(sender.calls) == 1


def test_send_test_reports_failure(db):
    endpoint = _endpoint(db)
    ok, detail = webhooks_mod.send_test(
        db, endpoint, sender=_FakeSender(0, "connection refused")
    )
    assert ok is False
    assert "connection refused" in detail


# ---------------------------------------------------------------------------
# The management page (HTTP)
# ---------------------------------------------------------------------------

def test_webhooks_page_renders_200(authed_client):
    resp = authed_client.get("/webhooks")
    assert resp.status_code == 200
    # The event catalog is offered as checkboxes.
    assert "user.created" in resp.text


def test_create_webhook_with_explicit_secret(authed_client, db):
    resp = authed_client.post(
        "/webhooks",
        data={
            "name": "sales",
            "url": "https://sales.example.com/hook",
            "secret": "my-secret",
            "events": ["user.created", "user.expiring"],
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    endpoint = db.query(WebhookEndpoint).filter_by(name="sales").one()
    assert endpoint.url == "https://sales.example.com/hook"
    assert endpoint.events == ["user.created", "user.expiring"]
    # The secret is stored (it must be usable to sign) but never
    # shown on the list page.
    page = authed_client.get("/webhooks")
    assert "my-secret" not in page.text


def test_create_webhook_blank_secret_generated_and_shown_once(
    authed_client, db
):
    resp = authed_client.post(
        "/webhooks",
        data={"name": "auto", "url": "https://example.com/h"},
    )
    assert resp.status_code == 200, resp.text  # rendered, not redirected
    endpoint = db.query(WebhookEndpoint).filter_by(name="auto").one()
    assert endpoint.secret
    # The generated secret is on THIS page …
    assert endpoint.secret in resp.text
    # … and nowhere else.
    page = authed_client.get("/webhooks")
    assert endpoint.secret not in page.text


def test_create_webhook_invalid_url_rejected(authed_client, db):
    for bad in ("not-a-url", "javascript:alert(1)", "ftp://example.com/x",
                "https://"):
        resp = authed_client.post(
            "/webhooks",
            data={"name": "bad", "url": bad},
            follow_redirects=False,
        )
        assert resp.status_code == 303, bad
    assert db.query(WebhookEndpoint).count() == 0


def test_webhook_test_button_uses_real_sender_path(
    authed_client, db, monkeypatch
):
    """The test button goes through send_test with the default
    sender — stubbed here so no real HTTP happens."""
    endpoint = _endpoint(db)
    sender = _FakeSender(status=200)
    monkeypatch.setattr(webhooks_mod, "_default_sender", sender)
    resp = authed_client.post(
        f"/webhooks/{endpoint.id}/test", follow_redirects=False
    )
    assert resp.status_code == 303
    assert len(sender.calls) == 1
    db.refresh(endpoint)
    assert endpoint.last_status == "delivered"


def test_webhook_toggle_and_delete(authed_client, db):
    endpoint = _endpoint(db)
    endpoint_id = endpoint.id
    resp = authed_client.post(
        f"/webhooks/{endpoint_id}/toggle", follow_redirects=False
    )
    assert resp.status_code == 303
    db.refresh(endpoint)
    assert endpoint.enabled is False
    resp = authed_client.post(
        f"/webhooks/{endpoint_id}/delete", follow_redirects=False
    )
    assert resp.status_code == 303
    db.expire_all()
    assert db.get(WebhookEndpoint, endpoint_id) is None


def test_webhook_toggle_missing_404s(authed_client):
    resp = authed_client.post("/webhooks/99999/toggle",
                              follow_redirects=False)
    assert resp.status_code == 404
