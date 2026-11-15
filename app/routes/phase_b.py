"""Best-panel program, Phase B routes — ``/plans``, ``/audit``,
``/api-tokens``, ``/api/v1/*``, ``/webhooks``, TOTP setup, tags,
devices and managed hosts.

Mounted by ``app.main`` after the users router. Every HTML route
uses the standard guards (``require_admin`` + ``require_csrf`` on
POSTs); the ``/api/v1/*`` endpoints use Bearer-token auth
(:func:`app.api_tokens.require_api_token`) instead — they take no
cookie, so CSRF does not apply to them (see the CSRF note in
``app.main``).

Two lazy seams (same pattern as ``app/routes/users.py``):
``_user_out`` / ``_inbound_out`` live in ``main``; importing them
at module level would be circular because ``main`` imports this
router.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app import api_tokens as api_tokens_mod
from app import devices as devices_mod
from app import events as events_mod
from app import hosts as hosts_mod
from app import lifecycle as lifecycle_mod
from app import links as links_mod
from app import plans as plans_mod
from app import tags as tags_mod
from app import totp as totp_mod
from app import webhooks as webhooks_mod
from app.i18n import get_lang, t_for
from app.models import (
    Admin,
    ApiToken,
    AuditLog,
    Inbound,
    ManagedHost,
    User,
    UserTemplate,
    WebhookEndpoint,
)
from app.webcommon import (
    _audit,
    _redirect,
    _template_ctx,
    db_session,
    require_admin,
    require_csrf,
    templates,
)

logger = logging.getLogger("sparky-manager")

router = APIRouter()

AUDIT_PAGE_SIZE = 25


def _user_out(user: Any) -> dict[str, Any]:
    """User JSON shape via ``main`` (lazy seam — see module docstring)."""
    from app.main import _user_out as _main_user_out

    return _main_user_out(user)


def _inbound_out(inbound: Any) -> dict[str, Any]:
    """Inbound JSON shape via ``main`` (lazy seam)."""
    from app.main import _inbound_out as _main_inbound_out

    return _main_inbound_out(inbound)


def _parse_page(page: str, total_pages: int) -> int:
    """A page number clamped to ``1..total_pages`` (bad input -> 1,
    never a 500 — same rule as the users list)."""
    try:
        page_n = int((page or "1").strip())
    except ValueError:
        page_n = 1
    return min(max(page_n, 1), total_pages)


# ---------------------------------------------------------------------------
# User templates / plans (item 9)
# ---------------------------------------------------------------------------


@router.get("/plans", response_class=HTMLResponse)
def plans_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """List templates + the create form (inbound checkboxes)."""
    templates_list = db.query(UserTemplate).order_by(UserTemplate.name).all()
    inbounds = db.query(Inbound).order_by(Inbound.tag).all()
    return templates.TemplateResponse(request, "plans.html",
        _template_ctx(request, {
            "admin": admin,
            "plans": templates_list,
            "inbounds": inbounds,
            "reset_cycles": lifecycle_mod.RESET_CYCLES,
        }),
    )


@router.post("/plans")
async def create_plan(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Create a template from the form. A bad value redirects back
    to the page with an error flash (303, like the other create
    flows); an unknown expiry mode is coerced to ``fixed`` (the
    form only offers the two valid modes, so anything else is a
    tampered POST)."""
    t = t_for(get_lang(request))
    form = await request.form()
    name = (form.get("name") or "").strip()
    traffic_limit_bytes: Optional[int] = None
    raw_limit = (form.get("traffic_limit_gb") or "").strip()
    if raw_limit:
        try:
            traffic_limit_bytes = int(float(raw_limit) * 1024**3)
            if traffic_limit_bytes <= 0:
                traffic_limit_bytes = None
        except ValueError:
            return _redirect("/plans", request, err=t["traffic_limit_gb"])
    expiry_days: Optional[int] = None
    raw_days = (form.get("expiry_days") or "").strip()
    if raw_days:
        try:
            expiry_days = int(raw_days)
            if expiry_days <= 0:
                expiry_days = None
        except ValueError:
            return _redirect("/plans", request, err=t["expires_days"])
    expiry_mode = (form.get("expiry_mode") or "fixed").strip()
    if expiry_mode not in lifecycle_mod.EXPIRY_STRATEGIES:
        expiry_mode = "fixed"
    reset_cycle = (form.get("reset_cycle") or "").strip() or None
    if reset_cycle is not None and reset_cycle not in lifecycle_mod.RESET_CYCLES:
        return _redirect("/plans", request, err=t["invalid_reset_cycle"])
    inbound_ids: list[int] = []
    for raw in form.getlist("inbound_ids"):
        try:
            inbound_ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    template = plans_mod.create_template(
        db,
        name,
        traffic_limit_bytes=traffic_limit_bytes,
        expiry_days=expiry_days,
        expiry_mode=expiry_mode,
        inbound_ids=inbound_ids,
        reset_cycle=reset_cycle,
    )
    if template is None:
        return _redirect("/plans", request, err=t["invalid_plan"])
    _audit(db, admin.id, "plan.create", name)
    logger.info("plan created: %s", name)
    return _redirect("/plans", request, msg=t["plan_created"])


@router.post("/plans/{template_id}/delete")
def delete_plan(
    request: Request,
    template_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Delete a template (existing users are untouched — a plan is
    a preset, not a live link)."""
    template = db.get(UserTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=404, detail="plan not found")
    name = template.name
    plans_mod.delete_template(db, template_id)
    _audit(db, admin.id, "plan.delete", name)
    logger.info("plan deleted: %s", name)
    return _redirect("/plans", request)


# ---------------------------------------------------------------------------
# Audit log viewer (item 15)
# ---------------------------------------------------------------------------


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    q: str = Query(""),
    page: str = Query("1"),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """The audit log, newest first, with text search (action/detail)
    and pagination. The log itself already existed — this page is
    the viewer it never had."""
    needle = (q or "").strip()
    query = db.query(AuditLog, Admin.username).outerjoin(
        Admin, AuditLog.admin_id == Admin.id
    )
    if needle:
        like = f"%{needle}%"
        query = query.filter(
            (AuditLog.action.ilike(like)) | (AuditLog.detail.ilike(like))
        )
    total = query.count()
    total_pages = max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)
    page_n = _parse_page(page, total_pages)
    rows = (
        query.order_by(AuditLog.id.desc())
        .offset((page_n - 1) * AUDIT_PAGE_SIZE)
        .limit(AUDIT_PAGE_SIZE)
        .all()
    )
    entries = [
        {"entry": entry, "username": username} for entry, username in rows
    ]
    return templates.TemplateResponse(request, "audit.html",
        _template_ctx(request, {
            "admin": admin,
            "entries": entries,
            "total": total,
            "q": q or "",
            "page": page_n,
            "total_pages": total_pages,
            "page_size": AUDIT_PAGE_SIZE,
        }),
    )


# ---------------------------------------------------------------------------
# API tokens (item 12) — management page
# ---------------------------------------------------------------------------


@router.get("/api-tokens", response_class=HTMLResponse)
def api_tokens_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """List tokens (hashes never leave the DB) + the create form."""
    tokens = db.query(ApiToken).order_by(ApiToken.id).all()
    return templates.TemplateResponse(request, "api_tokens.html",
        _template_ctx(request, {
            "admin": admin,
            "tokens": tokens,
            "scopes": api_tokens_mod.SCOPES,
        }),
    )


@router.post("/api-tokens")
async def create_api_token(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Create a token. Renders the one-time page showing the raw
    token — it is NEVER in a redirect URL (URLs end up in logs).
    """
    t = t_for(get_lang(request))
    form = await request.form()
    name = (form.get("name") or "").strip() or "token"
    if len(name) > 64:
        name = name[:64]
    scopes = [
        s for s in form.getlist("scopes") if s in api_tokens_mod.SCOPES
    ]
    expires_at: Optional[datetime] = None
    raw_days = (form.get("expires_days") or "").strip()
    if raw_days:
        try:
            days = int(raw_days)
            if days > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except ValueError:
            return _redirect("/api-tokens", request, err=t["expires_days"])
    token, raw = api_tokens_mod.create_token(db, name, scopes, expires_at)
    _audit(db, admin.id, "api_token.create", f"{name} scopes={','.join(scopes)}")
    logger.info("API token created: %s", name)
    return templates.TemplateResponse(request, "api_token_created.html",
        _template_ctx(request, {
            "admin": admin,
            "token": token,
            "raw_token": raw,
        }),
    )


@router.post("/api-tokens/{token_id}/revoke")
def revoke_api_token(
    request: Request,
    token_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Revoke a token (immediate — the hash is gone)."""
    token = db.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="token not found")
    name = token.name
    api_tokens_mod.revoke_token(db, token_id)
    _audit(db, admin.id, "api_token.revoke", name)
    logger.info("API token revoked: %s", name)
    return _redirect("/api-tokens", request)


# ---------------------------------------------------------------------------
# API v1 (item 12) — Bearer-token JSON endpoints
# ---------------------------------------------------------------------------


@router.get("/api/v1/status")
def api_v1_status(
    token: Any = Depends(api_tokens_mod.require_api_token("status:read")),
    db: Session = Depends(db_session),
):
    """Read-only panel status for scripts/monitors: counts + total
    traffic. No per-user detail (that needs ``users:read``)."""
    users = db.query(User).all()
    total_used = sum(u.traffic_used_bytes or 0 for u in users)
    return {
        "users": len(users),
        "inbounds": db.query(Inbound).count(),
        "traffic_used_bytes": total_used,
    }


@router.get("/api/v1/users")
def api_v1_list_users(
    token: Any = Depends(api_tokens_mod.require_api_token("users:read")),
    db: Session = Depends(db_session),
):
    return [_user_out(u) for u in db.query(User).order_by(User.id).all()]


@router.get("/api/v1/users/{user_id}")
def api_v1_get_user(
    user_id: int,
    token: Any = Depends(api_tokens_mod.require_api_token("users:read")),
    db: Session = Depends(db_session),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return _user_out(user)


@router.get("/api/v1/inbounds")
def api_v1_list_inbounds(
    token: Any = Depends(api_tokens_mod.require_api_token("inbounds:read")),
    db: Session = Depends(db_session),
):
    return [
        _inbound_out(i)
        for i in db.query(Inbound).order_by(Inbound.port).all()
    ]


# ---------------------------------------------------------------------------
# Outgoing webhooks (item 14)
# ---------------------------------------------------------------------------


def _valid_webhook_url(url: str) -> bool:
    """An http(s) URL with a host (no javascript:, no bare path)."""
    try:
        parsed = urlparse((url or "").strip())
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


@router.get("/webhooks", response_class=HTMLResponse)
def webhooks_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """List endpoints (secrets never leave the DB) + the create form."""
    endpoints = db.query(WebhookEndpoint).order_by(WebhookEndpoint.id).all()
    return templates.TemplateResponse(request, "webhooks.html",
        _template_ctx(request, {
            "admin": admin,
            "endpoints": endpoints,
            "events_catalog": list(events_mod.EVENT_CATALOG.items()),
        }),
    )


@router.post("/webhooks")
async def create_webhook(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Create an endpoint. A blank secret is auto-generated — and
    shown ONCE on the rendered page (it never goes in a redirect
    URL, and the list page never shows secrets)."""
    t = t_for(get_lang(request))
    form = await request.form()
    name = (form.get("name") or "").strip() or "webhook"
    if len(name) > 64:
        name = name[:64]
    url = (form.get("url") or "").strip()
    if not _valid_webhook_url(url):
        return _redirect("/webhooks", request, err=t["invalid_webhook_url"])
    secret = (form.get("secret") or "").strip()
    generated_secret: Optional[str] = None
    if not secret:
        secret = secrets.token_urlsafe(24)
        generated_secret = secret
    events = [
        e for e in form.getlist("events") if e in events_mod.EVENT_CATALOG
    ]
    endpoint = WebhookEndpoint(
        name=name, url=url, secret=secret, enabled=True
    )
    endpoint.events = events  # empty list = all catalog events
    db.add(endpoint)
    db.commit()
    _audit(db, admin.id, "webhook.create", f"{name} {url}")
    logger.info("webhook created: %s", name)
    if generated_secret is not None:
        endpoints = db.query(WebhookEndpoint).order_by(WebhookEndpoint.id).all()
        return templates.TemplateResponse(request, "webhooks.html",
            _template_ctx(request, {
                "admin": admin,
                "endpoints": endpoints,
                "events_catalog": list(events_mod.EVENT_CATALOG.items()),
                "created_secret": generated_secret,
                "created_name": name,
            }),
        )
    return _redirect("/webhooks", request, msg=t["webhook_created"])


@router.post("/webhooks/{endpoint_id}/delete")
def delete_webhook(
    request: Request,
    endpoint_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    name = endpoint.name
    db.delete(endpoint)
    db.commit()
    _audit(db, admin.id, "webhook.delete", name)
    logger.info("webhook deleted: %s", name)
    return _redirect("/webhooks", request)


@router.post("/webhooks/{endpoint_id}/toggle")
def toggle_webhook(
    request: Request,
    endpoint_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    endpoint.enabled = not endpoint.enabled
    db.commit()
    _audit(
        db, admin.id, "webhook.toggle",
        f"{endpoint.name} enabled={endpoint.enabled}",
    )
    return _redirect("/webhooks", request)


@router.post("/webhooks/{endpoint_id}/test")
def test_webhook(
    request: Request,
    endpoint_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Send a ``webhook.test`` event to one endpoint (proves the
    URL + signature verify before the admin relies on it)."""
    t = t_for(get_lang(request))
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail="webhook not found")
    ok, detail = webhooks_mod.send_test(db, endpoint)
    _audit(
        db, admin.id, "webhook.test",
        f"{endpoint.name} ok={ok} {detail}",
    )
    if ok:
        return _redirect("/webhooks", request, msg=t["webhook_test_ok"])
    return _redirect(
        "/webhooks", request, err=t["webhook_test_failed"] + f" {detail}"
    )


# ---------------------------------------------------------------------------
# TOTP 2FA setup (item 13)
# ---------------------------------------------------------------------------


def _render_totp_setup(
    request: Request,
    db: Session,
    admin: Any,
    *,
    error: str = "",
    recovery_codes: Optional[list[str]] = None,
) -> HTMLResponse:
    """Render the setup page: the pending secret's QR + secret text
    + confirm form — or, after a successful setup, the one-time
    recovery codes (``recovery_codes`` set)."""
    secret = totp_mod.get_pending_secret(db)
    provisioning = ""
    if secret:
        account = admin.username if admin is not None else "admin"
        provisioning = totp_mod.provisioning_uri(secret, account)
    return templates.TemplateResponse(request, "totp_setup.html",
        _template_ctx(request, {
            "admin": admin,
            "secret": secret,
            "provisioning_uri": provisioning,
            "error": error,
            "recovery_codes": recovery_codes,
            "totp_enabled": totp_mod.is_totp_enabled(db),
        }),
    )


@router.get("/settings/totp/setup", response_class=HTMLResponse)
def totp_setup_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Start (or resume) a setup: a pending secret is generated
    once and reused until the setup completes or is abandoned —
    regenerating on every GET would change the QR on refresh."""
    if not totp_mod.get_pending_secret(db):
        totp_mod.begin_setup(db)
    return _render_totp_setup(request, db, admin)


@router.get("/settings/totp/qr")
def totp_setup_qr(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """QR PNG of the pending secret's provisioning URI (the CSP
    blocks data: images, so the QR is served from a route).
    404 when no setup is in progress."""
    secret = totp_mod.get_pending_secret(db)
    if not secret:
        raise HTTPException(status_code=404, detail="no TOTP setup in progress")
    account = admin.username if admin is not None else "admin"
    uri = totp_mod.provisioning_uri(secret, account)
    png = links_mod.make_qr_png(uri)
    return Response(content=png, media_type="image/png")


@router.post("/settings/totp/setup")
async def totp_setup_submit(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Confirm the setup with a code from the authenticator app.
    On success the recovery codes are shown ONCE (rendered, never
    redirected — they must not land in a URL)."""
    t = t_for(get_lang(request))
    form = await request.form()
    code = (form.get("code") or "").strip()
    secret = totp_mod.get_pending_secret(db)
    if not secret:
        return _redirect(
            "/settings?section=security", request, err=t["totp_no_setup"]
        )
    if not totp_mod.verify_code(secret, code):
        return _render_totp_setup(
            request, db, admin, error=t["totp_wrong_code"]
        )
    codes = totp_mod.complete_setup(db, secret)
    _audit(db, admin.id, "totp.enabled", "")
    logger.info("TOTP enabled for %s", admin.username)
    return _render_totp_setup(request, db, admin, recovery_codes=codes)


@router.post("/settings/totp/disable")
async def totp_disable_submit(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Disable 2FA — requires a valid code (3x-ui's rule: replacing
    or removing the secret needs a code). An admin who lost the
    device AND the recovery codes uses ``sparky-manager
    totp-disable`` on the server instead."""
    t = t_for(get_lang(request))
    form = await request.form()
    code = (form.get("code") or "").strip()
    secret = totp_mod.get_totp_secret(db)
    code_ok = bool(secret) and totp_mod.verify_code(secret, code)
    if not code_ok and not totp_mod.verify_recovery_code(db, code):
        return _redirect(
            "/settings?section=security", request, err=t["totp_wrong_code"]
        )
    totp_mod.disable_totp(db)
    _audit(db, admin.id, "totp.disabled", "")
    logger.info("TOTP disabled for %s", admin.username)
    return _redirect(
        "/settings?section=security", request, msg=t["totp_disabled"]
    )


# ---------------------------------------------------------------------------
# Tags (item 16) — on the user detail page
# ---------------------------------------------------------------------------


@router.post("/users/{user_id}/tags")
async def add_user_tag(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    form = await request.form()
    tag = tags_mod.add_tag(db, user.id, (form.get("tag") or ""))
    if tag is None:
        return _redirect(
            f"/users/{user_id}", request, err=t["invalid_tag"]
        )
    _audit(db, admin.id, "user.tag_add", f"{user.name} tag={tag}")
    return _redirect(f"/users/{user_id}", request)


@router.post("/users/{user_id}/tags/remove")
async def remove_user_tag(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    form = await request.form()
    tag = (form.get("tag") or "").strip()
    if tags_mod.remove_tag(db, user.id, tag):
        _audit(db, admin.id, "user.tag_remove", f"{user.name} tag={tag}")
    return _redirect(f"/users/{user_id}", request)


# ---------------------------------------------------------------------------
# Devices (item 17) — single-device removal, on the user detail page
# ---------------------------------------------------------------------------


@router.post("/users/{user_id}/devices/{device_id}/delete")
def delete_user_device(
    request: Request,
    user_id: int,
    device_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Remove one device (frees its slot — the next-oldest device
    becomes allowed). A device of another user is never touched."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    if devices_mod.remove_device(db, device_id, user.id):
        _audit(db, admin.id, "user.device_remove", f"{user.name} device={device_id}")
    return _redirect(f"/users/{user_id}", request)


# ---------------------------------------------------------------------------
# Managed hosts (item 18) — on the inbound edit page
# ---------------------------------------------------------------------------


@router.post("/inbounds/{inbound_id}/hosts")
async def create_inbound_host(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Add a managed host to an inbound (no re-render needed — the
    server-side configs never carry hosts; only links/feeds do)."""
    t = t_for(get_lang(request))
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    form = await request.form()
    address = (form.get("address") or "").strip()
    port: Optional[int] = None
    raw_port = (form.get("port") or "").strip()
    if raw_port:
        try:
            port = int(raw_port)
        except ValueError:
            return _redirect(
                f"/inbounds/{inbound_id}/edit",
                request, err=t["invalid_host_port"],
            )
    sni = (form.get("sni") or "").strip() or None
    remark = (form.get("remark") or "").strip() or None
    sort_order = 0
    raw_order = (form.get("sort_order") or "").strip()
    if raw_order:
        try:
            sort_order = int(raw_order)
        except ValueError:
            sort_order = 0
    error = hosts_mod.validate_host(address, port, sni)
    if error is not None:
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t[error]
        )
    host = hosts_mod.create_host(
        db, inbound.id, address, port=port, sni=sni, remark=remark,
        sort_order=sort_order,
    )
    if host is None:  # pragma: no cover — validated above
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t["invalid_host_address"]
        )
    _audit(db, admin.id, "host.create", f"{inbound.tag} {address}")
    return _redirect(f"/inbounds/{inbound_id}/edit", request)


@router.post("/inbounds/{inbound_id}/hosts/{host_id}/delete")
def delete_inbound_host(
    request: Request,
    inbound_id: int,
    host_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    if hosts_mod.delete_host(db, host_id, inbound.id):
        _audit(db, admin.id, "host.delete", f"{inbound.tag} host={host_id}")
    return _redirect(f"/inbounds/{inbound_id}/edit", request)


@router.post("/inbounds/{inbound_id}/hosts/{host_id}/toggle")
def toggle_inbound_host(
    request: Request,
    inbound_id: int,
    host_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    host = (
        db.query(ManagedHost)
        .filter(
            ManagedHost.id == host_id,
            ManagedHost.inbound_id == inbound.id,
        )
        .first()
    )
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    host.enabled = not host.enabled
    db.commit()
    _audit(
        db, admin.id, "host.toggle",
        f"{inbound.tag} host={host_id} enabled={host.enabled}",
    )
    return _redirect(f"/inbounds/{inbound_id}/edit", request)
