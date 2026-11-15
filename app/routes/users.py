"""Users routes (Phase 5 split) — ``/users*``.

Moved out of ``app/main.py`` unchanged (paths, forms, redirects,
CSRF) and mounted by ``main`` with ``app.include_router`` in the
same position, so route precedence is unchanged.

Two lazy seams (both temporary — they go away when the owning code
splits): :func:`rerender_configs` and :func:`_file_export_urls`
live in ``main`` (with the config renderers and the subscription
routes); importing them at module level would be circular because
``main`` imports this router. The lazy import reads ``main``'s
attribute at call time, so tests patching ``main_mod.rerender_configs``
still take effect.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.i18n import get_lang, t_for
from app.models import Client, Inbound, User
from app.webcommon import (
    NAME_RE,
    WEB_PATH,
    _audit,
    _client_is_frozen,
    _create_clients_for_user,
    _links_for_user,
    _next_awg_address,
    _next_wg_address,
    _notify_telegram,
    _redirect,
    _set_client_extra,
    _set_client_frozen,
    _sub_host,
    _template_ctx,
    _traffic_chart,
    db_session,
    get_settings,
    require_admin,
    require_csrf,
    templates,
)

logger = logging.getLogger("sparky-manager")

router = APIRouter()


def rerender_configs(db: Session) -> None:
    """Re-render configs via ``main`` (lazy seam — see module docstring)."""
    from app.main import rerender_configs as _main_rerender_configs

    _main_rerender_configs(db)


def _file_export_urls(db: Session, user: Any, base: str) -> dict[str, str]:
    """File-export URLs via ``main`` (lazy seam — see module docstring)."""
    from app.main import _file_export_urls as _main_file_export_urls

    return _main_file_export_urls(db, user, base)


USERS_PAGE_SIZE = 25

USER_SORTS = ("created", "name", "expiry", "traffic")

USER_STATUSES = ("all", "enabled", "disabled", "frozen", "expired")

def _aware_dt(value: Optional[datetime]) -> Optional[datetime]:
    """A stored datetime as timezone-aware UTC (SQLite returns naive
    values for ``DateTime(timezone=True)`` columns)."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

# XTLS flows Xray accepts for VLESS clients. Vision needs TLS or
# Reality; the "-udp443" variant additionally serves QUIC on 443.
VLESS_FLOWS = ("xtls-rprx-vision", "xtls-rprx-vision-udp443")

# Bounds for the per-client IP limit and bulk expiry extension.
IP_LIMIT_MAX = 1000

EXTEND_DAYS_MAX = 3650

def _parse_expiry_date(value: str) -> Optional[datetime]:
    """``YYYY-MM-DD`` -> end of that day (23:59:59 UTC), or ``None``
    for an empty value (never expires). Raises ``ValueError`` on a
    malformed date. A past date is allowed — it expires the user
    immediately, which is a legitimate admin action."""
    text = (value or "").strip()
    if not text:
        return None
    parsed = datetime.strptime(text, "%Y-%m-%d")
    return parsed.replace(
        hour=23, minute=59, second=59, tzinfo=timezone.utc
    )

def _parse_ip_limit(value: str) -> Optional[int]:
    """Per-client IP limit: empty or ``0`` means unlimited (``None``);
    otherwise an int in ``1..IP_LIMIT_MAX``. Raises ``ValueError``."""
    text = (value or "").strip()
    if not text:
        return None
    limit = int(text)
    if limit == 0:
        return None
    if not 1 <= limit <= IP_LIMIT_MAX:
        raise ValueError("ip limit out of range")
    return limit

def _client_flow_options(inbound: Any) -> list[str]:
    """Allowed ``flow`` values for a client of ``inbound``.

    Flow is VLESS-only (VMess has no flow). Vision needs TLS or
    Reality, so a security=``none`` inbound offers only ``""``
    (no flow) — saving the edit page then clears any stale Vision
    value a client picked up when the inbound had TLS/Reality.
    A Reality inbound offers only the Vision variants: the Xray
    renderer defaults an empty flow to ``xtls-rprx-vision`` for
    Reality (``app/xray.py``), so offering "none" there would render
    Vision on the server while the share link carried no flow — a
    client that can never connect.
    """
    if getattr(inbound, "protocol", None) != "vless":
        return []
    stream = getattr(inbound, "stream", None) or {}
    security = (stream.get("security") or "none") if isinstance(stream, dict) else "none"
    if security == "reality":
        return list(VLESS_FLOWS)
    if security == "tls":
        return ["", *VLESS_FLOWS]
    return [""]

def _move_targets(
    db: Session, user: Any, client: Any
) -> list[Any]:
    """Inbounds a client may move to: same protocol as its current
    inbound, enabled, not the current one, and without an existing
    client for this user (``UNIQUE(user_id, inbound_id)``)."""
    current = db.get(Inbound, client.inbound_id)
    if current is None:
        return []
    taken = {
        row[0]
        for row in db.query(Client.inbound_id)
        .filter(Client.user_id == user.id)
        .all()
    }
    query = (
        db.query(Inbound)
        .filter(
            Inbound.protocol == current.protocol,
            Inbound.enabled.is_(True),
            Inbound.id != current.id,
        )
    )
    if taken:
        query = query.filter(~Inbound.id.in_(taken))
    return query.order_by(Inbound.tag).all()

def _user_client_rows(
    db: Session, user: Any, *, with_moves: bool = True
) -> list[dict[str, Any]]:
    """One row per client of ``user`` for the edit/detail pages:
    the client, its inbound, its flow options, its move targets
    (skipped when ``with_moves`` is False — the detail page does
    not need them), and its frozen / IP-limit state (from ``extra``).
    """
    clients = (
        db.query(Client)
        .filter(Client.user_id == user.id)
        .order_by(Client.inbound_id)
        .all()
    )
    inbounds = {i.id: i for i in db.query(Inbound).all()}
    rows: list[dict[str, Any]] = []
    for client in clients:
        inbound = inbounds.get(client.inbound_id)
        if inbound is None:
            continue
        extra = getattr(client, "extra", None) or {}
        rows.append(
            {
                "client": client,
                "inbound": inbound,
                "flow_options": _client_flow_options(inbound),
                "move_targets": (
                    _move_targets(db, user, client) if with_moves else []
                ),
                "frozen": _client_is_frozen(client),
                "ip_limit": extra.get("ip_limit")
                if isinstance(extra, dict)
                else None,
            }
        )
    return rows

def _user_edit_values(
    user: Any, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """Pre-filled values for the user edit form (user fields + one
    set of per-client fields per row, keyed ``flow_<id>`` /
    ``ip_limit_<id>`` / ``frozen_<id>`` / ``move_<id>``)."""
    limit_gb = ""
    if user.traffic_limit_bytes:
        limit_gb = str(round(user.traffic_limit_bytes / 1024**3, 2))
    values: dict[str, Any] = {
        "name": user.name,
        "note": user.note or "",
        "traffic_limit_gb": limit_gb,
        "expires_date": (
            user.expires_at.strftime("%Y-%m-%d") if user.expires_at else ""
        ),
    }
    for row in rows:
        client = row["client"]
        cid = client.id
        flow = getattr(client, "flow", None) or ""
        # The form only offers the flow options valid for this
        # inbound; a stale value outside them shows as the first
        # option (and is corrected on save).
        if row["flow_options"] and flow not in row["flow_options"]:
            flow = row["flow_options"][0]
        values[f"flow_{cid}"] = flow
        values[f"ip_limit_{cid}"] = (
            "" if row["ip_limit"] is None else str(row["ip_limit"])
        )
        values[f"frozen_{cid}"] = bool(row["frozen"])
        values[f"move_{cid}"] = ""
    return values

def _render_user_edit(
    request: Request,
    user: Any,
    values: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    error: str | None = None,
    db: Session,
) -> HTMLResponse:
    """Render the user edit page (GET and POST-error re-render)."""
    return templates.TemplateResponse(
        request,
        "user_edit.html",
        _template_ctx(
            request,
            {
                "user": user,
                "values": values,
                "rows": rows,
                "error": error or "",
            },
        ),
    )

def _apply_client_move(
    db: Session, client: Any, target: Any
) -> Optional[str]:
    """Move ``client`` to ``target`` (same protocol, pre-validated).

    Credentials stay; WireGuard/AmneziaWG get a fresh address from
    the target subnet (the old address belongs to the old subnet's
    pool). Traffic history is per-user, so it is untouched. Returns
    an error string, or ``None`` on success. Does not commit.
    """
    protocol = target.protocol
    if protocol in ("wireguard", "amneziawg"):
        subnet = (target.stream or {}).get("subnet") or (
            "10.8.0.0/24" if protocol == "wireguard" else "10.8.1.0/24"
        )
        try:
            if protocol == "wireguard":
                address = _next_wg_address(db, subnet, inbound_id=target.id)
            else:
                address = _next_awg_address(db, subnet, inbound_id=target.id)
        except ValueError:
            return "move_address_exhausted"
        _set_client_extra(client, "allowed_ips", address)
    client.inbound_id = target.id
    return None


@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    q: str = Query(""),
    status: str = Query("all"),
    sort: str = Query("created"),
    page: str = Query("1"),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Users list with server-side search / filter / sort / pagination
    (Phase 4). All params are bookmarkable GET params; a bad value
    falls back to the default, never a 500 (``page`` is parsed by
    hand for exactly that reason — an ``int`` Query param would 422
    on ``?page=abc``)."""
    now = datetime.now(timezone.utc)
    users = db.query(User).all()
    total_users = len(users)

    # Search: name or note, case-insensitive substring.
    needle = (q or "").strip().lower()
    if needle:
        users = [
            u
            for u in users
            if needle in u.name.lower()
            or (u.note and needle in u.note.lower())
        ]

    # Frozen is a per-user flag: all of the user's clients frozen
    # (and at least one client) — same rule as the detail page.
    # Computed for every render: the table shows the frozen badge.
    clients_by_user: dict[int, list[Any]] = {}
    for client in db.query(Client).all():
        clients_by_user.setdefault(client.user_id, []).append(client)
    frozen_ids = {
        user_id
        for user_id, clients in clients_by_user.items()
        if clients and all(_client_is_frozen(c) for c in clients)
    }
    # Expired ids are precomputed here (with naive/aware handling) —
    # the template must never compare datetimes itself.
    expired_ids = {
        u.id
        for u in db.query(User).all()
        if _aware_dt(u.expires_at) is not None
        and _aware_dt(u.expires_at) <= now
    }

    status = (status or "").strip().lower()
    if status not in USER_STATUSES:
        status = "all"
    if status == "enabled":
        users = [u for u in users if u.enabled]
    elif status == "disabled":
        users = [u for u in users if not u.enabled]
    elif status == "frozen":
        users = [u for u in users if u.id in frozen_ids]
    elif status == "expired":
        users = [u for u in users if u.id in expired_ids]

    sort = (sort or "").strip().lower()
    if sort not in USER_SORTS:
        sort = "created"
    if sort == "name":
        users.sort(key=lambda u: u.name.lower())
    elif sort == "expiry":
        # Never-expiring users sort last (no expiry to approach).
        users.sort(
            key=lambda u: _aware_dt(u.expires_at)
            or datetime.max.replace(tzinfo=timezone.utc)
        )
    elif sort == "traffic":
        users.sort(key=lambda u: u.traffic_used_bytes or 0, reverse=True)
    else:
        users.sort(
            key=lambda u: _aware_dt(u.created_at)
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    filtered_total = len(users)
    try:
        page_n = int((page or "1").strip())
    except ValueError:
        page_n = 1
    total_pages = max(
        1, (filtered_total + USERS_PAGE_SIZE - 1) // USERS_PAGE_SIZE
    )
    page_n = min(max(page_n, 1), total_pages)
    start = (page_n - 1) * USERS_PAGE_SIZE
    page_users = users[start : start + USERS_PAGE_SIZE]
    return templates.TemplateResponse(request, "users.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "users": page_users,
                "total_users": total_users,
                "filtered_total": filtered_total,
                "frozen_ids": frozen_ids,
                "expired_ids": expired_ids,
                "q": q or "",
                "status": status,
                "sort": sort,
                "page": page_n,
                "total_pages": total_pages,
                "page_size": USERS_PAGE_SIZE,
            },
        ),
    )


@router.post("/users")
def create_user(
    request: Request,
    name: str = Form(...),
    note: str = Form(""),
    traffic_limit_gb: str = Form(""),
    expires_days: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    lang = get_lang(request)
    t = t_for(lang)
    name = name.strip()
    if not NAME_RE.match(name):
        return _redirect("/users", request, err=t["invalid_name"])
    if db.query(User).filter(User.name == name).first() is not None:
        return _redirect("/users", request, err=t["name_exists"])
    limit_bytes: Optional[int] = None
    if traffic_limit_gb.strip():
        try:
            limit_bytes = int(float(traffic_limit_gb) * 1024**3)
            if limit_bytes <= 0:
                limit_bytes = None
        except ValueError:
            return _redirect("/users", request, err=t["traffic_limit_gb"])
    expires_at: Optional[datetime] = None
    if expires_days.strip():
        try:
            days = int(expires_days)
            if days > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except ValueError:
            return _redirect("/users", request, err=t["expires_days"])
    user = User(
        name=name,
        note=note.strip() or None,
        enabled=True,
        traffic_limit_bytes=limit_bytes,
        traffic_used_bytes=0,
        expires_at=expires_at,
        sub_token=secrets.token_urlsafe(24),
    )
    db.add(user)
    db.commit()
    _create_clients_for_user(db, user)
    _audit(db, admin.id, "user.create", name)
    logger.info("user created: %s", name)
    _notify_telegram(db, t["tg_user_created"].format(name=name))
    errors = rerender_configs(db)
    err = "; ".join(errors) if errors else ""
    if err:
        err = t["rerender_failed"] + err
    return _redirect(f"/users/{user.id}", request, err=err)


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    settings = get_settings(db)
    host = _sub_host(request, settings)
    base = str(request.base_url).rstrip("/") + WEB_PATH
    links = _links_for_user(db, user, host, settings)
    clients = (
        db.query(Client)
        .filter(Client.user_id == user.id)
        .order_by(Client.inbound_id)
        .all()
    )
    inbounds = {i.id: i for i in db.query(Inbound).all()}
    # Phase 2: frozen / IP-limit state per client (from `extra`) and
    # the user-level frozen flag (all clients frozen).
    rows = _user_client_rows(db, user, with_moves=False)
    client_extra = {
        row["client"].id: {
            "frozen": row["frozen"],
            "ip_limit": row["ip_limit"],
        }
        for row in rows
    }
    frozen = bool(rows) and all(row["frozen"] for row in rows)
    # Phase 3: this user's 14-day traffic chart (admin view only —
    # the public /u/<token> page does not pass this context).
    user_traffic_chart, user_traffic_14d = _traffic_chart(db, user_id=user.id)
    return templates.TemplateResponse(request, "user_detail.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "user": user,
                "clients": clients,
                "inbounds": inbounds,
                "client_extra": client_extra,
                "frozen": frozen,
                "links": links,
                "links_available": True,
                "sub_url": f"{base}/sub/{user.sub_token}",
                "zedsecure_url": f"{base}/sub/{user.sub_token}/zedsecure.json",
                "user_url": f"{base}/u/{user.sub_token}",
                "file_urls": _file_export_urls(db, user, base),
                "host": host,
                "user_traffic_chart": user_traffic_chart,
                "user_traffic_14d": user_traffic_14d,
            },
        ),
    )


@router.post("/users/{user_id}/toggle")
def toggle_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    user.enabled = not user.enabled
    db.commit()
    _audit(db, admin.id, "user.toggle", f"{user.name} enabled={user.enabled}")
    logger.info("user toggled: %s enabled=%s", user.name, user.enabled)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(f"/users/{user_id}", request, err=err)


@router.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    name = user.name
    db.query(Client).filter(Client.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    _audit(db, admin.id, "user.delete", name)
    logger.info("user deleted: %s", name)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/users", request, err=err)


@router.post("/users/{user_id}/rotate-token")
def rotate_token(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    user.sub_token = secrets.token_urlsafe(24)
    db.commit()
    _audit(db, admin.id, "user.rotate_token", user.name)
    logger.info("subscription token rotated for %s", user.name)
    # No core re-render needed: the subscription token is not in core configs.
    return _redirect(f"/users/{user_id}", request)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_page(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Pre-filled edit page for one user (Phase 2)."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    rows = _user_client_rows(db, user)
    return _render_user_edit(
        request, user, _user_edit_values(user, rows), rows, db=db
    )


@router.post("/users/{user_id}/edit")
async def edit_user_submit(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Validate, save, re-render — two passes so a bad per-client
    field never leaves a half-saved user.

    On a validation error the edit form is re-rendered (200) with
    the submitted values preserved, like the inbound editor.
    """
    t = t_for(get_lang(request))
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    form = await request.form()
    data: dict[str, str] = {
        str(key): str(value) for key, value in form.multi_items()
        if isinstance(value, str)
    }
    rows = _user_client_rows(db, user)
    values = _user_edit_values(user, rows)
    # Merge the submitted values over the current ones so a
    # validation error shows what the admin typed, not the old DB.
    for key, value in data.items():
        values[key] = value
    for row in rows:
        cid = row["client"].id
        values[f"frozen_{cid}"] = data.get(f"frozen_{cid}") in ("on", "true", "1")

    def _error(message: str) -> HTMLResponse:
        return _render_user_edit(
            request, user, values, rows, error=message, db=db
        )

    # --- pass 1: validate everything, apply nothing ---
    name = (data.get("name") or "").strip()
    if not NAME_RE.match(name):
        return _error(t["invalid_name"])
    clash = (
        db.query(User)
        .filter(User.name == name, User.id != user.id)
        .first()
    )
    if clash is not None:
        return _error(t["name_exists"])
    limit_bytes: Optional[int] = None
    if (data.get("traffic_limit_gb") or "").strip():
        try:
            limit_bytes = int(float(data["traffic_limit_gb"]) * 1024**3)
            if limit_bytes <= 0:
                limit_bytes = None
        except ValueError:
            return _error(t["traffic_limit_gb"])
    try:
        expires_at = _parse_expiry_date(data.get("expires_date") or "")
    except ValueError:
        return _error(t["invalid_expiry_date"])

    planned: list[tuple[Any, str, Optional[int], bool, Any]] = []
    planned_targets: set[int] = set()
    for row in rows:
        client = row["client"]
        cid = client.id
        # Flow (VLESS only; a field the form did not send leaves the
        # stored value untouched).
        flow = getattr(client, "flow", None) or ""
        options = row["flow_options"]
        if options and f"flow_{cid}" in data:
            flow = data[f"flow_{cid}"]
            if flow not in options:
                return _error(t["invalid_flow"])
        # IP limit (a field the form did not send keeps the value).
        ip_limit: Optional[int] = row["ip_limit"]
        if f"ip_limit_{cid}" in data:
            try:
                ip_limit = _parse_ip_limit(data[f"ip_limit_{cid}"])
            except ValueError:
                return _error(t["invalid_ip_limit"])
        frozen = data.get(f"frozen_{cid}") in ("on", "true", "1")
        # Move to another compatible inbound.
        target = None
        move_raw = (data.get(f"move_{cid}") or "").strip()
        if move_raw:
            try:
                target_id = int(move_raw)
            except ValueError:
                return _error(t["move_invalid_target"])
            allowed = {i.id for i in row["move_targets"]}
            if target_id not in allowed or target_id in planned_targets:
                return _error(t["move_invalid_target"])
            planned_targets.add(target_id)
            target = db.get(Inbound, target_id)
            if target is None:  # pragma: no cover - allowed ids exist
                return _error(t["move_invalid_target"])
            # Pre-check the WG/AWG address pool so a full pool fails
            # validation (no partial save) instead of mid-apply.
            if target.protocol in ("wireguard", "amneziawg"):
                subnet = (target.stream or {}).get("subnet") or (
                    "10.8.0.0/24"
                    if target.protocol == "wireguard"
                    else "10.8.1.0/24"
                )
                try:
                    if target.protocol == "wireguard":
                        _next_wg_address(db, subnet, inbound_id=target.id)
                    else:
                        _next_awg_address(db, subnet, inbound_id=target.id)
                except ValueError:
                    return _error(t["move_address_exhausted"])
        planned.append((client, flow, ip_limit, frozen, target))

    # --- pass 2: apply ---
    user.name = name
    user.note = (data.get("note") or "").strip() or None
    user.traffic_limit_bytes = limit_bytes
    user.expires_at = expires_at
    for client, flow, ip_limit, frozen, target in planned:
        client.flow = flow or None
        _set_client_extra(client, "ip_limit", ip_limit)
        _set_client_frozen(client, frozen)
        if target is not None:
            move_err = _apply_client_move(db, client, target)
            if move_err is not None:  # pre-checked; defence in depth
                db.rollback()
                return _error(t[move_err])
    db.commit()
    _audit(db, admin.id if admin is not None else None, "user.update", name)
    logger.info("user updated: %s", name)
    errors = rerender_configs(db)
    if errors:
        return _redirect(
            f"/users/{user.id}",
            request,
            err=t["rerender_failed"] + "; ".join(errors),
        )
    return _redirect(f"/users/{user.id}", request, msg=t["user_updated"])


@router.post("/users/{user_id}/freeze")
def freeze_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Freeze every client of the user: they drop out of configs,
    links and feeds, but keep credentials and traffic history."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    count = 0
    for client in db.query(Client).filter(Client.user_id == user.id).all():
        if not _client_is_frozen(client):
            _set_client_frozen(client, True)
            count += 1
    db.commit()
    _audit(db, admin.id, "user.freeze", f"{user.name} ({count} clients)")
    logger.info("user frozen: %s (%d clients)", user.name, count)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(f"/users/{user_id}", request, msg=t["user_frozen"], err=err)


@router.post("/users/{user_id}/unfreeze")
def unfreeze_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Unfreeze every client of the user (restores the frozen state)."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    count = 0
    for client in db.query(Client).filter(Client.user_id == user.id).all():
        if _client_is_frozen(client):
            _set_client_frozen(client, False)
            count += 1
    db.commit()
    _audit(db, admin.id, "user.unfreeze", f"{user.name} ({count} clients)")
    logger.info("user unfrozen: %s (%d clients)", user.name, count)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(
        f"/users/{user_id}", request, msg=t["user_unfrozen"], err=err
    )


BULK_ACTIONS = ("enable", "disable", "delete", "reset-traffic", "extend-expiry")


@router.post("/users/bulk")
async def bulk_users(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Bulk ops on the selected users (Phase 2).

    ``action`` comes from the clicked submit button; ``extend-expiry``
    also needs ``extend_days``. Every action can change usability
    (a reset user is back under quota, an extended user un-expires),
    so configs are re-rendered once at the end.
    """
    t = t_for(get_lang(request))
    form = await request.form()
    ids: set[int] = set()
    for raw in form.getlist("user_ids"):
        try:
            ids.add(int(raw))
        except (TypeError, ValueError):
            continue
    if not ids:
        return _redirect("/users", request, err=t["no_users_selected"])
    action = (form.get("action") or "").strip()
    if action not in BULK_ACTIONS:
        return _redirect("/users", request, err=t["invalid_action"])
    users = db.query(User).filter(User.id.in_(ids)).all()
    if not users:
        return _redirect("/users", request, err=t["no_users_selected"])
    extend_days: Optional[int] = None
    if action == "extend-expiry":
        try:
            extend_days = int((form.get("extend_days") or "").strip())
        except ValueError:
            return _redirect("/users", request, err=t["invalid_extend_days"])
        if not 1 <= extend_days <= EXTEND_DAYS_MAX:
            return _redirect("/users", request, err=t["invalid_extend_days"])
    now = datetime.now(timezone.utc)
    for user in users:
        if action == "enable":
            user.enabled = True
        elif action == "disable":
            user.enabled = False
        elif action == "delete":
            db.query(Client).filter(Client.user_id == user.id).delete()
            db.delete(user)
        elif action == "reset-traffic":
            user.traffic_used_bytes = 0
        elif action == "extend-expiry":
            assert extend_days is not None  # validated above
            base = user.expires_at
            if base is not None and base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            # Extend from the current expiry when it is still in the
            # future, else from now (an expired user must not stay
            # expired after an extension); never-expiring users get
            # now + N days.
            base = max(base, now) if base is not None else now
            user.expires_at = base + timedelta(days=extend_days)
    db.commit()
    _audit(db, admin.id, "user.bulk", f"{action} x{len(users)}")
    logger.info("bulk users: %s x%d", action, len(users))
    errors = rerender_configs(db)
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/users", request, msg=t["bulk_done"], err=err)
