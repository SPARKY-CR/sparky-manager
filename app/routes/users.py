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
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app import devices as devices_mod
from app import events as events_mod
from app import ip_limits as ip_limits_mod
from app import lifecycle as lifecycle_mod
from app import links as links_mod
from app import plans as plans_mod
from app import tags as tags_mod
from app.i18n import get_lang, t_for
from app.models import (
    Client,
    Device,
    Inbound,
    IpBan,
    User,
    UserLifecycle,
    UserTag,
    UserTemplate,
)
from app.webcommon import (
    NAME_RE,
    WEB_PATH,
    _audit,
    _client_is_frozen,
    _create_clients_for_user,
    _links_for_user,
    _next_awg_address,
    _next_wg_address,
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


def _delete_user_rows(db: Session, user: Any) -> None:
    """Delete a user and everything hanging off it: HWID devices
    (they reference the clients — deleted first), the lifecycle
    row, the tags, the clients, then the user row. Shared by the
    single delete and the bulk delete. Does not commit — the
    caller commits with the rest of its work."""
    client_ids = [
        row[0]
        for row in db.query(Client.id)
        .filter(Client.user_id == user.id)
        .all()
    ]
    if client_ids:
        db.query(Device).filter(
            Device.client_id.in_(client_ids)
        ).delete(synchronize_session=False)
    db.query(UserLifecycle).filter(
        UserLifecycle.user_id == user.id
    ).delete(synchronize_session=False)
    db.query(UserTag).filter(
        UserTag.user_id == user.id
    ).delete(synchronize_session=False)
    db.query(Client).filter(Client.user_id == user.id).delete()
    db.delete(user)


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

def _addable_inbounds(
    db: Session, user: Any
) -> list[Any]:
    """Enabled inbounds the user has no client on yet — any protocol,
    including shared ones (an inbound other users already use). Only
    enabled inbounds: a client on a disabled inbound renders nowhere,
    and new users never get one either (``_create_clients_for_user``
    skips disabled inbounds)."""
    taken = {
        row[0]
        for row in db.query(Client.inbound_id)
        .filter(Client.user_id == user.id)
        .all()
    }
    query = db.query(Inbound).filter(Inbound.enabled.is_(True))
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
                # Phase B item 17: per-client device limit (None =
                # no limit, feature off) + item 19: last fetch.
                "hwid_limit": devices_mod.get_hwid_limit(client),
                "last_fetch_at": extra.get("last_fetch_at")
                if isinstance(extra, dict)
                else None,
            }
        )
    return rows

def _user_edit_values(
    user: Any, rows: list[dict[str, Any]], lifecycle: Any = None
) -> dict[str, Any]:
    """Pre-filled values for the user edit form (user fields + one
    set of per-client fields per row, keyed ``flow_<id>`` /
    ``ip_limit_<id>`` / ``frozen_<id>`` / ``move_<id>`` /
    ``hwid_limit_<id>`` — plus the Phase B lifecycle fields when a
    lifecycle row exists)."""
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
        # Phase B items 10–11 (lifecycle): blank/"" means "not set".
        "expiry_strategy": (
            lifecycle.expiry_strategy if lifecycle is not None else "fixed"
        ),
        "usage_days": (
            str(lifecycle.usage_duration_days)
            if lifecycle is not None and lifecycle.usage_duration_days
            else ""
        ),
        "reset_cycle": (
            lifecycle.reset_cycle if lifecycle is not None else ""
        ) or "",
        "reset_day": (
            str(lifecycle.reset_day)
            if lifecycle is not None and lifecycle.reset_day
            else ""
        ),
        "renewal_mode": (
            lifecycle.renewal_mode if lifecycle is not None else ""
        ) or "",
        "renewal_interval_days": (
            str(lifecycle.renewal_interval_days)
            if lifecycle is not None and lifecycle.renewal_interval_days
            else ""
        ),
        "renewal_day": (
            str(lifecycle.renewal_day)
            if lifecycle is not None and lifecycle.renewal_day
            else ""
        ),
        "renewal_weekday": (
            str(lifecycle.renewal_weekday)
            if lifecycle is not None and lifecycle.renewal_weekday is not None
            else ""
        ),
        "renewal_max": (
            str(lifecycle.renewal_max)
            if lifecycle is not None and lifecycle.renewal_max is not None
            else ""
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
        values[f"hwid_limit_{cid}"] = (
            "" if row.get("hwid_limit") is None else str(row["hwid_limit"])
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
    """Render the user edit page (GET and POST-error re-render).

    Phase B items 10–11: the lifecycle summary (on-hold state,
    first use, lifetime usage, next reset) and the renewal
    schedule preview (computed from the SAVED lifecycle row, not
    from the submitted form — the preview answers "what happens
    with the current settings", and a mid-edit preview would be a
    guess about unsaved values).
    """
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    renewal_preview: list[str] = []
    next_reset: Optional[str] = None
    if lifecycle is not None:
        try:
            renewal_preview = [
                d.strftime("%Y-%m-%d")
                for d in lifecycle_mod.preview_renewals(lifecycle, user)
            ]
        except Exception:  # noqa: BLE001 — a bad row, no preview
            renewal_preview = []
        try:
            nxt = lifecycle_mod.next_reset_date(lifecycle, user)
            next_reset = nxt.strftime("%Y-%m-%d") if nxt else None
        except Exception:  # noqa: BLE001 — a bad row, no date
            next_reset = None
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
                "lifecycle": lifecycle,
                "lifetime_bytes": (
                    int(lifecycle.lifetime_bytes or 0)
                    if lifecycle is not None
                    else 0
                ),
                "on_hold": lifecycle_mod.is_on_hold(lifecycle),
                "next_reset": next_reset,
                "renewal_preview": renewal_preview,
                "reset_cycles": lifecycle_mod.RESET_CYCLES,
                "renewal_modes": lifecycle_mod.RENEWAL_MODES,
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
    tag: str = Query(""),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Users list with server-side search / filter / sort / pagination
    (Phase 4). All params are bookmarkable GET params; a bad value
    falls back to the default, never a 500 (``page`` is parsed by
    hand for exactly that reason — an ``int`` Query param would 422
    on ``?page=abc``)."""
    now = datetime.now(timezone.utc)
    # One user load (Phase 6 — audit Q6): the expired-ids set used
    # to re-query the whole table; it now derives from this load.
    all_users = db.query(User).all()
    total_users = len(all_users)
    users = list(all_users)

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
        for u in all_users
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

    # Phase B item 16: filter by tag (an unknown tag matches
    # nothing — the filter options only ever list real tags).
    tag = (tag or "").strip()
    if tag:
        tagged_ids = tags_mod.user_ids_with_tag(db, tag)
        users = [u for u in users if u.id in tagged_ids]

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
                # Phase B item 9: plan picker in the add-user form.
                "templates": db.query(UserTemplate).order_by(
                    UserTemplate.name
                ).all(),
                # Phase B item 16: tag filter options + chips.
                "tags": tags_mod.all_tags(db),
                "tag": tag,
                "tags_by_user": tags_mod.tags_by_user(db),
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
    template_id: str = Form(""),
    expiry_mode: str = Form(""),
    usage_days: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Create a user, optionally from a plan (Phase B item 9).

    Resolution order — explicit form values beat the plan: a typed
    traffic limit overrides the plan's quota; a typed expiry-days
    overrides the plan's expiry (as a fixed date); an explicit
    first-use choice overrides the plan's expiry mode. Empty form
    fields fall back to the plan; with no plan, empty means
    unlimited / never expires (the old behaviour).
    """
    lang = get_lang(request)
    t = t_for(lang)
    name = name.strip()
    if not NAME_RE.match(name):
        return _redirect("/users", request, err=t["invalid_name"])
    if db.query(User).filter(User.name == name).first() is not None:
        return _redirect("/users", request, err=t["name_exists"])
    template: Optional[UserTemplate] = None
    if (template_id or "").strip():
        try:
            template = db.get(UserTemplate, int(template_id.strip()))
        except ValueError:
            template = None
        if template is None:
            return _redirect("/users", request, err=t["invalid_plan"])
    form_limit_bytes: Optional[int] = None
    form_limit_given = bool(traffic_limit_gb.strip())
    if form_limit_given:
        try:
            form_limit_bytes = int(float(traffic_limit_gb) * 1024**3)
            if form_limit_bytes <= 0:
                form_limit_bytes = None
        except ValueError:
            return _redirect("/users", request, err=t["traffic_limit_gb"])
    form_expires_days: Optional[int] = None
    if expires_days.strip():
        try:
            form_expires_days = int(expires_days)
            if form_expires_days <= 0:
                form_expires_days = None
        except ValueError:
            return _redirect("/users", request, err=t["expires_days"])
    expiry_mode = (expiry_mode or "").strip()
    if expiry_mode not in ("", "fixed", "first_use"):
        expiry_mode = ""
    usage_days_n: Optional[int] = None
    if usage_days.strip():
        try:
            usage_days_n = int(usage_days)
            if usage_days_n <= 0:
                usage_days_n = None
        except ValueError:
            return _redirect("/users", request, err=t["expires_days"])
    if expiry_mode == "first_use" and usage_days_n is None:
        # Fall back to the plan's duration when the plan is
        # first-use; otherwise first-use has no clock to start.
        if template is not None and template.expiry_mode == "first_use":
            usage_days_n = template.expiry_days
        if usage_days_n is None or usage_days_n <= 0:
            return _redirect("/users", request, err=t["first_use_needs_days"])
    user = User(
        name=name,
        note=note.strip() or None,
        enabled=True,
        traffic_limit_bytes=None,
        traffic_used_bytes=0,
        expires_at=None,
        sub_token=secrets.token_urlsafe(24),
    )
    db.add(user)
    db.commit()
    # The plan goes on first (quota / expiry / reset cycle /
    # inbound set); the form overrides below win over it.
    inbound_ids: Optional[set] = None
    if template is not None:
        inbound_ids = plans_mod.apply_template_to_user(db, user, template)
    if form_limit_given:
        user.traffic_limit_bytes = form_limit_bytes
    if expiry_mode == "first_use":
        assert usage_days_n is not None  # validated above
        lifecycle = lifecycle_mod.get_or_create_lifecycle(db, user.id)
        lifecycle.expiry_strategy = "first_use"
        lifecycle.usage_duration_days = int(usage_days_n)
        lifecycle.first_use_at = None
        user.expires_at = None
    elif form_expires_days is not None:
        # A fixed expiry from the form clears any first-use plan
        # (the plan's lifecycle row would otherwise re-arm the
        # clock at first fetch).
        lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
        if lifecycle is not None:
            lifecycle.expiry_strategy = "fixed"
            lifecycle.usage_duration_days = None
            lifecycle.first_use_at = None
        user.expires_at = datetime.now(timezone.utc) + timedelta(
            days=form_expires_days
        )
    db.commit()
    _create_clients_for_user(db, user, inbound_ids=inbound_ids)
    _audit(db, admin.id, "user.create", name)
    logger.info("user created: %s", name)
    # Phase A event bus: user creation is a selectable event
    # (``user.created``); a user created twice in a row is two
    # real events, so no dedup key.
    events_mod.notify_event(
        db, "user.created", t["tg_user_created"].format(name=name)
    )
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
    # the user-level frozen flag (all clients frozen). Phase B adds
    # the device limit + last fetch per client (from `extra` too).
    rows = _user_client_rows(db, user, with_moves=False)
    client_extra = {
        row["client"].id: {
            "frozen": row["frozen"],
            "ip_limit": row["ip_limit"],
            "hwid_limit": row["hwid_limit"],
            "last_fetch_at": row["last_fetch_at"],
        }
        for row in rows
    }
    frozen = bool(rows) and all(row["frozen"] for row in rows)
    # Phase B items 10–11/16/17: lifecycle summary, tags, devices.
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    next_reset: Optional[str] = None
    renewal_preview: list[str] = []
    if lifecycle is not None:
        try:
            nxt = lifecycle_mod.next_reset_date(lifecycle, user)
            next_reset = nxt.strftime("%Y-%m-%d") if nxt else None
        except Exception:  # noqa: BLE001 — a bad row, no date
            next_reset = None
        try:
            renewal_preview = [
                d.strftime("%Y-%m-%d")
                for d in lifecycle_mod.preview_renewals(lifecycle, user)
            ]
        except Exception:  # noqa: BLE001 — a bad row, no preview
            renewal_preview = []
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
                "addable_inbounds": _addable_inbounds(db, user),
                "frozen": frozen,
                "links": links,
                "links_available": True,
                "sub_url": f"{base}/sub/{user.sub_token}",
                "zedsecure_url": f"{base}/sub/{user.sub_token}/zedsecure.json",
                "zedsecure_deeplink": links_mod.zedsecure_deep_link(
                    f"{base}/sub/{user.sub_token}", user.name
                ),
                "user_url": f"{base}/u/{user.sub_token}",
                "file_urls": _file_export_urls(db, user, base),
                "host": host,
                "user_traffic_chart": user_traffic_chart,
                "user_traffic_14d": user_traffic_14d,
                "lifecycle": lifecycle,
                "lifetime_bytes": (
                    int(lifecycle.lifetime_bytes or 0)
                    if lifecycle is not None
                    else 0
                ),
                "on_hold": lifecycle_mod.is_on_hold(lifecycle),
                "next_reset": next_reset,
                "renewal_preview": renewal_preview,
                "tags": tags_mod.tags_for_user(db, user.id),
                "devices": devices_mod.devices_for_user(db, user.id),
                # Phase C item 20: active IP-limit bans, with the
                # user's effective limit (min over Xray-core
                # clients — None when no limit is set anywhere).
                "ip_bans": ip_limits_mod.active_bans(db, user.id),
                "effective_ip_limit": ip_limits_mod.effective_ip_limit(
                    db, user
                ),
            },
        ),
    )


@router.post("/users/{user_id}/ip-bans/{ban_id}/unban")
def unban_ip(
    request: Request,
    user_id: int,
    ban_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Lift one IP-limit ban early (Phase C item 20): fail2ban
    unban + delete the row. The job re-bans on the next tick if
    the IP is still over the user's limit — unban is a reprieve,
    not an exemption (raise the limit for that)."""
    t = t_for(get_lang(request))
    ban = db.get(IpBan, ban_id)
    if ban is None or ban.user_id != user_id:
        return _redirect(
            f"/users/{user_id}", request, err=t["ip_ban_not_found"]
        )
    ip = ban.ip
    ok = ip_limits_mod.unban_ip(db, ban)
    _audit(db, admin.id, "ip_limit.unban", f"user {user_id}: {ip}")
    if ok:
        return _redirect(
            f"/users/{user_id}", request, msg=t["ip_unbanned"]
        )
    return _redirect(
        f"/users/{user_id}",
        request,
        err=t["ip_unban_failed"],
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
    _delete_user_rows(db, user)
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


@router.post("/users/{user_id}/add-inbound")
def add_user_to_inbound(
    request: Request,
    user_id: int,
    inbound_id: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Add an existing user to another inbound (any protocol,
    including shared ones). The client is created by the same
    ``_create_clients_for_user`` new users go through — fresh
    credentials for the inbound's protocol, WireGuard/AmneziaWG
    address from the inbound's subnet — restricted to the one
    inbound. The (user, inbound) uniqueness rule is enforced by
    the picker and re-checked here."""
    t = t_for(get_lang(request))
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    try:
        target_id = int((inbound_id or "").strip())
    except ValueError:
        return _redirect(f"/users/{user_id}", request, err=t["invalid_inbound"])
    target = db.get(Inbound, target_id)
    if target is None or not target.enabled:
        return _redirect(f"/users/{user_id}", request, err=t["invalid_inbound"])
    existing = (
        db.query(Client)
        .filter(Client.user_id == user.id, Client.inbound_id == target.id)
        .first()
    )
    if existing is not None:
        return _redirect(f"/users/{user_id}", request, err=t["already_on_inbound"])
    # Pre-check the WG/AWG address pool (mirrors the move flow): a
    # full pool fails before any write, instead of creating a client
    # with no allowed_ips.
    if target.protocol in ("wireguard", "amneziawg"):
        subnet = (target.stream or {}).get("subnet") or (
            "10.8.0.0/24" if target.protocol == "wireguard" else "10.8.1.0/24"
        )
        try:
            if target.protocol == "wireguard":
                _next_wg_address(db, subnet, inbound_id=target.id)
            else:
                _next_awg_address(db, subnet, inbound_id=target.id)
        except ValueError:
            return _redirect(
                f"/users/{user_id}",
                request,
                err=t["add_inbound_address_exhausted"],
            )
    _create_clients_for_user(db, user, inbound_ids={target.id})
    _audit(db, admin.id, "user.add_inbound", f"{user.name} -> {target.tag}")
    logger.info("user added to inbound: %s -> %s", user.name, target.tag)
    errors = rerender_configs(db)
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(
        f"/users/{user_id}", request, msg=t["user_inbound_added"], err=err
    )


@router.post("/users/{user_id}/detach/{client_id}")
def detach_user_from_inbound(
    request: Request,
    user_id: int,
    client_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Detach the user from ONE inbound (delete just that client).

    The last client may be detached too: zero-client users are
    already a normal state in the codebase (fresh installs start
    with no inbounds, so a new user has zero clients; deleting an
    inbound deletes its clients, which can leave users at zero),
    both pages render that state, and add-to-inbound makes the
    detach fully reversible. The confirmation dialog carries a
    distinct warning when it is the last client."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    client = (
        db.query(Client)
        .filter(Client.id == client_id, Client.user_id == user.id)
        .first()
    )
    if client is None:
        raise HTTPException(status_code=404, detail="client not found")
    inbound = db.get(Inbound, client.inbound_id)
    tag = inbound.tag if inbound is not None else str(client.inbound_id)
    db.delete(client)
    db.commit()
    _audit(db, admin.id, "user.detach_inbound", f"{user.name} from {tag}")
    logger.info("user detached from inbound: %s from %s", user.name, tag)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(
        f"/users/{user_id}", request, msg=t["user_inbound_detached"], err=err
    )


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
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    return _render_user_edit(
        request, user, _user_edit_values(user, rows, lifecycle), rows, db=db
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

    # Phase B items 10–11 (lifecycle). A missing field keeps the
    # stored value (the form always sends them, but a partial POST
    # — e.g. an older bot flow — must not wipe the lifecycle).
    lifecycle = lifecycle_mod.get_lifecycle(db, user.id)
    strategy = (data.get("expiry_strategy") or "").strip()
    if not strategy:
        strategy = (
            lifecycle.expiry_strategy if lifecycle is not None else "fixed"
        )
    if strategy not in lifecycle_mod.EXPIRY_STRATEGIES:
        return _error(t["invalid_expiry_strategy"])
    usage_days: Optional[int] = None
    if (data.get("usage_days") or "").strip():
        try:
            usage_days = int(data["usage_days"])
            if usage_days <= 0:
                usage_days = None
        except ValueError:
            return _error(t["expires_days"])
    elif lifecycle is not None:
        usage_days = lifecycle.usage_duration_days
    clock_started = lifecycle is not None and lifecycle.first_use_at is not None
    if strategy == "first_use" and not clock_started and not usage_days:
        return _error(t["first_use_needs_days"])
    reset_cycle = (data.get("reset_cycle") or "").strip()
    if not reset_cycle and "reset_cycle" not in data and lifecycle is not None:
        reset_cycle = lifecycle.reset_cycle or ""
    if reset_cycle and reset_cycle not in lifecycle_mod.RESET_CYCLES:
        return _error(t["invalid_reset_cycle"])
    reset_day: Optional[int] = None
    if (data.get("reset_day") or "").strip():
        try:
            reset_day = int(data["reset_day"])
            if not 1 <= reset_day <= lifecycle_mod.RESET_DAY_MAX:
                raise ValueError
        except ValueError:
            return _error(t["invalid_reset_day"])
    elif lifecycle is not None:
        reset_day = lifecycle.reset_day
    renewal_mode = (data.get("renewal_mode") or "").strip()
    if not renewal_mode and "renewal_mode" not in data and lifecycle is not None:
        renewal_mode = lifecycle.renewal_mode or ""
    if renewal_mode and renewal_mode not in lifecycle_mod.RENEWAL_MODES:
        return _error(t["invalid_renewal_mode"])
    renewal_interval_days: Optional[int] = None
    if (data.get("renewal_interval_days") or "").strip():
        try:
            renewal_interval_days = int(data["renewal_interval_days"])
            if renewal_interval_days <= 0:
                renewal_interval_days = None
        except ValueError:
            return _error(t["invalid_renewal_interval"])
    elif lifecycle is not None:
        renewal_interval_days = lifecycle.renewal_interval_days
    renewal_day: Optional[int] = None
    if (data.get("renewal_day") or "").strip():
        try:
            renewal_day = int(data["renewal_day"])
            if not 1 <= renewal_day <= lifecycle_mod.RESET_DAY_MAX:
                raise ValueError
        except ValueError:
            return _error(t["invalid_renewal_day"])
    elif lifecycle is not None:
        renewal_day = lifecycle.renewal_day
    renewal_weekday: Optional[int] = None
    if (data.get("renewal_weekday") or "").strip():
        try:
            renewal_weekday = int(data["renewal_weekday"])
            if not 0 <= renewal_weekday <= 6:
                raise ValueError
        except ValueError:
            return _error(t["invalid_renewal_weekday"])
    elif lifecycle is not None:
        renewal_weekday = lifecycle.renewal_weekday
    renewal_max: Optional[int] = None
    if (data.get("renewal_max") or "").strip():
        try:
            renewal_max = int(data["renewal_max"])
            if renewal_max <= 0:
                raise ValueError
        except ValueError:
            return _error(t["invalid_renewal_max"])
    elif lifecycle is not None:
        renewal_max = lifecycle.renewal_max
    if renewal_mode == "rolling" and not renewal_interval_days:
        return _error(t["invalid_renewal_interval"])
    if renewal_mode == "calendar_day" and not renewal_day:
        return _error(t["invalid_renewal_day"])
    if renewal_mode == "calendar_weekday" and renewal_weekday is None:
        return _error(t["invalid_renewal_weekday"])

    planned: list[tuple[Any, str, Optional[int], Optional[int], bool, Any]] = []
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
        # Phase B item 17: device limit (same rule as the IP limit).
        hwid_limit: Optional[int] = row.get("hwid_limit")
        if f"hwid_limit_{cid}" in data:
            try:
                hwid_limit = devices_mod.parse_hwid_limit(data[f"hwid_limit_{cid}"])
            except ValueError:
                return _error(t["invalid_hwid_limit"])
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
        planned.append((client, flow, ip_limit, hwid_limit, frozen, target))

    # --- pass 2: apply ---
    user.name = name
    user.note = (data.get("note") or "").strip() or None
    user.traffic_limit_bytes = limit_bytes
    # First-use wins over a typed expiry date while the clock has
    # not started yet (the date field is meaningless until the
    # clock runs — the clock sets the date at first use). Once the
    # clock HAS started, the date stands (it is the clock's output).
    if strategy == "first_use" and not clock_started:
        expires_at = None
    user.expires_at = expires_at
    # Phase B items 10–11: persist the lifecycle row. A row is
    # created only when a feature is actually set (a plain user
    # stays row-less); an existing row is updated in place (its
    # lifetime counter and renewal count survive an edit).
    any_lifecycle = (
        strategy == "first_use" or bool(reset_cycle) or bool(renewal_mode)
    )
    if any_lifecycle and lifecycle is None:
        lifecycle = lifecycle_mod.get_or_create_lifecycle(db, user.id)
    if lifecycle is not None:
        lifecycle.expiry_strategy = strategy
        lifecycle.usage_duration_days = usage_days
        lifecycle.reset_cycle = reset_cycle or None
        lifecycle.reset_day = reset_day
        lifecycle.renewal_mode = renewal_mode or None
        lifecycle.renewal_interval_days = renewal_interval_days
        lifecycle.renewal_day = renewal_day
        lifecycle.renewal_weekday = renewal_weekday
        lifecycle.renewal_max = renewal_max
    for client, flow, ip_limit, hwid_limit, frozen, target in planned:
        client.flow = flow or None
        _set_client_extra(client, "ip_limit", ip_limit)
        devices_mod.set_hwid_limit(client, hwid_limit)
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
            _delete_user_rows(db, user)
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
