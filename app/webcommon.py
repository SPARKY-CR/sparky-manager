"""Shared web plumbing for the panel (Phase 5 split).

Everything the HTML routes share — session/auth, CSRF, template and
redirect helpers, settings/audit accessors, usability helpers, link
builders, client credential/address helpers, Telegram notifications,
traffic charts — moved out of ``app/main.py`` so the route modules
(``app/routes/*``) can import it without importing ``main`` (which
would be circular: ``main`` mounts the routers).

``main.py`` re-exports every public-ish name defined here, so
``main_mod.<name>`` references (remaining routes, bot, tests) keep
working unchanged.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import re
import secrets
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import charts as charts_mod
from app import config as panel_config
from app import links as links_mod
from app import telegram as telegram_mod
from app import wireguard as wireguard_mod
from app.auth import csrf_token_for_session, get_admin_from_token, verify_csrf_token
from app.config import normalize_web_path
from app.db import get_session
from app.i18n import get_lang, t_for
from app.models import (
    AuditLog,
    Client,
    Inbound,
    Setting,
    TrafficDaily,
    client_is_frozen,
    client_is_usable,
)

logger = logging.getLogger("sparky-manager")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"


def _web_prefix() -> str:
    """Secret panel web path: "" (panel at root) or "/<segment>"."""
    raw = getattr(panel_config, "WEB_PATH", "") or ""
    try:
        return normalize_web_path(str(raw))
    except ValueError:
        logger.warning("invalid SPARKY_WEB_PATH %r; panel served at root", raw)
        return ""


WEB_PATH = _web_prefix()


SESSION_COOKIE = "sparky_manager_session"

SESSION_MAX_AGE = 12 * 3600  # 12 hours

NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------


def get_settings(db: Session) -> dict[str, str]:
    """All panel settings as a plain dict.

    Base layer: ``app.config.get_settings_dict()`` (environment /
    installer defaults). Overlay: the ``Setting`` table rows — the
    settings page and ``ensure_defaults()`` write there, and a row
    present in the DB always wins over the env default (an empty DB
    value means "cleared", so it wins too). This is what makes the
    domain / Reality-key / WireGuard-key settings actually take effect
    instead of being shadowed by env defaults.
    """
    merged: dict[str, str] = {}
    if hasattr(panel_config, "get_settings_dict"):
        try:
            result = panel_config.get_settings_dict()
            if isinstance(result, dict):
                merged = {
                    str(k): ("" if v is None else str(v)) for k, v in result.items()
                }
        except Exception:  # noqa: BLE001
            logger.exception("get_settings_dict() failed; reading Setting table")
    for row in db.query(Setting).all():
        merged[row.key] = row.value or ""
    return merged

def get_setting(db: Session, key: str, default: str = "") -> str:
    """One setting value, ``default`` when unset/empty."""
    value = get_settings(db).get(key, "")
    return value if value else default

def set_setting(db: Session, key: str, value: str) -> None:
    """Upsert one setting row."""
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
    db.commit()

def _audit(db: Session, admin_id: Optional[int], action: str, detail: str = "") -> None:
    """Best-effort audit-log write; never breaks the request."""
    try:
        db.add(AuditLog(admin_id=admin_id, action=action, detail=detail))
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("audit log write failed for %s", action)

def _usable_clients(db: Session, user: Any) -> list[tuple[Any, Any]]:
    """``(client, inbound)`` pairs usable for ``user`` (inbound order)."""
    out: list[tuple[Any, Any]] = []
    clients = (
        db.query(Client)
        .filter(Client.user_id == user.id)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .order_by(Inbound.port)
        .all()
    )
    for client in clients:
        inbound = db.query(Inbound).filter(Inbound.id == client.inbound_id).first()
        if inbound is not None and client_is_usable(client, user, inbound):
            out.append((client, inbound))
    return out

def _sub_host(request: Request, settings: dict[str, str]) -> str:
    """Host used in share links / subscriptions.

    Explicit ``subscription_host`` setting wins, then the configured
    domain, then the host the request arrived on (bare IP works).
    """
    host = (settings.get("subscription_host") or "").strip()
    if host:
        return host
    domain = (settings.get("domain") or "").strip()
    if domain:
        return domain
    return request.url.hostname or "127.0.0.1"

def _client_dict(client: Any, user: Any) -> dict[str, Any]:
    """Plain dict for a client row, as the link builders expect."""
    extra: dict[str, Any] = {}
    raw_extra = getattr(client, "extra_json", None)
    if raw_extra:
        try:
            extra = json.loads(raw_extra) if isinstance(raw_extra, str) else dict(raw_extra)
        except (ValueError, TypeError):
            extra = {}
    return {
        "id": client.id,
        "user_id": client.user_id,
        "user_name": getattr(user, "name", ""),
        "uuid": getattr(client, "uuid", None),
        "password": getattr(client, "password", None),
        "method": getattr(client, "method", None),
        "flow": getattr(client, "flow", None),
        # Link builders / renderers read "extra_json" (dict or JSON str).
        "extra_json": extra,
        "extra": extra,
    }

def _inbound_dict(inbound: Any) -> dict[str, Any]:
    """Plain dict for an inbound row, as the link builders expect."""
    stream: dict[str, Any] = {}
    raw = getattr(inbound, "stream_json", None)
    if raw:
        try:
            stream = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (ValueError, TypeError):
            stream = {}
    return {
        "id": inbound.id,
        "tag": inbound.tag,
        "core": inbound.core,
        "protocol": inbound.protocol,
        "port": inbound.port,
        "enabled": inbound.enabled,
        "remark": getattr(inbound, "remark", "") or "",
        # Link builders / renderers read "stream_json" (a dict here).
        "stream_json": stream,
        "stream": stream,
    }

def _links_for_user(
    db: Session, user: Any, host: str, settings: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Share links for one user's usable clients."""
    links: list[dict[str, Any]] = []
    for client, inbound in _usable_clients(db, user):
        try:
            inbound_dict = _inbound_dict(inbound)
            if inbound.protocol == "amneziawg":
                # The vpn:// link needs the server public key, which
                # lives in settings (like WireGuard's) — hand it to
                # the link builder through the inbound stream, where
                # build_share_link looks for it.
                stream = dict(inbound_dict.get("stream_json") or {})
                stream.setdefault(
                    "awg_server_public_key",
                    (settings or {}).get("amneziawg_public_key") or "",
                )
                inbound_dict["stream_json"] = stream
            link = links_mod.build_share_link(
                inbound.protocol,
                _client_dict(client, user),
                inbound_dict,
                host,
                user.name,
            )
        except Exception:  # noqa: BLE001
            logger.exception("build_share_link failed for %s", inbound.tag)
            continue
        if link:
            links.append(
                {"inbound": inbound, "client": client, "link": str(link)}
            )
    return links

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

def db_session():
    """FastAPI dependency yielding a DB session.

    ``app.db.get_session()`` is a ``@contextmanager`` (not a plain
    generator), so ``yield from`` on it raises TypeError — enter it
    with ``with`` instead.
    """
    with get_session() as db:
        yield db

def _admin_from_request(request: Request, db: Session) -> Optional[Any]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        return get_admin_from_token(db, token)
    except Exception:  # noqa: BLE001
        logger.exception("session lookup failed")
        return None

def require_admin(request: Request, db: Session = Depends(db_session)) -> Any:
    """HTML auth dependency: redirect to /login when not signed in."""
    admin = _admin_from_request(request, db)
    if admin is None:
        lang = get_lang(request)
        raise HTTPException(status_code=303, headers={"Location": f"/login?lang={lang}"})
    return admin

def require_admin_api(request: Request, db: Session = Depends(db_session)) -> Any:
    """JSON API auth dependency: 401 when not signed in."""
    admin = _admin_from_request(request, db)
    if admin is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return admin

CSRF_FORM_FIELD = "csrf_token"

CSRF_HEADER = "X-CSRF-Token"

class CSRFError(Exception):
    """Raised when CSRF validation fails (missing/wrong token)."""

async def _check_csrf_token(request: Request) -> None:
    """Validate the CSRF token for this request's session.

    Fails closed: any missing piece (no session cookie, no submitted
    token, unparseable form) raises CSRFError. The session itself was already validated by the auth
    dependency this runs under, so the cookie token here is a live
    session's token.
    """
    session_token = request.cookies.get(SESSION_COOKIE)
    submitted = request.headers.get(CSRF_HEADER)
    if submitted is None:
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001 — malformed body: no token
            form = None
        if form is not None:
            value = form.get(CSRF_FORM_FIELD)
            submitted = value if isinstance(value, str) else None
    if (
        not session_token
        or not submitted
        or not verify_csrf_token(session_token, submitted)
    ):
        raise CSRFError()

async def require_csrf(
    request: Request, admin: Any = Depends(require_admin)
) -> None:
    """CSRF dependency for HTML form POSTs (auth: 303 redirect)."""
    await _check_csrf_token(request)

async def require_csrf_api(
    request: Request, admin: Any = Depends(require_admin_api)
) -> None:
    """CSRF dependency for the JSON API (auth: 401, token via header)."""
    await _check_csrf_token(request)

def _template_ctx(request: Request, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    lang = get_lang(request)
    # CSRF token for the session cookie ("" when logged out — the
    # login form carries no token; see the S1 note above require_csrf).
    # Deriving from an arbitrary cookie value is harmless: the POST
    # check requires a *valid* session anyway.
    session_token = request.cookies.get(SESSION_COOKIE)
    csrf_token = (
        csrf_token_for_session(session_token) if session_token else ""
    )
    ctx: dict[str, Any] = {
        "request": request,
        "lang": lang,
        "t": t_for(lang),
        "base_path": WEB_PATH,
        "msg": request.query_params.get("msg", ""),
        "err": request.query_params.get("err", ""),
        "csrf_token": csrf_token,
    }
    if extra:
        ctx.update(extra)
    return ctx

def _redirect(url: str, request: Request, msg: str = "", err: str = "") -> RedirectResponse:
    """303 redirect preserving ?lang= when English, plus ?msg=/?err=."""
    sep = "&" if "?" in url else "?"
    target = WEB_PATH + url
    if get_lang(request) == "en":
        target += f"{sep}lang=en"
        sep = "&"
    if msg:
        from urllib.parse import quote

        target += f"{sep}msg={quote(msg)}"
        sep = "&"
    if err:
        from urllib.parse import quote

        target += f"{sep}err={quote(err[:500])}"
    response = RedirectResponse(url=target, status_code=303)
    if request.query_params.get("lang") in ("fa", "en"):
        response.set_cookie("lang", request.query_params["lang"], max_age=365 * 86400)
    return response

def _ss2022_password() -> str:
    """A valid Shadowsocks-2022 key: base64 of 16 random bytes for
    ``2022-blake3-aes-128-gcm``. A random token string is NOT a valid
    key — Xray rejects it at load (``bad key``) and sing-box does the
    same, so SS/ShadowTLS clients must get a real key, not a password
    (coordinator fix, 2026-11-11, verified against Xray 26.11.9)."""
    return base64.b64encode(secrets.token_bytes(16)).decode()

def _new_client_credentials(inbound: Any) -> dict[str, Any]:
    """Fresh credentials for one client of ``inbound``'s protocol."""
    protocol = inbound.protocol
    creds: dict[str, Any] = {"enabled": True}
    if protocol in ("vless", "vmess", "tuic"):
        creds["uuid"] = str(uuid.uuid4())
        creds["password"] = secrets.token_urlsafe(12)
    elif protocol in ("trojan", "hysteria2", "anytls", "naive"):
        creds["password"] = secrets.token_urlsafe(16)
    elif protocol == "shadowsocks":
        creds["password"] = _ss2022_password()
        creds["method"] = "2022-blake3-aes-128-gcm"
    elif protocol == "shadowtls":
        # ShadowTLS detours to an inner Shadowsocks inbound, so the
        # client needs the same cipher method or its share link is
        # skipped from the v2rayNG feed (coordinator fix, 2026-11-11).
        creds["password"] = _ss2022_password()
        creds["method"] = "2022-blake3-aes-128-gcm"
    elif protocol == "wireguard":
        # generate_keypair() -> (private_key, public_key) tuple.
        # Private key goes in `password`, public key in `uuid` (the
        # field the WG renderer / traffic map read as the peer key).
        if hasattr(wireguard_mod, "generate_keypair"):
            try:
                pair = wireguard_mod.generate_keypair()
                if isinstance(pair, dict):
                    creds["password"] = pair.get("private_key") or pair.get("private")
                    creds["uuid"] = pair.get("public_key") or pair.get("public")
                elif isinstance(pair, (list, tuple)) and len(pair) >= 2:
                    creds["password"], creds["uuid"] = str(pair[0]), str(pair[1])
                else:
                    creds["password"] = str(pair)
            except Exception:  # noqa: BLE001
                logger.exception("wireguard keypair generation failed")
                creds["password"] = secrets.token_urlsafe(24)
                creds["uuid"] = None
        else:
            creds["password"] = secrets.token_urlsafe(24)
            creds["uuid"] = None
    elif protocol == "amneziawg":
        # Same key layout as WireGuard (private in `password`, public
        # in `uuid`); the AWG renderer reads the same fields.
        if hasattr(wireguard_mod, "generate_keypair"):
            try:
                pair = wireguard_mod.generate_keypair()
                if isinstance(pair, dict):
                    creds["password"] = pair.get("private_key") or pair.get("private")
                    creds["uuid"] = pair.get("public_key") or pair.get("public")
                elif isinstance(pair, (list, tuple)) and len(pair) >= 2:
                    creds["password"], creds["uuid"] = str(pair[0]), str(pair[1])
                else:
                    creds["password"] = str(pair)
            except Exception:  # noqa: BLE001
                logger.exception("amneziawg keypair generation failed")
                creds["password"] = secrets.token_urlsafe(24)
                creds["uuid"] = None
        else:
            creds["password"] = secrets.token_urlsafe(24)
            creds["uuid"] = None
    elif protocol in ("openvpn", "openconnect", "ikev2"):
        # Username/password auth: the username is the panel user name
        # (read from the client dict at render time), the password is
        # stored here. OpenVPN checks it via scripts/ovpn-auth.py,
        # ocserv via the ocpasswd file, IKEv2 via the EAP secrets in
        # swanctl.conf.
        creds["password"] = secrets.token_urlsafe(16)
    else:
        creds["uuid"] = str(uuid.uuid4())
        creds["password"] = secrets.token_urlsafe(12)
    if protocol == "vless":
        creds["flow"] = "xtls-rprx-vision"
    return creds

def _next_pool_address(
    db: Session,
    *,
    protocol: str,
    subnet: str,
    inbound_id: int | None = None,
) -> str:
    """Next free peer address inside ``subnet`` for ``protocol``.

    Scans the ``allowed_ips`` stored in existing clients'
    ``extra_json`` (of this inbound when ``inbound_id`` is given,
    else of every inbound of the protocol) and returns the first
    free host address as ``<ip>/32``. The server itself holds the
    first host address (``.1`` — see :func:`_subnet_server_address`),
    so allocation starts at the second host; the broadcast address
    is never handed out. Raises ``ValueError`` when the pool is
    exhausted.
    """
    net = ipaddress.ip_network(subnet, strict=False)
    query = (
        db.query(Client.extra_json)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .filter(Inbound.protocol == protocol)
    )
    if inbound_id is not None:
        query = query.filter(Inbound.id == inbound_id)
    used: set[ipaddress.IPv4Address] = set()
    for (raw,) in query.all():
        if not raw:
            continue
        try:
            extra = json.loads(raw) if isinstance(raw, str) else dict(raw)
            allowed = str(extra.get("allowed_ips") or "")
        except (ValueError, TypeError):
            continue
        for part in allowed.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                addr = ipaddress.ip_interface(part).ip
            except ValueError:
                continue
            if addr in net:
                used.add(addr)
    for host in net.hosts():
        # The first host is the server's own address.
        if host == net.network_address + 1:
            continue
        if host not in used:
            return f"{host}/32"
    raise ValueError(f"{protocol} address pool ({subnet}) exhausted")

def _next_wg_address(
    db: Session,
    subnet: str = "10.8.0.0/24",
    inbound_id: int | None = None,
) -> str:
    """Next free WireGuard peer address (10.8.0.2/32 … 10.8.0.254/32
    for the default subnet).

    The subnet comes from the inbound's stream (editable since the
    Phase 1 inbound editor); the default keeps the old behaviour
    for inbounds created before the editor existed.
    """
    return _next_pool_address(
        db, protocol="wireguard", subnet=subnet, inbound_id=inbound_id
    )

def _next_awg_address(
    db: Session,
    subnet: str = "10.8.1.0/24",
    inbound_id: int | None = None,
) -> str:
    """Next free AmneziaWG peer address (10.8.1.2/32 … 10.8.1.254/32
    for the default subnet).

    A separate pool from WireGuard (10.8.0.0/24) — the two
    interfaces (wg0 / awg0) must never hand out the same address.
    The subnet comes from the inbound's stream (editable since the
    Phase 1 inbound editor).
    """
    return _next_pool_address(
        db, protocol="amneziawg", subnet=subnet, inbound_id=inbound_id
    )

def _create_clients_for_user(
    db: Session, user: Any, inbound_ids: Optional[set] = None
) -> None:
    """One client row per enabled inbound for a new user.

    ``inbound_ids`` (Phase 4, Telegram bot) restricts the clients to
    the given inbounds — ``None`` keeps the web behaviour (every
    enabled inbound). A listed inbound that is disabled or missing
    gets no client.
    """
    query = db.query(Inbound).filter(Inbound.enabled.is_(True))
    if inbound_ids is not None:
        query = query.filter(Inbound.id.in_(sorted(inbound_ids)))
    for inbound in query.all():
        creds = _new_client_credentials(inbound)
        extra_json: Optional[str] = None
        if inbound.protocol == "wireguard":
            # The WG renderer needs allowed_ips per peer; allocate
            # one from the inbound's own subnet (editable in the
            # inbound editor; 10.8.0.0/24 for older inbounds).
            subnet = inbound.stream.get("subnet") or "10.8.0.0/24"
            try:
                address = _next_wg_address(db, subnet, inbound_id=inbound.id)
                extra_json = json.dumps({"allowed_ips": address})
            except ValueError:
                logger.warning("no free WireGuard address for user %s", user.name)
        if inbound.protocol == "amneziawg":
            # Same idea, separate pool (10.8.1.0/24 — never the WG pool).
            subnet = inbound.stream.get("subnet") or "10.8.1.0/24"
            try:
                address = _next_awg_address(db, subnet, inbound_id=inbound.id)
                extra_json = json.dumps({"allowed_ips": address})
            except ValueError:
                logger.warning("no free AmneziaWG address for user %s", user.name)
        db.add(
            Client(
                user_id=user.id,
                inbound_id=inbound.id,
                uuid=creds.get("uuid"),
                password=creds.get("password"),
                method=creds.get("method"),
                flow=creds.get("flow"),
                extra_json=extra_json,
                enabled=True,
            )
        )
        db.flush()  # so a second WireGuard inbound sees this peer's IP
    db.commit()

def _set_client_extra(client: Any, key: str, value: Any) -> None:
    """Set (or, for ``None``, remove) one key in a client's ``extra``
    JSON. Read-modify-write through the model property so other keys
    (e.g. ``allowed_ips``) are preserved."""
    extra = dict(getattr(client, "extra", None) or {})
    if value is None:
        extra.pop(key, None)
    else:
        extra[key] = value
    client.extra = extra

def _set_client_frozen(client: Any, frozen: bool) -> None:
    """Freeze/unfreeze one client (``extra.frozen``). A frozen client
    is unusable (see :func:`app.models.client_is_frozen`) but keeps
    its credentials, config and traffic history."""
    _set_client_extra(client, "frozen", True if frozen else None)

def _client_is_frozen(client: Any) -> bool:
    """Frozen flag for one client (model helper, with a direct
    ``extra`` read as fallback — same rule either way)."""
    try:
        return bool(client_is_frozen(client))
    except (TypeError, AttributeError, ValueError):
        pass
    extra = getattr(client, "extra", None) or {}
    return bool(extra.get("frozen")) if isinstance(extra, dict) else False

def _notify_telegram(db: Session, text: str) -> bool:
    """Send a Telegram notification if configured. Never raises.

    The token is read from settings and passed straight to the
    sender — it is never logged (not even on failure: the warning
    below carries no exception text, because HTTP errors can echo
    the request URL, which contains the token).
    """
    if not text:
        return False
    try:
        settings = get_settings(db)
        token = settings.get("telegram_bot_token", "")
        chat_id = settings.get("telegram_chat_id", "")
        if not token or not chat_id:
            return False
        return bool(telegram_mod.send_message(token, chat_id, text))
    except Exception:  # noqa: BLE001
        logger.warning("telegram notification failed")
        return False

def clients_count_by_inbound(db: Session) -> dict[int, int]:
    """``{inbound_id: client_count}`` in ONE grouped query.

    The dashboard and inbounds pages used to issue one COUNT per
    inbound (N+1 — audit Q6, fixed in Phase 6). Inbounds with no
    clients are absent from the result (callers use ``.get(id, 0)``).
    """
    rows = (
        db.query(Client.inbound_id, func.count(Client.id))
        .group_by(Client.inbound_id)
        .all()
    )
    return {inbound_id: count for inbound_id, count in rows}


def _traffic_chart(
    db: Session, user_id: Optional[int] = None, today: Any = None
) -> tuple[str, int]:
    """``(svg, total_bytes)`` for the last 14 days of ``traffic_daily``.

    ``user_id=None`` charts all users (dashboard); a user id charts
    one user (user detail). Days with no recorded traffic are zero
    bars, never invented values. Returns ``("", 0)`` on failure.
    Never raises.

    The query is bounded to the chart window (Phase 6): the series
    only ever shows the last 14 days, so older rows are filtered at
    the DB level instead of loaded and discarded in Python.
    """
    try:
        query = db.query(TrafficDaily)
        if user_id is not None:
            query = query.filter(TrafficDaily.user_id == user_id)
        chart_today = today or date.today()
        if isinstance(chart_today, datetime):
            chart_today = chart_today.date()
        first_day = chart_today - timedelta(days=charts_mod.CHART_DAYS - 1)
        query = query.filter(TrafficDaily.date >= first_day)
        rows = [
            (row.date, (row.up_bytes or 0) + (row.down_bytes or 0))
            for row in query.all()
        ]
        series = charts_mod.daily_traffic_series(rows, today=today)
        return (
            charts_mod.traffic_chart_svg(series),
            sum(total for _day, total in series),
        )
    except Exception:  # noqa: BLE001
        logger.warning("traffic chart failed")
        return "", 0
