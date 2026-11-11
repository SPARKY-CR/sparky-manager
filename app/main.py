"""vpn-panel — FastAPI application (Phase 1 MVP).

Original code, written from scratch for this project.

Routes: HTML UI (Persian-first, RTL, English toggle via ``?lang=en``),
a small JSON API, and the public per-user subscription endpoints
(``/sub/<token>`` dual format, ``/u/<token>`` human page).

Domain-agnostic: works with a bare server IP; the domain setting is
optional and empty means "no domain". Panel listens on the
installer-chosen port (random on a fresh install, default 2053),
path ``/``, admin username ``admin``.

Contract assumptions (sibling modules are owned by other agents; if a
renderer/links module is missing at import time we log a warning and
keep serving — config re-rendering is best-effort and its failures are
shown to the admin instead of crashing the request):

- ``app.db``: ``SessionLocal``, ``init_db()`` (no args — it binds its
  own engine), ``get_session()`` (a ``@contextmanager``)
- ``app.models``: ``Admin, Setting, Inbound, User, Client, TrafficDaily,
  AuditLog, Session``; helpers ``user_is_usable(user, now=None)``,
  ``client_is_usable(client, user, inbound, now=None)``. Note:
  ``Inbound`` uniqueness is ``(port, protocol)``, so VLESS-Reality
  (TCP 443) and Hysteria2 (UDP 443) share port 443 legitimately.
- ``app.auth``: ``hash_password, verify_password, create_session(db,
  admin, ip) -> token, get_admin_from_token(db, token),
  invalidate_session, record_failed_login(ip), is_locked_out(ip)``
- ``app.config``: ``PANEL_PORT`` (default 2053), ``DATA_DIR``, ``DB_PATH``, ``XRAY_CONFIG``,
  SINGBOX_CONFIG, WG_CONFIG``, ``get_settings_dict()`` (env defaults;
  the DB ``Setting`` table overlays it — see ``get_settings()``)
- ``app.links``: ``build_share_link(protocol, client_dict, inbound_dict,
  host, name)`` — client/inbound dicts carry ``extra_json`` /
  ``stream_json`` as *dicts*; ``make_qr_png(data) -> bytes``
- ``app.subscription``: ``choose_format(ua, q)`` -> ``"v2rayng"`` /
  ``"singbox"``, ``build_v2rayng_feed(links) -> bytes``,
  ``build_singbox_feed(outbounds) -> dict``,
  ``outbound_for_client(protocol, client, inbound, host, tag)``,
  ``subscription_userinfo(used, limit, expires_unix)``
- ``app.xray``: ``render_xray_config(inbounds, clients_by_tag,
  settings) -> dict``, ``write_and_validate(cfg, path, binary)
  -> (ok, messages)``
- ``app.singbox``: ``render_singbox_config(inbounds, clients_by_tag,
  settings) -> (dict, warnings)``, ``write_and_validate(...)`` same tuple
- ``app.wireguard``: ``render_wg_config(server_private_key, peers, *,
  address, listen_port, dns) -> str`` (peers: ``public_key`` +
  ``allowed_ips``), ``render_peer_config(...)``,
  ``generate_keypair() -> (private_key, public_key)``
- ``app.traffic``: ``sync_traffic(db, *, xray_stats=None, wg_text=None,
  nft_text=None, wg_pubkey_to_user_id=None, nft_port_to_user_id=None)``
- ``app.ikev2``: ``get_ikev2_status() -> dict``

Bootstrap secrets (installer contract): on first run
``ensure_defaults()`` prefers the environment variables the installer
writes to ``panel.env`` — ``VPN_PANEL_ADMIN_PASSWORD``,
``VPN_PANEL_REALITY_PRIVATE_KEY`` / ``_PUBLIC_KEY`` / ``_SHORT_ID``,
``VPN_PANEL_WG_PRIVATE_KEY`` / ``_PUBLIC_KEY`` — and generates fresh
values only when they are absent. The admin password is printed to
stdout only when it was generated here; an env-supplied password is
never printed (the installer prints it in its login box).

TLS: none inside this module. The systemd unit runs uvicorn with
``--ssl-certfile`` / ``--ssl-keyfile``; the ``__main__`` block is
plain-HTTP local dev only, and importing ``app.main`` as an ASGI app
starts no server.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import subprocess
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

logger = logging.getLogger("vpn-panel")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

SESSION_COOKIE = "vpn_panel_session"
SESSION_MAX_AGE = 12 * 3600  # 12 hours
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# ---------------------------------------------------------------------------
# Optional / contract imports.
# Core modules (db, models, config, auth) are required for the app to run;
# service modules (links, subscription, renderers, traffic, ikev2) are
# optional at import time: missing ones only disable the feature that
# needs them, never the whole panel.
# ---------------------------------------------------------------------------

try:
    from app import config as panel_config
except ImportError:  # pragma: no cover - sibling module not written yet
    panel_config = None  # type: ignore[assignment]
    logger.warning("app.config not available yet; using built-in defaults")

try:
    from app.db import SessionLocal, get_session, init_db
except ImportError:  # pragma: no cover
    SessionLocal = None  # type: ignore[assignment]
    get_session = None  # type: ignore[assignment]
    init_db = None  # type: ignore[assignment]
    logger.warning("app.db not available yet")

try:
    from app import models
    from app.models import (
        Admin,
        AuditLog,
        Client,
        Inbound,
        Setting,
        TrafficDaily,
        User,
    )
    try:
        from app.models import client_is_usable, user_is_usable
    except ImportError:
        client_is_usable = None  # type: ignore[assignment]
        user_is_usable = None  # type: ignore[assignment]
except ImportError:  # pragma: no cover
    models = None  # type: ignore[assignment]
    Admin = AuditLog = Client = Inbound = Setting = TrafficDaily = User = None  # type: ignore[assignment]
    client_is_usable = None  # type: ignore[assignment]
    user_is_usable = None  # type: ignore[assignment]
    logger.warning("app.models not available yet")

try:
    from app import auth as auth_mod
    from app.auth import (
        create_session,
        get_admin_from_token,
        hash_password,
        invalidate_session,
        is_locked_out,
        record_failed_login,
        verify_password,
    )
except ImportError:  # pragma: no cover
    auth_mod = None  # type: ignore[assignment]
    create_session = get_admin_from_token = hash_password = None  # type: ignore[assignment]
    invalidate_session = is_locked_out = record_failed_login = None  # type: ignore[assignment]
    verify_password = None  # type: ignore[assignment]
    logger.warning("app.auth not available yet")

try:
    from app import links as links_mod
except ImportError:
    links_mod = None
    logger.warning("app.links not available yet; share links / QR disabled")

try:
    from app import subscription as subscription_mod
except ImportError:
    subscription_mod = None
    logger.warning("app.subscription not available yet; /sub feeds disabled")

try:
    from app import xray as xray_mod
except ImportError:
    xray_mod = None
    logger.warning("app.xray not available yet; Xray re-render disabled")

try:
    from app import singbox as singbox_mod
except ImportError:
    singbox_mod = None
    logger.warning("app.singbox not available yet; sing-box re-render disabled")

try:
    from app import wireguard as wireguard_mod
except ImportError:
    wireguard_mod = None
    logger.warning("app.wireguard not available yet; WireGuard re-render disabled")

try:
    from app import traffic as traffic_mod
except ImportError:
    traffic_mod = None
    logger.warning("app.traffic not available yet; traffic sync disabled")

try:
    from app import ikev2 as ikev2_mod
except ImportError:
    ikev2_mod = None
    logger.warning("app.ikev2 not available yet; IKEv2 status unavailable")


def _cfg_attr(name: str, default: Any) -> Any:
    """Read an attribute from app.config, falling back to ``default``."""
    if panel_config is not None:
        return getattr(panel_config, name, default)
    return default


PANEL_PORT = _cfg_attr("PANEL_PORT", 2053)
DATA_DIR = Path(_cfg_attr("DATA_DIR", "/opt/vpn-panel/data"))
# app.config names these XRAY_CONFIG / SINGBOX_CONFIG / WG_CONFIG.
XRAY_CONFIG_PATH = _cfg_attr("XRAY_CONFIG", "/usr/local/etc/xray/config.json")
XRAY_BINARY = _cfg_attr("XRAY_BINARY", "/usr/local/bin/xray")
SINGBOX_CONFIG_PATH = _cfg_attr("SINGBOX_CONFIG", "/etc/sing-box/config.json")
SINGBOX_BINARY = _cfg_attr("SINGBOX_BINARY", "/usr/local/bin/sing-box")
WG_CONFIG_PATH = _cfg_attr("WG_CONFIG", "/etc/wireguard/wg0.conf")

# Secrets the installer writes to panel.env / install.env (loaded via the
# systemd unit's EnvironmentFile). ensure_defaults() prefers these over
# generating fresh values, so the installer's login box always matches
# what the app actually uses. Never logged.
ENV_ADMIN_PASSWORD = "VPN_PANEL_ADMIN_PASSWORD"
ENV_REALITY_PRIVATE_KEY = "VPN_PANEL_REALITY_PRIVATE_KEY"
ENV_REALITY_PUBLIC_KEY = "VPN_PANEL_REALITY_PUBLIC_KEY"
ENV_REALITY_SHORT_ID = "VPN_PANEL_REALITY_SHORT_ID"
ENV_WG_PRIVATE_KEY = "VPN_PANEL_WG_PRIVATE_KEY"
ENV_WG_PUBLIC_KEY = "VPN_PANEL_WG_PUBLIC_KEY"

# ---------------------------------------------------------------------------
# i18n — inline fa/en strings (no app.i18n dependency).
# ---------------------------------------------------------------------------

STRINGS: dict[str, dict[str, str]] = {
    "fa": {
        "app_name": "پنل VPN",
        "dashboard": "داشبورد",
        "inbounds": "اینباندها",
        "users": "کاربران",
        "settings": "تنظیمات",
        "logout": "خروج",
        "login": "ورود",
        "username": "نام کاربری",
        "password": "رمز عبور",
        "sign_in": "ورود به پنل",
        "login_hint": "با حساب مدیر وارد شوید.",
        "wrong_credentials": "نام کاربری یا رمز عبور اشتباه است.",
        "locked_out": "به دلیل تلاش‌های ناموفق زیاد، ورود موقتاً قفل شده است. چند دقیقه دیگر تلاش کنید.",
        "total_users": "کل کاربران",
        "active_users": "کاربران فعال",
        "total_inbounds": "کل اینباندها",
        "traffic_used": "ترافیک مصرف‌شده",
        "online_now": "آنلاین (تقریبی)",
        "ikev2_status": "وضعیت IKEv2",
        "ikev2_note": "IKEv2 توسط Ikev2-manager مدیریت می‌شود، نه این پنل.",
        "recent_users": "کاربران اخیر",
        "name": "نام",
        "status": "وضعیت",
        "enabled": "فعال",
        "disabled": "غیرفعال",
        "used": "مصرف‌شده",
        "limit": "سقف",
        "unlimited": "نامحدود",
        "expires": "انقضا",
        "never": "بدون انقضا",
        "actions": "عملیات",
        "add_user": "افزودن کاربر",
        "add_inbound": "افزودن اینباند",
        "note": "یادداشت",
        "traffic_limit_gb": "سقف ترافیک (گیگابایت، خالی = نامحدود)",
        "expires_days": "انقضا (روز، خالی = بدون انقضا)",
        "create": "ایجاد",
        "save": "ذخیره",
        "delete": "حذف",
        "toggle": "فعال / غیرفعال",
        "rotate_token": "تعویض توکن اشتراک",
        "confirm_delete": "آیا مطمئن هستید؟ این عمل قابل بازگشت نیست.",
        "tag": "برچسب (tag)",
        "core": "هسته",
        "protocol": "پروتکل",
        "port": "پورت",
        "remark": "توضیح",
        "sni": "SNI (برای Reality / TLS)",
        "path": "مسیر (Path)",
        "network": "شبکه / انتقال",
        "domain": "دامنه (اختیاری — خالی یعنی بدون دامنه)",
        "subscription_host": "هاست اشتراک (IP یا دامنه؛ خالی یعنی خودکار)",
        "reality_sni": "SNI پیش‌فرض Reality",
        "subscription_link": "لینک اشتراک",
        "user_page": "صفحه کاربر",
        "copy": "کپی",
        "copied": "کپی شد!",
        "show_password": "نمایش رمز",
        "hide_password": "پنهان کردن رمز",
        "back_to_users": "بازگشت به کاربران",
        "back_to_dashboard": "بازگشت به داشبورد",
        "no_users": "هنوز کاربری ساخته نشده است.",
        "no_inbounds": "هنوز اینباندی ساخته نشده است.",
        "clients": "کلاینت‌ها",
        "share_links": "لینک‌های اشتراک",
        "qr_code": "کد QR",
        "sub_v2rayng": "اشتراک v2rayNG",
        "sub_singbox": "اشتراک sing-box",
        "user_not_found": "کاربر پیدا نشد.",
        "user_unusable": "این اشتراک غیرفعال، منقضی یا پر شده است.",
        "links_unavailable": "ماژول ساخت لینک هنوز در دسترس نیست.",
        "rerender_failed": "خطا در بازسازی کانفیگ: ",
        "port_in_use": "این پورت قبلاً استفاده شده است.",
        "invalid_port": "پورت باید بین ۱ تا ۶۵۵۳۵ باشد.",
        "invalid_name": "نام فقط می‌تواند شامل حروف، عدد، - و _ باشد.",
        "name_exists": "کاربری با این نام از قبل وجود دارد.",
        "tag_exists": "اینباندی با این برچسب از قبل وجود دارد.",
        "traffic_today": "ترافیک امروز",
        "sub_token": "توکن اشتراک",
        "created_at": "ساخته شده",
        "details": "جزئیات",
        "open_ikev2_manager": "باز کردن Ikev2-manager",
        "footer_note": "پنل VPN — فاز ۱",
    },
    "en": {
        "app_name": "VPN Panel",
        "dashboard": "Dashboard",
        "inbounds": "Inbounds",
        "users": "Users",
        "settings": "Settings",
        "logout": "Log out",
        "login": "Login",
        "username": "Username",
        "password": "Password",
        "sign_in": "Sign in to the panel",
        "login_hint": "Sign in with the admin account.",
        "wrong_credentials": "Wrong username or password.",
        "locked_out": "Too many failed attempts — login is temporarily locked. Try again in a few minutes.",
        "total_users": "Total users",
        "active_users": "Active users",
        "total_inbounds": "Total inbounds",
        "traffic_used": "Traffic used",
        "online_now": "Online (approx.)",
        "ikev2_status": "IKEv2 status",
        "ikev2_note": "IKEv2 is managed by Ikev2-manager, not this panel.",
        "recent_users": "Recent users",
        "name": "Name",
        "status": "Status",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "used": "Used",
        "limit": "Limit",
        "unlimited": "Unlimited",
        "expires": "Expires",
        "never": "Never",
        "actions": "Actions",
        "add_user": "Add user",
        "add_inbound": "Add inbound",
        "note": "Note",
        "traffic_limit_gb": "Traffic limit (GB, empty = unlimited)",
        "expires_days": "Expiry (days, empty = never)",
        "create": "Create",
        "save": "Save",
        "delete": "Delete",
        "toggle": "Enable / disable",
        "rotate_token": "Rotate subscription token",
        "confirm_delete": "Are you sure? This cannot be undone.",
        "tag": "Tag",
        "core": "Core",
        "protocol": "Protocol",
        "port": "Port",
        "remark": "Remark",
        "sni": "SNI (for Reality / TLS)",
        "path": "Path",
        "network": "Network / transport",
        "domain": "Domain (optional — empty means no domain)",
        "subscription_host": "Subscription host (IP or domain; empty = automatic)",
        "reality_sni": "Default Reality SNI",
        "subscription_link": "Subscription link",
        "user_page": "User page",
        "copy": "Copy",
        "copied": "Copied!",
        "show_password": "Show password",
        "hide_password": "Hide password",
        "back_to_users": "Back to users",
        "back_to_dashboard": "Back to dashboard",
        "no_users": "No users yet.",
        "no_inbounds": "No inbounds yet.",
        "clients": "Clients",
        "share_links": "Share links",
        "qr_code": "QR code",
        "sub_v2rayng": "v2rayNG subscription",
        "sub_singbox": "sing-box subscription",
        "user_not_found": "User not found.",
        "user_unusable": "This subscription is disabled, expired or out of quota.",
        "links_unavailable": "The link-builder module is not available yet.",
        "rerender_failed": "Config re-render failed: ",
        "port_in_use": "This port is already in use.",
        "invalid_port": "Port must be between 1 and 65535.",
        "invalid_name": "Name may only contain letters, digits, - and _.",
        "name_exists": "A user with this name already exists.",
        "tag_exists": "An inbound with this tag already exists.",
        "traffic_today": "Traffic today",
        "sub_token": "Subscription token",
        "created_at": "Created",
        "details": "Details",
        "open_ikev2_manager": "Open Ikev2-manager",
        "footer_note": "VPN Panel — Phase 1",
    },
}


def get_lang(request: Request) -> str:
    """Language for this request: ``?lang=en|fa`` wins, else cookie, else fa."""
    q = request.query_params.get("lang")
    if q in ("fa", "en"):
        return q
    cookie = request.cookies.get("lang")
    if cookie in ("fa", "en"):
        return cookie
    return "fa"


def t_for(lang: str) -> dict[str, str]:
    """Translation dict for ``lang`` (falls back to Persian)."""
    return STRINGS.get(lang, STRINGS["fa"])


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
    if panel_config is not None and hasattr(panel_config, "get_settings_dict"):
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


# ---------------------------------------------------------------------------
# Usability helpers (delegate to app.models when available)
# ---------------------------------------------------------------------------


def _user_usable(db: Session, user: Any, now: Optional[datetime] = None) -> bool:
    if user_is_usable is not None:
        try:
            return bool(user_is_usable(user, now))
        except TypeError:
            return bool(user_is_usable(user))
    now = now or datetime.now(timezone.utc)
    if not getattr(user, "enabled", False):
        return False
    expires = getattr(user, "expires_at", None)
    if expires is not None:
        exp = expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)
        if exp <= now:
            return False
    limit = getattr(user, "traffic_limit_bytes", None)
    if limit is not None and getattr(user, "traffic_used_bytes", 0) >= limit:
        return False
    return True


def _client_usable(db: Session, client: Any, user: Any, inbound: Any) -> bool:
    if client_is_usable is not None:
        try:
            return bool(client_is_usable(client, user, inbound))
        except TypeError:
            return bool(client_is_usable(client, user, inbound, None))
    if not getattr(client, "enabled", False):
        return False
    if not getattr(inbound, "enabled", False):
        return False
    return _user_usable(db, user)


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
        if inbound is not None and _client_usable(db, client, user, inbound):
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
    db: Session, user: Any, host: str
) -> list[dict[str, Any]]:
    """Share links for one user's usable clients (empty when unavailable)."""
    if links_mod is None:
        return []
    links: list[dict[str, Any]] = []
    for client, inbound in _usable_clients(db, user):
        try:
            link = links_mod.build_share_link(
                inbound.protocol,
                _client_dict(client, user),
                _inbound_dict(inbound),
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


# ---------------------------------------------------------------------------
# Config re-render + core restart (best-effort; failures are reported,
# never raised into the request).
# ---------------------------------------------------------------------------


def _restart_service(name: str) -> Optional[str]:
    """``systemctl restart <name>``; returns an error string or None."""
    try:
        proc = subprocess.run(
            ["systemctl", "restart", name],
            timeout=30,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return f"systemctl not found; could not restart {name}"
    except subprocess.TimeoutExpired:
        return f"restart of {name} timed out"
    except OSError as exc:  # noqa: BLE001
        return f"could not restart {name}: {exc}"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return f"restart of {name} failed: {err or 'exit ' + str(proc.returncode)}"
    return None


def rerender_configs(db: Session) -> list[str]:
    """Re-render Xray / sing-box / WireGuard configs from the DB.

    Returns a list of error strings (empty = all good). Each core is
    attempted independently; one core failing does not stop the others,
    and the old config / running service is left untouched on failure.
    """
    errors: list[str] = []
    settings = get_settings(db)
    inbounds = db.query(Inbound).order_by(Inbound.id).all()
    if not inbounds:
        return errors

    clients_by_tag: dict[str, list[dict[str, Any]]] = {}
    for inbound in inbounds:
        rows: list[dict[str, Any]] = []
        for client in db.query(Client).filter(Client.inbound_id == inbound.id).all():
            user = db.query(User).filter(User.id == client.user_id).first()
            if user is None:
                continue
            if not _client_usable(db, client, user, inbound):
                continue  # renderers omit unusable clients (DESIGN §4)
            rows.append(_client_dict(client, user))
        clients_by_tag[inbound.tag] = rows

    xray_inbounds = [i for i in inbounds if i.core == "xray" and i.enabled]
    singbox_inbounds = [i for i in inbounds if i.core == "singbox" and i.enabled]
    wg_inbounds = [i for i in inbounds if i.core == "wireguard" and i.enabled]

    if xray_inbounds and xray_mod is not None:
        try:
            cfg = xray_mod.render_xray_config(
                [_inbound_dict(i) for i in xray_inbounds], clients_by_tag, settings
            )
            # write_and_validate() returns (ok, messages) and never raises
            # for a missing binary / bad path — honour it.
            ok, messages = xray_mod.write_and_validate(cfg, XRAY_CONFIG_PATH, XRAY_BINARY)
            if not ok:
                errors.append("xray config not written: " + "; ".join(messages))
            else:
                err = _restart_service("xray")
                if err:
                    errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"xray render/restart failed: {exc}")
            logger.exception("xray re-render failed")
    elif xray_inbounds:
        errors.append("app.xray is not available; Xray config was not updated")

    if singbox_inbounds and singbox_mod is not None:
        try:
            result = singbox_mod.render_singbox_config(
                [_inbound_dict(i) for i in singbox_inbounds], clients_by_tag, settings
            )
            cfg = result[0] if isinstance(result, tuple) else result
            warnings = result[1] if isinstance(result, tuple) and len(result) > 1 else []
            for warning in warnings or []:
                errors.append(f"sing-box warning: {warning}")
            ok, messages = singbox_mod.write_and_validate(
                cfg, SINGBOX_CONFIG_PATH, SINGBOX_BINARY
            )
            if not ok:
                errors.append("sing-box config not written: " + "; ".join(messages))
            else:
                err = _restart_service("sing-box")
                if err:
                    errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"sing-box render/restart failed: {exc}")
            logger.exception("sing-box re-render failed")
    elif singbox_inbounds:
        errors.append("app.singbox is not available; sing-box config was not updated")

    if wg_inbounds and wireguard_mod is not None:
        try:
            # Real API: render_wg_config(server_private_key, peers, *,
            # address, listen_port, dns) -> str. Peers carry
            # public_key + allowed_ips; the server key lives in settings
            # (seeded from VPN_PANEL_WG_PRIVATE_KEY by ensure_defaults).
            server_key = (settings.get("wireguard_private_key") or "").strip()
            if not server_key:
                server_key = os.environ.get(ENV_WG_PRIVATE_KEY, "").strip()
            if not server_key:
                errors.append(
                    "wireguard server key missing (setting "
                    "wireguard_private_key / VPN_PANEL_WG_PRIVATE_KEY); "
                    "wg0.conf was not updated"
                )
            else:
                wg_inbound = wg_inbounds[0]
                peers: list[dict[str, Any]] = []
                for client in clients_by_tag.get(wg_inbound.tag, []):
                    extra = client.get("extra_json") or {}
                    if not isinstance(extra, dict):
                        extra = {}
                    if client.get("uuid") and extra.get("allowed_ips"):
                        peers.append(
                            {
                                "public_key": client["uuid"],
                                "allowed_ips": extra["allowed_ips"],
                            }
                        )
                content = wireguard_mod.render_wg_config(
                    server_key,
                    peers,
                    listen_port=int(wg_inbound.port),
                )
                Path(WG_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
                tmp = Path(str(WG_CONFIG_PATH) + ".tmp")
                tmp.write_text(content, encoding="utf-8")
                tmp.replace(WG_CONFIG_PATH)
                err = _restart_service("wg-quick@wg0")
                if err:
                    errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"wireguard render/restart failed: {exc}")
            logger.exception("wireguard re-render failed")
    elif wg_inbounds:
        errors.append("app.wireguard is not available; wg0.conf was not updated")

    return errors


# ---------------------------------------------------------------------------
# Startup: tables, default admin, default inbounds
# ---------------------------------------------------------------------------


def _default_inbounds(reality: Optional[dict[str, str]] = None) -> list[dict[str, Any]]:
    """Default inbounds created when the DB is empty (DESIGN §3/§8).

    ``reality`` (when given) carries the installer's Reality keypair /
    short-id so the VLESS-Reality inbound's ``stream_json`` holds the
    public key + short-id the share links and subscriptions need
    (``links`` / ``subscription`` read them from the inbound, not from
    settings). The private key goes to settings as well, for the Xray
    renderer, which accepts either place.
    """
    reality_block: dict[str, Any] = {
        "sni": "www.microsoft.com",
        "dest": "www.microsoft.com:443",
    }
    if reality:
        if reality.get("private_key"):
            reality_block["private_key"] = reality["private_key"]
        if reality.get("public_key"):
            reality_block["public_key"] = reality["public_key"]
        if reality.get("short_id"):
            reality_block["short_id"] = reality["short_id"]
    return [
        {
            "tag": "vless-reality",
            "core": "xray",
            "protocol": "vless",
            "port": 443,
            "remark": "VLESS + Reality",
            "stream_json": json.dumps(
                {
                    "network": "tcp",
                    "security": "reality",
                    "transport": "tcp",
                    "reality": reality_block,
                }
            ),
        },
        {
            "tag": "hysteria2",
            "core": "xray",
            "protocol": "hysteria2",
            "port": 443,
            "remark": "Hysteria2 (UDP 443, shares port with VLESS-Reality)",
            "stream_json": json.dumps({"transport": "udp", "security": "tls"}),
        },
        {
            "tag": "shadowsocks",
            "core": "xray",
            "protocol": "shadowsocks",
            "port": 8388,
            "remark": "Shadowsocks 2022",
            "stream_json": json.dumps(
                {
                    "network": "tcp,udp",
                    "security": "none",
                    "transport": "tcp",
                    "method": "2022-blake3-aes-128-gcm",
                }
            ),
        },
        {
            "tag": "wireguard",
            "core": "wireguard",
            "protocol": "wireguard",
            "port": 51820,
            "remark": "WireGuard (native)",
            "stream_json": json.dumps({"transport": "udp"}),
        },
    ]


def _env_or_generate(key: str, generator) -> tuple[str, bool]:
    """Value of env var ``key`` when set and non-blank, else a fresh
    generated value. Returns ``(value, came_from_env)``."""
    value = os.environ.get(key, "").strip()
    if value:
        return value, True
    return generator(), False


def ensure_defaults(db: Session) -> Optional[str]:
    """Seed the DB on first run: admin, default inbounds, key settings.

    Bootstrap rule (installer contract): secrets prefer the
    environment variables the installer wrote to
    ``/opt/vpn-panel/data/panel.env`` (loaded via the systemd unit's
    ``EnvironmentFile``) — ``VPN_PANEL_ADMIN_PASSWORD``,
    ``VPN_PANEL_REALITY_PRIVATE_KEY`` / ``_PUBLIC_KEY`` / ``_SHORT_ID``,
    ``VPN_PANEL_WG_PRIVATE_KEY`` / ``_PUBLIC_KEY``. Fresh values are
    generated only when the env vars are absent (e.g. a dev run).

    Returns the admin password ONLY when it was generated here (the
    installer already prints an env-supplied password in its login
    box, so this function must never print that one). Returns None
    when an admin already exists — the password is never printed again.
    """
    generated_password: Optional[str] = None
    if db.query(Admin).count() == 0:
        password, from_env = _env_or_generate(
            ENV_ADMIN_PASSWORD, lambda: secrets.token_urlsafe(12)
        )
        if not from_env:
            generated_password = password
        db.add(Admin(username="admin", password_hash=hash_password(password)))
        db.commit()
        if generated_password is not None:
            # No env password was supplied (dev run): print once so the
            # operator can log in. Never printed again afterwards.
            print("=" * 60, flush=True)
            print("  vpn-panel — first run: admin account created", flush=True)
            print(f"  Panel:    http://<server-ip>:{PANEL_PORT}  (or https if TLS is set up)", flush=True)
            print("  Username: admin", flush=True)
            print(f"  Password: {generated_password}", flush=True)
            print("  Save this password — it is printed ONLY this once.", flush=True)
            print("=" * 60, flush=True)
        else:
            logger.info("admin account created from VPN_PANEL_ADMIN_PASSWORD")

    # Reality keypair / short-id: env first, generate only if absent.
    # Stored in settings (Xray renderer reads reality_private_key from
    # settings) and embedded in the default inbound (links read the
    # public key / short-id from the inbound's stream_json).
    reality: dict[str, str] = {}
    settings_now = {row.key: (row.value or "") for row in db.query(Setting).all()}
    if settings_now.get("reality_private_key"):
        reality["private_key"] = settings_now["reality_private_key"]
    if settings_now.get("reality_public_key"):
        reality["public_key"] = settings_now["reality_public_key"]
    if settings_now.get("reality_short_id"):
        reality["short_id"] = settings_now["reality_short_id"]
    if "private_key" not in reality:
        # No usable stored keypair: prefer env, else generate a fresh
        # X25519 pair via the xray module when available.
        env_private = os.environ.get(ENV_REALITY_PRIVATE_KEY, "").strip()
        env_public = os.environ.get(ENV_REALITY_PUBLIC_KEY, "").strip()
        env_short = os.environ.get(ENV_REALITY_SHORT_ID, "").strip()
        if env_private and env_public:
            reality["private_key"] = env_private
            reality["public_key"] = env_public
            if env_short:
                reality["short_id"] = env_short
        elif xray_mod is not None and hasattr(xray_mod, "generate_reality_keypair"):
            try:
                pair = xray_mod.generate_reality_keypair()
                if isinstance(pair, dict):
                    reality["private_key"] = str(pair.get("private_key") or pair.get("privateKey") or "")
                    reality["public_key"] = str(pair.get("public_key") or pair.get("publicKey") or "")
                elif isinstance(pair, (list, tuple)) and len(pair) >= 2:
                    reality["private_key"], reality["public_key"] = str(pair[0]), str(pair[1])
            except Exception:  # noqa: BLE001
                logger.exception("reality keypair generation failed")
        if "short_id" not in reality and reality.get("private_key"):
            # A keypair exists (env or generated) but no short-id: mint one.
            reality["short_id"] = env_short or secrets.token_hex(4)
    for key in ("reality_private_key", "reality_public_key", "reality_short_id"):
        short = key.removeprefix("reality_")
        if reality.get(short) and not settings_now.get(key):
            db.add(Setting(key=key, value=reality[short]))
    if db.query(Setting).filter(Setting.key == "reality_sni").first() is None:
        db.add(Setting(key="reality_sni", value="www.microsoft.com"))
    db.commit()

    # WireGuard server keypair: env first, generate only if absent.
    wg_now = {row.key: (row.value or "") for row in db.query(Setting).all()}
    if not wg_now.get("wireguard_private_key"):
        env_wg_private = os.environ.get(ENV_WG_PRIVATE_KEY, "").strip()
        env_wg_public = os.environ.get(ENV_WG_PUBLIC_KEY, "").strip()
        if env_wg_private:
            db.add(Setting(key="wireguard_private_key", value=env_wg_private))
            if env_wg_public:
                db.add(Setting(key="wireguard_public_key", value=env_wg_public))
        elif wireguard_mod is not None and hasattr(wireguard_mod, "generate_keypair"):
            try:
                pair = wireguard_mod.generate_keypair()
                private, public = (pair[0], pair[1]) if isinstance(pair, (list, tuple)) else (str(pair), "")
                db.add(Setting(key="wireguard_private_key", value=private))
                if public:
                    db.add(Setting(key="wireguard_public_key", value=public))
            except Exception:  # noqa: BLE001
                logger.exception("wireguard keypair generation failed")
        db.commit()

    if db.query(Inbound).count() == 0:
        # One transaction per row, so a single conflicting row (e.g.
        # UNIQUE(port, protocol)) is skipped with a warning instead of
        # rolling back the whole seed.
        from sqlalchemy.exc import IntegrityError

        for row in _default_inbounds(reality or None):
            try:
                db.add(Inbound(**row))
                db.commit()
            except IntegrityError:
                db.rollback()
                logger.warning(
                    "default inbound %s skipped: port %s conflicts "
                    "(UNIQUE(port, protocol))",
                    row["tag"],
                    row["port"],
                )
    return generated_password

# ---------------------------------------------------------------------------
# App setup, background tasks, auth
# ---------------------------------------------------------------------------


async def _traffic_sync_loop() -> None:
    """Every 60 s: poll traffic sources and roll usage into the DB."""
    while True:
        await asyncio.sleep(60)
        if traffic_mod is None or SessionLocal is None:
            continue
        db = SessionLocal()
        try:
            wg_text: Optional[str] = None
            try:
                proc = subprocess.run(
                    ["wg", "show", "wg0", "transfer"],
                    timeout=10,
                    capture_output=True,
                    text=True,
                )
                if proc.returncode == 0:
                    wg_text = proc.stdout
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                wg_text = None
            traffic_mod.sync_traffic(
                db, wg_text=wg_text, wg_pubkey_to_user_id=_wg_pubkey_map(db)
            )
        except Exception:  # noqa: BLE001
            logger.exception("traffic sync failed")
        finally:
            db.close()


async def _expiry_sweeper_loop() -> None:
    """Every 5 min: re-render configs so expired/over-quota users drop
    out (the renderers omit unusable clients — DESIGN §4/§6.4)."""
    while True:
        await asyncio.sleep(300)
        if SessionLocal is None:
            continue
        db = SessionLocal()
        try:
            errors = rerender_configs(db)
            if errors:
                logger.warning("expiry sweeper re-render errors: %s", errors)
        except Exception:  # noqa: BLE001
            logger.exception("expiry sweeper failed")
        finally:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create tables, seed defaults, start background loops."""
    if init_db is not None:
        try:
            # app.db has no module-level `engine` (use get_engine() /
            # init_db() with no args — it binds the engine itself).
            init_db()
        except Exception:  # noqa: BLE001
            logger.exception("init_db failed")
    if SessionLocal is not None:
        db = SessionLocal()
        try:
            ensure_defaults(db)
        except Exception:  # noqa: BLE001
            logger.exception("seeding defaults failed")
        finally:
            db.close()
    tasks = [
        asyncio.create_task(_traffic_sync_loop()),
        asyncio.create_task(_expiry_sweeper_loop()),
    ]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="vpn-panel", lifespan=lifespan)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def db_session():
    """FastAPI dependency yielding a DB session.

    ``app.db.get_session()`` is a ``@contextmanager`` (not a plain
    generator), so ``yield from`` on it raises TypeError — enter it
    with ``with`` instead.
    """
    if get_session is not None:
        with get_session() as db:
            yield db
        return
    if SessionLocal is None:
        raise HTTPException(status_code=503, detail="database not initialised")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _admin_from_request(request: Request, db: Session) -> Optional[Any]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or get_admin_from_token is None:
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


def _template_ctx(request: Request, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    lang = get_lang(request)
    ctx: dict[str, Any] = {
        "request": request,
        "lang": lang,
        "t": t_for(lang),
        "msg": request.query_params.get("msg", ""),
        "err": request.query_params.get("err", ""),
    }
    if extra:
        ctx.update(extra)
    return ctx


def _redirect(url: str, request: Request, msg: str = "", err: str = "") -> RedirectResponse:
    """303 redirect preserving ?lang= when English, plus ?msg=/?err=."""
    sep = "&" if "?" in url else "?"
    target = url
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


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        path="/",
    )


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
        if wireguard_mod is not None and hasattr(wireguard_mod, "generate_keypair"):
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
    else:
        creds["uuid"] = str(uuid.uuid4())
        creds["password"] = secrets.token_urlsafe(12)
    if protocol == "vless":
        creds["flow"] = "xtls-rprx-vision"
    return creds


def _next_wg_address(db: Session) -> str:
    """Next free WireGuard peer address (10.8.0.2/32 … 10.8.0.254/32).

    Scans the ``allowed_ips`` stored in existing WireGuard clients'
    ``extra_json``; the server itself is 10.8.0.1 (see
    ``render_wg_config`` default address).
    """
    used: set[int] = set()
    for (raw,) in (
        db.query(Client.extra_json)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .filter(Inbound.protocol == "wireguard")
        .all()
    ):
        if not raw:
            continue
        try:
            extra = json.loads(raw) if isinstance(raw, str) else dict(raw)
            allowed = str(extra.get("allowed_ips") or "")
        except (ValueError, TypeError):
            continue
        match = re.search(r"10\.8\.0\.(\d+)/32", allowed)
        if match:
            used.add(int(match.group(1)))
    for octet in range(2, 255):
        if octet not in used:
            return f"10.8.0.{octet}/32"
    raise ValueError("WireGuard address pool (10.8.0.0/24) exhausted")


def _wg_pubkey_map(db: Session) -> dict[str, int]:
    """WireGuard peer public key -> user id, for traffic attribution
    (``traffic.sync_traffic`` only attributes ``wg show`` output
    through this map — without it WG bytes are parsed and ignored)."""
    mapping: dict[str, int] = {}
    rows = (
        db.query(Client.uuid, Client.user_id)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .filter(Inbound.protocol == "wireguard", Client.enabled.is_(True))
        .all()
    )
    for public_key, user_id in rows:
        if public_key:
            mapping[public_key] = user_id
    return mapping


def _create_clients_for_user(db: Session, user: Any) -> None:
    """One client row per enabled inbound for a new user."""
    for inbound in db.query(Inbound).filter(Inbound.enabled.is_(True)).all():
        creds = _new_client_credentials(inbound)
        extra_json: Optional[str] = None
        if inbound.protocol == "wireguard":
            # The WG renderer needs allowed_ips per peer; allocate one.
            try:
                extra_json = json.dumps({"allowed_ips": _next_wg_address(db)})
            except ValueError:
                logger.warning("no free WireGuard address for user %s", user.name)
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


def _stream_transport(stream: dict[str, Any], protocol: str) -> str:
    """Transport ('tcp'/'udp') for clash checks: explicit value wins,
    else the protocol default (UDP for hysteria2/tuic/wireguard)."""
    transport = str(stream.get("transport") or "").lower()
    if transport in ("tcp", "udp"):
        return transport
    return "udp" if protocol in ("hysteria2", "tuic", "wireguard", "amneziawg") else "tcp"


# ---------------------------------------------------------------------------
# Public / health routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by the installer."""
    return {"status": "ok"}


@app.get("/")
def index(request: Request, db: Session = Depends(db_session)):
    """Root: dashboard when signed in, login page otherwise."""
    if _admin_from_request(request, db) is not None:
        return _redirect("/dashboard", request)
    return _redirect("/login", request)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", _template_ctx(request, {"admin": None})
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(db_session),
):
    lang = get_lang(request)
    t = t_for(lang)
    ip = request.client.host if request.client else "unknown"
    if is_locked_out is not None and is_locked_out(ip):
        return templates.TemplateResponse(request, "login.html",
            _template_ctx(request, {"admin": None, "error": t["locked_out"]}),
            status_code=429,
        )
    admin = db.query(Admin).filter(Admin.username == username).first()
    if admin is None or verify_password is None or not verify_password(password, admin.password_hash):
        if record_failed_login is not None:
            record_failed_login(ip)
        return templates.TemplateResponse(request, "login.html",
            _template_ctx(request, {"admin": None, "error": t["wrong_credentials"]}),
            status_code=401,
        )
    admin.last_login_at = datetime.now(timezone.utc)
    db.commit()
    token = create_session(db, admin, ip)
    response = _redirect("/dashboard", request)
    _set_session_cookie(response, request, token)
    return response


@app.get("/logout")
def logout(request: Request, db: Session = Depends(db_session)):
    token = request.cookies.get(SESSION_COOKIE)
    if token and invalidate_session is not None:
        try:
            invalidate_session(db, token)
        except Exception:  # noqa: BLE001
            logger.exception("invalidate_session failed")
    response = _redirect("/login", request)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    users = db.query(User).order_by(User.created_at.desc()).limit(10).all()
    total_users = db.query(User).count()
    active_users = sum(1 for u in db.query(User).all() if _user_usable(db, u))
    total_inbounds = db.query(Inbound).count()
    traffic_used = sum(u.traffic_used_bytes or 0 for u in db.query(User).all())
    today = datetime.now(timezone.utc).date()
    online = 0
    try:
        rows = db.query(TrafficDaily).filter(TrafficDaily.date == today).all()
        online = sum(1 for r in rows if (r.up_bytes or 0) + (r.down_bytes or 0) > 0)
    except Exception:  # noqa: BLE001
        online = 0
    ikev2_status: dict[str, Any] = {}
    if ikev2_mod is not None and hasattr(ikev2_mod, "get_ikev2_status"):
        try:
            ikev2_status = ikev2_mod.get_ikev2_status() or {}
        except Exception:  # noqa: BLE001
            ikev2_status = {"error": "unavailable"}
    return templates.TemplateResponse(request, "dashboard.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "users": users,
                "total_users": total_users,
                "active_users": active_users,
                "total_inbounds": total_inbounds,
                "traffic_used": traffic_used,
                "online": online,
                "ikev2_status": ikev2_status,
            },
        ),
    )


# ---------------------------------------------------------------------------
# Users (HTML)
# ---------------------------------------------------------------------------


@app.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return templates.TemplateResponse(request, "users.html", _template_ctx(request, {"admin": admin, "users": users})
    )


@app.post("/users")
def create_user(
    request: Request,
    name: str = Form(...),
    note: str = Form(""),
    traffic_limit_gb: str = Form(""),
    expires_days: str = Form(""),
    admin: Any = Depends(require_admin),
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
    errors = rerender_configs(db)
    err = "; ".join(errors) if errors else ""
    if err:
        err = t["rerender_failed"] + err
    return _redirect(f"/users/{user.id}", request, err=err)


@app.get("/users/{user_id}", response_class=HTMLResponse)
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
    base = str(request.base_url).rstrip("/")
    links = _links_for_user(db, user, host)
    clients = (
        db.query(Client)
        .filter(Client.user_id == user.id)
        .order_by(Client.inbound_id)
        .all()
    )
    inbounds = {i.id: i for i in db.query(Inbound).all()}
    return templates.TemplateResponse(request, "user_detail.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "user": user,
                "clients": clients,
                "inbounds": inbounds,
                "links": links,
                "links_available": links_mod is not None,
                "sub_url": f"{base}/sub/{user.sub_token}",
                "user_url": f"{base}/u/{user.sub_token}",
                "host": host,
            },
        ),
    )


@app.post("/users/{user_id}/toggle")
def toggle_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    user.enabled = not user.enabled
    db.commit()
    _audit(db, admin.id, "user.toggle", f"{user.name} enabled={user.enabled}")
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect(f"/users/{user_id}", request, err=err)


@app.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
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
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/users", request, err=err)


@app.post("/users/{user_id}/rotate-token")
def rotate_token(
    request: Request,
    user_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    user.sub_token = secrets.token_urlsafe(24)
    db.commit()
    _audit(db, admin.id, "user.rotate_token", user.name)
    # No core re-render needed: the subscription token is not in core configs.
    return _redirect(f"/users/{user_id}", request)


# ---------------------------------------------------------------------------
# Inbounds (HTML)
# ---------------------------------------------------------------------------


@app.get("/inbounds", response_class=HTMLResponse)
def inbounds_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    inbounds = db.query(Inbound).order_by(Inbound.port, Inbound.tag).all()
    return templates.TemplateResponse(request, "inbounds.html",
        _template_ctx(request, {"admin": admin, "inbounds": inbounds}),
    )


@app.post("/inbounds")
def create_inbound(
    request: Request,
    tag: str = Form(...),
    core: str = Form(...),
    protocol: str = Form(...),
    port: int = Form(...),
    remark: str = Form(""),
    sni: str = Form(""),
    path: str = Form(""),
    network: str = Form("tcp"),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    tag = tag.strip()
    core = core.strip().lower()
    protocol = protocol.strip().lower()
    if not NAME_RE.match(tag):
        return _redirect("/inbounds", request, err=t["invalid_name"])
    if db.query(Inbound).filter(Inbound.tag == tag).first() is not None:
        return _redirect("/inbounds", request, err=t["tag_exists"])
    if not 1 <= port <= 65535:
        return _redirect("/inbounds", request, err=t["invalid_port"])
    stream: dict[str, Any] = {
        "network": network.strip() or "tcp",
        "transport": _stream_transport({"transport": network.strip()}, protocol),
    }
    if sni.strip():
        stream["reality"] = {"sni": sni.strip(), "dest": f"{sni.strip()}:443"}
        stream["tls"] = {"sni": sni.strip()}
        stream["security"] = "reality" if protocol == "vless" else "tls"
    if path.strip():
        stream["path"] = path.strip()
    # Port clash: models.Inbound enforces UNIQUE(port, protocol), so
    # the same port on different transports may coexist (VLESS-Reality
    # TCP 443 + Hysteria2 UDP 443, DESIGN §3). A clash is the same port
    # on the SAME transport.
    for existing in db.query(Inbound).all():
        existing_stream: dict[str, Any] = {}
        if existing.stream_json:
            try:
                existing_stream = json.loads(existing.stream_json)
            except ValueError:
                existing_stream = {}
        if existing.port == port and _stream_transport(existing_stream, existing.protocol) == stream["transport"]:
            return _redirect("/inbounds", request, err=t["port_in_use"])
    inbound = Inbound(
        tag=tag,
        core=core,
        protocol=protocol,
        port=port,
        enabled=True,
        remark=remark.strip() or None,
        stream_json=json.dumps(stream),
    )
    db.add(inbound)
    db.commit()
    _audit(db, admin.id, "inbound.create", f"{tag} {protocol}:{port}")
    errors = rerender_configs(db)
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


@app.post("/inbounds/{inbound_id}/toggle")
def toggle_inbound(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    inbound = db.query(Inbound).filter(Inbound.id == inbound_id).first()
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    inbound.enabled = not inbound.enabled
    db.commit()
    _audit(db, admin.id, "inbound.toggle", f"{inbound.tag} enabled={inbound.enabled}")
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


@app.post("/inbounds/{inbound_id}/delete")
def delete_inbound(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    inbound = db.query(Inbound).filter(Inbound.id == inbound_id).first()
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    tag = inbound.tag
    db.query(Client).filter(Client.inbound_id == inbound.id).delete()
    db.delete(inbound)
    db.commit()
    _audit(db, admin.id, "inbound.delete", tag)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


# ---------------------------------------------------------------------------
# Settings (HTML)
# ---------------------------------------------------------------------------


@app.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    settings = get_settings(db)
    return templates.TemplateResponse(request, "settings.html",
        _template_ctx(request, {"admin": admin, "settings": settings}),
    )


@app.post("/settings")
def save_settings(
    request: Request,
    domain: str = Form(""),
    subscription_host: str = Form(""),
    reality_sni: str = Form(""),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    set_setting(db, "domain", domain.strip())
    set_setting(db, "subscription_host", subscription_host.strip())
    set_setting(db, "reality_sni", reality_sni.strip() or "www.microsoft.com")
    _audit(db, admin.id, "settings.update", f"domain={domain.strip()!r}")
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/settings", request, err=err)

# ---------------------------------------------------------------------------
# Public per-user pages and subscriptions (token only, no admin auth)
# ---------------------------------------------------------------------------


@app.get("/u/{token}", response_class=HTMLResponse)
def user_page(request: Request, token: str, db: Session = Depends(db_session)):
    """Human page: per-user links + QR codes. Token is the only secret."""
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None:
        return templates.TemplateResponse(request, "user_detail.html",
            _template_ctx(
                request,
                {
                    "admin": None,
                    "user": None,
                    "public": True,
                    "error": t_for(get_lang(request))["user_not_found"],
                },
            ),
            status_code=404,
        )
    settings = get_settings(db)
    host = _sub_host(request, settings)
    base = str(request.base_url).rstrip("/")
    usable = _user_usable(db, user)
    links = _links_for_user(db, user, host) if usable else []
    return templates.TemplateResponse(request, "user_detail.html",
        _template_ctx(
            request,
            {
                "admin": None,
                "user": user,
                "public": True,
                "clients": [],
                "inbounds": {},
                "links": links,
                "links_available": links_mod is not None,
                "sub_url": f"{base}/sub/{user.sub_token}",
                "user_url": f"{base}/u/{user.sub_token}",
                "host": host,
                "error": "" if usable else t_for(get_lang(request))["user_unusable"],
            },
        ),
    )


def _subscription_response(request: Request, token: str, db: Session) -> Response:
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None or not _user_usable(db, user):
        # Disabled / expired / over-quota / unknown: 403 with an EMPTY body.
        return Response(content=b"", status_code=403)
    if subscription_mod is None:
        return Response(content=b"", status_code=503)
    settings = get_settings(db)
    host = _sub_host(request, settings)
    ua = request.headers.get("user-agent", "")
    fmt = request.query_params.get("format", "")
    try:
        chosen = subscription_mod.choose_format(ua, fmt)
    except Exception:  # noqa: BLE001
        chosen = "singbox" if fmt == "singbox" else "v2rayng"
    chosen = str(chosen).lower().replace("-", "")
    if chosen not in ("v2rayng", "singbox"):
        chosen = "singbox" if "singbox" in chosen or "json" in chosen else "v2rayng"

    expires_unix = 0
    if user.expires_at is not None:
        exp = user.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        expires_unix = int(exp.timestamp())
    userinfo = ""
    try:
        userinfo = str(
            subscription_mod.subscription_userinfo(
                user.traffic_used_bytes or 0,
                user.traffic_limit_bytes,
                expires_unix,
            )
            or ""
        )
    except Exception:  # noqa: BLE001
        logger.exception("subscription_userinfo failed")

    headers: dict[str, str] = {}
    if userinfo:
        headers["Subscription-Userinfo"] = userinfo

    if chosen == "singbox":
        outbounds: list[dict[str, Any]] = []
        for client, inbound in _usable_clients(db, user):
            try:
                inbound_dict = _inbound_dict(inbound)
                if inbound.protocol == "wireguard":
                    # The server public key is not part of the inbound
                    # row — it lives in settings (seeded from
                    # VPN_PANEL_WG_PUBLIC_KEY). Hand it to the
                    # outbound builder through the inbound's stream,
                    # where outbound_for_client looks for it.
                    stream = dict(inbound_dict.get("stream_json") or {})
                    stream.setdefault(
                        "peer_public_key",
                        (settings.get("wireguard_public_key") or ""),
                    )
                    inbound_dict["stream_json"] = stream
                outbound = subscription_mod.outbound_for_client(
                    inbound.protocol,
                    _client_dict(client, user),
                    inbound_dict,
                    host,
                    f"{user.name}-{inbound.tag}",
                )
            except Exception:  # noqa: BLE001
                logger.exception("outbound_for_client failed for %s", inbound.tag)
                continue
            if outbound:
                outbounds.append(outbound)
        try:
            feed = subscription_mod.build_singbox_feed(outbounds)
        except Exception:  # noqa: BLE001
            logger.exception("build_singbox_feed failed")
            return Response(content=b"", status_code=500)
        return JSONResponse(content=feed, headers=headers)

    links = [entry["link"] for entry in _links_for_user(db, user, host)]
    try:
        body = subscription_mod.build_v2rayng_feed(links)
    except Exception:  # noqa: BLE001
        logger.exception("build_v2rayng_feed failed")
        return Response(content=b"", status_code=500)
    if isinstance(body, str):
        body = body.encode()
    headers["Content-Type"] = "text/plain; charset=utf-8"
    return Response(content=body, headers=headers, media_type="text/plain")


@app.get("/sub/{token}")
def subscription(request: Request, token: str, db: Session = Depends(db_session)):
    """Dual-format subscription: UA sniffing + ``?format=`` override."""
    return _subscription_response(request, token, db)


@app.get("/sub/{token}/qr")
def subscription_qr(
    request: Request,
    token: str,
    link: str = Query(...),
    db: Session = Depends(db_session),
):
    """QR PNG for one share link, gated by the user's subscription token."""
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None or not _user_usable(db, user):
        return Response(content=b"", status_code=403)
    if links_mod is None or not hasattr(links_mod, "make_qr_png"):
        raise HTTPException(status_code=503, detail="QR generation unavailable")
    png = links_mod.make_qr_png(link)
    return Response(content=png, media_type="image/png")


# ---------------------------------------------------------------------------
# JSON API (mirrors the HTML forms; cookie session auth)
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    """Payload for POST /api/users."""

    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    note: str = ""
    traffic_limit_gb: Optional[float] = Field(default=None, ge=0)
    expires_days: Optional[int] = Field(default=None, ge=0)


class InboundCreate(BaseModel):
    """Payload for POST /api/inbounds."""

    tag: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    core: str = Field(..., pattern=r"^(xray|singbox|wireguard|ikev2)$")
    protocol: str = Field(..., min_length=1, max_length=32)
    port: int = Field(..., ge=1, le=65535)
    remark: str = ""
    sni: str = ""
    path: str = ""
    network: str = "tcp"


def _user_out(user: Any) -> dict[str, Any]:
    return {
        "id": user.id,
        "name": user.name,
        "enabled": bool(user.enabled),
        "traffic_limit_bytes": user.traffic_limit_bytes,
        "traffic_used_bytes": user.traffic_used_bytes or 0,
        "expires_at": user.expires_at.isoformat() if user.expires_at else None,
        "sub_token": user.sub_token,
        "note": user.note or "",
    }


def _inbound_out(inbound: Any) -> dict[str, Any]:
    return {
        "id": inbound.id,
        "tag": inbound.tag,
        "core": inbound.core,
        "protocol": inbound.protocol,
        "port": inbound.port,
        "enabled": bool(inbound.enabled),
        "remark": getattr(inbound, "remark", "") or "",
    }


@app.get("/api/users")
def api_list_users(
    admin: Any = Depends(require_admin_api),
    db: Session = Depends(db_session),
):
    return [_user_out(u) for u in db.query(User).order_by(User.id).all()]


@app.post("/api/users", status_code=201)
def api_create_user(
    payload: UserCreate,
    request: Request,
    admin: Any = Depends(require_admin_api),
    db: Session = Depends(db_session),
):
    if db.query(User).filter(User.name == payload.name).first() is not None:
        raise HTTPException(status_code=409, detail="user already exists")
    limit_bytes: Optional[int] = None
    if payload.traffic_limit_gb:
        limit_bytes = int(payload.traffic_limit_gb * 1024**3)
    expires_at: Optional[datetime] = None
    if payload.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_days)
    user = User(
        name=payload.name,
        note=payload.note or None,
        enabled=True,
        traffic_limit_bytes=limit_bytes,
        traffic_used_bytes=0,
        expires_at=expires_at,
        sub_token=secrets.token_urlsafe(24),
    )
    db.add(user)
    db.commit()
    _create_clients_for_user(db, user)
    _audit(db, admin.id, "user.create", payload.name)
    errors = rerender_configs(db)
    result = _user_out(user)
    if errors:
        result["rerender_errors"] = errors
    return result


@app.get("/api/inbounds")
def api_list_inbounds(
    admin: Any = Depends(require_admin_api),
    db: Session = Depends(db_session),
):
    return [_inbound_out(i) for i in db.query(Inbound).order_by(Inbound.port).all()]


# ---------------------------------------------------------------------------
# Run directly (dev convenience; production uses uvicorn + systemd)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=PANEL_PORT)
