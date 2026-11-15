"""sparky-manager — FastAPI application (Phase 1 MVP).

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
- ``app.wgapply``: ``apply_config(content, *, config_path,
  interface, wg_bin, wg_quick_bin, unit, run, journal, redact) ->
  ApplyResult`` — validate, ``wg-quick strip``, live ``wg
  syncconf`` when the interface is up, ``systemctl start`` when it
  is absent, restore on failure (also used for AmneziaWG with
  ``awg`` / ``awg-quick`` / ``awg0``)
- ``app.openvpn``: ``render_server_config`` / ``render_client_config``
  / ``validate_server_config`` (username/password auth via
  ``scripts/ovpn-auth.py``)
- ``app.openconnect``: ``render_ocserv_config`` /
  ``render_ocpasswd`` (SHA-512 crypt) / ``render_profile_xml`` /
  ``validate_ocserv_config``
- ``app.amneziawg``: ``generate_awg_params`` /
  ``validate_awg_params`` / ``render_server_config`` /
  ``render_peer_config`` / ``build_vpn_link`` / ``parse_vpn_link``
  / ``is_available``
- ``app.ikev2``: ``render_swanctl_config`` / ``validate_swanctl_config``
  / ``render_mobileconfig`` (plist) / ``pem_to_der`` /
  ``load_ca_cert_der`` / ``server_id_from_cert_pem``
- ``app.traffic``: ``sync_traffic(db, *, xray_stats=None, wg_text=None,
  nft_text=None, wg_pubkey_to_user_id=None, nft_port_to_user_id=None)``

Bootstrap secrets (installer contract): on first run
``ensure_defaults()`` prefers the environment variables the installer
writes to ``panel.env`` — ``SPARKY_ADMIN_PASSWORD``,
``SPARKY_REALITY_PRIVATE_KEY`` / ``_PUBLIC_KEY`` / ``_SHORT_ID``,
``SPARKY_WG_PRIVATE_KEY`` / ``_PUBLIC_KEY`` — and generates fresh
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
import hmac
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import shutil
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

logger = logging.getLogger("sparky-manager")

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

SESSION_COOKIE = "sparky_manager_session"
SESSION_MAX_AGE = 12 * 3600  # 12 hours
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# ---------------------------------------------------------------------------
# Optional / contract imports.
# Core modules (db, models, config, auth) are required for the app to run;
# service modules (links, subscription, renderers, traffic) are
# optional at import time: missing ones only disable the feature that
# needs them, never the whole panel.
# ---------------------------------------------------------------------------

try:
    from app import config as panel_config
    from app.config import normalize_web_path
except ImportError:  # pragma: no cover - sibling module not written yet
    panel_config = None  # type: ignore[assignment]
    normalize_web_path = None  # type: ignore[assignment]
    logger.warning("app.config not available yet; using built-in defaults")

try:
    from app.db import (
        SessionLocal,
        dispose_engine,
        get_session,
        init_db,
        reset_engine,
    )
except ImportError:  # pragma: no cover
    SessionLocal = None  # type: ignore[assignment]
    get_session = None  # type: ignore[assignment]
    init_db = None  # type: ignore[assignment]
    dispose_engine = None  # type: ignore[assignment]
    reset_engine = None  # type: ignore[assignment]
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
        from app.models import (
            client_is_frozen,
            client_is_usable,
            user_is_usable,
        )
    except ImportError:
        client_is_usable = None  # type: ignore[assignment]
        client_is_frozen = None  # type: ignore[assignment]
        user_is_usable = None  # type: ignore[assignment]
except ImportError:  # pragma: no cover
    models = None  # type: ignore[assignment]
    Admin = AuditLog = Client = Inbound = Setting = TrafficDaily = User = None  # type: ignore[assignment]
    client_is_usable = None  # type: ignore[assignment]
    client_is_frozen = None  # type: ignore[assignment]
    user_is_usable = None  # type: ignore[assignment]
    logger.warning("app.models not available yet")

try:
    from app import auth as auth_mod
    from app.auth import (
        create_session,
        csrf_token_for_session,
        get_admin_from_token,
        hash_password,
        invalidate_other_sessions,
        invalidate_session,
        is_locked_out,
        record_failed_login,
        record_successful_login,
        verify_csrf_token,
        verify_password,
    )
except ImportError:  # pragma: no cover
    auth_mod = None  # type: ignore[assignment]
    create_session = get_admin_from_token = hash_password = None  # type: ignore[assignment]
    invalidate_session = invalidate_other_sessions = None  # type: ignore[assignment]
    is_locked_out = record_failed_login = None  # type: ignore[assignment]
    record_successful_login = None  # type: ignore[assignment]
    csrf_token_for_session = verify_csrf_token = None  # type: ignore[assignment]
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
    from app import wgapply as wgapply_mod
except ImportError:
    wgapply_mod = None
    logger.warning("app.wgapply not available yet; WireGuard apply disabled")

try:
    from app import openvpn as openvpn_mod
except ImportError:
    openvpn_mod = None
    logger.warning("app.openvpn not available yet; OpenVPN re-render disabled")

try:
    from app import openconnect as openconnect_mod
except ImportError:
    openconnect_mod = None
    logger.warning("app.openconnect not available yet; OpenConnect re-render disabled")

try:
    from app import amneziawg as amneziawg_mod
except ImportError:
    amneziawg_mod = None
    logger.warning("app.amneziawg not available yet; AmneziaWG re-render disabled")

try:
    from app import ikev2 as ikev2_mod
except ImportError:
    ikev2_mod = None
    logger.warning("app.ikev2 not available yet; IKEv2 re-render disabled")

try:
    from app import traffic as traffic_mod
except ImportError:
    traffic_mod = None
    logger.warning("app.traffic not available yet; traffic sync disabled")

try:
    from app import panel_log as panel_log_mod
except ImportError:
    panel_log_mod = None
    logger.warning("app.panel_log not available yet; file logging disabled")

try:
    from app import telegram as telegram_mod
except ImportError:
    telegram_mod = None
    logger.warning("app.telegram not available yet; notifications disabled")

try:
    from app import system_status as system_status_mod
except ImportError:
    system_status_mod = None
    logger.warning("app.system_status not available yet; server status disabled")

try:
    from app import charts as charts_mod
except ImportError:
    charts_mod = None
    logger.warning("app.charts not available yet; traffic charts disabled")

try:
    from app import backup as backup_mod
except ImportError:
    backup_mod = None
    logger.warning("app.backup not available yet; backup/restore disabled")

try:
    from app import bot as bot_mod
except ImportError:
    bot_mod = None
    logger.warning("app.bot not available yet; Telegram bot disabled")

if panel_log_mod is not None:
    # Rotating file log (data/logs/panel.log) + console (systemd
    # journal). Idempotent; in tests DATA_DIR points at the temp home,
    # so test logs never touch the real install.
    panel_log_mod.setup_panel_logging()


def _redact(text: object) -> str:
    """Mask credential-shaped text before it reaches a log line."""
    if panel_log_mod is not None:
        return panel_log_mod.redact(text)
    return str(text)

def _cfg_attr(name: str, default: Any) -> Any:
    """Read an attribute from app.config, falling back to ``default``."""
    if panel_config is not None:
        return getattr(panel_config, name, default)
    return default


def _web_prefix() -> str:
    """Secret panel web path: "" (panel at root) or "/<segment>"."""
    raw = _cfg_attr("WEB_PATH", "") or ""
    if normalize_web_path is None:
        return ""
    try:
        return normalize_web_path(str(raw))
    except ValueError:
        logger.warning("invalid SPARKY_WEB_PATH %r; panel served at root", raw)
        return ""


WEB_PATH = _web_prefix()

# Honor X-Forwarded-Proto for the session cookie's Secure flag only
# when the operator declared a trusted TLS-terminating proxy
# (SPARKY_TRUST_FORWARDED_PROTO=1). Default False: the standard
# install terminates TLS in uvicorn, and an untrusted client could
# spoof the header (S4).
TRUST_FORWARDED_PROTO = bool(_cfg_attr("TRUST_FORWARDED_PROTO", False))


def _is_secure_request(request: Request) -> bool:
    """True when this request arrived over HTTPS — directly, or via a
    trusted TLS-terminating proxy (see TRUST_FORWARDED_PROTO)."""
    if request.url.scheme == "https":
        return True
    if TRUST_FORWARDED_PROTO:
        forwarded = request.headers.get("x-forwarded-proto", "")
        # First value wins when proxies chain the header.
        return forwarded.split(",")[0].strip().lower() == "https"
    return False


PANEL_PORT = _cfg_attr("PANEL_PORT", 2053)
DATA_DIR = Path(_cfg_attr("DATA_DIR", "/opt/sparky-manager/data"))
# app.config names these XRAY_CONFIG / SINGBOX_CONFIG / WG_CONFIG.
XRAY_CONFIG_PATH = _cfg_attr("XRAY_CONFIG", "/usr/local/etc/xray/config.json")
XRAY_BINARY = _cfg_attr("XRAY_BINARY", "/usr/local/bin/xray")
SINGBOX_CONFIG_PATH = _cfg_attr("SINGBOX_CONFIG", "/etc/sing-box/config.json")
SINGBOX_BINARY = _cfg_attr("SINGBOX_BINARY", "/usr/local/bin/sing-box")
WG_CONFIG_PATH = _cfg_attr("WG_CONFIG", "/etc/wireguard/wg0.conf")
OVPN_CONFIG_PATH = _cfg_attr("OVPN_CONFIG", "/etc/openvpn/server/sparky-manager.conf")
OCSERV_CONFIG_PATH = _cfg_attr("OCSERV_CONFIG", "/etc/ocserv/ocserv.conf")
OCSERV_PASSWD_PATH = _cfg_attr("OCSERV_PASSWD", "/etc/ocserv/ocpasswd")
AWG_CONFIG_PATH = _cfg_attr("AWG_CONFIG", "/etc/amnezia/amneziawg/awg0.conf")
SWANCTL_CONFIG_PATH = _cfg_attr("SWANCTL_CONFIG", "/etc/swanctl/swanctl.conf")
CA_CERT_PATH = _cfg_attr("CA_CERT", "/opt/sparky-manager/data/ca/ca-cert.pem")
CA_KEY_PATH = _cfg_attr("CA_KEY", "/opt/sparky-manager/data/ca/ca-key.pem")
VPN_SERVER_CERT_PATH = _cfg_attr("VPN_SERVER_CERT", "/opt/sparky-manager/data/ca/server-cert.pem")
VPN_SERVER_KEY_PATH = _cfg_attr("VPN_SERVER_KEY", "/opt/sparky-manager/data/ca/server-key.pem")
OVPN_AUTH_SCRIPT_PATH = _cfg_attr(
    "OVPN_AUTH_SCRIPT", "/opt/sparky-manager/scripts/ovpn-auth.py"
)

# Secrets the installer writes to panel.env / install.env (loaded via the
# systemd unit's EnvironmentFile). ensure_defaults() prefers these over
# generating fresh values, so the installer's login box always matches
# what the app actually uses. Never logged.
ENV_ADMIN_PASSWORD = "SPARKY_ADMIN_PASSWORD"
ENV_REALITY_PRIVATE_KEY = "SPARKY_REALITY_PRIVATE_KEY"
ENV_REALITY_PUBLIC_KEY = "SPARKY_REALITY_PUBLIC_KEY"
ENV_REALITY_SHORT_ID = "SPARKY_REALITY_SHORT_ID"
ENV_WG_PRIVATE_KEY = "SPARKY_WG_PRIVATE_KEY"
ENV_WG_PUBLIC_KEY = "SPARKY_WG_PUBLIC_KEY"
ENV_AWG_PRIVATE_KEY = "SPARKY_AWG_PRIVATE_KEY"
ENV_AWG_PUBLIC_KEY = "SPARKY_AWG_PUBLIC_KEY"

# ---------------------------------------------------------------------------
# i18n — inline fa/en strings (no app.i18n dependency).
# ---------------------------------------------------------------------------

STRINGS: dict[str, dict[str, str]] = {
    "fa": {
        "app_name": "Sparky Manager",
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
        "csrf_error_title": "درخواست نامعتبر است",
        "csrf_error_message": "توکن امنیتی این فرم معتبر نیست یا منقضی شده است. لطفاً صفحه را تازه‌سازی کنید و دوباره تلاش کنید.",
        "total_users": "کل کاربران",
        "active_users": "کاربران فعال",
        "total_inbounds": "کل اینباندها",
        "traffic_used": "ترافیک مصرف‌شده",
        "online_now": "آنلاین (تقریبی)",
        "recent_users": "کاربران اخیر",
        "protocol_distribution": "توزیع پروتکل‌ها",
        "recent_activity": "فعالیت‌های اخیر",
        "view_all": "مشاهدهٔ همه",
        "refresh": "تازه‌سازی",
        "search_inbounds": "جستجوی اینباند…",
        "all_protocols": "همهٔ پروتکل‌ها",
        "all_statuses": "همهٔ وضعیت‌ها",
        "no_matches": "موردی پیدا نشد.",
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
        "new_values": "مقادیر جدید",
        "port_auto_hint": "پورت و برچسب خودکار ساخته می‌شوند؛ کافیست ثبت کنید.",
        "zedsecure_bundle": "خروجی ZedSecure",
        "zedsecure_hint": "یک فایل JSON با همهٔ کانفیگ‌های این کاربر، مخصوص اپ ZedSecure.",
        "file_exports": "فایل‌های کانفیگ",
        "file_exports_hint": "فایل آمادهٔ دانلود برای پروتکل‌هایی که لینک اشتراک ندارند (OpenVPN ،OpenConnect ،AmneziaWG ،IKEv2).",
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
        "port_reserved": "پورت‌های ۵۰۰ و ۴۵۰۰ برای IKEv2 رزرو شده‌اند و نمی‌توان آن‌ها را به اینباند داد.",
        "invalid_name": "نام فقط می‌تواند شامل حروف، عدد، - و _ باشد.",
        "name_exists": "کاربری با این نام از قبل وجود دارد.",
        "tag_exists": "اینباندی با این برچسب از قبل وجود دارد.",
        "traffic_today": "ترافیک امروز",
        "sub_token": "توکن اشتراک",
        "created_at": "ساخته شده",
        "details": "جزئیات",
        "logs": "لاگ‌ها",
        "log_level": "سطح لاگ",
        "log_level_hint": "DEBUG جزئیات بیشتری می‌نویسد (برای دیباگ خطاها)؛ بدون ری‌استارت اعمال می‌شود.",
        "log_download": "دانلود لاگ",
        "log_clear": "پاک‌کردن لاگ",
        "log_search": "جستجو در لاگ",
        "log_search_ph": "متن موردنظر…",
        "log_filter_level": "سطح",
        "log_empty": "هنوز لاگی نوشته نشده است.",
        "log_file": "فایل لاگ",
        "log_files": "فایل‌های لاگ",
        "log_cleared": "لاگ پاک شد.",
        "log_time": "زمان",
        "log_message": "پیام",
        "logs_hint": "جدیدترین خط‌ها اول می‌آیند. خطاها و ری‌استارت‌ها با جزئیات کامل اینجا ثبت می‌شوند.",
        "confirm_clear_logs": "لاگ فعلی پاک شود؟",
        "size": "اندازه",
        "footer_note": "پنل VPN — فاز ۱",
        # Inbound editor (Phase 1 of the professional-panel expansion).
        "edit": "ویرایش",
        "edit_inbound": "ویرایش اینباند",
        "back_to_inbounds": "بازگشت به اینباندها",
        "basic_settings": "تنظیمات پایه",
        "security": "امنیت",
        "security_none": "بدون امنیت",
        "transport": "ترانسپورت",
        "host_header": "هاست (Host header)",
        "service_name": "نام سرویس gRPC",
        "xhttp_mode": "حالت XHTTP",
        "fingerprint": "اثرانگشت (Fingerprint)",
        "reality_settings": "تنظیمات Reality",
        "reality_dest": "مقصد (dest)",
        "reality_server_names": "نام‌های سرور (با کاما جدا کنید)",
        "short_id": "Short ID",
        "private_key": "کلید خصوصی",
        "public_key": "کلید عمومی",
        "regenerate": "تولید دوباره",
        "regenerate_reality_hint": "کلید و Short ID جدید ساخته می‌شود — لینک‌های قدیمی از کار می‌افتند.",
        "tls_settings": "تنظیمات TLS",
        "tls_sni": "SNI برای TLS",
        "tls_alpn": "ALPN (با کاما جدا کنید)",
        "tls_cert_path": "مسیر گواهی (cert)",
        "tls_key_path": "مسیر کلید (key)",
        "tls_paths_hint": "خالی یعنی گواهی پنل (Let's Encrypt یا خودامضا) استفاده می‌شود.",
        "sniffing": "اسنیفینگ (تشخیص پروتکل)",
        "sniffing_hint": "تشخیص خودکار پروتکل ترافیک (HTTP/TLS/QUIC) برای روتینگ بهتر.",
        "fallbacks": "فالبک‌ها (Fallbacks)",
        "fallbacks_hint": "هر خط یک مقصد: host:port یا host:port,xver — برای سرو چند پروتکل روی یک پورت.",
        "up_mbps": "سقف آپلود (Mbps، خالی = بدون سقف)",
        "down_mbps": "سقف دانلود (Mbps، خالی = بدون سقف)",
        "congestion_control": "کنترل ازدحام",
        "zero_rtt": "0-RTT (اتصال مجدد سریع‌تر)",
        "strict_mode": "حالت سخت‌گیرانه (Strict mode)",
        "inner_port": "پورت داخلی (Inner SS)",
        "shadowtls_password": "رمز ShadowTLS",
        "method": "روش رمزنگاری",
        "subnet": "زیرشبکه (Subnet)",
        "subnet_hint_wg": "آدرس سرور اولین آدرس این زیرشبکه می‌شود؛ آدرس‌های فعلی کاربرها تغییر نمی‌کند.",
        "mtu": "MTU",
        "dns_servers": "سرورهای DNS",
        "dns_hint": "با کاما جدا کنید؛ حداکثر دو سرور.",
        "server_key": "کلید سرور",
        "regenerate_server_key": "تولید کلید سرور جدید",
        "regenerate_server_key_hint": "کلید عمومی سرور عوض می‌شود — همهٔ کاربرها باید کانفیگ جدید بگیرند.",
        "confirm_regenerate": "آیا مطمئن هستید؟ کانفیگ‌های فعلی از کار می‌افتند.",
        "awg_params": "پارامترهای آمنزیا (Obfuscation)",
        "awg_params_hint": "این مقادیر باید در سرور و کلاینت یکسان باشند؛ با تغییر آن‌ها کاربرها باید کانفیگ جدید بگیرند.",
        "header_protection_key": "کلید محافظت از هدر",
        "proto": "پروتکل انتقال",
        "max_clients": "حداکثر کلاینت هم‌زمان",
        "listen": "آدرس گوش دادن (Listen)",
        "invalid_subnet": "زیرشبکه معتبر نیست (مثل 10.8.0.0/24).",
        "invalid_dns": "آدرس DNS معتبر نیست.",
        "invalid_mtu": "MTU باید بین ۵۷۶ تا ۹۰۰۰ باشد.",
        "invalid_fallbacks": "فرمت فالبک اشتباه است (host:port یا host:port,xver).",
        "invalid_short_id": "Short ID باید رشتهٔ هگزادسیمال با طول زوج باشد.",
        "invalid_reality_key": "کلید خصوصی Reality معتبر نیست (۴۳ کاراکتر base64url).",
        "invalid_awg_params": "پارامترهای آمنزیا معتبر نیستند: ",
        "invalid_inner_port": "پورت داخلی باید بین ۱ تا ۶۵۵۳۵ باشد.",
        "invalid_max_clients": "حداکثر کلاینت باید بین ۱ تا ۱۰۰۰۰۰ باشد.",
        "invalid_mbps": "سقف سرعت باید عدد مثبت باشد.",
        "invalid_transport": "ترنسپورت یا امنیت انتخاب‌شده معتبر نیست.",
        "invalid_input": "ورودی معتبر نیست.",
        "reality_key_failed": "ساخت کلیدهای Reality ناموفق بود.",
        "invalid_mode": "حالت XHTTP معتبر نیست (auto / packet / stream).",
        "invalid_fingerprint": "فینگرپرینت معتبر نیست.",
        "invalid_congestion": "کنترل ازدحام معتبر نیست.",
        "invalid_method": "روش رمزنگاری معتبر نیست.",
        "reality_needs_tcp": "Reality فقط با TCP کار می‌کند — ترنسپورت را روی TCP بگذارید.",
        "inbound_not_found": "اینباند پیدا نشد.",
        "inbound_updated": "اینباند به‌روز شد.",
        "reality_regenerated": "کلیدهای Reality تازه ساخته شدند.",
        "awg_params_regenerated": "پارامترهای آمنزیا تازه ساخته شدند.",
        "server_key_regenerated": "کلید سرور تازه ساخته شد — کاربرها باید کانفیگ جدید بگیرند.",
        # User editor (Phase 2 of the professional-panel expansion).
        "edit_user": "ویرایش کاربر",
        "back_to_user": "بازگشت به کاربر",
        "expiry_date": "تاریخ انقضا (خالی = بدون انقضا)",
        "expiry_date_hint": "تاریخ به وقت UTC است و کاربر تا پایان همان روز معتبر می‌ماند.",
        "flow": "Flow (XTLS)",
        "flow_none": "بدون Flow",
        "ip_limit": "سقف آی‌پی هم‌زمان",
        "ip_limit_hint": "خالی یا صفر یعنی نامحدود. فعلاً فقط ذخیره و نمایش داده می‌شود — پنل راهی برای دیدن آی‌پی‌های متصل ندارد و سقف را اعمال نمی‌کند.",
        "frozen": "فریز شده",
        "freeze": "فریز",
        "unfreeze": "آزاد کردن فریز",
        "freeze_hint": "کاربر فریز شده نمی‌تواند وصل شود، ولی کانفیگ و سابقهٔ ترافیکش حفظ می‌شود.",
        "move_to": "انتقال به اینباند",
        "keep_inbound": "— همین اینباند —",
        "move_hint": "فقط اینباندهای هم‌پروتکل که کاربر در آن‌ها کلاینت ندارد. برای وایرگارد/آمنزیا آدرس جدید از ساب‌نت مقصد گرفته می‌شود.",
        "per_client_settings": "تنظیمات هر کلاینت",
        "no_clients": "این کاربر کلاینتی ندارد.",
        "bulk_actions": "عملیات گروهی",
        "bulk_enable": "فعال‌کردن انتخاب‌شده‌ها",
        "bulk_disable": "غیرفعال‌کردن انتخاب‌شده‌ها",
        "bulk_delete": "حذف انتخاب‌شده‌ها",
        "bulk_reset_traffic": "صفر کردن ترافیک انتخاب‌شده‌ها",
        "bulk_extend_expiry": "تمدید انقضا",
        "extend_days": "تمدید (روز)",
        "extend_days_hint": "به انقضای فعلی اضافه می‌شود؛ برای کاربر بدون انقضا از امروز حساب می‌شود.",
        "reset_traffic": "صفر کردن ترافیک",
        "no_users_selected": "هیچ کاربری انتخاب نشده است.",
        "invalid_action": "عملیات انتخاب‌شده معتبر نیست.",
        "invalid_extend_days": "روزهای تمدید باید بین ۱ تا ۳۶۵۰ باشد.",
        "invalid_expiry_date": "تاریخ انقضا معتبر نیست (قالب: YYYY-MM-DD).",
        "invalid_ip_limit": "سقف آی‌پی باید بین ۱ تا ۱۰۰۰ باشد (خالی = نامحدود).",
        "invalid_flow": "Flow انتخاب‌شده معتبر نیست.",
        "flow_needs_tls": "Flow فقط با TLS یا Reality کار می‌کند.",
        "flow_needs_vision": "برای اینباند Reality باید یک Flow از نوع Vision انتخاب شود.",
        "move_invalid_target": "اینباند مقصد برای انتقال معتبر نیست.",
        "move_address_exhausted": "در ساب‌نت اینباند مقصد آدرس آزاد نیست.",
        "user_updated": "کاربر به‌روز شد.",
        "user_frozen": "کاربر فریز شد — کلاینت‌هایش از کانفیگ‌ها حذف شدند.",
        "user_unfrozen": "فریز کاربر برداشته شد.",
        "bulk_done": "عملیات گروهی انجام شد.",
        "confirm_bulk_delete": "کاربران انتخاب‌شده حذف شوند؟ این عمل قابل بازگشت نیست.",
        "select_all": "انتخاب همه",
        "traffic_reset_hint": "فقط شمارندهٔ ترافیک صفر می‌شود؛ سابقهٔ روزانه حفظ می‌شود.",
        # Panel & server settings (Phase 3 of the professional-panel expansion).
        "change_password": "تغییر رمز عبور",
        "current_password": "رمز عبور فعلی",
        "new_password": "رمز عبور جدید",
        "confirm_password": "تکرار رمز عبور جدید",
        "password_too_short": "رمز عبور جدید باید حداقل ۸ کاراکتر باشد.",
        "password_mismatch": "تکرار رمز عبور با رمز جدید یکی نیست.",
        "wrong_current_password": "رمز عبور فعلی اشتباه است.",
        "password_changed": "رمز عبور عوض شد — نشست‌های دیگر خارج شدند.",
        "password_change_hint": "بعد از تغییر، فایل ورود نصب‌کننده (/root/sparky-manager-login.txt) هنوز رمز قدیمی را دارد.",
        "telegram_notifications": "اعلان‌های تلگرام",
        "telegram_bot_token": "توکن ربات تلگرام",
        "telegram_bot_token_hint": "خالی بگذارید تا توکن فعلی حفظ شود. توکن هیچ‌وقت نمایش داده نمی‌شود.",
        "telegram_configured": "توکن تنظیم شده",
        "telegram_chat_id": "آیدی چت تلگرام (عدد)",
        "telegram_chat_id_hint": "آیدی عددی چت مدیر؛ می‌توانید از ربات @userinfobot بگیرید.",
        "telegram_test": "ارسال پیام آزمایشی",
        "telegram_test_sent": "پیام آزمایشی ارسال شد.",
        "telegram_test_failed": "ارسال پیام آزمایشی ناموفق بود — توکن و آیدی چت را بررسی کنید.",
        "telegram_not_configured": "تلگرام تنظیم نشده است — اول توکن و آیدی چت را ذخیره کنید.",
        "invalid_chat_id": "آیدی چت باید عدد باشد (مثلاً 123456789 یا برای گروه با - شروع می‌شود).",
        "backup_restore": "پشتیبان‌گیری و بازیابی",
        "backup_download": "دانلود پشتیبان",
        "backup_hint": "فایل ZIP شامل دیتابیس پنل و اطلاعات نسخه است. این فایل همهٔ رمزها، کلیدهای خصوصی و توکن ربات را دارد — مثل یک کلید خصوصی با آن رفتار کنید و هرگز آن را به اشتراک نگذارید.",
        "restore_backup": "بازیابی از پشتیبان",
        "restore_file": "فایل پشتیبان (ZIP یا .db)",
        "restore_confirm": "می‌دانم که وضعیت فعلی پنل جایگزین می‌شود (از وضعیت فعلی اول پشتیبان گرفته می‌شود).",
        "restore": "بازیابی",
        "restore_hint": "بعد از بازیابی ممکن است لازم باشد دوباره وارد شوید.",
        "restore_done": "بازیابی انجام شد — کانفیگ‌ها بازسازی شدند.",
        "restore_no_file": "فایلی انتخاب نشده است.",
        "restore_confirm_required": "برای بازیابی باید تأیید کنید.",
        "restore_invalid": "فایل پشتیبان معتبر نیست: ",
        "restore_newer_schema": "این پشتیبان از نسخهٔ جدیدتری است و با این پنل سازگار نیست.",
        "restore_failed": "بازیابی ناموفق بود.",
        "server_status": "وضعیت سرور",
        "cpu_load": "بار پردازنده (۱ / ۵ / ۱۵ دقیقه)",
        "memory": "حافظه (RAM)",
        "disk": "دیسک",
        "uptime": "مدت روشن بودن سرور",
        "service": "سرویس",
        "service_running": "در حال اجرا",
        "service_stopped": "متوقف",
        "service_unknown": "نامشخص",
        "traffic_chart": "ترافیک ۱۴ روز گذشته",
        "traffic_chart_user": "ترافیک این کاربر — ۱۴ روز گذشته",
        "traffic_total_14d": "مجموع ۱۴ روز گذشته",
        "no_traffic_data": "هنوز ترافیکی ثبت نشده است.",
        "tg_test": "🔔 sparky-manager: پیام آزمایشی — اعلان‌های تلگرام فعال‌اند.",
        "tg_user_created": "👤 کاربر جدید ساخته شد: {name}",
        "tg_user_expiring": "⏰ کاربر «{name}» تا {hours} ساعت دیگر منقضی می‌شود.",
        "tg_rerender_failed": "⚠️ بازسازی کانفیگ‌ها ناموفق بود: {errors}",
        # Telegram management bot — webhook settings (Phase 4).
        "telegram_webhook": "ربات تلگرام (مدیریت کامل)",
        "telegram_webhook_hint": "با ثبت وب‌هوک، ربات از تلگرام به همهٔ کارهای پنل دسترسی دارد: کاربر، اینباند، لینک و وضعیت سرور. فقط آیدی چت مدیر بالا می‌تواند از ربات استفاده کند.",
        "telegram_webhook_register": "ثبت / به‌روزرسانی وب‌هوک",
        "telegram_webhook_refresh": "بررسی وضعیت وب‌هوک",
        "telegram_webhook_url": "آدرس وب‌هوک",
        "telegram_webhook_registered_at": "ثبت‌شده در",
        "telegram_webhook_pending": "به‌روزرسانی‌های در انتظار",
        "telegram_webhook_last_error": "آخرین خطا",
        "telegram_webhook_not_registered": "وب‌هوک ثبت نشده است.",
        "telegram_webhook_registered": "وب‌هوک ثبت شد — ربات در تلگرام فعال است.",
        "telegram_webhook_failed": "ثبت وب‌هوک ناموفق بود:",
        "telegram_webhook_status_ok": "وضعیت وب‌هوک به‌روز شد.",
        "telegram_webhook_status_failed": "دریافت وضعیت وب‌هوک ناموفق بود — توکن و اتصال را بررسی کنید.",
        "telegram_domain_required": "برای وب‌هوک اول باید دامنه را در تنظیمات وارد کنید.",
        "telegram_webhook_port_warning": "تلگرام فقط روی پورت‌های ۴۴۳، ۸۰، ۸۸ و ۸۴۴۳ وب‌هوک می‌فرستد؛ پورت فعلی پنل در این لیست نیست (نصب‌کننده را با ‎--port 8443‎ دوباره اجرا کنید یا از ریورس‌پروکسی استفاده کنید).",
        # Telegram management bot — transport (polling, Phase 4 follow-up).
        "telegram_transport": "روش دریافت پیام‌های ربات",
        "telegram_transport_webhook": "وب‌هوک",
        "telegram_transport_polling": "پولینگ (دریافت دوره‌ای)",
        "telegram_transport_hint": "پولینگ پیش‌فرض است و روی هر پورتی کار می‌کند؛ وب‌هوک فقط روی پورت‌های ۴۴۳، ۸۰، ۸۸ و ۸۴۴۳ کار می‌کند. تغییر روش بلافاصله اعمال می‌شود و نیازی به ری‌استارت پنل نیست.",
        "telegram_polling_active": "پولینگ فعال شد — ربات پیام‌ها را مستقیم از تلگرام می‌گیرد.",
        "telegram_polling_webhook_failed": "حذف وب‌هوک از تلگرام ناموفق بود — تا وب‌هوک حذف نشود پولینگ پیامی نمی‌گیرد؛ دوباره ذخیره کنید تا تلاش شود.",
        # Telegram management bot — diagnostics + commands (upgrade Phase 3).
        "telegram_diag": "وضعیت اتصال تلگرام",
        "telegram_diag_mode": "روش اتصال",
        "telegram_diag_bot": "ربات",
        "telegram_diag_chat": "چت مجاز",
        "telegram_diag_commands_registered": "دستورات ثبت‌شده در",
        "telegram_diag_polling_last_poll": "آخرین پولینگ موفق",
        "telegram_diag_polling_last_update": "آخرین پیام دریافتی",
        "telegram_diag_polling_last_error": "آخرین خطای پولینگ",
        "telegram_diag_polling_offset": "شمارهٔ آخرین به‌روزرسانی",
        "telegram_diag_never": "هنوز نه",
        "telegram_diag_identity_unknown": "نامشخص — «بررسی هویت ربات» را بزنید.",
        "telegram_commands_register": "ثبت دستورات ربات",
        "telegram_commands_registered": "دستورات ربات در تلگرام ثبت شد.",
        "telegram_commands_failed": "ثبت دستورات ربات در تلگرام ناموفق بود:",
        "telegram_identity_refresh": "بررسی هویت ربات",
        "telegram_identity_ok": "هویت ربات به‌روز شد.",
        "telegram_identity_failed": "دریافت هویت ربات ناموفق بود — توکن و اتصال را بررسی کنید.",
        # Telegram management bot — bot strings (Phase 4).
        "bot_welcome": "🤖 ربات مدیریت sparky-manager\n\nاز منو انتخاب کنید:",
        "bot_help": "🤖 راهنمای ربات\n\n/start — منوی اصلی\n/help — همین راهنما\n/menu — منوی اصلی\n/status — وضعیت سرور و ترافیک\n/users — فهرست کاربران\n/inbounds — فهرست اینباندها\n/cancel — لغو عملیات در حال انجام\n\nاز منو می‌توانید کاربران را ببینید، جستجو و ویرایش کنید و بسازید، فریز/حذف/تمدید کنید، اینباندها را بسازید و فعال/غیرفعال/حذف کنید، لینک هر کاربر را بگیرید، سرویس‌ها را ریستارت کنید، بکاپ بگیرید و وضعیت سرور را ببینید.",
        "bot_menu_users": "👥 کاربران",
        "bot_menu_inbounds": "📡 اینباندها",
        "bot_menu_status": "📊 وضعیت سرور",
        "bot_menu_help": "❓ راهنما",
        "bot_back_main": "🔙 منوی اصلی",
        "bot_back_users": "🔙 کاربران",
        "bot_back_inbounds": "🔙 اینباندها",
        "bot_back": "🔙 بازگشت",
        "bot_cancel": "❌ لغو",
        "bot_cancelled": "لغو شد.",
        "bot_users_title": "👥 کاربران (صفحه {page} از {pages})",
        "bot_no_users": "هنوز کاربری ساخته نشده است.",
        "bot_prev": "◀️ قبلی",
        "bot_next": "بعدی ▶️",
        "bot_new_user": "➕ کاربر جدید",
        "bot_user_not_found": "کاربر پیدا نشد.",
        "bot_inbound_not_found": "اینباند پیدا نشد.",
        "bot_status_enabled": "فعال",
        "bot_status_disabled": "غیرفعال",
        "bot_status_expired": "منقضی‌شده",
        "bot_status_over_quota": "تمام‌شده (حجم)",
        "bot_status_frozen": "فریز شده",
        "bot_traffic": "ترافیک",
        "bot_expires": "انقضا",
        "bot_never": "هرگز",
        "bot_unlimited": "نامحدود",
        "bot_inbounds": "اینباندها",
        "bot_days_left": "{days} روز مانده",
        "bot_links": "🔗 لینک‌ها",
        "bot_links_title": "🔗 لینک‌های {name}",
        "bot_sub_link": "سابسکریپشن",
        "bot_no_links": "برای این کاربر لینکی نیست (کاربر غیرفعال یا منقضی است، یا کلاینتی ندارد).",
        "bot_no_host": "برای ساخت لینک اول باید دامنه یا هاست سابسکریپشن را در تنظیمات پنل وارد کنید.",
        "bot_freeze": "🧊 فریز",
        "bot_unfreeze": "❄️ رفع فریز",
        "bot_frozen": "کاربر فریز شد.",
        "bot_unfrozen": "فریز کاربر برداشته شد.",
        "bot_extend": "⏰ تمدید",
        "bot_extend_prompt": "تمدید «{name}» — چند روز؟",
        "bot_extend_days": "+{days} روز",
        "bot_extended": "انقضای کاربر {days} روز تمدید شد.",
        "bot_reset_traffic": "🔄 ریست ترافیک",
        "bot_reset_confirm": "ترافیک «{name}» صفر شود؟ سابقهٔ روزانه حفظ می‌شود.",
        "bot_traffic_reset": "ترافیک کاربر صفر شد.",
        "bot_delete": "🗑️ حذف",
        "bot_delete_confirm": "«{name}» حذف شود؟ این عمل قابل بازگشت نیست.",
        "bot_deleted": "کاربر حذف شد.",
        "bot_confirm_yes": "✅ بله",
        "bot_confirm_no": "❌ خیر",
        "bot_create_name": "➕ ساخت کاربر جدید\n\nنام کاربر را بفرستید (فقط حروف، عدد، ‎-‎ و ‎_‎):",
        "bot_create_name_invalid": "نام معتبر نیست — فقط حروف انگلیسی، عدد، ‎-‎ و ‎_‎ مجاز است. دوباره بفرستید:",
        "bot_create_name_exists": "کاربری با این نام هست. نام دیگری بفرستید:",
        "bot_create_pick_inbounds": "اینباندهای این کاربر را انتخاب کنید (با ضربه زدن روشن/خاموش می‌شوند؛ پیش‌فرض همهٔ اینباندهای فعال):",
        "bot_create_no_inbounds": "اینباند فعالی نیست — اول از پنل یک اینباند بسازید و فعال کنید.",
        "bot_create_pick_one": "حداقل یک اینباند انتخاب کنید.",
        "bot_create_limit": "حجم کاربر (گیگابایت)؟ ۰ یا خالی یعنی نامحدود:",
        "bot_create_limit_invalid": "عدد معتبر نیست — حجم را به گیگابایت بفرستید (مثلاً ۱۰) یا ۰ برای نامحدود:",
        "bot_create_expiry": "انقضا (روز)؟ ۰ یا خالی یعنی بدون انقضا:",
        "bot_create_expiry_invalid": "عدد معتبر نیست — تعداد روز را بفرستید (مثلاً ۳۰) یا ۰ برای بدون انقضا:",
        "bot_create_done": "✅ کاربر «{name}» ساخته شد.",
        "bot_create_failed": "ساخت کاربر ناموفق بود.",
        "bot_create_confirm": "✅ انجام شد",
        "bot_use_buttons": "لطفاً از دکمه‌ها استفاده کنید (یا /cancel برای لغو).",
        "bot_flow_expired": "این عملیات منقضی شده است — دوباره شروع کنید.",
        "bot_inbounds_title": "📡 اینباندها",
        "bot_no_inbounds": "هنوز اینباندی ساخته نشده است.",
        "bot_enable": "✅ فعال کردن",
        "bot_disable": "❌ غیرفعال کردن",
        "bot_inbound_toggled": "اینباند {state} شد.",
        "bot_status_title": "📊 وضعیت سرور",
        "bot_status_users": "👥 کاربران: {total} ({enabled} فعال، {expired} منقضی)",
        "bot_traffic_today": "📈 ترافیک امروز",
        "bot_traffic_14d": "📈 ترافیک ۱۴ روز گذشته",
        "bot_unknown_command": "دستور ناشناخته است — /help را بفرستید یا از منو استفاده کنید.",
        "bot_rerender_failed": "بازسازی کانفیگ‌ها ناموفق بود:",
        "bot_action_failed": "عملیات ناموفق بود.",
        "bot_view_user": "👤 مشاهدهٔ کاربر",
        # Telegram management bot — upgrade Phase 3 (search, edit,
        # inbound create/delete, services, backup, stale callbacks).
        "bot_menu_services": "🛠️ سرویس‌ها",
        "bot_menu_backup": "📦 بکاپ",
        "bot_search": "🔍 جستجو",
        "bot_search_prompt": "🔍 جستجوی کاربر\n\nنام یا یادداشت کاربر را بفرستید (بخشی از آن کافی است):",
        "bot_search_title": "🔍 نتایج جستجو برای «{query}» (صفحه {page} از {pages})",
        "bot_search_no_match": "کاربری با این مشخصات پیدا نشد.",
        "bot_edit": "✏️ ویرایش",
        "bot_edit_pick": "کدام را ویرایش کنیم؟",
        "bot_edit_name": "نام",
        "bot_edit_limit": "حجم",
        "bot_edit_expiry": "انقضا",
        "bot_edit_name_prompt": "نام جدید «{name}» را بفرستید (فقط حروف، عدد، ‎-‎ و ‎_‎):",
        "bot_edit_limit_prompt": "حجم جدید (گیگابایت)؟ ۰ یا خالی یعنی نامحدود:",
        "bot_edit_expiry_prompt": "انقضای جدید (روز از امروز)؟ ۰ یا خالی یعنی بدون انقضا:",
        "bot_edited": "✅ ویرایش انجام شد.",
        "bot_new_inbound": "➕ اینباند جدید",
        "bot_create_inbound_protocol": "پروتکل اینباند جدید را انتخاب کنید:",
        "bot_create_inbound_port": "پورت اینباند؟ خالی یعنی خودکار:",
        "bot_create_inbound_port_invalid": "پورت معتبر نیست — عددی بین ۱ تا ۶۵۵۳۵ بفرستید یا خالی برای خودکار:",
        "bot_create_inbound_port_in_use": "این پورت روی همین پروتکل استفاده شده است — پورت دیگری بفرستید یا خالی برای خودکار:",
        "bot_create_inbound_port_reserved": "این پورت رزرو شده است (IKEv2) — پورت دیگری بفرستید:",
        "bot_create_inbound_sni": "SNI برای {protocol}؟ خالی یعنی پیش‌فرض پنل ({sni}):",
        "bot_create_inbound_done": "✅ اینباند «{tag}» ساخته شد ({protocol}:{port}).",
        "bot_create_inbound_failed": "ساخت اینباند ناموفق بود.",
        "bot_inbound_delete_confirm": "اینباند «{tag}» حذف شود؟ همهٔ کلاینت‌های آن هم حذف می‌شوند. این عمل قابل بازگشت نیست.",
        "bot_inbound_deleted": "اینباند حذف شد.",
        "bot_services_title": "🛠️ سرویس‌ها",
        "bot_service_running": "در حال اجرا",
        "bot_service_stopped": "متوقف",
        "bot_service_unknown": "نامشخص",
        "bot_service_restart": "🔄 ریستارت",
        "bot_service_restart_confirm": "سرویس «{name}» ریستارت شود؟",
        "bot_service_restarted": "✅ سرویس «{name}» ریستارت شد و در حال اجراست.",
        "bot_service_restart_failed": "❌ ریستارت «{name}» ناموفق بود:",
        "bot_service_restart_unverified": "🔄 ریستارت «{name}» انجام شد، ولی وضعیت سرویس قابل بررسی نیست.",
        "bot_services_awg_note": "ریستارت AmneziaWG از ربات ممکن نیست (دسترسی لازم در نصب‌کننده تعریف نشده است).",
        "bot_backup_title": "📦 بکاپ",
        "bot_backup_hint": "بکاپ شامل کل دیتابیس و کلیدهاست — آن را مثل کلید خصوصی نگه دارید. فقط به همین چت فرستاده می‌شود.",
        "bot_backup_send": "📦 دریافت بکاپ",
        "bot_backup_sent": "✅ بکاپ فرستاده شد.",
        "bot_backup_failed": "ساخت یا ارسال بکاپ ناموفق بود.",
        "bot_backup_too_large": "بکاپ بزرگ‌تر از حد تلگرام (۵۰ مگابایت) است — از صفحهٔ تنظیمات پنل دانلود کنید.",
        "bot_stale_callback": "این دکمه دیگر معتبر نیست — از منو ادامه بدهید.",
    },
    "en": {
        "app_name": "Sparky Manager",
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
        "csrf_error_title": "Invalid request",
        "csrf_error_message": "This form's security token is missing or expired. Please reload the page and try again.",
        "total_users": "Total users",
        "active_users": "Active users",
        "total_inbounds": "Total inbounds",
        "traffic_used": "Traffic used",
        "online_now": "Online (approx.)",
        "recent_users": "Recent users",
        "protocol_distribution": "Protocol distribution",
        "recent_activity": "Recent activity",
        "view_all": "View all",
        "refresh": "Refresh",
        "search_inbounds": "Search inbounds…",
        "all_protocols": "All protocols",
        "all_statuses": "All states",
        "no_matches": "No matches.",
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
        "new_values": "New values",
        "port_auto_hint": "Port and tag are auto-generated — just submit.",
        "zedsecure_bundle": "ZedSecure export",
        "zedsecure_hint": "One JSON file with all of this user's configs, made for the ZedSecure app.",
        "file_exports": "Config files",
        "file_exports_hint": "Ready-to-download files for the protocols without a share link (OpenVPN, OpenConnect, AmneziaWG, IKEv2).",
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
        "port_reserved": "Ports 500 and 4500 are reserved for IKEv2 and cannot be assigned to an inbound.",
        "invalid_name": "Name may only contain letters, digits, - and _.",
        "name_exists": "A user with this name already exists.",
        "tag_exists": "An inbound with this tag already exists.",
        "traffic_today": "Traffic today",
        "sub_token": "Subscription token",
        "created_at": "Created",
        "details": "Details",
        "logs": "Logs",
        "log_level": "Log level",
        "log_level_hint": "DEBUG writes more detail (for debugging errors); applies without a restart.",
        "log_download": "Download log",
        "log_clear": "Clear log",
        "log_search": "Search logs",
        "log_search_ph": "Search text…",
        "log_filter_level": "Level",
        "log_empty": "No log lines yet.",
        "log_file": "Log file",
        "log_files": "Log files",
        "log_cleared": "Log cleared.",
        "log_time": "Time",
        "log_message": "Message",
        "logs_hint": "Newest lines first. Errors and restarts are recorded here with full detail.",
        "confirm_clear_logs": "Clear the current log?",
        "size": "Size",
        "footer_note": "VPN Panel — Phase 1",
        # Inbound editor (Phase 1 of the professional-panel expansion).
        "edit": "Edit",
        "edit_inbound": "Edit inbound",
        "back_to_inbounds": "Back to inbounds",
        "basic_settings": "Basic settings",
        "security": "Security",
        "security_none": "None",
        "transport": "Transport",
        "host_header": "Host header",
        "service_name": "gRPC service name",
        "xhttp_mode": "XHTTP mode",
        "fingerprint": "Fingerprint",
        "reality_settings": "Reality settings",
        "reality_dest": "Destination (dest)",
        "reality_server_names": "Server names (comma-separated)",
        "short_id": "Short ID",
        "private_key": "Private key",
        "public_key": "Public key",
        "regenerate": "Regenerate",
        "regenerate_reality_hint": "A new keypair and short ID are generated — old links stop working.",
        "tls_settings": "TLS settings",
        "tls_sni": "TLS SNI",
        "tls_alpn": "ALPN (comma-separated)",
        "tls_cert_path": "Certificate path",
        "tls_key_path": "Key path",
        "tls_paths_hint": "Empty means the panel certificate (Let's Encrypt or self-signed) is used.",
        "sniffing": "Sniffing",
        "sniffing_hint": "Auto-detect the traffic protocol (HTTP/TLS/QUIC) for better routing.",
        "fallbacks": "Fallbacks",
        "fallbacks_hint": "One destination per line: host:port or host:port,xver — serve several protocols on one port.",
        "up_mbps": "Upload cap (Mbps, empty = no cap)",
        "down_mbps": "Download cap (Mbps, empty = no cap)",
        "congestion_control": "Congestion control",
        "zero_rtt": "0-RTT (faster reconnect)",
        "strict_mode": "Strict mode",
        "inner_port": "Inner port (inner SS)",
        "shadowtls_password": "ShadowTLS password",
        "method": "Cipher method",
        "subnet": "Subnet",
        "subnet_hint_wg": "The server takes the first address of this subnet; existing users keep their addresses.",
        "mtu": "MTU",
        "dns_servers": "DNS servers",
        "dns_hint": "Comma-separated; at most two servers.",
        "server_key": "Server key",
        "regenerate_server_key": "Regenerate server key",
        "regenerate_server_key_hint": "The server public key changes — all users must re-fetch their configs.",
        "confirm_regenerate": "Are you sure? Current configs will stop working.",
        "awg_params": "AmneziaWG obfuscation parameters",
        "awg_params_hint": "These values must match on server and client; changing them means users must re-fetch their configs.",
        "header_protection_key": "Header protection key",
        "proto": "Transport protocol",
        "max_clients": "Max simultaneous clients",
        "listen": "Listen address",
        "invalid_subnet": "Invalid subnet (e.g. 10.8.0.0/24).",
        "invalid_dns": "Invalid DNS address.",
        "invalid_mtu": "MTU must be between 576 and 9000.",
        "invalid_fallbacks": "Invalid fallback format (host:port or host:port,xver).",
        "invalid_short_id": "Short ID must be a hex string with even length.",
        "invalid_reality_key": "Invalid Reality private key (43-char base64url).",
        "invalid_awg_params": "Invalid AmneziaWG parameters: ",
        "invalid_inner_port": "Inner port must be between 1 and 65535.",
        "invalid_max_clients": "Max clients must be between 1 and 100000.",
        "invalid_mbps": "Speed cap must be a positive number.",
        "invalid_transport": "Invalid transport or security selection.",
        "invalid_input": "Invalid input.",
        "reality_key_failed": "Reality key generation failed.",
        "invalid_mode": "Invalid XHTTP mode (auto / packet / stream).",
        "invalid_fingerprint": "Invalid fingerprint.",
        "invalid_congestion": "Invalid congestion control.",
        "invalid_method": "Invalid encryption method.",
        "reality_needs_tcp": "Reality only works over TCP — set the transport to TCP.",
        "inbound_not_found": "Inbound not found.",
        "inbound_updated": "Inbound updated.",
        "reality_regenerated": "Reality keys regenerated.",
        "awg_params_regenerated": "AmneziaWG parameters regenerated.",
        "server_key_regenerated": "Server key regenerated — users must re-fetch their configs.",
        # User editor (Phase 2 of the professional-panel expansion).
        "edit_user": "Edit user",
        "back_to_user": "Back to user",
        "expiry_date": "Expiry date (empty = never)",
        "expiry_date_hint": "The date is UTC; the user stays valid through the end of that day.",
        "flow": "Flow (XTLS)",
        "flow_none": "No flow",
        "ip_limit": "Concurrent IP limit",
        "ip_limit_hint": "Empty or 0 means unlimited. Stored and shown only for now — the panel has no way to see connected IPs, so the limit is not enforced.",
        "frozen": "Frozen",
        "freeze": "Freeze",
        "unfreeze": "Unfreeze",
        "freeze_hint": "A frozen user cannot connect, but keeps configs and traffic history.",
        "move_to": "Move to inbound",
        "keep_inbound": "— keep this inbound —",
        "move_hint": "Only same-protocol inbounds without a client for this user. WireGuard/AmneziaWG get a fresh address from the target subnet.",
        "per_client_settings": "Per-client settings",
        "no_clients": "This user has no clients.",
        "bulk_actions": "Bulk actions",
        "bulk_enable": "Enable selected",
        "bulk_disable": "Disable selected",
        "bulk_delete": "Delete selected",
        "bulk_reset_traffic": "Reset traffic of selected",
        "bulk_extend_expiry": "Extend expiry",
        "extend_days": "Extend (days)",
        "extend_days_hint": "Added to the current expiry; for users without expiry it counts from today.",
        "reset_traffic": "Reset traffic",
        "no_users_selected": "No users selected.",
        "invalid_action": "Invalid bulk action.",
        "invalid_extend_days": "Extension days must be between 1 and 3650.",
        "invalid_expiry_date": "Invalid expiry date (format: YYYY-MM-DD).",
        "invalid_ip_limit": "IP limit must be between 1 and 1000 (empty = unlimited).",
        "invalid_flow": "Invalid flow selection.",
        "flow_needs_tls": "Flow only works with TLS or Reality.",
        "flow_needs_vision": "A Reality inbound needs a Vision flow.",
        "move_invalid_target": "Invalid move target inbound.",
        "move_address_exhausted": "No free address in the target inbound's subnet.",
        "user_updated": "User updated.",
        "user_frozen": "User frozen — clients removed from configs.",
        "user_unfrozen": "User unfrozen.",
        "bulk_done": "Bulk action completed.",
        "confirm_bulk_delete": "Delete the selected users? This cannot be undone.",
        "select_all": "Select all",
        "traffic_reset_hint": "Only the traffic counter is reset; daily history is kept.",
        # Panel & server settings (Phase 3 of the professional-panel expansion).
        "change_password": "Change password",
        "current_password": "Current password",
        "new_password": "New password",
        "confirm_password": "Confirm new password",
        "password_too_short": "The new password must be at least 8 characters.",
        "password_mismatch": "The confirmation does not match the new password.",
        "wrong_current_password": "The current password is wrong.",
        "password_changed": "Password changed — other sessions were signed out.",
        "password_change_hint": "After changing, the installer's login file (/root/sparky-manager-login.txt) still has the old password.",
        "telegram_notifications": "Telegram notifications",
        "telegram_bot_token": "Telegram bot token",
        "telegram_bot_token_hint": "Leave blank to keep the current token. The token is never displayed.",
        "telegram_configured": "Token configured",
        "telegram_chat_id": "Telegram chat ID (number)",
        "telegram_chat_id_hint": "The admin's numeric chat ID; you can get it from @userinfobot.",
        "telegram_test": "Send test message",
        "telegram_test_sent": "Test message sent.",
        "telegram_test_failed": "Test message failed — check the token and chat ID.",
        "telegram_not_configured": "Telegram is not configured — save a token and chat ID first.",
        "invalid_chat_id": "Chat ID must be a number (e.g. 123456789, or starting with - for a group).",
        "backup_restore": "Backup & restore",
        "backup_download": "Download backup",
        "backup_hint": "A ZIP with the panel database and version info. It contains every password, private key and the bot token — treat it like a private key and never share it.",
        "restore_backup": "Restore from backup",
        "restore_file": "Backup file (ZIP or .db)",
        "restore_confirm": "I understand the current panel state will be replaced (it is backed up first).",
        "restore": "Restore",
        "restore_hint": "You may need to log in again after a restore.",
        "restore_done": "Restore completed — configs were re-rendered.",
        "restore_no_file": "No file selected.",
        "restore_confirm_required": "Tick the confirmation box to restore.",
        "restore_invalid": "Invalid backup file: ",
        "restore_newer_schema": "This backup is from a newer version and is not compatible with this panel.",
        "restore_failed": "Restore failed.",
        "server_status": "Server status",
        "cpu_load": "CPU load (1 / 5 / 15 min)",
        "memory": "Memory (RAM)",
        "disk": "Disk",
        "uptime": "Server uptime",
        "service": "Service",
        "service_running": "Running",
        "service_stopped": "Stopped",
        "service_unknown": "Unknown",
        "traffic_chart": "Traffic — last 14 days",
        "traffic_chart_user": "This user's traffic — last 14 days",
        "traffic_total_14d": "Total, last 14 days",
        "no_traffic_data": "No traffic recorded yet.",
        "tg_test": "🔔 sparky-manager: test message — Telegram notifications are working.",
        "tg_user_created": "👤 New user created: {name}",
        "tg_user_expiring": "⏰ User “{name}” expires in {hours} hours.",
        "tg_rerender_failed": "⚠️ Config re-render failed: {errors}",
        # Telegram management bot — webhook settings (Phase 4).
        "telegram_webhook": "Telegram bot (full management)",
        "telegram_webhook_hint": "Registering the webhook lets the bot manage the whole panel from Telegram: users, inbounds, links and server status. Only the admin chat ID above can use the bot.",
        "telegram_webhook_register": "Register / update webhook",
        "telegram_webhook_refresh": "Check webhook status",
        "telegram_webhook_url": "Webhook URL",
        "telegram_webhook_registered_at": "Registered at",
        "telegram_webhook_pending": "Pending updates",
        "telegram_webhook_last_error": "Last error",
        "telegram_webhook_not_registered": "Webhook not registered.",
        "telegram_webhook_registered": "Webhook registered — the bot is live on Telegram.",
        "telegram_webhook_failed": "Webhook registration failed:",
        "telegram_webhook_status_ok": "Webhook status refreshed.",
        "telegram_webhook_status_failed": "Could not fetch webhook status — check the token and connection.",
        "telegram_domain_required": "Set a domain in settings first — the webhook needs a public HTTPS URL.",
        "telegram_webhook_port_warning": "Telegram only delivers webhooks on ports 443, 80, 88 and 8443; the panel's current port is not in that list (re-run the installer with --port 8443 or use a reverse proxy).",
        # Telegram management bot — transport (polling, Phase 4 follow-up).
        "telegram_transport": "How the bot receives updates",
        "telegram_transport_webhook": "Webhook",
        "telegram_transport_polling": "Polling",
        "telegram_transport_hint": "Polling is the default and works on any port; webhooks only work on ports 443, 80, 88 and 8443. Switching takes effect immediately — no panel restart needed.",
        "telegram_polling_active": "Polling active — the bot now fetches updates directly from Telegram.",
        "telegram_polling_webhook_failed": "Could not remove the webhook from Telegram — polling receives nothing until the webhook is removed; save again to retry.",
        # Telegram management bot — diagnostics + commands (upgrade Phase 3).
        "telegram_diag": "Telegram connection",
        "telegram_diag_mode": "Connection mode",
        "telegram_diag_bot": "Bot",
        "telegram_diag_chat": "Authorized chat",
        "telegram_diag_commands_registered": "Commands registered at",
        "telegram_diag_polling_last_poll": "Last successful poll",
        "telegram_diag_polling_last_update": "Last update received",
        "telegram_diag_polling_last_error": "Last polling error",
        "telegram_diag_polling_offset": "Last update id",
        "telegram_diag_never": "not yet",
        "telegram_diag_identity_unknown": "Unknown — press “Check bot identity”.",
        "telegram_commands_register": "Register bot commands",
        "telegram_commands_registered": "Bot commands registered on Telegram.",
        "telegram_commands_failed": "Registering the bot commands on Telegram failed:",
        "telegram_identity_refresh": "Check bot identity",
        "telegram_identity_ok": "Bot identity refreshed.",
        "telegram_identity_failed": "Could not fetch the bot identity — check the token and the connection.",
        # Telegram management bot — bot strings (Phase 4).
        "bot_welcome": "🤖 sparky-manager management bot\n\nPick from the menu:",
        "bot_help": "🤖 Bot help\n\n/start — main menu\n/help — this help\n/menu — main menu\n/status — server status and traffic\n/users — user list\n/inbounds — inbound list\n/cancel — abort the current operation\n\nFrom the menu you can list, search, edit and create users, freeze/delete/extend them, create, enable/disable and delete inbounds, get any user's links, restart services, get a backup, and check server status.",
        "bot_menu_users": "👥 Users",
        "bot_menu_inbounds": "📡 Inbounds",
        "bot_menu_status": "📊 Server status",
        "bot_menu_help": "❓ Help",
        "bot_back_main": "🔙 Main menu",
        "bot_back_users": "🔙 Users",
        "bot_back_inbounds": "🔙 Inbounds",
        "bot_back": "🔙 Back",
        "bot_cancel": "❌ Cancel",
        "bot_cancelled": "Cancelled.",
        "bot_users_title": "👥 Users (page {page} of {pages})",
        "bot_no_users": "No users yet.",
        "bot_prev": "◀️ Previous",
        "bot_next": "Next ▶️",
        "bot_new_user": "➕ New user",
        "bot_user_not_found": "User not found.",
        "bot_inbound_not_found": "Inbound not found.",
        "bot_status_enabled": "enabled",
        "bot_status_disabled": "disabled",
        "bot_status_expired": "expired",
        "bot_status_over_quota": "out of traffic",
        "bot_status_frozen": "frozen",
        "bot_traffic": "Traffic",
        "bot_expires": "Expires",
        "bot_never": "never",
        "bot_unlimited": "unlimited",
        "bot_inbounds": "Inbounds",
        "bot_days_left": "{days} days left",
        "bot_links": "🔗 Links",
        "bot_links_title": "🔗 Links for {name}",
        "bot_sub_link": "Subscription",
        "bot_no_links": "No links for this user (disabled, expired, or no clients).",
        "bot_no_host": "Set a domain or subscription host in the panel settings first — links need a server address.",
        "bot_freeze": "🧊 Freeze",
        "bot_unfreeze": "❄️ Unfreeze",
        "bot_frozen": "User frozen.",
        "bot_unfrozen": "User unfrozen.",
        "bot_extend": "⏰ Extend",
        "bot_extend_prompt": "Extend “{name}” — by how many days?",
        "bot_extend_days": "+{days} days",
        "bot_extended": "User expiry extended by {days} days.",
        "bot_reset_traffic": "🔄 Reset traffic",
        "bot_reset_confirm": "Reset “{name}”'s traffic counter to zero? Daily history is kept.",
        "bot_traffic_reset": "User traffic reset.",
        "bot_delete": "🗑️ Delete",
        "bot_delete_confirm": "Delete “{name}”? This cannot be undone.",
        "bot_deleted": "User deleted.",
        "bot_confirm_yes": "✅ Yes",
        "bot_confirm_no": "❌ No",
        "bot_create_name": "➕ New user\n\nSend the user name (letters, digits, - and _ only):",
        "bot_create_name_invalid": "Invalid name — only letters, digits, - and _ are allowed. Send it again:",
        "bot_create_name_exists": "A user with this name already exists. Send another name:",
        "bot_create_pick_inbounds": "Pick this user's inbounds (tap to toggle; all enabled inbounds are selected by default):",
        "bot_create_no_inbounds": "No enabled inbounds — create and enable one in the panel first.",
        "bot_create_pick_one": "Pick at least one inbound.",
        "bot_create_limit": "Traffic limit in GB? 0 or empty means unlimited:",
        "bot_create_limit_invalid": "Not a valid number — send the limit in GB (e.g. 10) or 0 for unlimited:",
        "bot_create_expiry": "Expiry in days? 0 or empty means never expires:",
        "bot_create_expiry_invalid": "Not a valid number — send the days (e.g. 30) or 0 for no expiry:",
        "bot_create_done": "✅ User “{name}” created.",
        "bot_create_failed": "Could not create the user.",
        "bot_create_confirm": "✅ Done",
        "bot_use_buttons": "Please use the buttons (or /cancel to abort).",
        "bot_flow_expired": "This operation expired — please start again.",
        "bot_inbounds_title": "📡 Inbounds",
        "bot_no_inbounds": "No inbounds yet.",
        "bot_enable": "✅ Enable",
        "bot_disable": "❌ Disable",
        "bot_inbound_toggled": "Inbound {state}.",
        "bot_status_title": "📊 Server status",
        "bot_status_users": "👥 Users: {total} ({enabled} enabled, {expired} expired)",
        "bot_traffic_today": "📈 Traffic today",
        "bot_traffic_14d": "📈 Traffic, last 14 days",
        "bot_unknown_command": "Unknown command — send /help or use the menu.",
        "bot_rerender_failed": "Config re-render failed:",
        "bot_action_failed": "The action failed.",
        "bot_view_user": "👤 View user",
        # Telegram management bot — upgrade Phase 3 (search, edit,
        # inbound create/delete, services, backup, stale callbacks).
        "bot_menu_services": "🛠️ Services",
        "bot_menu_backup": "📦 Backup",
        "bot_search": "🔍 Search",
        "bot_search_prompt": "🔍 Search users\n\nSend the user's name or note (part of it is enough):",
        "bot_search_title": "🔍 Results for “{query}” (page {page} of {pages})",
        "bot_search_no_match": "No user matches that search.",
        "bot_edit": "✏️ Edit",
        "bot_edit_pick": "What should I edit?",
        "bot_edit_name": "Name",
        "bot_edit_limit": "Traffic limit",
        "bot_edit_expiry": "Expiry",
        "bot_edit_name_prompt": "Send the new name for “{name}” (letters, digits, - and _ only):",
        "bot_edit_limit_prompt": "New limit in GB? 0 or empty means unlimited:",
        "bot_edit_expiry_prompt": "New expiry in days from today? 0 or empty means never expires:",
        "bot_edited": "✅ Edited.",
        "bot_new_inbound": "➕ New inbound",
        "bot_create_inbound_protocol": "Pick the protocol for the new inbound:",
        "bot_create_inbound_port": "Port for the inbound? Empty means automatic:",
        "bot_create_inbound_port_invalid": "Not a valid port — send a number between 1 and 65535, or empty for automatic:",
        "bot_create_inbound_port_in_use": "That port is already used on the same transport — send another port, or empty for automatic:",
        "bot_create_inbound_port_reserved": "That port is reserved (IKEv2) — send another port:",
        "bot_create_inbound_sni": "SNI for {protocol}? Empty means the panel default ({sni}):",
        "bot_create_inbound_done": "✅ Inbound “{tag}” created ({protocol}:{port}).",
        "bot_create_inbound_failed": "Could not create the inbound.",
        "bot_inbound_delete_confirm": "Delete inbound “{tag}”? All of its clients are deleted too. This cannot be undone.",
        "bot_inbound_deleted": "Inbound deleted.",
        "bot_services_title": "🛠️ Services",
        "bot_service_running": "running",
        "bot_service_stopped": "stopped",
        "bot_service_unknown": "unknown",
        "bot_service_restart": "🔄 Restart",
        "bot_service_restart_confirm": "Restart service “{name}”?",
        "bot_service_restarted": "✅ Service “{name}” restarted and is running.",
        "bot_service_restart_failed": "❌ Restart of “{name}” failed:",
        "bot_service_restart_unverified": "🔄 Service “{name}” was restarted, but its state could not be verified.",
        "bot_services_awg_note": "AmneziaWG cannot be restarted from the bot (the installer does not grant the needed sudo access).",
        "bot_backup_title": "📦 Backup",
        "bot_backup_hint": "The backup contains the whole database and all keys — keep it like a private key. It is only sent to this chat.",
        "bot_backup_send": "📦 Get backup",
        "bot_backup_sent": "✅ Backup sent.",
        "bot_backup_failed": "Creating or sending the backup failed.",
        "bot_backup_too_large": "The backup is larger than Telegram's limit (50 MB) — download it from the panel settings page instead.",
        "bot_stale_callback": "This button is no longer valid — continue from the menu.",
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
    db: Session, user: Any, host: str, settings: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Share links for one user's usable clients (empty when unavailable)."""
    if links_mod is None:
        return []
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


# ---------------------------------------------------------------------------
# Config re-render + core restart (best-effort; failures are reported,
# never raised into the request).
# ---------------------------------------------------------------------------


def _privileged_cmd(*args: str) -> list[str]:
    """Prefix a privileged command with ``sudo -n`` when sudo exists.

    The panel runs as the unprivileged ``sparky-manager`` user; the
    installer grants it NOPASSWD sudo for exactly the commands it
    needs (``systemctl restart/is-active/status`` for its services,
    ``wg show wg0 transfer``). ``-n`` makes sudo fail immediately
    instead of prompting for a password (a prompt would hang the
    request until the subprocess timeout). When there is no sudo
    binary (dev run), the plain command is used and the caller sees
    the real error.
    """
    if shutil.which("sudo"):
        return ["sudo", "-n", *args]
    return list(args)


def _run_privileged(
    *args: str, timeout: int = 30, use_sudo: bool = True
) -> tuple[int, str, str]:
    """Run a privileged command (via ``sudo -n`` when available).

    Returns ``(returncode, stdout, stderr)``. Every invocation is
    logged (command, exit code, stderr tail) through the redactor —
    this is what makes a failed restart debuggable: the old code only
    surfaced systemctl's generic message (``the control process
    exited``) while the real error went to the journal. Missing
    binary / timeout / OSError are reported as 127 / 124 / 1 with the
    reason on stderr, never raised.

    ``use_sudo=False`` runs the plain command (same logging and
    error handling) — for steps that need no privilege, like
    ``wg-quick strip`` (see ``app.wgapply``).
    """
    argv = _privileged_cmd(*args) if use_sudo else list(args)
    try:
        proc = subprocess.run(
            argv, timeout=timeout, capture_output=True, text=True
        )
    except FileNotFoundError:
        detail = f"command not found: {argv[0]}"
        logger.error("privileged command failed: %s", _redact(detail))
        return 127, "", detail
    except subprocess.TimeoutExpired:
        detail = f"command timed out after {timeout}s: {' '.join(argv)}"
        logger.error("privileged command failed: %s", _redact(detail))
        return 124, "", detail
    except OSError as exc:  # noqa: BLE001
        detail = f"could not run {' '.join(argv)}: {exc}"
        logger.error("privileged command failed: %s", _redact(detail))
        return 1, "", detail
    tail = (proc.stderr or proc.stdout or "").strip()
    if proc.returncode != 0:
        logger.error(
            "privileged command failed (rc=%s): %s — %s",
            proc.returncode,
            " ".join(argv),
            _redact(tail[-800:]),
        )
    else:
        logger.debug("privileged command ok (rc=0): %s", " ".join(argv))
    return proc.returncode, proc.stdout, proc.stderr


def _journal_tail(unit: str, lines: int = 50) -> str:
    """Last ``lines`` of a service's journal (redacted, "" when unavailable).

    This is what makes a failed restart debuggable: systemd captures
    the service's own stdout/stderr into the journal, and systemctl
    only prints the generic job result. Needs the sudoers entry for
    ``journalctl -u <unit> -n 50 --no-pager`` (the installer grants
    it); without it this quietly returns "".
    """
    rc, stdout, stderr = _run_privileged(
        "journalctl", "-u", unit, "-n", str(lines), "--no-pager", timeout=15
    )
    if rc != 0:
        return ""
    tail = (stdout or stderr or "").strip()
    return _redact(tail[-1500:])


def _restart_service(name: str) -> Optional[str]:
    """``systemctl restart <name>`` (via sudo when available); returns
    an error string or None. The error carries the command's own
    output plus the service's journal tail — never again a bare
    "control process exited" with no underlying output."""
    rc, stdout, stderr = _run_privileged("systemctl", "restart", name, timeout=30)
    if rc == 0:
        return None
    err = (stderr or stdout or "").strip()
    detail = _redact(err) or f"exit {rc}"
    journal = _journal_tail(name)
    if journal:
        detail += f"\njournal ({name}):\n{journal}"
    return f"restart of {name} failed: {detail}"


def _privileged_runner(argv: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Adapter so ``app.wgapply`` can run commands through sudo."""
    return _run_privileged(*argv, timeout=timeout)


def _plain_runner(argv: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Adapter so ``app.wgapply`` can run ``wg-quick strip`` without
    sudo — strip only reads a file the panel wrote and prints text."""
    return _run_privileged(*argv, timeout=timeout, use_sudo=False)


def _apply_wireguard_config(
    content: str,
    *,
    config_path: str,
    interface: str = "wg0",
    wg_bin: str = "wg",
    wg_quick_bin: str = "wg-quick",
    unit: str = "wg-quick@wg0",
    extra_interface_keys: tuple[str, ...] = (),
) -> Optional[str]:
    """Validate + apply a rendered WireGuard/AmneziaWG server config.

    Returns an error string or None (see ``app.wgapply.apply_config``
    — validate, ``wg-quick strip``, live ``wg syncconf`` when the
    interface is up, ``systemctl start`` when it is absent, restore
    on failure, full output in the error).
    """
    if wgapply_mod is None:
        return "app.wgapply is not available; config was not applied"
    try:
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"wireguard apply failed: cannot create config dir: {exc}"
    result = wgapply_mod.apply_config(
        content,
        config_path=config_path,
        interface=interface,
        wg_bin=wg_bin,
        wg_quick_bin=wg_quick_bin,
        unit=unit,
        run=_privileged_runner,
        run_unprivileged=_plain_runner,
        journal=_journal_tail,
        redact=_redact,
        extra_interface_keys=extra_interface_keys,
    )
    if result.ok:
        logger.info("wireguard config applied via %s: %s", result.method, interface)
        return None
    return f"wireguard apply failed ({result.method}): {result.detail}"


def _ikev2_server_id(settings: dict[str, Any]) -> str:
    """Identity IKEv2 clients dial (must match the server cert SAN).

    Read from the server certificate itself when it exists (always
    matches), else the configured subscription host / domain.
    """
    if ikev2_mod is not None and hasattr(ikev2_mod, "server_id_from_cert_pem"):
        try:
            pem = Path(VPN_SERVER_CERT_PATH).read_text(encoding="utf-8")
            server_id = ikev2_mod.server_id_from_cert_pem(pem)
            if server_id:
                return str(server_id)
        except OSError:
            pass
    for key in ("subscription_host", "domain"):
        value = (settings.get(key) or "").strip()
        if value:
            return value
    return ""


def _apply_ikev2_config() -> Optional[str]:
    """Apply the rendered swanctl.conf: ``swanctl --load-all`` (the
    load itself is the validator), verified with ``--list-conns``.
    When the daemon is not running, a restart loads the config from
    disk and the list is retried. Returns an error string or None."""
    conn_name = getattr(ikev2_mod, "CONNECTION_NAME", "remote-access")
    rc, out, err = _run_privileged("swanctl", "--load-all", timeout=30)
    if rc != 0:
        detail = _redact((err or out or "").strip()) or f"exit {rc}"
        # The daemon may simply not be running — a restart loads the
        # config from disk, so try that before giving up.
        restart_err = _restart_service("strongswan")
        if restart_err:
            return (
                f"ikev2 apply failed: swanctl --load-all: {detail}; "
                f"{restart_err}"
            )
        rc2, out2, err2 = _run_privileged("swanctl", "--list-conns", timeout=15)
        if rc2 != 0 or conn_name not in (out2 or ""):
            detail2 = _redact((err2 or out2 or "").strip()) or f"exit {rc2}"
            return (
                "ikev2 apply failed: strongswan restarted but the "
                f"'{conn_name}' connection is not listed: {detail2}"
            )
        return None
    rc2, out2, err2 = _run_privileged("swanctl", "--list-conns", timeout=15)
    if rc2 != 0 or conn_name not in (out2 or ""):
        detail2 = _redact((err2 or out2 or "").strip()) or f"exit {rc2}"
        return (
            "ikev2 apply failed: swanctl --load-all succeeded but the "
            f"'{conn_name}' connection is not listed: {detail2}"
        )
    return None


def rerender_configs(db: Session) -> list[str]:
    """Re-render all server configs from the DB (Xray / sing-box /
    WireGuard / OpenVPN / ocserv / AmneziaWG / IKEv2).

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
    ovpn_inbounds = [i for i in inbounds if i.core == "openvpn" and i.enabled]
    ocserv_inbounds = [i for i in inbounds if i.core == "openconnect" and i.enabled]
    awg_inbounds = [i for i in inbounds if i.core == "amneziawg" and i.enabled]
    ikev2_inbounds = [i for i in inbounds if i.core == "ikev2" and i.enabled]

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
            # (seeded from SPARKY_WG_PRIVATE_KEY by ensure_defaults).
            server_key = (settings.get("wireguard_private_key") or "").strip()
            if not server_key:
                server_key = _env_secret(ENV_WG_PRIVATE_KEY)
            if not server_key:
                errors.append(
                    "wireguard server key missing (setting "
                    "wireguard_private_key / SPARKY_WG_PRIVATE_KEY); "
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
                # Server address + MTU come from the inbound's stream
                # (editable since the Phase 1 inbound editor); a
                # hand-corrupted stream falls back to the old
                # defaults instead of breaking the re-render.
                wg_stream = _inbound_dict(wg_inbound).get("stream_json") or {}
                try:
                    wg_address = _subnet_server_address(
                        str(wg_stream.get("subnet") or "10.8.0.0/24")
                    )
                except ValueError:
                    wg_address = "10.8.0.1/24"
                content = wireguard_mod.render_wg_config(
                    server_key,
                    peers,
                    address=wg_address,
                    listen_port=int(wg_inbound.port),
                    # No DNS in the SERVER config: the line only changes
                    # the server's own resolver, it is never pushed to
                    # clients, and it makes `wg-quick up` fail hard on
                    # any system without a resolvconf provider (see
                    # app.wgapply). Client configs still carry DNS.
                    dns="",
                    mtu=_stream_mtu(wg_stream),
                )
                # Validate + live-reload (syncconf) or start; the
                # helper owns the atomic file replace and restores the
                # previous file on failure (see app.wgapply).
                err = _apply_wireguard_config(
                    content, config_path=str(WG_CONFIG_PATH)
                )
                if err:
                    errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"wireguard render/restart failed: {exc}")
            logger.exception("wireguard re-render failed")
    elif wg_inbounds:
        errors.append("app.wireguard is not available; wg0.conf was not updated")

    if ovpn_inbounds and openvpn_mod is not None:
        try:
            ovpn_inbound = ovpn_inbounds[0]
            stream = _inbound_dict(ovpn_inbound).get("stream_json") or {}
            subnet = str(stream.get("subnet") or openvpn_mod.DEFAULT_NETWORK)
            proto = _stream_transport(stream, "openvpn")
            content = openvpn_mod.render_server_config(
                port=int(ovpn_inbound.port),
                proto=proto,
                network=subnet,
                ca_cert=str(CA_CERT_PATH),
                server_cert=str(VPN_SERVER_CERT_PATH),
                server_key=str(VPN_SERVER_KEY_PATH),
                auth_script=str(OVPN_AUTH_SCRIPT_PATH),
                dns=_stream_dns(stream, ("1.1.1.1", "1.0.0.1")),
            )
            problems = openvpn_mod.validate_server_config(
                content,
                ca_cert=str(CA_CERT_PATH),
                server_cert=str(VPN_SERVER_CERT_PATH),
                server_key=str(VPN_SERVER_KEY_PATH),
                auth_script=str(OVPN_AUTH_SCRIPT_PATH),
            )
            if problems:
                errors.append("openvpn config invalid: " + "; ".join(problems))
            else:
                Path(OVPN_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
                tmp = Path(str(OVPN_CONFIG_PATH) + ".tmp")
                tmp.write_text(content, encoding="utf-8")
                tmp.replace(OVPN_CONFIG_PATH)
                err = _restart_service("openvpn-server@sparky-manager")
                if err:
                    errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"openvpn render/restart failed: {exc}")
            logger.exception("openvpn re-render failed")
    elif ovpn_inbounds:
        errors.append("app.openvpn is not available; openvpn config was not updated")

    if ocserv_inbounds and openconnect_mod is not None:
        try:
            ocserv_inbound = ocserv_inbounds[0]
            stream = _inbound_dict(ocserv_inbound).get("stream_json") or {}
            subnet = str(stream.get("subnet") or openconnect_mod.DEFAULT_NETWORK)
            try:
                max_clients = int(stream.get("max_clients") or 1024)
            except (TypeError, ValueError):
                max_clients = 1024
            if not 1 <= max_clients <= 100000:
                max_clients = 1024
            content = openconnect_mod.render_ocserv_config(
                port=int(ocserv_inbound.port),
                network=subnet,
                server_cert=str(VPN_SERVER_CERT_PATH),
                server_key=str(VPN_SERVER_KEY_PATH),
                passwd_file=str(OCSERV_PASSWD_PATH),
                dns=_stream_dns(stream, ("1.1.1.1", "1.0.0.1")),
                max_clients=max_clients,
            )
            # ocpasswd first (ocserv reads it at auth time, and the
            # config validator checks the file exists), then the
            # config — validated with `ocserv -t` before the live
            # file is replaced.
            users = [
                (c.get("user_name") or "", c.get("password") or "")
                for c in clients_by_tag.get(ocserv_inbound.tag, [])
            ]
            users = [(u, p) for u, p in users if u and p]
            passwd_text = openconnect_mod.render_ocpasswd(users)
            Path(OCSERV_PASSWD_PATH).parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(str(OCSERV_PASSWD_PATH) + ".tmp")
            tmp.write_text(passwd_text, encoding="utf-8")
            os.chmod(tmp, 0o660)
            tmp.replace(OCSERV_PASSWD_PATH)
            problems = openconnect_mod.validate_ocserv_config(
                content,
                passwd_file=str(OCSERV_PASSWD_PATH),
                server_cert=str(VPN_SERVER_CERT_PATH),
                server_key=str(VPN_SERVER_KEY_PATH),
            )
            if problems:
                errors.append("ocserv config invalid: " + "; ".join(problems))
            else:
                Path(OCSERV_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
                tmp = Path(str(OCSERV_CONFIG_PATH) + ".tmp")
                tmp.write_text(content, encoding="utf-8")
                rc, out, err_out = _run_privileged(
                    "ocserv", "-t", "-c", str(tmp), timeout=30
                )
                if rc != 0:
                    detail = _redact((err_out or out or "").strip()) or f"exit {rc}"
                    errors.append(f"ocserv config check failed: {detail}")
                    tmp.unlink(missing_ok=True)
                else:
                    tmp.replace(OCSERV_CONFIG_PATH)
                    err = _restart_service("ocserv")
                    if err:
                        errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ocserv render/restart failed: {exc}")
            logger.exception("ocserv re-render failed")
    elif ocserv_inbounds:
        errors.append("app.openconnect is not available; ocserv config was not updated")

    if awg_inbounds and amneziawg_mod is not None:
        try:
            awg_inbound = awg_inbounds[0]
            stream = _inbound_dict(awg_inbound).get("stream_json") or {}
            params = stream.get("awg_params") or {}
            if not isinstance(params, dict):
                params = {}
            problems = amneziawg_mod.validate_awg_params(params)
            server_key = (settings.get("amneziawg_private_key") or "").strip()
            if not server_key:
                server_key = _env_secret(ENV_AWG_PRIVATE_KEY)
            if not server_key:
                errors.append(
                    "amneziawg server key missing (setting "
                    "amneziawg_private_key / SPARKY_AWG_PRIVATE_KEY); "
                    "awg0.conf was not updated"
                )
            elif problems:
                errors.append("amneziawg params invalid: " + "; ".join(problems))
            else:
                peers: list[dict[str, Any]] = []
                for client in clients_by_tag.get(awg_inbound.tag, []):
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
                # Server address + MTU come from the inbound's
                # stream (editable since the Phase 1 inbound
                # editor); a hand-corrupted stream falls back to
                # the old defaults instead of breaking the
                # re-render.
                try:
                    awg_address = _subnet_server_address(
                        str(stream.get("subnet") or "10.8.1.0/24")
                    )
                except ValueError:
                    awg_address = "10.8.1.1/24"
                content = amneziawg_mod.render_server_config(
                    server_key,
                    peers,
                    address=awg_address,
                    listen_port=int(awg_inbound.port),
                    params=params,
                    mtu=_stream_mtu(stream),
                )
                if not amneziawg_mod.is_available():
                    # Write the config so it is ready when the tools
                    # appear, but say plainly the protocol cannot run
                    # yet — never pretend it works.
                    Path(AWG_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
                    tmp = Path(str(AWG_CONFIG_PATH) + ".tmp")
                    tmp.write_text(content, encoding="utf-8")
                    tmp.replace(AWG_CONFIG_PATH)
                    errors.append(
                        "amneziawg is not installed on this server "
                        "(awg-quick not found); awg0.conf was written "
                        "but the interface cannot start — install "
                        "AmneziaWG (see docs/PORTS.md) or disable this "
                        "inbound"
                    )
                else:
                    err = _apply_wireguard_config(
                        content,
                        config_path=str(AWG_CONFIG_PATH),
                        interface=amneziawg_mod.INTERFACE,
                        wg_bin="awg",
                        wg_quick_bin="awg-quick",
                        unit="awg-quick@awg0",
                        extra_interface_keys=tuple(
                            amneziawg_mod.AWG_INTERFACE_KEYS
                        ),
                    )
                    if err:
                        errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"amneziawg render/restart failed: {exc}")
            logger.exception("amneziawg re-render failed")
    elif awg_inbounds:
        errors.append("app.amneziawg is not available; awg0.conf was not updated")

    if ikev2_inbounds and ikev2_mod is not None:
        try:
            ikev2_inbound = ikev2_inbounds[0]
            stream = _inbound_dict(ikev2_inbound).get("stream_json") or {}
            subnet = str(stream.get("subnet") or ikev2_mod.DEFAULT_NETWORK)
            server_id = _ikev2_server_id(settings)
            if not server_id:
                errors.append(
                    "ikev2 server identity is unknown (no server "
                    "certificate and no domain/subscription host); "
                    "swanctl.conf was not updated"
                )
            else:
                users = [
                    (
                        int(c.get("user_id") or 0),
                        c.get("user_name") or "",
                        c.get("password") or "",
                    )
                    for c in clients_by_tag.get(ikev2_inbound.tag, [])
                ]
                users = [(uid, name, pw) for uid, name, pw in users if name and pw]
                content = ikev2_mod.render_swanctl_config(
                    users=users,
                    server_id=server_id,
                    network=subnet,
                    dns=_stream_dns(stream, ("1.1.1.1", "1.0.0.1")),
                )
                problems = ikev2_mod.validate_swanctl_config(content)
                if problems:
                    errors.append("ikev2 config invalid: " + "; ".join(problems))
                else:
                    Path(SWANCTL_CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
                    tmp = Path(str(SWANCTL_CONFIG_PATH) + ".tmp")
                    tmp.write_text(content, encoding="utf-8")
                    tmp.replace(SWANCTL_CONFIG_PATH)
                    err = _apply_ikev2_config()
                    if err:
                        errors.append(err)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ikev2 render/apply failed: {exc}")
            logger.exception("ikev2 re-render failed")
    elif ikev2_inbounds:
        errors.append("app.ikev2 is not available; swanctl.conf was not updated")

    if errors:
        logger.error(
            "config re-render finished with %d error(s): %s",
            len(errors),
            _redact("; ".join(errors)),
        )
    else:
        logger.info("config re-render ok")
    return errors


# ---------------------------------------------------------------------------
# Startup: tables, default admin, key settings
# ---------------------------------------------------------------------------


def _env_secret(key: str) -> str:
    """Read a ``SPARKY_*`` secret env var, falling back to the
    pre-rename ``VPN_PANEL_*`` spelling (same compat rule as
    ``app.config._env``)."""
    value = os.environ.get(key, "").strip()
    if value:
        return value
    if key.startswith("SPARKY_"):
        return os.environ.get("VPN_PANEL_" + key[len("SPARKY_"):], "").strip()
    return ""


def _env_or_generate(key: str, generator) -> tuple[str, bool]:
    """Value of env var ``key`` when set and non-blank, else a fresh
    generated value. Returns ``(value, came_from_env)``."""
    value = _env_secret(key)
    if value:
        return value, True
    return generator(), False


def ensure_defaults(db: Session) -> Optional[str]:
    """Seed the DB on first run: admin and key settings.

    No inbounds are created: a fresh install starts empty and the
    admin adds inbounds from the panel (each VLESS inbound gets its
    own fresh Reality keypair at creation time).

    Bootstrap rule (installer contract): secrets prefer the
    environment variables the installer wrote to
    ``/opt/sparky-manager/data/panel.env`` (loaded via the systemd unit's
    ``EnvironmentFile``) — ``SPARKY_ADMIN_PASSWORD``,
    ``SPARKY_REALITY_PRIVATE_KEY`` / ``_PUBLIC_KEY`` / ``_SHORT_ID``,
    ``SPARKY_WG_PRIVATE_KEY`` / ``_PUBLIC_KEY``. Fresh values are
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
            print("  sparky-manager — first run: admin account created", flush=True)
            print(f"  Panel:    http://<server-ip>:{PANEL_PORT}  (or https if TLS is set up)", flush=True)
            print("  Username: admin", flush=True)
            print(f"  Password: {generated_password}", flush=True)
            print("  Save this password — it is printed ONLY this once.", flush=True)
            print("=" * 60, flush=True)
        else:
            logger.info("admin account created from SPARKY_ADMIN_PASSWORD")

    # Reality keypair / short-id: env first, generate only if absent.
    # Stored in settings (the Xray renderer reads reality_private_key
    # from settings as a fallback); inbounds created from the panel
    # carry their own keypair in stream_json, which is where the links
    # read the public key / short-id from.
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
        env_private = _env_secret(ENV_REALITY_PRIVATE_KEY)
        env_public = _env_secret(ENV_REALITY_PUBLIC_KEY)
        env_short = _env_secret(ENV_REALITY_SHORT_ID)
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
        env_wg_private = _env_secret(ENV_WG_PRIVATE_KEY)
        env_wg_public = _env_secret(ENV_WG_PUBLIC_KEY)
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

    # AmneziaWG server keypair: env first, generate only if absent.
    # A separate keypair from WireGuard's — wg0 and awg0 are different
    # interfaces and must never share a server key.
    awg_now = {row.key: (row.value or "") for row in db.query(Setting).all()}
    if not awg_now.get("amneziawg_private_key"):
        env_awg_private = _env_secret(ENV_AWG_PRIVATE_KEY)
        env_awg_public = _env_secret(ENV_AWG_PUBLIC_KEY)
        if env_awg_private:
            db.add(Setting(key="amneziawg_private_key", value=env_awg_private))
            if env_awg_public:
                db.add(Setting(key="amneziawg_public_key", value=env_awg_public))
        elif wireguard_mod is not None and hasattr(wireguard_mod, "generate_keypair"):
            try:
                pair = wireguard_mod.generate_keypair()
                private, public = (pair[0], pair[1]) if isinstance(pair, (list, tuple)) else (str(pair), "")
                db.add(Setting(key="amneziawg_private_key", value=private))
                if public:
                    db.add(Setting(key="amneziawg_public_key", value=public))
            except Exception:  # noqa: BLE001
                logger.exception("amneziawg keypair generation failed")
        db.commit()

    # Schema version (Phase 3): a setting row, not a schema change —
    # backups carry it so restore can refuse a backup from a newer
    # panel. Missing means v1 (the first versioned release).
    version_now = {row.key: (row.value or "") for row in db.query(Setting).all()}
    if not version_now.get("schema_version"):
        version = (
            getattr(backup_mod, "SCHEMA_VERSION", 1)
            if backup_mod is not None
            else 1
        )
        db.add(Setting(key="schema_version", value=str(version)))
        db.commit()

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
                    _privileged_cmd("wg", "show", "wg0", "transfer"),
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
                _notify_rerender_failure(db, errors)
            _notify_expiring_users(db)
        except Exception:  # noqa: BLE001
            logger.exception("expiry sweeper failed")
        finally:
            db.close()


def _telegram_polling_token() -> Optional[str]:
    """The bot token when polling is the active transport, else None.

    Polling is active only when the ``telegram_transport`` setting is
    ``"polling"`` AND a bot token + admin chat ID are configured —
    the same gating the webhook route uses, plus the transport check.
    The setting is re-read every round (see ``_telegram_polling_loop``)
    so switching transports in the settings page takes effect without
    a panel restart. Returns None (never raises) when the DB or the
    telegram/bot modules are unavailable. The token is returned to
    the caller, never logged.
    """
    if telegram_mod is None or bot_mod is None or SessionLocal is None:
        return None
    db = SessionLocal()
    try:
        settings = get_settings(db)
    except Exception:  # noqa: BLE001 — a DB error idles the loop
        return None
    finally:
        db.close()
    transport = (settings.get("telegram_transport") or "").strip().lower()
    if transport not in TELEGRAM_TRANSPORTS:
        # Unset or invalid: the default applies (polling since the
        # professional upgrade, Phase 3).
        transport = TELEGRAM_TRANSPORT_DEFAULT
    if transport != "polling":
        return None
    token = (settings.get("telegram_bot_token") or "").strip()
    chat_id = (settings.get("telegram_chat_id") or "").strip()
    if not token or not chat_id:
        return None
    return token


def _load_polling_offset() -> Optional[int]:
    """The persisted ``getUpdates`` offset (settings table), or None
    when unset or unparseable — a bad stored value re-fetches from
    scratch, and ``bot.py``'s dedup keeps that harmless. Never
    raises."""
    if SessionLocal is None:
        return None
    db = SessionLocal()
    try:
        raw = get_setting(db, TELEGRAM_POLLING_OFFSET_KEY, "")
        return int(raw) if raw.strip() else None
    except (ValueError, Exception):  # noqa: BLE001 — bad value: start over
        return None
    finally:
        db.close()


def _record_polling_status(
    *, got_update: bool = False, error: Optional[str] = None
) -> None:
    """Persist one polling round's diagnostics (settings table).

    A successful round stamps ``telegram_polling_last_poll`` (and
    ``telegram_polling_last_update`` when at least one update
    arrived); a failed round stamps ``telegram_polling_last_error``
    with the time and a short reason. Never raises.
    """
    if SessionLocal is None:
        return
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc).isoformat()
        if error is not None:
            set_setting(
                db, TELEGRAM_POLLING_LAST_ERROR_KEY, f"{now} — {error}"
            )
        else:
            set_setting(db, TELEGRAM_POLLING_LAST_POLL_KEY, now)
            if got_update:
                set_setting(db, TELEGRAM_POLLING_LAST_UPDATE_KEY, now)
    except Exception:  # noqa: BLE001 — diagnostics must never break the loop
        logger.exception("telegram polling status persist failed")
    finally:
        db.close()


# Single-worker guard for the polling loop: the lifespan creates
# exactly one polling task, and this flag makes a second worker
# impossible even if the loop is ever (re)started by another path —
# two workers would race on the offset and double-deliver updates.
_polling_loop_active = False


async def _telegram_polling_loop() -> None:
    """Polling-loop entry point: refuse a second worker, then run the
    loop. The flag is cleared on exit (including cancellation at
    shutdown) so a later restart of the task is allowed."""
    global _polling_loop_active
    if _polling_loop_active:
        logger.warning(
            "telegram polling loop already running; refusing a second worker"
        )
        return
    _polling_loop_active = True
    try:
        await _telegram_polling_loop_inner()
    finally:
        _polling_loop_active = False


async def _telegram_polling_loop_inner() -> None:
    """Long-poll Telegram for bot updates (polling transport).

    The task itself is always started by the lifespan (like the
    sweeper/traffic loops), but it only ever calls ``getUpdates``
    while ``_telegram_polling_token()`` returns a token — i.e. while
    the transport is ``"polling"`` and the bot is configured. With
    the webhook transport (or an unconfigured bot) the loop is just
    a 10 s sleeper that makes zero network calls, and switching
    transports in the settings page takes effect live, with no
    restart. (Starting the task only at boot when polling was
    selected would have made every transport switch require a manual
    panel restart — the self-gating loop is the behavior the
    settings page promises.)

    Each update is dispatched through the SAME ``bot.handle_update``
    + ``TelegramSender`` the webhook route uses, with its own DB
    session per update (mirroring one webhook request per update),
    so polling and webhook behave identically. The offset is
    persisted in the settings table after every dispatched update
    (professional upgrade, Phase 3), so a restart resumes where the
    loop left off instead of re-fetching; duplicates are still
    ignored by ``bot.py``'s ``_seen_updates`` for the in-flight
    batch. Each round also records its diagnostics (last poll, last
    update, last error) for the settings page.

    The loop never crashes the panel: every failure path is caught
    and logged (never the token), a fast empty ``getUpdates`` return
    (the helper returns [] on failure) backs off exponentially, and
    ``get_updates`` runs in a thread (``asyncio.to_thread``) because
    it is a blocking 30 s long-poll — awaiting it directly would
    freeze the panel's event loop for the whole wait. Cancellation
    (lifespan shutdown) is honoured: ``CancelledError`` is never
    swallowed.
    """
    offset = _load_polling_offset()
    backoff = 0.0
    while True:
        try:
            token = _telegram_polling_token()
        except Exception:  # noqa: BLE001 — the loop must never die
            logger.exception("telegram polling config read failed")
            token = None
        if token is None:
            await asyncio.sleep(TELEGRAM_POLL_IDLE_SECONDS)
            backoff = 0.0
            continue
        started = time.monotonic()
        try:
            updates = await asyncio.to_thread(
                telegram_mod.get_updates, token, offset, TELEGRAM_POLL_TIMEOUT
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — get_updates never raises; belt & braces
            logger.exception("telegram polling getUpdates failed")
            updates = []
        if not isinstance(updates, list):
            updates = []
        if updates:
            backoff = 0.0
            for update in updates:
                if isinstance(update, dict):
                    update_id = update.get("update_id")
                    if isinstance(update_id, int):
                        offset = (
                            update_id + 1
                            if offset is None
                            else max(offset, update_id + 1)
                        )
                if bot_mod is None or SessionLocal is None:
                    continue
                db = SessionLocal()
                try:
                    bot_mod.handle_update(
                        db, update, bot_mod.TelegramSender(token)
                    )
                except Exception:  # noqa: BLE001 — one bad update must not stop the loop
                    logger.exception("telegram polling dispatch failed")
                finally:
                    # Persist the offset even when dispatch failed:
                    # Telegram considers the update delivered, and
                    # re-fetching it after a restart would re-run
                    # the (failed) action. The offset write is in
                    # the dispatch session so it costs no extra one.
                    try:
                        if offset is not None:
                            set_setting(
                                db, TELEGRAM_POLLING_OFFSET_KEY, str(offset)
                            )
                    except Exception:  # noqa: BLE001 — a missed write only re-fetches
                        logger.exception("telegram polling offset persist failed")
                    db.close()
            _record_polling_status(got_update=True)
        else:
            # No updates: a slow empty return is a normal long-poll
            # timeout (re-poll immediately); a fast one means the call
            # failed (get_updates returns [] on failure) — back off
            # exponentially so a dead Telegram cannot spin the loop.
            if time.monotonic() - started < TELEGRAM_POLL_SHORT_CALL_SECONDS:
                backoff = (
                    TELEGRAM_POLL_BACKOFF_BASE
                    if backoff == 0.0
                    else min(backoff * 2, TELEGRAM_POLL_BACKOFF_MAX)
                )
                _record_polling_status(error="getUpdates failed")
                await asyncio.sleep(backoff)
            else:
                backoff = 0.0
                _record_polling_status()


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
            if panel_log_mod is not None:
                # Log level from the DB setting (Settings page); INFO
                # when unset. Applied here so a restart honours it.
                try:
                    level = get_settings(db).get("log_level", "")
                    if level:
                        panel_log_mod.apply_log_level(level)
                except Exception:  # noqa: BLE001
                    logger.exception("applying log level failed")
            logger.info("sparky-manager started")
        except Exception:  # noqa: BLE001
            logger.exception("seeding defaults failed")
        finally:
            db.close()
    tasks = [
        asyncio.create_task(_traffic_sync_loop()),
        asyncio.create_task(_expiry_sweeper_loop()),
        # The polling task is always created but only polls while the
        # transport is "polling" (see _telegram_polling_loop); it is
        # cancelled with the other loops on shutdown.
        asyncio.create_task(_telegram_polling_loop()),
    ]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="sparky-manager", lifespan=lifespan)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Security headers (Phase 2, S3). The panel serves no external
# resources (bundled font, local JS/CSS, same-origin QR images), so
# a strict CSP is safe — except inline styles: the dashboard chart
# and a few stat cards render widths/colors inline, so style-src
# keeps 'unsafe-inline' (no inline *scripts* exist anywhere, and
# script-src stays strict). Nothing embeds the panel, so framing is
# denied outright. HSTS is sent unconditionally: browsers ignore it
# over plain HTTP, and production always serves HTTPS (uvicorn TLS).
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self'; "
        "font-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=31536000",
}


@app.middleware("http")
async def _security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    return response


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


# ---------------------------------------------------------------------------
# CSRF protection (Phase 2, S1)
#
# Every state-changing POST (all HTML forms + the JSON API) requires a
# per-session token: HMAC-SHA256 of the session token
# (app.auth.csrf_token_for_session), rendered as a hidden field in
# every form by _template_ctx and checked here with a constant-time
# compare. The token is accepted from the ``csrf_token`` form field
# or the ``X-CSRF-Token`` header (the JSON API has no form body).
#
# Exclusions (each deliberate, documented here):
# - POST /login: no session exists yet, so there is no token to check
#   against. Login CSRF is a non-issue for this single-admin panel:
#   an attacker would need the admin password to make it meaningful,
#   and that password IS the secret being protected.
# - POST /telegram/webhook/{secret}: an unauthenticated external POST
#   from Telegram's servers. It is authenticated by its random path
#   secret (constant-time compare) instead, and Telegram cannot
#   present a session cookie.
# - All GET routes: read-only by design (logout moved to POST).
# ---------------------------------------------------------------------------

CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"


class CSRFError(Exception):
    """Raised when CSRF validation fails (missing/wrong token)."""


async def _check_csrf_token(request: Request) -> None:
    """Validate the CSRF token for this request's session.

    Fails closed: any missing piece (no session cookie, no submitted
    token, unparseable form, unavailable auth helpers) raises
    CSRFError. The session itself was already validated by the auth
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
        or verify_csrf_token is None
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


@app.exception_handler(CSRFError)
async def _csrf_error_handler(request: Request, exc: CSRFError):
    """403 with a clear error page (JSON for the API)."""
    if request.url.path.startswith(WEB_PATH + "/api/"):
        return JSONResponse(
            status_code=403,
            content={"detail": "CSRF token missing or invalid"},
        )
    admin = None
    if get_session is not None:
        try:
            with get_session() as db:
                admin = _admin_from_request(request, db)
        except Exception:  # noqa: BLE001 — error page without sidebar
            admin = None
    t = t_for(get_lang(request))
    return templates.TemplateResponse(
        request,
        "error.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "error_title": t["csrf_error_title"],
                "error_message": t["csrf_error_message"],
            },
        ),
        status_code=403,
    )


def _template_ctx(request: Request, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    lang = get_lang(request)
    # CSRF token for the session cookie ("" when logged out — the
    # login form carries no token; see the S1 note above require_csrf).
    # Deriving from an arbitrary cookie value is harmless: the POST
    # check requires a *valid* session anyway.
    session_token = request.cookies.get(SESSION_COOKIE)
    csrf_token = (
        csrf_token_for_session(session_token)
        if session_token and csrf_token_for_session is not None
        else ""
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


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        # Secure whenever the request arrived over HTTPS, directly
        # or via a trusted TLS-terminating proxy (S4).
        secure=_is_secure_request(request),
        path=WEB_PATH or "/",
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
    elif protocol == "amneziawg":
        # Same key layout as WireGuard (private in `password`, public
        # in `uuid`); the AWG renderer reads the same fields.
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


def _stream_transport(stream: dict[str, Any], protocol: str) -> str:
    """Transport ('tcp'/'udp') for clash checks: explicit value wins,
    else the protocol default (UDP for hysteria2/tuic/wireguard/
    amneziawg/openvpn)."""
    transport = str(stream.get("transport") or "").lower()
    if transport in ("tcp", "udp"):
        return transport
    return (
        "udp"
        if protocol in ("hysteria2", "tuic", "wireguard", "amneziawg", "openvpn")
        else "tcp"
    )


def _inbound_transports(stream: dict[str, Any], protocol: str) -> set[str]:
    """Every transport an inbound binds.

    OpenConnect binds TCP *and* UDP on the same port, so it occupies
    both — a UDP inbound on that port would fail to bind even though
    the single-transport check would allow it. Every other protocol
    binds one transport.
    """
    if protocol == "openconnect":
        return {"tcp", "udp"}
    return {_stream_transport(stream, protocol)}


# ---------------------------------------------------------------------------
# Inbound-editor value parsing (Phase 1 of the professional-panel
# expansion). The edit form writes everything into the inbound's
# ``stream_json`` — no DB migration — and these helpers turn the raw
# form strings into the validated values the renderers read. Each one
# raises ``ValueError`` with a plain-English message; the edit handler
# maps it to a translated error string and re-renders the form.
# ---------------------------------------------------------------------------

#: Reality private keys are base64url WITHOUT padding of 32 bytes
#: (43 chars) — the format ``xray x25519`` emits.
_REALITY_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
#: A Reality shortId is a hex string of even length, at most 16 chars.
_SHORT_ID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")


def _parse_subnet(value: str) -> str:
    """Validate a client subnet (``10.8.0.0/24``) and normalise it.

    IPv4 only, with room for at least the server address plus one
    peer (prefix length <= 30). Host bits are normalised away, so
    ``10.8.0.5/24`` becomes ``10.8.0.0/24``.
    """
    text = (value or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"invalid subnet: {text!r}") from None
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError(f"subnet must be IPv4: {text!r}")
    if net.prefixlen > 30:
        raise ValueError(f"subnet is too small (need /30 or larger): {text!r}")
    return str(net)


def _subnet_server_address(subnet: str) -> str:
    """The server's own address inside ``subnet`` (first host, /32-less).

    ``10.8.0.0/24`` -> ``10.8.0.1/24``: the ``Address`` line of the
    WireGuard / AmneziaWG server config. The peer pool starts at
    .2 (see :func:`_next_wg_address`).
    """
    net = ipaddress.ip_network(subnet, strict=False)
    return f"{net.network_address + 1}/{net.prefixlen}"


def _parse_dns_list(value: str) -> tuple[str, ...]:
    """Parse a comma-separated DNS list (1–2 IPv4/IPv6 addresses)."""
    parts = [part.strip() for part in (value or "").split(",") if part.strip()]
    if not parts:
        raise ValueError("at least one DNS server is required")
    if len(parts) > 2:
        raise ValueError("at most two DNS servers are allowed")
    for part in parts:
        try:
            ipaddress.ip_address(part)
        except ValueError:
            raise ValueError(f"invalid DNS address: {part!r}") from None
    return tuple(parts)


def _stream_dns(stream: dict[str, Any], default: tuple[str, str]) -> tuple[str, ...]:
    """DNS servers from an inbound stream (``dns`` list or string).

    Falls back to ``default`` when the stream carries nothing (or
    nothing parseable) — a hand-edited stream must never break a
    re-render.
    """
    raw = stream.get("dns")
    if isinstance(raw, (list, tuple)):
        servers = [str(item).strip() for item in raw if str(item).strip()]
    elif isinstance(raw, str):
        servers = [part.strip() for part in raw.split(",") if part.strip()]
    else:
        return default
    valid: list[str] = []
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            continue
        valid.append(server)
    return tuple(valid) if valid else default


def _parse_mtu(value: str) -> int | None:
    """Parse an MTU field (blank = None, the kernel/client default)."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        mtu = int(text)
    except ValueError:
        raise ValueError(f"MTU is not a number: {text!r}") from None
    if not 576 <= mtu <= 9000:
        raise ValueError(f"MTU out of range 576-9000: {mtu}")
    return mtu


def _stream_mtu(stream: dict[str, Any]) -> int | None:
    """MTU from an inbound stream (``None`` when unset/invalid)."""
    raw = stream.get("mtu")
    if raw is None or raw == "":
        return None
    try:
        mtu = int(raw)
    except (TypeError, ValueError):
        return None
    return mtu if 576 <= mtu <= 9000 else None


def _parse_mbps(value: str) -> int | None:
    """Parse an optional speed cap in Mbps (blank = None, no cap)."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        mbps = int(text)
    except ValueError:
        raise ValueError(f"speed cap is not a number: {text!r}") from None
    if mbps <= 0:
        raise ValueError(f"speed cap must be positive: {mbps}")
    return mbps


def _parse_fallbacks(value: str) -> list[dict[str, Any]]:
    """Parse the fallbacks textarea: one ``host:port`` per line, with
    an optional ``,xver`` suffix (``127.0.0.1:8080,1``). A bare port
    number is also accepted (Xray forwards to localhost on it)."""
    fallbacks: list[dict[str, Any]] = []
    for raw_line in (value or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        xver = 0
        if "," in line:
            line, _, xver_text = line.rpartition(",")
            line = line.strip()
            try:
                xver = int(xver_text.strip())
            except ValueError:
                raise ValueError(f"invalid fallback xver: {line!r}") from None
            if xver not in (0, 1):
                raise ValueError(f"fallback xver must be 0 or 1: {line!r}")
        dest: Any = line
        if ":" in line:
            host, _, port_text = line.rpartition(":")
            if not host.strip():
                raise ValueError(f"invalid fallback destination: {line!r}")
            try:
                port = int(port_text)
            except ValueError:
                raise ValueError(f"invalid fallback port: {line!r}") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"fallback port out of range: {line!r}")
            dest = f"{host.strip()}:{port}"
        else:
            try:
                port = int(line)
            except ValueError:
                raise ValueError(f"invalid fallback destination: {line!r}") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"fallback port out of range: {line!r}")
            dest = port
        fallbacks.append({"dest": dest, "xver": xver})
    return fallbacks


def _fallbacks_text(fallbacks: Any) -> str:
    """Render a stored fallbacks list back into textarea lines."""
    if not isinstance(fallbacks, list):
        return ""
    lines: list[str] = []
    for entry in fallbacks:
        if not isinstance(entry, dict) or entry.get("dest") in (None, ""):
            continue
        line = str(entry["dest"])
        if entry.get("xver"):
            line += f",{int(entry['xver'])}"
        lines.append(line)
    return "\n".join(lines)


def _parse_short_id(value: str) -> str:
    """Validate a Reality shortId (hex, even length, <= 16 chars)."""
    text = (value or "").strip().lower()
    if not _SHORT_ID_RE.match(text):
        raise ValueError(f"invalid shortId: {value!r}")
    return text


def _parse_reality_private_key(value: str) -> str:
    """Validate a Reality private key (43-char base64url)."""
    text = (value or "").strip()
    if not _REALITY_KEY_RE.match(text):
        raise ValueError("invalid Reality private key")
    return text


# ---------------------------------------------------------------------------
# Inbound auto-generation (like 3X-UI: the add-inbound form comes
# pre-filled and the admin can accept the values as-is — no port typing
# required). The port is a random FREE one (10000-60000, not used by
# any inbound on the same transport, not reserved, not the panel port,
# and it must bind on the server); the tag is derived from protocol +
# port and made unique; a VLESS+Reality inbound gets a fresh keypair +
# short-id instead of sharing the installer's pair.
# ---------------------------------------------------------------------------

RESERVED_PORTS = frozenset({500, 4500})  # IKEv2 (kept free by design)
SUGGESTED_PORT_MIN = 10000
SUGGESTED_PORT_MAX = 60000


def _used_ports_by_transport(db: Session) -> dict[str, set[int]]:
    """Ports in use per transport, from the DB inbounds."""
    used: dict[str, set[int]] = {"tcp": set(), "udp": set()}
    for inbound in db.query(Inbound).all():
        for transport in _inbound_transports(inbound.stream, inbound.protocol):
            used.setdefault(transport, set()).add(int(inbound.port))
    return used


def _port_is_bindable(port: int) -> bool:
    """True when nothing on this machine is listening on ``port``.

    A quick bind probe (bind + close): a failed bind means another
    process holds the port. Best-effort only — a port can be taken
    between the probe and the real bind, so the create handler still
    validates the clash against the DB.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def suggest_free_port(db: Session, transport: str = "tcp") -> int:
    """Random free port for a new inbound (10000-60000).

    Excludes the reserved ports (500/4500), the panel's own port, and
    every port an existing inbound already uses on the same transport
    (TCP and UDP inbounds may share a port — VLESS-Reality TCP 443 +
    Hysteria2 UDP 443 — so only same-transport ports are excluded).
    Candidates are also bind-probed so a port held by another process
    is skipped. After 50 tries, any unused port in range is returned
    without the bind probe.
    """
    used = _used_ports_by_transport(db).get(transport, set())
    blocked = set(used) | set(RESERVED_PORTS) | {int(PANEL_PORT)}
    for _ in range(50):
        port = random.randint(SUGGESTED_PORT_MIN, SUGGESTED_PORT_MAX)
        if port in blocked:
            continue
        if _port_is_bindable(port):
            return port
    for _ in range(200):
        port = random.randint(SUGGESTED_PORT_MIN, SUGGESTED_PORT_MAX)
        if port not in blocked:
            return port
    raise ValueError("no free port found in 10000-60000")


# Conventional default port per protocol (tried first when the admin
# leaves the port empty; falls back to a random free port when taken).
PREFERRED_PORTS = {
    "openvpn": 1194,
    "openconnect": 4433,
    "amneziawg": 51821,
    "ikev2": 500,
}


def suggest_protocol_port(db: Session, protocol: str, transport: str) -> int:
    """Preferred port for a protocol, else a random free one.

    OpenVPN's well-known port is 1194, OpenConnect's is 443 (taken by
    the default VLESS/Hysteria2 inbounds, so 4433), AmneziaWG's is
    51821 (next to WireGuard's 51820), IKEv2's is 500 (UDP 500 +
    4500 are reserved for it by design).
    """
    preferred = PREFERRED_PORTS.get(protocol)
    if preferred is not None:
        used = _used_ports_by_transport(db).get(transport, set())
        blocked = set(used) | {int(PANEL_PORT)}
        if protocol == "ikev2":
            # Port 500 needs root to bind-probe and the panel runs
            # unprivileged, so only the DB usage is checked here.
            if preferred not in blocked:
                return preferred
        elif preferred not in blocked and _port_is_bindable(preferred):
            return preferred
    return suggest_free_port(db, transport)


def suggest_inbound_tag(db: Session, protocol: str, port: int) -> str:
    """Unique tag for a new inbound: ``<protocol>-<port>``, with a
    ``-2`` / ``-3`` … suffix while the tag is taken (same idea as
    3X-UI's auto-composed inbound tags)."""
    base = f"{protocol}-{port}"
    taken = {row[0] for row in db.query(Inbound.tag).all()}
    if base not in taken:
        return base
    for n in range(2, 100):
        candidate = f"{base}-{n}"
        if candidate not in taken:
            return candidate
    return f"{base}-{secrets.token_hex(3)}"


def _new_reality_keypair() -> dict[str, str]:
    """Fresh Reality keypair for one inbound (``xray x25519`` format).

    Prefers ``app.xray.generate_reality_keypair``; falls back to the
    WireGuard keypair generator re-encoded as base64url (same keys,
    different alphabet). Returns ``{}`` when nothing works — the
    caller then leaves the inbound on the installer's shared pair
    (the renderer falls back to the settings keys).
    """
    try:
        if xray_mod is not None and hasattr(xray_mod, "generate_reality_keypair"):
            pair = xray_mod.generate_reality_keypair()
            if isinstance(pair, dict) and pair.get("private_key") and pair.get("public_key"):
                return {"private_key": str(pair["private_key"]), "public_key": str(pair["public_key"])}
    except Exception:  # noqa: BLE001
        logger.exception("reality keypair generation failed")
    try:
        if wireguard_mod is not None and hasattr(wireguard_mod, "generate_keypair"):
            private_b64, public_b64 = wireguard_mod.generate_keypair()
            encode = lambda k: base64.urlsafe_b64encode(base64.b64decode(k)).rstrip(b"=").decode("ascii")  # noqa: E731
            return {"private_key": encode(private_b64), "public_key": encode(public_b64)}
    except Exception:  # noqa: BLE001
        logger.exception("reality keypair fallback failed")
    return {}


# ---------------------------------------------------------------------------
# Inbound editor (Phase 1 of the professional-panel expansion)
# ---------------------------------------------------------------------------

#: Default client subnet per single-instance protocol, used when an
#: older inbound has no ``subnet`` in its stream yet.
_EDIT_SUBNET_DEFAULTS = {
    "wireguard": "10.8.0.0/24",
    "amneziawg": "10.8.1.0/24",
    "openvpn": "10.9.0.0/24",
    "openconnect": "10.10.10.0/24",
    "ikev2": "10.20.0.0/24",
}

#: Protocols whose edit form shows the Xray transport/security block.
_XRAY_STREAM_PROTOCOLS = {"vless", "vmess", "trojan"}

#: Protocols whose edit form shows the TLS block (SNI / ALPN /
#: custom cert paths). Sing-box protocols are always TLS, so they
#: show the block without the security select.
_TLS_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "hysteria2",
    "tuic",
    "anytls",
    "naive",
    "shadowtls",
}

#: Allowed values for the validated select fields (anything else is
#: rejected — a hand-crafted POST must not smuggle an unknown value
#: into a renderer).
_XHTTP_MODES = {"auto", "packet", "stream"}
_FINGERPRINTS = {"chrome", "firefox", "safari", "edge", "random"}
_CONGESTION_CONTROLS = {"bbr", "cubic", "new_reno"}
_SHADOWTLS_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}


def _edit_form_values(inbound: Any) -> dict[str, Any]:
    """Every field of the edit form, pre-filled from the inbound.

    The template reads ONLY this dict (plus ``inbound`` itself), so
    the GET handler and the POST-error re-render share one source of
    truth: the POST handler merges the submitted values over it.
    """
    stream = inbound.stream if isinstance(inbound.stream, dict) else {}
    reality = stream.get("reality") if isinstance(stream.get("reality"), dict) else {}
    tls = stream.get("tls") if isinstance(stream.get("tls"), dict) else {}
    awg = stream.get("awg_params") if isinstance(stream.get("awg_params"), dict) else {}
    protocol = inbound.protocol
    security = str(stream.get("security") or "")
    if not security:
        # The renderer defaults trojan to TLS; everything else to
        # plain — show the effective value, not a blank select.
        security = "tls" if protocol == "trojan" else "none"
    dns = _stream_dns(stream, ("1.1.1.1", "1.0.0.1"))
    values: dict[str, Any] = {
        # Common
        "tag": inbound.tag,
        "port": inbound.port,
        "remark": inbound.remark or "",
        "enabled": bool(inbound.enabled),
        # Xray transport / security
        "network": str(stream.get("network") or "tcp"),
        "security": security,
        "path": str(stream.get("path") or ""),
        "host": str(stream.get("host") or ""),
        "service_name": str(stream.get("service_name") or ""),
        "mode": str(stream.get("mode") or "auto"),
        "fp": str(stream.get("fp") or "chrome"),
        "sniffing": bool(stream.get("sniffing")),
        "fallbacks": _fallbacks_text(stream.get("fallbacks")),
        # Reality
        "reality_dest": str(reality.get("dest") or ""),
        "reality_sni": str(reality.get("sni") or ""),
        "reality_server_names": ", ".join(
            str(name) for name in (reality.get("server_names") or [])
        ),
        "reality_short_id": str(reality.get("short_id") or ""),
        "reality_private_key": str(reality.get("private_key") or ""),
        "reality_public_key": str(reality.get("public_key") or ""),
        # TLS
        "tls_sni": str(tls.get("sni") or ""),
        "tls_alpn": ", ".join(str(item) for item in (tls.get("alpn") or [])),
        "tls_cert_path": str(tls.get("cert_path") or ""),
        "tls_key_path": str(tls.get("key_path") or ""),
        # Speed caps (hysteria2)
        "up_mbps": stream.get("up_mbps") if stream.get("up_mbps") else "",
        "down_mbps": stream.get("down_mbps") if stream.get("down_mbps") else "",
        # Sing-box
        "congestion_control": str(stream.get("congestion_control") or "bbr"),
        "zero_rtt": bool(stream.get("zero_rtt_handshake")),
        "strict_mode": bool(stream.get("strict_mode")),
        "shadowtls_password": str(stream.get("password") or ""),
        "method": str(stream.get("method") or "2022-blake3-aes-128-gcm"),
        "inner_port": stream.get("inner_port") if stream.get("inner_port") else "",
        # WG / AWG / OVPN / ocserv / IKEv2
        "subnet": str(
            stream.get("subnet") or _EDIT_SUBNET_DEFAULTS.get(protocol, "")
        ),
        "mtu": stream.get("mtu") if stream.get("mtu") else "",
        "dns": ", ".join(dns),
        "proto": str(stream.get("transport") or "udp"),
        "max_clients": stream.get("max_clients") if stream.get("max_clients") else 1024,
    }
    # AmneziaWG obfuscation parameters (one form field each).
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"):
        values[f"awg_{key.lower()}"] = awg.get(key, "")
    values["awg_header_key"] = awg.get("HeaderProtectionKey", "")
    return values


def _build_stream_from_form(
    inbound: Any, data: dict[str, str], t: dict[str, str]
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate the edit form and build the inbound's new stream.

    ``data`` is the submitted form (checkboxes present only when
    checked). Returns ``(new_stream, None)`` on success or
    ``(None, translated_error)`` on the first invalid field. The
    caller applies the result — this function touches nothing.
    """
    stream = dict(inbound.stream) if isinstance(inbound.stream, dict) else {}
    protocol = inbound.protocol

    def _field(name: str) -> str:
        return (data.get(name) or "").strip()

    def _checked(name: str) -> bool:
        return data.get(name) in ("on", "true", "1")

    # -- Xray transport / security (vless / vmess / trojan) --------
    if protocol in _XRAY_STREAM_PROTOCOLS:
        network = _field("network") or "tcp"
        if network not in ("tcp", "ws", "grpc", "xhttp", "httpupgrade"):
            return None, t["invalid_transport"]
        security = _field("security") or "none"
        if security not in ("none", "tls", "reality"):
            return None, t["invalid_transport"]
        if security == "reality" and network != "tcp":
            # Reality is a TCP-only security in Xray; a WS/gRPC
            # Reality inbound would fail `xray -test` at re-render.
            return None, t["reality_needs_tcp"]
        stream["network"] = network
        stream["security"] = security
        stream["transport"] = "tcp"
        stream["path"] = _field("path")
        stream["host"] = _field("host")
        stream["service_name"] = _field("service_name")
        mode = _field("mode") or "auto"
        if mode not in _XHTTP_MODES:
            return None, t["invalid_mode"]
        stream["mode"] = mode
        fp = _field("fp") or "chrome"
        if fp not in _FINGERPRINTS:
            return None, t["invalid_fingerprint"]
        stream["fp"] = fp
        stream["sniffing"] = _checked("sniffing")
        try:
            stream["fallbacks"] = _parse_fallbacks(data.get("fallbacks") or "")
        except ValueError:
            return None, t["invalid_fallbacks"]

        if security == "reality":
            try:
                short_id = _parse_short_id(data.get("reality_short_id") or "")
            except ValueError:
                return None, t["invalid_short_id"]
            private_key = _field("reality_private_key")
            reality = dict(stream.get("reality") or {})
            if private_key:
                try:
                    private_key = _parse_reality_private_key(private_key)
                except ValueError:
                    return None, t["invalid_reality_key"]
                reality["private_key"] = private_key
                # The public key MUST match the private key, or
                # clients cannot connect — derive it, never trust
                # a pasted public key.
                if xray_mod is not None and hasattr(
                    xray_mod, "reality_public_key"
                ):
                    public_key = xray_mod.reality_public_key(private_key)
                    if public_key:
                        reality["public_key"] = public_key
            reality["dest"] = _field("reality_dest")
            reality["sni"] = _field("reality_sni")
            reality["server_names"] = [
                part.strip()
                for part in _field("reality_server_names").split(",")
                if part.strip()
            ]
            reality["short_id"] = short_id
            stream["reality"] = reality

        if security == "tls":
            tls = dict(stream.get("tls") or {})
            tls["sni"] = _field("tls_sni")
            tls["alpn"] = [
                part.strip()
                for part in _field("tls_alpn").split(",")
                if part.strip()
            ]
            tls["cert_path"] = _field("tls_cert_path")
            tls["key_path"] = _field("tls_key_path")
            stream["tls"] = tls

    # -- TLS block for the always-TLS protocols ---------------------
    if protocol in ("hysteria2", "tuic", "anytls", "naive", "shadowtls"):
        tls = dict(stream.get("tls") or {})
        tls["sni"] = _field("tls_sni")
        tls["alpn"] = [
            part.strip() for part in _field("tls_alpn").split(",") if part.strip()
        ]
        tls["cert_path"] = _field("tls_cert_path")
        tls["key_path"] = _field("tls_key_path")
        stream["tls"] = tls

    # -- Hysteria2 speed caps ---------------------------------------
    if protocol == "hysteria2":
        try:
            up = _parse_mbps(data.get("up_mbps") or "")
            down = _parse_mbps(data.get("down_mbps") or "")
        except ValueError:
            return None, t["invalid_mbps"]
        stream["up_mbps"] = up
        stream["down_mbps"] = down

    # -- Sing-box protocol options ----------------------------------
    if protocol == "tuic":
        congestion = _field("congestion_control") or "bbr"
        if congestion not in _CONGESTION_CONTROLS:
            return None, t["invalid_congestion"]
        stream["congestion_control"] = congestion
        stream["zero_rtt_handshake"] = _checked("zero_rtt")
    if protocol == "shadowtls":
        method = _field("method") or "2022-blake3-aes-128-gcm"
        if method not in _SHADOWTLS_METHODS:
            return None, t["invalid_method"]
        stream["method"] = method
        stream["password"] = _field("shadowtls_password")
        stream["strict_mode"] = _checked("strict_mode")
        inner_raw = _field("inner_port")
        if inner_raw:
            try:
                inner_port = int(inner_raw)
            except ValueError:
                return None, t["invalid_inner_port"]
            if not 1 <= inner_port <= 65535:
                return None, t["invalid_inner_port"]
            stream["inner_port"] = inner_port
        else:
            stream.pop("inner_port", None)

    # -- WG / AWG / OVPN / ocserv / IKEv2 ---------------------------
    if protocol in ("wireguard", "amneziawg"):
        try:
            stream["subnet"] = _parse_subnet(data.get("subnet") or "")
        except ValueError:
            return None, t["invalid_subnet"]
        try:
            stream["mtu"] = _parse_mtu(data.get("mtu") or "")
        except ValueError:
            return None, t["invalid_mtu"]
        try:
            stream["dns"] = list(_parse_dns_list(data.get("dns") or ""))
        except ValueError:
            return None, t["invalid_dns"]
    if protocol == "amneziawg":
        params: dict[str, Any] = {}
        try:
            params["Jc"] = int(_field("awg_jc") or 0)
            params["Jmin"] = int(_field("awg_jmin") or 0)
            params["Jmax"] = int(_field("awg_jmax") or 0)
            for key in ("S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"):
                params[key] = int(_field(f"awg_{key.lower()}") or 0)
        except ValueError:
            return None, t["invalid_awg_params"]
        # I1–I5 are initiation TAGS (opaque strings), not numbers.
        for key in ("I1", "I2", "I3", "I4", "I5"):
            params[key] = _field(f"awg_{key.lower()}")
        params["HeaderProtectionKey"] = _field("awg_header_key")
        if amneziawg_mod is not None and hasattr(
            amneziawg_mod, "validate_awg_params"
        ):
            problems = amneziawg_mod.validate_awg_params(params)
            if problems:
                return None, t["invalid_awg_params"] + "; ".join(problems)
        stream["awg_params"] = params
    if protocol == "openvpn":
        proto = _field("proto") or "udp"
        if proto not in ("udp", "tcp"):
            return None, t["invalid_transport"]
        stream["transport"] = proto
        try:
            stream["subnet"] = _parse_subnet(data.get("subnet") or "")
        except ValueError:
            return None, t["invalid_subnet"]
        try:
            stream["dns"] = list(_parse_dns_list(data.get("dns") or ""))
        except ValueError:
            return None, t["invalid_dns"]
    if protocol == "openconnect":
        try:
            stream["subnet"] = _parse_subnet(data.get("subnet") or "")
        except ValueError:
            return None, t["invalid_subnet"]
        try:
            stream["dns"] = list(_parse_dns_list(data.get("dns") or ""))
        except ValueError:
            return None, t["invalid_dns"]
        try:
            max_clients = int(_field("max_clients") or 1024)
        except ValueError:
            return None, t["invalid_max_clients"]
        if not 1 <= max_clients <= 100000:
            return None, t["invalid_max_clients"]
        stream["max_clients"] = max_clients
    if protocol == "ikev2":
        try:
            stream["subnet"] = _parse_subnet(data.get("subnet") or "")
        except ValueError:
            return None, t["invalid_subnet"]
        try:
            stream["dns"] = list(_parse_dns_list(data.get("dns") or ""))
        except ValueError:
            return None, t["invalid_dns"]

    return stream, None


def _render_inbound_edit(
    request: Request,
    inbound: Any,
    values: dict[str, Any],
    *,
    error: str | None = None,
    msg: str | None = None,
    db: Session,
) -> HTMLResponse:
    """Render the edit page (GET and POST-error re-render share it)."""
    t = t_for(get_lang(request))
    settings = get_settings(db)
    server_public_key = ""
    if inbound.protocol == "wireguard":
        server_public_key = str(settings.get("wireguard_public_key") or "")
    elif inbound.protocol == "amneziawg":
        server_public_key = str(settings.get("amneziawg_public_key") or "")
    session_token = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "inbound_edit.html",
        {
            "t": t,
            "inbound": inbound,
            "values": values,
            "server_public_key": server_public_key,
            "error": error,
            "msg": msg,
            "lang": get_lang(request),
            # base_path is the web prefix (WEB_PATH): without it the
            # edit form and links render unprefixed and 404 on a
            # server served under a sub-path (every other page gets
            # it via _template_ctx; this helper builds its context
            # by hand, so it must include it explicitly).
            "base_path": WEB_PATH,
            # Same for the CSRF token (S1): this page's forms need
            # it, and _template_ctx is not used here.
            "csrf_token": (
                csrf_token_for_session(session_token)
                if session_token and csrf_token_for_session is not None
                else ""
            ),
        },
    )


@app.get("/inbounds/{inbound_id}/edit", response_class=HTMLResponse)
def edit_inbound_page(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    """Pre-filled edit page for one inbound (Phase 1)."""
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    return _render_inbound_edit(
        request, inbound, _edit_form_values(inbound), db=db
    )


@app.post("/inbounds/{inbound_id}/edit")
async def edit_inbound_submit(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Validate, save, re-render — exactly like the create path.

    On a validation error the edit form is re-rendered (200) with
    the submitted values preserved, so the admin fixes one field
    instead of retyping the whole form.
    """
    t = t_for(get_lang(request))
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    form = await request.form()
    data: dict[str, str] = {
        str(key): str(value) for key, value in form.multi_items()
        if isinstance(value, str)
    }
    values = _edit_form_values(inbound)
    # Merge the submitted values over the current ones so a
    # validation error shows what the admin typed, not the old DB.
    for key, value in data.items():
        values[key] = value
    for checkbox in ("enabled", "sniffing", "zero_rtt", "strict_mode"):
        values[checkbox] = data.get(checkbox) in ("on", "true", "1")

    def _error(message: str) -> HTMLResponse:
        return _render_inbound_edit(
            request, inbound, values, error=message, db=db
        )

    tag = (data.get("tag") or "").strip()
    if not NAME_RE.match(tag):
        return _error(t["invalid_name"])
    clash = (
        db.query(Inbound)
        .filter(Inbound.tag == tag, Inbound.id != inbound.id)
        .first()
    )
    if clash is not None:
        return _error(t["tag_exists"])
    try:
        port = int((data.get("port") or "").strip())
    except ValueError:
        return _error(t["invalid_port"])
    if not 1 <= port <= 65535:
        return _error(t["invalid_port"])
    if port in RESERVED_PORTS and not (inbound.protocol == "ikev2" and port == 500):
        return _error(t["port_reserved"])

    stream, stream_error = _build_stream_from_form(inbound, data, t)
    if stream is None:
        return _error(stream_error or t["invalid_input"])

    # Port clash, same rule as create: (port, transport) must be
    # unique across OTHER inbounds — OpenConnect occupies both.
    new_transports = _inbound_transports(stream, inbound.protocol)
    for other in db.query(Inbound).filter(Inbound.id != inbound.id).all():
        if int(other.port) != port:
            continue
        other_transports = _inbound_transports(
            other.stream if isinstance(other.stream, dict) else {},
            other.protocol,
        )
        if new_transports & other_transports:
            return _error(t["port_in_use"])

    inbound.tag = tag
    inbound.port = port
    inbound.remark = (data.get("remark") or "").strip() or None
    inbound.enabled = bool(data.get("enabled") in ("on", "true", "1"))
    inbound.stream = stream
    db.commit()
    _audit(
        db,
        admin.id if admin is not None else None,
        "inbound.update",
        f"{inbound.protocol} {tag}:{port}",
    )
    errors = rerender_configs(db)
    if errors:
        return _redirect(
            "/inbounds", request, err=t["rerender_failed"] + "; ".join(errors)
        )
    return _redirect("/inbounds", request, msg=t["inbound_updated"])


@app.post("/inbounds/{inbound_id}/regenerate-reality")
def regenerate_reality(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Fresh Reality keypair + shortId for one inbound (Phase 1).

    Clients must re-fetch their configs — the share links change.
    """
    t = t_for(get_lang(request))
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    if inbound.protocol not in _XRAY_STREAM_PROTOCOLS:
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t["invalid_transport"]
        )
    pair = _new_reality_keypair()
    if not pair:
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t["reality_key_failed"]
        )
    stream = dict(inbound.stream) if isinstance(inbound.stream, dict) else {}
    reality = dict(stream.get("reality") or {})
    reality["private_key"] = pair["private_key"]
    reality["public_key"] = pair["public_key"]
    reality["short_id"] = secrets.token_hex(8)
    stream["reality"] = reality
    inbound.stream = stream
    db.commit()
    _audit(
        db,
        admin.id if admin is not None else None,
        "inbound.regenerate_reality",
        inbound.tag,
    )
    errors = rerender_configs(db)
    if errors:
        return _redirect(
            f"/inbounds/{inbound_id}/edit",
            request,
            err=t["rerender_failed"] + "; ".join(errors),
        )
    return _redirect(
        f"/inbounds/{inbound_id}/edit", request, msg=t["reality_regenerated"]
    )


@app.post("/inbounds/{inbound_id}/regenerate-awg-params")
def regenerate_awg_params(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Fresh AmneziaWG obfuscation parameters for one inbound.

    Clients must re-fetch their configs — the junk-packet
    parameters are part of the client config.
    """
    t = t_for(get_lang(request))
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    if inbound.protocol != "amneziawg" or amneziawg_mod is None:
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t["invalid_transport"]
        )
    stream = dict(inbound.stream) if isinstance(inbound.stream, dict) else {}
    stream["awg_params"] = amneziawg_mod.generate_awg_params()
    inbound.stream = stream
    db.commit()
    _audit(
        db,
        admin.id if admin is not None else None,
        "inbound.regenerate_awg_params",
        inbound.tag,
    )
    errors = rerender_configs(db)
    if errors:
        return _redirect(
            f"/inbounds/{inbound_id}/edit",
            request,
            err=t["rerender_failed"] + "; ".join(errors),
        )
    return _redirect(
        f"/inbounds/{inbound_id}/edit", request, msg=t["awg_params_regenerated"]
    )


@app.post("/inbounds/{inbound_id}/regenerate-server-key")
def regenerate_server_key(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Fresh WireGuard/AmneziaWG SERVER keypair for the panel.

    The server key is shared by every inbound of the protocol
    (there is one wg0 / awg0 interface), so this regenerates the
    settings keypair — ALL clients of the protocol must re-fetch
    their configs. The edit page warns about this.
    """
    t = t_for(get_lang(request))
    inbound = db.get(Inbound, inbound_id)
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    if inbound.protocol not in ("wireguard", "amneziawg") or wireguard_mod is None:
        return _redirect(
            f"/inbounds/{inbound_id}/edit", request, err=t["invalid_transport"]
        )
    prefix = inbound.protocol
    private_b64, public_b64 = wireguard_mod.generate_keypair()
    set_setting(db, f"{prefix}_private_key", private_b64)
    set_setting(db, f"{prefix}_public_key", public_b64)
    db.commit()
    _audit(
        db,
        admin.id if admin is not None else None,
        "inbound.regenerate_server_key",
        f"{prefix} {inbound.tag}",
    )
    errors = rerender_configs(db)
    if errors:
        return _redirect(
            f"/inbounds/{inbound_id}/edit",
            request,
            err=t["rerender_failed"] + "; ".join(errors),
        )
    return _redirect(
        f"/inbounds/{inbound_id}/edit", request, msg=t["server_key_regenerated"]
    )


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
        logger.warning("login failed for %r from %s", username, ip)
        return templates.TemplateResponse(request, "login.html",
            _template_ctx(request, {"admin": None, "error": t["wrong_credentials"]}),
            status_code=401,
        )
    admin.last_login_at = datetime.now(timezone.utc)
    db.commit()
    # Clear the failure counter (S2): without this, failed attempts
    # kept accumulating across successful logins within the window.
    if record_successful_login is not None:
        record_successful_login(ip)
    logger.info("login ok for %r from %s", username, ip)
    token = create_session(db, admin, ip)
    response = _redirect("/dashboard", request)
    _set_session_cookie(response, request, token)
    return response


@app.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(db_session),
    csrf: None = Depends(require_csrf),
):
    # POST + CSRF token (S1): a GET logout is a logout-CSRF vector
    # (any site could sign the admin out with an <img> tag).
    token = request.cookies.get(SESSION_COOKIE)
    if token and invalidate_session is not None:
        try:
            invalidate_session(db, token)
        except Exception:  # noqa: BLE001
            logger.exception("invalidate_session failed")
    response = _redirect("/login", request)
    # The deletion must mirror the set attributes (path + Secure):
    # a mismatched path or a non-Secure deletion cannot clear a
    # Secure cookie set under the web path.
    response.delete_cookie(
        SESSION_COOKIE,
        path=WEB_PATH or "/",
        secure=_is_secure_request(request),
    )
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
    # Inbound node cards + protocol distribution (dashboard sections).
    inbounds = db.query(Inbound).order_by(Inbound.id).all()
    clients_by_inbound = {
        i.id: db.query(Client).filter(Client.inbound_id == i.id).count()
        for i in inbounds
    }
    recent_audit = (
        db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(6).all()
    )
    # Phase 3: 14-day total-traffic chart (inline SVG, no JS library).
    traffic_chart, traffic_14d = _traffic_chart(db)
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
                "inbounds": inbounds,
                "clients_by_inbound": clients_by_inbound,
                "today": today,
                "recent_audit": recent_audit,
                "traffic_chart": traffic_chart,
                "traffic_14d": traffic_14d,
            },
        ),
    )


# ---------------------------------------------------------------------------
# User editor helpers (Phase 2 of the professional-panel expansion)
# ---------------------------------------------------------------------------

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
    """Frozen flag for one client (model helper when available, else
    a direct ``extra`` read — same rule either way)."""
    if client_is_frozen is not None:
        try:
            return bool(client_is_frozen(client))
        except (TypeError, AttributeError, ValueError):
            pass
    extra = getattr(client, "extra", None) or {}
    return bool(extra.get("frozen")) if isinstance(extra, dict) else False


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
                "links_available": links_mod is not None,
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


@app.post("/users/{user_id}/toggle")
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


@app.post("/users/{user_id}/delete")
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


@app.post("/users/{user_id}/rotate-token")
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


@app.get("/users/{user_id}/edit", response_class=HTMLResponse)
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


@app.post("/users/{user_id}/edit")
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


@app.post("/users/{user_id}/freeze")
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


@app.post("/users/{user_id}/unfreeze")
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


@app.post("/users/bulk")
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
    settings = get_settings(db)
    # Pre-fill the form like 3X-UI does: a free port, a unique tag and
    # the configured Reality SNI, so the admin can submit as-is.
    try:
        suggested_port = suggest_free_port(db, "tcp")
        suggested_tag = suggest_inbound_tag(db, "vless", suggested_port)
    except ValueError:
        suggested_port, suggested_tag = 0, "vless"
    suggested = {
        "tag": suggested_tag,
        "port": suggested_port,
        "sni": settings.get("reality_sni") or "www.microsoft.com",
    }
    return templates.TemplateResponse(request, "inbounds.html",
        _template_ctx(request, {"admin": admin, "inbounds": inbounds, "suggested": suggested}),
    )


def _check_new_inbound(
    db: Session, protocol: str, port: int, tag: str, transport: str
) -> Optional[str]:
    """Validate a new inbound's port + tag (shared by the web create
    route and the Telegram bot's create flow, so the two paths can
    never disagree).

    Takes the FINAL port and tag (after auto-generation) and returns
    an error code — ``"invalid_port"`` | ``"port_reserved"`` |
    ``"invalid_name"`` | ``"tag_exists"`` | ``"port_in_use"`` — or
    None when the inbound is acceptable. The caller maps the code to
    its own message (web i18n key / bot string).
    """
    if not 1 <= port <= 65535:
        return "invalid_port"
    # UDP 500/4500 are reserved for IKEv2 by design — except port 500
    # itself, which is exactly what an IKEv2 inbound uses.
    if port in RESERVED_PORTS and not (protocol == "ikev2" and port == 500):
        return "port_reserved"
    if not NAME_RE.match(tag):
        return "invalid_name"
    if db.query(Inbound).filter(Inbound.tag == tag).first() is not None:
        return "tag_exists"
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
        if existing.port == port and transport in _inbound_transports(
            existing_stream, existing.protocol
        ):
            return "port_in_use"
    return None


@app.post("/inbounds")
def create_inbound(
    request: Request,
    tag: str = Form(""),
    core: str = Form(...),
    protocol: str = Form(...),
    port: int = Form(0),
    remark: str = Form(""),
    sni: str = Form(""),
    path: str = Form(""),
    network: str = Form("tcp"),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    tag = (tag or "").strip()
    core = core.strip().lower()
    protocol = protocol.strip().lower()
    network = (network or "tcp").strip() or "tcp"
    transport = _stream_transport({"transport": network}, protocol)
    # The new protocols fix their own transport: IKEv2 and AmneziaWG
    # are UDP-only, OpenConnect binds TCP+UDP on one port (its clash
    # check uses both — see _inbound_transports).
    if protocol in ("ikev2", "amneziawg"):
        transport = "udp"
    elif protocol == "openconnect":
        transport = "tcp"
    # Auto-generation: an empty port (0) means "pick a free one" and
    # an empty tag means "derive it from protocol + port" — the form
    # comes pre-filled with both, so accepting the defaults just works.
    # The preferred port per protocol is tried first (1194 for
    # OpenVPN, 4433 for OpenConnect, 51821 for AmneziaWG, 500 for
    # IKEv2) and a random free port is the fallback.
    if not port:
        try:
            port = suggest_protocol_port(db, protocol, transport)
        except ValueError:
            return _redirect("/inbounds", request, err=t["invalid_port"])
    if not tag:
        tag = suggest_inbound_tag(db, protocol, port)
    check = _check_new_inbound(db, protocol, port, tag, transport)
    if check is not None:
        return _redirect("/inbounds", request, err=t[check])
    stream: dict[str, Any] = {
        "network": network,
        "transport": transport,
    }
    # Protocol-specific defaults (the renderers read these from the
    # inbound stream): the client subnet, and the AmneziaWG
    # obfuscation parameters (generated once here, shared by the
    # server and every client of the inbound).
    if protocol == "wireguard":
        stream["subnet"] = "10.8.0.0/24"
    if protocol == "openvpn":
        stream["subnet"] = (
            openvpn_mod.DEFAULT_NETWORK if openvpn_mod is not None else "10.9.0.0/24"
        )
    elif protocol == "openconnect":
        stream["subnet"] = (
            openconnect_mod.DEFAULT_NETWORK
            if openconnect_mod is not None
            else "10.10.10.0/24"
        )
    elif protocol == "amneziawg":
        stream["subnet"] = (
            amneziawg_mod.DEFAULT_NETWORK
            if amneziawg_mod is not None
            else "10.8.1.0/24"
        )
        if amneziawg_mod is not None:
            stream["awg_params"] = amneziawg_mod.generate_awg_params()
    elif protocol == "ikev2":
        stream["subnet"] = (
            ikev2_mod.DEFAULT_NETWORK if ikev2_mod is not None else "10.20.0.0/24"
        )
    if sni.strip() and core in ("xray", "singbox"):
        reality_block: dict[str, Any] = {"sni": sni.strip(), "dest": f"{sni.strip()}:443"}
        if protocol == "vless":
            # A fresh keypair per inbound (like 3X-UI's "Get New Cert"):
            # the share links read public_key + short_id from here, so
            # without them the links would miss pbk/sid entirely.
            pair = _new_reality_keypair()
            if pair:
                reality_block["private_key"] = pair["private_key"]
                reality_block["public_key"] = pair["public_key"]
                reality_block["short_id"] = secrets.token_hex(4)
        stream["reality"] = reality_block
        stream["tls"] = {"sni": sni.strip()}
        stream["security"] = "reality" if protocol == "vless" else "tls"
    if path.strip():
        stream["path"] = path.strip()
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
    logger.info("inbound created: %s %s:%s", tag, protocol, port)
    errors = rerender_configs(db)
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


@app.post("/inbounds/{inbound_id}/toggle")
def toggle_inbound(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    inbound = db.query(Inbound).filter(Inbound.id == inbound_id).first()
    if inbound is None:
        raise HTTPException(status_code=404, detail="inbound not found")
    inbound.enabled = not inbound.enabled
    db.commit()
    _audit(db, admin.id, "inbound.toggle", f"{inbound.tag} enabled={inbound.enabled}")
    logger.info("inbound toggled: %s enabled=%s", inbound.tag, inbound.enabled)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


@app.post("/inbounds/{inbound_id}/delete")
def delete_inbound(
    request: Request,
    inbound_id: int,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
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
    logger.info("inbound deleted: %s", tag)
    errors = rerender_configs(db)
    t = t_for(get_lang(request))
    err = (t["rerender_failed"] + "; ".join(errors)) if errors else ""
    return _redirect("/inbounds", request, err=err)


# ---------------------------------------------------------------------------
# Settings (HTML)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Panel & server settings helpers (Phase 3 of the professional-panel expansion)
# ---------------------------------------------------------------------------

PASSWORD_MIN_LENGTH = 8
TELEGRAM_EXPIRY_HOURS = 24
TELEGRAM_RERENDER_NOTIFY_MIN_GAP = timedelta(hours=1)
CHAT_ID_RE = re.compile(r"^-?\d+$")
# Ports Telegram delivers webhooks to (Bot API rule — a panel on any
# other port cannot receive webhooks; see _public_panel_url).
TELEGRAM_WEBHOOK_PORTS = (443, 80, 88, 8443)
# Bot transports (Phase 4 follow-up): "polling" is the default
# (professional upgrade, Phase 3 — polling works on any panel port,
# while webhooks only work on 443/80/88/8443 and the installer picks
# a random port). An install that explicitly chose "webhook" keeps
# it — only the default for an unset value changed. Stored in the
# settings table as ``telegram_transport`` — no DB schema change.
TELEGRAM_TRANSPORTS = ("webhook", "polling")
TELEGRAM_TRANSPORT_DEFAULT = "polling"
# Polling diagnostics (professional upgrade, Phase 3) — all in the
# settings table, no DB schema change. The offset survives restarts
# (a restart no longer re-fetches already-processed updates); the
# timestamps feed the settings page's Telegram diagnostics section.
TELEGRAM_POLLING_OFFSET_KEY = "telegram_polling_offset"
TELEGRAM_POLLING_LAST_POLL_KEY = "telegram_polling_last_poll"
TELEGRAM_POLLING_LAST_UPDATE_KEY = "telegram_polling_last_update"
TELEGRAM_POLLING_LAST_ERROR_KEY = "telegram_polling_last_error"
# Polling loop tuning (see _telegram_polling_loop). The long-poll wait
# is 30 s (Bot API max is 50); the idle re-check keeps transport
# switches live without a restart; a fast empty getUpdates return is
# treated as a failure (the helper returns [] on failure) and backs
# off exponentially up to the cap.
TELEGRAM_POLL_TIMEOUT = 30.0
TELEGRAM_POLL_IDLE_SECONDS = 10.0
TELEGRAM_POLL_SHORT_CALL_SECONDS = 5.0
TELEGRAM_POLL_BACKOFF_BASE = 5.0
TELEGRAM_POLL_BACKOFF_MAX = 60.0

# BackupError.code -> STRINGS key for the restore error message.
_RESTORE_ERROR_KEYS = {
    "not_a_backup": "restore_invalid",
    "corrupt": "restore_invalid",
    "missing_tables": "restore_invalid",
    "too_large": "restore_invalid",
    "newer_schema": "restore_newer_schema",
}


def _change_admin_password(
    db: Session,
    admin: Any,
    current_password: str,
    new_password: str,
    confirm_password: str,
    keep_token: Optional[str] = None,
) -> tuple[bool, str]:
    """Validate and apply an admin password change.

    Returns ``(ok, message_key)``. On success the stored hash is
    replaced (PBKDF2 via :mod:`app.auth`, so the new password
    survives restarts — ``ensure_defaults`` only seeds a password
    when no admin exists) and every OTHER session is invalidated, so
    other devices are signed out while this one stays logged in. No
    password value is ever logged.
    """
    if verify_password is None or hash_password is None:
        return False, "invalid_input"
    if not verify_password(current_password, admin.password_hash):
        return False, "wrong_current_password"
    if len(new_password) < PASSWORD_MIN_LENGTH:
        return False, "password_too_short"
    if new_password != confirm_password:
        return False, "password_mismatch"
    admin.password_hash = hash_password(new_password)
    db.commit()
    if invalidate_other_sessions is not None:
        try:
            invalidate_other_sessions(db, admin.id, keep_token=keep_token)
        except Exception:  # noqa: BLE001
            logger.warning("invalidating other sessions failed")
    return True, "password_changed"


def _telegram_configured(db: Session) -> bool:
    """True when both a bot token and a chat ID are stored."""
    settings = get_settings(db)
    return bool(
        settings.get("telegram_bot_token") and settings.get("telegram_chat_id")
    )


def _ensure_webhook_secret(db: Session) -> str:
    """The random webhook path secret (generated once, stored in the
    settings table).

    The webhook URL carries this secret, NOT the bot token: the token
    in the URL would land in uvicorn's access log on every delivery
    (and it grants full Bot API access), while this single-purpose
    secret only authenticates webhook posts and can be rotated by
    deleting the ``telegram_webhook_secret`` setting row and
    re-registering the webhook.
    """
    settings = get_settings(db)
    secret = (settings.get("telegram_webhook_secret") or "").strip()
    if not secret:
        secret = secrets.token_urlsafe(32)
        set_setting(db, "telegram_webhook_secret", secret)
    return secret


def _public_panel_url(settings: dict[str, str], path: str = "") -> Optional[str]:
    """Public https URL for a panel path, or None when no domain is set.

    The domain setting is a bare hostname (a scheme the admin typed
    is stripped; a port the admin typed is respected). The panel port
    is appended unless it is 443 or the domain already carries one.
    The secret web prefix (WEB_PATH) is included, so the URL works
    exactly as the panel is served.
    """
    domain = (settings.get("domain") or "").strip()
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE).strip().rstrip("/")
    if not domain:
        return None
    if ":" in domain:
        host = domain
    elif PANEL_PORT == 443:
        host = domain
    else:
        host = f"{domain}:{PANEL_PORT}"
    return f"https://{host}{WEB_PATH}{path}"


def _mask_webhook_url(url: str) -> str:
    """A webhook URL with the secret segment masked (safe for the UI).

    The secret is the last path segment (``.../webhook/<secret>``);
    only its last 4 characters are shown, like ``mask_token``.
    """
    url = (url or "").strip()
    if not url:
        return ""
    head, _, tail = url.rpartition("/")
    if not tail or len(tail) <= 4:
        return url
    return f"{head}/••••{tail[-4:]}"


def _notify_telegram(db: Session, text: str) -> bool:
    """Send a Telegram notification if configured. Never raises.

    The token is read from settings and passed straight to the
    sender — it is never logged (not even on failure: the warning
    below carries no exception text, because HTTP errors can echo
    the request URL, which contains the token).
    """
    if telegram_mod is None or not text:
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


def _notify_expiring_users(db: Session, now: Optional[datetime] = None) -> int:
    """Notify about users expiring within 24h (once per user per day).

    Runs from the expiry sweeper. Dedup state lives in the
    ``telegram_expiry_notified`` setting (``{user_id: "YYYY-MM-DD"}``)
    — no schema change. Returns the number of notifications sent.
    Background task, so the message uses Persian (panel default).
    Never raises.
    """
    if telegram_mod is None:
        return 0
    try:
        now = now or datetime.now(timezone.utc)
        today = now.date().isoformat()
        settings = get_settings(db)
        try:
            notified = json.loads(settings.get("telegram_expiry_notified", "") or "{}")
            if not isinstance(notified, dict):
                notified = {}
        except ValueError:
            notified = {}
        pruned = {k: v for k, v in notified.items() if v == today}
        changed = len(pruned) != len(notified)
        notified = pruned
        t = t_for("fa")
        sent = 0
        horizon = now + timedelta(hours=TELEGRAM_EXPIRY_HOURS)
        for user in db.query(User).filter(User.enabled.is_(True)).all():
            if user.expires_at is None:
                continue
            expires = user.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if not (now < expires <= horizon):
                continue
            if notified.get(str(user.id)) == today:
                continue
            hours = max(1, int((expires - now).total_seconds() // 3600))
            if _notify_telegram(
                db, t["tg_user_expiring"].format(name=user.name, hours=hours)
            ):
                notified[str(user.id)] = today
                changed = True
                sent += 1
        if changed:
            set_setting(db, "telegram_expiry_notified", json.dumps(notified))
        return sent
    except Exception:  # noqa: BLE001
        logger.warning("expiry notification check failed")
        return 0


def _notify_rerender_failure(db: Session, errors: list[str]) -> bool:
    """Notify about a re-render failure, at most once per hour.

    The sweeper runs every 5 minutes, so an unthrottled hook would
    spam the admin while a failure persists. The last-notify time
    lives in the ``telegram_rerender_notified_at`` setting. Never
    raises.
    """
    if telegram_mod is None or not errors:
        return False
    try:
        now = datetime.now(timezone.utc)
        settings = get_settings(db)
        last = settings.get("telegram_rerender_notified_at", "")
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                if now - last_dt < TELEGRAM_RERENDER_NOTIFY_MIN_GAP:
                    return False
            except ValueError:
                pass
        t = t_for("fa")
        detail = "; ".join(str(e) for e in errors)[:200]
        if _notify_telegram(db, t["tg_rerender_failed"].format(errors=detail)):
            set_setting(db, "telegram_rerender_notified_at", now.isoformat())
            return True
        return False
    except Exception:  # noqa: BLE001
        logger.warning("re-render failure notification failed")
        return False


def _traffic_chart(
    db: Session, user_id: Optional[int] = None, today: Any = None
) -> tuple[str, int]:
    """``(svg, total_bytes)`` for the last 14 days of ``traffic_daily``.

    ``user_id=None`` charts all users (dashboard); a user id charts
    one user (user detail). Days with no recorded traffic are zero
    bars, never invented values. Returns ``("", 0)`` when the charts
    module is unavailable. Never raises.
    """
    if charts_mod is None:
        return "", 0
    try:
        query = db.query(TrafficDaily)
        if user_id is not None:
            query = query.filter(TrafficDaily.user_id == user_id)
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


def _db_file_path(db: Session) -> Optional[Path]:
    """The SQLite file the current session's engine uses (None if unknown)."""
    try:
        bind = db.get_bind()
        database = getattr(getattr(bind, "url", None), "database", None)
        if database and database != ":memory:":
            return Path(database)
    except Exception:  # noqa: BLE001
        pass
    try:
        configured = _cfg_attr("DB_PATH", "")
        return Path(configured) if configured else None
    except Exception:  # noqa: BLE001
        return None


@app.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    settings = get_settings(db)
    # The bot token never reaches the template context: the form only
    # ever shows a "configured" badge, never the value. Same for the
    # webhook secret and the webhook URL that carries it — the template
    # gets the masked URL only.
    settings_view = {
        k: v
        for k, v in settings.items()
        if k
        not in ("telegram_bot_token", "telegram_webhook_secret", "telegram_webhook_url")
    }
    server_status = None
    if system_status_mod is not None:
        try:
            server_status = system_status_mod.collect_server_status(DATA_DIR)
        except Exception:  # noqa: BLE001
            server_status = None
    webhook_info = None
    raw_info = settings.get("telegram_webhook_info", "")
    if raw_info:
        try:
            parsed = json.loads(raw_info)
            webhook_info = parsed if isinstance(parsed, dict) else None
        except ValueError:
            webhook_info = None
    # Bot identity (getMe, cached by the refresh action) — public
    # info only (id, username, first name), never the token.
    bot_identity = None
    raw_identity = settings.get("telegram_bot_identity", "")
    if raw_identity:
        try:
            parsed = json.loads(raw_identity)
            bot_identity = parsed if isinstance(parsed, dict) else None
        except ValueError:
            bot_identity = None
    return templates.TemplateResponse(request, "settings.html",
        _template_ctx(request, {
            "admin": admin,
            "settings": settings_view,
            "server_status": server_status,
            "telegram_configured": _telegram_configured(db),
            "telegram_token_set": bool(settings.get("telegram_bot_token")),
            "telegram_transport_default": TELEGRAM_TRANSPORT_DEFAULT,
            "telegram_webhook_url_display": _mask_webhook_url(
                settings.get("telegram_webhook_url", "")
            ),
            "telegram_webhook_registered_at": settings.get(
                "telegram_webhook_registered_at", ""
            ),
            "telegram_webhook_info": webhook_info,
            "telegram_bot_identity": bot_identity,
            "telegram_commands_registered_at": settings.get(
                "telegram_commands_registered_at", ""
            ),
            "telegram_polling_status": {
                "last_poll": settings.get(TELEGRAM_POLLING_LAST_POLL_KEY, ""),
                "last_update": settings.get(
                    TELEGRAM_POLLING_LAST_UPDATE_KEY, ""
                ),
                "last_error": settings.get(TELEGRAM_POLLING_LAST_ERROR_KEY, ""),
                "offset": settings.get(TELEGRAM_POLLING_OFFSET_KEY, ""),
            },
        }),
    )


@app.post("/settings")
def save_settings(
    request: Request,
    domain: str = Form(""),
    subscription_host: str = Form(""),
    reality_sni: str = Form(""),
    log_level: str = Form(""),
    telegram_bot_token: str = Form(""),
    telegram_chat_id: str = Form(""),
    telegram_transport: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    chat_id = telegram_chat_id.strip()
    if chat_id and not CHAT_ID_RE.match(chat_id):
        return _redirect("/settings", request, err=t["invalid_chat_id"])
    # The previous transport is read before saving so a switch to
    # polling can be detected (it needs a deleteWebhook call — see
    # below). An invalid submitted value keeps the previous one.
    settings_before = get_settings(db)
    previous_transport = (
        (settings_before.get("telegram_transport") or "").strip().lower()
        or TELEGRAM_TRANSPORT_DEFAULT
    )
    if previous_transport not in TELEGRAM_TRANSPORTS:
        previous_transport = TELEGRAM_TRANSPORT_DEFAULT
    submitted_transport = telegram_transport.strip().lower()
    transport = (
        submitted_transport
        if submitted_transport in TELEGRAM_TRANSPORTS
        else previous_transport
    )
    set_setting(db, "domain", domain.strip())
    set_setting(db, "subscription_host", subscription_host.strip())
    set_setting(db, "reality_sni", reality_sni.strip() or "www.microsoft.com")
    commands_err = ""
    if telegram_bot_token.strip():
        # A blank token field keeps the current token (the form never
        # shows it, so a submit without a new value must not clear it).
        # Clearing the chat ID disables notifications.
        new_token = telegram_bot_token.strip()
        set_setting(db, "telegram_bot_token", new_token)
        # A new bot gets its command menu registered right away
        # (setMyCommands) — best-effort: a failure is reported, not
        # fatal (the settings still save; the admin can retry from
        # the "Register commands" button). A failed registration on
        # a fresh token is also the first sign the token is wrong.
        if telegram_mod is not None and bot_mod is not None:
            ok, error = telegram_mod.set_my_commands(
                new_token, list(bot_mod.BOT_COMMANDS)
            )
            if ok:
                set_setting(
                    db,
                    "telegram_commands_registered_at",
                    datetime.now(timezone.utc).isoformat(),
                )
            else:
                commands_err = t["telegram_commands_failed"] + (
                    f" {error}" if error else ""
                )
    set_setting(db, "telegram_chat_id", chat_id)
    set_setting(db, "telegram_transport", transport)
    if transport != previous_transport:
        _audit(
            db, admin.id, "telegram.transport_change",
            f"{previous_transport} -> {transport}",
        )
    if log_level.strip() and panel_log_mod is not None:
        # Applies immediately (no restart); the value is validated
        # against the known levels inside apply_log_level.
        applied = panel_log_mod.apply_log_level(log_level.strip())
        set_setting(db, "log_level", applied)
        logger.info("log level set to %s by %s", applied, admin.username)
    msg = ""
    polling_err = ""
    if transport == "polling" and telegram_mod is not None:
        # A webhook set on Telegram's side suppresses getUpdates
        # delivery, so polling receives nothing until the webhook is
        # gone. The call runs on every save with transport=polling
        # (it is idempotent), so a failed removal at switch time is
        # retried silently by later saves. Only a failure AT the
        # switch is shown: a later failure cannot re-create a
        # webhook, so showing it would be a false alarm — and a
        # success is only announced on the switch itself, not on
        # every unrelated save.
        effective_token = (
            telegram_bot_token.strip()
            or settings_before.get("telegram_bot_token", "")
        ).strip()
        if effective_token:
            ok, error = telegram_mod.delete_webhook(effective_token)
            if ok:
                if transport != previous_transport:
                    msg = t["telegram_polling_active"]
            elif transport != previous_transport:
                detail = error.strip() if error else ""
                polling_err = t["telegram_polling_webhook_failed"] + (
                    f" {detail}" if detail else ""
                )
            else:
                logger.warning("telegram polling webhook removal failed")
    _audit(db, admin.id, "settings.update", f"domain={domain.strip()!r}")
    errors = rerender_configs(db)
    err_parts = []
    # The polling failure goes FIRST: _redirect truncates err to 500
    # chars, and the transport switch is the action the admin just
    # took — its failure must survive even when the re-render also
    # reports (long) errors.
    if polling_err:
        err_parts.append(polling_err)
    if commands_err:
        err_parts.append(commands_err)
    if errors:
        err_parts.append(t["rerender_failed"] + "; ".join(errors))
    return _redirect(
        "/settings", request, msg=msg, err=" ".join(err_parts)
    )


@app.post("/settings/password")
def change_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    token = request.cookies.get(SESSION_COOKIE)
    ok, key = _change_admin_password(
        db, admin, current_password, new_password, confirm_password,
        keep_token=token,
    )
    if not ok:
        return _redirect("/settings", request, err=t[key])
    _audit(db, admin.id, "admin.password_change", admin.username)
    logger.info("admin password changed by %s", admin.username)
    return _redirect("/settings", request, msg=t[key])


@app.post("/settings/telegram-test")
def telegram_test(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    if not _telegram_configured(db):
        return _redirect("/settings", request, err=t["telegram_not_configured"])
    if _notify_telegram(db, t["tg_test"]):
        _audit(db, admin.id, "telegram.test", "")
        return _redirect("/settings", request, msg=t["telegram_test_sent"])
    return _redirect("/settings", request, err=t["telegram_test_failed"])


@app.post("/settings/telegram-webhook")
def register_telegram_webhook(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """(Re-)register the bot webhook with Telegram (Phase 4).

    The webhook URL is the panel's public URL + WEB_PATH +
    ``/telegram/webhook/<secret>``. A domain is required (Telegram
    needs a public HTTPS URL); when the panel port is not one of the
    ports Telegram delivers webhooks to, the registration is still
    attempted and Telegram's own error is shown, with the port
    warning appended so the admin knows why it failed.
    """
    t = t_for(get_lang(request))
    if telegram_mod is None or not _telegram_configured(db):
        return _redirect("/settings", request, err=t["telegram_not_configured"])
    settings = get_settings(db)
    secret = _ensure_webhook_secret(db)
    url = _public_panel_url(settings, f"/telegram/webhook/{secret}")
    if url is None:
        return _redirect("/settings", request, err=t["telegram_domain_required"])
    token = settings.get("telegram_bot_token", "")
    ok, error = telegram_mod.set_webhook(token, url)
    if not ok:
        # Telegram's errors do not echo the URL, but the description
        # is user-visible text — strip the secret defensively anyway.
        detail = error.replace(secret, "••••") if error else ""
        msg = t["telegram_webhook_failed"] + (f" {detail}" if detail else "")
        if PANEL_PORT not in TELEGRAM_WEBHOOK_PORTS:
            msg += " " + t["telegram_webhook_port_warning"]
        return _redirect("/settings", request, err=msg)
    set_setting(db, "telegram_webhook_url", url)
    set_setting(
        db,
        "telegram_webhook_registered_at",
        datetime.now(timezone.utc).isoformat(),
    )
    _audit(db, admin.id, "telegram.webhook_register", "")
    logger.info("telegram webhook registered by %s", admin.username)
    return _redirect("/settings", request, msg=t["telegram_webhook_registered"])


@app.post("/settings/telegram-webhook-status")
def refresh_telegram_webhook_status(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Refresh the stored webhook status from Telegram's getWebhookInfo.

    The status is fetched on demand (not on every settings-page
    render) so a slow or dead Telegram never slows the page. Only the
    useful fields are stored; the URL is masked at render time.
    """
    t = t_for(get_lang(request))
    if telegram_mod is None or not _telegram_configured(db):
        return _redirect("/settings", request, err=t["telegram_not_configured"])
    settings = get_settings(db)
    info = telegram_mod.get_webhook_info(settings.get("telegram_bot_token", ""))
    if info is None:
        return _redirect("/settings", request, err=t["telegram_webhook_status_failed"])
    kept = {
        key: info[key]
        for key in (
            "url",
            "pending_update_count",
            "last_error_date",
            "last_error_message",
            "last_synchronization_error_date",
        )
        if key in info
    }
    set_setting(db, "telegram_webhook_info", json.dumps(kept))
    return _redirect("/settings", request, msg=t["telegram_webhook_status_ok"])


@app.post("/settings/telegram-commands")
def register_telegram_commands(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Register the bot's command menu with Telegram (setMyCommands).

    The command list comes from ``app.bot.BOT_COMMANDS`` (start /
    help / menu / status / users / inbounds / cancel) — the same
    list the bot actually handles, so Telegram's menu can never
    offer a command the bot does not implement. The registration
    time is stored for the diagnostics section.
    """
    t = t_for(get_lang(request))
    if telegram_mod is None or bot_mod is None or not _telegram_configured(db):
        return _redirect("/settings", request, err=t["telegram_not_configured"])
    settings = get_settings(db)
    ok, error = telegram_mod.set_my_commands(
        settings.get("telegram_bot_token", ""), list(bot_mod.BOT_COMMANDS)
    )
    if not ok:
        msg = t["telegram_commands_failed"] + (f" {error}" if error else "")
        return _redirect("/settings", request, err=msg)
    set_setting(
        db,
        "telegram_commands_registered_at",
        datetime.now(timezone.utc).isoformat(),
    )
    _audit(db, admin.id, "telegram.commands_register", "")
    return _redirect("/settings", request, msg=t["telegram_commands_registered"])


@app.post("/settings/telegram-identity")
def refresh_telegram_identity(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    """Fetch the bot's identity (getMe) and cache it for diagnostics.

    Fetched on demand (not on every settings-page render) so a slow
    or dead Telegram never slows the page. Only the public identity
    (id, username, first name) is stored — never the token.
    """
    t = t_for(get_lang(request))
    if telegram_mod is None or not _telegram_configured(db):
        return _redirect("/settings", request, err=t["telegram_not_configured"])
    settings = get_settings(db)
    info = telegram_mod.get_me(settings.get("telegram_bot_token", ""))
    if info is None:
        return _redirect("/settings", request, err=t["telegram_identity_failed"])
    kept = {
        key: info[key]
        for key in ("id", "username", "first_name")
        if key in info
    }
    kept["fetched_at"] = datetime.now(timezone.utc).isoformat()
    set_setting(db, "telegram_bot_identity", json.dumps(kept))
    _audit(db, admin.id, "telegram.identity_refresh", "")
    return _redirect("/settings", request, msg=t["telegram_identity_ok"])


@app.post("/telegram/webhook/{secret}")
async def telegram_webhook(
    request: Request,
    secret: str,
    db: Session = Depends(db_session),
):
    """Telegram webhook (Phase 4). No login: Telegram cannot log in —
    the path secret authenticates the post, and the bot module
    authenticates the chat. Inert (404) when the bot is not
    configured, no webhook was ever registered, or the secret does
    not match — nothing about the bot is revealed to a wrong guess.
    A malformed body still gets 200: Telegram retries non-2xx
    responses, and retrying garbage helps nobody.
    """
    if bot_mod is None:
        raise HTTPException(status_code=404, detail="not found")
    settings = get_settings(db)
    token = settings.get("telegram_bot_token", "")
    stored = settings.get("telegram_webhook_secret", "")
    if not token or not settings.get("telegram_chat_id") or not stored:
        raise HTTPException(status_code=404, detail="not found")
    if not hmac.compare_digest(secret, stored):
        raise HTTPException(status_code=404, detail="not found")
    try:
        update = await request.json()
    except Exception:  # noqa: BLE001 — malformed body: 200, no retry storm
        return {"ok": True}
    if not isinstance(update, dict):
        return {"ok": True}
    try:
        bot_mod.handle_update(db, update, bot_mod.TelegramSender(token))
    except Exception:  # noqa: BLE001 — dispatch never breaks the webhook
        logger.exception("telegram webhook dispatch failed")
    return {"ok": True}


@app.get("/settings/backup")
def download_backup(
    request: Request,
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    if backup_mod is None:
        raise HTTPException(status_code=503, detail="backup unavailable")
    db_path = _db_file_path(db)
    if db_path is None or not db_path.exists():
        raise HTTPException(status_code=503, detail="database path unknown")
    try:
        data = backup_mod.create_backup_zip(db_path)
    except Exception:  # noqa: BLE001
        logger.exception("backup creation failed")
        raise HTTPException(status_code=500, detail="backup failed")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    _audit(db, admin.id, "settings.backup", f"{len(data)} bytes")
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition":
                f'attachment; filename="sparky-manager-backup-{stamp}.zip"'
        },
    )


@app.post("/settings/restore")
async def restore_backup(
    request: Request,
    backup_file: UploadFile = File(None),
    confirm_restore: str = Form(""),
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    # Capture the admin id up front: the restore closes this request's
    # session (rollback expires its objects), so `admin` is detached
    # by the time the post-restore audit runs.
    admin_id = admin.id
    if backup_mod is None or reset_engine is None or dispose_engine is None:
        return _redirect("/settings", request, err=t["restore_failed"])
    if not confirm_restore:
        return _redirect("/settings", request, err=t["restore_confirm_required"])
    if backup_file is None or not backup_file.filename:
        return _redirect("/settings", request, err=t["restore_no_file"])
    # Read the upload with a size cap (chunked, so an oversized file
    # is refused without ever being fully buffered).
    chunks: list[bytes] = []
    total = 0
    cap = backup_mod.BACKUP_MAX_BYTES
    while True:
        chunk = await backup_file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            return _redirect("/settings", request, err=t["restore_invalid"])
        chunks.append(chunk)
    data = b"".join(chunks)
    db_path = _db_file_path(db)
    if db_path is None or not db_path.exists():
        return _redirect("/settings", request, err=t["restore_failed"])
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sparky-restore-") as tmp:
        try:
            info = backup_mod.validate_backup_bytes(data, tmp)
        except backup_mod.BackupError as exc:
            key = _RESTORE_ERROR_KEYS.get(exc.code, "restore_invalid")
            if key == "restore_newer_schema":
                message = t[key]
            else:
                message = t[key] + (exc.detail or exc.code)
            return _redirect("/settings", request, err=message)
        # Validation passed: back up the current DB first, then swap.
        try:
            backup_mod.backup_current_db(db_path, DATA_DIR / "backups")
        except Exception:  # noqa: BLE001
            logger.exception("pre-restore backup failed")
            return _redirect("/settings", request, err=t["restore_failed"])
        # Close this request's session and dispose the engine BEFORE
        # the file is replaced (the old engine's connections point at
        # the old file). The session is rolled back first so the
        # dependency's exit-commit has nothing to write.
        try:
            db.rollback()
            db.close()
        except Exception:  # noqa: BLE001
            pass
        dispose_engine()
        try:
            backup_mod.swap_db_file(db_path, info.db_file)
        except Exception:  # noqa: BLE001
            logger.exception("restore file swap failed")
            return _redirect("/settings", request, err=t["restore_failed"])
        try:
            reset_engine()
        except Exception:  # noqa: BLE001
            logger.exception("engine reset after restore failed")
            return _redirect("/settings", request, err=t["restore_failed"])
    # Fresh session on the restored DB: audit + re-render configs.
    # (SessionLocal directly — get_session() would rebind to the
    # configured path if the singleton were ever unset.)
    errors: list[str] = []
    fresh = SessionLocal()
    try:
        _audit(fresh, admin_id, "settings.restore",
               f"{info.users} users, {info.inbounds} inbounds")
        errors = rerender_configs(fresh)
    except Exception:  # noqa: BLE001
        logger.exception("post-restore re-render failed")
        errors = ["post-restore re-render failed"]
    finally:
        fresh.close()
    if errors:
        return _redirect(
            "/settings", request,
            err=t["rerender_failed"] + "; ".join(errors),
        )
    return _redirect("/settings", request, msg=t["restore_done"])


# ---------------------------------------------------------------------------
# Logs (admin only) — the file log, viewable / searchable / downloadable
# from the panel, so a failed restart can be debugged without SSH.
# ---------------------------------------------------------------------------


@app.get("/logs", response_class=HTMLResponse)
def logs_page(
    request: Request,
    level: str = Query(""),
    q: str = Query(""),
    limit: int = Query(500),
    admin: Any = Depends(require_admin),
    db: Session = Depends(db_session),
):
    if panel_log_mod is None:
        lines, total, files, log_path = [], 0, [], ""
    else:
        log_path = panel_log_mod.get_log_path()
        try:
            limit_n = max(50, min(int(limit), 2000))
        except (TypeError, ValueError):
            limit_n = 500
        lines, total = panel_log_mod.read_log_lines(
            log_path, level=level or None, query=q or None, limit=limit_n
        )
        files = panel_log_mod.list_log_files()
    return templates.TemplateResponse(request, "logs.html",
        _template_ctx(
            request,
            {
                "admin": admin,
                "lines": lines,
                "total": total,
                "level": level,
                "q": q,
                "limit": limit,
                "files": files,
                "log_path": str(log_path),
            },
        ),
    )


@app.get("/logs/download")
def logs_download(
    request: Request,
    admin: Any = Depends(require_admin),
):
    if panel_log_mod is None:
        raise HTTPException(status_code=503, detail="logging unavailable")
    path = panel_log_mod.get_log_path()
    if not path.exists():
        raise HTTPException(status_code=404, detail="log file not found")
    return FileResponse(path, filename="panel.log", media_type="text/plain")


@app.post("/logs/clear")
def logs_clear(
    request: Request,
    admin: Any = Depends(require_admin),
    csrf: None = Depends(require_csrf),
    db: Session = Depends(db_session),
):
    t = t_for(get_lang(request))
    if panel_log_mod is not None:
        if panel_log_mod.clear_log():
            logger.info("log cleared by admin %s", admin.username)
            _audit(db, admin.id, "logs.clear", "")
            return _redirect("/logs", request, msg=t["log_cleared"])
        logger.exception("clearing the log file failed")
        return _redirect("/logs", request, err=t["log_clear"])
    return _redirect("/logs", request, err=t["log_clear"])


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
    base = str(request.base_url).rstrip("/") + WEB_PATH
    usable = _user_usable(db, user)
    links = _links_for_user(db, user, host, settings) if usable else []
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
                "zedsecure_url": f"{base}/sub/{user.sub_token}/zedsecure.json",
                "user_url": f"{base}/u/{user.sub_token}",
                "file_urls": _file_export_urls(db, user, base) if usable else {},
                "host": host,
                "error": "" if usable else t_for(get_lang(request))["user_unusable"],
            },
        ),
    )


def _token_fp(token: str) -> str:
    """Short fingerprint for a subscription token (never the token)."""
    if panel_log_mod is not None:
        return panel_log_mod.token_fingerprint(token)
    return "?"


def _userinfo_header(user: Any) -> str:
    """``Subscription-Userinfo`` header value for ``user`` ("" on error)."""
    if subscription_mod is None:
        return ""
    expires_unix = 0
    if user.expires_at is not None:
        exp = user.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        expires_unix = int(exp.timestamp())
    try:
        return str(
            subscription_mod.subscription_userinfo(
                user.traffic_used_bytes or 0,
                user.traffic_limit_bytes,
                expires_unix,
            )
            or ""
        )
    except Exception:  # noqa: BLE001
        logger.exception("subscription_userinfo failed")
        return ""


def _singbox_outbounds_for(
    db: Session, client: Any, inbound: Any, user: Any, host: str, settings: dict[str, Any]
) -> list[dict[str, Any]]:
    """Every sing-box object for a (client, inbound) pair (``[]`` to skip).

    Shared by the sing-box feed and the ZedSecure bundle. The
    WireGuard server public key is not part of the inbound row — it
    lives in settings — so it is handed to the outbound builder
    through the inbound's stream, where ``outbounds_for_client``
    looks for it. ShadowTLS contributes two objects (outer outbound
    + inner SS detour outbound), so the feed must use this one.
    """
    if subscription_mod is None:
        return []
    try:
        inbound_dict = _inbound_dict(inbound)
        if inbound.protocol == "wireguard":
            stream = dict(inbound_dict.get("stream_json") or {})
            stream.setdefault(
                "peer_public_key",
                (settings.get("wireguard_public_key") or ""),
            )
            inbound_dict["stream_json"] = stream
        outbounds = subscription_mod.outbounds_for_client(
            inbound.protocol,
            _client_dict(client, user),
            inbound_dict,
            host,
            f"{user.name}-{inbound.tag}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("outbounds_for_client failed for %s", inbound.tag)
        return []
    return list(outbounds or [])


def _wireguard_conf_for(
    client: Any, inbound: Any, host: str, settings: dict[str, Any]
) -> Optional[str]:
    """Rendered WireGuard ``.conf`` for one client (None when unavailable)."""
    if wireguard_mod is None:
        return None
    try:
        client_dict = _client_dict(client, None)
        extra = client_dict.get("extra_json") or {}
        if not isinstance(extra, dict):
            extra = {}
        private_key = (client_dict.get("password") or "").strip()
        address = str(extra.get("allowed_ips") or "").strip()
        server_public = (settings.get("wireguard_public_key") or "").strip()
        if not private_key or not address or not server_public:
            return None
        # MTU / DNS come from the inbound's stream (editable since
        # the Phase 1 inbound editor); the first DNS server is the
        # one a WireGuard client config carries.
        stream = _inbound_dict(inbound).get("stream_json") or {}
        dns_servers = _stream_dns(stream, ("1.1.1.1",))
        return wireguard_mod.render_peer_config(
            private_key,
            address,
            server_public,
            host,
            server_port=int(inbound.port),
            dns=dns_servers[0] if dns_servers else "1.1.1.1",
            mtu=_stream_mtu(stream) or 1280,
        )
    except Exception:  # noqa: BLE001
        logger.exception("wireguard peer config failed for %s", inbound.tag)
        return None


def _ca_cert_pem() -> str:
    """PEM text of the panel CA ("" when it has not been generated yet)."""
    try:
        return Path(CA_CERT_PATH).read_text(encoding="utf-8")
    except OSError:
        return ""


def _openvpn_config_for(
    user: Any, client: Any, inbound: Any, host: str, settings: dict[str, Any]
) -> Optional[str]:
    """Rendered client ``.ovpn`` for one user (None when unavailable)."""
    if openvpn_mod is None:
        return None
    ca_pem = _ca_cert_pem()
    if not ca_pem:
        return None
    stream = _inbound_dict(inbound).get("stream_json") or {}
    return openvpn_mod.render_client_config(
        host=host,
        port=int(inbound.port),
        proto=_stream_transport(stream, "openvpn"),
        ca_cert_pem=ca_pem,
    )


def _openconnect_profile_for(
    user: Any, client: Any, inbound: Any, host: str, settings: dict[str, Any]
) -> Optional[str]:
    """Rendered AnyConnect profile XML for one user (None when unavailable)."""
    if openconnect_mod is None:
        return None
    return openconnect_mod.render_profile_xml(host=host, port=int(inbound.port))


def _amneziawg_conf_for(
    user: Any, client: Any, inbound: Any, host: str, settings: dict[str, Any]
) -> Optional[str]:
    """Rendered AmneziaWG client ``.conf`` for one user (None when unavailable)."""
    if amneziawg_mod is None:
        return None
    client_dict = _client_dict(client, user)
    extra = client_dict.get("extra_json") or {}
    if not isinstance(extra, dict):
        extra = {}
    private_key = (client_dict.get("password") or "").strip()
    address = str(extra.get("allowed_ips") or "").strip()
    server_public = (settings.get("amneziawg_public_key") or "").strip()
    if not private_key or not address or not server_public:
        return None
    stream = _inbound_dict(inbound).get("stream_json") or {}
    params = stream.get("awg_params") or {}
    if not isinstance(params, dict):
        params = {}
    dns_servers = _stream_dns(stream, ("1.1.1.1",))
    return amneziawg_mod.render_peer_config(
        private_key,
        address,
        server_public,
        host,
        server_port=int(inbound.port),
        params=params,
        dns=dns_servers[0] if dns_servers else "1.1.1.1",
        mtu=_stream_mtu(stream) or 1280,
    )


def _ikev2_mobileconfig_for(
    user: Any, client: Any, inbound: Any, host: str, settings: dict[str, Any]
) -> Optional[str]:
    """Rendered ``.mobileconfig`` profile for one user (None when unavailable)."""
    if ikev2_mod is None:
        return None
    client_dict = _client_dict(client, user)
    user_name = client_dict.get("user_name") or ""
    password = (client_dict.get("password") or "").strip()
    if not user_name or not password:
        return None
    server_id = _ikev2_server_id(settings)
    if not server_id:
        return None
    ca_der = ikev2_mod.load_ca_cert_der(CA_CERT_PATH)
    blob = ikev2_mod.render_mobileconfig(
        user_name=user_name,
        eap_password=password,
        server_host=host,
        server_id=server_id,
        ca_cert_der=ca_der,
    )
    return blob.decode("utf-8")


# Token-gated file exports: (filename, media type, builder) per protocol.
_FILE_EXPORTS: dict[str, tuple[str, str, Any]] = {
    "openvpn": (
        "openvpn.ovpn",
        "text/plain; charset=utf-8",
        _openvpn_config_for,
    ),
    "openconnect": (
        "openconnect.xml",
        "application/xml; charset=utf-8",
        _openconnect_profile_for,
    ),
    "amneziawg": (
        "amneziawg.conf",
        "text/plain; charset=utf-8",
        _amneziawg_conf_for,
    ),
    "ikev2": (
        "ikev2.mobileconfig",
        "application/octet-stream",
        _ikev2_mobileconfig_for,
    ),
}


def _user_file_export(
    db: Session, user: Any, protocol: str, host: str, settings: dict[str, Any]
) -> tuple[str, str, str] | None:
    """``(filename, media_type, content)`` for the user's first usable
    inbound of ``protocol`` — the file export for that protocol."""
    spec = _FILE_EXPORTS.get(protocol)
    if spec is None:
        return None
    filename, media_type, builder = spec
    for client, inbound in _usable_clients(db, user):
        if inbound.protocol != protocol:
            continue
        try:
            content = builder(user, client, inbound, host, settings)
        except Exception:  # noqa: BLE001
            logger.exception("file export failed for %s", inbound.tag)
            continue
        if content:
            return filename, media_type, content
    return None


def _user_file_response(
    request: Request, token: str, db: Session, protocol: str
) -> Response:
    """Token-gated file export (same 403 rules as the feeds)."""
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None or not _user_usable(db, user):
        logger.warning(
            "file export 403 for token %s (%s)", _token_fp(token), protocol
        )
        return Response(content=b"", status_code=403)
    settings = get_settings(db)
    host = _sub_host(request, settings)
    found = _user_file_export(db, user, protocol, host, settings)
    if found is None:
        return Response(content=b"", status_code=404)
    filename, media_type, content = found
    logger.info(
        "file export served: user=%s protocol=%s token=%s",
        user.name, protocol, _token_fp(token),
    )
    return Response(
        content=content.encode("utf-8"),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _file_export_urls(db: Session, user: Any, base: str) -> dict[str, str]:
    """File-export download URLs for the protocols the user has a
    usable inbound for (shown on the user pages)."""
    urls: dict[str, str] = {}
    protocols = {inbound.protocol for _, inbound in _usable_clients(db, user)}
    for protocol, (filename, _media, _builder) in _FILE_EXPORTS.items():
        if protocol in protocols:
            urls[protocol] = f"{base}/sub/{user.sub_token}/{filename}"
    return urls


def _build_zedsecure_bundle(
    db: Session, user: Any, host: str, settings: dict[str, Any]
) -> dict[str, Any]:
    """ZedSecure bundle: everything the app needs, in one document.

    Schema (``format: "zedsecure-bundle"``, ``version: 1``): user
    metadata (name / expiry / traffic), one ``configs`` entry per
    usable (client, inbound) — share link when one exists, the
    sing-box outbound object (``singbox_endpoint`` for WireGuard,
    which is an endpoint since sing-box 1.13), the WireGuard
    ``.conf`` text for WireGuard inbounds, and the file exports for
    the protocols that have no share-link / sing-box form: the
    OpenVPN ``.ovpn`` text (``openvpn_config``), the OpenConnect
    profile + credentials (``openconnect``), the AmneziaWG ``.conf``
    text (``amneziawg_conf`` — the ``vpn://`` link is the share
    link), and the IKEv2 ``.mobileconfig`` text
    (``ikev2_mobileconfig``) — plus the flat ``links`` list and the
    whole sing-box feed under ``singbox`` (including the ShadowTLS
    detour outbound and the WireGuard endpoint). Built only from
    the existing per-user builders; no protocol logic is duplicated
    here.
    """
    configs: list[dict[str, Any]] = []
    links: list[str] = []
    singbox_outbounds: list[dict[str, Any]] = []
    link_by_tag = {e["inbound"].tag: e["link"] for e in _links_for_user(db, user, host, settings)}
    for client, inbound in _usable_clients(db, user):
        entry: dict[str, Any] = {
            "tag": inbound.tag,
            "protocol": inbound.protocol,
            "core": inbound.core,
            "port": int(inbound.port),
            "remark": getattr(inbound, "remark", "") or "",
        }
        link = link_by_tag.get(inbound.tag)
        if link:
            entry["share_link"] = link
            links.append(link)
        outbounds = _singbox_outbounds_for(db, client, inbound, user, host, settings)
        if outbounds:
            primary = outbounds[0]
            if inbound.protocol == "wireguard":
                # A WireGuard object is an endpoint, not an outbound
                # (sing-box 1.13+): keep the bundle schema honest.
                entry["singbox_endpoint"] = primary
            else:
                entry["singbox_outbound"] = primary
            singbox_outbounds.extend(outbounds)
        if inbound.protocol == "wireguard":
            conf = _wireguard_conf_for(client, inbound, host, settings)
            if conf:
                entry["wireguard_conf"] = conf
        if inbound.protocol == "openvpn":
            conf = _openvpn_config_for(user, client, inbound, host, settings)
            if conf:
                entry["openvpn_config"] = conf
        if inbound.protocol == "openconnect":
            profile = _openconnect_profile_for(
                user, client, inbound, host, settings
            )
            if profile:
                entry["openconnect"] = {
                    "host": host,
                    "port": int(inbound.port),
                    "username": user.name,
                    "password": client.password or "",
                    "profile_xml": profile,
                }
        if inbound.protocol == "amneziawg":
            conf = _amneziawg_conf_for(user, client, inbound, host, settings)
            if conf:
                entry["amneziawg_conf"] = conf
        if inbound.protocol == "ikev2":
            mobileconfig = _ikev2_mobileconfig_for(
                user, client, inbound, host, settings
            )
            if mobileconfig:
                entry["ikev2_mobileconfig"] = mobileconfig
        configs.append(entry)
    feed = {"outbounds": singbox_outbounds}
    if subscription_mod is not None:
        try:
            feed = subscription_mod.build_singbox_feed(singbox_outbounds)
        except Exception:  # noqa: BLE001
            logger.exception("build_singbox_feed failed for bundle")
    return {
        "format": "zedsecure-bundle",
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": {
            "name": user.name,
            "expires_at": user.expires_at.isoformat() if user.expires_at else None,
            "traffic_used_bytes": user.traffic_used_bytes or 0,
            "traffic_limit_bytes": user.traffic_limit_bytes,
            "traffic_unlimited": user.traffic_limit_bytes is None,
        },
        "server": {"host": host},
        "configs": configs,
        "links": links,
        "singbox": feed,
    }


def _subscription_response(request: Request, token: str, db: Session) -> Response:
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None or not _user_usable(db, user):
        # Disabled / expired / over-quota / unknown: 403 with an EMPTY body.
        logger.warning("subscription 403 for token %s", _token_fp(token))
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

    headers: dict[str, str] = {}
    userinfo = _userinfo_header(user)
    if userinfo:
        headers["Subscription-Userinfo"] = userinfo
    logger.info(
        "subscription served: user=%s format=%s token=%s",
        user.name, chosen, _token_fp(token),
    )

    if chosen == "singbox":
        outbounds: list[dict[str, Any]] = []
        for client, inbound in _usable_clients(db, user):
            outbounds.extend(
                _singbox_outbounds_for(db, client, inbound, user, host, settings)
            )
        try:
            feed = subscription_mod.build_singbox_feed(outbounds)
        except Exception:  # noqa: BLE001
            logger.exception("build_singbox_feed failed")
            return Response(content=b"", status_code=500)
        return JSONResponse(content=feed, headers=headers)

    links = [entry["link"] for entry in _links_for_user(db, user, host, settings)]
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


@app.get("/sub/{token}/zedsecure.json")
def zedsecure_bundle(request: Request, token: str, db: Session = Depends(db_session)):
    """ZedSecure bundle: one JSON document with all of the user's
    configs (share links + sing-box outbounds + WireGuard ``.conf``),
    made for the ZedSecure app to import in one action. Same access
    rules as the other feeds: unknown / disabled / expired /
    over-quota user → 403 with an empty body. Rotating the token
    invalidates the old bundle URL."""
    user = db.query(User).filter(User.sub_token == token).first()
    if user is None or not _user_usable(db, user):
        logger.warning("zedsecure bundle 403 for token %s", _token_fp(token))
        return Response(content=b"", status_code=403)
    settings = get_settings(db)
    host = _sub_host(request, settings)
    bundle = _build_zedsecure_bundle(db, user, host, settings)
    logger.info(
        "zedsecure bundle served: user=%s configs=%d token=%s",
        user.name, len(bundle.get("configs", [])), _token_fp(token),
    )
    headers: dict[str, str] = {}
    userinfo = _userinfo_header(user)
    if userinfo:
        headers["Subscription-Userinfo"] = userinfo
    return JSONResponse(content=bundle, headers=headers)


@app.get("/sub/{token}/openvpn.ovpn")
def subscription_openvpn(
    request: Request, token: str, db: Session = Depends(db_session)
):
    """Token-gated ``.ovpn`` download for the user's OpenVPN inbound."""
    return _user_file_response(request, token, db, "openvpn")


@app.get("/sub/{token}/openconnect.xml")
def subscription_openconnect(
    request: Request, token: str, db: Session = Depends(db_session)
):
    """Token-gated AnyConnect profile download for the user's
    OpenConnect inbound."""
    return _user_file_response(request, token, db, "openconnect")


@app.get("/sub/{token}/amneziawg.conf")
def subscription_amneziawg(
    request: Request, token: str, db: Session = Depends(db_session)
):
    """Token-gated ``.conf`` download for the user's AmneziaWG inbound."""
    return _user_file_response(request, token, db, "amneziawg")


@app.get("/sub/{token}/ikev2.mobileconfig")
def subscription_ikev2(
    request: Request, token: str, db: Session = Depends(db_session)
):
    """Token-gated ``.mobileconfig`` download for the user's IKEv2
    inbound."""
    return _user_file_response(request, token, db, "ikev2")


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
    core: str = Field(
        ...,
        pattern=r"^(xray|singbox|wireguard|openvpn|openconnect|amneziawg|ikev2)$",
    )
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
    csrf: None = Depends(require_csrf_api),
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


# ---------------------------------------------------------------------------
# Secret web path (v9): mount the panel under /<random-path>, like 3X-UI's
# webBasePath. With a path set, the panel only answers under it — the root
# (/login, /dashboard, /health, ...) returns 404. The root app carries
# the same lifespan: a mounted sub-app's lifespan does NOT run (verified
# with a stub app), so startup (init_db, admin seeding, background
# loops) must live here, or the panel would boot with no admin user.
# ---------------------------------------------------------------------------


def _mount_web_path(panel_app: FastAPI, web_path: str) -> FastAPI:
    """Return ``panel_app`` mounted under ``web_path`` ("" = root, unchanged)."""
    if not web_path:
        return panel_app
    root = FastAPI(title="sparky-manager", lifespan=lifespan)
    root.mount(web_path, panel_app)
    return root


app = _mount_web_path(app, WEB_PATH)
