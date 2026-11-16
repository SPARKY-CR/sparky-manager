"""Telegram management bot (Phase 4) — the whole panel from Telegram.

The bot lives inside the FastAPI app (no second service): Telegram
delivers updates to ``POST /telegram/webhook/<secret>`` (see
``app.main.telegram_webhook``), which hands them to :func:`handle_update`.

Architecture
------------
- :func:`handle_update` is the only entry point. It never raises: a
  bad update is logged and dropped, never turned into a 500 (Telegram
  retries non-2xx responses, so a crashing handler would loop).
- The dispatcher talks to the panel through ``app.main`` (lazy import
  inside :func:`handle_update` — ``app.main`` imports this module for
  the webhook route, so a top-level import would be circular). All
  state changes reuse the web routes' exact semantics: same audit
  actions, same ``rerender_configs`` call, same validation rules.
- Replies go through a small sender object (``send`` / ``edit`` /
  ``answer``). Production uses :class:`TelegramSender` (Bot API);
  tests inject a fake that records calls — no real network in tests.
- The bot speaks Persian (``BOT_LANGUAGE``): there is no per-admin
  language setting to follow, and the admin is Persian-speaking. Every
  bot string still has an EN key (see ``BOT_STRING_KEYS``) so a future
  language setting can switch the bot without touching the code.

Security
--------
- Only the configured admin chat ID (``telegram_chat_id`` setting) may
  use the bot. Updates from any other chat are ignored silently — no
  reply, no error, nothing that confirms the bot exists.
- No tokens are ever sent in chat, and update payloads are never
  logged. Client passwords ARE shown to the admin (per-client view
  and Links view, OpenVPN/OpenConnect only) — the bot serves only
  the configured admin chat, so this is the same trust boundary as
  the admin panel, which shows the same passwords; the user asked
  for the credentials to be visible because the client app prompts
  for them (OpenVPN's ``.ovpn`` embeds them; OpenConnect's profile
  cannot — see DESIGN.md §15.8).
- Duplicate ``update_id`` values are ignored (Telegram redelivers).

State (in-memory only — no DB schema change)
--------------------------------------------
- ``_conversations``: per-chat guided-flow state (the create-user
  flow), with a 10-minute timeout. ``/cancel`` aborts it; any other
  command or menu tap abandons it.
- ``_seen_updates``: processed update ids, pruned after an hour.

Callback data is ``family:action:args`` (``m:`` menu, ``u:`` user,
``i:`` inbound, ``c:`` create flow, ``s:`` services, ``b:`` backup)
— short on purpose, well under Telegram's 64-byte callback-data
limit.

Professional upgrade (Phase 3) adds: the ``/menu`` / ``/status`` /
``/users`` / ``/inbounds`` commands (registered on Telegram via
``setMyCommands`` — see :data:`BOT_COMMANDS`), user search + guided
user edit, a guided inbound-create flow + inbound delete, service
restart, backup delivery as a document, and a friendly answer for
stale/invalid callbacks instead of silence.

Bot polish adds: HTML formatting (bold titles, bold field labels —
all bot messages go out with ``parse_mode="HTML"`` and every
user-controlled value is escaped with :func:`h` first, because
Telegram rejects malformed HTML), a persistent reply keyboard
(``/start`` and ``/menu`` install it; taps arrive as plain text and
:func:`_on_text` matches the exact labels), and two-column inline
keyboards where they fit. Handlers, flows, callback data and command
behavior are unchanged — presentation only.

Menu + bot UX polish adds: inbound creation for every protocol the
web panel supports (``BOT_CREATE_PROTOCOLS``), and Skip/Back buttons
on every guided flow — an empty message cannot be sent on Telegram,
so every optional step has a visible Skip button that submits the
default, and every multi-step flow has a Back button (both are
``c:`` callbacks, handled step-by-step in
:func:`_on_create_callback`). No prompt says "leave empty" anymore.

Bot client parity adds: per-client management in the bot (the
clients list, add-to-inbound, detach, per-client move, per-client
freeze, XTLS flow edit — the web user page's operations, with the
web's validation, reusing the web helpers from
``app.routes.users``), native config files sent as documents from
the Links view (OpenVPN/OpenConnect/AmneziaWG/IKEv2 have no share
link), and the OpenVPN/OpenConnect username/password shown in the
per-client view and the Links view.
"""

from __future__ import annotations

import html
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from app import telegram as telegram_mod
from app import links as links_mod
from app.models import Admin, Client, Inbound, TrafficDaily, User, client_is_frozen
from app.routes.users import (
    _addable_inbounds,
    _apply_client_move,
    _client_flow_options,
    _move_targets,
)

logger = logging.getLogger("sparky-manager")

try:
    from app import system_status as system_status_mod
except ImportError:  # pragma: no cover - sibling module missing
    system_status_mod = None
    logger.warning("app.system_status not available; bot status is traffic-only")

# The bot speaks Persian: there is no per-admin language setting to
# follow (the panel language lives in a request cookie), and the
# admin is Persian-speaking. EN keys exist for every bot string.
BOT_LANGUAGE = "fa"

# The command menu registered on Telegram via setMyCommands (see
# app.main.register_telegram_commands + save_settings). Descriptions
# are Persian — the bot is Persian-first. Every command here is
# implemented in _on_command; never add one without implementing it.
BOT_COMMANDS = (
    {"command": "start", "description": "منوی اصلی"},
    {"command": "help", "description": "راهنما"},
    {"command": "menu", "description": "منوی اصلی"},
    {"command": "status", "description": "وضعیت سرور و ترافیک"},
    {"command": "users", "description": "فهرست کاربران"},
    {"command": "inbounds", "description": "فهرست اینباندها"},
    {"command": "cancel", "description": "لغو عملیات در حال انجام"},
)

# Protocols the bot's guided inbound-create flow offers — every
# protocol the web panel supports, each created with the web create
# route's defaults (subnets, AWG params, preferred ports), so the
# two paths can never disagree. Core is derived from the protocol:
# hysteria2 is Xray (the default owner per the ``hysteria2_core``
# setting — the admin can move it to sing-box from the panel).
BOT_CREATE_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria2",
    "tuic",
    "anytls",
    "naive",
    "shadowtls",
    "wireguard",
    "amneziawg",
    "openvpn",
    "openconnect",
    "ikev2",
)
BOT_PROTOCOL_CORES = {
    "vless": "xray",
    "vmess": "xray",
    "trojan": "xray",
    "shadowsocks": "xray",
    "hysteria2": "xray",
    "tuic": "singbox",
    "anytls": "singbox",
    "naive": "singbox",
    "shadowtls": "singbox",
    "wireguard": "wireguard",
    "amneziawg": "amneziawg",
    "openvpn": "openvpn",
    "openconnect": "openconnect",
    "ikev2": "ikev2",
}
# Protocols where an SNI prompt is meaningful (TLS / Reality — the
# SNI becomes the TLS server name, or the ShadowTLS handshake
# target). The native cores use certificates/keys, not SNI, and
# Shadowsocks has no TLS at all.
BOT_SNI_PROTOCOLS = (
    "vless",
    "vmess",
    "trojan",
    "hysteria2",
    "tuic",
    "anytls",
    "naive",
    "shadowtls",
)

# Service key -> display name (shared by the status view and the
# services view) and key -> systemd unit the panel may restart.
# Every core is restartable: the installer's sudoers block (v15)
# grants `systemctl restart` for all 7 units, including AmneziaWG
# (before v15 only `start` was granted for awg-quick@awg0, so the
# bot offered no AWG restart button). The panel itself
# (sparky-manager) is still absent: restarting the panel from inside
# the bot would kill the process before it could report the result.
_SERVICE_NAMES = {
    "xray": "Xray",
    "sing-box": "sing-box",
    "wireguard": "WireGuard",
    "amneziawg": "AmneziaWG",
    "openvpn": "OpenVPN",
    "openconnect": "OpenConnect",
    "ikev2": "IKEv2",
}
_SERVICE_RESTART_UNITS = {
    "xray": "xray",
    "sing-box": "sing-box",
    "wireguard": "wg-quick@wg0",
    "amneziawg": "awg-quick@awg0",
    "openvpn": "openvpn-server@sparky-manager",
    "openconnect": "ocserv",
    "ikev2": "strongswan",
}

# Guided-flow state expires after 10 minutes of inactivity.
CONVERSATION_TIMEOUT = 600.0
# Processed update ids are remembered for an hour (Telegram redelivery
# windows are seconds, not hours; the cap bounds memory either way).
SEEN_UPDATE_TTL = 3600.0
MAX_SEEN_UPDATES = 5000
USERS_PAGE_SIZE = 8
# Same page size for the inbound list (paginated in the debug pass —
# an unpaginated list could exceed Telegram's 4096-char cap).
INBOUNDS_PAGE_SIZE = 8
# Bot API messages cap at 4096 chars; chunk long texts below that.
MESSAGE_CHUNK = 4000
# Protocols whose auth is a username/password pair the admin may
# need to see (and type once, where the config file cannot carry
# it): OpenVPN (the .ovpn embeds it) and OpenConnect (the AnyConnect
# profile cannot — see DESIGN.md §15.8). IKEv2 embeds its EAP
# password in the .mobileconfig, so it needs no display.
_CREDENTIAL_PROTOCOLS = ("openvpn", "openconnect")
# Native protocols with a file export (no share link) — the bot
# sends these as documents from the Links view, in this order.
_NATIVE_FILE_PROTOCOLS = ("openvpn", "openconnect", "amneziawg", "ikev2")

# Every STRINGS key this module reads — the test suite asserts each one
# exists in both the fa and the en dict (a missing key would KeyError
# mid-dispatch, so the list is the contract, not a comment).
BOT_STRING_KEYS = (
    # Panel keys reused by the bot (already in STRINGS).
    "status",
    "enabled",
    "disabled",
    "protocol",
    "port",
    "core",
    "remark",
    "clients",
    "cpu_load",
    "memory",
    "disk",
    "uptime",
    # Bot-only keys (fa + en, added with Phase 4).
    "bot_welcome",
    "bot_help",
    "bot_menu_users",
    "bot_menu_inbounds",
    "bot_menu_status",
    "bot_menu_help",
    "bot_back_main",
    "bot_back_users",
    "bot_back_inbounds",
    "bot_back",
    "bot_cancel",
    "bot_cancelled",
    "bot_users_title",
    "bot_no_users",
    "bot_prev",
    "bot_next",
    "bot_new_user",
    "bot_user_not_found",
    "bot_inbound_not_found",
    "bot_status_enabled",
    "bot_status_disabled",
    "bot_status_expired",
    "bot_status_over_quota",
    "bot_status_frozen",
    "bot_traffic",
    "bot_expires",
    "bot_never",
    "bot_unlimited",
    "bot_inbounds",
    "bot_days_left",
    "bot_links",
    "bot_links_title",
    "bot_sub_link",
    "bot_no_links",
    "bot_no_host",
    "bot_freeze",
    "bot_unfreeze",
    "bot_frozen",
    "bot_unfrozen",
    "bot_extend",
    "bot_extend_prompt",
    "bot_extend_days",
    "bot_extended",
    "bot_reset_traffic",
    "bot_reset_confirm",
    "bot_traffic_reset",
    "bot_delete",
    "bot_delete_confirm",
    "bot_deleted",
    "bot_confirm_yes",
    "bot_confirm_no",
    "bot_create_name",
    "bot_create_name_invalid",
    "bot_create_name_exists",
    "bot_create_pick_inbounds",
    "bot_create_no_inbounds",
    "bot_create_pick_one",
    "bot_create_limit",
    "bot_create_limit_invalid",
    "bot_create_expiry",
    "bot_create_expiry_invalid",
    "bot_create_done",
    "bot_create_failed",
    "bot_create_confirm",
    "bot_use_buttons",
    "bot_flow_expired",
    "bot_inbounds_title",
    "bot_no_inbounds",
    "bot_enable",
    "bot_disable",
    "bot_inbound_toggled",
    "bot_status_title",
    "bot_status_users",
    "bot_traffic_today",
    "bot_traffic_14d",
    "bot_unknown_command",
    "bot_rerender_failed",
    "bot_action_failed",
    "bot_view_user",
    # Upgrade Phase 3: search, edit, inbound create/delete,
    # services, backup, stale callbacks.
    "bot_menu_services",
    "bot_menu_backup",
    "bot_search",
    "bot_search_prompt",
    "bot_search_title",
    "bot_search_no_match",
    "bot_edit",
    "bot_edit_pick",
    "bot_edit_name",
    "bot_edit_limit",
    "bot_edit_expiry",
    "bot_edit_name_prompt",
    "bot_edit_limit_prompt",
    "bot_edit_expiry_prompt",
    "bot_edited",
    "bot_new_inbound",
    "bot_create_inbound_protocol",
    "bot_create_inbound_port",
    "bot_create_inbound_port_invalid",
    "bot_create_inbound_port_in_use",
    "bot_create_inbound_port_reserved",
    "bot_create_inbound_sni",
    "bot_create_inbound_done",
    "bot_create_inbound_failed",
    "bot_inbound_delete_confirm",
    "bot_inbound_deleted",
    "bot_services_title",
    "bot_service_running",
    "bot_service_stopped",
    "bot_service_unknown",
    "bot_service_restart",
    "bot_service_restart_confirm",
    "bot_service_restarted",
    "bot_service_restart_failed",
    "bot_service_restart_unverified",
    "bot_failure_log_attached",
    "bot_failure_log_truncated",
    "bot_backup_title",
    "bot_backup_hint",
    "bot_backup_send",
    "bot_backup_sent",
    "bot_backup_failed",
    "bot_backup_too_large",
    "bot_stale_callback",
    # Bot polish: persistent reply keyboard.
    "bot_reply_menu",
    "bot_reply_keyboard_hint",
    # Menu + bot UX polish: skip buttons for optional steps (an
    # empty message cannot be sent on Telegram) and clear-search.
    "bot_skip_unlimited",
    "bot_skip_never",
    "bot_skip_auto",
    "bot_skip_default",
    "bot_clear_search",
    # Bot client parity: per-client management, native files,
    # credentials display (plus the panel keys the bot newly reads).
    "username",
    "password",
    "flow",
    "add_to_inbound",
    "detach",
    "add_inbound_address_exhausted",
    "bot_clients_title",
    "bot_no_clients",
    "bot_client_not_found",
    "bot_add_inbound_pick",
    "bot_add_inbound_none",
    "bot_add_inbound_done",
    "bot_detach_confirm",
    "bot_detach_last_confirm",
    "bot_detached",
    "bot_move",
    "bot_move_pick",
    "bot_move_none",
    "bot_move_done",
    "bot_move_address_exhausted",
    "bot_client_frozen",
    "bot_client_unfrozen",
    "bot_edit_flow",
    "bot_flow_pick",
    "bot_flow_none",
    "bot_flow_set",
    "bot_flow_cleared",
    "bot_native_files",
    "bot_file_send_failed",
    "bot_credentials",
)

# ---------------------------------------------------------------------------
# In-memory state (see module docstring — nothing here touches the DB)
# ---------------------------------------------------------------------------

# {chat_id: {"step": str, "data": dict, "expires": float(monotonic)}}
_conversations: dict[int, dict[str, Any]] = {}
# {update_id: float(monotonic) when seen}
_seen_updates: dict[int, float] = {}


def _update_seen(update_id: int) -> bool:
    """True when this update was already processed (Telegram redelivery)."""
    now = time.monotonic()
    if update_id in _seen_updates:
        return True
    if len(_seen_updates) >= MAX_SEEN_UPDATES:
        _seen_updates.clear()
    cutoff = now - SEEN_UPDATE_TTL
    for seen_id in [u for u, ts in _seen_updates.items() if ts < cutoff]:
        del _seen_updates[seen_id]
    _seen_updates[update_id] = now
    return False


def _get_conversation(chat_id: int) -> Optional[dict[str, Any]]:
    """The chat's live conversation, or None (expired flows are dropped)."""
    conv = _conversations.get(chat_id)
    if conv is None:
        return None
    if time.monotonic() > conv["expires"]:
        del _conversations[chat_id]
        return None
    return conv


def _start_conversation(chat_id: int, step: str, data: Optional[dict] = None) -> None:
    _conversations[chat_id] = {
        "step": step,
        "data": data or {},
        "expires": time.monotonic() + CONVERSATION_TIMEOUT,
    }


def _end_conversation(chat_id: int) -> None:
    _conversations.pop(chat_id, None)


# ---------------------------------------------------------------------------
# Sender (Bot API) + dispatch context
# ---------------------------------------------------------------------------


class TelegramSender:
    """Bot API sender bound to one bot token (built by the webhook route).

    These methods are the whole surface the dispatcher needs; tests
    inject a fake with the same methods. ``send`` returns False (never
    raises) when Telegram is unreachable — the dispatcher treats a
    failed reply as "the admin did not see it" and moves on.

    All bot messages go out with ``parse_mode="HTML"`` (bold titles,
    structured layout) — so every user-controlled value in a message
    is escaped with :func:`h` first: Telegram rejects a message whose
    HTML is malformed, and one stray ``<`` would fail the whole reply.
    """

    def __init__(self, token: str):
        self.token = token

    def send(
        self, chat_id: int, text: str, reply_markup: Optional[dict] = None
    ) -> bool:
        return telegram_mod.send_message(
            self.token,
            str(chat_id),
            text,
            reply_markup=reply_markup,
            parse_mode="HTML",
        )

    def send_id(
        self, chat_id: int, text: str, reply_markup: Optional[dict] = None
    ) -> Optional[int]:
        """Send like :meth:`send` but return the message id (None on
        failure) — for messages the bot deletes right after sending."""
        return telegram_mod.send_message_id(
            self.token,
            str(chat_id),
            text,
            reply_markup=reply_markup,
            parse_mode="HTML",
        )

    def delete(self, chat_id: int, message_id: int) -> bool:
        """Delete a message the bot sent. False on failure (the
        message may already be gone) — never raises."""
        return telegram_mod.delete_message(self.token, str(chat_id), message_id)

    def edit(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: Optional[dict] = None,
    ) -> bool:
        return telegram_mod.edit_message_text(
            self.token,
            str(chat_id),
            message_id,
            text,
            reply_markup=reply_markup,
            parse_mode="HTML",
        )

    def answer(self, callback_query_id: str, text: Optional[str] = None) -> bool:
        return telegram_mod.answer_callback_query(
            self.token, callback_query_id, text=text
        )

    def document(self, chat_id: int, filename: str, data: bytes) -> bool:
        """Send a file as a document (backup delivery)."""
        return telegram_mod.send_document(
            self.token, str(chat_id), filename, data
        )


@dataclass
class _Ctx:
    """Everything a handler needs for one update."""

    db: Any
    panel: Any  # the app.main module (lazy import, see handle_update)
    sender: Any  # TelegramSender or a test fake
    t: dict[str, str]  # translation strings (Persian)
    chat_id: int
    now: datetime


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _kb(rows: list[list[tuple[str, str]]]) -> dict[str, Any]:
    """Inline keyboard from ``[[(text, callback_data), ...], ...]``."""
    return {
        "inline_keyboard": [
            [{"text": text, "callback_data": data} for text, data in row]
            for row in rows
        ]
    }


def _url_row(text: str, url: str) -> list[dict[str, str]]:
    """One inline-keyboard row holding a single URL button.

    Telegram opens the URL when the button is tapped (no callback
    reaches the bot) — used for the ZedSecure deep link, which must
    open the app, not answer in this chat.
    """
    return [{"text": text, "url": url}]


def _main_menu_kb(t: dict[str, str]) -> dict[str, Any]:
    return _kb(
        [
            [(t["bot_menu_users"], "m:users"), (t["bot_menu_inbounds"], "m:inb")],
            [(t["bot_menu_status"], "m:status"), (t["bot_menu_help"], "m:help")],
            [
                (t["bot_menu_services"], "m:svc"),
                (t["bot_menu_backup"], "m:bkp"),
            ],
        ]
    )


def _main_reply_kb(t: dict[str, str]) -> dict[str, Any]:
    """Persistent reply keyboard: the main actions, one tap away.

    Unlike the inline menu it stays in the chat until replaced, so
    the admin never has to scroll back to a menu message. Taps arrive
    as plain-text messages — :func:`_on_text` matches these exact
    labels. Sent with ``/start`` and ``/menu`` (the inline menu
    stays the detailed menu for the flows).
    """
    return {
        "keyboard": [
            [
                {"text": t["bot_menu_users"]},
                {"text": t["bot_menu_inbounds"]},
            ],
            [
                {"text": t["bot_menu_status"]},
                {"text": t["bot_reply_menu"]},
            ],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


def _install_reply_keyboard(ctx: _Ctx) -> None:
    """(Re-)install the persistent reply keyboard, invisibly.

    One message can only carry one reply markup, so the keyboard
    rides along as a second, short message — which is then deleted
    immediately: the reply keyboard persists client-side after its
    message is deleted, so the chat shows no "🎛️ منوی سریع:" hint
    text while the buttons stay one tap away. A failed send (no
    message id) or a failed delete is not fatal — the worst case is
    the hint message staying visible, exactly like before this fix.
    Never raises.
    """
    try:
        message_id = ctx.sender.send_id(
            ctx.chat_id,
            ctx.t["bot_reply_keyboard_hint"],
            reply_markup=_main_reply_kb(ctx.t),
        )
    except Exception:  # noqa: BLE001 — a failed install must not break /start
        logger.exception("telegram reply keyboard install failed")
        return
    if message_id is None:
        return
    try:
        ctx.sender.delete(ctx.chat_id, message_id)
    except Exception:  # noqa: BLE001 — delete failure leaves the hint visible
        logger.exception("telegram reply keyboard hint delete failed")


def _flow_kb(
    t: dict[str, str], skip_key: Optional[str] = None, back: bool = True
) -> dict[str, Any]:
    """Keyboard for a guided-flow text step.

    ``skip_key`` is the i18n key of the Skip button (``bot_skip_*``)
    for an OPTIONAL step — the only way to submit the default value,
    because Telegram cannot send an empty message (a prompt saying
    "leave empty" is a dead end). ``back`` adds the Back button
    (``c:back`` — step-driven, see :func:`_on_create_callback`).
    Cancel is always present. A required first step passes neither
    and gets Cancel only.
    """
    row: list[tuple[str, str]] = []
    if skip_key is not None:
        row.append((t[skip_key], "c:skip"))
    if back:
        row.append((t["bot_back"], "c:back"))
    rows = [row] if row else []
    rows.append([(t["bot_cancel"], "c:cancel")])
    return _kb(rows)


def h(value: Any) -> str:
    """Escape a user-controlled value for Telegram's HTML parse mode.

    Telegram rejects a message whose HTML is malformed, so every
    value the admin or the system supplied — user names, notes,
    inbound tags and remarks, SNI, share links (full of ``&``), error
    text — goes through here before it is embedded in a message.
    Trusted i18n strings do NOT go through this: they carry the
    ``<b>`` tags themselves (see :func:`_b`). Quotes are left alone —
    they are harmless in HTML text content.
    """
    return html.escape(str(value), quote=False)


def _b(text: str) -> str:
    """Bold a trusted string (i18n text, fixed labels) — never pass
    user input here; escape it with :func:`h` first."""
    return f"<b>{text}</b>"


def _titled(text: str) -> str:
    """Bold the header line of a two-part message (``header\\n\\nbody``).

    Whole-message i18n strings (welcome, help, prompts) keep their
    plain text in the string table; the bold header is added here so
    the strings stay readable and reusable. A message without a
    blank-line-separated header is returned unchanged.
    """
    head, sep, rest = text.partition("\n\n")
    if not sep:
        return text
    return f"<b>{head}</b>{sep}{rest}"


def _format_bytes(n: int) -> str:
    """Short human size (``"1.5 GB"``, ``"850 MB"``) — same rule as
    ``app.charts`` so the bot and the web UI agree."""
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # unreachable; keeps type checkers calm


def _aware(value: datetime) -> datetime:
    """SQLite stores datetimes without tzinfo; treat a naive value read
    back from the DB as UTC so comparisons never raise."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _parse_int(raw: Any) -> Optional[int]:
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return None


def _parse_limit_gb(raw: str) -> Optional[int]:
    """GB text -> traffic-limit bytes, or None for unlimited.

    Empty / 0 means unlimited (same as the web form's empty limit).
    Raises ValueError for anything else that is not a positive
    number. Shared by the create flow and the edit flow so the two
    can never disagree.
    """
    raw = raw.strip().replace(",", ".")
    if raw in ("", "0", "0.0"):
        return None
    gb = float(raw)
    if gb <= 0:
        raise ValueError
    return int(gb * 1024**3)


def _parse_expiry_days(raw: str, now: datetime) -> Optional[datetime]:
    """Days text -> expiry datetime, or None for never.

    Empty / 0 means no expiry (same as the web form's empty date).
    Raises ValueError for anything else that is not a positive
    integer. Shared by the create flow and the edit flow.
    """
    raw = raw.strip()
    if raw in ("", "0"):
        return None
    days = int(raw)
    if days <= 0:
        raise ValueError
    return now + timedelta(days=days)


def _split_text(text: str, limit: Optional[int] = None) -> list[str]:
    """Split a long message into ``<= limit`` chunks on line boundaries
    (links are one per line, so a split never breaks a link). A single
    line longer than the limit goes in a chunk of its own — the sender
    truncates at the Bot API limit, so nothing is ever lost silently.
    ``limit`` defaults to ``MESSAGE_CHUNK`` (resolved here, not as a
    default argument, so tests can shrink it)."""
    limit = limit or MESSAGE_CHUNK
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        if current and len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = ""
        current += line + "\n"
    if current.strip():
        chunks.append(current.rstrip("\n"))
    return chunks or [""]


def _audit(ctx: _Ctx, action: str, detail: str = "") -> None:
    """Audit a bot action exactly like the web equivalent: same action
    name, same detail shape, plus a ``[telegram]`` marker so the
    channel is visible in the log. The admin id is the panel's (single)
    admin row — the bot authenticates by chat ID, not by session."""
    admin_id = None
    try:
        admin = ctx.db.query(Admin).order_by(Admin.id).first()
        admin_id = admin.id if admin is not None else None
    except Exception:  # noqa: BLE001 — audit must never break the action
        admin_id = None
    ctx.panel._audit(ctx.db, admin_id, action, detail)


def _rerender(ctx: _Ctx) -> list[str]:
    """Re-render configs like the web routes do; returns error strings."""
    try:
        return list(ctx.panel.rerender_configs(ctx.db) or [])
    except Exception:  # noqa: BLE001 — rerender_configs is best-effort
        logger.exception("telegram bot re-render failed")
        return [ctx.t["bot_action_failed"]]


# Failure logs in the bot: the full journal tail is copyable — inline
# in a <pre> block when it fits, as a .log file when it does not. The
# budget is well under Telegram's 4096-char cap because the note is
# appended to a view message (users / inbounds / services list) that
# takes space of its own.
_FAILURE_LOG_INLINE_BUDGET = 1500
# Lines of the log shown in the note when the full log goes to a file.
_FAILURE_LOG_PREVIEW_LINES = 5

# systemctl's `See "systemctl status ..." and "journalctl -xeu ..."`
# hint is not actionable from Telegram (the admin cannot run
# systemctl from a chat) — strip it from bot-facing error text,
# line by line, whatever unit it names.
_SYSTEMD_HINT_RE = re.compile(r'^\s*See "systemctl status .*$', re.MULTILINE)


def _strip_systemd_hint(text: str) -> str:
    """Drop systemctl's "See systemctl status ... / journalctl ..."
    boilerplate lines; keep the real error + the journal."""
    cleaned = _SYSTEMD_HINT_RE.sub("", text or "")
    return "\n".join(
        line for line in cleaned.splitlines() if line.strip()
    ).strip()


def _failure_note(ctx: _Ctx, title: str, error_text: str, filename: str) -> str:
    """A copyable failure note for the admin.

    The cleaned error goes in a ``<pre>`` block (copyable with a
    long press) when it fits the inline budget. When it does not,
    the FULL log is sent as a ``.log`` file and the note shows only
    the first lines (cut at a line boundary, never mid-line) plus a
    marker pointing at the file. When the file send fails, the note
    falls back to the same line-boundary preview with a "truncated"
    marker — a mid-line cut inside a ``<pre>`` block is never
    produced.
    """
    cleaned = _strip_systemd_hint(error_text)
    if not cleaned:
        return title
    if len(cleaned) <= _FAILURE_LOG_INLINE_BUDGET:
        return f"{title}\n<pre>{h(cleaned)}</pre>"
    document = getattr(ctx.sender, "document", None)
    sent = False
    if callable(document):
        try:
            sent = bool(document(ctx.chat_id, filename, cleaned.encode("utf-8")))
        except Exception:  # noqa: BLE001 — the file must not break the note
            logger.exception("telegram bot failure-log file send failed")
            sent = False
    preview = "\n".join(cleaned.splitlines()[:_FAILURE_LOG_PREVIEW_LINES])
    marker = (
        ctx.t["bot_failure_log_attached"]
        if sent
        else ctx.t["bot_failure_log_truncated"]
    )
    return f"{title}\n<pre>{h(preview)}</pre>\n{marker}"


def _rerender_note(ctx: _Ctx, errors: list[str]) -> Optional[str]:
    """Warning appended to a reply when re-rendering failed.

    The error text comes from the system (config validators, shell
    output) and can contain anything, so it is HTML-escaped — one
    stray ``<`` would fail the whole reply. Long errors go to a file
    (see :func:`_failure_note`); the note itself never cuts mid-line.
    """
    if not errors:
        return None
    return "⚠️ " + _failure_note(
        ctx, ctx.t["bot_rerender_failed"], "\n".join(errors), "rerender-error.log"
    )


def _show(ctx: _Ctx, message_id: Optional[int], text: str, keyboard: Any = None) -> None:
    """Update the menu message in place; send a new one when the edit
    fails (message too old, deleted, or identical text)."""
    if message_id:
        if ctx.sender.edit(ctx.chat_id, message_id, text, reply_markup=keyboard):
            return
    ctx.sender.send(ctx.chat_id, text, reply_markup=keyboard)


def _send_long(ctx: _Ctx, message_id: Optional[int], text: str, keyboard: Any = None) -> None:
    """Send a long text (links): the first chunk edits the menu message,
    the rest arrive as follow-up messages."""
    chunks = _split_text(text)
    _show(ctx, message_id, chunks[0], keyboard)
    for chunk in chunks[1:]:
        ctx.sender.send(ctx.chat_id, chunk)


def _set_frozen(client: Any, frozen: bool) -> None:
    """Freeze/unfreeze one client (``extra.frozen``) — same rule as
    ``app.main._set_client_frozen``: freeze sets the key, unfreeze
    removes it, other extra keys (e.g. ``allowed_ips``) are kept."""
    extra = dict(getattr(client, "extra", None) or {})
    if frozen:
        extra["frozen"] = True
    else:
        extra.pop("frozen", None)
    client.extra = extra


def _user_frozen(ctx: _Ctx, user: Any) -> bool:
    """True when the user has clients and all of them are frozen."""
    clients = ctx.db.query(Client).filter(Client.user_id == user.id).all()
    return bool(clients) and all(client_is_frozen(c) for c in clients)


def _user_state(ctx: _Ctx, user: Any) -> tuple[str, str]:
    """``(emoji, status label)`` for one user."""
    t = ctx.t
    if not user.enabled:
        return "❌", t["bot_status_disabled"]
    if user.expires_at is not None and _aware(user.expires_at) <= ctx.now:
        return "⏰", t["bot_status_expired"]
    if (
        user.traffic_limit_bytes is not None
        and (user.traffic_used_bytes or 0) >= user.traffic_limit_bytes
    ):
        return "📊", t["bot_status_over_quota"]
    if _user_frozen(ctx, user):
        return "🧊", t["bot_status_frozen"]
    return "✅", t["bot_status_enabled"]


def _expiry_text(ctx: _Ctx, user: Any) -> str:
    """``"2026-12-01 (12 روز مانده)"`` / ``"هرگز"`` / ``"منقضی‌شده"``."""
    t = ctx.t
    if user.expires_at is None:
        return t["bot_never"]
    expires = _aware(user.expires_at)
    if expires <= ctx.now:
        return f"{expires.strftime('%Y-%m-%d')} ({t['bot_status_expired']})"
    days = (expires - ctx.now).days
    return f"{expires.strftime('%Y-%m-%d')} ({t['bot_days_left'].format(days=days)})"


def _traffic_summary(ctx: _Ctx) -> tuple[int, int]:
    """``(today_bytes, last_14_days_bytes)`` from ``traffic_daily``."""
    today = date.today()
    first = today - timedelta(days=13)
    today_total = 0
    total_14d = 0
    for row in ctx.db.query(TrafficDaily).all():
        total = (row.up_bytes or 0) + (row.down_bytes or 0)
        if row.date == today:
            today_total += total
        if row.date >= first:
            total_14d += total
    return today_total, total_14d


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle_update(db: Any, update: Any, sender: Any, *, now: Any = None) -> None:
    """Dispatch one Telegram update. Never raises (see module docstring)."""
    try:
        _dispatch(db, update, sender, now=now)
    except Exception:  # noqa: BLE001 — a bad update must never break the webhook
        logger.exception("telegram bot dispatch failed")


def _dispatch(db: Any, update: Any, sender: Any, *, now: Any = None) -> None:
    if not isinstance(update, dict):
        return
    update_id = update.get("update_id")
    if isinstance(update_id, int) and _update_seen(update_id):
        return
    # Lazy import: app.main imports this module for the webhook route,
    # so importing it here (at dispatch time, never at module import)
    # avoids a circular import.
    from app import main as panel

    settings = panel.get_settings(db)
    token = (settings.get("telegram_bot_token") or "").strip()
    admin_chat = (settings.get("telegram_chat_id") or "").strip()
    if not token or not admin_chat:
        return  # bot not configured
    t = panel.t_for(BOT_LANGUAGE)
    now = now or datetime.now(timezone.utc)

    message = update.get("message")
    if isinstance(message, dict):
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None or str(chat_id) != admin_chat:
            return  # silently ignore strangers
        text = message.get("text")
        if not isinstance(text, str):
            return  # non-text messages are ignored
        ctx = _Ctx(db=db, panel=panel, sender=sender, t=t, chat_id=chat_id, now=now)
        text = text.strip()
        if text.startswith("/"):
            _on_command(ctx, text)
        else:
            _on_text(ctx, text)
        return

    callback = update.get("callback_query")
    if isinstance(callback, dict):
        msg = callback.get("message") or {}
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None or str(chat_id) != admin_chat:
            return  # silently ignore strangers
        ctx = _Ctx(db=db, panel=panel, sender=sender, t=t, chat_id=chat_id, now=now)
        message_id = msg.get("message_id")
        callback_id = callback.get("id") or ""
        data = callback.get("data") or ""
        toast = None
        try:
            toast = _on_callback(ctx, message_id, data)
        except Exception:  # noqa: BLE001 — one bad tap must not break the bot
            logger.exception("telegram bot callback failed")
        if callback_id:
            sender.answer(callback_id, toast)
        return
    # Anything else (edited messages, channel posts, ...) is ignored.


# ---------------------------------------------------------------------------
# Commands + free text
# ---------------------------------------------------------------------------


def _on_command(ctx: _Ctx, text: str) -> None:
    """``/start`` / ``/help`` / ``/menu`` / ``/status`` / ``/users`` /
    ``/inbounds`` / ``/cancel`` (a ``@botname`` suffix is stripped,
    so the commands work in groups too — though only the admin chat
    ever reaches this code; the dispatcher checked the chat id).
    Every command here is in BOT_COMMANDS (the setMyCommands menu).
    """
    t = ctx.t
    command = text.split()[0].split("@")[0].lower()
    if command == "/cancel":
        _end_conversation(ctx.chat_id)
        ctx.sender.send(ctx.chat_id, t["bot_cancelled"], reply_markup=_main_menu_kb(t))
        return
    _end_conversation(ctx.chat_id)  # any other command abandons the flow
    if command in ("/start", "/menu"):
        ctx.sender.send(
            ctx.chat_id, _titled(t["bot_welcome"]), reply_markup=_main_menu_kb(t)
        )
        # (Re-)install the persistent reply keyboard — sent, then
        # deleted at once, so the chat shows no hint text while the
        # buttons stay (see _install_reply_keyboard).
        _install_reply_keyboard(ctx)
    elif command == "/help":
        ctx.sender.send(
            ctx.chat_id, _titled(t["bot_help"]), reply_markup=_main_menu_kb(t)
        )
    elif command == "/status":
        _show_status(ctx, None)
    elif command == "/users":
        _show_users(ctx, None, page=0)
    elif command == "/inbounds":
        _show_inbounds(ctx, None)
    else:
        ctx.sender.send(
            ctx.chat_id, t["bot_unknown_command"], reply_markup=_main_menu_kb(t)
        )


def _on_text(ctx: _Ctx, text: str) -> None:
    """Free text: a reply-keyboard tap, a guided-flow step, or the
    menu hint when idle."""
    # Reply-keyboard taps arrive as plain text — match the exact
    # label first, so a tap during a flow abandons the flow and acts
    # (like a command does). Labels carry emoji, so a typed value
    # (name, number, query) can essentially never collide with one.
    reply_actions = {
        ctx.t["bot_menu_users"]: "users",
        ctx.t["bot_menu_inbounds"]: "inb",
        ctx.t["bot_menu_status"]: "status",
        ctx.t["bot_reply_menu"]: "main",
    }
    action = reply_actions.get(text)
    if action is not None:
        _end_conversation(ctx.chat_id)
        if action == "users":
            _show_users(ctx, None, page=0)
        elif action == "inb":
            _show_inbounds(ctx, None)
        elif action == "status":
            _show_status(ctx, None)
        else:
            # The reply keyboard is already in the chat — no need to
            # re-send it; show the inline menu instead.
            ctx.sender.send(
                ctx.chat_id,
                _titled(ctx.t["bot_welcome"]),
                reply_markup=_main_menu_kb(ctx.t),
            )
        return
    conv = _get_conversation(ctx.chat_id)
    if conv is None:
        ctx.sender.send(
            ctx.chat_id, ctx.t["bot_unknown_command"], reply_markup=_main_menu_kb(ctx.t)
        )
        return
    step = conv["step"]
    if step == "name":
        _flow_name(ctx, conv, text)
    elif step == "inbounds":
        ctx.sender.send(ctx.chat_id, ctx.t["bot_use_buttons"])
    elif step == "limit":
        _flow_limit(ctx, conv, text)
    elif step == "expiry":
        _flow_expiry(ctx, conv, text)
    elif step == "search":
        _flow_search(ctx, conv, text)
    elif step == "search_results":
        # The results are on screen; new text starts a fresh search.
        _flow_search(ctx, conv, text)
    elif step == "edit_name":
        _flow_edit_name(ctx, conv, text)
    elif step == "edit_limit":
        _flow_edit_limit(ctx, conv, text)
    elif step == "edit_expiry":
        _flow_edit_expiry(ctx, conv, text)
    elif step == "inb_port":
        _flow_inbound_port(ctx, conv, text)
    elif step == "inb_sni":
        _flow_inbound_sni(ctx, conv, text)
    else:  # unknown step — defensive; drop the flow
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, ctx.t["bot_unknown_command"], reply_markup=_main_menu_kb(ctx.t)
        )


# ---------------------------------------------------------------------------
# Create-user flow (name → inbounds → traffic limit → expiry)
# ---------------------------------------------------------------------------


def _enabled_inbounds(ctx: _Ctx) -> list:
    return (
        ctx.db.query(Inbound)
        .filter(Inbound.enabled.is_(True))
        .order_by(Inbound.port, Inbound.tag)
        .all()
    )


def _inbound_picker_kb(ctx: _Ctx, inbounds: list, selected: set) -> dict[str, Any]:
    t = ctx.t
    rows = []
    for inbound in inbounds:
        mark = "✅" if inbound.id in selected else "⬜"
        rows.append(
            [(f"{mark} {inbound.tag} ({inbound.protocol})", f"c:tg:{inbound.id}")]
        )
    rows.append([(t["bot_create_confirm"], "c:done"), (t["bot_cancel"], "c:cancel")])
    rows.append([(t["bot_back"], "c:back")])
    return _kb(rows)


def _start_create(ctx: _Ctx, message_id: Optional[int]) -> None:
    """First step of the create flow (from the users list)."""
    t = ctx.t
    if not _enabled_inbounds(ctx):
        _show(
            ctx,
            message_id,
            t["bot_create_no_inbounds"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    _start_conversation(ctx.chat_id, "name", {})
    _show(
        ctx,
        message_id,
        _titled(t["bot_create_name"]),
        _kb([[(t["bot_cancel"], "c:cancel")]]),
    )


def _flow_name(ctx: _Ctx, conv: dict, text: str) -> None:
    """Create step 1: the name (same rules as the web form)."""
    t = ctx.t
    name = text.strip()
    if not ctx.panel.NAME_RE.match(name):
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_name_invalid"],
            reply_markup=_kb([[(t["bot_cancel"], "c:cancel")]]),
        )
        return
    if ctx.db.query(User).filter(User.name == name).first() is not None:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_name_exists"],
            reply_markup=_kb([[(t["bot_cancel"], "c:cancel")]]),
        )
        return
    inbounds = _enabled_inbounds(ctx)
    if not inbounds:  # raced with the last inbound being disabled
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, t["bot_create_no_inbounds"], reply_markup=_main_menu_kb(t)
        )
        return
    conv["data"]["name"] = name
    conv["step"] = "inbounds"
    conv["data"]["selected"] = {i.id for i in inbounds}
    conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
    ctx.sender.send(
        ctx.chat_id,
        t["bot_create_pick_inbounds"],
        reply_markup=_inbound_picker_kb(ctx, inbounds, conv["data"]["selected"]),
    )


def _flow_limit(ctx: _Ctx, conv: dict, text: str) -> None:
    """Create step 3: traffic limit in GB (the Unlimited button
    means unlimited)."""
    t = ctx.t
    try:
        conv["data"]["limit_bytes"] = _parse_limit_gb(text)
    except ValueError:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_limit_invalid"],
            reply_markup=_flow_kb(t, "bot_skip_unlimited"),
        )
        return
    conv["step"] = "expiry"
    conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
    ctx.sender.send(
        ctx.chat_id,
        t["bot_create_expiry"],
        reply_markup=_flow_kb(t, "bot_skip_never"),
    )


def _flow_expiry(ctx: _Ctx, conv: dict, text: str) -> None:
    """Create step 4: expiry in days (the Never button means no
    expiry), then create."""
    t = ctx.t
    try:
        expires_at = _parse_expiry_days(text, ctx.now)
    except ValueError:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_expiry_invalid"],
            reply_markup=_flow_kb(t, "bot_skip_never"),
        )
        return
    name = conv["data"]["name"]
    selected = set(conv["data"].get("selected") or set())
    _end_conversation(ctx.chat_id)
    try:
        user = User(
            name=name,
            enabled=True,
            traffic_limit_bytes=conv["data"].get("limit_bytes"),
            traffic_used_bytes=0,
            expires_at=expires_at,
            sub_token=secrets.token_urlsafe(24),
        )
        ctx.db.add(user)
        ctx.db.commit()
        # Clients only on the picked inbounds (the web form creates
        # them on every enabled inbound — the picker defaults to the
        # same set, so the two paths agree unless the admin narrowed it).
        ctx.panel._create_clients_for_user(ctx.db, user, inbound_ids=selected)
    except Exception:  # noqa: BLE001 — a failed create must say so
        ctx.db.rollback()
        logger.exception("telegram bot user creation failed")
        ctx.sender.send(
            ctx.chat_id, t["bot_create_failed"], reply_markup=_main_menu_kb(t)
        )
        return
    _audit(ctx, "user.create", f"{name} [telegram]")
    errors = _rerender(ctx)
    text_out = t["bot_create_done"].format(name=h(name))
    note = _rerender_note(ctx, errors)
    if note:
        text_out += "\n\n" + note
    ctx.sender.send(
        ctx.chat_id,
        text_out,
        reply_markup=_kb(
            [
                [(t["bot_view_user"], f"u:v:{user.id}")],
                [(t["bot_back_users"], "u:list:0")],
            ]
        ),
    )


def _on_create_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> Optional[str]:
    """Flow-control buttons (``c:`` family): cancel, skip, back, and
    the create flow's inbound picker.

    "c:" is the shared flow family — every guided flow's prompts use
    ``c:cancel`` (and now ``c:skip`` / ``c:back``), so this handler
    is step-driven: Skip submits the current step's default value
    (the ONLY way to submit "empty" — Telegram cannot send an empty
    message), Back returns to the previous step without abandoning
    the flow. A Skip/Back tap on a step that has no such action (a
    stale keyboard) gets the friendly stale answer, never a crash.
    """
    t = ctx.t
    action = parts[1] if len(parts) > 1 else ""
    if action == "cancel":
        _end_conversation(ctx.chat_id)
        _show(ctx, message_id, t["bot_cancelled"], _main_menu_kb(t))
        return None
    conv = _get_conversation(ctx.chat_id)
    if conv is None:
        _show(ctx, message_id, t["bot_flow_expired"], _main_menu_kb(t))
        return None
    if action == "skip":
        # Each optional step's default is what its text handler does
        # with "" — the Skip button just invokes that path.
        step = conv["step"]
        if step == "limit":
            _flow_limit(ctx, conv, "")
        elif step == "expiry":
            _flow_expiry(ctx, conv, "")
        elif step == "edit_limit":
            _flow_edit_limit(ctx, conv, "")
        elif step == "edit_expiry":
            _flow_edit_expiry(ctx, conv, "")
        elif step == "inb_port":
            _flow_inbound_port(ctx, conv, "")
        elif step == "inb_sni":
            _flow_inbound_sni(ctx, conv, "")
        else:
            _show_stale(ctx, message_id)
        return None
    if action == "back":
        step = conv["step"]
        conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
        if step == "inbounds":
            # Back to the name step (the name is re-entered; the
            # picker selection is rebuilt when it is given again).
            conv["step"] = "name"
            _show(
                ctx,
                message_id,
                _titled(t["bot_create_name"]),
                _kb([[(t["bot_cancel"], "c:cancel")]]),
            )
        elif step == "limit":
            conv["step"] = "inbounds"
            inbounds = _enabled_inbounds(ctx)
            selected = conv["data"].get("selected") or {
                i.id for i in inbounds
            }
            _show(
                ctx,
                message_id,
                t["bot_create_pick_inbounds"],
                _inbound_picker_kb(ctx, inbounds, selected),
            )
        elif step == "expiry":
            conv["step"] = "limit"
            _show(
                ctx, message_id, t["bot_create_limit"], _flow_kb(t, "bot_skip_unlimited")
            )
        elif step in ("edit_name", "edit_limit", "edit_expiry"):
            user_id = conv["data"].get("user_id")
            _end_conversation(ctx.chat_id)
            if isinstance(user_id, int):
                _show_edit_menu(ctx, message_id, user_id)
            else:
                _show_users(ctx, message_id, page=0)
        elif step == "search":
            _end_conversation(ctx.chat_id)
            _show_users(ctx, message_id, page=0)
        elif step == "inb_port":
            _end_conversation(ctx.chat_id)
            _show_inbound_protocol_picker(ctx, message_id)
        elif step == "inb_sni":
            conv["step"] = "inb_port"
            _show(
                ctx,
                message_id,
                t["bot_create_inbound_port"],
                _flow_kb(t, "bot_skip_auto"),
            )
        else:
            _show_stale(ctx, message_id)
        return None
    if conv["step"] != "inbounds":
        _show(ctx, message_id, t["bot_flow_expired"], _main_menu_kb(t))
        return None
    if action == "tg":
        inbound_id = _parse_int(parts[2]) if len(parts) > 2 else None
        if inbound_id is None:
            return None
        selected = conv["data"].setdefault("selected", set())
        if inbound_id in selected:
            selected.discard(inbound_id)
        else:
            # Only real enabled inbounds can be (re-)selected — a
            # stale keyboard may still list a disabled one.
            inbound = ctx.db.get(Inbound, inbound_id)
            if inbound is not None and inbound.enabled:
                selected.add(inbound_id)
        conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
        inbounds = _enabled_inbounds(ctx)
        _show(
            ctx,
            message_id,
            t["bot_create_pick_inbounds"],
            _inbound_picker_kb(ctx, inbounds, selected),
        )
        return None
    if action == "done":
        if not conv["data"].get("selected"):
            return t["bot_create_pick_one"]  # toast; stay on the picker
        conv["step"] = "limit"
        conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
        _show(
            ctx,
            message_id,
            t["bot_create_limit"],
            _flow_kb(t, "bot_skip_unlimited"),
        )
        return None
    _show_stale(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Callback router
# ---------------------------------------------------------------------------


def _show_stale(ctx: _Ctx, message_id: Optional[int]) -> None:
    """A friendly answer for an expired/invalid button tap: the
    message says the button is dead and the main menu is one tap
    away. Never a crash, never a stack trace, never silence."""
    _show(
        ctx,
        message_id,
        ctx.t["bot_stale_callback"],
        _main_menu_kb(ctx.t),
    )


def _on_callback(ctx: _Ctx, message_id: Optional[int], data: str) -> Optional[str]:
    """Route one button tap. Returns a toast string (or None) for the
    dispatcher to answer with."""
    parts = (data or "").split(":")
    if not parts or not parts[0]:
        _show_stale(ctx, message_id)
        return None
    family = parts[0]
    if family == "c":
        return _on_create_callback(ctx, message_id, parts)
    # Any other tap abandons an in-progress flow — the admin clearly
    # moved on to something else. Exception: paging through search
    # results (u:list) continues the search flow, whose query lives
    # in the conversation state — ending it would lose the query.
    conv = _get_conversation(ctx.chat_id)
    continues_search = (
        conv is not None
        and conv["step"] == "search_results"
        and family == "u"
        and len(parts) > 1
        and parts[1] == "list"
    )
    if not continues_search:
        _end_conversation(ctx.chat_id)
    if family == "m":
        return _on_menu_callback(ctx, message_id, parts)
    if family == "u":
        return _on_user_callback(ctx, message_id, parts)
    if family == "i":
        return _on_inbound_callback(ctx, message_id, parts)
    if family == "s":
        return _on_service_callback(ctx, message_id, parts)
    if family == "b":
        return _on_backup_callback(ctx, message_id, parts)
    _show_stale(ctx, message_id)
    return None


def _on_menu_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> None:
    t = ctx.t
    action = parts[1] if len(parts) > 1 else ""
    if action == "main":
        _show(ctx, message_id, _titled(t["bot_welcome"]), _main_menu_kb(t))
    elif action == "help":
        _show(
            ctx,
            message_id,
            _titled(t["bot_help"]),
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
    elif action == "users":
        _show_users(ctx, message_id, page=0)
    elif action == "inb":
        _show_inbounds(ctx, message_id)
    elif action == "status":
        _show_status(ctx, message_id)
    elif action == "svc":
        _show_services(ctx, message_id)
    elif action == "bkp":
        _show_backup(ctx, message_id)
    else:
        _show_stale(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Users (list / view / links / freeze / extend / reset / delete)
# ---------------------------------------------------------------------------


def _show_users(
    ctx: _Ctx,
    message_id: Optional[int],
    page: int,
    note: Optional[str] = None,
    query: Optional[str] = None,
) -> None:
    """The user list, optionally filtered by a search query (name or
    note, case-insensitive substring). The query lives in the
    conversation state while paging (see _on_callback), never in the
    callback data — a Persian query would not fit Telegram's 64-byte
    callback-data limit."""
    t = ctx.t
    users = ctx.db.query(User).order_by(User.created_at.desc()).all()
    if query:
        needle = query.lower()
        users = [
            u
            for u in users
            if needle in (u.name or "").lower()
            or needle in (u.note or "").lower()
        ]
    pages = max(1, (len(users) + USERS_PAGE_SIZE - 1) // USERS_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    rows = users[page * USERS_PAGE_SIZE : (page + 1) * USERS_PAGE_SIZE]
    if query:
        lines = [
            _b(
                t["bot_search_title"].format(
                    query=h(query), page=page + 1, pages=pages
                )
            ),
            "",
        ]
    else:
        lines = [_b(t["bot_users_title"].format(page=page + 1, pages=pages)), ""]
    if not users:
        lines.append(t["bot_search_no_match"] if query else t["bot_no_users"])
    kb_rows: list[list[tuple[str, str]]] = []
    for user in rows:
        emoji, _label = _user_state(ctx, user)
        limit = (
            _format_bytes(user.traffic_limit_bytes)
            if user.traffic_limit_bytes
            else t["bot_unlimited"]
        )
        expiry = (
            _aware(user.expires_at).strftime("%Y-%m-%d")
            if user.expires_at is not None
            else "—"
        )
        lines.append(
            f"{emoji} {h(user.name)} — "
            f"{_format_bytes(user.traffic_used_bytes or 0)}/{limit} — {expiry}"
        )
        kb_rows.append([(user.name, f"u:v:{user.id}")])
    nav: list[tuple[str, str]] = []
    if page > 0:
        nav.append((t["bot_prev"], f"u:list:{page - 1}"))
    if page < pages - 1:
        nav.append((t["bot_next"], f"u:list:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    if query:
        # The filter lives in the conversation state while paging,
        # so without this button there is no way back to the full
        # list from the results themselves (an empty message cannot
        # be sent to clear it).
        kb_rows.append([(t["bot_clear_search"], "u:clear")])
    kb_rows.append([(t["bot_search"], "u:search"), (t["bot_new_user"], "u:new")])
    kb_rows.append([(t["bot_back_main"], "m:main")])
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    _show(ctx, message_id, text, _kb(kb_rows))


def _start_search(ctx: _Ctx, message_id: Optional[int]) -> None:
    """First step of the user search: ask for the query text."""
    _start_conversation(ctx.chat_id, "search", {})
    _show(
        ctx,
        message_id,
        _titled(ctx.t["bot_search_prompt"]),
        _flow_kb(ctx.t),
    )


def _flow_search(ctx: _Ctx, conv: dict, text: str) -> None:
    """Search step: filter the user list by the query. The step
    becomes ``search_results`` so paging keeps the query (see
    _on_callback); the Clear button on the results ends the filter
    (an empty message cannot be sent on Telegram)."""
    query = text.strip()
    if not query:
        _end_conversation(ctx.chat_id)
        _show_users(ctx, None, page=0)
        return
    conv["step"] = "search_results"
    conv["data"]["query"] = query
    conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
    _show_users(ctx, None, page=0, query=query)


def _show_user(
    ctx: _Ctx, message_id: Optional[int], user_id: int, note: Optional[str] = None
) -> None:
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    emoji, label = _user_state(ctx, user)
    limit = (
        _format_bytes(user.traffic_limit_bytes)
        if user.traffic_limit_bytes
        else t["bot_unlimited"]
    )
    clients = ctx.db.query(Client).filter(Client.user_id == user.id).all()
    inbound_names: list[str] = []
    for client in clients:
        inbound = ctx.db.get(Inbound, client.inbound_id)
        if inbound is None:
            continue
        name = h(inbound.tag)
        if client_is_frozen(client):
            name += " 🧊"
        inbound_names.append(name)
    lines = [
        _b(f"👤 {h(user.name)}"),
        f"{_b(t['status'] + ':')} {emoji} {label}",
        f"{_b(t['bot_traffic'] + ':')} {_format_bytes(user.traffic_used_bytes or 0)} / {limit}",
        f"{_b(t['bot_expires'] + ':')} {_expiry_text(ctx, user)}",
        f"{_b(t['bot_inbounds'] + ':')} {', '.join(inbound_names) if inbound_names else '—'}",
    ]
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    frozen = _user_frozen(ctx, user)
    kb_rows: list[list[tuple[str, str]]] = [
        [
            (t["bot_links"], f"u:links:{user.id}"),
            (t["bot_edit"], f"u:edit:{user.id}"),
            (t["clients"], f"u:cl:{user.id}"),
        ],
        [
            (
                t["bot_unfreeze"] if frozen else t["bot_freeze"],
                f"u:{'unfrz' if frozen else 'frz'}:{user.id}",
            ),
            (t["bot_extend"], f"u:ext:{user.id}"),
        ],
        [
            (t["bot_reset_traffic"], f"u:rst:{user.id}"),
            (t["bot_delete"], f"u:del:{user.id}"),
        ],
        [(t["bot_back_users"], "u:list:0")],
    ]
    _show(ctx, message_id, text, _kb(kb_rows))


# ---------------------------------------------------------------------------
# User edit (guided: pick a field, then send the new value)
# ---------------------------------------------------------------------------


def _show_edit_menu(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    """Pick which field to edit (name / traffic limit / expiry)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    _show(
        ctx,
        message_id,
        t["bot_edit_pick"],
        _kb(
            [
                [
                    (t["bot_edit_name"], f"u:edit:{user_id}:name"),
                    (t["bot_edit_limit"], f"u:edit:{user_id}:limit"),
                    (t["bot_edit_expiry"], f"u:edit:{user_id}:expiry"),
                ],
                [(t["bot_back"], f"u:v:{user_id}")],
            ]
        ),
    )


def _start_edit(
    ctx: _Ctx, message_id: Optional[int], user_id: int, field: str
) -> None:
    """Start one edit step (the new value arrives as free text)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    prompts = {
        "name": t["bot_edit_name_prompt"].format(name=h(user.name)),
        "limit": t["bot_edit_limit_prompt"],
        "expiry": t["bot_edit_expiry_prompt"],
    }
    prompt = prompts.get(field)
    if prompt is None:
        _show_stale(ctx, message_id)
        return
    skip_keys = {"limit": "bot_skip_unlimited", "expiry": "bot_skip_never"}
    _start_conversation(ctx.chat_id, f"edit_{field}", {"user_id": user_id})
    _show(
        ctx,
        message_id,
        prompt,
        _flow_kb(t, skip_keys.get(field)),
    )


def _apply_user_edit(ctx: _Ctx, conv: dict) -> Optional[Any]:
    """The user being edited (None when it vanished mid-flow)."""
    user_id = conv["data"].get("user_id")
    if not isinstance(user_id, int):
        return None
    return ctx.db.get(User, user_id)


def _finish_user_edit(ctx: _Ctx, user: Any) -> None:
    """Commit an edit: audit + re-render + show the user again."""
    t = ctx.t
    ctx.db.commit()
    _audit(ctx, "user.update", f"{user.name} [telegram]")
    errors = _rerender(ctx)
    note = _rerender_note(ctx, errors)
    text = t["bot_edited"]
    if note:
        text += "\n\n" + note
    _end_conversation(ctx.chat_id)
    _show_user(ctx, None, user.id, note=text)


def _flow_edit_name(ctx: _Ctx, conv: dict, text: str) -> None:
    """Edit step: rename (same rules as the web edit route)."""
    t = ctx.t
    user = _apply_user_edit(ctx, conv)
    if user is None:
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, t["bot_user_not_found"], reply_markup=_main_menu_kb(t)
        )
        return
    name = text.strip()
    if not ctx.panel.NAME_RE.match(name):
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_name_invalid"],
            reply_markup=_flow_kb(t),
        )
        return
    clash = (
        ctx.db.query(User)
        .filter(User.name == name, User.id != user.id)
        .first()
    )
    if clash is not None:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_name_exists"],
            reply_markup=_flow_kb(t),
        )
        return
    user.name = name
    _finish_user_edit(ctx, user)


def _flow_edit_limit(ctx: _Ctx, conv: dict, text: str) -> None:
    """Edit step: traffic limit in GB (the Unlimited button means
    unlimited)."""
    t = ctx.t
    user = _apply_user_edit(ctx, conv)
    if user is None:
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, t["bot_user_not_found"], reply_markup=_main_menu_kb(t)
        )
        return
    try:
        user.traffic_limit_bytes = _parse_limit_gb(text)
    except ValueError:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_limit_invalid"],
            reply_markup=_flow_kb(t, "bot_skip_unlimited"),
        )
        return
    _finish_user_edit(ctx, user)


def _flow_edit_expiry(ctx: _Ctx, conv: dict, text: str) -> None:
    """Edit step: expiry in days from today (the Never button means
    no expiry).

    The web edit route takes a calendar date; the bot takes days,
    like its create flow — the validation (a valid future expiry or
    none) is the same, only the chat-friendly input differs.
    """
    t = ctx.t
    user = _apply_user_edit(ctx, conv)
    if user is None:
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, t["bot_user_not_found"], reply_markup=_main_menu_kb(t)
        )
        return
    try:
        user.expires_at = _parse_expiry_days(text, ctx.now)
    except ValueError:
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_expiry_invalid"],
            reply_markup=_flow_kb(t, "bot_skip_never"),
        )
        return
    _finish_user_edit(ctx, user)


def _send_links(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    """The user's share links + subscription link (same links the panel
    generates), the native config files (OpenVPN/OpenConnect/
    AmneziaWG/IKEv2 have no share link — sent as documents after the
    message), and the OpenVPN/OpenConnect username/password pairs
    (the .ovpn embeds them now; the AnyConnect profile cannot, so
    they are shown here). A host is required for share links
    (subscription_host or domain setting); the subscription URL uses
    the domain when set, else the subscription_host fallback (no
    domain needed) — without either it is omitted, not a broken
    link. The file exports need the host too, so the no-host case
    stays an honest message. When a subscription URL exists, the
    keyboard also carries an "Add to ZedSecure" URL button
    (``zedsecure://import`` deep link — tapping it opens the app's
    confirmation dialog; the app fetches the subscription itself)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    settings = ctx.panel.get_settings(ctx.db)
    host = (settings.get("subscription_host") or "").strip() or (
        settings.get("domain") or ""
    ).strip()
    if not host:
        _show(
            ctx,
            message_id,
            t["bot_no_host"],
            _kb([[(t["bot_back"], f"u:v:{user_id}")]]),
        )
        return
    links = ctx.panel._links_for_user(ctx.db, user, host, settings)
    sub_url = ctx.panel._subscription_panel_url(settings, f"/sub/{user.sub_token}")
    # Native config files, one per protocol (the first usable client
    # of that protocol — same rule as the web's file-export URLs).
    # One broken export must not hide the rest.
    files: list[tuple[str, str, str]] = []
    for protocol in _NATIVE_FILE_PROTOCOLS:
        try:
            found = ctx.panel._user_file_export(
                ctx.db, user, protocol, host, settings
            )
        except Exception:  # noqa: BLE001 — see above
            logger.exception("bot file export failed for %s", protocol)
            continue
        if found is not None:
            files.append(found)
    # Username/password pairs for the usable native clients (the
    # app prompts for them where the file cannot carry them).
    credentials: list[tuple[str, str, str]] = []
    for client, inbound in ctx.panel._usable_clients(ctx.db, user):
        if inbound.protocol in _CREDENTIAL_PROTOCOLS:
            credentials.append(
                (inbound.tag, user.name, client.password or "")
            )
    if not links and not sub_url and not files and not credentials:
        _show(
            ctx,
            message_id,
            t["bot_no_links"],
            _kb([[(t["bot_back"], f"u:v:{user_id}")]]),
        )
        return
    lines = [_b(t["bot_links_title"].format(name=h(user.name))), ""]
    if sub_url:
        lines.append(_b(t["bot_sub_link"] + ":"))
        lines.append(h(sub_url))
        lines.append("")
    for entry in links:
        lines.append(_b(h(entry["inbound"].tag) + ":"))
        lines.append(h(entry["link"]))
        lines.append("")
    if credentials:
        lines.append(_b(t["bot_credentials"] + ":"))
        for tag, username, password in credentials:
            lines.append(
                f"{h(tag)}: <code>{h(username)}</code> / "
                f"<code>{h(password)}</code>"
            )
        lines.append("")
    if files:
        lines.append(_b(t["bot_native_files"] + ":"))
        for filename, _media, _content in files:
            lines.append(f"📎 <code>{h(filename)}</code>")
        lines.append("")
    keyboard = _kb([[(t["bot_back"], f"u:v:{user_id}")]])
    if sub_url:
        # One-tap import: the deep link opens ZedSecure's
        # confirmation dialog; the app fetches the subscription
        # itself. A URL button, not a callback — tapping it must
        # leave this chat for the app.
        deeplink = links_mod.zedsecure_deep_link(sub_url, user.name)
        keyboard["inline_keyboard"].insert(
            0, _url_row(t["add_to_zedsecure"], deeplink)
        )
    _send_long(
        ctx,
        message_id,
        "\n".join(lines).rstrip("\n"),
        keyboard,
    )
    for filename, _media, content in files:
        if not ctx.sender.document(
            ctx.chat_id, filename, content.encode("utf-8")
        ):
            ctx.sender.send(
                ctx.chat_id,
                t["bot_file_send_failed"].format(filename=h(filename)),
            )


def _freeze_user(
    ctx: _Ctx, message_id: Optional[int], user_id: int, freeze: bool
) -> Optional[str]:
    """Freeze/unfreeze every client of the user (same as the web
    freeze/unfreeze routes: credentials and history are kept)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    count = 0
    for client in ctx.db.query(Client).filter(Client.user_id == user.id).all():
        if client_is_frozen(client) != freeze:
            _set_frozen(client, freeze)
            count += 1
    ctx.db.commit()
    action = "user.freeze" if freeze else "user.unfreeze"
    _audit(ctx, action, f"{user.name} ({count} clients) [telegram]")
    errors = _rerender(ctx)
    _show_user(ctx, message_id, user_id, note=_rerender_note(ctx, errors))
    return t["bot_frozen"] if freeze else t["bot_unfrozen"]


# ---------------------------------------------------------------------------
# Per-client management (bot parity with the web user page)
# ---------------------------------------------------------------------------


def _client_rows(ctx: _Ctx, user_id: int) -> Optional[tuple[Any, list]]:
    """``(user, [(client, inbound), ...])`` for the clients view, or
    ``None`` when the user is gone."""
    user = ctx.db.get(User, user_id)
    if user is None:
        return None
    rows = []
    for client in (
        ctx.db.query(Client)
        .filter(Client.user_id == user.id)
        .order_by(Client.inbound_id)
        .all()
    ):
        inbound = ctx.db.get(Inbound, client.inbound_id)
        if inbound is None:
            continue
        rows.append((client, inbound))
    return user, rows


def _show_clients(
    ctx: _Ctx, message_id: Optional[int], user_id: int, note: Optional[str] = None
) -> None:
    """The user's clients, one button each (the per-client view)."""
    t = ctx.t
    found = _client_rows(ctx, user_id)
    if found is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    user, rows = found
    lines = [_b(t["bot_clients_title"].format(name=h(user.name)))]
    kb_rows: list[list[tuple[str, str]]] = []
    for client, inbound in rows:
        mark = "🧊 " if client_is_frozen(client) else ""
        kb_rows.append(
            [(f"{mark}{inbound.tag} ({inbound.protocol})", f"u:cv:{client.id}")]
        )
    if not kb_rows:
        lines.append("")
        lines.append(t["bot_no_clients"])
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    kb_rows.append([(t["add_to_inbound"], f"u:add:{user_id}")])
    kb_rows.append([(t["bot_back"], f"u:v:{user_id}")])
    _show(ctx, message_id, text, _kb(kb_rows))


def _show_client(
    ctx: _Ctx, message_id: Optional[int], client_id: int, note: Optional[str] = None
) -> None:
    """One client: inbound, status, flow (VLESS), and the
    username/password pair for the protocols that have one
    (OpenVPN/OpenConnect — in ``<code>`` blocks, tap to copy)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    frozen = client_is_frozen(client)
    state = (
        "🧊 " + t["bot_status_frozen"]
        if frozen
        else "✅ " + t["bot_status_enabled"]
    )
    lines = [
        _b(f"🧩 {h(inbound.tag)}"),
        f"{_b(t['protocol'] + ':')} {h(inbound.protocol)}",
        f"{_b(t['port'] + ':')} {inbound.port}",
        f"{_b(t['status'] + ':')} {state}",
    ]
    if inbound.protocol == "vless":
        flow = client.flow or ""
        lines.append(
            f"{_b(t['flow'] + ':')} "
            f"{h(flow) if flow else t['bot_flow_none']}"
        )
    if inbound.protocol in _CREDENTIAL_PROTOCOLS:
        lines.append(f"{_b(t['username'] + ':')} <code>{h(user.name)}</code>")
        lines.append(
            f"{_b(t['password'] + ':')} <code>{h(client.password or '')}</code>"
        )
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    kb_rows: list[list[tuple[str, str]]] = [
        [
            (
                t["bot_unfreeze"] if frozen else t["bot_freeze"],
                f"u:{'cunfrz' if frozen else 'cfrz'}:{client.id}",
            ),
            (t["detach"], f"u:det:{client.id}"),
        ]
    ]
    # Move / flow are offered only when they can do something: a
    # same-protocol target must exist, and flow is VLESS-only.
    second_row: list[tuple[str, str]] = []
    if _move_targets(ctx.db, user, client):
        second_row.append((t["bot_move"], f"u:mv:{client.id}"))
    if _client_flow_options(inbound):
        second_row.append((t["bot_edit_flow"], f"u:cfl:{client.id}"))
    if second_row:
        kb_rows.append(second_row)
    kb_rows.append([(t["bot_back"], f"u:cl:{user.id}")])
    _show(ctx, message_id, text, _kb(kb_rows))


def _show_add_inbound(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    """Picker of the inbounds the user has no client on yet (any
    protocol, including shared ones — the web rule)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    addable = _addable_inbounds(ctx.db, user)
    if not addable:
        _show(
            ctx,
            message_id,
            t["bot_add_inbound_none"],
            _kb([[(t["bot_back"], f"u:cl:{user_id}")]]),
        )
        return
    rows = [
        [(f"{inbound.tag} ({inbound.protocol})", f"u:add:{user_id}:{inbound.id}")]
        for inbound in addable
    ]
    rows.append([(t["bot_back"], f"u:cl:{user_id}")])
    _show(ctx, message_id, t["bot_add_inbound_pick"], _kb(rows))


def _add_user_to_inbound(
    ctx: _Ctx, message_id: Optional[int], user_id: int, inbound_id: int
) -> Optional[str]:
    """Add the user to one inbound (same checks as the web route:
    enabled inbound, no existing client, WG/AWG pool pre-check)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    target = ctx.db.get(Inbound, inbound_id)
    if target is None or not target.enabled:
        _show_stale(ctx, message_id)
        return None
    existing = (
        ctx.db.query(Client)
        .filter(Client.user_id == user.id, Client.inbound_id == target.id)
        .first()
    )
    if existing is not None:
        # Raced with the web UI (or a double tap): the client is
        # already there — show the list, create nothing.
        _show_clients(ctx, message_id, user_id)
        return None
    if target.protocol in ("wireguard", "amneziawg"):
        subnet = (target.stream or {}).get("subnet") or (
            "10.8.0.0/24" if target.protocol == "wireguard" else "10.8.1.0/24"
        )
        try:
            if target.protocol == "wireguard":
                ctx.panel._next_wg_address(ctx.db, subnet, inbound_id=target.id)
            else:
                ctx.panel._next_awg_address(ctx.db, subnet, inbound_id=target.id)
        except ValueError:
            _show_clients(
                ctx,
                message_id,
                user_id,
                note=t["add_inbound_address_exhausted"],
            )
            return None
    ctx.panel._create_clients_for_user(ctx.db, user, inbound_ids={target.id})
    _audit(ctx, "user.add_inbound", f"{user.name} -> {target.tag} [telegram]")
    errors = _rerender(ctx)
    note = t["bot_add_inbound_done"].format(tag=h(target.tag))
    rerender_note = _rerender_note(ctx, errors)
    if rerender_note:
        note += "\n\n" + rerender_note
    _show_clients(ctx, message_id, user_id, note=note)
    return t["bot_add_inbound_done"].format(tag=target.tag)


def _show_detach_confirm(ctx: _Ctx, message_id: Optional[int], client_id: int) -> None:
    """Detach confirmation — a distinct warning when it is the
    user's last client (same as the web detail page)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    count = ctx.db.query(Client).filter(Client.user_id == user.id).count()
    if count <= 1:
        text = t["bot_detach_last_confirm"].format(tag=h(inbound.tag))
    else:
        text = t["bot_detach_confirm"].format(tag=h(inbound.tag))
    _show(
        ctx,
        message_id,
        text,
        _kb(
            [
                [
                    (t["bot_confirm_yes"], f"u:det:{client_id}:ok"),
                    (t["bot_confirm_no"], f"u:cv:{client_id}"),
                ]
            ]
        ),
    )


def _detach_client(
    ctx: _Ctx, message_id: Optional[int], client_id: int
) -> Optional[str]:
    """Detach the user from ONE inbound (same as the web route:
    the last client may be detached too — zero-client users are a
    normal state, and add-to-inbound makes it reversible)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    tag = inbound.tag if inbound is not None else str(client.inbound_id)
    user_id = user.id
    ctx.db.delete(client)
    ctx.db.commit()
    _audit(ctx, "user.detach_inbound", f"{user.name} from {tag} [telegram]")
    errors = _rerender(ctx)
    note = t["bot_detached"].format(tag=h(tag))
    rerender_note = _rerender_note(ctx, errors)
    if rerender_note:
        note += "\n\n" + rerender_note
    _show_clients(ctx, message_id, user_id, note=note)
    return t["bot_detached"].format(tag=tag)


def _freeze_client(
    ctx: _Ctx, message_id: Optional[int], client_id: int, freeze: bool
) -> Optional[str]:
    """Freeze/unfreeze ONE client (the per-user freeze is ``u:frz`` —
    this is the web edit page's per-client checkbox)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    _set_frozen(client, freeze)
    ctx.db.commit()
    action = "user.freeze" if freeze else "user.unfreeze"
    _audit(ctx, action, f"{user.name} ({inbound.tag}) [telegram]")
    errors = _rerender(ctx)
    _show_client(ctx, message_id, client_id, note=_rerender_note(ctx, errors))
    return t["bot_client_frozen"] if freeze else t["bot_client_unfrozen"]


def _show_move_picker(ctx: _Ctx, message_id: Optional[int], client_id: int) -> None:
    """Picker of the same-protocol inbounds the client may move to."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    targets = _move_targets(ctx.db, user, client)
    if not targets:
        _show_client(ctx, message_id, client_id, note=t["bot_move_none"])
        return
    rows = [
        [(f"{target.tag} ({target.protocol})", f"u:mv:{client_id}:{target.id}")]
        for target in targets
    ]
    rows.append([(t["bot_back"], f"u:cv:{client_id}")])
    _show(ctx, message_id, t["bot_move_pick"], _kb(rows))


def _move_client(
    ctx: _Ctx, message_id: Optional[int], client_id: int, target_id: int
) -> Optional[str]:
    """Move one client to another same-protocol inbound (web rules:
    the target is re-validated against the move targets — a stale
    tap cannot move anywhere invalid; WG/AWG get a fresh address
    from the target subnet)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    target = ctx.db.get(Inbound, target_id)
    valid = target is not None and any(
        row.id == target.id for row in _move_targets(ctx.db, user, client)
    )
    if not valid:
        _show_stale(ctx, message_id)
        return None
    error = _apply_client_move(ctx.db, client, target)
    if error == "move_address_exhausted":
        _show_client(
            ctx, message_id, client_id, note=t["bot_move_address_exhausted"]
        )
        return None
    ctx.db.commit()
    _audit(
        ctx,
        "user.update",
        f"{user.name} move {inbound.tag} -> {target.tag} [telegram]",
    )
    errors = _rerender(ctx)
    note = t["bot_move_done"].format(tag=h(target.tag))
    rerender_note = _rerender_note(ctx, errors)
    if rerender_note:
        note += "\n\n" + rerender_note
    _show_client(ctx, message_id, client_id, note=note)
    return t["bot_move_done"].format(tag=target.tag)


def _show_flow_picker(ctx: _Ctx, message_id: Optional[int], client_id: int) -> None:
    """Pick the XTLS flow for a VLESS client (web rules: the options
    depend on the inbound's security — Reality offers only the
    Vision variants, TLS offers none + Vision, none offers none)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    options = _client_flow_options(inbound)
    if not options:
        _show_stale(ctx, message_id)
        return
    current = client.flow or ""
    rows = []
    for option in options:
        label = option if option else t["bot_flow_none"]
        mark = "✅ " if current == option else ""
        rows.append([(f"{mark}{label}", f"u:cfl:{client_id}:{option or 'none'}")])
    rows.append([(t["bot_back"], f"u:cv:{client_id}")])
    _show(ctx, message_id, t["bot_flow_pick"], _kb(rows))


def _set_client_flow(
    ctx: _Ctx, message_id: Optional[int], client_id: int, flow: str
) -> Optional[str]:
    """Set one client's XTLS flow (re-validated against the
    inbound's options — a stale tap cannot set an invalid flow;
    stored as ``None`` for "none", like the web edit route)."""
    t = ctx.t
    client = ctx.db.get(Client, client_id)
    user = ctx.db.get(User, client.user_id) if client is not None else None
    inbound = ctx.db.get(Inbound, client.inbound_id) if client is not None else None
    if client is None or user is None or inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_client_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    if flow == "none":
        flow = ""
    options = _client_flow_options(inbound)
    if flow not in options:
        _show_stale(ctx, message_id)
        return None
    client.flow = flow or None
    ctx.db.commit()
    _audit(
        ctx,
        "user.update",
        f"{user.name} flow {inbound.tag}={flow or 'none'} [telegram]",
    )
    errors = _rerender(ctx)
    if flow:
        toast = t["bot_flow_set"].format(flow=flow)
        note = t["bot_flow_set"].format(flow=h(flow))
    else:
        toast = note = t["bot_flow_cleared"]
    rerender_note = _rerender_note(ctx, errors)
    if rerender_note:
        note += "\n\n" + rerender_note
    _show_client(ctx, message_id, client_id, note=note)
    return toast


def _show_extend_menu(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    _show(
        ctx,
        message_id,
        t["bot_extend_prompt"].format(name=h(user.name)),
        _kb(
            [
                [
                    (t["bot_extend_days"].format(days=7), f"u:ext:{user_id}:7"),
                    (t["bot_extend_days"].format(days=30), f"u:ext:{user_id}:30"),
                    (t["bot_extend_days"].format(days=90), f"u:ext:{user_id}:90"),
                ],
                [(t["bot_back"], f"u:v:{user_id}")],
            ]
        ),
    )


def _extend_user(
    ctx: _Ctx, message_id: Optional[int], user_id: int, days: int
) -> Optional[str]:
    """Extend one user's expiry (same base rule as the web bulk extend:
    from the current expiry when it is still in the future, else from
    now; a never-expiring user gets now + N days)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    base = user.expires_at
    if base is not None:
        base = max(_aware(base), ctx.now)
    else:
        base = ctx.now
    user.expires_at = base + timedelta(days=days)
    ctx.db.commit()
    _audit(ctx, "user.extend", f"{user.name} +{days}d [telegram]")
    errors = _rerender(ctx)
    _show_user(ctx, message_id, user_id, note=_rerender_note(ctx, errors))
    return t["bot_extended"].format(days=days)


def _show_reset_confirm(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    _show(
        ctx,
        message_id,
        t["bot_reset_confirm"].format(name=h(user.name)),
        _kb(
            [
                [
                    (t["bot_confirm_yes"], f"u:rst:{user_id}:ok"),
                    (t["bot_confirm_no"], f"u:v:{user_id}"),
                ]
            ]
        ),
    )


def _reset_traffic(ctx: _Ctx, message_id: Optional[int], user_id: int) -> Optional[str]:
    """Zero the running traffic counter (daily history is kept — same
    as the web bulk traffic reset)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    user.traffic_used_bytes = 0
    ctx.db.commit()
    _audit(ctx, "user.reset_traffic", f"{user.name} [telegram]")
    errors = _rerender(ctx)
    _show_user(ctx, message_id, user_id, note=_rerender_note(ctx, errors))
    return t["bot_traffic_reset"]


def _show_delete_confirm(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return
    _show(
        ctx,
        message_id,
        t["bot_delete_confirm"].format(name=h(user.name)),
        _kb(
            [
                [
                    (t["bot_confirm_yes"], f"u:del:{user_id}:ok"),
                    (t["bot_confirm_no"], f"u:v:{user_id}"),
                ]
            ]
        ),
    )


def _delete_user(ctx: _Ctx, message_id: Optional[int], user_id: int) -> Optional[str]:
    """Delete the user and its clients (same as the web delete route)."""
    t = ctx.t
    user = ctx.db.get(User, user_id)
    if user is None:
        _show(
            ctx,
            message_id,
            t["bot_user_not_found"],
            _kb([[(t["bot_back_users"], "u:list:0")]]),
        )
        return None
    name = user.name
    ctx.db.query(Client).filter(Client.user_id == user.id).delete()
    ctx.db.delete(user)
    ctx.db.commit()
    _audit(ctx, "user.delete", f"{name} [telegram]")
    errors = _rerender(ctx)
    _show_users(ctx, message_id, page=0, note=_rerender_note(ctx, errors))
    return t["bot_deleted"]


def _on_user_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> Optional[str]:
    if len(parts) < 2:
        _show_stale(ctx, message_id)
        return None
    action = parts[1]
    if action == "list":
        page = _parse_int(parts[2]) if len(parts) > 2 else 0
        # Paging through search results keeps the query (it lives in
        # the conversation state — see _on_callback).
        query = None
        conv = _get_conversation(ctx.chat_id)
        if conv is not None and conv["step"] == "search_results":
            query = conv["data"].get("query")
        _show_users(ctx, message_id, page or 0, query=query)
        return None
    if action == "new":
        _start_create(ctx, message_id)
        return None
    if action == "search":
        _start_search(ctx, message_id)
        return None
    if action == "clear":
        # The conversation (and its query) is already ended by the
        # dispatcher for non-"c:" taps — show the unfiltered list.
        _show_users(ctx, message_id, page=0)
        return None
    if action in ("cv", "det", "mv", "cfrz", "cunfrz", "cfl"):
        # Per-client actions: parts[2] is a CLIENT id, not a user id.
        client_id = _parse_int(parts[2]) if len(parts) > 2 else None
        if client_id is None:
            _show_stale(ctx, message_id)
            return None
        if action == "cv":
            _show_client(ctx, message_id, client_id)
        elif action == "det":
            if len(parts) > 3 and parts[3] == "ok":
                return _detach_client(ctx, message_id, client_id)
            _show_detach_confirm(ctx, message_id, client_id)
        elif action == "mv":
            if len(parts) > 3:
                target_id = _parse_int(parts[3])
                if target_id:
                    return _move_client(ctx, message_id, client_id, target_id)
                _show_stale(ctx, message_id)
            else:
                _show_move_picker(ctx, message_id, client_id)
        elif action == "cfrz":
            return _freeze_client(ctx, message_id, client_id, True)
        elif action == "cunfrz":
            return _freeze_client(ctx, message_id, client_id, False)
        elif action == "cfl":
            if len(parts) > 3:
                return _set_client_flow(ctx, message_id, client_id, parts[3])
            _show_flow_picker(ctx, message_id, client_id)
        return None
    user_id = _parse_int(parts[2]) if len(parts) > 2 else None
    if user_id is None:
        _show_stale(ctx, message_id)
        return None
    if action == "v":
        _show_user(ctx, message_id, user_id)
    elif action == "links":
        _send_links(ctx, message_id, user_id)
    elif action == "cl":
        _show_clients(ctx, message_id, user_id)
    elif action == "add":
        if len(parts) > 3:
            inbound_id = _parse_int(parts[3])
            if inbound_id:
                return _add_user_to_inbound(ctx, message_id, user_id, inbound_id)
            _show_stale(ctx, message_id)
        else:
            _show_add_inbound(ctx, message_id, user_id)
    elif action == "edit":
        if len(parts) > 3:
            _start_edit(ctx, message_id, user_id, parts[3])
        else:
            _show_edit_menu(ctx, message_id, user_id)
    elif action == "frz":
        return _freeze_user(ctx, message_id, user_id, True)
    elif action == "unfrz":
        return _freeze_user(ctx, message_id, user_id, False)
    elif action == "ext":
        if len(parts) > 3:
            days = _parse_int(parts[3])
            if days and days > 0:
                return _extend_user(ctx, message_id, user_id, days)
        else:
            _show_extend_menu(ctx, message_id, user_id)
    elif action == "rst":
        if len(parts) > 3 and parts[3] == "ok":
            return _reset_traffic(ctx, message_id, user_id)
        _show_reset_confirm(ctx, message_id, user_id)
    elif action == "del":
        if len(parts) > 3 and parts[3] == "ok":
            return _delete_user(ctx, message_id, user_id)
        _show_delete_confirm(ctx, message_id, user_id)
    else:
        _show_stale(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Inbounds (list / view / toggle)
# ---------------------------------------------------------------------------


def _show_inbounds(
    ctx: _Ctx,
    message_id: Optional[int],
    page: int = 0,
    note: Optional[str] = None,
) -> None:
    """The inbound list, paginated like the user list (8 per page).

    Client counts come from the one grouped query in
    ``clients_count_by_inbound`` — the per-inbound COUNT this used to
    issue was the bot's last N+1 (debug pass, 2026-11-15).
    """
    t = ctx.t
    inbounds = ctx.db.query(Inbound).order_by(Inbound.port, Inbound.tag).all()
    pages = max(1, (len(inbounds) + INBOUNDS_PAGE_SIZE - 1) // INBOUNDS_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    rows = inbounds[page * INBOUNDS_PAGE_SIZE : (page + 1) * INBOUNDS_PAGE_SIZE]
    counts = ctx.panel.clients_count_by_inbound(ctx.db)
    lines = [
        _b(t["bot_inbounds_title"].format(page=page + 1, pages=pages)),
        "",
    ]
    kb_rows: list[list[tuple[str, str]]] = []
    if not inbounds:
        lines.append(t["bot_no_inbounds"])
    tag_buttons: list[tuple[str, str]] = []
    for inbound in rows:
        emoji = "✅" if inbound.enabled else "❌"
        count = counts.get(inbound.id, 0)
        lines.append(
            f"{emoji} {h(inbound.tag)} — {inbound.protocol}:{inbound.port} "
            f"({count} {t['clients']})"
        )
        tag_buttons.append((inbound.tag, f"i:v:{inbound.id}"))
    # Two tag buttons per row (button text is plain — never escaped).
    for i in range(0, len(tag_buttons), 2):
        kb_rows.append(tag_buttons[i : i + 2])
    nav: list[tuple[str, str]] = []
    if page > 0:
        nav.append((t["bot_prev"], f"i:list:{page - 1}"))
    if page < pages - 1:
        nav.append((t["bot_next"], f"i:list:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([(t["bot_new_inbound"], "i:new")])
    kb_rows.append([(t["bot_back_main"], "m:main")])
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    _show(ctx, message_id, text, _kb(kb_rows))


# ---------------------------------------------------------------------------
# Inbound create (guided: protocol -> port -> SNI) + delete
# ---------------------------------------------------------------------------


def _bot_inbound_transport(panel: Any, protocol: str) -> str:
    """Transport for a bot-created inbound — the same rule as the
    web create route: the protocol default (UDP for hysteria2 /
    tuic / wireguard / amneziawg / openvpn), with IKEv2 and
    AmneziaWG forced UDP and OpenConnect forced TCP. The clash check
    depends on it: Hysteria2 on UDP 443 must not "clash" with VLESS
    on TCP 443, and a second Hysteria2 on UDP 443 must."""
    transport = panel._stream_transport({}, protocol)
    if protocol in ("ikev2", "amneziawg"):
        transport = "udp"
    elif protocol == "openconnect":
        transport = "tcp"
    return transport


def _show_inbound_protocol_picker(ctx: _Ctx, message_id: Optional[int]) -> None:
    """First step of the inbound-create flow: pick a protocol."""
    t = ctx.t
    protos = [
        (protocol.upper(), f"i:new:{protocol}")
        for protocol in BOT_CREATE_PROTOCOLS
    ]
    rows = [protos[i : i + 2] for i in range(0, len(protos), 2)]
    rows.append([(t["bot_cancel"], "c:cancel")])
    _show(ctx, message_id, t["bot_create_inbound_protocol"], _kb(rows))


def _start_inbound_create(ctx: _Ctx, message_id: Optional[int], protocol: str) -> None:
    """Second step: ask for the port (the Auto button picks one)."""
    if protocol not in BOT_CREATE_PROTOCOLS:
        _show_stale(ctx, message_id)
        return
    _start_conversation(ctx.chat_id, "inb_port", {"protocol": protocol})
    _show(
        ctx,
        message_id,
        ctx.t["bot_create_inbound_port"],
        _flow_kb(ctx.t, "bot_skip_auto"),
    )


def _flow_inbound_port(ctx: _Ctx, conv: dict, text: str) -> None:
    """Inbound-create step 2: the port (the Auto button picks one).

    Validation is the shared ``_check_new_inbound`` helper (same
    checks as the web create route: range, reserved ports, clash).
    Every error reply carries the step keyboard, so the admin can
    always tap Auto or Back instead of retyping.
    """
    t = ctx.t
    protocol = conv["data"]["protocol"]
    transport = _bot_inbound_transport(ctx.panel, protocol)
    kb = _flow_kb(t, "bot_skip_auto")
    raw = text.strip()
    if not raw:
        try:
            port = ctx.panel.suggest_protocol_port(ctx.db, protocol, transport)
        except ValueError:
            ctx.sender.send(
                ctx.chat_id, t["bot_create_inbound_port_invalid"], reply_markup=kb
            )
            return
    else:
        port = _parse_int(raw)
        if port is None:
            ctx.sender.send(
                ctx.chat_id, t["bot_create_inbound_port_invalid"], reply_markup=kb
            )
            return
    # The tag is auto-generated at create time (unique by
    # construction), so the check runs against a placeholder tag —
    # only the port errors can fire here.
    check = ctx.panel._check_new_inbound(
        ctx.db, protocol, port, f"__bot_check_{port}", transport
    )
    if check == "invalid_port":
        ctx.sender.send(
            ctx.chat_id, t["bot_create_inbound_port_invalid"], reply_markup=kb
        )
        return
    if check == "port_reserved":
        ctx.sender.send(
            ctx.chat_id, t["bot_create_inbound_port_reserved"], reply_markup=kb
        )
        return
    if check == "port_in_use":
        ctx.sender.send(
            ctx.chat_id, t["bot_create_inbound_port_in_use"], reply_markup=kb
        )
        return
    conv["data"]["port"] = port
    conv["data"]["transport"] = transport
    conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
    if protocol in BOT_SNI_PROTOCOLS:
        settings = ctx.panel.get_settings(ctx.db)
        default_sni = (settings.get("reality_sni") or "").strip() or "www.microsoft.com"
        conv["data"]["default_sni"] = default_sni
        conv["step"] = "inb_sni"
        ctx.sender.send(
            ctx.chat_id,
            t["bot_create_inbound_sni"].format(
                protocol=protocol.upper(), sni=h(default_sni)
            ),
            reply_markup=_flow_kb(t, "bot_skip_default"),
        )
        return
    _create_inbound_from_flow(ctx, conv)


def _flow_inbound_sni(ctx: _Ctx, conv: dict, text: str) -> None:
    """Inbound-create step 3: the SNI (the Default button keeps the
    panel default)."""
    sni = text.strip() or conv["data"].get("default_sni") or "www.microsoft.com"
    conv["data"]["sni"] = sni
    _create_inbound_from_flow(ctx, conv)


def _create_inbound_from_flow(ctx: _Ctx, conv: dict) -> None:
    """Create the inbound — the same stream shape as the web create
    route: auto tag, fresh Reality keypair for VLESS, the native
    cores' default subnets (and fresh AmneziaWG obfuscation params),
    SNI block for the Xray / sing-box cores."""
    t = ctx.t
    protocol = conv["data"]["protocol"]
    port = conv["data"]["port"]
    core = BOT_PROTOCOL_CORES[protocol]
    transport = conv["data"].get("transport") or _bot_inbound_transport(
        ctx.panel, protocol
    )
    tag = ctx.panel.suggest_inbound_tag(ctx.db, protocol, port)
    # Re-validate at create time: another admin may have taken the
    # port while this flow was running.
    check = ctx.panel._check_new_inbound(ctx.db, protocol, port, tag, transport)
    if check is not None:
        _end_conversation(ctx.chat_id)
        ctx.sender.send(
            ctx.chat_id, t["bot_create_inbound_failed"], reply_markup=_main_menu_kb(t)
        )
        return
    stream: dict[str, Any] = {"network": transport, "transport": transport}
    # Protocol-specific defaults, mirroring the web create route
    # (the renderers read these from the inbound stream).
    if protocol == "wireguard":
        stream["subnet"] = "10.8.0.0/24"
    elif protocol == "openvpn":
        stream["subnet"] = ctx.panel.openvpn_mod.DEFAULT_NETWORK
    elif protocol == "openconnect":
        stream["subnet"] = ctx.panel.openconnect_mod.DEFAULT_NETWORK
    elif protocol == "amneziawg":
        stream["subnet"] = ctx.panel.amneziawg_mod.DEFAULT_NETWORK
        stream["awg_params"] = ctx.panel.amneziawg_mod.generate_awg_params()
    elif protocol == "ikev2":
        stream["subnet"] = ctx.panel.ikev2_mod.DEFAULT_NETWORK
    sni = conv["data"].get("sni")
    if sni and core in ("xray", "singbox"):
        reality_block: dict[str, Any] = {"sni": sni, "dest": f"{sni}:443"}
        if protocol == "vless":
            pair = ctx.panel._new_reality_keypair()
            if pair:
                reality_block["private_key"] = pair["private_key"]
                reality_block["public_key"] = pair["public_key"]
                reality_block["short_id"] = secrets.token_hex(4)
        stream["reality"] = reality_block
        stream["tls"] = {"sni": sni}
        stream["security"] = "reality" if protocol == "vless" else "tls"
    _end_conversation(ctx.chat_id)
    try:
        inbound = Inbound(
            tag=tag,
            core=core,
            protocol=protocol,
            port=port,
            enabled=True,
            remark=None,
            stream_json=json.dumps(stream),
        )
        ctx.db.add(inbound)
        ctx.db.commit()
    except Exception:  # noqa: BLE001 — a failed create must say so
        ctx.db.rollback()
        logger.exception("telegram bot inbound creation failed")
        ctx.sender.send(
            ctx.chat_id, t["bot_create_inbound_failed"], reply_markup=_main_menu_kb(t)
        )
        return
    _audit(ctx, "inbound.create", f"{tag} {protocol}:{port} [telegram]")
    errors = _rerender(ctx)
    text_out = t["bot_create_inbound_done"].format(
        tag=h(tag), protocol=protocol, port=port
    )
    note = _rerender_note(ctx, errors)
    if note:
        text_out += "\n\n" + note
    ctx.sender.send(
        ctx.chat_id,
        text_out,
        reply_markup=_kb(
            [
                [(t["bot_back_inbounds"], "i:list")],
            ]
        ),
    )


def _show_inbound_delete_confirm(
    ctx: _Ctx, message_id: Optional[int], inbound_id: int
) -> None:
    """Delete confirmation (deleting an inbound deletes its clients
    too — same as the web delete route)."""
    t = ctx.t
    inbound = ctx.db.get(Inbound, inbound_id)
    if inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_inbound_not_found"],
            _kb([[(t["bot_back_inbounds"], "i:list")]]),
        )
        return
    _show(
        ctx,
        message_id,
        t["bot_inbound_delete_confirm"].format(tag=h(inbound.tag)),
        _kb(
            [
                [
                    (t["bot_confirm_yes"], f"i:del:{inbound_id}:ok"),
                    (t["bot_confirm_no"], f"i:v:{inbound_id}"),
                ]
            ]
        ),
    )


def _delete_inbound(
    ctx: _Ctx, message_id: Optional[int], inbound_id: int
) -> Optional[str]:
    """Delete the inbound and its clients (same as the web route)."""
    t = ctx.t
    inbound = ctx.db.get(Inbound, inbound_id)
    if inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_inbound_not_found"],
            _kb([[(t["bot_back_inbounds"], "i:list")]]),
        )
        return None
    tag = inbound.tag
    ctx.db.query(Client).filter(Client.inbound_id == inbound.id).delete()
    ctx.db.delete(inbound)
    ctx.db.commit()
    _audit(ctx, "inbound.delete", f"{tag} [telegram]")
    errors = _rerender(ctx)
    _show_inbounds(ctx, message_id, note=_rerender_note(ctx, errors))
    return t["bot_inbound_deleted"]


def _show_inbound(
    ctx: _Ctx, message_id: Optional[int], inbound_id: int, note: Optional[str] = None
) -> None:
    t = ctx.t
    inbound = ctx.db.get(Inbound, inbound_id)
    if inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_inbound_not_found"],
            _kb([[(t["bot_back_inbounds"], "i:list")]]),
        )
        return
    count = ctx.db.query(Client).filter(Client.inbound_id == inbound.id).count()
    lines = [
        _b(f"📡 {h(inbound.tag)}"),
        f"{_b(t['status'] + ':')} {'✅ ' + t['enabled'] if inbound.enabled else '❌ ' + t['disabled']}",
        f"{_b(t['protocol'] + ':')} {inbound.protocol}",
        f"{_b(t['core'] + ':')} {inbound.core}",
        f"{_b(t['port'] + ':')} {inbound.port}",
        f"{_b(t['clients'] + ':')} {count}",
    ]
    if inbound.remark:
        lines.append(f"{_b(t['remark'] + ':')} {h(inbound.remark)}")
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    toggle_label = t["bot_disable"] if inbound.enabled else t["bot_enable"]
    _show(
        ctx,
        message_id,
        text,
        _kb(
            [
                [(toggle_label, f"i:tg:{inbound.id}"), (t["bot_delete"], f"i:del:{inbound.id}")],
                [(t["bot_back_inbounds"], "i:list")],
            ]
        ),
    )


def _toggle_inbound(ctx: _Ctx, message_id: Optional[int], inbound_id: int) -> Optional[str]:
    """Flip one inbound's enabled flag (same as the web toggle route)."""
    t = ctx.t
    inbound = ctx.db.get(Inbound, inbound_id)
    if inbound is None:
        _show(
            ctx,
            message_id,
            t["bot_inbound_not_found"],
            _kb([[(t["bot_back_inbounds"], "i:list")]]),
        )
        return None
    inbound.enabled = not inbound.enabled
    ctx.db.commit()
    _audit(
        ctx,
        "inbound.toggle",
        f"{inbound.tag} enabled={inbound.enabled} [telegram]",
    )
    errors = _rerender(ctx)
    _show_inbound(ctx, message_id, inbound_id, note=_rerender_note(ctx, errors))
    state = t["bot_status_enabled"] if inbound.enabled else t["bot_status_disabled"]
    return t["bot_inbound_toggled"].format(state=state)


def _on_inbound_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> Optional[str]:
    action = parts[1] if len(parts) > 1 else ""
    if action == "list":
        page = _parse_int(parts[2]) if len(parts) > 2 else 0
        _show_inbounds(ctx, message_id, page or 0)
        return None
    if action == "new":
        if len(parts) > 2:
            _start_inbound_create(ctx, message_id, parts[2])
        else:
            _show_inbound_protocol_picker(ctx, message_id)
        return None
    inbound_id = _parse_int(parts[2]) if len(parts) > 2 else None
    if inbound_id is None:
        _show_stale(ctx, message_id)
        return None
    if action == "v":
        _show_inbound(ctx, message_id, inbound_id)
    elif action == "tg":
        return _toggle_inbound(ctx, message_id, inbound_id)
    elif action == "del":
        if len(parts) > 3 and parts[3] == "ok":
            return _delete_inbound(ctx, message_id, inbound_id)
        _show_inbound_delete_confirm(ctx, message_id, inbound_id)
    else:
        _show_stale(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Server status
# ---------------------------------------------------------------------------


def _show_status(ctx: _Ctx, message_id: Optional[int]) -> None:
    """Server status (``app.system_status``) + traffic summary from
    ``traffic_daily``. A section whose data is unavailable is skipped,
    never invented."""
    t = ctx.t
    lines = [_b(t["bot_status_title"]), ""]
    status = None
    if system_status_mod is not None:
        try:
            status = system_status_mod.collect_server_status(ctx.panel.DATA_DIR)
        except Exception:  # noqa: BLE001 — status must never break the bot
            status = None
    if status is not None:
        load = status.get("load")
        if load:
            lines.append(
                f"{_b(t['cpu_load'] + ':')} {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
            )
        mem = status.get("memory")
        if mem:
            lines.append(
                f"{_b(t['memory'] + ':')} "
                f"{_format_bytes(mem['total'] - mem['available'])} / "
                f"{_format_bytes(mem['total'])}"
            )
        disk = status.get("disk")
        if disk:
            lines.append(
                f"{_b(t['disk'] + ':')} {_format_bytes(disk['used'])} / "
                f"{_format_bytes(disk['total'])}"
            )
        lines.append(f"{_b(t['uptime'] + ':')} {h(status.get('uptime') or '—')}")
        services = status.get("services") or {}
        if services:
            parts = []
            for key, state in services.items():
                emoji = {"running": "✅", "stopped": "❌"}.get(state, "❓")
                parts.append(f"{_SERVICE_NAMES.get(key, key)} {emoji}")
            lines.append("")
            lines.append(" | ".join(parts))
    users = ctx.db.query(User).all()
    enabled = sum(1 for u in users if u.enabled)
    expired = sum(
        1
        for u in users
        if u.expires_at is not None and _aware(u.expires_at) <= ctx.now
    )
    lines.append("")
    lines.append(
        t["bot_status_users"].format(
            total=len(users), enabled=enabled, expired=expired
        )
    )
    today_total, total_14d = _traffic_summary(ctx)
    lines.append(f"{_b(t['bot_traffic_today'] + ':')} {_format_bytes(today_total)}")
    lines.append(f"{_b(t['bot_traffic_14d'] + ':')} {_format_bytes(total_14d)}")
    _show(ctx, message_id, "\n".join(lines), _kb([[(t["bot_back_main"], "m:main")]]))


# ---------------------------------------------------------------------------
# Services (status + restart with confirmation)
# ---------------------------------------------------------------------------


def _service_states(ctx: _Ctx) -> dict[str, str]:
    """Service states from ``app.system_status`` (the same source as
    the web settings page) — ``{key: running|stopped|unknown}``.
    An unavailable collector yields all-unknown, never a crash."""
    if system_status_mod is None:
        return {key: "unknown" for key in _SERVICE_NAMES}
    try:
        status = system_status_mod.collect_server_status(ctx.panel.DATA_DIR)
        services = (status or {}).get("services") or {}
        return {
            key: services.get(key, "unknown") for key in _SERVICE_NAMES
        }
    except Exception:  # noqa: BLE001 — status must never break the bot
        return {key: "unknown" for key in _SERVICE_NAMES}


def _show_services(
    ctx: _Ctx, message_id: Optional[int], note: Optional[str] = None
) -> None:
    """Every service with its state; a restart button for each
    service the panel may actually restart (see
    ``_SERVICE_RESTART_UNITS`` — all 7 cores since sudoers v15)."""
    t = ctx.t
    states = _service_states(ctx)
    state_labels = {
        "running": t["bot_service_running"],
        "stopped": t["bot_service_stopped"],
        "unknown": t["bot_service_unknown"],
    }
    state_emoji = {"running": "✅", "stopped": "❌"}.get
    lines = [_b(t["bot_services_title"]), ""]
    kb_rows: list[list[tuple[str, str]]] = []
    for key in _SERVICE_NAMES:
        state = states.get(key, "unknown")
        emoji = state_emoji(state, "❓")
        lines.append(
            f"{emoji} {_b(_SERVICE_NAMES[key])} — "
            f"{state_labels.get(state, t['bot_service_unknown'])}"
        )
        if key in _SERVICE_RESTART_UNITS:
            kb_rows.append(
                [(f"{t['bot_service_restart']} {_SERVICE_NAMES[key]}", f"s:rst:{key}")]
            )
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    kb_rows.append([(t["bot_back_main"], "m:main")])
    _show(ctx, message_id, text, _kb(kb_rows))


def _show_restart_confirm(ctx: _Ctx, message_id: Optional[int], key: str) -> None:
    t = ctx.t
    if key not in _SERVICE_RESTART_UNITS:
        _show_stale(ctx, message_id)
        return
    _show(
        ctx,
        message_id,
        t["bot_service_restart_confirm"].format(name=_SERVICE_NAMES[key]),
        _kb(
            [
                [
                    (t["bot_confirm_yes"], f"s:rst:{key}:ok"),
                    (t["bot_confirm_no"], "s:list"),
                ]
            ]
        ),
    )


def _restart_service_via_bot(
    ctx: _Ctx, message_id: Optional[int], key: str
) -> Optional[str]:
    """Restart one service (``systemctl restart`` via the panel's
    privileged runner — the same call the re-render path uses) and
    report the honest result: success only when the service is
    actually running afterwards, failure with the error text."""
    t = ctx.t
    unit = _SERVICE_RESTART_UNITS.get(key)
    if unit is None:
        _show_stale(ctx, message_id)
        return None
    name = _SERVICE_NAMES[key]
    try:
        error = ctx.panel._restart_service(unit)
    except Exception:  # noqa: BLE001 — a restart failure must say so
        logger.exception("telegram bot service restart failed")
        error = t["bot_action_failed"]
    if error is not None:
        note = _failure_note(
            ctx,
            t["bot_service_restart_failed"].format(name=name),
            str(error),
            f"{key}-restart-error.log",
        )
        _show_services(ctx, message_id, note=note)
        return None
    # A zero exit code is not proof the service is up — re-check.
    # "unknown" is neither success nor failure: the restart ran, but
    # the state could not be verified (no systemd answer).
    state = _service_states(ctx).get(key, "unknown")
    if state == "stopped":
        note = (
            t["bot_service_restart_failed"].format(name=name)
            + " "
            + t["bot_service_stopped"]
        )
        _show_services(ctx, message_id, note=note)
        return None
    _audit(ctx, "service.restart", f"{key} [telegram]")
    if state == "running":
        note = t["bot_service_restarted"].format(name=name)
    else:
        note = t["bot_service_restart_unverified"].format(name=name)
    _show_services(ctx, message_id, note=note)
    return note


def _on_service_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> Optional[str]:
    action = parts[1] if len(parts) > 1 else ""
    if action == "list":
        _show_services(ctx, message_id)
        return None
    if action == "rst":
        key = parts[2] if len(parts) > 2 else ""
        if not key:
            _show_stale(ctx, message_id)
            return None
        if len(parts) > 3 and parts[3] == "ok":
            return _restart_service_via_bot(ctx, message_id, key)
        _show_restart_confirm(ctx, message_id, key)
        return None
    _show_stale(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Backup (create the ZIP and send it as a document to the admin chat)
# ---------------------------------------------------------------------------


def _show_backup(ctx: _Ctx, message_id: Optional[int]) -> None:
    t = ctx.t
    text = _b(t["bot_backup_title"]) + "\n\n" + t["bot_backup_hint"]
    _show(
        ctx,
        message_id,
        text,
        _kb(
            [
                [(t["bot_backup_send"], "b:get")],
                [(t["bot_back_main"], "m:main")],
            ]
        ),
    )


def _send_backup(ctx: _Ctx, message_id: Optional[int]) -> None:
    """Create the backup ZIP (same builder as the settings-page
    download) and send it to the admin chat — and ONLY there: the
    dispatcher verified this chat is the configured admin chat, and
    the ZIP is a full credential bundle. A ZIP over Telegram's 50 MB
    bot-API cap is refused honestly (the web download still works).
    """
    t = ctx.t
    if ctx.panel.backup_mod is None:
        _show(
            ctx,
            message_id,
            t["bot_backup_failed"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
        return
    db_path = ctx.panel._db_file_path(ctx.db)
    if db_path is None or not db_path.exists():
        _show(
            ctx,
            message_id,
            t["bot_backup_failed"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
        return
    try:
        data = ctx.panel.backup_mod.create_backup_zip(db_path)
    except Exception:  # noqa: BLE001 — a failed backup must say so
        logger.exception("telegram bot backup creation failed")
        _show(
            ctx,
            message_id,
            t["bot_backup_failed"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
        return
    if len(data) > telegram_mod.MAX_DOCUMENT_BYTES:
        _show(
            ctx,
            message_id,
            t["bot_backup_too_large"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
        return
    stamp = ctx.now.strftime("%Y%m%d-%H%M%S")
    filename = f"sparky-manager-backup-{stamp}.zip"
    if not ctx.sender.document(ctx.chat_id, filename, data):
        _show(
            ctx,
            message_id,
            t["bot_backup_failed"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
        return
    _audit(ctx, "settings.backup", f"{len(data)} bytes [telegram]")
    _show(
        ctx,
        message_id,
        t["bot_backup_sent"],
        _kb([[(t["bot_back_main"], "m:main")]]),
    )


def _on_backup_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> Optional[str]:
    action = parts[1] if len(parts) > 1 else ""
    if action == "menu":
        _show_backup(ctx, message_id)
        return None
    if action == "get":
        _send_backup(ctx, message_id)
        return None
    _show_stale(ctx, message_id)
    return None


__all__ = [
    "BOT_LANGUAGE",
    "BOT_COMMANDS",
    "BOT_STRING_KEYS",
    "CONVERSATION_TIMEOUT",
    "TelegramSender",
    "handle_update",
]
