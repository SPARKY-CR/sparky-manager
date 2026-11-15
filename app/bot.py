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
- No secrets are ever sent in chat (no tokens, no passwords) and
  update payloads are never logged.
- Duplicate ``update_id`` values are ignored (Telegram redelivers).

State (in-memory only — no DB schema change)
--------------------------------------------
- ``_conversations``: per-chat guided-flow state (the create-user
  flow), with a 10-minute timeout. ``/cancel`` aborts it; any other
  command or menu tap abandons it.
- ``_seen_updates``: processed update ids, pruned after an hour.

Callback data is ``family:action:args`` (``m:`` menu, ``u:`` user,
``i:`` inbound, ``c:`` create flow) — short on purpose, well under
Telegram's 64-byte callback-data limit.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from app import telegram as telegram_mod
from app.models import Admin, Client, Inbound, TrafficDaily, User, client_is_frozen

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

# Guided-flow state expires after 10 minutes of inactivity.
CONVERSATION_TIMEOUT = 600.0
# Processed update ids are remembered for an hour (Telegram redelivery
# windows are seconds, not hours; the cap bounds memory either way).
SEEN_UPDATE_TTL = 3600.0
MAX_SEEN_UPDATES = 5000
USERS_PAGE_SIZE = 8
# Bot API messages cap at 4096 chars; chunk long texts below that.
MESSAGE_CHUNK = 4000

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

    The three methods are the whole surface the dispatcher needs; tests
    inject a fake with the same methods. ``send`` returns False (never
    raises) when Telegram is unreachable — the dispatcher treats a
    failed reply as "the admin did not see it" and moves on.
    """

    def __init__(self, token: str):
        self.token = token

    def send(
        self, chat_id: int, text: str, reply_markup: Optional[dict] = None
    ) -> bool:
        return telegram_mod.send_message(
            self.token, str(chat_id), text, reply_markup=reply_markup
        )

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
        )

    def answer(self, callback_query_id: str, text: Optional[str] = None) -> bool:
        return telegram_mod.answer_callback_query(
            self.token, callback_query_id, text=text
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


def _main_menu_kb(t: dict[str, str]) -> dict[str, Any]:
    return _kb(
        [
            [(t["bot_menu_users"], "m:users"), (t["bot_menu_inbounds"], "m:inb")],
            [(t["bot_menu_status"], "m:status"), (t["bot_menu_help"], "m:help")],
        ]
    )


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


def _rerender_note(ctx: _Ctx, errors: list[str]) -> Optional[str]:
    """One-line warning appended to a reply when re-rendering failed."""
    if not errors:
        return None
    return "⚠️ " + ctx.t["bot_rerender_failed"] + " " + "; ".join(errors)[:400]


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
    """``/start`` / ``/help`` / ``/cancel`` (a ``@botname`` suffix is
    stripped, so the commands work in groups too — though only the
    admin chat ever reaches this code)."""
    t = ctx.t
    command = text.split()[0].split("@")[0].lower()
    if command == "/cancel":
        _end_conversation(ctx.chat_id)
        ctx.sender.send(ctx.chat_id, t["bot_cancelled"], reply_markup=_main_menu_kb(t))
        return
    _end_conversation(ctx.chat_id)  # any other command abandons the flow
    if command == "/start":
        ctx.sender.send(ctx.chat_id, t["bot_welcome"], reply_markup=_main_menu_kb(t))
    elif command == "/help":
        ctx.sender.send(ctx.chat_id, t["bot_help"], reply_markup=_main_menu_kb(t))
    else:
        ctx.sender.send(
            ctx.chat_id, t["bot_unknown_command"], reply_markup=_main_menu_kb(t)
        )


def _on_text(ctx: _Ctx, text: str) -> None:
    """Free text: a guided-flow step, or the menu hint when idle."""
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
        t["bot_create_name"],
        _kb([[(t["bot_cancel"], "c:cancel")]]),
    )


def _flow_name(ctx: _Ctx, conv: dict, text: str) -> None:
    """Create step 1: the name (same rules as the web form)."""
    t = ctx.t
    name = text.strip()
    if not ctx.panel.NAME_RE.match(name):
        ctx.sender.send(ctx.chat_id, t["bot_create_name_invalid"])
        return
    if ctx.db.query(User).filter(User.name == name).first() is not None:
        ctx.sender.send(ctx.chat_id, t["bot_create_name_exists"])
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
    """Create step 3: traffic limit in GB (0 / empty = unlimited)."""
    t = ctx.t
    raw = text.strip().replace(",", ".")
    if raw in ("", "0", "0.0"):
        conv["data"]["limit_bytes"] = None
    else:
        try:
            gb = float(raw)
            if gb <= 0:
                raise ValueError
            conv["data"]["limit_bytes"] = int(gb * 1024**3)
        except ValueError:
            ctx.sender.send(ctx.chat_id, t["bot_create_limit_invalid"])
            return
    conv["step"] = "expiry"
    conv["expires"] = time.monotonic() + CONVERSATION_TIMEOUT
    ctx.sender.send(ctx.chat_id, t["bot_create_expiry"])


def _flow_expiry(ctx: _Ctx, conv: dict, text: str) -> None:
    """Create step 4: expiry in days (0 / empty = never), then create."""
    t = ctx.t
    raw = text.strip()
    if raw in ("", "0"):
        expires_at = None
    else:
        try:
            days = int(raw)
            if days <= 0:
                raise ValueError
            expires_at = ctx.now + timedelta(days=days)
        except ValueError:
            ctx.sender.send(ctx.chat_id, t["bot_create_expiry_invalid"])
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
    text_out = t["bot_create_done"].format(name=name)
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
    """Create-flow buttons: toggle an inbound, confirm, or cancel."""
    t = ctx.t
    action = parts[1] if len(parts) > 1 else ""
    if action == "cancel":
        _end_conversation(ctx.chat_id)
        _show(ctx, message_id, t["bot_cancelled"], _main_menu_kb(t))
        return None
    conv = _get_conversation(ctx.chat_id)
    if conv is None or conv["step"] != "inbounds":
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
            _kb([[(t["bot_cancel"], "c:cancel")]]),
        )
        return None
    return None


# ---------------------------------------------------------------------------
# Callback router
# ---------------------------------------------------------------------------


def _on_callback(ctx: _Ctx, message_id: Optional[int], data: str) -> Optional[str]:
    """Route one button tap. Returns a toast string (or None) for the
    dispatcher to answer with."""
    parts = (data or "").split(":")
    if not parts or not parts[0]:
        return None
    family = parts[0]
    if family == "c":
        return _on_create_callback(ctx, message_id, parts)
    # Any other tap abandons an in-progress create flow — the admin
    # clearly moved on to something else.
    _end_conversation(ctx.chat_id)
    if family == "m":
        return _on_menu_callback(ctx, message_id, parts)
    if family == "u":
        return _on_user_callback(ctx, message_id, parts)
    if family == "i":
        return _on_inbound_callback(ctx, message_id, parts)
    return None


def _on_menu_callback(ctx: _Ctx, message_id: Optional[int], parts: list) -> None:
    t = ctx.t
    action = parts[1] if len(parts) > 1 else ""
    if action == "main":
        _show(ctx, message_id, t["bot_welcome"], _main_menu_kb(t))
    elif action == "help":
        _show(
            ctx,
            message_id,
            t["bot_help"],
            _kb([[(t["bot_back_main"], "m:main")]]),
        )
    elif action == "users":
        _show_users(ctx, message_id, page=0)
    elif action == "inb":
        _show_inbounds(ctx, message_id)
    elif action == "status":
        _show_status(ctx, message_id)
    return None


# ---------------------------------------------------------------------------
# Users (list / view / links / freeze / extend / reset / delete)
# ---------------------------------------------------------------------------


def _show_users(
    ctx: _Ctx, message_id: Optional[int], page: int, note: Optional[str] = None
) -> None:
    t = ctx.t
    users = ctx.db.query(User).order_by(User.created_at.desc()).all()
    pages = max(1, (len(users) + USERS_PAGE_SIZE - 1) // USERS_PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    rows = users[page * USERS_PAGE_SIZE : (page + 1) * USERS_PAGE_SIZE]
    lines = [t["bot_users_title"].format(page=page + 1, pages=pages), ""]
    if not users:
        lines.append(t["bot_no_users"])
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
            f"{emoji} {user.name} — "
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
    kb_rows.append([(t["bot_new_user"], "u:new")])
    kb_rows.append([(t["bot_back_main"], "m:main")])
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    _show(ctx, message_id, text, _kb(kb_rows))


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
        name = inbound.tag
        if client_is_frozen(client):
            name += " 🧊"
        inbound_names.append(name)
    lines = [
        f"👤 {user.name}",
        f"{t['status']}: {emoji} {label}",
        f"{t['bot_traffic']}: {_format_bytes(user.traffic_used_bytes or 0)} / {limit}",
        f"{t['bot_expires']}: {_expiry_text(ctx, user)}",
        f"{t['bot_inbounds']}: {', '.join(inbound_names) if inbound_names else '—'}",
    ]
    text = "\n".join(lines)
    if note:
        text += "\n\n" + note
    frozen = _user_frozen(ctx, user)
    kb_rows: list[list[tuple[str, str]]] = [
        [(t["bot_links"], f"u:links:{user.id}")],
        [
            (
                t["bot_unfreeze"] if frozen else t["bot_freeze"],
                f"u:{'unfrz' if frozen else 'frz'}:{user.id}",
            )
        ],
        [
            (t["bot_extend"], f"u:ext:{user.id}"),
            (t["bot_reset_traffic"], f"u:rst:{user.id}"),
        ],
        [(t["bot_delete"], f"u:del:{user.id}")],
        [(t["bot_back_users"], "u:list:0")],
    ]
    _show(ctx, message_id, text, _kb(kb_rows))


def _send_links(ctx: _Ctx, message_id: Optional[int], user_id: int) -> None:
    """The user's share links + subscription link (same links the panel
    generates). A host is required for share links (subscription_host
    or domain setting); the subscription URL additionally needs a
    domain — without one the admin gets an honest message, not a
    broken link."""
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
    sub_url = ctx.panel._public_panel_url(settings, f"/sub/{user.sub_token}")
    if not links and not sub_url:
        _show(
            ctx,
            message_id,
            t["bot_no_links"],
            _kb([[(t["bot_back"], f"u:v:{user_id}")]]),
        )
        return
    lines = [t["bot_links_title"].format(name=user.name), ""]
    if sub_url:
        lines.append(f"{t['bot_sub_link']}:")
        lines.append(sub_url)
        lines.append("")
    for entry in links:
        lines.append(f"{entry['inbound'].tag}:")
        lines.append(entry["link"])
        lines.append("")
    _send_long(
        ctx,
        message_id,
        "\n".join(lines).rstrip("\n"),
        _kb([[(t["bot_back"], f"u:v:{user_id}")]]),
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
        t["bot_extend_prompt"].format(name=user.name),
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
        t["bot_reset_confirm"].format(name=user.name),
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
        t["bot_delete_confirm"].format(name=user.name),
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
        return None
    action = parts[1]
    if action == "list":
        page = _parse_int(parts[2]) if len(parts) > 2 else 0
        _show_users(ctx, message_id, page or 0)
        return None
    if action == "new":
        _start_create(ctx, message_id)
        return None
    user_id = _parse_int(parts[2]) if len(parts) > 2 else None
    if user_id is None:
        return None
    if action == "v":
        _show_user(ctx, message_id, user_id)
    elif action == "links":
        _send_links(ctx, message_id, user_id)
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
    return None


# ---------------------------------------------------------------------------
# Inbounds (list / view / toggle)
# ---------------------------------------------------------------------------


def _show_inbounds(ctx: _Ctx, message_id: Optional[int]) -> None:
    t = ctx.t
    inbounds = ctx.db.query(Inbound).order_by(Inbound.port, Inbound.tag).all()
    lines = [t["bot_inbounds_title"], ""]
    kb_rows: list[list[tuple[str, str]]] = []
    if not inbounds:
        lines.append(t["bot_no_inbounds"])
    for inbound in inbounds:
        emoji = "✅" if inbound.enabled else "❌"
        count = (
            ctx.db.query(Client).filter(Client.inbound_id == inbound.id).count()
        )
        lines.append(
            f"{emoji} {inbound.tag} — {inbound.protocol}:{inbound.port} "
            f"({count} {t['clients']})"
        )
        kb_rows.append([(inbound.tag, f"i:v:{inbound.id}")])
    kb_rows.append([(t["bot_back_main"], "m:main")])
    _show(ctx, message_id, "\n".join(lines), _kb(kb_rows))


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
        f"📡 {inbound.tag}",
        f"{t['status']}: {'✅ ' + t['enabled'] if inbound.enabled else '❌ ' + t['disabled']}",
        f"{t['protocol']}: {inbound.protocol}",
        f"{t['core']}: {inbound.core}",
        f"{t['port']}: {inbound.port}",
        f"{t['clients']}: {count}",
    ]
    if inbound.remark:
        lines.append(f"{t['remark']}: {inbound.remark}")
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
                [(toggle_label, f"i:tg:{inbound.id}")],
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
        _show_inbounds(ctx, message_id)
        return None
    inbound_id = _parse_int(parts[2]) if len(parts) > 2 else None
    if inbound_id is None:
        return None
    if action == "v":
        _show_inbound(ctx, message_id, inbound_id)
    elif action == "tg":
        return _toggle_inbound(ctx, message_id, inbound_id)
    return None


# ---------------------------------------------------------------------------
# Server status
# ---------------------------------------------------------------------------


def _show_status(ctx: _Ctx, message_id: Optional[int]) -> None:
    """Server status (``app.system_status``) + traffic summary from
    ``traffic_daily``. A section whose data is unavailable is skipped,
    never invented."""
    t = ctx.t
    lines = [t["bot_status_title"], ""]
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
                f"{t['cpu_load']}: {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
            )
        mem = status.get("memory")
        if mem:
            lines.append(
                f"{t['memory']}: "
                f"{_format_bytes(mem['total'] - mem['available'])} / "
                f"{_format_bytes(mem['total'])}"
            )
        disk = status.get("disk")
        if disk:
            lines.append(
                f"{t['disk']}: {_format_bytes(disk['used'])} / "
                f"{_format_bytes(disk['total'])}"
            )
        lines.append(f"{t['uptime']}: {status.get('uptime') or '—'}")
        services = status.get("services") or {}
        if services:
            names = {
                "xray": "Xray",
                "sing-box": "sing-box",
                "wireguard": "WireGuard",
                "amneziawg": "AmneziaWG",
                "openvpn": "OpenVPN",
                "openconnect": "OpenConnect",
                "ikev2": "IKEv2",
            }
            parts = []
            for key, state in services.items():
                emoji = {"running": "✅", "stopped": "❌"}.get(state, "❓")
                parts.append(f"{names.get(key, key)} {emoji}")
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
    lines.append(f"{t['bot_traffic_today']}: {_format_bytes(today_total)}")
    lines.append(f"{t['bot_traffic_14d']}: {_format_bytes(total_14d)}")
    _show(ctx, message_id, "\n".join(lines), _kb([[(t["bot_back_main"], "m:main")]]))


__all__ = [
    "BOT_LANGUAGE",
    "BOT_STRING_KEYS",
    "CONVERSATION_TIMEOUT",
    "TelegramSender",
    "handle_update",
]
