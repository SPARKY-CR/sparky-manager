"""Telegram Bot API — a small reusable client (Phase 3 sender, Phase 4 bot).

Phase 3 introduced the one-way notifier (``send_message``); Phase 4
adds the rest of the Bot API surface the management bot needs:
inline keyboards (``reply_markup``), message edits, callback answers,
and webhook registration / status. Everything still goes through one
private ``_post`` helper, so the security rules hold everywhere.

Security rules (never relax these):
- The bot token is NEVER logged, not even partially — not by this
  module, and callers must not log it either. ``mask_token`` exists
  only for UI display ("configured: …Ab12"). Error descriptions
  returned by Telegram are passed through to the caller, never
  logged here.
- Failures are reported as ``False`` / ``None``, never raised: a dead
  Telegram must never break a panel request or a background loop.
- ``httpx`` is a declared panel dependency (requirements.txt); every
  call uses a short timeout so a slow Telegram cannot hang a request.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("sparky-manager")

TELEGRAM_API_BASE = "https://api.telegram.org/bot"
DEFAULT_TIMEOUT = 10.0
# Bot API limit for a single message.
MAX_MESSAGE_LENGTH = 4096


def mask_token(token: str) -> str:
    """Display form of a bot token: last 4 chars only.

    Returns ``""`` for an empty token. The masked form is safe to show
    in the UI (it proves a token is configured without revealing it).
    """
    token = (token or "").strip()
    if not token:
        return ""
    if len(token) <= 4:
        return "••••"
    return "••••" + token[-4:]


def _post(
    token: str,
    method: str,
    payload: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """One Bot API call. Returns the parsed JSON dict, or ``None`` on
    any failure (missing token, missing httpx, transport error, HTTP
    error, bad JSON). Never raises, never logs the token — the log
    carries only the HTTP status code, because an error body can echo
    the request URL, which contains the token."""
    token = (token or "").strip()
    if not token or not method:
        return None
    try:
        import httpx
    except ImportError:
        logger.warning("telegram api call failed: httpx not installed")
        return None

    url = f"{TELEGRAM_API_BASE}{token}/{method}"
    try:
        response = httpx.post(url, json=payload or {}, timeout=timeout)
    except Exception:  # noqa: BLE001 — timeout / DNS / connect errors
        logger.warning("telegram api call failed: request error")
        return None
    if response.status_code != 200:
        # Log only the status code — the body may echo the request.
        logger.warning("telegram api call failed: HTTP %s", response.status_code)
        return None
    try:
        data = response.json()
    except ValueError:
        logger.warning("telegram api call failed: bad JSON response")
        return None
    if not isinstance(data, dict):
        logger.warning("telegram api call failed: bad JSON response")
        return None
    return data


def _ok(data: Optional[dict[str, Any]]) -> bool:
    """True when the Bot API answered ``{"ok": true}``."""
    return bool(data and data.get("ok"))


def send_message(
    token: str,
    chat_id: str,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Send ``text`` to ``chat_id`` via the Bot API. True on success.

    Returns False (never raises) when the token/chat id are missing,
    the text is empty, the request times out, Telegram answers with
    an error, or ``httpx`` is unavailable. The token is never logged.
    ``reply_markup`` (Phase 4) is an inline-keyboard dict; it is only
    sent when given, so notification calls keep the exact Phase 3
    payload.
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not token or not chat_id or not text:
        return False
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 1] + "…"

    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return _ok(_post(token, "sendMessage", payload, timeout=timeout))


def edit_message_text(
    token: str,
    chat_id: str,
    message_id: int,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Replace a sent message's text (and keyboard). True on success.

    False when the message cannot be edited (too old, deleted, or
    identical text) — the caller falls back to sending a new message.
    Same never-raise / never-log-the-token contract as ``send_message``.
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not token or not chat_id or not text or not message_id:
        return False
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 1] + "…"

    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return _ok(_post(token, "editMessageText", payload, timeout=timeout))


def answer_callback_query(
    token: str,
    callback_query_id: str,
    text: Optional[str] = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Dismiss a button tap's loading spinner (optionally with a short
    toast ``text``). True on success. Never raises."""
    token = (token or "").strip()
    callback_query_id = (callback_query_id or "").strip()
    if not token or not callback_query_id:
        return False
    payload: dict[str, Any] = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = str(text)[:200]  # Bot API toast limit
    return _ok(_post(token, "answerCallbackQuery", payload, timeout=timeout))


def set_webhook(
    token: str,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bool, str]:
    """Register ``url`` as the bot's webhook.

    Returns ``(ok, error_description)`` — the description is
    Telegram's own error text ("" on success or on a transport
    failure). The caller must redact the webhook secret from the
    description before showing it: Telegram's errors do not echo the
    URL, but the description is user-visible text, so the caller
    strips the secret defensively. Never raises, never logs the token.
    """
    token = (token or "").strip()
    url = (url or "").strip()
    if not token or not url:
        return False, ""
    data = _post(token, "setWebhook", {"url": url}, timeout=timeout)
    if data is None:
        return False, ""
    if data.get("ok"):
        return True, ""
    description = data.get("description")
    return False, str(description) if description else ""


def get_webhook_info(
    token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """The ``getWebhookInfo`` result dict, or None on any failure.

    The result carries the registered URL (which includes the webhook
    secret), the pending-update count and the last error, if any —
    the caller masks the URL before display. Never raises, never logs
    the token.
    """
    token = (token or "").strip()
    if not token:
        return None
    data = _post(token, "getWebhookInfo", {}, timeout=timeout)
    if not _ok(data):
        return None
    result = data.get("result") if data else None
    return result if isinstance(result, dict) else None


__all__ = [
    "TELEGRAM_API_BASE",
    "DEFAULT_TIMEOUT",
    "MAX_MESSAGE_LENGTH",
    "mask_token",
    "send_message",
    "edit_message_text",
    "answer_callback_query",
    "set_webhook",
    "get_webhook_info",
]
