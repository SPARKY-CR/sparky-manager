"""Telegram Bot API — a small reusable client (Phase 3 sender, Phase 4 bot).

Phase 3 introduced the one-way notifier (``send_message``); Phase 4
adds the rest of the Bot API surface the management bot needs:
inline keyboards (``reply_markup``), message edits, callback answers,
and webhook registration / status. The polling transport (Phase 4
follow-up) adds ``get_updates`` (long-poll) and ``delete_webhook``
(switching to polling must remove the webhook first, or Telegram
never delivers to ``getUpdates``). The professional upgrade (Phase 3)
adds ``get_me`` (bot identity for diagnostics), ``set_my_commands``
(the bot's command menu) and ``send_document`` (backup delivery).
Everything still goes through the private ``_post`` / ``_post_files``
helpers, so the security rules hold everywhere.

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
import re
from typing import Any, Optional

logger = logging.getLogger("sparky-manager")

TELEGRAM_API_BASE = "https://api.telegram.org/bot"
DEFAULT_TIMEOUT = 10.0
# Bot API limit for a single message.
MAX_MESSAGE_LENGTH = 4096
# Bot API limit for a document a bot may send (sendDocument).
MAX_DOCUMENT_BYTES = 50 * 1024 * 1024


def _truncate_html_safe(text: str, limit: int) -> str:
    """Truncate ``text`` to at most ``limit`` chars without breaking
    the HTML the bot uses (only ``<b>...</b>`` pairs, plus the
    ``&amp;``/``&lt;``/``&gt;``/``&quot;`` entities ``h()`` produces).

    A dumb cut can split a tag (``<b``) or an entity (``&am``) in two,
    and Telegram rejects the whole message for malformed HTML — so the
    admin would see nothing at all. The cut therefore drops a trailing
    partial tag/entity, appends "…", and closes any still-open ``<b>``.
    Five chars are reserved up front (1 for "…" + 4 for "</b>") so the
    result never exceeds ``limit``. Plain-text callers keep the dumb
    cut (no markup can break there).
    """
    if len(text) <= limit:
        return text
    cut = text[: max(0, limit - 5)]
    cut = re.sub(r"<[^>]*$", "", cut)
    cut = re.sub(r"&[a-zA-Z0-9#]*$", "", cut)
    out = cut + "…"
    if out.count("<b>") > out.count("</b>"):
        out += "</b>"
    return out


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


def _post_files(
    token: str,
    method: str,
    data: Optional[dict[str, Any]] = None,
    files: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """Like :func:`_post`, but multipart (file uploads).

    Same contract: parsed JSON dict or None on any failure, never
    raises, never logs the token. ``files`` is the httpx mapping
    (``{"document": (filename, bytes, content_type)}``).
    """
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
        response = httpx.post(
            url, data=data or {}, files=files or {}, timeout=timeout
        )
    except Exception:  # noqa: BLE001 — timeout / DNS / connect errors
        logger.warning("telegram api call failed: request error")
        return None
    if response.status_code != 200:
        # Log only the status code — the body may echo the request.
        logger.warning("telegram api call failed: HTTP %s", response.status_code)
        return None
    try:
        parsed = response.json()
    except ValueError:
        logger.warning("telegram api call failed: bad JSON response")
        return None
    if not isinstance(parsed, dict):
        logger.warning("telegram api call failed: bad JSON response")
        return None
    return parsed


def _ok(data: Optional[dict[str, Any]]) -> bool:
    """True when the Bot API answered ``{"ok": true}``."""
    return bool(data and data.get("ok"))


def send_message(
    token: str,
    chat_id: str,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    parse_mode: Optional[str] = None,
    message_thread_id: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Send ``text`` to ``chat_id`` via the Bot API. True on success.

    Returns False (never raises) when the token/chat id are missing,
    the text is empty, the request times out, Telegram answers with
    an error, or ``httpx`` is unavailable. The token is never logged.
    ``reply_markup`` (Phase 4) is an inline-keyboard dict; it is only
    sent when given, so notification calls keep the exact Phase 3
    payload. ``parse_mode`` (bot polish) is likewise only sent when
    given — the management bot passes ``"HTML"``; notifications stay
    plain text. ``message_thread_id`` (Phase A event bus) routes the
    message into a forum topic of a supergroup; it is only sent when
    given, and Telegram refuses the message when the chat is not a
    forum or the topic does not exist (no silent fallback — a wrong
    topic id must be visible, not quietly ignored).
    """
    return _ok(
        _send_message_data(
            token,
            chat_id,
            text,
            reply_markup=reply_markup,
            parse_mode=parse_mode,
            message_thread_id=message_thread_id,
            timeout=timeout,
        )
    )


def _send_message_data(
    token: str,
    chat_id: str,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    parse_mode: Optional[str] = None,
    message_thread_id: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """Shared send path for :func:`send_message` and
    :func:`send_message_id`: validate, truncate, post ``sendMessage``,
    return the parsed Bot API dict (``None`` on any failure)."""
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not token or not chat_id or not text:
        return None
    if len(text) > MAX_MESSAGE_LENGTH:
        if parse_mode:
            text = _truncate_html_safe(text, MAX_MESSAGE_LENGTH)
        else:
            text = text[: MAX_MESSAGE_LENGTH - 1] + "…"

    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    if parse_mode is not None:
        payload["parse_mode"] = parse_mode
    if message_thread_id is not None:
        payload["message_thread_id"] = int(message_thread_id)
    return _post(token, "sendMessage", payload, timeout=timeout)


def send_message_id(
    token: str,
    chat_id: str,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    parse_mode: Optional[str] = None,
    message_thread_id: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[int]:
    """Send ``text`` like :func:`send_message`, but return the sent
    message's id (``None`` on failure) instead of a bool — the caller
    needs the id to delete the message again (the bot's
    reply-keyboard installer sends the keyboard, then deletes its
    own message so the chat shows no hint text). Same never-raise /
    never-log-the-token contract."""
    data = _send_message_data(
        token,
        chat_id,
        text,
        reply_markup=reply_markup,
        parse_mode=parse_mode,
        message_thread_id=message_thread_id,
        timeout=timeout,
    )
    if not _ok(data):
        return None
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, dict):
        return None
    message_id = result.get("message_id")
    return int(message_id) if isinstance(message_id, int) else None


def delete_message(
    token: str,
    chat_id: str,
    message_id: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Delete a message the bot sent (Bot API ``deleteMessage``).
    True on success; False (never raises) when the message is
    already gone, too old to delete, or Telegram is unreachable.
    Deleting the reply-keyboard installer's message leaves the
    keyboard in place client-side — the delete only removes the
    visible hint text."""
    chat_id = (chat_id or "").strip()
    if not token or not chat_id or not message_id:
        return False
    return _ok(
        _post(
            token,
            "deleteMessage",
            {"chat_id": chat_id, "message_id": message_id},
            timeout=timeout,
        )
    )


def edit_message_text(
    token: str,
    chat_id: str,
    message_id: int,
    text: str,
    *,
    reply_markup: Optional[dict[str, Any]] = None,
    parse_mode: Optional[str] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Replace a sent message's text (and keyboard). True on success.

    False when the message cannot be edited (too old, deleted, or
    identical text) — the caller falls back to sending a new message.
    Same never-raise / never-log-the-token contract as ``send_message``.
    ``parse_mode`` is only sent when given (the bot passes ``"HTML"``).
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not token or not chat_id or not text or not message_id:
        return False
    if len(text) > MAX_MESSAGE_LENGTH:
        if parse_mode:
            text = _truncate_html_safe(text, MAX_MESSAGE_LENGTH)
        else:
            text = text[: MAX_MESSAGE_LENGTH - 1] + "…"

    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    if parse_mode is not None:
        payload["parse_mode"] = parse_mode
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


def delete_webhook(
    token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bool, str]:
    """Remove the bot's webhook from Telegram's side.

    Required when switching to the polling transport: a webhook set
    on Telegram's side suppresses ``getUpdates`` delivery, so polling
    would receive nothing until the webhook is gone. Same contract
    as ``set_webhook``: returns ``(ok, error_description)`` ("" on
    success or on a transport failure), never raises, never logs the
    token. Pending updates are kept (``drop_pending_updates`` is not
    set) so nothing the admin sent is lost in the switch — the
    polling loop picks them up.
    """
    token = (token or "").strip()
    if not token:
        return False, ""
    data = _post(token, "deleteWebhook", {}, timeout=timeout)
    if data is None:
        return False, ""
    if data.get("ok"):
        return True, ""
    description = data.get("description")
    return False, str(description) if description else ""


def get_updates(
    token: str,
    offset: Optional[int] = None,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """Long-poll ``getUpdates``; returns the parsed ``result`` list.

    ``timeout`` is the Bot API long-poll wait in seconds (Telegram
    holds the request up to that long when there is nothing new; max
    50). The HTTP timeout is ``timeout + 5`` so a full long-poll wait
    never trips the client timeout. ``offset`` (when given) tells
    Telegram to skip everything up to and including that update id.
    Empty list on ANY failure (missing token, transport error, HTTP
    error, ``ok: false``, a non-list result) — the polling loop
    treats a fast empty return as a failure and backs off. Never
    raises, never logs the token. This is a blocking call: the
    polling loop runs it in a thread (``asyncio.to_thread``) so the
    30 s wait never blocks the panel's event loop.
    """
    token = (token or "").strip()
    if not token:
        return []
    payload: dict[str, Any] = {"timeout": int(timeout)}
    if offset is not None:
        payload["offset"] = offset
    data = _post(token, "getUpdates", payload, timeout=float(timeout) + 5.0)
    if not _ok(data):
        return []
    result = data.get("result") if data else None
    return list(result) if isinstance(result, list) else []


def get_me(
    token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[dict[str, Any]]:
    """The ``getMe`` result dict (bot id, username, first name), or
    None on any failure. The bot's public identity — safe to show in
    the settings diagnostics. Never raises, never logs the token."""
    token = (token or "").strip()
    if not token:
        return None
    data = _post(token, "getMe", {}, timeout=timeout)
    if not _ok(data):
        return None
    result = data.get("result") if data else None
    return result if isinstance(result, dict) else None


def set_my_commands(
    token: str,
    commands: list[dict[str, str]],
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bool, str]:
    """Register the bot's command menu (``setMyCommands``).

    ``commands`` is a list of ``{"command": ..., "description": ...}``
    dicts (see ``app.bot.BOT_COMMANDS``). Same contract as
    ``set_webhook``: returns ``(ok, error_description)`` ("" on
    success or on a transport failure), never raises, never logs the
    token. An empty command list is refused — clearing the menu is
    never what a caller wants here.
    """
    token = (token or "").strip()
    if not token or not commands:
        return False, ""
    data = _post(
        token, "setMyCommands", {"commands": list(commands)}, timeout=timeout
    )
    if data is None:
        return False, ""
    if data.get("ok"):
        return True, ""
    description = data.get("description")
    return False, str(description) if description else ""


def send_document(
    token: str,
    chat_id: str,
    filename: str,
    data: bytes,
    *,
    message_thread_id: Optional[int] = None,
    timeout: float = 30.0,
) -> bool:
    """Send ``data`` as a document to ``chat_id`` (multipart upload).

    True on success. Files over the Bot API 50 MB cap are refused
    up front (False) instead of uploading a doomed request — the
    caller reports that honestly (the web settings page can still
    download the same file). Never raises, never logs the token.
    The 30 s timeout covers a multi-MB upload on a slow link.
    ``message_thread_id`` routes the document into a forum topic
    (same contract as :func:`send_message`).
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    filename = (filename or "").strip()
    if not token or not chat_id or not filename or not data:
        return False
    if len(data) > MAX_DOCUMENT_BYTES:
        return False
    payload: dict[str, Any] = {"chat_id": chat_id}
    if message_thread_id is not None:
        payload["message_thread_id"] = int(message_thread_id)
    result = _post_files(
        token,
        "sendDocument",
        data=payload,
        files={"document": (filename, data, "application/zip")},
        timeout=timeout,
    )
    return _ok(result)


# Marzban splits backup archives at 49 MB for Telegram delivery —
# 1 MB under the Bot API's 50 MB cap, so a part is never refused for
# size. Same margin here.
DOCUMENT_PART_BYTES = 49 * 1024 * 1024


def split_document_parts(filename: str, data: bytes) -> list[tuple[str, bytes]]:
    """Split ``data`` into Telegram-sized parts.

    Returns ``[(filename, data)]`` unchanged when the file fits in
    one part; otherwise one entry per 49 MB chunk, named
    ``<stem>.part<n>of<m><suffix>`` (e.g.
    ``backup.zip`` -> ``backup.part1of3.zip``). Pure function —
    the sender below is the only part that touches the network.
    """
    if len(data) <= DOCUMENT_PART_BYTES:
        return [(filename, data)]
    stem, dot, suffix = filename.rpartition(".")
    if not dot:
        stem, suffix = filename, ""
    else:
        suffix = "." + suffix
    total = (len(data) + DOCUMENT_PART_BYTES - 1) // DOCUMENT_PART_BYTES
    parts: list[tuple[str, bytes]] = []
    for index in range(total):
        chunk = data[
            index * DOCUMENT_PART_BYTES : (index + 1) * DOCUMENT_PART_BYTES
        ]
        parts.append((f"{stem}.part{index + 1}of{total}{suffix}", chunk))
    return parts


def send_document_parts(
    token: str,
    chat_id: str,
    filename: str,
    data: bytes,
    *,
    message_thread_id: Optional[int] = None,
    timeout: float = 30.0,
) -> bool:
    """Send ``data`` as one document, or several parts when it is too
    large for a single upload (Marzban's split-at-49 MB rule).

    True only when EVERY part was accepted — a partial delivery is
    reported as a failure (the caller logs it; the file stays
    downloadable from the panel). Never raises, never logs the token.
    """
    if not data:
        return False
    for part_name, chunk in split_document_parts(filename, data):
        if not send_document(
            token,
            chat_id,
            part_name,
            chunk,
            message_thread_id=message_thread_id,
            timeout=timeout,
        ):
            return False
    return True


__all__ = [
    "TELEGRAM_API_BASE",
    "DEFAULT_TIMEOUT",
    "MAX_MESSAGE_LENGTH",
    "MAX_DOCUMENT_BYTES",
    "DOCUMENT_PART_BYTES",
    "mask_token",
    "send_message",
    "edit_message_text",
    "answer_callback_query",
    "set_webhook",
    "get_webhook_info",
    "delete_webhook",
    "get_updates",
    "get_me",
    "set_my_commands",
    "send_document",
    "split_document_parts",
    "send_document_parts",
]
