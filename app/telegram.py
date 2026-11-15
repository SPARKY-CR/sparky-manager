"""Telegram notifications — a small reusable sender (Phase 3).

This module is deliberately tiny and dependency-light: one
``send_message`` helper over the Bot API, built for the Phase 4
management bot to reuse. It knows nothing about the panel's DB or
settings — the caller passes the token and chat id it read from
settings, and this module only sends.

Security rules (never relax these):
- The bot token is NEVER logged, not even partially — not by this
  module, and callers must not log it either. ``mask_token`` exists
  only for UI display ("configured: …Ab12").
- Failures are reported as ``False``, never raised: a dead Telegram
  must never break a panel request or a background loop.
- ``httpx`` is a declared panel dependency (requirements.txt); the
  sender uses a short timeout so a slow Telegram cannot hang a request.
"""

from __future__ import annotations

import logging
from typing import Optional

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


def send_message(
    token: str,
    chat_id: str,
    text: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> bool:
    """Send ``text`` to ``chat_id`` via the Bot API. True on success.

    Returns False (never raises) when the token/chat id are missing,
    the text is empty, the request times out, Telegram answers with
    an error, or ``httpx`` is unavailable. The token is never logged.
    """
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not token or not chat_id or not text:
        return False
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 1] + "…"

    try:
        import httpx
    except ImportError:
        logger.warning("telegram send failed: httpx not installed")
        return False

    url = f"{TELEGRAM_API_BASE}{token}/sendMessage"
    try:
        response = httpx.post(
            url,
            json={"chat_id": chat_id, "text": text},
            timeout=timeout,
        )
    except Exception:  # noqa: BLE001 — timeout / DNS / connect errors
        logger.warning("telegram send failed: request error")
        return False
    if response.status_code != 200:
        # Log only the status code — the body may echo the request.
        logger.warning(
            "telegram send failed: HTTP %s", response.status_code
        )
        return False
    try:
        payload = response.json()
    except ValueError:
        logger.warning("telegram send failed: bad JSON response")
        return False
    if not isinstance(payload, dict) or not payload.get("ok"):
        logger.warning("telegram send failed: API returned ok=false")
        return False
    return True


__all__ = [
    "TELEGRAM_API_BASE",
    "DEFAULT_TIMEOUT",
    "MAX_MESSAGE_LENGTH",
    "mask_token",
    "send_message",
]
