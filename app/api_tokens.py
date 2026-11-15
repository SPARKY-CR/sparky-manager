"""Scoped, expiring API tokens (best-panel program, Phase B item 12
— 3x-ui / Remnawave model).

The panel's ``/api/*`` endpoints used to accept only a cookie
session — unusable for scripts and external bots (the sales-bot
ecosystem in the research report talks to panel APIs, not to
cookie sessions). ``/api/v1/*`` accepts Bearer tokens instead:

* tokens are random (``spk_`` + 32 urlsafe bytes), stored only as
  a SHA-256 hash — the plaintext is shown to the admin exactly
  once, at creation, and never again (like the login session
  tokens in :mod:`app.auth`);
* each token carries scopes (``status:read`` / ``users:read`` /
  ``inbounds:read`` / ``admin`` — the last satisfies every scope)
  and an optional expiry (Remnawave mandates expiry; sparky
  warns instead — a never-expiring token is the admin's explicit
  choice, shown as such in the UI);
* authentication is the ``Authorization: Bearer <token>`` header
  (or ``X-API-Key`` — the Hiddify convention); a missing/invalid/
  expired token gets 401, a valid token without the scope gets
  403, and ``last_used_at`` is stamped on every accepted call.

CSRF does not apply to these endpoints: they take no cookie, so
there is no ambient authority for a browser to abuse (the same
reasoning as the Telegram webhook exemption — see the CSRF note in
``app.main``). The token management page itself is normal HTML
forms with CSRF.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from app.models import ApiToken
from app.webcommon import db_session

#: Token prefix (identifies a sparky API token at a glance, and
#: keeps tokens out of the subscription-token namespace).
TOKEN_PREFIX = "spk_"

#: Scope name -> i18n key for its label on the token page.
SCOPES: dict[str, str] = {
    "status:read": "api_scope_status_read",
    "users:read": "api_scope_users_read",
    "inbounds:read": "api_scope_inbounds_read",
    "admin": "api_scope_admin",
}

#: The scope that satisfies every check.
ADMIN_SCOPE = "admin"


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def hash_token(raw: str) -> str:
    """The SHA-256 hash stored for a raw token."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_token(
    db: DbSession,
    name: str,
    scopes: list[str],
    expires_at: Optional[datetime] = None,
) -> tuple[ApiToken, str]:
    """Create a token. Returns ``(row, raw_token)`` — the caller
    shows ``raw_token`` to the admin ONCE and never stores it.
    Unknown scope names are dropped; an empty scope list stays
    empty (a token with no scopes authenticates but authorizes
    nothing). Commits."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    clean_scopes = sorted({s for s in (scopes or []) if s in SCOPES})
    row = ApiToken(
        name=(name or "").strip() or "token",
        token_hash=hash_token(raw),
        expires_at=expires_at,
        scopes_json="[]",
    )
    row.scopes = clean_scopes
    db.add(row)
    db.commit()
    return row, raw


def revoke_token(db: DbSession, token_id: int) -> bool:
    """Delete a token (revocation is immediate — the hash is gone).
    True when one existed."""
    row = db.get(ApiToken, token_id)
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def verify_token(db: DbSession, raw: Optional[str]) -> Optional[ApiToken]:
    """The token row for a valid, unexpired raw token, else None.

    A successful verification stamps ``last_used_at`` (committed).
    Never raises. An expired token is simply invalid (it is NOT
    deleted — the admin can see it expired and revoke it by hand).
    """
    if not raw:
        return None
    row = (
        db.query(ApiToken)
        .filter(ApiToken.token_hash == hash_token(raw.strip()))
        .first()
    )
    if row is None:
        return None
    expires = _aware(row.expires_at)
    if expires is not None and expires <= datetime.now(timezone.utc):
        return None
    row.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return row


def token_has_scope(token: ApiToken, scope: str) -> bool:
    """True when the token's scopes include ``scope`` — or the
    ``admin`` scope, which satisfies every check."""
    scopes = set(token.scopes or [])
    return scope in scopes or ADMIN_SCOPE in scopes


def _bearer_token(request: Request) -> Optional[str]:
    """The token from ``Authorization: Bearer <token>`` or the
    ``X-API-Key`` header (Hiddify's convention)."""
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    api_key = (request.headers.get("x-api-key") or "").strip()
    return api_key or None


def require_api_token(scope: str) -> Callable[..., Any]:
    """A FastAPI dependency factory: the returned dependency
    authenticates the request's Bearer token and requires
    ``scope`` (401 unauthenticated, 403 insufficient scope).
    The returned function is named ``require_api_token`` so the
    Phase 6 route-table test recognises it as an auth guard.
    """

    def require_api_token(
        request: Request, db: DbSession = Depends(db_session)
    ) -> ApiToken:
        token = verify_token(db, _bearer_token(request))
        if token is None:
            raise HTTPException(status_code=401, detail="invalid API token")
        if not token_has_scope(token, scope):
            raise HTTPException(status_code=403, detail="insufficient scope")
        return token

    require_api_token.__name__ = "require_api_token"
    return require_api_token


__all__ = [
    "TOKEN_PREFIX",
    "SCOPES",
    "ADMIN_SCOPE",
    "hash_token",
    "create_token",
    "revoke_token",
    "verify_token",
    "token_has_scope",
    "require_api_token",
]
