"""Admin authentication — stdlib only, no extra dependencies.

- Passwords: PBKDF2-HMAC-SHA256 with a per-user random salt, stored as
  ``pbkdf2$iterations$salt_hex$hash_hex``. (DESIGN.md §7 suggests
  Argon2id; Phase 1 uses stdlib PBKDF2 instead so the panel has zero
  extra auth dependencies — the stored format is versioned by its
  prefix, so a future Argon2id migration can be detected per row.)
- Sessions: server-side rows (:class:`app.models.Session`) holding only
  the SHA-256 hash of a random token; the raw token is handed to the
  browser once (HttpOnly cookie) and never stored. Logout deletes the
  row. 12-hour expiry.
- Rate limiting: in-memory per-IP counter — 5 failed logins lock the
  IP out for 15 minutes (DESIGN.md §7).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session as DbSession

from app.models import Admin, Session as LoginSession

# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256, stdlib only)
# ---------------------------------------------------------------------------

_HASH_ALGO = "pbkdf2"
_HASH_NAME = "sha256"
DEFAULT_ITERATIONS = 600_000  # OWASP recommendation for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_HASH_BYTES = 32


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Hash ``password``; returns ``pbkdf2$iterations$salt_hex$hash_hex``.

    A fresh random salt is generated on every call, so two identical
    passwords never produce the same stored string.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        _HASH_NAME, password.encode("utf-8"), salt, iterations, dklen=_HASH_BYTES
    )
    return f"{_HASH_ALGO}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of ``password`` against a stored hash.

    Returns ``False`` (never raises) for malformed stored values and
    for hashes produced by an unknown scheme, so a bad row can never
    take the login path down.
    """
    try:
        algo, iterations_s, salt_hex, hash_hex = stored.split("$")
        if algo != _HASH_ALGO:
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac(
        _HASH_NAME, password.encode("utf-8"), salt, iterations, dklen=len(expected)
    )
    return hmac.compare_digest(digest, expected)


# ---------------------------------------------------------------------------
# Sessions (server-side, token hash only)
# ---------------------------------------------------------------------------

SESSION_TTL = timedelta(hours=12)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: DbSession, admin: Admin, ip: Optional[str] = None
) -> str:
    """Create a login session for ``admin``; returns the raw token.

    Only the SHA-256 hash is stored. The caller must hand the raw token
    to the browser (HttpOnly cookie) and never log or persist it.
    """
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(
        LoginSession(
            token_hash=_hash_token(token),
            admin_id=admin.id,
            expires_at=now + SESSION_TTL,
            created_ip=ip,
            created_at=now,
        )
    )
    db.commit()
    return token


def get_admin_from_token(db: DbSession, token: str) -> Optional[Admin]:
    """Return the admin for a valid, unexpired session token, else None.

    Expired sessions are removed as a side effect. A token that was
    never issued (or was invalidated by logout) simply returns None.
    """
    if not token:
        return None
    row = (
        db.query(LoginSession)
        .filter(LoginSession.token_hash == _hash_token(token))
        .first()
    )
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    expires_at = row.expires_at
    if expires_at.tzinfo is None:  # SQLite stores datetimes naive
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        db.delete(row)
        db.commit()
        return None
    return db.get(Admin, row.admin_id)


def invalidate_session(db: DbSession, token: str) -> bool:
    """Delete the session for ``token`` (logout). True if one existed."""
    if not token:
        return False
    row = (
        db.query(LoginSession)
        .filter(LoginSession.token_hash == _hash_token(token))
        .first()
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


# ---------------------------------------------------------------------------
# Login rate limiting (in-memory, per IP)
# ---------------------------------------------------------------------------

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60  # 15 minutes

# ip -> list of epoch timestamps of failed attempts (pruned on read).
_failed_logins: dict[str, list[float]] = {}


def _prune(ip: str, now: float) -> list[float]:
    attempts = [t for t in _failed_logins.get(ip, []) if now - t < LOCKOUT_SECONDS]
    if attempts:
        _failed_logins[ip] = attempts
    else:
        _failed_logins.pop(ip, None)
    return attempts


def record_failed_login(ip: str) -> None:
    """Record one failed login from ``ip`` (call on every bad attempt)."""
    now = time.time()
    _failed_logins[ip] = _prune(ip, now) + [now]


def record_successful_login(ip: str) -> None:
    """Clear the failure counter for ``ip`` after a successful login."""
    _failed_logins.pop(ip, None)


def is_locked_out(ip: str) -> bool:
    """True once ``ip`` has had 5 failed logins inside 15 minutes."""
    return len(_prune(ip, time.time())) >= MAX_FAILED_LOGINS


__all__ = [
    "DEFAULT_ITERATIONS",
    "SESSION_TTL",
    "MAX_FAILED_LOGINS",
    "LOCKOUT_SECONDS",
    "hash_password",
    "verify_password",
    "create_session",
    "get_admin_from_token",
    "invalidate_session",
    "record_failed_login",
    "record_successful_login",
    "is_locked_out",
]
