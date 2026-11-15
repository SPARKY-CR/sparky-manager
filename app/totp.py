"""TOTP two-factor authentication for the admin login (best-panel
program, Phase B item 13 — 3x-ui's TOTP shape).

Stdlib only: RFC 6238 TOTP (HMAC-SHA1, 30-second steps, 6 digits)
implemented directly on :mod:`hmac` / :mod:`hashlib`, so the panel
gains 2FA without a new dependency (no ``pyotp`` pin to maintain,
no ``requirements.txt`` change).

Storage (settings table — no schema change, the panel has no
migration system):

* ``totp_enabled`` — ``"1"`` while 2FA is on.
* ``totp_secret`` — the base32 TOTP secret (stored in the clear,
  like the Telegram bot token in settings — a backup ZIP is a
  credential bundle either way; DESIGN.md §7 says so).
* ``totp_recovery_hashes`` — JSON list of SHA-256 hashes of the
  one-time recovery codes shown once at setup (plaintext is never
  stored; a used code's hash is removed, so each code works once).
* ``totp_pending_secret`` — the secret of a setup in progress,
  moved to ``totp_secret`` only after the admin proves it with a
  valid code (an abandoned setup never enables 2FA).

Login flow (see ``app.main``): after the password checks out and
2FA is on, the login does NOT create a session — it issues a
short-lived *pending* token (an HMAC-signed, HttpOnly cookie) and
redirects to ``/login/totp``. The pending token is signed with the
admin's own password hash as the key, so it is stateless (survives
a panel restart), expires in 5 minutes, and dies on a password
change. The session is created only after a valid TOTP (or
recovery) code.

Lockout recovery (never lock the admin out):

* the 8 recovery codes, shown once at setup (each works once);
* ``sudo sparky-manager totp-disable`` on the server (CLI,
  :func:`disable_totp` below) clears 2FA from the DB — it needs
  SSH access to the server, which is the recovery path when the
  device AND the codes are gone. Documented in DESIGN.md §15.6
  and the setup page itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from sqlalchemy.orm import Session as DbSession

from app.webcommon import get_setting, set_setting

# ---------------------------------------------------------------------------
# Settings keys (settings table — no schema change)
# ---------------------------------------------------------------------------

TOTP_ENABLED_KEY = "totp_enabled"
TOTP_SECRET_KEY = "totp_secret"
TOTP_PENDING_SECRET_KEY = "totp_pending_secret"
TOTP_RECOVERY_HASHES_KEY = "totp_recovery_hashes"

# A pending 2FA login lives 5 minutes; the admin then re-enters the
# password (the pending token is short-lived by design — it is a
# half-authenticated state, not a session).
PENDING_TOKEN_TTL_SECONDS = 5 * 60

# Recovery codes: 8 codes, each 10 hex chars (40 bits — enough for a
# one-time code that is also rate-limited by the login lockout).
RECOVERY_CODE_COUNT = 8

# TOTP parameters (RFC 6238 defaults).
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
# Verification window: the current step plus one step either side
# (clock skew between the panel and the phone).
TOTP_WINDOW_STEPS = 1

TOTP_ISSUER = "sparky-manager"


# ---------------------------------------------------------------------------
# TOTP core (RFC 6238, stdlib only)
# ---------------------------------------------------------------------------


def generate_secret() -> str:
    """A fresh random TOTP secret: 20 bytes, base32-encoded (RFC
    4226/6238's recommended 160 bits)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def provisioning_uri(secret: str, account: str, issuer: str = TOTP_ISSUER) -> str:
    """The ``otpauth://`` URL authenticator apps scan (or the admin
    types the secret by hand — the setup page shows both)."""
    label = quote(f"{issuer}:{account}")
    params = (
        f"secret={quote(secret)}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    )
    return f"otpauth://totp/{label}?{params}"


def _hotp(secret_bytes: bytes, counter: int) -> str:
    """One HMAC-based one-time password (RFC 4226 §5.3)."""
    message = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_code(secret: str, at: Optional[float] = None) -> str:
    """The TOTP code for ``secret`` at Unix time ``at`` (now when
    omitted). Raises :class:`ValueError` for a malformed secret."""
    try:
        secret_bytes = base64.b32decode(secret.strip().upper())
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise ValueError("invalid TOTP secret") from exc
    moment = time.time() if at is None else float(at)
    counter = int(moment // TOTP_PERIOD_SECONDS)
    return _hotp(secret_bytes, counter)


def verify_code(
    secret: str,
    code: str,
    at: Optional[float] = None,
    window: int = TOTP_WINDOW_STEPS,
) -> bool:
    """True when ``code`` is a valid TOTP code for ``secret`` within
    ``window`` steps either side of ``at`` (clock-skew tolerance).

    The submitted code must be exactly 6 digits (spaces are
    stripped — apps sometimes group them); anything else is False,
    never an exception. Candidates are compared in constant time.
    """
    candidate = (code or "").replace(" ", "").strip()
    if len(candidate) != TOTP_DIGITS or not candidate.isdigit():
        return False
    try:
        secret_bytes = base64.b32decode(secret.strip().upper())
    except (ValueError, TypeError, base64.binascii.Error):
        return False
    moment = time.time() if at is None else float(at)
    counter = int(moment // TOTP_PERIOD_SECONDS)
    for step in range(counter - window, counter + window + 1):
        if hmac.compare_digest(_hotp(secret_bytes, step), candidate):
            return True
    return False


# ---------------------------------------------------------------------------
# Recovery codes (one-time, hashed at rest)
# ---------------------------------------------------------------------------


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """``count`` fresh recovery codes (10 hex chars each)."""
    return [secrets.token_hex(5) for _ in range(count)]


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode("utf-8")).hexdigest()


def verify_recovery_code(db: DbSession, code: str) -> bool:
    """True when ``code`` matches a stored recovery-code hash — and
    CONSUMES it (the hash is removed, so each code works once).

    Returns False (never raises) for a missing/blank code, no stored
    hashes, or no match. A blank code never matches an empty hash
    list.
    """
    candidate = (code or "").replace(" ", "").strip().lower()
    if not candidate:
        return False
    try:
        stored = json.loads(get_setting(db, TOTP_RECOVERY_HASHES_KEY, ""))
    except ValueError:
        return False
    if not isinstance(stored, list) or not stored:
        return False
    target = _hash_recovery_code(candidate)
    remaining = [h for h in stored if not hmac.compare_digest(str(h), target)]
    if len(remaining) == len(stored):
        return False
    set_setting(db, TOTP_RECOVERY_HASHES_KEY, json.dumps(remaining))
    return True


def recovery_codes_remaining(db: DbSession) -> int:
    """How many unused recovery codes are left (0 when 2FA is off)."""
    try:
        stored = json.loads(get_setting(db, TOTP_RECOVERY_HASHES_KEY, ""))
    except ValueError:
        return 0
    return len(stored) if isinstance(stored, list) else 0


# ---------------------------------------------------------------------------
# 2FA state (settings table)
# ---------------------------------------------------------------------------


def is_totp_enabled(db: DbSession) -> bool:
    """True only when 2FA is enabled AND a secret is stored (a
    half-written state — enabled flag without a secret — counts as
    off, so a corrupted setting can never lock the admin out)."""
    return (
        get_setting(db, TOTP_ENABLED_KEY, "") == "1"
        and bool(get_setting(db, TOTP_SECRET_KEY, ""))
    )


def get_totp_secret(db: DbSession) -> str:
    """The live TOTP secret ("" when 2FA is not set up)."""
    return get_setting(db, TOTP_SECRET_KEY, "")


def begin_setup(db: DbSession) -> str:
    """Start a setup: generate a pending secret and store it (any
    previous pending secret is replaced). Returns the secret."""
    secret = generate_secret()
    set_setting(db, TOTP_PENDING_SECRET_KEY, secret)
    return secret


def get_pending_secret(db: DbSession) -> str:
    """The pending setup secret ("" when no setup is in progress)."""
    return get_setting(db, TOTP_PENDING_SECRET_KEY, "")


def complete_setup(db: DbSession, secret: str) -> list[str]:
    """Enable 2FA with ``secret`` (already verified by the caller):
    store the secret, set the enabled flag, clear the pending
    secret, and generate + store hashed recovery codes. Returns the
    plaintext recovery codes — shown to the admin ONCE by the
    caller, never stored."""
    codes = generate_recovery_codes()
    set_setting(db, TOTP_SECRET_KEY, secret)
    set_setting(db, TOTP_ENABLED_KEY, "1")
    set_setting(db, TOTP_PENDING_SECRET_KEY, "")
    set_setting(
        db,
        TOTP_RECOVERY_HASHES_KEY,
        json.dumps([_hash_recovery_code(c) for c in codes]),
    )
    return codes


def disable_totp(db: DbSession) -> bool:
    """Turn 2FA off entirely (secret, flag, pending secret, recovery
    hashes). Returns True when 2FA was on. This is the lockout
    recovery used by ``sparky-manager totp-disable`` (CLI) — it
    needs server access, which is the point: only someone with SSH
    can bypass 2FA this way."""
    was_on = is_totp_enabled(db) or bool(get_pending_secret(db))
    set_setting(db, TOTP_ENABLED_KEY, "")
    set_setting(db, TOTP_SECRET_KEY, "")
    set_setting(db, TOTP_PENDING_SECRET_KEY, "")
    set_setting(db, TOTP_RECOVERY_HASHES_KEY, "")
    return was_on


# ---------------------------------------------------------------------------
# Pending-login token (stateless, HMAC-signed with the password hash)
# ---------------------------------------------------------------------------

_PENDING_LABEL = b"sparky-manager totp pending v1"


def make_pending_token(admin: object, now: Optional[float] = None) -> str:
    """A short-lived token proving ``admin`` passed the password
    step. ``admin`` needs ``id`` and ``password_hash``. The token is
    ``base64url("<admin_id>:<expiry_unix>.<hmac_hex>")`` where the
    HMAC key is the admin's password hash — so the token is
    stateless, expires in 5 minutes, and dies on a password change.
    """
    moment = time.time() if now is None else float(now)
    expiry = int(moment) + PENDING_TOKEN_TTL_SECONDS
    payload = f"{int(admin.id)}:{expiry}"
    signature = hmac.new(
        str(admin.password_hash).encode("utf-8"),
        _PENDING_LABEL + b"." + payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}.{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_pending_token(db: DbSession, token: str) -> Optional[object]:
    """The admin for a valid, unexpired pending token, else None.

    Never raises. An expired, malformed, or wrong-key token simply
    returns None (the login page is shown again).
    """
    from app.models import Admin

    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        payload, signature = raw.rsplit(".", 1)
        admin_id_s, expiry_s = payload.split(":", 1)
        admin_id = int(admin_id_s)
        expiry = int(expiry_s)
    except (ValueError, TypeError, base64.binascii.Error):
        return None
    if time.time() > expiry:
        return None
    admin = db.get(Admin, admin_id)
    if admin is None:
        return None
    expected = hmac.new(
        str(admin.password_hash).encode("utf-8"),
        _PENDING_LABEL + b"." + payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    return admin


__all__ = [
    "TOTP_ENABLED_KEY",
    "TOTP_SECRET_KEY",
    "TOTP_PENDING_SECRET_KEY",
    "TOTP_RECOVERY_HASHES_KEY",
    "PENDING_TOKEN_TTL_SECONDS",
    "RECOVERY_CODE_COUNT",
    "TOTP_PERIOD_SECONDS",
    "TOTP_DIGITS",
    "TOTP_WINDOW_STEPS",
    "TOTP_ISSUER",
    "generate_secret",
    "provisioning_uri",
    "totp_code",
    "verify_code",
    "generate_recovery_codes",
    "verify_recovery_code",
    "recovery_codes_remaining",
    "is_totp_enabled",
    "get_totp_secret",
    "begin_setup",
    "get_pending_secret",
    "complete_setup",
    "disable_totp",
    "make_pending_token",
    "verify_pending_token",
]
