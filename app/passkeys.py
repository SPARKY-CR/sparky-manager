"""Passkey / WebAuthn login (Phase C item 22).

An additional sign-in method alongside password (+ TOTP 2FA from
Phase B). A passkey login is a full login on its own — the
authenticator is a phishing-resistant possession factor and
performs user verification (biometric / PIN) when available, so it
satisfies authentication the way GitHub treats passkeys as
satisfying 2FA. Password + TOTP always remain usable: passkeys
are an addition, never a replacement, and the admin can never be
locked out by a lost passkey (the password still works).

How it works
------------
Registration (admin-only, Settings → Security) and login both run
the standard two-step ceremony: the server generates options with
a random challenge, the browser's ``navigator.credentials``
answers, the server verifies the response with the ``webauthn``
library (Duo Labs, pinned in ``requirements.txt``) — signature
verification is cryptographic and is NEVER hand-rolled here.

The challenge is carried in a stateless HMAC-signed token (same
shape as the TOTP pending token in :mod:`app.totp`: the key is the
admin's password hash, so the token expires in 5 minutes and dies
on a password change). The token binds the challenge to the admin,
the purpose (``"register"`` / ``"login"``) and the RP ID, so a
token from one ceremony cannot be replayed into the other.

RP ID / origin: the RP ID is the request host (port stripped) and
the origin is the request base URL. A credential is bound to the
RP ID it was registered for — the browser refuses to use it from
another host — so an admin who reaches the panel by several hosts
registers one passkey per host. The panel is always served over
HTTPS (or loopback), which WebAuthn requires.

Sign counts: the stored ``sign_count`` is passed to the library,
which rejects a regression (a lower count than the stored one
means the credential was cloned). Authenticators that don't track
a counter report 0, which the library accepts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from app.models import Admin, PasskeyCredential

logger = logging.getLogger(__name__)

__all__ = [
    "CHALLENGE_TTL_SECONDS",
    "RP_NAME",
    "begin_login",
    "begin_registration",
    "finish_login",
    "finish_registration",
    "make_challenge_token",
    "verify_challenge_token",
]

#: Relying-party name shown by the browser during registration.
RP_NAME = "sparky-manager"

#: Challenge-token lifetime (seconds) — same 5 minutes as the TOTP
#: pending token: long enough to find the security key, short
#: enough that a leaked token is useless quickly.
CHALLENGE_TTL_SECONDS = 5 * 60

#: HMAC label for challenge tokens (distinct from the TOTP pending
#: label so a token from one flow can never validate in the other).
_CHALLENGE_LABEL = b"sparky-passkey-challenge-v1"

#: Valid challenge-token purposes.
_PURPOSES = ("register", "login")


def make_challenge_token(
    admin: Admin,
    purpose: str,
    challenge: bytes,
    rp_id: str,
    now: Optional[float] = None,
) -> str:
    """A short-lived token binding ``challenge`` to ``admin``,
    ``purpose`` and ``rp_id``.

    ``base64url(json + "." + hmac_hex)`` where the HMAC key is the
    admin's password hash (stateless, 5-minute expiry, dies on a
    password change — the TOTP pending-token shape). ``purpose``
    must be ``"register"`` or ``"login"``.
    """
    if purpose not in _PURPOSES:
        raise ValueError(f"unknown challenge purpose: {purpose!r}")
    moment = time.time() if now is None else float(now)
    payload = json.dumps(
        {
            "a": int(admin.id),
            "p": purpose,
            "r": rp_id,
            "c": bytes_to_base64url(challenge),
            "e": int(moment) + CHALLENGE_TTL_SECONDS,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    signature = hmac.new(
        str(admin.password_hash).encode("utf-8"),
        _CHALLENGE_LABEL + b"." + payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    raw = f"{payload}.{signature}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_challenge_token(
    db: Session, token: str, purpose: str
) -> Optional[tuple[Admin, bytes, str]]:
    """The ``(admin, challenge, rp_id)`` for a valid, unexpired
    challenge token of the given ``purpose`` — else ``None``.

    Never raises: an expired, malformed, wrong-purpose or
    wrong-key token simply returns None.
    """
    if not token or purpose not in _PURPOSES:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        # Canonical-encoding check: b64decode tolerates trailing
        # junk after the padding (e.g. token + "x" decodes to the
        # same bytes), so a token that is not exactly the encoding
        # of its own decoded bytes is rejected.
        if base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii") != token:
            return None
        payload, signature = raw.rsplit(".", 1)
        data = json.loads(payload)
        if data.get("p") != purpose:
            return None
        if time.time() > int(data["e"]):
            return None
        admin_id = int(data["a"])
        rp_id = str(data["r"])
        challenge = base64url_to_bytes(str(data["c"]))
    except (ValueError, TypeError, KeyError, base64.binascii.Error):
        return None
    admin = db.get(Admin, admin_id)
    if admin is None:
        return None
    expected = hmac.new(
        str(admin.password_hash).encode("utf-8"),
        _CHALLENGE_LABEL + b"." + payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    return admin, challenge, rp_id


def begin_registration(
    admin: Admin,
    rp_id: str,
    existing_credential_ids: list[bytes],
) -> tuple[dict[str, Any], str]:
    """Registration options + challenge token for ``admin``.

    ``existing_credential_ids`` (the admin's registered credential
    IDs) are excluded so the browser won't re-register the same
    passkey. Returns ``(options_dict, challenge_token)`` — the
    options dict is JSON-ready for the browser.
    """
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=str(admin.id).encode("utf-8"),
        user_name=admin.username,
        user_display_name=admin.username,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=credential_id)
            for credential_id in existing_credential_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED
        ),
    )
    token = make_challenge_token(admin, "register", options.challenge, rp_id)
    return json.loads(options_to_json(options)), token


def finish_registration(
    db: Session,
    admin: Admin,
    token: str,
    credential: Any,
    name: str,
    expected_origin: str,
) -> PasskeyCredential:
    """Verify a registration response and store the credential.

    Raises ``ValueError`` (safe message, no internals) on an
    invalid/expired challenge, a failed verification, or a
    credential that is already registered. The caller commits
    nothing — this function commits the new row itself.
    """
    verified = verify_challenge_token(db, token, "register")
    if verified is None:
        raise ValueError("invalid or expired challenge")
    token_admin, challenge, rp_id = verified
    if token_admin.id != admin.id:
        raise ValueError("invalid or expired challenge")
    try:
        result = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
        )
    except Exception as exc:  # noqa: BLE001 — library raises many types
        logger.warning("passkey registration verification failed: %s", exc)
        raise ValueError("verification failed") from exc
    credential_id = bytes_to_base64url(result.credential_id)
    existing = (
        db.query(PasskeyCredential)
        .filter(PasskeyCredential.credential_id == credential_id)
        .first()
    )
    if existing is not None:
        raise ValueError("this passkey is already registered")
    transports = None
    if isinstance(credential, dict):
        response = credential.get("response") or {}
        if isinstance(response, dict):
            raw_transports = response.get("transports")
            if isinstance(raw_transports, list):
                transports = [
                    str(t) for t in raw_transports if isinstance(t, str)
                ]
    row = PasskeyCredential(
        admin_id=admin.id,
        credential_id=credential_id,
        public_key=bytes_to_base64url(result.credential_public_key),
        sign_count=result.sign_count,
        transports_json=json.dumps(transports) if transports else None,
        name=(name or "").strip()[:64] or "Passkey",
        rp_id=rp_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def begin_login(
    admin: Admin,
    rp_id: str,
    credentials: list[PasskeyCredential],
) -> tuple[dict[str, Any], str]:
    """Authentication options + challenge token for ``admin``.

    ``allow_credentials`` lists the admin's registered passkeys so
    the browser offers exactly those. Raises ``ValueError`` when
    the admin has no passkeys (the login page hides the button
    then, so this is a belt-and-braces check).
    """
    if not credentials:
        raise ValueError("no passkeys registered")
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(cred.credential_id)
            )
            for cred in credentials
        ],
    )
    token = make_challenge_token(admin, "login", options.challenge, rp_id)
    return json.loads(options_to_json(options)), token


def finish_login(
    db: Session,
    token: str,
    credential: Any,
    expected_origin: str,
) -> PasskeyCredential:
    """Verify an authentication response; returns the credential
    used (with its sign count + last-used time updated).

    Raises ``ValueError`` (safe message) on an invalid/expired
    challenge, an unknown credential, or a failed verification —
    including a sign-count regression (cloned credential). The
    caller creates the session from the returned credential's
    ``admin_id``.
    """
    verified = verify_challenge_token(db, token, "login")
    if verified is None:
        raise ValueError("invalid or expired challenge")
    admin, challenge, rp_id = verified
    raw_id = None
    if isinstance(credential, dict):
        raw_id = credential.get("rawId") or credential.get("id")
    if not isinstance(raw_id, str):
        raise ValueError("unknown credential")
    row = (
        db.query(PasskeyCredential)
        .filter(PasskeyCredential.credential_id == raw_id)
        .first()
    )
    if row is None or row.admin_id != admin.id:
        raise ValueError("unknown credential")
    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=expected_origin,
            credential_public_key=base64url_to_bytes(row.public_key),
            credential_current_sign_count=row.sign_count,
        )
    except Exception as exc:  # noqa: BLE001 — library raises many types
        logger.warning("passkey login verification failed: %s", exc)
        raise ValueError("verification failed") from exc
    row.sign_count = result.new_sign_count
    row.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return row
