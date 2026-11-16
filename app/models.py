"""SQLAlchemy 2.0 models for sparky-manager (see DESIGN.md §4).

Original code, written from scratch for this project.

Rules enforced by the backend (not just the UI):
- A user is usable iff enabled AND not expired AND under its traffic
  limit (see :func:`user_is_usable`); a client is usable iff the
  client, its user and its inbound are all usable (see
  :func:`client_is_usable`) AND the client is not frozen (see
  :func:`client_is_frozen`). Renderers omit unusable clients.
- ``traffic_used_bytes`` is a running total; the traffic syncer adds
  *deltas* only, never overwrites. ``traffic_daily`` is the history.
- Deleting a user deletes its clients (FK cascade) and regenerates
  configs (done by the caller).
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all panel tables."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(value: datetime) -> datetime:
    """SQLite stores datetimes without tzinfo; treat a naive value read
    back from the DB as UTC so comparisons never raise."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def generate_sub_token() -> str:
    """Random 32-char URL-safe subscription token (hex, per user)."""
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Admin / settings
# ---------------------------------------------------------------------------


class Admin(Base):
    """Exactly one row in Phase 1 (username ``admin``).

    ``password_hash`` uses the ``pbkdf2$iterations$salt$hash`` format
    produced by :mod:`app.auth` (stdlib PBKDF2-HMAC-SHA256).
    """

    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="admin", cascade="all, delete-orphan"
    )
    audit_entries: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="admin"
    )


class Setting(Base):
    """Single-row key/value settings (panel port, domain, Reality keys,
    TLS mode, traffic-sync interval, ...). No .env sprawl."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ---------------------------------------------------------------------------
# Inbounds / users / clients
# ---------------------------------------------------------------------------


class Inbound(Base):
    """One listening inbound, across both cores.

    ``core``: ``xray`` | ``singbox`` | ``wireguard`` | ``ikev2`` |
    ``openvpn`` | ``openconnect`` | ``amneziawg``. ``protocol``: ``vless`` | ``vmess`` |
    ``trojan`` | ``shadowsocks`` | ``hysteria2`` | ``tuic`` | ``anytls`` |
    ``naive`` | ``shadowtls`` | ``wireguard`` | ``amneziawg`` |
    ``openvpn`` | ``openconnect`` | ``ikev2``.
    ``stream_json`` is a JSON blob so a new transport needs no migration.
    """

    __tablename__ = "inbounds"
    # NOTE (coordinator fix, 2026-11-11): port is NOT unique on its own.
    # The default first pair shares port 443 across transports —
    # VLESS+Reality on TCP 443 and Hysteria2 on UDP 443. Uniqueness is
    # (port, protocol); same-transport clashes are caught by the
    # renderers/validators, which enforce uniqueness per transport.
    __table_args__ = (UniqueConstraint("port", "protocol"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tag: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    core: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    stream_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    remark: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    clients: Mapped[list["Client"]] = relationship(
        "Client", back_populates="inbound", cascade="all, delete-orphan"
    )

    @property
    def stream(self) -> dict[str, Any]:
        """``stream_json`` parsed as a dict (``{}`` when empty/invalid)."""
        try:
            data = json.loads(self.stream_json or "{}")
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    @stream.setter
    def stream(self, value: dict[str, Any]) -> None:
        self.stream_json = json.dumps(value)


class User(Base):
    """One person. Credentials live per (user, inbound) in :class:`Client`."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    traffic_limit_bytes: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # NULL = unlimited
    traffic_used_bytes: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )  # NULL = never
    sub_token: Mapped[str] = mapped_column(
        String(64), unique=True, default=generate_sub_token, nullable=False
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    clients: Mapped[list["Client"]] = relationship(
        "Client", back_populates="user", cascade="all, delete-orphan"
    )
    traffic_days: Mapped[list["TrafficDaily"]] = relationship(
        "TrafficDaily", back_populates="user", cascade="all, delete-orphan"
    )


class Client(Base):
    """One credential per (user, inbound) — what the config renderers
    and the link builders both read."""

    __tablename__ = "clients"
    __table_args__ = (UniqueConstraint("user_id", "inbound_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    inbound_id: Mapped[int] = mapped_column(
        ForeignKey("inbounds.id", ondelete="CASCADE"), nullable=False
    )
    uuid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    flow: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="clients")
    inbound: Mapped["Inbound"] = relationship("Inbound", back_populates="clients")

    @property
    def extra(self) -> dict[str, Any]:
        """``extra_json`` parsed as a dict (``{}`` when empty/invalid)."""
        if not self.extra_json:
            return {}
        try:
            data = json.loads(self.extra_json)
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    @extra.setter
    def extra(self, value: dict[str, Any]) -> None:
        self.extra_json = json.dumps(value)


# ---------------------------------------------------------------------------
# Traffic history / audit
# ---------------------------------------------------------------------------


class TrafficDaily(Base):
    """Append-only daily rollup (one row per user per day). The syncer
    upserts today's row; the dashboard graphs history from here."""

    __tablename__ = "traffic_daily"
    __table_args__ = (UniqueConstraint("user_id", "date"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    date: Mapped[Any] = mapped_column(Date, nullable=False)
    up_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    down_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="traffic_days")


class AuditLog(Base):
    """Admin actions only in Phase 1."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("admins.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    admin: Mapped[Optional["Admin"]] = relationship(
        "Admin", back_populates="audit_entries"
    )


# ---------------------------------------------------------------------------
# Server-side login sessions
# ---------------------------------------------------------------------------


class Session(Base):
    """Server-side login session. Only the SHA-256 hash of the token is
    stored; the raw token is handed to the browser once (HttpOnly
    cookie) and never persisted. Logout deletes the row, which
    invalidates the session immediately."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    admin_id: Mapped[int] = mapped_column(
        ForeignKey("admins.id", ondelete="CASCADE"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    admin: Mapped["Admin"] = relationship("Admin", back_populates="sessions")


# ---------------------------------------------------------------------------
# Best-panel program, Phase B (2026-11-16) — NEW TABLES ONLY.
#
# The panel has no migration system (``create_all()`` only), so new
# COLUMNS on existing tables would silently not exist on the live
# server. Phase B therefore stores all new state in NEW tables
# (``create_all`` creates them on existing installs), in the
# ``settings`` table, or in ``clients.extra_json``. Nothing below
# touches an existing table.
# ---------------------------------------------------------------------------


class UserTemplate(Base):
    """A reusable user plan (Phase B item 9, PasarGuard templates).

    An admin defines a template once (quota, expiry, which inbounds
    the user gets, reset cycle) and applies it when creating a user.
    ``inbound_ids_json`` is a JSON list of inbound ids; an empty
    list means "every enabled inbound" (the normal new-user
    behaviour). ``expiry_mode`` is ``"fixed"`` (``expiry_days`` from
    creation) or ``"first_use"`` (the clock starts at first use —
    see :class:`UserLifecycle`).
    """

    __tablename__ = "user_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    traffic_limit_bytes: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # NULL = unlimited
    expiry_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )  # NULL = never expires
    expiry_mode: Mapped[str] = mapped_column(
        String(16), default="fixed", nullable=False
    )
    inbound_ids_json: Mapped[str] = mapped_column(
        Text, default="[]", nullable=False
    )
    reset_cycle: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # NULL = no automatic reset (see app/lifecycle.py)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    @property
    def inbound_ids(self) -> list[int]:
        """``inbound_ids_json`` parsed as a list of ints."""
        try:
            data = json.loads(self.inbound_ids_json or "[]")
        except (ValueError, TypeError):
            return []
        if not isinstance(data, list):
            return []
        out: list[int] = []
        for value in data:
            try:
                out.append(int(value))
            except (TypeError, ValueError):
                continue
        return out

    @inbound_ids.setter
    def inbound_ids(self, value: list[int]) -> None:
        self.inbound_ids_json = json.dumps([int(v) for v in value])


class UserLifecycle(Base):
    """Per-user lifecycle state (Phase B items 10–11).

    One row per user that uses any lifecycle feature (users without
    a row behave exactly as before: fixed expiry, no reset, no
    renewal, no lifetime counter). ``expiry_strategy`` is ``"fixed"``
    or ``"first_use"``; for ``"first_use"`` the expiry clock starts
    when ``first_use_at`` is first set (first subscription fetch or
    first recorded traffic) and ``expires_at`` on the user row is
    then ``first_use_at + usage_duration_days``.

    ``reset_cycle`` is one of ``"daily"`` / ``"weekly"`` / ``"monthly"`` /
    ``"month_rolling"`` (see :mod:`app.lifecycle`); ``reset_day`` is
    the day-of-month for ``"monthly"`` (1–28). ``renewal_mode`` is
    ``"rolling"`` (extend by ``renewal_interval_days`` from expiry),
    ``"calendar_day"`` (next occurrence of ``renewal_day``) or
    ``"calendar_weekday"`` (next occurrence of ``renewal_weekday``,
    0=Monday); ``renewal_max`` caps the number of automatic renewals
    (NULL = unlimited), ``renewals_done`` counts them.
    ``lifetime_bytes`` is the never-reset usage counter (Marzban's
    ``lifetime_used_traffic``); resets only touch
    ``users.traffic_used_bytes``.
    """

    __tablename__ = "user_lifecycle"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    expiry_strategy: Mapped[str] = mapped_column(
        String(16), default="fixed", nullable=False
    )
    usage_duration_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    first_use_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reset_cycle: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    reset_day: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_reset_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    renewal_mode: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    renewal_interval_days: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    renewal_day: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    renewal_weekday: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    renewal_max: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    renewals_done: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    lifetime_bytes: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )


class ApiToken(Base):
    """Scoped, expiring API token (Phase B item 12, 3x-ui/Remnawave).

    Only the SHA-256 hash is stored — the raw token is shown to the
    admin exactly once, at creation, and never again (like the login
    session tokens in :class:`Session`). ``scopes_json`` is a JSON
    list of scope names (``"admin"`` satisfies every scope);
    ``expires_at`` NULL means the token never expires (Remnawave
    mandates expiry; sparky warns instead — a never-expiring token
    is the admin's explicit choice, shown as such in the UI).
    """

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    scopes_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    @property
    def scopes(self) -> list[str]:
        """``scopes_json`` parsed as a list of scope names."""
        try:
            data = json.loads(self.scopes_json or "[]")
        except (ValueError, TypeError):
            return []
        return [str(s) for s in data] if isinstance(data, list) else []

    @scopes.setter
    def scopes(self, value: list[str]) -> None:
        self.scopes_json = json.dumps([str(s) for s in value])


class WebhookEndpoint(Base):
    """An outgoing webhook (Phase B item 14, Remnawave model).

    Panel events (see :data:`app.events.EVENT_CATALOG`) are POSTed
    as JSON to ``url``, signed HMAC-SHA256 with ``secret``
    (``X-Sparky-Signature: sha256=<hex>``). ``events_json`` is the
    subscribed event list; an empty list means "all catalog events".
    The secret is stored in the clear — it must be usable to sign,
    like the Telegram bot token in settings (a backup ZIP is a
    credential bundle either way; DESIGN.md §7 says so).
    ``last_status`` / ``last_error`` / ``last_delivered_at`` record
    the most recent delivery attempt (or failure).
    """

    __tablename__ = "webhook_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    secret: Mapped[str] = mapped_column(Text, nullable=False)
    events_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_delivered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    @property
    def events(self) -> list[str]:
        """``events_json`` parsed as a list of event names."""
        try:
            data = json.loads(self.events_json or "[]")
        except (ValueError, TypeError):
            return []
        return [str(s) for s in data] if isinstance(data, list) else []

    @events.setter
    def events(self, value: list[str]) -> None:
        self.events_json = json.dumps([str(s) for s in value])


class UserTag(Base):
    """One tag on one user (Phase B item 16).

    Notes already exist on the user row; tags are the filterable
    half (no panel documents per-user tags — an easy differentiator).
    Tags are single tokens (see :data:`app.tags.TAG_RE`); the
    (user, tag) pair is unique.
    """

    __tablename__ = "user_tags"
    __table_args__ = (UniqueConstraint("user_id", "tag"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tag: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Device(Base):
    """One HWID-identified device on one client (Phase B item 17).

    Registered at subscription fetch time from the ``x-hwid``
    (+ ``x-device-os`` / ``x-device-model``) headers cooperating
    clients send (Happ, v2RayTun, …). The per-client device LIMIT
    lives in ``clients.extra_json`` (``hwid_limit`` — NULL means no
    limit, i.e. the feature is off for that client); this table only
    records devices, so tracking works whether or not a limit is
    set. Clients that send no HWID header are never registered and
    never limited (the documented 404 trap: v2rayNG / Hiddify send
    no HWID, so a limit must never lock them out).
    """

    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("client_id", "hwid"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    hwid: Mapped[str] = mapped_column(String(128), nullable=False)
    os: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # The client this device belongs to (used by the user-detail
    # devices table to show the inbound tag). A relationship adds no
    # column — the schema is unchanged.
    client: Mapped["Client"] = relationship("Client")


class ManagedHost(Base):
    """A per-inbound endpoint override (Phase B item 18, 3x-ui
    managed hosts).

    Decouples "what the core listens on" from "what clients are
    told to connect to" (CDN fronting, several domains/regions for
    one inbound). The first enabled host (lowest ``sort_order``,
    then lowest id) wins for the inbound: its ``address`` replaces
    the subscription host, its ``port`` (when set) replaces the
    inbound port, and its ``sni`` (when set) replaces the TLS /
    Reality SNI in generated share links and sing-box feeds. The
    server-side configs are untouched — the core still listens on
    the inbound's own port. File exports (.conf / .ovpn / …) use
    the default host, not managed hosts (documented limitation).
    """

    __tablename__ = "managed_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    inbound_id: Mapped[int] = mapped_column(
        ForeignKey("inbounds.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sni: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    remark: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class IpBan(Base):
    """An IP-limit ban (Phase C item 20, 3x-ui ``3x-ipl`` jail).

    One row per (user, IP) the IP-limit job banned through
    fail2ban. The row is the panel's record of the ban — the ban
    itself lives in fail2ban (jail ``sparky-ipl``, 30-minute
    bantime) — and exists so the job can dedup (never re-ban an
    IP that is already banned) and so the admin can see active
    bans on the user page and unban early. Expired rows are pruned
    by the job; an unban deletes the row. ``expires_at`` mirrors
    the fail2ban bantime so the UI can show when the ban lifts.
    """

    __tablename__ = "ip_bans"
    __table_args__ = (UniqueConstraint("user_id", "ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    banned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class PasskeyCredential(Base):
    """A registered WebAuthn passkey (Phase C item 22).

    One row per passkey the admin registered (Settings → Security).
    ``credential_id`` is the base64url credential ID the browser
    returns; ``public_key`` is the base64url COSE public key bytes
    the ``webauthn`` library needs to verify assertions.
    ``sign_count`` is the authenticator's signature counter at the
    last successful login — a regression (a lower count than the
    stored one) means the credential was cloned and the login is
    rejected. ``rp_id`` is the relying-party ID the credential was
    registered for (the panel host at registration time); a
    passkey only works on the host it was registered for, so an
    admin who reaches the panel by several hosts registers one
    passkey per host. Password + TOTP always remain usable —
    passkeys are an additional sign-in method, never a replacement.
    """

    __tablename__ = "passkey_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    admin_id: Mapped[int] = mapped_column(
        ForeignKey("admins.id", ondelete="CASCADE"), nullable=False
    )
    credential_id: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    transports_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    rp_id: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def transports(self) -> list[str]:
        """Transport hints (``"usb"`` / ``"nfc"`` / ``"ble"`` /
        ``"internal"`` / …) as a list; ``[]`` when unset."""
        if not self.transports_json:
            return []
        try:
            value = json.loads(self.transports_json)
        except (ValueError, TypeError):
            return []
        return value if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# Usability rules (DESIGN.md §4)
# ---------------------------------------------------------------------------


def user_is_usable(user: "User", now: Optional[datetime] = None) -> bool:
    """A user is usable iff enabled AND not expired AND under quota.

    ``now`` defaults to the current UTC time; pass an explicit value in
    tests. A ``None`` expiry means "never expires"; a ``None`` traffic
    limit means "unlimited".
    """
    now = _as_aware(now or _utcnow())
    if not user.enabled:
        return False
    if user.expires_at is not None and _as_aware(user.expires_at) <= now:
        return False
    if (
        user.traffic_limit_bytes is not None
        and user.traffic_used_bytes >= user.traffic_limit_bytes
    ):
        return False
    return True


def user_unusable_reason(
    user: "User", now: Optional[datetime] = None
) -> Optional[str]:
    """Why ``user`` is unusable: ``"disabled"``, ``"expired"`` or
    ``"limited"`` (over quota) — ``None`` when the user is usable.

    The same rule as :func:`user_is_usable`, split into the reason
    so the subscription placeholder feed (Phase A) can name the
    state instead of serving a silently empty feed. Precedence:
    disabled beats expired beats limited (an admin-disabled user is
    disabled whatever else is true about them).
    """
    now = _as_aware(now or _utcnow())
    if not user.enabled:
        return "disabled"
    if user.expires_at is not None and _as_aware(user.expires_at) <= now:
        return "expired"
    if (
        user.traffic_limit_bytes is not None
        and user.traffic_used_bytes >= user.traffic_limit_bytes
    ):
        return "limited"
    return None


def client_is_frozen(client: "Client") -> bool:
    """True when the client's ``extra`` JSON carries ``frozen: true``.

    Freeze is a per-client hold (Phase 2): a frozen client cannot
    connect — it is omitted from every rendered config, share link
    and subscription feed — but its credentials, config and traffic
    history are kept, so unfreezing restores it exactly. Distinct
    from ``enabled=False`` (admin off-switch) and from delete.
    Defensive: any unreadable/missing ``extra`` counts as not frozen.
    """
    try:
        extra = client.extra
    except (AttributeError, TypeError, ValueError):
        return False
    if not isinstance(extra, dict):
        return False
    return bool(extra.get("frozen"))


def client_is_usable(
    client: "Client",
    user: "User",
    inbound: "Inbound",
    now: Optional[datetime] = None,
) -> bool:
    """A client is usable iff its own flag, its user and its inbound
    are all usable (DESIGN.md §4 rule, applied to the triple) AND it
    is not frozen (Phase 2: ``extra.frozen``)."""
    if not client.enabled:
        return False
    if not inbound.enabled:
        return False
    if client_is_frozen(client):
        return False
    return user_is_usable(user, now=now)


__all__ = [
    "Base",
    "Admin",
    "Setting",
    "Inbound",
    "User",
    "Client",
    "TrafficDaily",
    "AuditLog",
    "Session",
    # Phase B tables (new tables only — no existing-table change).
    "UserTemplate",
    "UserLifecycle",
    "ApiToken",
    "WebhookEndpoint",
    "UserTag",
    "Device",
    "ManagedHost",
    # Phase C tables (new tables only — no existing-table change).
    "IpBan",
    "PasskeyCredential",
    "generate_sub_token",
    "user_is_usable",
    "user_unusable_reason",
    "client_is_usable",
    "client_is_frozen",
]
