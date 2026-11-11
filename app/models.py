"""SQLAlchemy 2.0 models for sparky-manager (see DESIGN.md §4).

Original code, written from scratch for this project.

Rules enforced by the backend (not just the UI):
- A user is usable iff enabled AND not expired AND under its traffic
  limit (see :func:`user_is_usable`); a client is usable iff the
  client, its user and its inbound are all usable (see
  :func:`client_is_usable`). Renderers omit unusable clients.
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
    ``openvpn`` | ``openconnect``. ``protocol``: ``vless`` | ``vmess`` |
    ``trojan`` | ``shadowsocks`` | ``hysteria2`` | ``tuic`` | ``anytls`` |
    ``naive`` | ``shadowtls`` | ``wireguard`` | ...
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


def client_is_usable(
    client: "Client",
    user: "User",
    inbound: "Inbound",
    now: Optional[datetime] = None,
) -> bool:
    """A client is usable iff its own flag, its user and its inbound
    are all usable (DESIGN.md §4 rule, applied to the triple)."""
    if not client.enabled:
        return False
    if not inbound.enabled:
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
    "generate_sub_token",
    "user_is_usable",
    "client_is_usable",
]
