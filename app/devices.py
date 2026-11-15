"""HWID device tracking + per-client device limits (best-panel
program, Phase B item 17 — 3x-ui / PasarGuard / Remnawave).

Enforcement happens at **subscription fetch**, not at connection
time (there is no observation hook on live connections — the same
honest limit as the IP limit). Cooperating clients (Happ,
v2RayTun, Koala Clash, …) send ``x-hwid`` (+ ``x-device-os`` /
``x-device-model``) headers; the panel registers the device per
client and, when the client has a device limit, omits over-limit
clients from the feed.

The documented trap, handled plainly:

* **Clients that send no HWID header are never registered and
  never limited.** v2rayNG and the Hiddify app send no HWID — with
  a limit set, other panels 404 their whole subscription ("their
  subscription looks deleted"). Sparky never does that: no header
  means no enforcement, full feed.
* **The feature ships OFF by default**: a client with no
  ``hwid_limit`` in its ``extra_json`` is never limited (devices
  are still tracked for it, so the admin can see them before
  deciding to limit).
* **Over-limit means omitted, not 404**: a device past the limit
  simply does not see that client's config in the feed; the rest
  of the subscription still works. Which devices are "in" is
  first-come, first-served (oldest ``first_seen_at`` first), so a
  blocked device cannot displace an allowed one by re-fetching —
  and removing one device (single-device removal, PasarGuard's
  ``/hwids`` shape) frees the slot for the next-oldest device.
* **TTL cleanup**: devices unseen for ``hwid_device_ttl_days``
  (settings, default 90, 0 = never prune) are deleted by the
  sweeper, so the table cannot grow without bound.

The per-client limit lives in ``clients.extra_json`` as
``hwid_limit`` (NULL = no limit) — no schema change.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session as DbSession

from app.models import Client, Device, Inbound
from app.webcommon import _set_client_extra, get_setting

#: Headers cooperating clients send at subscription fetch.
HWID_HEADER = "x-hwid"
HWID_OS_HEADER = "x-device-os"
HWID_MODEL_HEADER = "x-device-model"

#: Setting key for the device TTL (days); 0 = never prune.
HWID_TTL_SETTING_KEY = "hwid_device_ttl_days"
HWID_TTL_DEFAULT_DAYS = 90

#: A device id longer than this is not a HWID, it is abuse.
HWID_MAX_LENGTH = 128
HWID_LIMIT_MAX = 100


def get_hwid_limit(client: Any) -> Optional[int]:
    """The client's device limit (None = no limit, feature off)."""
    try:
        extra = getattr(client, "extra", None) or {}
        limit = extra.get("hwid_limit")
    except (AttributeError, TypeError, ValueError):
        return None
    if limit is None:
        return None
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        return None
    return limit if 1 <= limit <= HWID_LIMIT_MAX else None


def set_hwid_limit(client: Any, limit: Optional[int]) -> None:
    """Set (or, for None, clear) the client's device limit in
    ``extra_json``. Does not commit."""
    _set_client_extra(client, "hwid_limit", limit)


def parse_hwid_limit(value: str) -> Optional[int]:
    """Form value -> limit: empty or ``0`` means no limit (None);
    otherwise an int in ``1..HWID_LIMIT_MAX``. Raises ValueError."""
    text = (value or "").strip()
    if not text:
        return None
    limit = int(text)
    if limit == 0:
        return None
    if not 1 <= limit <= HWID_LIMIT_MAX:
        raise ValueError("hwid limit out of range")
    return limit


def normalize_hwid(raw: Optional[str]) -> Optional[str]:
    """A cleaned HWID header value, or None when absent/blank/too
    long (never trust a header value blindly)."""
    hwid = (raw or "").strip()
    if not hwid or len(hwid) > HWID_MAX_LENGTH:
        return None
    return hwid


def register_device(
    db: DbSession,
    client: Any,
    hwid: str,
    os_name: Optional[str] = None,
    model: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Device:
    """Upsert the (client, hwid) device row: a new device gets
    ``first_seen_at`` = ``last_seen_at`` = now; a known device only
    moves ``last_seen_at`` (and refreshes os/model when the headers
    carry them). Commits."""
    now = now or datetime.now(timezone.utc)
    device = (
        db.query(Device)
        .filter(Device.client_id == client.id, Device.hwid == hwid)
        .first()
    )
    if device is None:
        device = Device(
            client_id=client.id,
            hwid=hwid,
            os=(os_name or "").strip()[:64] or None,
            model=(model or "").strip()[:128] or None,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(device)
    else:
        device.last_seen_at = now
        if (os_name or "").strip():
            device.os = os_name.strip()[:64]
        if (model or "").strip():
            device.model = model.strip()[:128]
    db.commit()
    return device


def _device_rank(db: DbSession, device: Device) -> int:
    """The device's position among its client's devices, oldest
    first (1-based). First-come, first-served: the ``limit`` oldest
    devices are allowed, the rest are over the limit."""
    rows = (
        db.query(Device)
        .filter(Device.client_id == device.client_id)
        .order_by(Device.first_seen_at, Device.id)
        .all()
    )
    for index, row in enumerate(rows, start=1):
        if row.id == device.id:
            return index
    return len(rows) + 1  # pragma: no cover — the device is in the list


def check_and_register(
    db: DbSession,
    clients: list[Any],
    hwid: Optional[str],
    os_name: Optional[str] = None,
    model: Optional[str] = None,
    now: Optional[datetime] = None,
) -> set[int]:
    """Subscription-fetch enforcement for one device.

    ``clients`` are the user's usable clients. When ``hwid`` is
    None (the client sent no header), nothing is registered and
    nothing is excluded — the feed is served whole. Otherwise the
    device is registered on every listed client, and a client is
    EXCLUDED (its id is returned) when it has a limit and this
    device's rank on it exceeds the limit. Commits (registrations).
    """
    excluded: set[int] = set()
    clean = normalize_hwid(hwid)
    if clean is None:
        return excluded
    for client in clients:
        device = register_device(db, client, clean, os_name, model, now=now)
        limit = get_hwid_limit(client)
        if limit is None:
            continue
        if _device_rank(db, device) > limit:
            excluded.add(client.id)
    return excluded


def devices_for_user(db: DbSession, user_id: int) -> list[dict[str, Any]]:
    """Every device of the user's clients, newest activity first:
    ``{"device", "client", "inbound", "allowed"}`` rows for the
    user detail page. ``allowed`` is False when the client's limit
    (if any) ranks this device out."""
    rows = (
        db.query(Device, Client, Inbound)
        .join(Client, Device.client_id == Client.id)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .filter(Client.user_id == user_id)
        .order_by(Device.last_seen_at.desc())
        .all()
    )
    out: list[dict[str, Any]] = []
    for device, client, inbound in rows:
        limit = get_hwid_limit(client)
        allowed = True
        if limit is not None:
            allowed = _device_rank(db, device) <= limit
        out.append(
            {
                "device": device,
                "client": client,
                "inbound": inbound,
                "allowed": allowed,
            }
        )
    return out


def remove_device(db: DbSession, device_id: int, user_id: int) -> bool:
    """Single-device removal (PasarGuard's ``/hwids`` shape): delete
    the device, freeing its slot. True when a device of THIS user
    was removed (a device of another user is never touched)."""
    row = (
        db.query(Device)
        .join(Client, Device.client_id == Client.id)
        .filter(Device.id == device_id, Client.user_id == user_id)
        .first()
    )
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def delete_devices_for_client(db: DbSession, client_id: int) -> int:
    """Delete all devices of a client (client deletion cleanup).
    Commits."""
    deleted = (
        db.query(Device)
        .filter(Device.client_id == client_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(deleted)


def get_ttl_days(db: DbSession) -> int:
    """The device TTL in days (settings, default 90; 0 = never
    prune). A bad value falls back to the default, never a crash."""
    try:
        value = int((get_setting(db, HWID_TTL_SETTING_KEY, "") or "").strip())
    except ValueError:
        return HWID_TTL_DEFAULT_DAYS
    if value < 0:
        return HWID_TTL_DEFAULT_DAYS
    return value


def prune_devices(
    db: DbSession, ttl_days: Optional[int] = None, now: Optional[datetime] = None
) -> int:
    """Delete devices unseen for longer than the TTL (0 = never
    prune). Returns the number deleted. Commits when anything was
    deleted."""
    if ttl_days is None:
        ttl_days = get_ttl_days(db)
    if ttl_days <= 0:
        return 0
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=int(ttl_days))
    deleted = (
        db.query(Device)
        .filter(Device.last_seen_at < cutoff)
        .delete(synchronize_session=False)
    )
    if deleted:
        db.commit()
    return int(deleted)


__all__ = [
    "HWID_HEADER",
    "HWID_OS_HEADER",
    "HWID_MODEL_HEADER",
    "HWID_TTL_SETTING_KEY",
    "HWID_TTL_DEFAULT_DAYS",
    "HWID_MAX_LENGTH",
    "HWID_LIMIT_MAX",
    "get_hwid_limit",
    "set_hwid_limit",
    "parse_hwid_limit",
    "normalize_hwid",
    "register_device",
    "check_and_register",
    "devices_for_user",
    "remove_device",
    "delete_devices_for_client",
    "get_ttl_days",
    "prune_devices",
]
