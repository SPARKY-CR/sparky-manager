"""IP-limit enforcement (Phase C item 20, 3x-ui ``3x-ipl`` jail).

Phase 2 stored a per-client IP limit (``clients.extra_json``
``ip_limit``) and showed it, but never enforced it — the panel had
no honest way to see connected IPs. The observation hook is Xray's
``GetUsersStats`` RPC (see :mod:`app.xray_stats`): with the
``statsUserOnline`` policy the renderer enables, one call returns
every user's currently-online IPs. A periodic job
(:func:`enforce_ip_limits_once`, driven by ``_ip_limit_loop`` in
:mod:`app.main`) keeps the newest ``limit`` IPs per user and bans
the rest through fail2ban (jail ``sparky-ipl``, 30-minute bantime,
installed by ``install.sh``).

Enforcement model (3x-ui's, minus the destructive half):

* Observation is per *user* (Xray's email is ``user-<id>``), while
  the limit is stored per *client*. The effective per-user limit is
  the **minimum** of the limits set on the user's Xray-core clients
  (``inbound.core == "xray"``); no limit set anywhere means no
  enforcement. The limit is off by default — a limit of 0 or absent
  is unlimited, exactly as before this phase.
* A ban is a **fail2ban ban only**. 3x-ui also force-cycles the
  client (gRPC RemoveUser + AddUser) to kill live sessions, but
  that needs per-protocol account protobuf encoding for 9 protocols
  and a failed re-add after a successful remove locks the user out
  — and 3x-ui's own audit notes a hot RemoveUser cannot close live
  sessions anyway (Xray has no KickUser API). The ban already blocks
  reconnection, and the next Xray restart/re-render drops live
  sessions. Documented limitation: an established session from a
  banned IP is not killed immediately.
* Each ban is written two ways: a direct ``fail2ban-client set
  sparky-ipl banip <ip>`` call (immediate, deterministic) AND a
  ``[LIMIT_IP]`` line in ``<data>/logs/iplimit.log`` (audit trail,
  and the jail's filter matches it — belt and braces; fail2ban
  dedups bans). The panel keeps an :class:`app.models.IpBan` row
  per ban so the job never re-bans an already-banned IP and the
  admin can see active bans on the user page and unban early.

Scope (honest): Xray-core inbounds only. WireGuard / AmneziaWG
have no hook to need — the kernel allows one endpoint per key, so
a per-client IP limit above 1 is vacuous there. OpenVPN (status
file), OpenConnect (``occtl show users``) and IKEv2 (``swanctl
--list-sas``) have observation hooks in principle, but each needs
a privileged reader + parser — not implemented in this phase
(DESIGN.md §15.4). sing-box-core inbounds (Hysteria2/TUIC/AnyTLS/
Naive/ShadowTLS on sing-box) have no per-user observation API at
all. Note Hysteria2 *can* be Xray core (the ``hysteria2_core``
setting) — the filter is ``inbound.core == "xray"``, not protocol.

Fail-soft, always: a dead Stats API, a missing fail2ban, or a
failing ban call means "no enforcement this tick", never a crashed
panel. Every ban/unban failure is logged; the job keeps going.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from app import panel_log as panel_log_mod
from app import xray_stats as xray_stats_mod
from app.models import Client, Inbound, IpBan, User
from app.xray import parse_user_email
from app.xray_stats import OnlineIP, UserOnlineStats

logger = logging.getLogger(__name__)

__all__ = [
    "FAIL2BAN_JAIL",
    "IP_BAN_MINUTES",
    "IP_LIMIT_INTERVAL_SECONDS",
    "IPLIMIT_LOG_NAME",
    "active_bans",
    "ban_ip",
    "effective_ip_limit",
    "enforce_ip_limits_once",
    "get_iplimit_log_path",
    "prune_expired_bans",
    "select_excess_ips",
    "unban_ip",
    "write_limit_log_line",
]

#: fail2ban jail name (installed by install.sh; the sudoers block
#: covers ``fail2ban-client set sparky-ipl banip/unbanip *``).
FAIL2BAN_JAIL = "sparky-ipl"

#: How long a ban lasts (minutes). Mirrors the jail's ``bantime``
#: (1800 s) in install.sh — keep the two in sync; the IpBan row's
#: ``expires_at`` is computed from this constant.
IP_BAN_MINUTES = 30

#: Seconds between IP-limit job ticks (3x-ui checks every 10 s; the
#: Xray "online" window is 20 s of activity, so a 10 s tick samples
#: overlapping windows and never misses an IP that stays online).
IP_LIMIT_INTERVAL_SECONDS = 10

#: The iplimit audit log (next to panel.log; the jail's filter
#: matches its ``[LIMIT_IP]`` lines).
IPLIMIT_LOG_NAME = "iplimit.log"

#: The fail2ban filter matches lines of this shape (the date prefix
#: lets fail2ban's default date templates match).
_LOG_LINE_FORMAT = "{when} [LIMIT_IP] {ip} user-{user_id}\n"

#: Runner type: ``(returncode, stdout, stderr)`` — the
#: :func:`app.main._run_privileged` contract. Injected (tests pass
#: a stub); the default lazily imports ``app.main`` so this module
#: never creates a main <-> ip_limits import cycle.
Runner = Callable[..., tuple[int, str, str]]


def _default_runner() -> Runner:
    """The panel's privileged runner (lazy import — see above)."""
    from app.main import _run_privileged  # noqa: PLC0415

    return _run_privileged


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_iplimit_log_path(data_dir: Path | str | None = None) -> Path:
    """``<data>/logs/iplimit.log`` (next to ``panel.log``)."""
    return panel_log_mod.get_log_dir(data_dir) / IPLIMIT_LOG_NAME


def write_limit_log_line(
    ip: str, user_id: int, data_dir: Path | str | None = None
) -> bool:
    """Append one ``[LIMIT_IP]`` line to the iplimit log.

    The line is the jail filter's input and the audit trail. Never
    raises — a log failure must not lose the ban (the direct
    fail2ban-client call already happened).
    """
    path = get_iplimit_log_path(data_dir)
    line = _LOG_LINE_FORMAT.format(
        when=_utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ip=ip,
        user_id=user_id,
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as exc:
        logger.warning("could not write iplimit log %s: %s", path, exc)
        return False
    return True


def _client_ip_limit(client: Client) -> Optional[int]:
    """The client's stored IP limit (``extra.ip_limit``), or None.

    The write side validates 1–1000 (``_parse_ip_limit`` in
    :mod:`app.routes.users`); this re-validates defensively so a
    stale or corrupt value can never enforce a nonsense limit.
    0 / absent / non-numeric / out of range all mean "no limit".
    """
    try:
        extra = client.extra
    except (AttributeError, TypeError, ValueError):
        return None
    if not isinstance(extra, dict):
        return None
    try:
        limit = int(extra.get("ip_limit"))
    except (TypeError, ValueError):
        return None
    if limit < 1 or limit > 1000:
        return None
    return limit


def effective_ip_limit(db: Session, user: User) -> Optional[int]:
    """The user's effective IP limit: the **minimum** of the limits
    set on the user's Xray-core clients — or ``None`` (unlimited)
    when no Xray-core client of the user carries a limit.

    Observation is per user (Xray's email is ``user-<id>``) while
    the limit is stored per client, so the minimum is the honest
    reading: a user with one client limited to 2 IPs and another
    unlimited is still limited to 2 IPs overall. Clients on
    non-Xray inbounds (sing-box core, native protocols) carry no
    observable IPs and are ignored.
    """
    clients = (
        db.query(Client)
        .join(Inbound, Client.inbound_id == Inbound.id)
        .filter(Client.user_id == user.id, Inbound.core == "xray")
        .all()
    )
    limits = [
        limit
        for limit in (_client_ip_limit(c) for c in clients)
        if limit is not None
    ]
    return min(limits) if limits else None


def select_excess_ips(online: list[OnlineIP], limit: int) -> list[str]:
    """The IPs over ``limit``: keep the newest ``limit`` by
    ``last_seen``, ban the rest. Pure function (no DB, no I/O).

    Defensive: the same IP twice keeps its newest sighting (Xray
    should never report duplicates, but a duplicate must not eat a
    slot). Ties on ``last_seen`` break by IP string so the result
    is deterministic.
    """
    newest: dict[str, int] = {}
    for entry in online:
        if entry.ip not in newest or entry.last_seen > newest[entry.ip]:
            newest[entry.ip] = entry.last_seen
    ranked = sorted(newest.items(), key=lambda kv: (-kv[1], kv[0]))
    return [ip for ip, _ in ranked[limit:]]


def _valid_ip(ip: str) -> bool:
    """True when ``ip`` parses as an IP address (v4 or v6).

    The IP comes from Xray's API, but it is about to be handed to a
    sudo command — never pass an unvalidated string there.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def ban_ip(
    db: Session,
    user_id: int,
    ip: str,
    *,
    runner: Optional[Runner] = None,
    now: Optional[datetime] = None,
    data_dir: Path | str | None = None,
) -> bool:
    """Ban ``ip`` for ``user_id`` (fail2ban + log line + IpBan row).

    Returns True when the fail2ban call succeeded (rc 0); the log
    line is written and the IpBan row created either way — the row
    is the panel's record of the attempt, and the log line lets the
    jail's filter catch the IP even if the direct call failed.
    Never raises; an invalid IP is refused (logged, False).
    """
    if not _valid_ip(ip):
        logger.warning("refusing to ban invalid IP %r", ip)
        return False
    now = now or _utcnow()
    run = runner or _default_runner()
    rc, _out, err = run(
        "fail2ban-client",
        "set",
        FAIL2BAN_JAIL,
        "banip",
        ip,
        timeout=15,
    )
    if rc != 0:
        logger.warning(
            "fail2ban banip %s failed (rc=%s): %s", ip, rc, err.strip()
        )
    write_limit_log_line(ip, user_id, data_dir=data_dir)
    existing = (
        db.query(IpBan)
        .filter(IpBan.user_id == user_id, IpBan.ip == ip)
        .first()
    )
    if existing is None:
        db.add(
            IpBan(
                user_id=user_id,
                ip=ip,
                banned_at=now,
                expires_at=now + timedelta(minutes=IP_BAN_MINUTES),
            )
        )
    else:  # refresh the expiry (a re-ban restarts the bantime)
        existing.banned_at = now
        existing.expires_at = now + timedelta(minutes=IP_BAN_MINUTES)
    db.commit()
    return rc == 0


def unban_ip(
    db: Session,
    ban: IpBan,
    *,
    runner: Optional[Runner] = None,
) -> bool:
    """Unban one IpBan row (fail2ban + delete the row).

    Returns True when the fail2ban call succeeded. The row is
    deleted either way — it is the panel's record, not the ban
    itself (fail2ban's own bantime expires the ban regardless, and
    the job re-bans on the next tick if the IP is still over the
    limit). Never raises.
    """
    run = runner or _default_runner()
    rc, _out, err = run(
        "fail2ban-client",
        "set",
        FAIL2BAN_JAIL,
        "unbanip",
        ban.ip,
        timeout=15,
    )
    if rc != 0:
        logger.warning(
            "fail2ban unbanip %s failed (rc=%s): %s",
            ban.ip,
            rc,
            err.strip(),
        )
    db.delete(ban)
    db.commit()
    return rc == 0


def prune_expired_bans(
    db: Session, now: Optional[datetime] = None
) -> int:
    """Delete IpBan rows whose ``expires_at`` has passed (fail2ban
    already lifted those bans). Returns the number pruned."""
    now = now or _utcnow()
    rows = db.query(IpBan).filter(IpBan.expires_at <= now).all()
    for row in rows:
        db.delete(row)
    if rows:
        db.commit()
    return len(rows)


def active_bans(db: Session, user_id: int) -> list[IpBan]:
    """The user's not-yet-expired IpBan rows, newest first (for the
    user detail page)."""
    return (
        db.query(IpBan)
        .filter(IpBan.user_id == user_id, IpBan.expires_at > _utcnow())
        .order_by(IpBan.banned_at.desc())
        .all()
    )


def enforce_ip_limits_once(
    db: Session,
    *,
    collect_fn: Optional[Callable[[], list[UserOnlineStats]]] = None,
    runner: Optional[Runner] = None,
    now: Optional[datetime] = None,
    data_dir: Path | str | None = None,
) -> dict[str, Any]:
    """One enforcement pass: prune, observe, ban the excess.

    ``collect_fn`` injects the online-stats source for tests
    (default: a live :func:`app.xray_stats.get_users_stats` call).
    Returns a summary dict (``pruned``, ``users_checked``,
    ``banned`` as ``[(user_id, ip)]``) for logging and tests.
    Never raises — any failure means "no enforcement this tick".
    """
    now = now or _utcnow()
    summary: dict[str, Any] = {"pruned": 0, "users_checked": 0, "banned": []}
    try:
        summary["pruned"] = prune_expired_bans(db, now=now)
    except Exception:  # noqa: BLE001 — pruning must not stop the pass
        logger.exception("IP-limit prune failed")
        db.rollback()
    try:
        online = (
            collect_fn()
            if collect_fn is not None
            else xray_stats_mod.get_users_stats()
        )
    except Exception:  # noqa: BLE001 — fail soft by design
        logger.warning("IP-limit collection failed")
        return summary
    if not isinstance(online, list):
        return summary
    for user_stats in online:
        try:
            user_id = parse_user_email(user_stats.email)
        except Exception:  # noqa: BLE001 — one bad email, not the pass
            continue
        if user_id is None:
            continue
        user = db.get(User, user_id)
        if user is None:
            continue
        summary["users_checked"] += 1
        try:
            limit = effective_ip_limit(db, user)
        except Exception:  # noqa: BLE001 — one bad user, not the pass
            logger.exception("IP-limit lookup failed for user %s", user_id)
            db.rollback()
            continue
        if limit is None:
            continue
        excess = select_excess_ips(user_stats.ips, limit)
        for ip in excess:
            already = (
                db.query(IpBan)
                .filter(
                    IpBan.user_id == user_id,
                    IpBan.ip == ip,
                    IpBan.expires_at > now,
                )
                .first()
            )
            if already is not None:
                continue  # already banned — fail2ban dedups anyway
            try:
                if ban_ip(
                    db,
                    user_id,
                    ip,
                    runner=runner,
                    now=now,
                    data_dir=data_dir,
                ):
                    summary["banned"].append((user_id, ip))
            except Exception:  # noqa: BLE001 — one bad ban, not the pass
                logger.exception("IP-limit ban failed for %s", ip)
                db.rollback()
    return summary
