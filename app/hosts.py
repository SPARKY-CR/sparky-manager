"""Managed hosts — per-inbound endpoint overrides (best-panel
program, Phase B item 18, 3x-ui's managed hosts).

One inbound, several faces: the core listens on its own port, but
clients are told to connect to a different address / port / SNI
(CDN fronting, several domains or regions for one inbound, a
burned SNI replaced without touching the server config). The
first enabled host (lowest ``sort_order``, then lowest id) wins
for the inbound.

Applied in the link/feed builders only (``_links_for_user`` and
``_singbox_outbounds_for`` in ``app.main`` — the ZedSecure bundle
reuses them, so it inherits the override): the host's ``address``
replaces the subscription host, its ``port`` (when set) replaces
the inbound port, and its ``sni`` (when set) replaces the TLS /
Reality SNI the client sends. Server-side configs are untouched.
File exports (.conf / .ovpn / .mobileconfig / …) use the default
host, not managed hosts — a documented limitation (the file
builders take a bare host string, not an inbound row).
"""

from __future__ import annotations

import copy
import re
from typing import Any, Optional

from sqlalchemy.orm import Session as DbSession

from app.models import ManagedHost

#: A host address: hostname or IP, no scheme, no path, no spaces.
ADDRESS_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")
#: An SNI: a hostname, no spaces, no port.
SNI_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

HOST_PORT_MIN = 1
HOST_PORT_MAX = 65535


def validate_host(
    address: str, port: Optional[int], sni: Optional[str]
) -> Optional[str]:
    """Validate a managed host's fields. Returns an error key
    (``invalid_host_address`` / ``invalid_host_port`` /
    ``invalid_host_sni``) or None when valid."""
    address = (address or "").strip()
    if not address or not ADDRESS_RE.match(address):
        return "invalid_host_address"
    if port is not None and not HOST_PORT_MIN <= int(port) <= HOST_PORT_MAX:
        return "invalid_host_port"
    sni = (sni or "").strip()
    if sni and not SNI_RE.match(sni):
        return "invalid_host_sni"
    return None


def hosts_for_inbound(db: DbSession, inbound_id: int) -> list[ManagedHost]:
    """All hosts of an inbound, in precedence order (lowest
    ``sort_order`` first, then lowest id)."""
    return (
        db.query(ManagedHost)
        .filter(ManagedHost.inbound_id == inbound_id)
        .order_by(ManagedHost.sort_order, ManagedHost.id)
        .all()
    )


def active_host_for_inbound(
    db: DbSession, inbound_id: int
) -> Optional[ManagedHost]:
    """The host that wins for the inbound (first enabled in
    precedence order), or None when the inbound has no enabled host
    (the default endpoint is used)."""
    return (
        db.query(ManagedHost)
        .filter(
            ManagedHost.inbound_id == inbound_id,
            ManagedHost.enabled.is_(True),
        )
        .order_by(ManagedHost.sort_order, ManagedHost.id)
        .first()
    )


def active_hosts_for_inbounds(
    db: DbSession, inbound_ids: list[int]
) -> dict[int, ManagedHost]:
    """The winning host per inbound (first enabled in precedence
    order) for a batch of inbounds, in ONE query — the link/feed
    builders call this instead of one query per inbound."""
    if not inbound_ids:
        return {}
    rows = (
        db.query(ManagedHost)
        .filter(
            ManagedHost.inbound_id.in_(inbound_ids),
            ManagedHost.enabled.is_(True),
        )
        .order_by(
            ManagedHost.inbound_id, ManagedHost.sort_order, ManagedHost.id
        )
        .all()
    )
    out: dict[int, ManagedHost] = {}
    for row in rows:
        out.setdefault(row.inbound_id, row)
    return out


def create_host(
    db: DbSession,
    inbound_id: int,
    address: str,
    port: Optional[int] = None,
    sni: Optional[str] = None,
    remark: Optional[str] = None,
    sort_order: int = 0,
) -> Optional[ManagedHost]:
    """Create a managed host. Returns None when the fields are
    invalid. Commits on success."""
    error = validate_host(address, port, sni)
    if error is not None:
        return None
    host = ManagedHost(
        inbound_id=inbound_id,
        address=(address or "").strip(),
        port=port,
        sni=(sni or "").strip() or None,
        remark=(remark or "").strip() or None,
        sort_order=int(sort_order),
        enabled=True,
    )
    db.add(host)
    db.commit()
    return host


def delete_host(db: DbSession, host_id: int, inbound_id: int) -> bool:
    """Delete a host of THIS inbound (a host of another inbound is
    never touched). True when one was deleted."""
    host = (
        db.query(ManagedHost)
        .filter(ManagedHost.id == host_id, ManagedHost.inbound_id == inbound_id)
        .first()
    )
    if host is None:
        return False
    db.delete(host)
    db.commit()
    return True


def delete_hosts_for_inbound(db: DbSession, inbound_id: int) -> int:
    """Delete all hosts of an inbound (inbound deletion cleanup).
    Commits."""
    deleted = (
        db.query(ManagedHost)
        .filter(ManagedHost.inbound_id == inbound_id)
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(deleted)


def apply_host_override(
    inbound_dict: dict[str, Any], host: Optional[ManagedHost], default_host: str
) -> tuple[str, dict[str, Any]]:
    """Apply a managed host to a link/feed build.

    Returns ``(host, inbound_dict)`` — the host the client should
    connect to, and a COPY of the inbound dict with the overrides
    applied (port, and the SNI in every place the link builders
    read it: the flat ``sni`` key, ``tls.sni`` and
    ``reality.sni``). With no host, the inputs pass through
    unchanged (same dict object — callers only read it). The
    Reality public key / short id are never touched: only the
    server name the client sends changes.
    """
    if host is None:
        return default_host, inbound_dict
    out = copy.deepcopy(inbound_dict)
    link_host = (host.address or "").strip() or default_host
    if host.port is not None:
        out["port"] = int(host.port)
    sni = (host.sni or "").strip()
    if sni:
        stream = out.get("stream_json")
        if not isinstance(stream, dict):
            stream = {}
            out["stream_json"] = stream
        stream["sni"] = sni
        tls = stream.get("tls")
        if isinstance(tls, dict):
            tls["sni"] = sni
        reality = stream.get("reality")
        if isinstance(reality, dict):
            reality["sni"] = sni
    return link_host, out


__all__ = [
    "ADDRESS_RE",
    "SNI_RE",
    "HOST_PORT_MIN",
    "HOST_PORT_MAX",
    "validate_host",
    "hosts_for_inbound",
    "active_host_for_inbound",
    "active_hosts_for_inbounds",
    "create_host",
    "delete_host",
    "delete_hosts_for_inbound",
    "apply_host_override",
]
