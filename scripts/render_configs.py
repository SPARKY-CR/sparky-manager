#!/usr/bin/env python3
"""Render Xray / sing-box / WireGuard configs from the panel SQLite DB.

Standalone script (no FastAPI, no web server, stdlib + the panel's own
``app.xray`` / ``app.singbox`` / ``app.wireguard`` renderers)::

    python3 scripts/render_configs.py [--db PATH] [--out-dir DIR]

It opens the DB **read-only** (SQLite URI ``mode=ro``), reads the
``inbounds`` / ``users`` / ``clients`` tables (plus ``settings`` when
present), applies the DESIGN.md §4 usability rule (a client is usable
iff the client, its user and its inbound are all enabled, the user is
not expired and is under its traffic limit), calls the three
renderers, and writes ``xray.json``, ``sing-box.json`` and
``wg0.conf`` into the output directory (created when missing).

Exit codes: ``0`` when all three files were written and validated,
``1`` when the DB is missing/unreadable, required tables are absent,
or any config fails validation (the old files are then left alone —
the renderers write atomically and only rename into place on
success). A missing core binary is NOT a failure: the renderers
validate the JSON structure and note
``"binary not present — JSON validated only"``.

WireGuard notes: the server private key comes from settings
(``wireguard_private_key`` / ``wg_private_key`` /
``server_private_key``). When no key is stored — the DB is opened
read-only, so this script cannot save one — a fresh keypair is
generated for this render only and the summary says so loudly: the
admin must store that key in settings before the next render, or
every render will produce a different server key and all peers will
break. Peer public keys / addresses come from each client's
``extra_json`` (``public_key``, ``allowed_ips`` / ``address``,
``preshared_key``); peers without a public key are skipped, and a
peer without an address is allocated ``10.8.0.<n>/32`` in order.
When the DB has no WireGuard inbound at all, an empty server
``wg0.conf`` (no peers) is still written, and the summary says so.

TLS certificates: the renderers take certificate paths from settings.
When settings name none, this script additionally checks the panel's
conventional location ``<home>/certs/fullchain.pem`` +
``<home>/certs/privkey.pem`` on disk and, only when both files exist,
passes them in as the self-signed pair — that is how a no-domain
install (self-signed cert, Reality + WireGuard carrying the VPN side)
still gets working TUIC/AnyTLS/Naive/ShadowTLS inbounds. When no
certificate exists anywhere, the sing-box renderer omits those
inbounds and the summary lists the warnings.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import pathname2url

# The renderers live in app/ next to this script's parent directory.
# Insert the repo root so `python3 scripts/render_configs.py` works
# from anywhere, not only from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from app.singbox import render_singbox_config
    from app.singbox import write_and_validate as write_singbox
    from app.wireguard import generate_keypair, render_wg_config
    from app.xray import render_xray_config
    from app.xray import write_and_validate as write_xray
except ImportError as exc:  # pragma: no cover - import-time failure
    print(f"error: cannot import panel renderers: {exc}", file=sys.stderr)
    raise SystemExit(1)

DEFAULT_DB = "/opt/vpn-panel/data/panel.db"
DEFAULT_OUT_DIR = "/opt/vpn-panel/data/rendered"
DEFAULT_WG_ADDRESS = "10.8.0.1/24"
DEFAULT_WG_PORT = 51820

REQUIRED_TABLES = ("inbounds", "users", "clients")

#: Settings keys (in priority order) holding the WireGuard server key.
_WG_KEY_SETTINGS = (
    "wireguard_private_key",
    "wg_private_key",
    "server_private_key",
    "wg_server_private_key",
)


# ---------------------------------------------------------------------------
# DB reading (read-only, column-tolerant)
# ---------------------------------------------------------------------------


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of ``table`` (empty set when the table is absent)."""
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return set()
    return {row[1] for row in rows}


def _select_existing(
    conn: sqlite3.Connection, table: str, wanted: list[str]
) -> list[dict]:
    """``SELECT`` the ``wanted`` columns that actually exist, as dicts."""
    columns = _table_columns(conn, table)
    selected = [c for c in wanted if c in columns]
    if not selected:
        return []
    query = f"SELECT {', '.join(selected)} FROM {table}"
    conn.row_factory = sqlite3.Row
    return [dict(row) for row in conn.execute(query).fetchall()]


def _parse_json_blob(value: object, *, what: str, warnings: list[str]) -> dict:
    """Parse a JSON text blob to a dict (``{}`` + warning when invalid)."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except ValueError:
            warnings.append(f"{what}: invalid JSON, treated as empty")
            return {}
        if isinstance(data, dict):
            return data
    warnings.append(f"{what}: not a JSON object, treated as empty")
    return {}


def _parse_datetime(value: object) -> datetime | None:
    """Parse a DB datetime (ISO string, with or without tz) to UTC."""
    if isinstance(value, datetime):
        return (
            value
            if value.tzinfo is not None
            else value.replace(tzinfo=timezone.utc)
        )
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return (
        parsed if parsed.tzinfo is not None
        else parsed.replace(tzinfo=timezone.utc)
    )


def _user_is_usable(
    user: dict, *, now: datetime, warnings: list[str]
) -> bool:
    """DESIGN.md §4 usability: enabled, not expired, under quota."""
    if not user.get("enabled", True):
        return False
    expires_at = _parse_datetime(user.get("expires_at"))
    if user.get("expires_at") and expires_at is None:
        warnings.append(
            f"user '{user.get('name')}': unparsable expires_at "
            f"{user.get('expires_at')!r}, treated as never expiring"
        )
    if expires_at is not None and expires_at <= now:
        return False
    limit = user.get("traffic_limit_bytes")
    used = user.get("traffic_used_bytes") or 0
    if limit is not None and used >= limit:
        return False
    return True


def _read_settings(conn: sqlite3.Connection) -> dict[str, str]:
    """Key/value settings (``{}`` when the table is absent)."""
    if "settings" not in {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }:
        return {}
    settings: dict[str, str] = {}
    for row in conn.execute("SELECT key, value FROM settings").fetchall():
        if row[0] is not None:
            settings[str(row[0])] = "" if row[1] is None else str(row[1])
    return settings


def _inject_panel_cert_paths(
    settings: dict[str, str], *, warnings: list[str]
) -> None:
    """Fill in the panel self-signed cert paths when they exist on disk.

    Only when settings name no certificate at all: if
    ``<home>/certs/fullchain.pem`` + ``<home>/certs/privkey.pem``
    both exist, they are added as ``self_signed_cert_path`` /
    ``self_signed_key_path`` so the sing-box TLS inbounds can render
    (clients must allow insecure for a self-signed cert). Nothing is
    invented when the files are absent — the renderers then omit the
    TLS inbounds and warn, as designed.
    """
    cert_keys = (
        "cert_path",
        "tls_cert_path",
        "certificate_path",
        "fullchain_path",
        "self_signed_cert_path",
        "cert_file",
    )
    if any(settings.get(key) for key in cert_keys):
        return
    home = settings.get("home") or "/opt/vpn-panel"
    cert = os.path.join(home, "certs", "fullchain.pem")
    key = os.path.join(home, "certs", "privkey.pem")
    if os.path.isfile(cert) and os.path.isfile(key):
        settings["self_signed_cert_path"] = cert
        settings["self_signed_key_path"] = key
        warnings.append(
            "no certificate in settings; using panel self-signed pair "
            f"at {cert} (clients must allow insecure)"
        )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _load_db(
    db_path: Path,
) -> tuple[
    list[dict], dict[str, list[dict]], list[dict], dict[str, str], list[str]
]:
    """Read the DB into renderer inputs.

    Returns ``(inbounds, clients_by_tag, wg_peers, settings, warnings)``.
    Raises ``SystemExit``-style errors via ``ValueError`` for missing
    files / tables so ``main`` can report them and exit 1.
    """
    warnings: list[str] = []
    if not db_path.is_file():
        raise ValueError(f"database not found: {db_path}")
    uri = "file:" + pathname2url(str(db_path)) + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise ValueError(f"cannot open database {db_path}: {exc}") from exc
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        missing = [t for t in REQUIRED_TABLES if t not in tables]
        if missing:
            raise ValueError(
                f"database {db_path} is missing table(s): "
                + ", ".join(missing)
            )
        settings = _read_settings(conn)

        inbounds: list[dict] = []
        for row in _select_existing(
            conn,
            "inbounds",
            [
                "id",
                "tag",
                "core",
                "protocol",
                "port",
                "enabled",
                "stream_json",
                "remark",
            ],
        ):
            row["stream_json"] = _parse_json_blob(
                row.get("stream_json"),
                what=f"inbound '{row.get('tag')}' stream_json",
                warnings=warnings,
            )
            row["enabled"] = bool(row.get("enabled", True))
            inbounds.append(row)
        inbound_by_id = {row.get("id"): row for row in inbounds}

        now = datetime.now(timezone.utc)
        users: dict[int, dict] = {}
        for row in _select_existing(
            conn,
            "users",
            [
                "id",
                "name",
                "enabled",
                "traffic_limit_bytes",
                "traffic_used_bytes",
                "expires_at",
                "sub_token",
                "note",
            ],
        ):
            users[row.get("id")] = row

        clients_by_tag: dict[str, list[dict]] = {}
        wg_peers: list[dict] = []
        wg_index = 0
        for row in _select_existing(
            conn,
            "clients",
            [
                "id",
                "user_id",
                "inbound_id",
                "uuid",
                "password",
                "method",
                "flow",
                "extra_json",
                "enabled",
            ],
        ):
            if not row.get("enabled", True):
                continue
            user = users.get(row.get("user_id"))
            inbound = inbound_by_id.get(row.get("inbound_id"))
            if user is None or inbound is None:
                continue
            if not _user_is_usable(user, now=now, warnings=warnings):
                continue
            if not inbound.get("enabled", True):
                continue
            extra = _parse_json_blob(
                row.get("extra_json"),
                what=f"client #{row.get('id')} extra_json",
                warnings=warnings,
            )
            client = {
                "uuid": row.get("uuid"),
                "password": row.get("password"),
                "method": row.get("method"),
                "flow": row.get("flow"),
                "extra_json": extra,
                "name": user.get("name"),
            }
            tag = inbound.get("tag")
            if tag:
                clients_by_tag.setdefault(str(tag), []).append(client)
            if str(inbound.get("core")) == "wireguard":
                # Panel-created WG clients store the peer public key in
                # Client.uuid (see main._new_client_credentials); older
                # / hand-seeded rows may carry it in extra_json instead.
                public_key = (
                    extra.get("public_key")
                    or extra.get("peer_public_key")
                    or extra.get("publicKey")
                    or row.get("uuid")
                )
                if not public_key:
                    warnings.append(
                        f"wireguard peer for user "
                        f"'{user.get('name')}' has no public_key, skipped"
                    )
                    continue
                allowed = extra.get("allowed_ips") or extra.get("address")
                if isinstance(allowed, list):
                    allowed = ", ".join(str(a) for a in allowed)
                if not allowed:
                    wg_index += 1
                    allowed = f"10.8.0.{wg_index + 1}/32"
                peer: dict[str, str] = {
                    "public_key": str(public_key),
                    "allowed_ips": str(allowed),
                }
                preshared = extra.get("preshared_key")
                if preshared:
                    peer["preshared_key"] = str(preshared)
                wg_peers.append(peer)
        return inbounds, clients_by_tag, wg_peers, settings, warnings
    finally:
        conn.close()


def _wireguard_server_key(
    settings: dict[str, str], *, warnings: list[str]
) -> str:
    """Server private key from settings, else a fresh ephemeral one.

    The DB is open read-only, so a generated key cannot be saved
    here — the warning tells the admin to store it in settings,
    otherwise the next render generates a different key and every
    peer stops working.
    """
    for key in _WG_KEY_SETTINGS:
        value = settings.get(key)
        if value:
            return value
    private_key, public_key = generate_keypair()
    warnings.append(
        "no wireguard private key in settings; generated a NEW server "
        f"keypair for this render only (public {public_key}). The DB "
        "is read-only so it was NOT saved — store the private key in "
        "settings (wireguard_private_key) or the next render will "
        "produce a different server key and all peers will break."
    )
    return private_key


def _write_text_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temp file + atomic rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, render, write, print a summary."""
    parser = argparse.ArgumentParser(
        description="Render Xray / sing-box / WireGuard configs "
        "from the panel SQLite DB."
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("VPN_PANEL_DB", DEFAULT_DB),
        help=f"panel SQLite DB (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--out-dir",
        default=os.environ.get("VPN_PANEL_OUT_DIR", DEFAULT_OUT_DIR),
        help=f"output directory (default: {DEFAULT_OUT_DIR})",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    out_dir = Path(args.out_dir)
    try:
        inbounds, clients_by_tag, wg_peers, settings, warnings = _load_db(
            db_path
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"error: cannot read database {db_path}: {exc}", file=sys.stderr)
        return 1

    _inject_panel_cert_paths(settings, warnings=warnings)
    settings.setdefault("hysteria2_core", "xray")

    # -- render ------------------------------------------------------------
    xray_cfg = render_xray_config(inbounds, clients_by_tag, settings)
    singbox_cfg, singbox_warnings = render_singbox_config(
        inbounds, clients_by_tag, settings
    )
    warnings.extend(singbox_warnings)

    wg_inbounds = [
        row
        for row in inbounds
        if str(row.get("core")) == "wireguard" and row.get("enabled", True)
    ]
    wg_port = DEFAULT_WG_PORT
    if wg_inbounds:
        try:
            wg_port = int(wg_inbounds[0].get("port") or DEFAULT_WG_PORT)
        except (TypeError, ValueError):
            wg_port = DEFAULT_WG_PORT
    server_key = _wireguard_server_key(settings, warnings=warnings)
    wg_text = render_wg_config(
        server_key,
        wg_peers,
        address=settings.get("wg_address", DEFAULT_WG_ADDRESS),
        listen_port=wg_port,
        dns=settings.get("dns", "1.1.1.1"),
    )

    # -- write -------------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    xray_path = out_dir / "xray.json"
    singbox_path = out_dir / "sing-box.json"
    wg_path = out_dir / "wg0.conf"

    ok, notes = write_xray(xray_cfg, xray_path)
    if not ok:
        for error in notes:
            print(f"error: xray.json: {error}", file=sys.stderr)
        return 1
    ok, singbox_notes = write_singbox(singbox_cfg, singbox_path)
    if not ok:
        for error in singbox_notes:
            print(f"error: sing-box.json: {error}", file=sys.stderr)
        return 1
    try:
        _write_text_atomic(wg_path, wg_text)
    except OSError as exc:
        print(f"error: cannot write {wg_path}: {exc}", file=sys.stderr)
        return 1

    # -- summary -----------------------------------------------------------
    xray_count = sum(
        1 for row in inbounds if str(row.get("core")) == "xray"
    )
    singbox_count = sum(
        1 for row in inbounds if str(row.get("core")) == "singbox"
    )
    usable_clients = sum(len(v) for v in clients_by_tag.values())
    print(f"db: {db_path}")
    print(f"out-dir: {out_dir}")
    print(
        f"inbounds: {len(inbounds)} total "
        f"(xray {xray_count}, singbox {singbox_count}, "
        f"wireguard {len(wg_inbounds)})"
    )
    print(f"usable clients rendered: {usable_clients}")
    print(
        f"wrote {xray_path} "
        f"({len(xray_cfg.get('inbounds', []))} inbounds incl. api)"
    )
    print(
        f"wrote {singbox_path} "
        f"({len(singbox_cfg.get('inbounds', []))} inbounds)"
    )
    if not wg_inbounds:
        print("note: no wireguard inbound in DB — wrote an empty "
              "server wg0.conf (no peers)")
    print(f"wrote {wg_path} ({len(wg_peers)} peers)")
    for note in notes + singbox_notes:
        print(f"note: {note}")
    for warning in warnings:
        print(f"warning: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
