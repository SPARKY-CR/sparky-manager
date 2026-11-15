"""Phase 6 (professional upgrade) tests — scripts/render_configs.py.

The standalone renderer (used by install.sh and by operators to
rebuild configs from the panel DB) had ZERO tests (Phase 1 audit
G3-2). It runs as a subprocess here — the honest way to test a CLI
script — against both the seeded panel DB and minimal hand-built
DBs. The script opens the DB read-only; the tests assert it stays
that way.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "render_configs.py"


def _run(db_path, out_dir, extra_args=()):
    return subprocess.run(
        [sys.executable, str(SCRIPT),
         "--db", str(db_path), "--out-dir", str(out_dir), *extra_args],
        capture_output=True, text=True, timeout=60,
    )


def _minimal_db(path, *, users=(), inbounds=(), clients=(), settings=()):
    """A panel-shaped DB built with raw sqlite3 (no ORM)."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, "
        "enabled INTEGER, traffic_limit_bytes INTEGER, "
        "traffic_used_bytes INTEGER, expires_at TEXT, sub_token TEXT, "
        "note TEXT)")
    conn.execute(
        "CREATE TABLE inbounds (id INTEGER PRIMARY KEY, tag TEXT, "
        "core TEXT, protocol TEXT, port INTEGER, enabled INTEGER, "
        "stream_json TEXT, remark TEXT)")
    conn.execute(
        "CREATE TABLE clients (id INTEGER PRIMARY KEY, user_id INTEGER, "
        "inbound_id INTEGER, uuid TEXT, password TEXT, method TEXT, "
        "flow TEXT, extra_json TEXT, enabled INTEGER)")
    conn.execute(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
    for row in users:
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?,?)", row)
    for row in inbounds:
        conn.execute("INSERT INTO inbounds VALUES (?,?,?,?,?,?,?,?)", row)
    for row in clients:
        conn.execute("INSERT INTO clients VALUES (?,?,?,?,?,?,?,?,?)", row)
    for key, value in settings:
        conn.execute("INSERT INTO settings VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def _vless_inbound(**overrides):
    row = (1, "vless-test", "xray", "vless", 1443, 1,
           json.dumps({"network": "tcp", "security": "none"}), "")
    for key, value in overrides.items():
        idx = {"id": 0, "tag": 1, "core": 2, "protocol": 3, "port": 4,
               "enabled": 5, "stream_json": 6, "remark": 7}[key]
        row = row[:idx] + (value,) + row[idx + 1:]
    return row


def _user(**overrides):
    row = (1, "alice", 1, None, 0, None, "tok-alice", "")
    for key, value in overrides.items():
        idx = {"id": 0, "name": 1, "enabled": 2, "traffic_limit_bytes": 3,
               "traffic_used_bytes": 4, "expires_at": 5, "sub_token": 6,
               "note": 7}[key]
        row = row[:idx] + (value,) + row[idx + 1:]
    return row


# ---------------------------------------------------------------------------
# Happy path — the seeded panel DB renders all three configs
# ---------------------------------------------------------------------------

def test_renders_all_three_configs_from_seeded_db(
    db, seeded, db_engine, tmp_path
):
    out_dir = tmp_path / "rendered"
    db_path = Path(db_engine.url.database)
    before = db_path.read_bytes()
    proc = _run(db_path, out_dir)
    assert proc.returncode == 0, proc.stderr
    xray_path = out_dir / "xray.json"
    singbox_path = out_dir / "sing-box.json"
    wg_path = out_dir / "wg0.conf"
    assert xray_path.exists() and singbox_path.exists() and wg_path.exists()
    xray_cfg = json.loads(xray_path.read_text())
    tags = [i.get("tag") for i in xray_cfg.get("inbounds", [])]
    assert "vless-reality" in tags
    assert "api" in tags  # the Stats API inbound (Phase 5)
    wg_text = wg_path.read_text()
    assert "[Interface]" in wg_text
    assert "[Peer]" in wg_text  # alice's WireGuard client
    # The summary reports real counts.
    assert "usable clients rendered:" in proc.stdout
    assert "wrote" in proc.stdout
    # The DB was opened read-only: byte-identical afterwards.
    assert db_path.read_bytes() == before


def test_rendered_xray_config_excludes_unusable_users(
    db, seeded, db_engine, tmp_path
):
    """bob (expired), carol (over quota) and dave (disabled) must
    not appear in the rendered config; alice must."""
    out_dir = tmp_path / "rendered"
    proc = _run(Path(db_engine.url.database), out_dir)
    assert proc.returncode == 0, proc.stderr
    xray_cfg = json.loads((out_dir / "xray.json").read_text())
    emails = set()
    for inbound in xray_cfg.get("inbounds", []):
        for client in inbound.get("settings", {}).get("clients", []):
            if client.get("email"):
                emails.add(client["email"])
    alice = seeded["users"]["alice"]
    bob = seeded["users"]["bob"]
    carol = seeded["users"]["carol"]
    dave = seeded["users"]["dave"]
    assert f"user-{alice.id}@sparky.local" in emails
    for user in (bob, carol, dave):
        assert f"user-{user.id}@sparky.local" not in emails


# ---------------------------------------------------------------------------
# Error handling — exit 1, old files untouched
# ---------------------------------------------------------------------------

def test_missing_db_exits_1(tmp_path):
    out_dir = tmp_path / "rendered"
    proc = _run(tmp_path / "no-such.db", out_dir)
    assert proc.returncode == 1
    assert "database not found" in proc.stderr
    assert not out_dir.exists()


def test_db_missing_tables_exits_1(tmp_path):
    db_path = tmp_path / "empty.db"
    sqlite3.connect(db_path).close()
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 1
    assert "missing table" in proc.stderr


def test_invalid_json_blob_is_tolerated_with_warning(tmp_path):
    db_path = tmp_path / "panel.db"
    _minimal_db(
        db_path,
        users=[_user()],
        inbounds=[_vless_inbound(stream_json="{not json")],
        clients=[(1, 1, 1, "00000000-0000-4000-8000-000000000001",
                  None, None, None, "{}", 1)],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "invalid JSON" in proc.stdout


def test_unparsable_expiry_is_treated_as_never_expiring(tmp_path):
    db_path = tmp_path / "panel.db"
    _minimal_db(
        db_path,
        users=[_user(expires_at="not-a-date")],
        inbounds=[_vless_inbound()],
        clients=[(1, 1, 1, "00000000-0000-4000-8000-000000000001",
                  None, None, None, "{}", 1)],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "unparsable expires_at" in proc.stdout
    xray_cfg = json.loads((tmp_path / "rendered" / "xray.json").read_text())
    emails = [
        c.get("email")
        for i in xray_cfg.get("inbounds", [])
        for c in i.get("settings", {}).get("clients", [])
    ]
    assert "user-1@sparky.local" in emails  # still rendered


# ---------------------------------------------------------------------------
# WireGuard — key handling, peer allocation, empty server config
# ---------------------------------------------------------------------------

def test_no_wireguard_inbound_writes_empty_server_config(tmp_path):
    db_path = tmp_path / "panel.db"
    _minimal_db(db_path, users=[_user()], inbounds=[_vless_inbound()])
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "no wireguard inbound" in proc.stdout
    wg_text = (tmp_path / "rendered" / "wg0.conf").read_text()
    assert "[Interface]" in wg_text
    assert "[Peer]" not in wg_text


def test_wireguard_peer_without_public_key_is_skipped(tmp_path):
    db_path = tmp_path / "panel.db"
    wg = (2, "wg0", "wireguard", "wireguard", 51820, 1, "{}", "")
    _minimal_db(
        db_path,
        users=[_user()],
        inbounds=[wg],
        clients=[(1, 1, 2, None, None, None, None, "{}", 1)],
        settings=[("wireguard_private_key",
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "has no public_key, skipped" in proc.stdout
    wg_text = (tmp_path / "rendered" / "wg0.conf").read_text()
    assert "[Peer]" not in wg_text


def test_wireguard_key_from_settings_is_used(tmp_path):
    db_path = tmp_path / "panel.db"
    wg = (2, "wg0", "wireguard", "wireguard", 51820, 1, "{}", "")
    key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    _minimal_db(
        db_path,
        users=[_user()],
        inbounds=[wg],
        clients=[(1, 1, 2, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                  None, None, None,
                  json.dumps({"allowed_ips": "10.8.0.2/32"}), 1)],
        settings=[("wireguard_private_key", key)],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "generated a NEW server keypair" not in proc.stdout
    wg_text = (tmp_path / "rendered" / "wg0.conf").read_text()
    assert f"PrivateKey = {key}" in wg_text
    assert "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" in wg_text
    assert "AllowedIPs = 10.8.0.2/32" in wg_text


def test_wireguard_key_generated_when_absent_warns_loudly(tmp_path):
    db_path = tmp_path / "panel.db"
    wg = (2, "wg0", "wireguard", "wireguard", 51820, 1, "{}", "")
    _minimal_db(db_path, users=[_user()], inbounds=[wg])
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    assert "generated a NEW server keypair" in proc.stdout
    assert "NOT saved" in proc.stdout


def test_wireguard_peer_without_address_gets_allocated(tmp_path):
    db_path = tmp_path / "panel.db"
    wg = (2, "wg0", "wireguard", "wireguard", 51820, 1, "{}", "")
    _minimal_db(
        db_path,
        users=[_user()],
        inbounds=[wg],
        clients=[(1, 1, 2, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                  None, None, None, "{}", 1)],
        settings=[("wireguard_private_key",
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    wg_text = (tmp_path / "rendered" / "wg0.conf").read_text()
    assert "AllowedIPs = 10.8.0.2/32" in wg_text


# ---------------------------------------------------------------------------
# Usability rule — the script applies DESIGN.md §4 itself
# ---------------------------------------------------------------------------

def test_expired_and_disabled_users_excluded(tmp_path):
    db_path = tmp_path / "panel.db"
    now = datetime.now(timezone.utc)
    expired = (now - timedelta(days=1)).isoformat()
    _minimal_db(
        db_path,
        users=[
            _user(),
            _user(id=2, name="bob", expires_at=expired, sub_token="tok-bob"),
            _user(id=3, name="dave", enabled=0, sub_token="tok-dave"),
        ],
        inbounds=[_vless_inbound()],
        clients=[
            (1, 1, 1, "00000000-0000-4000-8000-000000000001",
             None, None, None, "{}", 1),
            (2, 2, 1, "00000000-0000-4000-8000-000000000002",
             None, None, None, "{}", 1),
            (3, 3, 1, "00000000-0000-4000-8000-000000000003",
             None, None, None, "{}", 1),
        ],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    xray_cfg = json.loads((tmp_path / "rendered" / "xray.json").read_text())
    emails = [
        c.get("email")
        for i in xray_cfg.get("inbounds", [])
        for c in i.get("settings", {}).get("clients", [])
    ]
    assert emails == ["user-1@sparky.local"]


def test_disabled_inbound_excluded(tmp_path):
    db_path = tmp_path / "panel.db"
    _minimal_db(
        db_path,
        users=[_user()],
        inbounds=[_vless_inbound(enabled=0)],
        clients=[(1, 1, 1, "00000000-0000-4000-8000-000000000001",
                  None, None, None, "{}", 1)],
    )
    proc = _run(db_path, tmp_path / "rendered")
    assert proc.returncode == 0, proc.stderr
    xray_cfg = json.loads((tmp_path / "rendered" / "xray.json").read_text())
    tags = [i.get("tag") for i in xray_cfg.get("inbounds", [])]
    assert "vless-test" not in tags
