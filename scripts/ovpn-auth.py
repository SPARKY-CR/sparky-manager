#!/usr/bin/env python3
"""OpenVPN ``auth-user-pass-verify`` script for sparky-manager.

Called by OpenVPN as ``ovpn-auth.py <credentials-file>`` (via-file
mode): the file's first line is the username, the second is the
password. The script checks the pair against the panel database
(the user must exist and be enabled, with an enabled OpenVPN client
whose stored password matches) and exits 0 to allow the connection
or 1 to deny it.

Stdlib only, no panel imports — it runs as root from OpenVPN and
must not depend on the panel venv. The database is opened
read-only (``mode=ro``) and the password is compared with
``hmac.compare_digest``. Only the username and the outcome are ever
logged (to stderr, which OpenVPN captures); the password is never
printed.
"""

import hmac
import os
import sqlite3
import sys


def _db_path() -> str:
    return os.environ.get(
        "SPARKY_DB", "/opt/sparky-manager/data/panel.db"
    )


def _check(username: str, password: str) -> bool:
    try:
        conn = sqlite3.connect(f"file:{_db_path()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        print(f"ovpn-auth: cannot open panel db: {exc}", file=sys.stderr)
        return False
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE name = ? AND enabled = 1",
            (username,),
        ).fetchone()
        if row is None:
            return False
        user_id = row[0]
        rows = conn.execute(
            """
            SELECT c.password FROM clients c
            JOIN inbounds i ON c.inbound_id = i.id
            WHERE c.user_id = ? AND i.protocol = 'openvpn'
              AND i.core = 'openvpn'
              AND c.enabled = 1 AND i.enabled = 1
            """,
            (user_id,),
        ).fetchall()
        for (stored,) in rows:
            if stored and hmac.compare_digest(str(stored), password):
                return True
        return False
    except sqlite3.Error as exc:
        print(f"ovpn-auth: db query failed: {exc}", file=sys.stderr)
        return False
    finally:
        conn.close()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("ovpn-auth: usage: ovpn-auth.py <credentials-file>", file=sys.stderr)
        return 1
    try:
        with open(argv[1], encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        print(f"ovpn-auth: cannot read credentials file: {exc}", file=sys.stderr)
        return 1
    if len(lines) < 2:
        print("ovpn-auth: credentials file has fewer than 2 lines", file=sys.stderr)
        return 1
    username = lines[0].strip()
    password = lines[1]
    if not username:
        print("ovpn-auth: empty username", file=sys.stderr)
        return 1
    ok = _check(username, password)
    print(
        f"ovpn-auth: user {username!r}: {'allowed' if ok else 'denied'}",
        file=sys.stderr,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
