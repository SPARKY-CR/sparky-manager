"""Phase 6 (professional upgrade) security-boundary tests.

A systematic sweep of the whole route table (not spot checks):
every admin route requires authentication, every state-changing
POST carries CSRF protection, sessions expire, and malicious input
(SQL injection strings, XSS payloads, path traversal, command
injection) is handled safely. The Phase 1 audit verified these
boundaries by code review only (G3-5); this file turns them into
tests that fail if a future change reopens one.

Telegram authorization is NOT re-tested here: Phase 3 already
proves a stranger gets nothing from every new command and callback
(see tests/test_telegram_phase3.py::test_stranger_gets_nothing_from_new_commands
and ::test_stranger_gets_nothing_from_new_callbacks — the latter
covers the service-restart and backup callbacks explicitly, and
asserts no restart, no delete and no re-render happened).
"""

from __future__ import annotations

import io
import logging
import secrets
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import main as main_mod
from app import backup as backup_mod
from app import openconnect as openconnect_mod
from app.models import Client, Inbound, Session as LoginSession, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

# ---------------------------------------------------------------------------
# Route-table introspection (covers the router split: FastAPI 0.163
# keeps included routers as _IncludedRouter placeholders, so the walk
# recurses into original_router).
# ---------------------------------------------------------------------------

CSRF_EXEMPT_POSTS = {
    # No session exists yet, so there is no token to check against.
    "/login",
    # Unauthenticated external POST, authenticated by its path secret.
    "/telegram/webhook/{secret}",
}

PUBLIC_GETS = {
    "/health",  # liveness probe (no data)
    "/",  # redirect to /login or /dashboard
    "/login",  # the login page itself
    "/u/{token}",  # token-gated public user page (128-bit token)
    "/sub/{token}",  # token-gated subscription feeds (128-bit token)
    "/sub/{token}/zedsecure.json",
    "/sub/{token}/openvpn.ovpn",
    "/sub/{token}/openconnect.xml",
    "/sub/{token}/amneziawg.conf",
    "/sub/{token}/ikev2.mobileconfig",
    "/sub/{token}/qr",
    # FastAPI's auto-generated API docs — unauthenticated by design
    # (they expose the route schema, no data), reachable only under
    # the secret web path in production. Noted as a LOW finding in
    # the Phase 6 report; not changed (behavior preservation).
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/openapi.json",
}


def _all_routes():
    """Every (methods, path, dependency-names) triple in the app."""
    def _walk(routes):
        for route in routes:
            if type(route).__name__ == "_IncludedRouter":
                yield from _walk(route.original_router.routes)
            elif hasattr(route, "methods") and hasattr(route, "path"):
                # Plain Starlette Routes (the auto-generated /docs,
                # /openapi.json, /redoc) and the /static Mount have no
                # dependant — they carry no app dependencies.
                dependant = getattr(route, "dependant", None)
                if dependant is None:
                    yield route.methods or set(), route.path, []
                    continue
                deps = [
                    getattr(getattr(d, "call", None), "__name__", "?")
                    for d in dependant.dependencies
                ]
                yield route.methods or set(), route.path, deps

    return list(_walk(main_mod.app.routes))


def test_every_post_route_has_csrf_except_documented_exemptions():
    """The Phase 2 route-coverage check, automated: any new POST
    route added without require_csrf fails this test."""
    uncovered = []
    for methods, path, deps in _all_routes():
        if "POST" not in methods:
            continue
        if path in CSRF_EXEMPT_POSTS:
            continue
        if "require_csrf" not in deps and "require_csrf_api" not in deps:
            uncovered.append(path)
    assert uncovered == [], (
        f"POST routes without CSRF protection: {uncovered}")


def test_every_admin_route_requires_auth():
    """Every GET route is either public-by-design (listed above) or
    guarded by require_admin / require_admin_api."""
    unguarded = []
    for methods, path, deps in _all_routes():
        if "GET" not in methods:
            continue
        if path in PUBLIC_GETS:
            continue
        if path.startswith("/static"):
            continue
        if "require_admin" not in deps and "require_admin_api" not in deps:
            unguarded.append(path)
    assert unguarded == [], f"GET routes without auth: {unguarded}"


# ---------------------------------------------------------------------------
# Unauthenticated sweep — every admin route, no session
# ---------------------------------------------------------------------------

ADMIN_GETS = [
    "/dashboard",
    "/users",
    "/inbounds",
    "/settings",
    "/settings?section=telegram",
    "/settings?section=security",
    "/settings?section=backup",
    "/settings/backup",
    "/logs",
    "/logs/download",
]


@pytest.mark.parametrize("path", ADMIN_GETS)
def test_unauthenticated_get_redirects_to_login(test_client, path):
    resp = test_client.get(path, follow_redirects=False)
    assert resp.status_code == 303, path
    assert resp.headers["location"].startswith("/login"), path


def test_unauthenticated_detail_and_edit_pages_redirect(
    test_client, db, seeded
):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    for path in (
        f"/users/{alice.id}",
        f"/users/{alice.id}/edit",
        f"/inbounds/{vless.id}/edit",
    ):
        resp = test_client.get(path, follow_redirects=False)
        assert resp.status_code == 303, path
        assert resp.headers["location"].startswith("/login"), path


def _post_targets(seeded):
    alice = seeded["users"]["alice"]
    vless = seeded["inbounds"]["vless-reality"]
    return [
        ("/users", {"name": "intruder", "inbounds": "1"}),
        (f"/users/{alice.id}/toggle", {}),
        (f"/users/{alice.id}/delete", {}),
        (f"/users/{alice.id}/freeze", {}),
        (f"/users/{alice.id}/rotate-token", {}),
        ("/users/bulk", {"action": "delete", "user_ids": str(alice.id)}),
        ("/inbounds", {"tag": "evil", "protocol": "vless", "port": "1443"}),
        (f"/inbounds/{vless.id}/toggle", {}),
        (f"/inbounds/{vless.id}/delete", {}),
        (f"/inbounds/{vless.id}/regenerate-reality", {}),
        ("/settings", {"domain": "evil.example"}),
        ("/settings/password", {
            "current_password": "x", "new_password": "Pwned123456",
            "confirm_password": "Pwned123456"}),
        ("/settings/telegram-test", {}),
        ("/settings/telegram-webhook", {}),
        ("/settings/telegram-webhook-status", {}),
        ("/settings/telegram-commands", {}),
        ("/settings/telegram-identity", {}),
        ("/settings/restore", {"confirm_restore": "yes"}),
        ("/logs/clear", {}),
    ]


def test_unauthenticated_posts_redirect_to_login(test_client, db, seeded):
    for path, data in _post_targets(seeded):
        resp = test_client.post_raw(path, data=data, follow_redirects=False)
        assert resp.status_code == 303, path
        assert resp.headers["location"].startswith("/login"), path


def test_unauthenticated_posts_change_nothing(test_client, db, seeded):
    """The sweep above proves the redirect; this proves no state
    changed behind it (the dangerous half of an auth bypass)."""
    alice = seeded["users"]["alice"]
    users_before = db.query(User).count()
    inbounds_before = db.query(Inbound).count()
    for path, data in _post_targets(seeded):
        test_client.post_raw(path, data=data, follow_redirects=False)
    db.expire_all()
    assert db.query(User).count() == users_before
    assert db.query(User).filter(User.name == "intruder").first() is None
    assert db.get(User, alice.id) is not None  # delete did not run
    assert db.query(Inbound).count() == inbounds_before
    assert db.query(Inbound).filter(Inbound.tag == "evil").first() is None
    # The admin password still works (password change did not run).
    resp = test_client.post(
        "/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_unauthenticated_api_returns_401(test_client):
    assert test_client.get("/api/users").status_code == 401
    assert test_client.get("/api/inbounds").status_code == 401
    resp = test_client.post_raw(
        "/api/users", json={"name": "x", "inbounds": [1]},
        follow_redirects=False)
    assert resp.status_code == 401


def test_unauthenticated_logout_redirects_to_login(test_client):
    # Logout has no direct require_admin, but require_csrf itself
    # depends on require_admin — so the auth check runs first and
    # an unauthenticated logout redirects to /login (never 200).
    resp = test_client.post_raw("/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_public_token_endpoints_reject_unknown_tokens(test_client):
    bad = "0" * 32
    # The human page 404s; the machine feeds 403 with an EMPTY body
    # (no data, no user existence signal — by design).
    resp = test_client.get(f"/u/{bad}", follow_redirects=False)
    assert resp.status_code == 404
    # The QR endpoint needs its ?link= param first (422 without it —
    # validation runs before the token check and reveals nothing).
    resp = test_client.get(f"/sub/{bad}/qr", follow_redirects=False)
    assert resp.status_code == 422
    for path in (f"/sub/{bad}", f"/sub/{bad}/qr?link=https://example.com/x",
                 f"/sub/{bad}/zedsecure.json",
                 f"/sub/{bad}/openvpn.ovpn",
                 f"/sub/{bad}/amneziawg.conf",
                 f"/sub/{bad}/ikev2.mobileconfig"):
        resp = test_client.get(path, follow_redirects=False)
        assert resp.status_code == 403, path
        assert resp.content == b"", path


# ---------------------------------------------------------------------------
# Session expiration — enforced at the HTTP layer, row pruned
# ---------------------------------------------------------------------------

def test_expired_session_cookie_redirects_to_login(authed_client, db):
    row = db.query(LoginSession).first()
    assert row is not None
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    resp = authed_client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")
    # The expired row is pruned on lookup (audit S7).
    db.expire_all()
    assert db.query(LoginSession).count() == 0


def test_expired_session_api_returns_401(authed_client, db):
    row = db.query(LoginSession).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert authed_client.get("/api/users").status_code == 401


def test_forged_session_cookie_is_rejected(test_client):
    test_client.cookies.set(
        main_mod.SESSION_COOKIE, secrets.token_hex(32))
    resp = test_client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303
    assert test_client.get("/api/users").status_code == 401


# ---------------------------------------------------------------------------
# Malicious input — SQL injection strings and XSS payloads in text fields
# ---------------------------------------------------------------------------

SQLI = "' OR '1'='1'; DROP TABLE users; --"
XSS = '<script>alert("xss")</script><img src=x onerror=alert(1)>'


def test_sqli_and_xss_in_user_note_stored_safely_and_escaped(
    authed_client, db, seeded
):
    resp = authed_client.post(
        "/users",
        data={"name": "mallory", "note": f"{SQLI} {XSS}",
              "traffic_limit": "", "expires_at": "", "inbounds": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    db.expire_all()
    user = db.query(User).filter(User.name == "mallory").first()
    assert user is not None
    # The users table survived (no DROP ran) and the note is stored
    # verbatim (the DB keeps the truth; escaping happens at render).
    assert db.query(User).filter(User.name == "alice").first() is not None
    assert SQLI in user.note
    # Rendered pages escape it: no executable markup reaches the admin.
    for path in ("/users", f"/users/{user.id}"):
        page = authed_client.get(path)
        assert page.status_code == 200
        assert "<script>alert" not in page.text, path
        assert "&lt;script&gt;" in page.text, path
        # The <img> tag is escaped too: the attribute text survives
        # only inside an escaped entity, never as live markup.
        assert "<img src=x" not in page.text, path
        assert "&lt;img" in page.text, path


def test_search_param_is_not_sql(authed_client, db, seeded):
    """``?q=' OR '1'='1`` must match by substring only — if it were
    interpolated into SQL it would return every user."""
    resp = authed_client.get("/users?q=' OR '1'='1")
    assert resp.status_code == 200
    alice = seeded["users"]["alice"]
    assert f"/users/{alice.id}\"" not in resp.text


def test_search_param_xss_is_escaped(authed_client):
    resp = authed_client.get("/users?q=<script>alert(1)</script>")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_xss_in_inbound_remark_is_escaped(authed_client, db, seeded):
    vless = seeded["inbounds"]["vless-reality"]
    db.get(Inbound, vless.id).remark = XSS
    db.commit()
    page = authed_client.get("/inbounds")
    assert page.status_code == 200
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text


def test_sqli_name_is_rejected_by_validation(authed_client, db):
    before = db.query(User).count()
    resp = authed_client.post(
        "/users",
        data={"name": SQLI, "note": "", "traffic_limit": "",
              "expires_at": "", "inbounds": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303  # back to the form with an error
    assert "err=" in resp.headers["location"]
    db.expire_all()
    assert db.query(User).count() == before


# ---------------------------------------------------------------------------
# Path traversal — the restore upload filename is never used as a path
# ---------------------------------------------------------------------------

def test_restore_traversal_filename_is_ignored(
    authed_client, db, seeded, db_engine, tmp_path
):
    main_mod.ensure_defaults(db)
    # Dummy certs so the post-restore re-render has no warnings
    # (the seeded TUIC/AnyTLS/Naive inbounds need a cert configured).
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    main_mod.set_setting(db, "cert_path", str(cert))
    main_mod.set_setting(db, "key_path", str(key))
    data = backup_mod.create_backup_zip(Path(db_engine.url.database))
    probe = tmp_path / "phase6-traversal-probe.zip"
    assert not probe.exists()
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": (
            "../../../../phase6-traversal-probe.zip", data,
            "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "msg=" in resp.headers["location"]  # restore succeeded
    assert not probe.exists()  # nothing was written outside
    assert not (tmp_path / "phase6-traversal-probe.zip").exists()


def test_restore_traversal_filename_with_garbage_is_rejected(
    authed_client, db, seeded, tmp_path
):
    probe = tmp_path / "phase6-traversal-garbage.zip"
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": (
            "../../phase6-traversal-garbage.zip", b"not a zip",
            "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "err=" in resp.headers["location"]
    assert not probe.exists()


def test_restore_rejects_zip_with_traversal_member(
    authed_client, db, seeded, db_engine, tmp_path
):
    """A ZIP whose members carry ``..`` paths must not escape the
    restore temp dir (Zip Slip): validation only ever reads the
    whitelisted ``panel.db`` member by name, never extracts."""
    main_mod.ensure_defaults(db)
    data = backup_mod.create_backup_zip(Path(db_engine.url.database))
    good = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("panel.db", good.read("panel.db"))
        zf.writestr("meta.json", good.read("meta.json"))
        zf.writestr("../../phase6-zipslip.txt", "pwned")
        zf.writestr("/tmp/phase6-zipslip-abs.txt", "pwned")
    resp = authed_client.post(
        "/settings/restore",
        files={"backup_file": ("backup.zip", buf.getvalue(),
                               "application/zip")},
        data={"confirm_restore": "yes"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert not Path("/tmp/phase6-zipslip-abs.txt").exists()
    assert not Path("/tmp/phase6-zipslip.txt").exists()
    # A member "../../phase6-zipslip.txt" extracted from the restore
    # temp dir (/tmp/sparky-restore-*/) would land at the filesystem
    # root — assert it is not there either.
    assert not Path("/phase6-zipslip.txt").exists()


# ---------------------------------------------------------------------------
# Command injection — adversarial strings through the subprocess paths
# ---------------------------------------------------------------------------

MARKER = "phase6-cmdinj-marker"


def _marker_path(tmp_path):
    return tmp_path / MARKER


def test_openssl_hash_with_shell_metachars_executes_nothing(tmp_path):
    """The ocserv password reaches ``openssl passwd`` on stdin, never
    as an argv element — shell metacharacters in it must not run."""
    marker = _marker_path(tmp_path)
    evil = f"$(touch {marker}); `touch {marker}2`; pw | touch {marker}3"
    hashed = openconnect_mod._openssl_hash(evil)
    assert hashed is not None and hashed.startswith("$6$")
    assert not marker.exists()
    assert not Path(str(marker) + "2").exists()
    assert not Path(str(marker) + "3").exists()


def test_verify_password_with_malicious_salt_executes_nothing(tmp_path):
    """A stored hash whose salt carries shell metacharacters must
    not execute anything on the verify path (the salt is one argv
    element, never a shell string)."""
    marker = _marker_path(tmp_path)
    stored = f"$6$$(touch {marker})$fakesalthash"
    assert openconnect_mod.verify_password("whatever", stored) is False
    assert not marker.exists()


def test_rerender_with_adversarial_data_executes_nothing(
    test_client, db, seeded, tmp_path, monkeypatch
):
    """End to end: shell metacharacters in a user note, an inbound
    remark and a client password flow through the full re-render
    (renderers + validators + apply paths) and nothing executes."""
    marker = _marker_path(tmp_path)
    evil = f"$(touch {marker})"
    alice = seeded["users"]["alice"]
    db.get(User, alice.id).note = evil
    vless = seeded["inbounds"]["vless-reality"]
    db.get(Inbound, vless.id).remark = evil
    # An OpenConnect inbound + client, so the ocserv hash path runs.
    oc = Inbound(tag="oc-test", core="openconnect",
                 protocol="openconnect", port=1443,
                 stream_json='{"tls": {"sni": "203.0.113.10"}}')
    db.add(oc)
    db.flush()
    db.add(Client(user_id=alice.id, inbound_id=oc.id,
                  password=f"pw{evil}", enabled=True))
    db.commit()
    # The ocserv validator needs the CA pair to exist, and `ocserv
    # -t` needs the binary — neither exists in the test env, so both
    # are stubbed (the evil data never reaches those argv lists: the
    # tmp config path is panel-generated, the password goes through
    # hash_password only). Dummy TLS certs keep the seeded
    # TUIC/AnyTLS/Naive inbounds from warning during the re-render.
    cert = tmp_path / "server-cert.pem"
    key = tmp_path / "server-key.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    main_mod.set_setting(db, "cert_path", str(cert))
    main_mod.set_setting(db, "key_path", str(key))
    monkeypatch.setattr(main_mod, "VPN_SERVER_CERT_PATH", str(cert))
    monkeypatch.setattr(main_mod, "VPN_SERVER_KEY_PATH", str(key))
    monkeypatch.setattr(
        main_mod, "_run_privileged", lambda *a, **k: (0, "", ""))
    errors = main_mod.rerender_configs(db)
    assert not marker.exists()
    # The render itself succeeded (no core errored on the input).
    assert errors == [], errors
    # And the ocpasswd file was written with a real hash for alice —
    # the evil password went through hash_password, not a shell.
    passwd_text = Path(main_mod.OCSERV_PASSWD_PATH).read_text()
    # ocpasswd format is user:group:hash (empty group here).
    assert "alice::$6$" in passwd_text


# ---------------------------------------------------------------------------
# Privileged-command logging — argv goes through the redactor (Phase 6)
# ---------------------------------------------------------------------------

def test_run_privileged_redacts_secrets_in_argv(monkeypatch, caplog):
    """The docstring promises every invocation is logged through the
    redactor; before Phase 6 the argv itself was logged raw."""
    calls = []

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(argv, **kwargs):
        calls.append(list(argv))
        return _Proc()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with caplog.at_level(logging.DEBUG, logger="sparky-manager"):
        rc, _out, _err = main_mod._run_privileged(
            "echo", "password=hunter2-secret-value", use_sudo=False)
    assert rc == 0
    assert calls == [["echo", "password=hunter2-secret-value"]]
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "hunter2-secret-value" not in logged
    assert "password=<redacted>" in logged


def test_run_privileged_failure_redacts_secrets_in_argv(monkeypatch, caplog):
    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(
        subprocess, "run", lambda argv, **kw: _Proc())
    with caplog.at_level(logging.DEBUG, logger="sparky-manager"):
        rc, _out, _err = main_mod._run_privileged(
            "echo", "sub_token=abc123def456", use_sudo=False)
    assert rc == 1
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "abc123def456" not in logged
    assert "sub_token=<redacted>" in logged
