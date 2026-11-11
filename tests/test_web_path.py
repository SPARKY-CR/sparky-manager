"""Secret web path tests (v9) + the Ikev2-manager reference removal.

The web path is the 3X-UI-style random path in front of the panel URL:
fresh installs get a random 12-char ``[a-z0-9]`` segment, re-installs
reuse it, and the panel only answers under ``/<path>`` — the root
returns 404. Subscription URLs must carry the prefix too (verified:
``request.base_url`` does NOT include ``root_path``).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import main as main_mod
from app.config import get_settings, normalize_web_path
from app.models import Inbound, User
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, HOST, ensure_defaults

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# config: normalization
# ---------------------------------------------------------------------------


def test_normalize_web_path():
    assert normalize_web_path("") == ""
    assert normalize_web_path("/") == ""
    assert normalize_web_path("abc123") == "/abc123"
    assert normalize_web_path("/abc123/") == "/abc123"
    assert normalize_web_path("a-b_c9") == "/a-b_c9"
    for bad in ("a b", "a/b", "a.b", "a?b", "-abc", "a b c"):
        with pytest.raises(ValueError):
            normalize_web_path(bad)


def test_get_settings_web_path(monkeypatch):
    monkeypatch.setenv("SPARKY_WEB_PATH", "k7x9q2")
    assert get_settings().web_path == "/k7x9q2"
    monkeypatch.setenv("SPARKY_WEB_PATH", "")
    assert get_settings().web_path == ""
    monkeypatch.delenv("SPARKY_WEB_PATH", raising=False)
    assert get_settings().web_path == ""


# ---------------------------------------------------------------------------
# main: redirects / template context / mount helper
# ---------------------------------------------------------------------------


def _fake_request() -> Request:
    return Request({
        "type": "http", "method": "GET", "path": "/",
        "headers": [], "query_string": b"",
        "server": ("testserver", 80), "scheme": "http",
        "client": ("testclient", 50000),
    })


def test_redirect_and_template_ctx_use_web_path(monkeypatch):
    monkeypatch.setattr(main_mod, "WEB_PATH", "/k7x9q2")
    req = _fake_request()
    assert main_mod._redirect("/dashboard", req).headers["location"] == "/k7x9q2/dashboard"
    assert main_mod._template_ctx(req)["base_path"] == "/k7x9q2"
    monkeypatch.setattr(main_mod, "WEB_PATH", "")
    assert main_mod._redirect("/dashboard", req).headers["location"] == "/dashboard"
    assert main_mod._template_ctx(req)["base_path"] == ""


def test_mount_web_path_identity():
    assert main_mod._mount_web_path(main_mod.app, "") is main_mod.app
    mounted = main_mod._mount_web_path(main_mod.app, "/k7x9q2")
    assert mounted is not main_mod.app


# ---------------------------------------------------------------------------
# end-to-end: the mounted panel (seeded DB, admin login through the path)
# ---------------------------------------------------------------------------


@pytest.fixture()
def mounted_client(db, tmp_path, monkeypatch):
    """A TestClient for the panel mounted under /k7x9q2 (logged out)."""
    monkeypatch.setattr(main_mod, "XRAY_CONFIG_PATH", str(tmp_path / "xray.json"))
    monkeypatch.setattr(main_mod, "SINGBOX_CONFIG_PATH", str(tmp_path / "singbox.json"))
    monkeypatch.setattr(main_mod, "WG_CONFIG_PATH", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    ensure_defaults(db)  # creates the admin from the env password
    main_mod.set_setting(db, "subscription_host", HOST)
    monkeypatch.setattr(main_mod, "WEB_PATH", "/k7x9q2")
    mounted = main_mod._mount_web_path(main_mod.app, "/k7x9q2")
    # NOTE: deliberately NOT used as a context manager (same reason as
    # conftest.test_client: entering it runs the lifespan, which would
    # rebind SessionLocal to the singleton engine).
    return TestClient(mounted)


def test_mounted_app_hides_root_and_serves_prefix(mounted_client, db):
    # The secret path hides the panel: root URLs 404.
    assert mounted_client.get("/login").status_code == 404
    assert mounted_client.get("/dashboard").status_code == 404
    assert mounted_client.get("/health").status_code == 404
    assert mounted_client.get("/").status_code == 404
    # Under the path the panel answers, with prefixed links.
    r = mounted_client.get("/k7x9q2/login")
    assert r.status_code == 200
    assert 'action="/k7x9q2/login"' in r.text
    assert 'href="/k7x9q2/static/style.css"' in r.text
    # Login through the path, redirect lands under the path.
    resp = mounted_client.post(
        "/k7x9q2/login",
        data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/k7x9q2/dashboard"
    r = mounted_client.get("/k7x9q2/dashboard")
    assert r.status_code == 200
    assert 'href="/k7x9q2/users"' in r.text
    assert 'href="/k7x9q2/inbounds"' in r.text
    assert 'href="/k7x9q2/settings"' in r.text
    # Health under the path (the installer's check URL).
    assert mounted_client.get("/k7x9q2/health").status_code == 200
    # Subscription URLs carry the prefix (base_url alone does not).
    user = db.query(User).first()
    assert user is not None
    r = mounted_client.get(f"/k7x9q2/users/{user.id}")
    assert r.status_code == 200
    assert f"/k7x9q2/sub/{user.sub_token}" in r.text


def test_inbound_port_500_4500_rejected(authed_client, db):
    """UDP 500/4500 stay reserved for IKEv2 — the form rejects them."""
    for port in (500, 4500):
        resp = authed_client.post(
            "/inbounds",
            data={"tag": f"bad{port}", "core": "xray", "protocol": "vless",
                  "port": port, "remark": "", "sni": "", "path": "",
                  "network": "tcp"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert db.query(Inbound).filter(Inbound.port == port).first() is None


# ---------------------------------------------------------------------------
# no other-project references left in the panel
# ---------------------------------------------------------------------------


def test_no_ikev2_manager_references():
    """The panel is built from scratch: no code, template, script,
    installer or doc (except DESIGN.md §1, which names the project
    only as what we do NOT copy) may reference Ikev2-manager."""
    for sub in ("app", "scripts"):
        for path in (REPO / sub).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".html", ".css", ".js"}:
                assert "Ikev2-manager" not in path.read_text(encoding="utf-8"), path
    for name in ("install.sh", "README.md", "README_FA.md"):
        assert "Ikev2-manager" not in (REPO / name).read_text(encoding="utf-8"), name
    design = (REPO / "DESIGN.md").read_text(encoding="utf-8")
    assert design.count("Ikev2-manager") == 1  # §1 principle only
    assert "ikev2_status" not in design
    assert "open_ikev2_manager" not in design
    assert not (REPO / "app" / "ikev2.py").exists()
    assert not (REPO / "app" / "i18n.py").exists()
