"""Phase A item 5 tests — PWA manifest + service worker, clickable
dashboard counter cards, and the in-panel tools page (config
tester, QR display, decoders).
"""

from __future__ import annotations

import base64
import json
import re

from app.links import build_vless_link, build_vmess_link
from app.webcommon import WEB_PATH


# ---------------------------------------------------------------------------
# PWA
# ---------------------------------------------------------------------------

def test_manifest_shape(test_client):
    resp = test_client.get("/manifest.webmanifest")
    assert resp.status_code == 200
    assert "application/manifest+json" in resp.headers["content-type"]
    manifest = resp.json()
    assert manifest["name"] == "Sparky Manager"
    assert manifest["display"] == "standalone"
    # start_url/scope cover the whole panel under its web path.
    assert manifest["start_url"] == f"{WEB_PATH}/dashboard"
    assert manifest["scope"] == f"{WEB_PATH}/"
    # One SVG icon (sizes "any" — SVG scales), maskable purpose.
    assert len(manifest["icons"]) == 1
    icon = manifest["icons"][0]
    assert icon["sizes"] == "any"
    assert icon["type"] == "image/svg+xml"
    assert icon["src"].endswith("/static/icons/icon.svg")
    assert "maskable" in icon.get("purpose", "")


def test_manifest_is_public(test_client):
    # No login needed — a browser fetches the manifest before any
    # auth context exists.
    assert test_client.get("/manifest.webmanifest").status_code == 200


def test_service_worker_serves(test_client):
    resp = test_client.get("/sw.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    assert "sparky-manager-v2" in resp.text
    assert "addEventListener" in resp.text
    # No fake offline page: pages are network-first.
    assert "offline" in resp.text.lower()


def test_manifest_icons_exist_on_disk():
    from pathlib import Path

    icons = Path("app/static/icons")
    # One SVG icon (a text file, so the push path can carry it) and
    # no PNGs: the GitHub connector cannot push binary files.
    assert (icons / "icon.svg").exists()
    assert not (icons / "icon-192.png").exists()
    assert not (icons / "icon-512.png").exists()
    content = (icons / "icon.svg").read_text(encoding="utf-8")
    assert "<svg" in content and "</svg>" in content
    assert "<polygon" in content
    assert "#8B7CFF" in content


def test_base_template_links_manifest(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    assert f'href="{WEB_PATH}/manifest.webmanifest"' in resp.text
    assert 'name="theme-color"' in resp.text


# ---------------------------------------------------------------------------
# Clickable dashboard cards
# ---------------------------------------------------------------------------

def test_dashboard_metric_cards_are_links(authed_client):
    resp = authed_client.get("/dashboard")
    assert resp.status_code == 200
    cards = re.findall(
        r'<a class="card metric-card metric-link" href="([^"]+)">',
        resp.text,
    )
    assert len(cards) == 5, cards
    assert f"{WEB_PATH}/users" in cards
    assert f"{WEB_PATH}/users?status=enabled" in cards
    assert f"{WEB_PATH}/inbounds" in cards
    assert f"{WEB_PATH}/users?sort=traffic" in cards
    # Every card target resolves.
    for href in cards:
        assert authed_client.get(href).status_code == 200, href


# ---------------------------------------------------------------------------
# Tools page
# ---------------------------------------------------------------------------

def test_tools_page_renders(authed_client):
    resp = authed_client.get("/tools")
    assert resp.status_code == 200
    assert f'action="{WEB_PATH}/tools/test"' in resp.text
    assert f'action="{WEB_PATH}/tools/qr"' in resp.text
    assert f'action="{WEB_PATH}/tools/decode"' in resp.text


def test_tools_page_requires_login(test_client):
    resp = test_client.get("/tools", follow_redirects=False)
    assert resp.status_code == 303


def test_tools_posts_require_csrf(authed_client):
    # A caller-supplied (wrong) token is never overwritten by the
    # CSRFTestClient — the route must reject it.
    for url, field in (
        ("/tools/test", "config_text"),
        ("/tools/qr", "qr_text"),
        ("/tools/decode", "decode_text"),
    ):
        resp = authed_client.post(
            url, data={"csrf_token": "wrong-token", field: "x"})
        assert resp.status_code == 403, url


def test_config_tester_valid_vless_link_redacts_credentials(authed_client):
    link = build_vless_link(
        uuid="11111111-2222-3333-4444-555555555555",
        host="203.0.113.10", port=443, name="my-vless",
    )
    resp = authed_client.post("/tools/test", data={"config_text": link})
    assert resp.status_code == 200
    # Valid, protocol shown — but the UUID never appears (redacted).
    assert "11111111-2222-3333-4444-555555555555" not in resp.text
    assert "••••" in resp.text
    assert "203.0.113.10" in resp.text


def test_config_tester_rejects_garbage(authed_client):
    resp = authed_client.post(
        "/tools/test", data={"config_text": "not a link or json"})
    assert resp.status_code == 200
    assert "flash-err" in resp.text


def test_config_tester_valid_xray_json(authed_client):
    cfg = {
        "inbounds": [{
            "tag": "vless-1", "protocol": "vless", "port": 443,
            "settings": {"clients": [{"id": "11111111-2222-3333-4444-555555555555"}]},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    resp = authed_client.post(
        "/tools/test", data={"config_text": json.dumps(cfg)})
    assert resp.status_code == 200
    assert "flash-ok" in resp.text
    assert "xray" in resp.text


def test_config_tester_invalid_xray_json_lists_errors(authed_client):
    cfg = {
        "inbounds": [
            {"tag": "a", "protocol": "vless", "port": 443,
             "settings": {"clients": [{"id": "x"}]}},
            {"tag": "b", "protocol": "trojan", "port": 443,
             "settings": {"clients": [{"password": "y"}]}},
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    resp = authed_client.post(
        "/tools/test", data={"config_text": json.dumps(cfg)})
    assert resp.status_code == 200
    assert "flash-err" in resp.text
    # Two TCP inbounds on one port is a structural error.
    assert "443" in resp.text


def test_config_tester_rejects_malformed_json(authed_client):
    resp = authed_client.post(
        "/tools/test", data={"config_text": '{"inbounds": [}'})
    assert resp.status_code == 200
    assert "flash-err" in resp.text


def test_config_tester_empty_input(authed_client):
    resp = authed_client.post("/tools/test", data={"config_text": "  "})
    assert resp.status_code == 200
    assert "flash-err" in resp.text


def test_qr_tool_returns_data_uri_image(authed_client):
    resp = authed_client.post(
        "/tools/qr", data={"qr_text": "vless://example"})
    assert resp.status_code == 200
    assert "data:image/png;base64," in resp.text


def test_qr_tool_empty_input(authed_client):
    resp = authed_client.post("/tools/qr", data={"qr_text": ""})
    assert resp.status_code == 200
    assert "flash-err" in resp.text


def test_decoder_vmess_link(authed_client):
    link = build_vmess_link(
        uuid="11111111-2222-3333-4444-555555555555",
        host="203.0.113.10", port=443, name="my-vmess",
    )
    resp = authed_client.post("/tools/decode", data={"decode_text": link})
    assert resp.status_code == 200
    # A decoder shows what the admin pasted — the remark and the
    # host are visible (decoding is its whole purpose).
    assert "my-vmess" in resp.text
    assert "203.0.113.10" in resp.text


def test_decoder_base64(authed_client):
    text = base64.b64encode("hello sparky".encode()).decode()
    resp = authed_client.post("/tools/decode", data={"decode_text": text})
    assert resp.status_code == 200
    assert "hello sparky" in resp.text


def test_decoder_bad_base64(authed_client):
    # Non-ASCII input cannot be base64 at all (the decoder encodes
    # to ASCII first) — a guaranteed rejection, not a coin flip on
    # whether discarded characters leave valid UTF-8 behind.
    resp = authed_client.post(
        "/tools/decode", data={"decode_text": "éééé not base64 éééé"})
    assert resp.status_code == 200
    assert "flash-err" in resp.text
