"""Shared validated-atomic config writer tests (Phase 5, item 7).

The round-trip tests in test_render.py cover the binary-absent path
through both wrappers; these cover the binary-present paths of
``app.config_io.write_and_validate_config`` (success, failure,
timeout) with fake binaries, including the per-core error messages.
"""
from __future__ import annotations

import stat

from app import config_io
from app import singbox
from app import xray


def _fake_binary(tmp_path, name, body):
    script = tmp_path / name
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


def _valid_xray_cfg():
    return xray.render_xray_config(
        [{"tag": "vless-reality", "core": "xray", "protocol": "vless",
          "port": 443, "enabled": True,
          "stream_json": {"network": "tcp", "security": "reality",
                          "reality": {"sni": "www.microsoft.com"}}}],
        {"vless-reality": [{"uuid": "11111111-2222-4333-8444-555555555555",
                            "flow": "xtls-rprx-vision"}]},
        {},
    )


def test_binary_success_writes_file(tmp_path):
    binary = _fake_binary(tmp_path, "xray-ok", "exit 0")
    target = tmp_path / "xray.json"
    ok, messages = xray.write_and_validate(_valid_xray_cfg(), target, binary=binary)
    assert ok and messages == []
    assert target.exists()


def test_binary_failure_keeps_old_file_and_names_core(tmp_path):
    target = tmp_path / "xray.json"
    target.write_text("{}\n")
    binary = _fake_binary(tmp_path, "xray-bad", 'echo "bad port" >&2; exit 3')
    ok, errors = xray.write_and_validate(_valid_xray_cfg(), target, binary=binary)
    assert not ok
    assert errors == ["xray -test failed (exit 3): bad port"]
    assert target.read_text() == "{}\n"
    # The sing-box wrapper names its own core and check verb.
    binary2 = _fake_binary(tmp_path, "sb-bad", 'echo "nope" >&2; exit 2')
    cfg, _ = singbox.render_singbox_config(
        [{"tag": "anytls", "core": "singbox", "protocol": "anytls",
          "port": 8444, "enabled": True,
          "stream_json": {"tls": {"sni": "example.com"}}}],
        {"anytls": [{"password": "pw-001"}]},
        {"domain": "example.com", "cert_path": "/c.pem", "key_path": "/k.pem"},
    )
    ok, errors = singbox.write_and_validate(cfg, tmp_path / "sb.json", binary=binary2)
    assert not ok
    assert errors == ["sing-box check failed (exit 2): nope"]


def test_binary_timeout_reports_and_removes_tmp(tmp_path):
    binary = _fake_binary(tmp_path, "xray-slow", "sleep 5")
    target = tmp_path / "xray.json"
    ok, errors = config_io.write_and_validate_config(
        _valid_xray_cfg(),
        target,
        binary=binary,
        name="xray",
        check_label="-test",
        check_cmd=lambda b, t: [b, "run", "-test", "-c", t],
        validate=xray.validate_xray_config,
        timeout=1,
    )
    assert not ok
    assert errors == ["xray validation timed out after 1s"]
    assert not target.exists()
    assert not (tmp_path / "xray.json.tmp.json").exists()
