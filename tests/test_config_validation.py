"""Phase A item 8 tests — config-profile validation before apply.

The panel validates generated Xray/sing-box JSON structurally AND
with the core binary's own test mode when the binary is runnable
from the panel process (unprivileged — the binaries are
world-executable). When the binary is absent, only the JSON
structure is validated and the file is still written — but the
re-render LOGS that the binary check did not run, so the panel
never silently claims a validation that did not happen.
"""

from __future__ import annotations

import json
import stat

import pytest

from app import config_io as config_io_mod
from app import main as main_mod
from app import singbox as singbox_mod
from app import xray as xray_mod


def _valid_xray_cfg():
    return {
        "inbounds": [{
            "tag": "vless-1", "protocol": "vless", "port": 443,
            "settings": {"clients": [
                {"id": "11111111-2222-3333-4444-555555555555"}]},
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def _write(cfg, path, binary, validate):
    return config_io_mod.write_and_validate_config(
        cfg, path,
        binary=binary, name="xray", check_label="check",
        check_cmd=lambda b, t: [b, t],
        validate=validate,
    )


def _fake_binary(tmp_path, name, exit_code):
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

def test_structural_rejection_keeps_old_file(tmp_path):
    target = tmp_path / "xray.json"
    target.write_text('{"old": true}\n')
    bad = _valid_xray_cfg()
    bad["inbounds"][0]["port"] = 0  # port 0 is never valid
    ok, errors = _write(bad, target, "/nonexistent/xray",
                        xray_mod.validate_xray_config)
    assert ok is False
    assert errors
    assert target.read_text() == '{"old": true}\n'
    assert not (tmp_path / "xray.json.tmp.json").exists()


def test_duplicate_tcp_port_rejected(tmp_path):
    cfg = _valid_xray_cfg()
    cfg["inbounds"].append({
        "tag": "trojan-1", "protocol": "trojan", "port": 443,
        "settings": {"clients": [{"password": "secret"}]},
    })
    ok, errors = _write(cfg, tmp_path / "xray.json", "/nonexistent/xray",
                        xray_mod.validate_xray_config)
    assert ok is False
    assert any("443" in e for e in errors)


def test_missing_credential_rejected(tmp_path):
    cfg = _valid_xray_cfg()
    cfg["inbounds"][0]["settings"]["clients"] = [{}]
    ok, errors = _write(cfg, tmp_path / "xray.json", "/nonexistent/xray",
                        xray_mod.validate_xray_config)
    assert ok is False
    assert errors


def test_non_serializable_config_rejected(tmp_path):
    target = tmp_path / "xray.json"
    target.write_text('{"old": true}\n')
    cfg = _valid_xray_cfg()
    cfg["inbounds"][0]["settings"]["clients"][0]["id"] = {1, 2, 3}
    ok, errors = _write(cfg, target, "/nonexistent/xray",
                        xray_mod.validate_xray_config)
    assert ok is False
    assert errors
    assert target.read_text() == '{"old": true}\n'


# ---------------------------------------------------------------------------
# Binary check (fake binaries)
# ---------------------------------------------------------------------------

def test_binary_absent_writes_with_warning_message(tmp_path):
    target = tmp_path / "xray.json"
    ok, messages = _write(_valid_xray_cfg(), target,
                          "/nonexistent/xray", xray_mod.validate_xray_config)
    assert ok is True
    assert target.exists()
    assert json.loads(target.read_text())["inbounds"][0]["tag"] == "vless-1"
    # The caller is TOLD the binary check did not run.
    assert len(messages) == 1
    assert "binary not present" in messages[0]


def test_binary_exit_zero_writes_cleanly(tmp_path):
    binary = _fake_binary(tmp_path, "fake-xray-ok", 0)
    target = tmp_path / "xray.json"
    ok, messages = _write(_valid_xray_cfg(), target, binary,
                          xray_mod.validate_xray_config)
    assert ok is True
    assert messages == []
    assert target.exists()


def test_binary_exit_nonzero_keeps_old_file(tmp_path):
    binary = _fake_binary(tmp_path, "fake-xray-bad", 1)
    target = tmp_path / "xray.json"
    target.write_text('{"old": true}\n')
    ok, errors = _write(_valid_xray_cfg(), target, binary,
                        xray_mod.validate_xray_config)
    assert ok is False
    assert errors
    assert "exit 1" in errors[0]
    assert target.read_text() == '{"old": true}\n'
    assert not (tmp_path / "xray.json.tmp.json").exists()


def test_binary_check_runs_unprivileged(tmp_path):
    # The panel is unprivileged: the binary check must work with no
    # sudo — a world-executable script in tmp proves the mechanism
    # needs no privilege (the real binaries are world-executable).
    binary = _fake_binary(tmp_path, "fake-xray", 0)
    target = tmp_path / "xray.json"
    ok, _ = _write(_valid_xray_cfg(), target, binary,
                   xray_mod.validate_xray_config)
    assert ok is True


# ---------------------------------------------------------------------------
# sing-box structural validation
# ---------------------------------------------------------------------------

def test_singbox_structural_validation(tmp_path):
    good = {
        "inbounds": [{
            "type": "vless", "tag": "vless-1", "listen_port": 443,
            "users": [{"uuid": "11111111-2222-3333-4444-555555555555"}],
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    ok, _ = config_io_mod.write_and_validate_config(
        good, tmp_path / "singbox.json",
        binary="/nonexistent/sing-box", name="sing-box",
        check_label="check", check_cmd=lambda b, t: [b, t],
        validate=singbox_mod.validate_singbox_config,
    )
    assert ok is True
    bad = {"inbounds": [{"type": "vless", "tag": "x"}], "outbounds": []}
    ok, errors = config_io_mod.write_and_validate_config(
        bad, tmp_path / "singbox.json",
        binary="/nonexistent/sing-box", name="sing-box",
        check_label="check", check_cmd=lambda b, t: [b, t],
        validate=singbox_mod.validate_singbox_config,
    )
    assert ok is False
    assert errors


# ---------------------------------------------------------------------------
# Re-render logs the binary-absent note (the honest gap, closed)
# ---------------------------------------------------------------------------

def test_rerender_logs_binary_absent_note(
        db, seeded, caplog, monkeypatch, tmp_path):
    # Dummy TLS certs (like the restore roundtrip test): without
    # them the sing-box render reports "no TLS certificate" warnings
    # and the re-render returns errors.
    cert = tmp_path / "fullchain.pem"
    key = tmp_path / "privkey.pem"
    cert.write_text("dummy certificate")
    key.write_text("dummy private key")
    main_mod.set_setting(db, "cert_path", str(cert))
    main_mod.set_setting(db, "key_path", str(key))
    # Point the binary paths at nothing: the re-render writes the
    # configs but must LOG that the binary check did not run.
    monkeypatch.setattr(main_mod, "XRAY_BINARY", "/nonexistent/xray")
    monkeypatch.setattr(main_mod, "SINGBOX_BINARY", "/nonexistent/sing-box")
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    monkeypatch.setattr(
        main_mod, "_apply_wireguard_config", lambda content, **kw: None)
    monkeypatch.setattr(main_mod, "_apply_ikev2_config", lambda: None)
    import logging

    with caplog.at_level(logging.WARNING, logger="sparky-manager"):
        errors = main_mod.rerender_configs(db)
    assert errors == []
    notes = [r.message for r in caplog.records
             if "validation note" in r.message]
    assert notes, "no binary-absent note was logged"
    assert all("binary not present" in note for note in notes)
