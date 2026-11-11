"""Panel logging (v12): rotating file log, runtime level, redaction.

Secrets must never reach the log file: UUIDs, private keys,
passwords, shared secrets and subscription tokens are masked by
:func:`redact`, and token fingerprints are logged instead of tokens.
"""

from __future__ import annotations

import logging

import pytest

from app import panel_log


def test_redact_uuid_and_private_key():
    text = (
        "peer uuid=550e8400-e29b-41d4-a716-446655440000 "
        "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "
        "and a normal word"
    )
    out = panel_log.redact(text)
    assert "550e8400" not in out
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" not in out
    assert "normal word" in out
    assert "<redacted>" in out


def test_redact_password_and_token_query():
    out = panel_log.redact(
        "login password=hunter2; GET /sub/abc?token=supersecrettoken123"
    )
    assert "hunter2" not in out
    assert "supersecrettoken123" not in out
    assert "/sub/abc?token=<redacted>" in out


def test_redact_leaves_innocent_text_alone():
    text = "restart of xray failed: exit 1; port 443; tag vless-reality"
    assert panel_log.redact(text) == text


def test_token_fingerprint_is_stable_and_short():
    fp1 = panel_log.token_fingerprint("abc123token")
    fp2 = panel_log.token_fingerprint("abc123token")
    assert fp1 == fp2
    assert len(fp1) == 12
    assert "abc123token" not in fp1
    assert panel_log.token_fingerprint("different") != fp1


def test_setup_logging_writes_and_rotates(tmp_path, monkeypatch):
    log_path = panel_log.setup_panel_logging(tmp_path, "DEBUG")
    assert log_path == tmp_path / "logs" / "panel.log"
    assert log_path.exists()
    logger = logging.getLogger(panel_log.LOGGER_NAME)
    logger.debug("hello debug")
    logger.info("hello info")
    for handler in logger.handlers:
        handler.flush()
    lines, total = panel_log.read_log_lines(log_path)
    assert total == 2
    assert lines[0]["message"].endswith("hello info")
    assert lines[0]["level"] == "INFO"
    assert lines[1]["level"] == "DEBUG"
    # Rotating handler exists (5 MB cap, 3 backups).
    from logging.handlers import RotatingFileHandler

    assert any(isinstance(h, RotatingFileHandler) for h in logger.handlers)


def test_apply_log_level_filters_at_runtime(tmp_path):
    panel_log.setup_panel_logging(tmp_path, "INFO")
    logger = logging.getLogger(panel_log.LOGGER_NAME)
    logger.debug("hidden debug")
    for handler in logger.handlers:
        handler.flush()
    log_path = panel_log.get_log_path(tmp_path)
    _, total = panel_log.read_log_lines(log_path)
    assert total == 0  # DEBUG below INFO: not written
    assert panel_log.apply_log_level("DEBUG") == "DEBUG"
    logger.debug("shown debug")
    for handler in logger.handlers:
        handler.flush()
    lines, total = panel_log.read_log_lines(log_path)
    assert total == 1
    assert lines[0]["level"] == "DEBUG"
    assert panel_log.apply_log_level("bogus") == "INFO"  # invalid -> default
    assert panel_log.current_level() == "INFO"


def test_read_log_lines_filter_and_search(tmp_path):
    log_path = tmp_path / "panel.log"
    log_path.write_text(
        "2026-11-11 10:00:00 [INFO] sparky-manager: render ok\n"
        "2026-11-11 10:01:00 [ERROR] sparky-manager: restart of xray failed: boom\n"
        "  traceback line stays attached\n"
        "2026-11-11 10:02:00 [WARNING] sparky-manager: slow render\n",
        encoding="utf-8",
    )
    lines, total = panel_log.read_log_lines(log_path)
    assert total == 3
    assert lines[0]["level"] == "WARNING"  # newest first
    lines, _ = panel_log.read_log_lines(log_path, level="ERROR")
    assert len(lines) == 1 and lines[0]["level"] == "ERROR"
    lines, _ = panel_log.read_log_lines(log_path, query="xray")
    assert len(lines) == 1
    assert "traceback line stays attached" in lines[0]["message"]
    lines, _ = panel_log.read_log_lines(log_path, limit=1)
    assert len(lines) == 1


def test_read_log_lines_missing_file(tmp_path):
    lines, total = panel_log.read_log_lines(tmp_path / "nope.log")
    assert lines == [] and total == 0


def test_list_log_files(tmp_path):
    import os
    import time

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "panel.log").write_text("x")
    (log_dir / "panel.log.1").write_text("y")
    (log_dir / "other.txt").write_text("z")
    # Pin mtimes: the current file is the newest.
    now = time.time()
    os.utime(log_dir / "panel.log.1", (now - 60, now - 60))
    os.utime(log_dir / "panel.log", (now, now))
    files = panel_log.list_log_files(tmp_path)
    assert [f["name"] for f in files] == ["panel.log", "panel.log.1"]
    assert files[0]["current"] is True
    assert files[1]["current"] is False


def test_clear_log_truncates_and_keeps_level(tmp_path):
    log_path = panel_log.setup_panel_logging(tmp_path, "DEBUG")
    logger = logging.getLogger(panel_log.LOGGER_NAME)
    panel_log.apply_log_level("DEBUG")
    logger.info("before clear")
    for handler in logger.handlers:
        handler.flush()
    assert log_path.read_text(encoding="utf-8").strip() != ""
    assert panel_log.clear_log(tmp_path) is True
    assert log_path.read_text(encoding="utf-8") == ""
    # Level survived the clear (DEBUG, not reset to INFO).
    assert panel_log.current_level() == "DEBUG"
    logger.debug("after clear")
    for handler in logger.handlers:
        handler.flush()
    assert "after clear" in log_path.read_text(encoding="utf-8")


def test_logs_page_requires_login(test_client):
    assert test_client.get("/logs", follow_redirects=False).status_code in (303, 307)
    assert test_client.get("/logs/download", follow_redirects=False).status_code in (401, 403, 303, 307)
    resp = test_client.post("/logs/clear", follow_redirects=False)
    assert resp.status_code in (401, 403, 303, 307)


def test_logs_page_lists_and_filters(authed_client, tmp_path, monkeypatch):
    import logging as _logging
    from app import main as main_mod
    from app import panel_log as pl

    log_path = pl.setup_panel_logging(tmp_path, "DEBUG")
    logger = _logging.getLogger(pl.LOGGER_NAME)
    logger.info("render ok for vless-reality")
    logger.error("restart of xray failed: boom")
    for handler in logger.handlers:
        handler.flush()
    monkeypatch.setattr(pl, "get_log_path", lambda data_dir=None: log_path)
    monkeypatch.setattr(pl, "get_log_dir", lambda data_dir=None: tmp_path / "logs")
    monkeypatch.setattr(pl, "list_log_files",
                        lambda data_dir=None: [{"name": "panel.log", "size_bytes": 10, "current": True}])

    resp = authed_client.get("/logs")
    assert resp.status_code == 200
    assert "render ok for vless-reality" in resp.text
    assert "restart of xray failed" in resp.text
    assert "panel.log" in resp.text
    # Level filter: only ERROR and above.
    resp = authed_client.get("/logs", params={"level": "ERROR"})
    assert resp.status_code == 200
    assert "restart of xray failed" in resp.text
    assert "render ok for vless-reality" not in resp.text
    # Text search.
    resp = authed_client.get("/logs", params={"q": "vless-reality"})
    assert "render ok for vless-reality" in resp.text
    assert "restart of xray failed" not in resp.text


def test_logs_download_and_clear(authed_client, tmp_path, monkeypatch):
    import logging as _logging
    from app import panel_log as pl

    log_path = pl.setup_panel_logging(tmp_path, "INFO")
    logger = _logging.getLogger(pl.LOGGER_NAME)
    logger.info("download me")
    for handler in logger.handlers:
        handler.flush()
    monkeypatch.setattr(pl, "get_log_path", lambda data_dir=None: log_path)
    monkeypatch.setattr(pl, "get_log_dir", lambda data_dir=None: tmp_path / "logs")

    resp = authed_client.get("/logs/download")
    assert resp.status_code == 200
    assert b"download me" in resp.content
    resp = authed_client.post("/logs/clear", follow_redirects=False)
    assert resp.status_code in (302, 303)
    # The old lines are gone; the clear itself is logged as the first
    # line of the fresh file (so the action is auditable).
    cleared = log_path.read_text(encoding="utf-8")
    assert "download me" not in cleared
    assert "log cleared by admin admin" in cleared


def test_settings_log_level_applies_live(authed_client, db):
    from app import main as main_mod
    from app import panel_log as pl

    resp = authed_client.post("/settings", data={
        "domain": "", "subscription_host": "203.0.113.10",
        "reality_sni": "www.microsoft.com", "log_level": "DEBUG",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert pl.current_level() == "DEBUG"
    assert main_mod.get_setting(db, "log_level") == "DEBUG"
    # Invalid level falls back to INFO (validated inside apply).
    resp = authed_client.post("/settings", data={
        "domain": "", "subscription_host": "203.0.113.10",
        "reality_sni": "www.microsoft.com", "log_level": "NOPE",
    }, follow_redirects=False)
    assert resp.status_code in (302, 303)
    assert pl.current_level() == "INFO"
    assert main_mod.get_setting(db, "log_level") == "INFO"


def test_secrets_never_logged(tmp_path, monkeypatch):
    """A rendered config containing keys must not leak them into the log."""
    from app import wireguard as wg_mod

    log_path = panel_log.setup_panel_logging(tmp_path, "DEBUG")
    logger = logging.getLogger(panel_log.LOGGER_NAME)
    private, public = wg_mod.generate_keypair()
    content = wg_mod.render_wg_config(private, [{"public_key": public, "allowed_ips": "10.8.0.2/32"}])
    # Call sites must log metadata only; even if a careless call passed
    # the raw config, the redactor must strip the keys.
    logger.info("rendered wg0.conf: %s", panel_log.redact(content))
    for handler in logger.handlers:
        handler.flush()
    logged = log_path.read_text(encoding="utf-8")
    assert private not in logged
    assert public not in logged
    assert "rendered wg0.conf" in logged
