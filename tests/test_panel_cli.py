"""Phase 6 (professional upgrade) CLI tests — ``app/panel_cli.py``.

The ``sparky-manager`` command (info / status / restart / backup /
update-cores) had ZERO tests (Phase 1 audit G3-2): it is the
operator's main tool on the server, so its exit codes and its
tolerance of missing services / files are behavior worth locking
in. All systemctl calls are stubbed — no real service is touched.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from app import panel_cli as cli_mod


@pytest.fixture()
def fake_settings(tmp_path, monkeypatch):
    """Point the CLI at a temp home (no /opt, no /root writes).

    A namespace, not a real Settings: the real one derives the core
    config paths as fixed absolute paths (``/usr/local/etc/...``),
    which exist on some machines — including this VM, where an
    earlier test run left a real ``/usr/local/etc/xray/config.json``
    behind. Pointing every path under tmp_path keeps the backup
    tests hermetic.
    """
    from types import SimpleNamespace

    settings = SimpleNamespace(
        home=tmp_path,
        domain="203.0.113.10",
        panel_port=22140,
        data_dir=tmp_path / "data",
        xray_config=tmp_path / "xray.json",
        singbox_config=tmp_path / "sing-box.json",
        wg_config=tmp_path / "wg0.conf",
        ovpn_config=tmp_path / "openvpn.conf",
        ocserv_config=tmp_path / "ocserv.conf",
        ocserv_passwd=tmp_path / "ocpasswd",
        awg_config=tmp_path / "awg0.conf",
        swanctl_config=tmp_path / "swanctl.conf",
    )
    monkeypatch.setattr(
        cli_mod._config, "get_settings", lambda: settings)
    return settings


def _systemctl_stub(states, calls=None):
    """A ``_run_systemctl`` fake: ``states`` maps unit -> state for
    ``is-active``; ``cat`` succeeds for units in ``states`` (the unit
    exists) and fails otherwise; ``restart`` always succeeds."""

    def _run(*args):
        if calls is not None:
            calls.append(args)
        if not args:
            return False, "unknown"
        verb = args[0]
        unit = args[1] if len(args) > 1 else ""
        if verb == "is-active":
            if unit in states:
                return True, states[unit]
            return False, "unknown"
        if verb == "cat":
            return (unit in states), "unit file" if unit in states else ""
        if verb == "restart":
            return True, ""
        return False, "unknown"

    return _run


# ---------------------------------------------------------------------------
# _run_systemctl — the primitive every command builds on
# ---------------------------------------------------------------------------

def test_run_systemctl_success(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = "active\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: _Proc())
    ok, state = cli_mod._run_systemctl("is-active", "xray")
    assert (ok, state) == (True, "active")


def test_run_systemctl_nonzero_and_timeout(monkeypatch):
    class _Fail:
        returncode = 3
        stdout = "inactive\n"
        stderr = ""

    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: _Fail())
    assert cli_mod._run_systemctl("is-active", "xray") == (False, "inactive")

    def _timeout(argv, **kw):
        raise subprocess.TimeoutExpired(argv, timeout=10)

    monkeypatch.setattr(subprocess, "run", _timeout)
    assert cli_mod._run_systemctl("is-active", "xray") == (False, "unknown")


def test_run_systemctl_missing_binary(monkeypatch):
    def _missing(argv, **kw):
        raise FileNotFoundError("no systemctl")

    monkeypatch.setattr(subprocess, "run", _missing)
    assert cli_mod._run_systemctl("is-active", "xray") == (False, "unknown")


def test_run_systemctl_restart_uses_sudo_when_available(monkeypatch):
    seen = []

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: seen.append(list(argv)) or _Proc())
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sudo")
    cli_mod._run_systemctl("restart", "xray")
    assert seen == [["sudo", "-n", "systemctl", "restart", "xray"]]
    # Read-only queries stay plain (they work unprivileged).
    cli_mod._run_systemctl("is-active", "xray")
    assert seen[-1] == ["systemctl", "is-active", "xray"]


# ---------------------------------------------------------------------------
# info — the login box reprint (password only from the login file)
# ---------------------------------------------------------------------------

def test_info_without_login_file(fake_settings, capsys, monkeypatch):
    monkeypatch.setattr(cli_mod, "LOGIN_FILE", Path("/nonexistent/login.txt"))
    assert cli_mod.cmd_info() == 0
    out = capsys.readouterr().out
    assert "https://203.0.113.10:22140" in out
    assert "Username: admin" in out
    assert "password stored only in /root/sparky-manager-login.txt" in out


def test_info_with_login_file(fake_settings, capsys, monkeypatch, tmp_path):
    login_file = tmp_path / "login.txt"
    login_file.write_text("Password: s3cret-from-install\n")
    monkeypatch.setattr(cli_mod, "LOGIN_FILE", login_file)
    assert cli_mod.cmd_info() == 0
    assert "s3cret-from-install" in capsys.readouterr().out


def test_info_without_domain_shows_placeholder(fake_settings, capsys,
                                               monkeypatch, tmp_path):
    fake_settings.domain = ""
    fake_settings.panel_port = 8443
    monkeypatch.setattr(cli_mod, "LOGIN_FILE", Path("/nonexistent/login.txt"))
    assert cli_mod.cmd_info() == 0
    assert "https://<server-IP>:8443" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# status — exit 0 only when every known service is active
# ---------------------------------------------------------------------------

def test_status_all_active_exits_0(monkeypatch, capsys):
    states = {s: "active" for s in cli_mod.PANEL_SERVICES}
    states[cli_mod.WG_SERVICE] = "active"
    monkeypatch.setattr(cli_mod, "_run_systemctl", _systemctl_stub(states))
    assert cli_mod.cmd_status() == 0
    out = capsys.readouterr().out
    for service in (*cli_mod.PANEL_SERVICES, cli_mod.WG_SERVICE):
        assert f"{service}: active" in out


def test_status_inactive_service_exits_1(monkeypatch, capsys):
    states = {s: "active" for s in cli_mod.PANEL_SERVICES}
    states["xray"] = "inactive"
    states[cli_mod.WG_SERVICE] = "active"
    monkeypatch.setattr(cli_mod, "_run_systemctl", _systemctl_stub(states))
    assert cli_mod.cmd_status() == 1
    assert "xray: inactive" in capsys.readouterr().out


def test_status_skips_uninstalled_vpn_services(monkeypatch, capsys):
    """A VPN service whose unit does not exist (never installed) is
    skipped — status must not fail for a service that was never
    there."""
    states = {s: "active" for s in cli_mod.PANEL_SERVICES}
    states[cli_mod.WG_SERVICE] = "active"
    # No VPN_SERVICES units in `states`: `cat` fails for all of them.
    monkeypatch.setattr(cli_mod, "_run_systemctl", _systemctl_stub(states))
    assert cli_mod.cmd_status() == 0
    out = capsys.readouterr().out
    for service in cli_mod.VPN_SERVICES:
        assert service not in out


def test_status_includes_installed_vpn_service(monkeypatch, capsys):
    states = {s: "active" for s in cli_mod.PANEL_SERVICES}
    states[cli_mod.WG_SERVICE] = "active"
    states["ocserv"] = "failed"
    monkeypatch.setattr(cli_mod, "_run_systemctl", _systemctl_stub(states))
    assert cli_mod.cmd_status() == 1
    assert "ocserv: failed" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# restart — 0 only when every restart succeeded
# ---------------------------------------------------------------------------

def test_restart_all_ok_exits_0(monkeypatch, capsys):
    calls: list = []
    monkeypatch.setattr(
        cli_mod, "_run_systemctl", _systemctl_stub({}, calls))
    assert cli_mod.cmd_restart() == 0
    out = capsys.readouterr().out
    for service in cli_mod.PANEL_SERVICES:
        assert f"{service}: restarted" in out
        assert ("restart", service) in calls
    # No VPN units exist in the stub, so none are restarted (the
    # `cat` probes still ran — only restarts are asserted here).
    assert not any(
        c[0] == "restart" and c[1] in cli_mod.VPN_SERVICES for c in calls
    )


def test_restart_failure_exits_1_and_reports(monkeypatch, capsys):
    def _run(*args):
        if args == ("restart", "xray"):
            return False, ""
        if args[0] == "cat":
            return False, ""
        return True, ""

    monkeypatch.setattr(cli_mod, "_run_systemctl", _run)
    assert cli_mod.cmd_restart() == 1
    err = capsys.readouterr().err
    assert "xray: restart FAILED" in err


def test_restart_existing_vpn_failure_exits_1(monkeypatch, capsys):
    """A v12 service whose unit EXISTS but whose restart fails counts
    as a failure (exit 1). A service whose unit does not exist at all
    is skipped instead — see test_restart_all_ok_exits_0."""
    def _run(*args):
        if args[0] == "cat":
            return args[1] == "ocserv", ""
        if args == ("restart", "ocserv"):
            return False, ""
        return True, ""

    monkeypatch.setattr(cli_mod, "_run_systemctl", _run)
    assert cli_mod.cmd_restart() == 1
    assert "ocserv: restart FAILED" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# backup — tarball of the data dir + core configs
# ---------------------------------------------------------------------------

def test_backup_creates_tarball(fake_settings, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "panel.db").write_bytes(b"fake db")
    dest = tmp_path / "backup.tar.gz"
    assert cli_mod.cmd_backup(str(dest)) == 0
    assert dest.exists()
    with tarfile.open(dest, "r:gz") as tar:
        names = tar.getnames()
    assert "data" in names
    assert "data/panel.db" in names


def test_backup_nothing_to_back_up_exits_1(fake_settings, tmp_path, capsys):
    # No data dir, no core configs exist under the temp home.
    dest = tmp_path / "backup.tar.gz"
    assert cli_mod.cmd_backup(str(dest)) == 1
    assert not dest.exists()
    assert "nothing to back up" in capsys.readouterr().err


def test_backup_creates_parent_dirs(fake_settings, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "panel.db").write_bytes(b"fake db")
    dest = tmp_path / "deep" / "nested" / "backup.tar.gz"
    assert cli_mod.cmd_backup(str(dest)) == 0
    assert dest.exists()


# ---------------------------------------------------------------------------
# update-cores — deliberately unimplemented (exit 2)
# ---------------------------------------------------------------------------

def test_update_cores_exits_2_and_says_so(capsys):
    assert cli_mod.cmd_update_cores() == 2
    err = capsys.readouterr().err
    assert "not implemented" in err
    assert "install.sh" in err


# ---------------------------------------------------------------------------
# Entry point — dispatch + argparse behavior
# ---------------------------------------------------------------------------

def test_main_dispatches_each_command(monkeypatch, fake_settings, capsys):
    monkeypatch.setattr(cli_mod, "_run_systemctl",
                        _systemctl_stub({s: "active" for s in
                                         (*cli_mod.PANEL_SERVICES,
                                          cli_mod.WG_SERVICE)}))
    monkeypatch.setattr(cli_mod, "LOGIN_FILE", Path("/nonexistent/login.txt"))
    assert cli_mod.main(["info"]) == 0
    assert cli_mod.main(["status"]) == 0
    assert cli_mod.main(["restart"]) == 0
    assert cli_mod.main(["update-cores"]) == 2
    data_dir = fake_settings.home / "data"
    data_dir.mkdir()
    (data_dir / "panel.db").write_bytes(b"x")
    dest = fake_settings.home / "b.tar.gz"
    assert cli_mod.main(["backup", str(dest)]) == 0
    assert dest.exists()


def test_main_rejects_unknown_command():
    with pytest.raises(SystemExit) as excinfo:
        cli_mod.main(["explode"])
    assert excinfo.value.code == 2


def test_main_requires_a_command():
    with pytest.raises(SystemExit) as excinfo:
        cli_mod.main([])
    assert excinfo.value.code == 2
