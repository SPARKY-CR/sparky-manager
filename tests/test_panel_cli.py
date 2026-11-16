"""Phase 6 (professional upgrade) CLI tests — ``app/panel_cli.py``.

The ``sparky-manager`` command (info / status / restart / backup /
update-cores) had ZERO tests (Phase 1 audit G3-2): it is the
operator's main tool on the server, so its exit codes and its
tolerance of missing services / files are behavior worth locking
in. All systemctl calls are stubbed — no real service is touched.

Phase C item 23 extended the CLI (users / user-add / user-disable /
user-enable / inbounds / restore / health) and removed the
``update-cores`` stub: core updates are install.sh's job, with its
SHA256 verification — a second updater would duplicate that and
could diverge (DESIGN.md §8).
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
        web_path="",
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
    exists) and fails otherwise; ``restart`` / ``stop`` / ``start``
    always succeed."""

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
        if verb in ("restart", "stop", "start"):
            return True, ""
        return False, "unknown"

    return _run


@pytest.fixture()
def _no_rerender_side_effects(monkeypatch):
    """Re-rendering in tests: configs go to tmp (autouse fixture)
    and the service restarts / WireGuard / IKEv2 applies are
    stubbed — the same three stubs the test_client fixture uses."""
    from app import main as main_mod

    monkeypatch.setattr(main_mod, "_restart_service", lambda name: None)
    monkeypatch.setattr(
        main_mod, "_apply_wireguard_config", lambda content, **kw: None
    )
    monkeypatch.setattr(main_mod, "_apply_ikev2_config", lambda: None)


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

def test_update_cores_removed():
    """Phase C item 23: the stub is gone (core updates are
    install.sh's job). argparse rejects the subcommand with exit 2
    — the same code the stub used to return, so scripts testing
    for failure keep working."""
    assert not hasattr(cli_mod, "cmd_update_cores")
    with pytest.raises(SystemExit) as excinfo:
        cli_mod.main(["update-cores"])
    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Phase C item 23 — users / user-add / user-disable / user-enable / inbounds
# ---------------------------------------------------------------------------


def test_users_lists_seeded_users(db, capsys):
    assert cli_mod.cmd_users() == 0
    out = capsys.readouterr().out
    for name in ("alice", "bob", "carol", "dave", "eve"):
        assert name in out
    assert "disabled" in out  # dave
    assert "11 clients" in out  # alice: a client on every inbound


def test_users_empty_db(capsys, tmp_path):
    # A fresh, unseeded DB prints "no users" (the db fixture is not
    # used here, so bind a bare engine first).
    from app import db as db_mod

    engine = db_mod.get_engine(tmp_path / "bare.db")
    db_mod.init_db(engine)
    try:
        assert cli_mod.cmd_users() == 0
    finally:
        db_mod.dispose_engine()
    assert "no users" in capsys.readouterr().out


def test_user_add_creates_user_and_clients(
    db, capsys, _no_rerender_side_effects
):
    from app.models import Client, User

    assert cli_mod.cmd_user_add("frank") == 0
    out = capsys.readouterr().out
    assert "frank" in out
    user = db.query(User).filter(User.name == "frank").one()
    assert user.enabled
    # One client per ENABLED inbound (10 of 11 — vmess-disabled is off).
    assert (
        db.query(Client).filter(Client.user_id == user.id).count() == 10
    )
    # No host configured: the token is printed instead of a URL.
    assert user.sub_token in out


def test_user_add_with_options_and_host(
    db, capsys, _no_rerender_side_effects
):
    from app import webcommon as webcommon_mod
    from app.models import User

    webcommon_mod.set_setting(db, "subscription_host", "203.0.113.10")
    assert (
        cli_mod.cmd_user_add(
            "grace", traffic_limit_gb=10, expires_days=30
        )
        == 0
    )
    out = capsys.readouterr().out
    user = db.query(User).filter(User.name == "grace").one()
    assert user.traffic_limit_bytes == 10 * 1024**3
    assert user.expires_at is not None
    assert "https://203.0.113.10:" in out
    assert f"/sub/{user.sub_token}" in out


def test_user_add_rejects_duplicate_and_bad_name(
    db, capsys, _no_rerender_side_effects
):
    assert cli_mod.cmd_user_add("alice") == 1
    assert "already exists" in capsys.readouterr().err
    assert cli_mod.cmd_user_add("bad name!") == 1
    assert "invalid name" in capsys.readouterr().err
    assert cli_mod.cmd_user_add("ok", traffic_limit_gb=0) == 1
    assert cli_mod.cmd_user_add("ok", expires_days=-1) == 1


def test_user_add_rerender_failure_exits_1(
    db, capsys, monkeypatch, _no_rerender_side_effects
):
    from app.models import User

    monkeypatch.setattr(cli_mod, "_rerender", lambda _db: ["boom"])
    assert cli_mod.cmd_user_add("henry") == 1
    assert "re-render failed" in capsys.readouterr().err
    # The user was still created (the error is reported, not hidden).
    assert db.query(User).filter(User.name == "henry").count() == 1


def test_user_add_rerender_warning_only_exits_0(
    db, capsys, monkeypatch, _no_rerender_side_effects
):
    # A "warning:" re-render note (an inbound omitted — no usable
    # clients, no TLS cert) is not a failure of the user operation.
    monkeypatch.setattr(
        cli_mod,
        "_rerender",
        lambda _db: ["sing-box warning: tuic 'tuic': no usable clients, omitted"],
    )
    assert cli_mod.cmd_user_add("ivan") == 0
    assert "re-render warning" in capsys.readouterr().err


def test_user_disable_enable_round_trip(
    db, capsys, _no_rerender_side_effects
):
    from app.models import User

    assert cli_mod.cmd_user_disable("alice") == 0
    assert "disabled" in capsys.readouterr().out
    db.expire_all()
    assert not db.query(User).filter(User.name == "alice").one().enabled
    # Idempotent: disabling again is a no-op success.
    assert cli_mod.cmd_user_disable("alice") == 0
    assert "already disabled" in capsys.readouterr().out
    assert cli_mod.cmd_user_enable("alice") == 0
    db.expire_all()
    assert db.query(User).filter(User.name == "alice").one().enabled


def test_user_disable_unknown_user(db, capsys, _no_rerender_side_effects):
    assert cli_mod.cmd_user_disable("nobody") == 1
    assert "no user named" in capsys.readouterr().err
    assert cli_mod.cmd_user_enable("nobody") == 1


def test_inbounds_lists_seeded_inbounds(db, capsys):
    assert cli_mod.cmd_inbounds() == 0
    out = capsys.readouterr().out
    assert "vless-reality vless port 443" in out
    assert "wireguard wireguard port 51820" in out
    assert "vmess-disabled" in out
    assert "disabled" in out


# ---------------------------------------------------------------------------
# Phase C item 23 — restore
# ---------------------------------------------------------------------------


def _make_backup_zip(tmp_path, user_name="restored"):
    """A backup ZIP from a second, minimal DB (one user, one xray
    inbound). Built on its own engine so the test's bound engine is
    untouched."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app import backup as backup_mod
    from app.models import Base, Inbound, User

    other_path = tmp_path / "other.db"
    engine = create_engine(f"sqlite:///{other_path}")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    inbound = Inbound(
        tag="vless-9000", core="xray", protocol="vless", port=9000
    )
    session.add(inbound)
    session.add(User(name=user_name))
    session.commit()
    session.close()
    engine.dispose()
    zip_bytes = backup_mod.create_backup_zip(other_path)
    zip_path = tmp_path / "backup.zip"
    zip_path.write_bytes(zip_bytes)
    return zip_path


def test_restore_swaps_db_and_restarts_panel(
    db, tmp_path, monkeypatch, capsys, _no_rerender_side_effects
):
    from app import db as db_mod
    from app.models import User

    calls: list[tuple] = []
    monkeypatch.setattr(
        cli_mod, "_run_systemctl", _systemctl_stub({}, calls)
    )
    monkeypatch.setattr(cli_mod._config, "DATA_DIR", tmp_path)
    zip_path = _make_backup_zip(tmp_path)
    assert cli_mod.cmd_restore(str(zip_path)) == 0
    out = capsys.readouterr().out
    assert "restored 1 users, 1 inbounds" in out
    assert ("stop", "sparky-manager") in calls
    assert ("start", "sparky-manager") in calls
    # The pre-restore backup of the OLD db was kept.
    assert list((tmp_path / "backups").glob("panel.db.*.bak"))
    # The live DB now holds the restored user (fresh session — the
    # restore disposed + reset the engine).
    fresh = db_mod.SessionLocal()
    try:
        names = {u.name for u in fresh.query(User).all()}
    finally:
        fresh.close()
    assert names == {"restored"}


def test_restore_missing_and_invalid_files(
    db, tmp_path, monkeypatch, capsys
):
    calls: list[tuple] = []
    monkeypatch.setattr(
        cli_mod, "_run_systemctl", _systemctl_stub({}, calls)
    )
    monkeypatch.setattr(cli_mod._config, "DATA_DIR", tmp_path)
    assert cli_mod.cmd_restore(str(tmp_path / "nope.zip")) == 1
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"this is not a backup at all, just text")
    assert cli_mod.cmd_restore(str(bad)) == 1
    # Validation failed before the stop: the panel was never touched.
    assert calls == []


def test_restore_stop_failure_aborts_before_swap(
    db, tmp_path, monkeypatch, capsys
):
    from app.models import User

    def _fail_stop(*args):
        if args and args[0] == "stop":
            return False, "denied"
        return True, ""

    monkeypatch.setattr(cli_mod, "_run_systemctl", _fail_stop)
    monkeypatch.setattr(cli_mod._config, "DATA_DIR", tmp_path)
    zip_path = _make_backup_zip(tmp_path)
    assert cli_mod.cmd_restore(str(zip_path)) == 1
    assert "needs root" in capsys.readouterr().err
    # The DB is untouched.
    assert db.query(User).count() == 5


# ---------------------------------------------------------------------------
# Phase C item 23 — health
# ---------------------------------------------------------------------------


class _FakeHealthResponse:
    """A urlopen stand-in: 200 + {"status": "ok"}."""

    status = 200

    def read(self):
        return b'{"status": "ok"}'

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_health_all_ok(
    db, fake_settings, monkeypatch, capsys
):
    monkeypatch.setattr(
        cli_mod,
        "_run_systemctl",
        _systemctl_stub(
            {s: "active" for s in (*cli_mod.PANEL_SERVICES, cli_mod.WG_SERVICE)}
        ),
    )
    monkeypatch.setattr(
        cli_mod.urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHealthResponse(),
    )
    assert cli_mod.cmd_health() == 0
    out = capsys.readouterr().out
    assert "database: ok (5 users)" in out
    assert "panel: ok" in out
    assert "xray: active" in out


def test_health_panel_down_exits_1(
    db, fake_settings, monkeypatch, capsys
):
    monkeypatch.setattr(
        cli_mod,
        "_run_systemctl",
        _systemctl_stub(
            {s: "active" for s in (*cli_mod.PANEL_SERVICES, cli_mod.WG_SERVICE)}
        ),
    )

    def _refused(*a, **kw):
        raise ConnectionRefusedError("no panel")

    monkeypatch.setattr(cli_mod.urllib.request, "urlopen", _refused)
    assert cli_mod.cmd_health() == 1
    assert "panel: FAILED" in capsys.readouterr().err


def test_health_inactive_service_exits_1(
    db, fake_settings, monkeypatch, capsys
):
    states = {s: "active" for s in (*cli_mod.PANEL_SERVICES, cli_mod.WG_SERVICE)}
    states["xray"] = "inactive"
    monkeypatch.setattr(cli_mod, "_run_systemctl", _systemctl_stub(states))
    monkeypatch.setattr(
        cli_mod.urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHealthResponse(),
    )
    assert cli_mod.cmd_health() == 1
    assert "xray: inactive" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Entry point — dispatch + argparse behavior
# ---------------------------------------------------------------------------

def test_main_dispatches_each_command(monkeypatch, fake_settings, capsys, db):
    monkeypatch.setattr(cli_mod, "_run_systemctl",
                        _systemctl_stub({s: "active" for s in
                                         (*cli_mod.PANEL_SERVICES,
                                          cli_mod.WG_SERVICE)}))
    monkeypatch.setattr(cli_mod, "LOGIN_FILE", Path("/nonexistent/login.txt"))
    monkeypatch.setattr(
        cli_mod.urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeHealthResponse(),
    )
    assert cli_mod.main(["info"]) == 0
    assert cli_mod.main(["status"]) == 0
    assert cli_mod.main(["restart"]) == 0
    assert cli_mod.main(["users"]) == 0
    assert cli_mod.main(["inbounds"]) == 0
    assert cli_mod.main(["health"]) == 0
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
