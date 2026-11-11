"""Tests for app.wgapply — the WireGuard / AmneziaWG apply path.

The old code wrote wg0.conf and ran ``systemctl restart wg-quick@wg0``,
surfacing only systemctl's generic message. These tests drive the new
path (validate → ``wg-quick strip`` → live ``wg syncconf`` when the
interface is up → ``systemctl start`` when it is absent, restore on
failure, full output in the error) against stub binaries that log
their argv, so no real wg/systemctl is needed. The real binaries do
not exist in this environment (see the v12 report), so the stub
harness carries the validation.
"""

import os
import subprocess
import textwrap

import pytest

from app import amneziawg, wgapply, wireguard

# A well-formed server config (keys are valid 32-byte base64).
_SERVER_KEY = wireguard.generate_keypair()[0]
_PEER_KEY = wireguard.generate_keypair()[1]


def _good_config() -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {_SERVER_KEY}\n"
        "Address = 10.8.0.1/24\n"
        "ListenPort = 51820\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {_PEER_KEY}\n"
        "AllowedIPs = 10.8.0.2/32\n"
    )


_WG_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env python3
    import os, sys
    d = os.environ["STUB_DIR"]
    open(os.path.join(d, "calls.log"), "a").write(" ".join(sys.argv) + "\\n")
    if sys.argv[1] == "show":
        state = open(os.path.join(d, "state")).read().strip() if os.path.exists(os.path.join(d, "state")) else "down"
        if state == "up":
            print(f"interface: {sys.argv[2]}\\n  public key: abc=")
            sys.exit(0)
        print("Unable to access interface: No such device", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] == "syncconf":
        if os.path.exists(os.path.join(d, "fail_syncconf")):
            print("Invalid key", file=sys.stderr)
            sys.exit(1)
        text = open(sys.argv[3]).read()
        if "PrivateKey" not in text:
            print("Line 1: No private key", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    sys.exit(1)
    '''
)

_WG_QUICK_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env python3
    import os, sys
    d = os.environ["STUB_DIR"]
    open(os.path.join(d, "calls.log"), "a").write(" ".join(sys.argv) + "\\n")
    if sys.argv[1] == "strip":
        text = open(sys.argv[2]).read()
        if "BADKEY" in text:
            print("wg-quick: bad key", file=sys.stderr)
            sys.exit(1)
        drop = {"address", "dns", "mtu", "table", "preup", "postup",
                "predown", "postdown", "saveconfig"}
        out = []
        for line in text.splitlines():
            if "=" in line and line.split("=")[0].strip().lower() in drop:
                continue
            out.append(line)
        print("\\n".join(out))
        sys.exit(0)
    sys.exit(1)
    '''
)

_SYSTEMCTL_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env python3
    import os, sys
    d = os.environ["STUB_DIR"]
    open(os.path.join(d, "calls.log"), "a").write(" ".join(sys.argv) + "\\n")
    if sys.argv[1] == "start":
        if os.path.exists(os.path.join(d, "fail_start")):
            print("Job for wg-quick@wg0.service failed because the control process exited with error code.", file=sys.stderr)
            sys.exit(1)
        open(os.path.join(d, "state"), "w").write("up")
        sys.exit(0)
    sys.exit(1)
    '''
)

_JOURNALCTL_STUB = textwrap.dedent(
    '''\
    #!/usr/bin/env python3
    import os, sys
    d = os.environ["STUB_DIR"]
    open(os.path.join(d, "calls.log"), "a").write(" ".join(sys.argv) + "\\n")
    print("wg-quick[123]: wg0: Unable to access interface: Protocol not supported")
    sys.exit(0)
    '''
)


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    """A stub bin dir (wg/wg-quick/awg/awg-quick/systemctl/journalctl)
    + a runner over it. ``state`` controls whether the interface is up."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    for name, body in (
        ("wg", _WG_STUB),
        ("awg", _WG_STUB),
        ("wg-quick", _WG_QUICK_STUB),
        ("awg-quick", _WG_QUICK_STUB),
        ("systemctl", _SYSTEMCTL_STUB),
        ("journalctl", _JOURNALCTL_STUB),
    ):
        path = stub_dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(stub_dir) + os.pathsep + env.get("PATH", "")
    env["STUB_DIR"] = str(tmp_path)

    def run(argv, timeout=30):
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr

    def journal(unit, lines=50):
        _rc, out, _err = run(["journalctl", "-u", unit, "-n", str(lines), "--no-pager"])
        return out

    def calls():
        log = tmp_path / "calls.log"
        return log.read_text(encoding="utf-8") if log.exists() else ""

    return {
        "dir": tmp_path,
        "run": run,
        "journal": journal,
        "calls": calls,
        "set_state": lambda s: (tmp_path / "state").write_text(s),
        "set_flag": lambda name: (tmp_path / name).write_text(""),
    }


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


def test_validate_accepts_good_config():
    assert wgapply.validate_config_text(_good_config()) == []


def test_validate_rejects_bad_private_key():
    bad = _good_config().replace(_SERVER_KEY, "not-a-key")
    problems = wgapply.validate_config_text(bad)
    assert problems and any("PrivateKey" in p for p in problems)


def test_validate_rejects_bad_allowed_ips():
    bad = _good_config().replace("10.8.0.2/32", "10.8.0.2/33")
    problems = wgapply.validate_config_text(bad)
    assert problems and any("AllowedIPs" in p for p in problems)


def test_validate_rejects_dns_in_server_config():
    bad = _good_config().replace(
        "ListenPort = 51820", "ListenPort = 51820\nDNS = 1.1.1.1"
    )
    problems = wgapply.validate_config_text(bad)
    assert problems and any("DNS" in p for p in problems)
    # Explicitly allowed (client configs carry DNS legitimately).
    assert wgapply.validate_config_text(bad, allow_dns=True) == []


def test_validate_rejects_unknown_key():
    bad = _good_config().replace(
        "ListenPort = 51820", "ListenPort = 51820\nFoo = bar"
    )
    problems = wgapply.validate_config_text(bad)
    assert problems and any("unknown key" in p for p in problems)


def test_server_render_has_no_dns_when_disabled():
    # The panel's server render passes dns="" (the DNS line only
    # changes the server's own resolver and breaks `wg-quick up`
    # without a resolvconf provider); the client render keeps it.
    text = wireguard.render_wg_config(_SERVER_KEY, [], dns="")
    assert "DNS" not in text
    peer = wireguard.render_peer_config(
        _SERVER_KEY, "10.8.0.2/32", _PEER_KEY, "203.0.113.10"
    )
    assert "DNS = 1.1.1.1" in peer


# ---------------------------------------------------------------------------
# Apply: syncconf when up, start when down
# ---------------------------------------------------------------------------


def test_apply_syncconf_when_up(harness, tmp_path):
    harness["set_state"]("up")
    live = tmp_path / "wg0.conf"
    live.write_text("[Interface]\nPrivateKey = old\n", encoding="utf-8")
    result = wgapply.apply_config(
        _good_config(),
        config_path=live,
        run=harness["run"],
        journal=harness["journal"],
    )
    assert result.ok, result.detail
    assert result.method == "syncconf"
    assert live.read_text(encoding="utf-8") == _good_config()
    calls = harness["calls"]()
    assert "wg syncconf wg0" in calls
    assert "systemctl start" not in calls
    assert "wg-quick up" not in calls


def test_apply_start_when_down(harness, tmp_path):
    harness["set_state"]("down")
    live = tmp_path / "wg0.conf"
    result = wgapply.apply_config(
        _good_config(),
        config_path=live,
        run=harness["run"],
        journal=harness["journal"],
    )
    assert result.ok, result.detail
    assert result.method == "start"
    assert live.read_text(encoding="utf-8") == _good_config()
    assert "systemctl start wg-quick@wg0" in harness["calls"]()
    assert "wg syncconf" not in harness["calls"]()


def test_apply_rejects_invalid_config_without_touching_file(harness, tmp_path):
    harness["set_state"]("up")
    live = tmp_path / "wg0.conf"
    live.write_text("ORIGINAL", encoding="utf-8")
    bad = _good_config().replace(_SERVER_KEY, "not-a-key")
    result = wgapply.apply_config(
        bad, config_path=live, run=harness["run"], journal=harness["journal"]
    )
    assert not result.ok
    assert "PrivateKey" in result.detail
    assert live.read_text(encoding="utf-8") == "ORIGINAL"
    assert harness["calls"]() == ""  # no binary was even invoked


def test_apply_syncconf_failure_keeps_old_file(harness, tmp_path):
    harness["set_state"]("up")
    harness["set_flag"]("fail_syncconf")
    live = tmp_path / "wg0.conf"
    live.write_text("ORIGINAL", encoding="utf-8")
    result = wgapply.apply_config(
        _good_config(),
        config_path=live,
        run=harness["run"],
        journal=harness["journal"],
    )
    assert not result.ok
    # The underlying wg error is in the detail — never a bare
    # "control process exited".
    assert "Invalid key" in result.detail
    assert live.read_text(encoding="utf-8") == "ORIGINAL"


def test_apply_start_failure_restores_old_file_and_includes_journal(
    harness, tmp_path
):
    harness["set_state"]("down")
    harness["set_flag"]("fail_start")
    live = tmp_path / "wg0.conf"
    live.write_text("ORIGINAL", encoding="utf-8")
    result = wgapply.apply_config(
        _good_config(),
        config_path=live,
        run=harness["run"],
        journal=harness["journal"],
    )
    assert not result.ok
    assert "control process exited" in result.detail
    assert "Protocol not supported" in result.detail  # journal tail
    assert live.read_text(encoding="utf-8") == "ORIGINAL"


def test_apply_strip_failure_reports_wg_quick_output(harness, tmp_path):
    harness["set_state"]("up")
    live = tmp_path / "wg0.conf"
    live.write_text("ORIGINAL", encoding="utf-8")
    # BADKEY passes the structural validator (it is not a key field)
    # but the stub wg-quick rejects it — the error must surface.
    bad = _good_config().replace("ListenPort = 51820", "ListenPort = 51820\n# BADKEY")
    result = wgapply.apply_config(
        bad, config_path=live, run=harness["run"], journal=harness["journal"]
    )
    assert not result.ok
    assert "wg-quick" in result.detail
    assert live.read_text(encoding="utf-8") == "ORIGINAL"


def test_apply_missing_wg_quick_reports_it(harness, tmp_path, monkeypatch):
    # A PATH with no wg-quick at all: the apply fails with a clear
    # "command not found" instead of a bare systemctl error.
    harness["set_state"]("down")
    env = dict(os.environ)
    env["PATH"] = "/usr/bin:/bin"
    env["STUB_DIR"] = str(tmp_path)

    def run(argv, timeout=30):
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr

    live = tmp_path / "wg0.conf"
    result = wgapply.apply_config(
        _good_config(), config_path=live, run=run, journal=None
    )
    assert not result.ok
    assert "wg-quick" in result.detail
    assert not live.exists()


# ---------------------------------------------------------------------------
# AmneziaWG through the same path
# ---------------------------------------------------------------------------


def test_apply_amneziawg_syncconf_when_up(harness, tmp_path):
    harness["set_state"]("up")
    params = amneziawg.generate_awg_params()
    assert amneziawg.validate_awg_params(params) == []
    content = amneziawg.render_server_config(
        _SERVER_KEY, [{"public_key": _PEER_KEY, "allowed_ips": "10.8.1.2/32"}],
        params=params,
    )
    assert "Jc = " in content and "HeaderProtectionKey = " in content
    live = tmp_path / "awg0.conf"
    result = wgapply.apply_config(
        content,
        config_path=live,
        interface="awg0",
        wg_bin="awg",
        wg_quick_bin="awg-quick",
        unit="awg-quick@awg0",
        run=harness["run"],
        journal=harness["journal"],
        extra_interface_keys=tuple(amneziawg.AWG_INTERFACE_KEYS),
    )
    assert result.ok, result.detail
    assert result.method == "syncconf"
    assert live.read_text(encoding="utf-8") == content
    assert "awg syncconf awg0" in harness["calls"]()


def test_validate_awg_params():
    params = amneziawg.generate_awg_params()
    assert amneziawg.validate_awg_params(params) == []
    bad = dict(params, HeaderProtectionKey="not-base64!!")
    assert amneziawg.validate_awg_params(bad)
    bad = dict(params, H2=params["H1"])  # H1-H4 must not overlap
    assert amneziawg.validate_awg_params(bad)
    bad = dict(params, S1=5)  # < 12 with a header key
    assert amneziawg.validate_awg_params(bad)
    bad = dict(params, Jmin=80, Jmax=70)
    assert amneziawg.validate_awg_params(bad)


def test_vpn_link_round_trip():
    params = amneziawg.generate_awg_params()
    conf = amneziawg.render_peer_config(
        _SERVER_KEY, "10.8.1.2/32", _PEER_KEY, "203.0.113.10", params=params
    )
    link = amneziawg.build_vpn_link(conf)
    assert link.startswith("vpn://")
    assert amneziawg.parse_vpn_link(link) == conf
