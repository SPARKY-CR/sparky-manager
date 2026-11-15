"""Installer tests (v14): extraction tests under real ``set -euo pipefail``.

The v9.2 lesson: installer logic must be tested under the real shell
flags, or SIGPIPE-style bugs hide. These tests extract functions /
blocks from ``install.sh`` and run them in a sandbox (stubbed
commands, temp paths) — the installer itself is never run end to
end here (it needs root, apt and the network).

What is covered:
* ``bash -n install.sh`` (syntax).
* The sudoers block: valid under ``visudo -cf`` and carries every
  command the panel needs (v14 additions included).
* ``pick_random_web_path`` (v9.2 regression): 12 chars, ``[a-z0-9]``,
  never exits 141 under ``set -euo pipefail``.
* ``generate_vpn_ca``: creates a CA + server cert with the right
  extensions (CA:TRUE on the root, serverAuth + SAN on the server
  cert), is idempotent, and the swanctl copies match.
* ``install_amneziawg``: never kills the install (returns 0 when
  the tools are already there, when the install succeeds, and when
  every apt step fails).
* The minimal server configs in install.sh carry the same required
  directives the panel's own validators require (installer / panel
  consistency).
* ``fix_panel_cert_perms`` (LE-rollback regression): the panel key
  stays group-readable by sparky-manager, or uvicorn dies with
  PermissionError in load_cert_chain; missing files still return 0.
* The Let's Encrypt rollback: backups preserve ownership/mode
  (``cp -p``), every ``.bak`` restore re-applies the permissions,
  the reloadcmd restarts only units that exist yet, and a re-run
  heals a pair an older installer left unreadable.
* Reality SNI reuse (live-feedback fix): a re-install re-reads the
  saved SNI from panel.env (``SPARKY_REALITY_SNI``) and skips the
  prompt; a fresh install still asks; ``--reality-sni`` always wins.
* The login box is trimmed: no protocol lists, logs line or
  subscriptions line — URL, credentials, cert info, reprint hint
  and installed versions only.
"""

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO / "install.sh"


def _install_text() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _extract_function(text: str, name: str) -> str:
    """The shell function ``name() { ... }`` (closing ``}`` at col 0)."""
    lines = text.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.startswith(f"{name}() {{")
    )
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def _extract_heredoc(text: str, start_marker: str) -> str:
    """Content between a ``cat > ... <<EOF`` line and the next ``EOF``.

    Ends with a newline, exactly as ``cat`` writes the heredoc: the
    last content line in install.sh is newline-terminated, and tools
    like visudo reject a file without the terminator (CI failure:
    "missing line terminator at end of file").
    """
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if start_marker in line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "EOF")
    return "\n".join(lines[start + 1 : end]) + "\n"


def _run_bash(script: str, env: dict | None = None, timeout: int = 60):
    import os

    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, env=full_env, timeout=timeout,
    )


def test_installer_syntax():
    proc = subprocess.run(
        ["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def test_sudoers_block_validates_and_covers_v14():
    text = _install_text()
    block = _extract_heredoc(
        text, "cat > /etc/sudoers.d/sparky-manager <<'EOF'"
    )
    # The file cat writes ends with a newline; visudo rejects a file
    # without the terminator ("missing line terminator at end of file").
    assert block.endswith("\n")
    # Every command the panel needs (v14 additions included).
    # NOTE: `wg-quick strip` has NO rule here — it runs unprivileged
    # (see app.wgapply), and the syncconf temp path is a lone
    # trailing `*`: newer sudo rejects wildcards embedded in a
    # command argument ("wildcards are not allowed in command
    # arguments", CI run #24) while the local 1.9.15p5 accepts them,
    # so the embedded form would pass here and fail on CI.
    for needed in (
        "/usr/bin/systemctl restart openvpn-server@sparky-manager",
        "/usr/bin/systemctl restart ocserv",
        "/usr/bin/systemctl restart strongswan",
        "/usr/bin/systemctl start wg-quick@wg0",
        "/usr/bin/systemctl start awg-quick@awg0",
        "/usr/bin/wg show wg0",
        "/usr/bin/awg show awg0",
        "/usr/bin/wg syncconf wg0 *",
        "/usr/bin/awg syncconf awg0 *",
        "/usr/bin/swanctl --load-all",
        "/usr/bin/swanctl --list-conns",
        "/usr/bin/ocserv -t -c *",
        "/usr/bin/journalctl -u wg-quick@wg0 -n 50 --no-pager",
        "/usr/bin/journalctl -u openvpn-server@sparky-manager -n 50 --no-pager",
        "/usr/bin/journalctl -u ocserv -n 50 --no-pager",
        "/usr/bin/journalctl -u strongswan -n 50 --no-pager",
        "/usr/bin/journalctl -u awg-quick@awg0 -n 50 --no-pager",
    ):
        assert needed in block, needed
    # No embedded wildcards anywhere in the rule: every `*` must be
    # a standalone argument (space before, comma/space/end after).
    # This is the guard for the CI-run-#24 lesson — the local
    # visudo would let an embedded `*` through, the CI runner's
    # newer sudo rejects the whole file for it.
    rule = next(
        line for line in block.splitlines() if line.startswith("sparky-manager")
    )
    for index, char in enumerate(rule):
        if char != "*":
            continue
        before = rule[index - 1] if index > 0 else ""
        after = rule[index + 1] if index + 1 < len(rule) else ""
        assert before == " " and after in (",", " ", ""), rule[max(0, index - 40):index + 10]
    # visudo validates the syntax (the file must not break sudo).
    import tempfile

    with tempfile.NamedTemporaryFile(
        "w", suffix=".sudoers", delete=False
    ) as handle:
        handle.write(block)
        path = handle.name
    proc = subprocess.run(
        ["visudo", "-cf", path], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout


def test_pick_random_web_path_no_sigpipe():
    text = _install_text()
    fn = _extract_function(text, "pick_random_web_path")
    script = (
        "set -euo pipefail\n" + fn + "\n"
        "for _ in 1 2 3 4 5; do\n"
        "  p=\"$(pick_random_web_path)\"\n"
        "  [ \"${#p}\" -eq 12 ] || { echo \"bad length: $p\"; exit 1; }\n"
        "  case \"$p\" in *[!a-z0-9]*) echo \"bad chars: $p\"; exit 1;; esac\n"
        "done\n"
        "echo OK\n"
    )
    proc = _run_bash(script)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "OK" in proc.stdout


def test_generate_vpn_ca(tmp_path):
    """The CA function, run with its hardcoded paths redirected to tmp.

    Real openssl (present here), real extensions, idempotent.
    ``chown`` is stubbed (the ``sparky-manager`` group does not exist
    in this VM — on a real install the installer creates it before
    this step) and its calls are asserted instead.
    """
    text = _install_text()
    fn = _extract_function(text, "generate_vpn_ca")
    root = tmp_path / "root"
    fn = fn.replace("/opt/sparky-manager", str(root / "opt" / "sparky-manager"))
    fn = fn.replace("/etc/swanctl", str(root / "etc" / "swanctl"))
    fn = fn.replace("die ", "echo DIE: ")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "chown").write_text(
        "#!/bin/bash\necho \"chown $@\" >> \"$STUB_LOG\"\nexit 0\n"
    )
    (stub_dir / "chown").chmod(0o755)
    import os

    env = {
        "PATH": str(stub_dir) + os.pathsep + os.environ.get("PATH", ""),
        "STUB_LOG": str(tmp_path / "calls.log"),
    }
    script = (
        "set -euo pipefail\n"
        "info() { printf '[test] %s\\n' \"$*\" >&2; }\n"
        + fn
        + "\n"
        "SERVER_IP=203.0.113.10\nDOMAIN=\nCERT_CN=203.0.113.10\n"
        "generate_vpn_ca\n"
        "generate_vpn_ca\n"  # second run must reuse, not regenerate
        "echo OK\n"
    )
    proc = _run_bash(script, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "OK" in proc.stdout
    calls = (tmp_path / "calls.log").read_text()
    assert "chown root:root" in calls  # CA private key + server key
    assert "chown root:sparky-manager" in calls  # certs + CA dir
    ca_dir = root / "opt" / "sparky-manager" / "data" / "ca"
    for name in ("ca-cert.pem", "ca-key.pem", "server-cert.pem", "server-key.pem"):
        assert (ca_dir / name).is_file(), name
    # Extensions: the root is a CA, the server cert has serverAuth +
    # the IP SAN (checked with real openssl).
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-text", "-in", str(ca_dir / "ca-cert.pem")],
        capture_output=True, text=True, timeout=30,
    )
    assert "CA:TRUE" in proc.stdout
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-text", "-in", str(ca_dir / "server-cert.pem")],
        capture_output=True, text=True, timeout=30,
    )
    assert "TLS Web Server Authentication" in proc.stdout
    assert "IP Address:203.0.113.10" in proc.stdout
    assert "CA:FALSE" in proc.stdout
    # The swanctl copies match the data/ca originals.
    for name, dest in (
        ("ca-cert.pem", root / "etc" / "swanctl" / "x509ca" / "ca-cert.pem"),
        ("server-cert.pem", root / "etc" / "swanctl" / "x509" / "server-cert.pem"),
        ("server-key.pem", root / "etc" / "swanctl" / "private" / "server-key.pem"),
    ):
        assert dest.read_bytes() == (ca_dir / name).read_bytes(), name


def test_install_amneziawg_never_kills_install(tmp_path):
    """The best-effort installer: returns 0 in all three cases."""
    text = _install_text()
    fn = _extract_function(text, "install_amneziawg")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    # Stub apt-get / add-apt-repository: log + succeed, or fail on demand.
    (stub_dir / "apt-get").write_text(
        "#!/bin/bash\n"
        "echo \"apt-get $@\" >> \"$STUB_LOG\"\n"
        "[ -f \"$STUB_FAIL\" ] && exit 1\n"
        "exit 0\n"
    )
    (stub_dir / "add-apt-repository").write_text(
        "#!/bin/bash\necho \"add-apt-repository $@\" >> \"$STUB_LOG\"\nexit 0\n"
    )
    (stub_dir / "uname").write_text("#!/bin/bash\necho 6.14.0-44-generic\n")
    for name in ("apt-get", "add-apt-repository", "uname"):
        (stub_dir / name).chmod(0o755)
    import os

    base_env = {
        "PATH": str(stub_dir) + os.pathsep + os.environ.get("PATH", ""),
        "STUB_LOG": str(tmp_path / "calls.log"),
        "STUB_FAIL": str(tmp_path / "fail"),
    }

    def run(extra_env: dict | None = None, with_awg: bool = False):
        env = dict(base_env)
        if extra_env:
            env.update(extra_env)
        if with_awg:
            (stub_dir / "awg-quick").write_text("#!/bin/bash\nexit 0\n")
            (stub_dir / "awg-quick").chmod(0o755)
        elif (stub_dir / "awg-quick").exists():
            (stub_dir / "awg-quick").unlink()
        script = (
            "set -euo pipefail\n"
            "info() { printf '[test] %s\\n' \"$*\" >&2; }\n"
            "warn() { printf '[test] WARN %s\\n' \"$*\" >&2; }\n"
            + fn
            + "\ninstall_amneziawg\necho \"rc=$?\"\n"
        )
        return _run_bash(script, env=env)

    # 1. Tools already installed: no apt call at all.
    proc = run(with_awg=True)
    assert proc.returncode == 0 and "rc=0" in proc.stdout
    assert not (tmp_path / "calls.log").exists()
    # 2. Tools missing, apt succeeds: the PPA is added, install runs.
    proc = run()
    assert proc.returncode == 0 and "rc=0" in proc.stdout
    assert "ppa:amnezia/ppa" in (tmp_path / "calls.log").read_text()
    # 3. Every apt step fails: still rc=0 (best-effort, never dies).
    (tmp_path / "fail").write_text("")
    proc = run()
    assert proc.returncode == 0 and "rc=0" in proc.stdout


def test_minimal_configs_match_panel_validators():
    """The installer's minimal server configs carry the directives
    the panel's own validators require (installer / panel consistency)."""
    from app import ikev2

    text = _install_text()
    # OpenVPN minimal config (heredoc after the openvpn command check).
    # The panel validator would also demand the referenced files
    # exist (they do on the server, not here), so the directive
    # presence is checked instead of running the full validator.
    ovpn = _extract_heredoc(
        text, "cat > /etc/openvpn/server/sparky-manager.conf <<EOF"
    )
    for directive in (
        "port 1194", "proto udp", "dev tun", "ca ", "cert ", "key ",
        "server 10.9.0.0", "auth-user-pass-verify", "cipher AES-256-GCM",
    ):
        assert directive in ovpn, directive
    # ocserv minimal config.
    ocserv = _extract_heredoc(text, "cat > /etc/ocserv/ocserv.conf <<EOF")
    for directive in (
        'auth = "plain[passwd=/etc/ocserv/ocpasswd]"',
        "tcp-port = 4433", "udp-port = 4433",
        "server-cert = ", "server-key = ",
        "ipv4-network = 10.10.10.0", "ipv4-netmask = 255.255.255.0",
    ):
        assert directive in ocserv, directive
    # swanctl minimal config: the panel validator accepts it (with an
    # empty secrets section — no users yet on a fresh install).
    swanctl = _extract_heredoc(text, "cat > /etc/swanctl/swanctl.conf <<EOF")
    assert ikev2.validate_swanctl_config(swanctl) == []
    # AmneziaWG minimal config carries the panel's default params.
    awg = _extract_heredoc(text, "cat > /etc/amnezia/amneziawg/awg0.conf <<EOF")
    for line in ("ListenPort = 51821", "Jc = 4", "S1 = 15", "H1 = 100"):
        assert line in awg, line
    assert "HeaderProtectionKey = ${AWG_PUBLIC_KEY}" not in awg


def test_fix_panel_cert_perms(tmp_path):
    """The cert-permission helper (LE-rollback regression): the panel
    key must stay group-readable by sparky-manager, or uvicorn dies
    with PermissionError in load_cert_chain. ``chown`` is stubbed
    (the ``sparky-manager`` group does not exist in this VM) and its
    calls are asserted instead; ``chmod`` is real.
    """
    text = _install_text()
    fn = _extract_function(text, "fix_panel_cert_perms")
    root = tmp_path / "root"
    fn = fn.replace("/opt/sparky-manager", str(root / "opt" / "sparky-manager"))
    certs = root / "opt" / "sparky-manager" / "certs"
    certs.mkdir(parents=True)
    (certs / "privkey.pem").write_text("KEY")
    (certs / "fullchain.pem").write_text("CERT")
    (certs / "privkey.pem").chmod(0o600)
    (certs / "fullchain.pem").chmod(0o600)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "chown").write_text(
        "#!/bin/bash\necho \"chown $@\" >> \"$STUB_LOG\"\nexit 0\n"
    )
    (stub_dir / "chown").chmod(0o755)
    import os
    import stat

    env = {
        "PATH": str(stub_dir) + os.pathsep + os.environ.get("PATH", ""),
        "STUB_LOG": str(tmp_path / "calls.log"),
    }
    script = (
        "set -euo pipefail\n" + fn + "\n"
        "fix_panel_cert_perms\n"
        "fix_panel_cert_perms\n"  # idempotent
        "echo OK\n"
    )
    proc = _run_bash(script, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "OK" in proc.stdout
    assert stat.S_IMODE((certs / "privkey.pem").stat().st_mode) == 0o640
    assert stat.S_IMODE((certs / "fullchain.pem").stat().st_mode) == 0o644
    calls = (tmp_path / "calls.log").read_text()
    assert "chown root:sparky-manager" in calls
    assert "privkey.pem" in calls and "fullchain.pem" in calls
    # Missing files: still rc 0 (rollback paths must not die).
    (certs / "privkey.pem").unlink()
    (certs / "fullchain.pem").unlink()
    proc = _run_bash(script, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "OK" in proc.stdout


def test_le_rollback_restores_cert_permissions():
    """LE-install rollback regression (first real-server install):
    restoring the .bak pair must re-apply the panel-readable
    permissions, backups must preserve them, the reloadcmd must not
    fail when the units do not exist yet, and a re-run must heal a
    pair an older installer left unreadable."""
    text = _install_text()
    fn = _extract_function(text, "obtain_le_ip_cert")
    lines = fn.splitlines()
    # Backups preserve ownership/mode.
    assert "cp -p /opt/sparky-manager/certs/fullchain.pem" in fn
    assert "cp -p /opt/sparky-manager/certs/privkey.pem" in fn
    # Every .bak restore is followed by the permission fix-up.
    restores = [
        i
        for i, line in enumerate(lines)
        if ".pem.bak" in line and line.strip().startswith("mv ")
    ]
    assert len(restores) == 4, restores  # two rollback paths x two files
    for i in restores:
        window = "\n".join(lines[i : i + 6])
        assert "fix_panel_cert_perms" in window, lines[i]
    # The reloadcmd restarts only units that exist (at install time
    # none do yet); a bare restart would fail --installcert.
    assert "systemctl restart sparky-manager sing-box" not in fn
    assert "list-unit-files" in fn
    # A re-run heals permissions left broken by an older installer.
    main_lines = text.splitlines()
    call = next(
        i
        for i, line in enumerate(main_lines)
        if line.strip() == "obtain_le_ip_cert || true"
    )
    window = "\n".join(main_lines[call : call + 6])
    assert "fix_panel_cert_perms" in window


def _extract_block(text: str, start_marker: str, end_line: str) -> str:
    """Top-level lines from the line containing ``start_marker``
    through the next line that is exactly ``end_line`` (at col 0)."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if start_marker in line)
    end = next(
        i for i in range(start + 1, len(lines)) if lines[i] == end_line
    )
    return "\n".join(lines[start : end + 1])


def _run_sni_block(block: str, root: Path, given: int, preset: str) -> str:
    """Run the extracted SNI-reuse block in bash with ``/opt`` faked
    to ``root``; returns the ``SNI=... SAVED=...`` line it prints."""
    block = block.replace("/opt/sparky-manager", str(root / "opt" / "sparky-manager"))
    script = (
        "set -euo pipefail\n"
        "info() { :; }\n"
        f"REALITY_SNI_GIVEN={given}\n"
        f'REALITY_SNI="{preset}"\n'
        + block
        + "\n"
        'echo "SNI=${REALITY_SNI} SAVED=${SNI_SAVED}"\n'
    )
    proc = _run_bash(script)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    return proc.stdout.strip().splitlines()[-1]


def test_reality_sni_reused_from_panel_env_on_reinstall(tmp_path):
    """A re-install re-reads the saved SNI from panel.env and skips
    the prompt (SNI_SAVED=1); a fresh install keeps the default and
    still asks; --reality-sni always wins over the saved value."""
    text = _install_text()
    block = _extract_block(text, "# Reality SNI: re-used from panel.env", "fi")
    # The block reads the panel.env key (SPARKY_REALITY_SNI), not the
    # install.env key (REALITY_SNI) — they are different files.
    assert "SPARKY_REALITY_SNI=" in block
    assert "install.env" not in block

    root = tmp_path / "root"
    data = root / "opt" / "sparky-manager" / "data"
    data.mkdir(parents=True)
    (data / "panel.env").write_text(
        "SPARKY_PORT='22140'\nSPARKY_REALITY_SNI='example.com'\n"
    )
    # Re-install with a saved value: reused, prompt skipped.
    out = _run_sni_block(block, root, given=0, preset="www.microsoft.com")
    assert out == "SNI=example.com SAVED=1", out
    # --reality-sni wins over the saved value.
    out = _run_sni_block(block, root, given=1, preset="flag.example")
    assert out == "SNI=flag.example SAVED=0", out
    # Fresh install (no panel.env): default kept, prompt still asked.
    (data / "panel.env").unlink()
    out = _run_sni_block(block, root, given=0, preset="www.microsoft.com")
    assert out == "SNI=www.microsoft.com SAVED=0", out


def test_reality_sni_prompt_guarded_by_saved_value():
    """The SNI prompt runs only when no saved value was reused."""
    text = _install_text()
    lines = text.splitlines()
    ask_i = next(
        i
        for i, line in enumerate(lines)
        if line.strip() == 'ask REALITY_SNI "Reality SNI" "$REALITY_SNI"'
    )
    assert lines[ask_i - 1].strip() == 'if [ "$SNI_SAVED" -eq 0 ]; then'
    assert lines[ask_i + 1].strip() == "fi"
    # Both --reality-sni spellings mark the flag as given.
    assert '--reality-sni)      REALITY_SNI="$2"; REALITY_SNI_GIVEN=1; shift 2 ;;' in text
    assert '--reality-sni=*)    REALITY_SNI="${1#--reality-sni=}"; REALITY_SNI_GIVEN=1; shift ;;' in text


def test_login_box_trimmed():
    """The login box keeps URL, credentials, cert info, the reprint
    hint and installed versions — the protocol lists, the logs line
    and the subscriptions line are gone."""
    text = _install_text()
    box = _extract_block(text, "# Login box", '} > "$LOGIN_FILE"')
    for removed in (
        "Default VPN (no domain needed)",
        "More protocols in the panel",
        "Panel logs:",
        "Subscriptions, QR codes",
    ):
        assert removed not in box, removed
    for kept in (
        "Panel:",
        "Username:",
        "Password:",
        "Panel cert fingerprint",
        "Reprint this anytime",
        "Installed versions:",
    ):
        assert kept in box, kept


# ---------------------------------------------------------------------------
# Debug pass (2026-11-15): re-install password trap, stale deployed
# files, uninstaller backing up a live WAL database
# ---------------------------------------------------------------------------


def test_password_prompt_skipped_on_reinstall():
    """A re-install never asks for (or accepts) an admin password: the
    installer cannot touch the DB, so a typed password would be
    printed in the login box without ever working — and would
    overwrite the login file holding the working password."""
    text = _install_text()
    lines = text.splitlines()
    ask_i = next(
        i
        for i, line in enumerate(lines)
        if line.strip() == 'ask_secret ADMIN_PASSWORD "Admin password"'
    )
    assert lines[ask_i - 1].strip() == 'if [ "$REINSTALL" -eq 0 ]; then'
    # The re-install branch warns about an ignored flag and clears
    # the flag value, so it can never reach the resolution below.
    branch = "\n".join(lines[ask_i : ask_i + 8])
    assert "--admin-password is ignored on a re-install" in branch
    assert 'ADMIN_PASSWORD=""' in branch
    # Both --admin-password spellings mark the flag as given.
    assert '--admin-password)   ADMIN_PASSWORD="$2"; ADMIN_PASSWORD_GIVEN=1; shift 2 ;;' in text
    assert '--admin-password=*) ADMIN_PASSWORD="${1#--admin-password=}"; ADMIN_PASSWORD_GIVEN=1; shift ;;' in text


def _run_password_block(block: str, reinstall: int, password: str,
                        stored: str) -> str:
    """Run the extracted password-resolution block in bash; returns
    the ``PASS=... KNOWN=...`` line it prints."""
    script = (
        "set -euo pipefail\n"
        "info() { :; }\n"
        f"REINSTALL={reinstall}\n"
        f'ADMIN_PASSWORD="{password}"\n'
        f'ADMIN_PASSWORD_STORED="{stored}"\n'
        + block
        + "\n"
        'echo "PASS=${ADMIN_PASSWORD} KNOWN=${PASSWORD_KNOWN}"\n'
    )
    proc = _run_bash(script)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    return proc.stdout.strip().splitlines()[-1]


def test_password_resolution_reinstall_uses_stored():
    """Re-install + stored password: the stored one wins and is known
    (the login box may print it)."""
    text = _install_text()
    block = _extract_block(text, "PASSWORD_KNOWN=1 means", "fi")
    out = _run_password_block(block, reinstall=1, password="", stored="s3cret")
    assert out == "PASS=s3cret KNOWN=1", out


def test_password_resolution_reinstall_without_stored_is_unknown():
    """Re-install + no stored password: the DB password is unknown —
    a generated one must never be printed as if it worked."""
    text = _install_text()
    block = _extract_block(text, "PASSWORD_KNOWN=1 means", "fi")
    out = _run_password_block(block, reinstall=1, password="", stored="")
    assert out == "PASS= KNOWN=0", out


def test_password_resolution_fresh_install_generates():
    """Fresh install + no password: one is generated and known."""
    text = _install_text()
    block = _extract_block(text, "PASSWORD_KNOWN=1 means", "fi")
    out = _run_password_block(block, reinstall=0, password="", stored="")
    assert out.startswith("PASS=") and out.endswith(" KNOWN=1"), out
    assert len(out.split()[0]) > len("PASS="), out  # non-empty


def test_password_resolution_supplied_password_kept():
    """Fresh install + a supplied password (flag or prompt): kept."""
    text = _install_text()
    block = _extract_block(text, "PASSWORD_KNOWN=1 means", "fi")
    out = _run_password_block(block, reinstall=0, password="typed", stored="")
    assert out == "PASS=typed KNOWN=1", out


def test_login_box_password_lines():
    """The login box says when the password is unchanged (re-install)
    and when it cannot be shown (re-install, no stored password)."""
    text = _install_text()
    box = _extract_block(text, "# Login box", '} > "$LOGIN_FILE"')
    assert "unchanged by this install" in box
    assert "installer cannot show it" in box
    assert "PASSWORD_KNOWN" in box
    assert "REINSTALL" in box


def test_deployed_dirs_cleaned_before_copy():
    """cp -a never deletes files, so the deployed app/scripts/systemd
    dirs are removed before the copy — otherwise a module deleted
    from the repo would linger in /opt and keep being imported."""
    text = _install_text()
    lines = text.splitlines()
    rm_i = next(
        i for i, line in enumerate(lines)
        if line.startswith("rm -rf /opt/sparky-manager/app")
    )
    cp_i = next(
        i for i, line in enumerate(lines)
        if line.startswith('cp -a "${REPO_DIR}/app/."')
    )
    mkdir_i = next(
        i for i, line in enumerate(lines)
        if line.strip() == "mkdir -p /opt/sparky-manager/app"
        and i > rm_i
    )
    assert rm_i < mkdir_i < cp_i
    assert "/opt/sparky-manager/scripts" in lines[rm_i]
    assert "/opt/sparky-manager/systemd" in lines[rm_i]
    # data/ and venv/ are never touched by the cleanup.
    assert "/opt/sparky-manager/data" not in lines[rm_i]
    assert "/opt/sparky-manager/venv" not in lines[rm_i]


def test_uninstaller_stops_services_before_backup():
    """The uninstaller stops the panel BEFORE tarring the data dir:
    a tar of the live dir can catch the SQLite WAL mid-write."""
    text = _install_text()
    fn = _extract_function(text, "uninstall_panel")
    lines = fn.splitlines()
    stop_i = next(
        i for i, line in enumerate(lines)
        if "systemctl stop sparky-manager" in line
    )
    tar_i = next(
        i for i, line in enumerate(lines) if 'tar -czf "$backup_file"' in line
    )
    assert stop_i < tar_i


def test_uninstaller_stops_all_managed_services():
    """Live incident (2026-11-15): a stale ocserv from the old install
    survived `--uninstall` (it stopped only sparky-manager/xray/
    sing-box) and still held TCP 443, so the fresh install's xray
    could not bind 443 and verification failed. The uninstaller now
    stops + disables every service the panel manages, and brings down
    the awg0 interface too (wg0 was already brought down, but its
    unit was never disabled)."""
    text = _install_text()
    fn = _extract_function(text, "uninstall_panel")
    stop_line = next(
        line for line in fn.splitlines() if "systemctl stop " in line
    )
    disable_line = next(
        line for line in fn.splitlines() if "systemctl disable " in line
    )
    for unit in (
        "sparky-manager",
        "xray",
        "sing-box",
        "ocserv",
        "openvpn-server@sparky-manager",
        "strongswan",
        "wg-quick@wg0",
        "awg-quick@awg0",
    ):
        assert unit in stop_line, unit
        assert unit in disable_line, unit
    assert "wg-quick down wg0" in fn
    assert "awg-quick down awg0" in fn


def test_uninstaller_removes_vpn_service_configs():
    """The installer only writes minimal v12 configs when the file
    does NOT exist, so a stale ocserv.conf (old 443 default) would
    survive the wipe and be started again by the fresh install's
    `enable --now` loop. The uninstaller removes the panel-managed
    configs — ocpasswd too (it holds user password hashes)."""
    text = _install_text()
    fn = _extract_function(text, "uninstall_panel")
    for path in (
        "/etc/ocserv/ocserv.conf",
        "/etc/ocserv/ocpasswd",
        "/etc/openvpn/server/sparky-manager.conf",
        "/etc/swanctl/swanctl.conf",
        "/etc/amnezia/amneziawg/awg0.conf",
    ):
        assert path in fn, path
