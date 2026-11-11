"""Installer tests (v12): extraction tests under real ``set -euo pipefail``.

The v9.2 lesson: installer logic must be tested under the real shell
flags, or SIGPIPE-style bugs hide. These tests extract functions /
blocks from ``install.sh`` and run them in a sandbox (stubbed
commands, temp paths) — the installer itself is never run end to
end here (it needs root, apt and the network).

What is covered:
* ``bash -n install.sh`` (syntax).
* The sudoers block: valid under ``visudo -cf`` and carries every
  command the panel needs (v12 additions included).
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
"""

import re
import subprocess
from pathlib import Path

import pytest

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
    """Content between a ``cat > ... <<EOF`` line and the next ``EOF``."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if start_marker in line)
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "EOF")
    return "\n".join(lines[start + 1 : end])


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


def test_sudoers_block_validates_and_covers_v12():
    text = _install_text()
    block = _extract_heredoc(
        text, "cat > /etc/sudoers.d/sparky-manager <<'EOF'"
    )
    # Every command the panel needs (v12 additions included).
    for needed in (
        "/usr/bin/systemctl restart openvpn-server@sparky-manager",
        "/usr/bin/systemctl restart ocserv",
        "/usr/bin/systemctl restart strongswan",
        "/usr/bin/systemctl start wg-quick@wg0",
        "/usr/bin/systemctl start awg-quick@awg0",
        "/usr/bin/wg show wg0",
        "/usr/bin/awg show awg0",
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
    from app import ikev2, openconnect, openvpn

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
