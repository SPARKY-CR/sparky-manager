"""Apply a rendered WireGuard / AmneziaWG server config safely.

Why this module exists
-----------------------
The old code wrote the new ``wg0.conf`` and ran ``systemctl restart
wg-quick@wg0``, surfacing only systemctl's generic message ("the
control process exited with error code"). The real error — wg-quick's
own stderr — goes to the systemd journal and was lost, which is why
a failed rebuild could not be debugged from the panel at all.

This module makes the apply step both robust and diagnosable:

1. **Structural validation first.** The candidate config is parsed
   and checked (32-byte base64 keys, valid CIDRs, valid port) before
   anything is written. A bad render fails early with a message that
   names the problem.
2. **`wg-quick strip` second.** ``wg-quick strip`` removes the
   wg-quick-only keys (Address, DNS, MTU, hooks) and prints the
   stripped config; a failure here means wg-quick itself rejects
   the file, and its output is returned.
3. **Live reload when the interface is already up.** ``wg syncconf``
   parses the whole stripped config *before* touching the interface
   (atomic on parse error) and applies only the diffs — no dropped
   sessions. The live file is replaced only *after* syncconf
   succeeds, so a rejected config never lands on disk.
4. **Start when the interface is absent.** The file is replaced
   first (``wg-quick up`` reads it), then ``systemctl start`` runs;
   on failure the previous file is restored and the journal tail
   (``journalctl -u <unit>``) is included in the error.
5. **Every failure carries the underlying output.** The returned
   ``detail`` always includes the failing command's stdout/stderr
   (and the journal tail on the systemd path), redacted by the
   caller's ``redact`` function — the panel never again reports a
   bare "control process exited".

One hazard removed at the source: a ``DNS = ...`` line in the
*server* config makes ``wg-quick up`` fail hard on any system
without a ``resolvconf`` provider (``resolvconf: command not found``,
exit 127, and the ``set -e`` trap deletes the half-built interface)
while buying nothing — the line only changes the *server's own*
resolver, it is never pushed to clients. The server render no
longer emits it (``render_wg_config(..., dns="")``); the validator
here rejects a DNS line in a server config unless the caller
explicitly allows it. Client ``.conf`` files still carry DNS — that
is where it belongs.

``run`` is an injectable callable ``run(argv, timeout=...) ->
(rc, stdout, stderr)``: the panel passes its sudo-wrapped runner,
tests pass a runner over stub binaries. ``journal`` is an optional
callable ``journal(unit, lines=...) -> str`` for the systemd
journal tail; without it the error just lacks the journal part.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

__all__ = [
    "ApplyResult",
    "apply_config",
    "interface_is_up",
    "strip_config",
    "validate_config_text",
]

# Keys wg-quick strips (wg-quick-specific [Interface] keys that the
# `wg` tool itself does not understand). `wg-quick strip` removes
# exactly these and prints the rest.
_STRIP_KEYS = {
    "address",
    "dns",
    "mtu",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
}

# Keys a plain WireGuard [Interface] may carry.
_WG_INTERFACE_KEYS = {
    "privatekey",
    "listenport",
    "fwmark",
    *(_STRIP_KEYS),
}

# AmneziaWG adds obfuscation fields to [Interface] (see
# app/amneziawg.py). They must match on server and client for the
# S/H/HeaderProtectionKey group; the validator only checks they are
# syntactically present, not their values.
_AWG_INTERFACE_KEYS = {
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "headerprotectionkey",
    "contentpaddingaddition",
    "randomtrailers",
    "disablecookies",
    "tcptimer",
    "udptimer",
    "tcpacktimeout",
    "udpacktimeout",
    "handshakejitter",
    "jittertime",
    "jittertime2",
}

# Keys a [Peer] may carry.
_PEER_KEYS = {
    "publickey",
    "allowedips",
    "presharedkey",
    "endpoint",
    "persistentkeepalive",
}

RunFn = Callable[..., tuple[int, str, str]]
JournalFn = Callable[..., str]
RedactFn = Callable[[str], str]


@dataclass
class ApplyResult:
    """Outcome of :func:`apply_config`.

    ``ok`` False means the live interface / file was left untouched
    (or restored). ``method`` is ``"syncconf"`` / ``"start"`` /
    ``"none"``. ``detail`` is the human-readable error, already
    redacted, carrying the failing command's output.
    """

    ok: bool
    method: str = "none"
    detail: str = ""
    journal: str = ""


def _tail(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    return text[-limit:] if len(text) > limit else text


def _b64_32_problem(value: str, what: str) -> Optional[str]:
    """None when ``value`` is base64 of exactly 32 bytes, else a message."""
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except Exception:  # noqa: BLE001
        return f"{what} is not valid base64"
    if len(raw) != 32:
        return f"{what} is not a 32-byte key ({len(raw)} bytes)"
    return None


def _cidr_problems(value: str, what: str) -> list[str]:
    problems: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            problems.append(f"{what} has an empty entry")
            continue
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            problems.append(f"{what} has an invalid CIDR: {part!r}")
    return problems


def _parse_sections(content: str) -> list[tuple[str, dict[str, str], int]]:
    """Parse wg config text into ``(section, {key: value}, line_no)``.

    Keys are lowercased; duplicate keys keep the last value. Lines
    that are neither a section header nor ``key = value`` are reported
    as problems by the caller through the returned ``(None, ...)``
    sentinel — here they are collected as a section named ``""``.
    """
    sections: list[tuple[str, dict[str, str], int]] = []
    current: Optional[tuple[str, dict[str, str], int]] = None
    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = (line[1:-1].strip().lower(), {}, lineno)
            sections.append(current)
            continue
        if current is None:
            sections.append(("", {"__bad__": raw_line}, lineno))
            continue
        if "=" not in line:
            current[1].setdefault("__bad__", raw_line)
            continue
        key, _, value = line.partition("=")
        current[1][key.strip().lower()] = value.strip()
    return sections


def validate_config_text(
    content: str,
    *,
    allow_dns: bool = False,
    extra_interface_keys: Sequence[str] = (),
) -> list[str]:
    """Structural validation of a rendered server config.

    Returns a list of problems (empty = valid). Checks: exactly one
    ``[Interface]`` with a valid 32-byte private key, a valid
    Address CIDR and a valid ListenPort; no DNS line (it breaks
    ``wg-quick up`` without a resolvconf provider and does nothing
    for the server); every ``[Peer]`` has a valid public key and
    valid AllowedIPs; no unknown keys (wg-quick / wg would reject
    or ignore them, and the panel only ever generates known keys).
    """
    problems: list[str] = []
    if not content.strip():
        return ["config is empty"]
    sections = _parse_sections(content)
    interfaces = [s for s in sections if s[0] == "interface"]
    peers = [s for s in sections if s[0] == "peer"]
    if not interfaces:
        problems.append("config has no [Interface] section")
    if len(interfaces) > 1:
        problems.append("config has more than one [Interface] section")
    if any(s[0] not in ("interface", "peer") for s in sections):
        problems.append("config has a line outside [Interface]/[Peer]")

    interface_keys = set(_WG_INTERFACE_KEYS) | {
        k.lower() for k in extra_interface_keys
    }
    for _name, keys, lineno in interfaces:
        if "__bad__" in keys:
            problems.append(
                f"[Interface] line {lineno}: unparsable line: {keys['__bad__']!r}"
            )
        private = keys.get("privatekey", "")
        if not private:
            problems.append("[Interface] is missing PrivateKey")
        else:
            problem = _b64_32_problem(private, "[Interface] PrivateKey")
            if problem:
                problems.append(problem)
        address = keys.get("address", "")
        if not address:
            problems.append("[Interface] is missing Address")
        else:
            problems.extend(_cidr_problems(address, "[Interface] Address"))
        port = keys.get("listenport", "")
        if port:
            try:
                port_n = int(port)
            except ValueError:
                problems.append(f"[Interface] ListenPort is not a number: {port!r}")
            else:
                if not 1 <= port_n <= 65535:
                    problems.append(
                        f"[Interface] ListenPort out of range: {port_n}"
                    )
        if "dns" in keys and not allow_dns:
            problems.append(
                "[Interface] DNS must not be set in a server config "
                "(it only changes the server's own resolver and breaks "
                "'wg-quick up' on systems without a resolvconf provider)"
            )
        for key in keys:
            if key in ("__bad__",):
                continue
            if key not in interface_keys:
                problems.append(f"[Interface] unknown key: {key}")

    for _name, keys, lineno in peers:
        if "__bad__" in keys:
            problems.append(
                f"[Peer] line {lineno}: unparsable line: {keys['__bad__']!r}"
            )
        public = keys.get("publickey", "")
        if not public:
            problems.append(f"[Peer] at line {lineno} is missing PublicKey")
        else:
            problem = _b64_32_problem(public, f"[Peer] at line {lineno} PublicKey")
            if problem:
                problems.append(problem)
        allowed = keys.get("allowedips", "")
        if not allowed:
            problems.append(f"[Peer] at line {lineno} is missing AllowedIPs")
        else:
            problems.extend(
                _cidr_problems(allowed, f"[Peer] at line {lineno} AllowedIPs")
            )
        preshared = keys.get("presharedkey", "")
        if preshared:
            problem = _b64_32_problem(
                preshared, f"[Peer] at line {lineno} PresharedKey"
            )
            if problem:
                problems.append(problem)
        for key in keys:
            if key in ("__bad__",):
                continue
            if key not in _PEER_KEYS:
                problems.append(f"[Peer] at line {lineno} unknown key: {key}")
    return problems


def interface_is_up(
    run: RunFn, *, interface: str = "wg0", wg_bin: str = "wg", timeout: int = 15
) -> bool:
    """True when the kernel interface exists (``wg show <iface>`` rc 0)."""
    try:
        rc, _, _ = run([wg_bin, "show", interface], timeout=timeout)
    except Exception:  # noqa: BLE001
        return False
    return rc == 0


def strip_config(
    content: str,
    *,
    wg_quick_bin: str = "wg-quick",
    run: RunFn,
    tmpdir: str | None = None,
    timeout: int = 30,
) -> tuple[Optional[str], str]:
    """Run ``wg-quick strip`` on ``content``; returns ``(stripped, detail)``.

    ``stripped`` is None on failure and ``detail`` carries the
    validator's output. The temp file is removed either way.
    """
    tmp_path: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".wg-strip-", suffix=".conf", dir=tmpdir
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        rc, stdout, stderr = run(
            [wg_quick_bin, "strip", str(tmp_path)], timeout=timeout
        )
        if rc != 0:
            detail = _tail(stderr or stdout) or f"exit {rc}"
            return None, f"{wg_quick_bin} strip failed: {detail}"
        return stdout, ""
    except FileNotFoundError:
        return None, f"{wg_quick_bin} strip failed: command not found: {wg_quick_bin}"
    except OSError as exc:
        return None, f"{wg_quick_bin} strip failed: {exc}"
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def apply_config(
    content: str,
    *,
    config_path: str | Path,
    interface: str = "wg0",
    wg_bin: str = "wg",
    wg_quick_bin: str = "wg-quick",
    unit: str = "wg-quick@wg0",
    run: RunFn,
    journal: Optional[JournalFn] = None,
    redact: RedactFn = lambda text: text,
    allow_dns: bool = False,
    extra_interface_keys: Sequence[str] = (),
    timeout: int = 30,
) -> ApplyResult:
    """Validate and apply a rendered server config (see module docstring).

    Returns :class:`ApplyResult`. On failure the live interface and
    the file on disk are left untouched (or restored), and
    ``detail`` carries the failing command's output plus the journal
    tail when available.
    """
    path = Path(config_path)
    problems = validate_config_text(
        content, allow_dns=allow_dns, extra_interface_keys=extra_interface_keys
    )
    if problems:
        return ApplyResult(
            ok=False,
            method="none",
            detail="wireguard config validation failed: "
            + redact("; ".join(problems)),
        )

    stripped, detail = strip_config(
        content,
        wg_quick_bin=wg_quick_bin,
        run=run,
        tmpdir=str(path.parent),
        timeout=timeout,
    )
    if stripped is None:
        return ApplyResult(
            ok=False, method="none", detail=redact(detail)
        )

    def journal_tail() -> str:
        if journal is None:
            return ""
        try:
            tail = journal(unit, lines=50)
        except Exception:  # noqa: BLE001
            return ""
        return _tail(tail or "", 1500)

    # Write the candidate to a temp file in the same directory so the
    # final replace is an atomic rename on the same filesystem.
    tmp_path: Optional[Path] = None
    stripped_path: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=".wg-apply-", suffix=".conf", dir=str(path.parent)
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)

        up = interface_is_up(run, interface=interface, wg_bin=wg_bin)
        if up:
            # Live reload: syncconf parses before applying, so a
            # rejected config leaves the running interface alone.
            sfd, stripped_name = tempfile.mkstemp(
                prefix=".wg-syncconf-", suffix=".conf", dir=str(path.parent)
            )
            stripped_path = Path(stripped_name)
            with os.fdopen(sfd, "w", encoding="utf-8") as handle:
                handle.write(stripped)
            rc, stdout, stderr = run(
                [wg_bin, "syncconf", interface, str(stripped_path)],
                timeout=timeout,
            )
            if rc == 0:
                tmp_path.replace(path)
                tmp_path = None
                return ApplyResult(ok=True, method="syncconf")
            detail = _tail(stderr or stdout) or f"exit {rc}"
            # The interface may have vanished mid-flight; if it is
            # really down now, fall through to the start path.
            if not interface_is_up(run, interface=interface, wg_bin=wg_bin):
                up = False
            else:
                journal_text = journal_tail()
                err = f"{wg_bin} syncconf failed: {detail}"
                if journal_text:
                    err += f"\njournal ({unit}):\n{journal_text}"
                return ApplyResult(
                    ok=False,
                    method="none",
                    detail=redact(err),
                    journal=journal_text,
                )

        # Interface absent: replace the file, then bring it up.
        # On failure restore the previous file (or remove the new
        # one) so no half-applied state is left behind.
        old: Optional[bytes] = None
        had_old = path.exists()
        if had_old:
            try:
                old = path.read_bytes()
            except OSError:
                old = None
        tmp_path.replace(path)
        tmp_path = None
        rc, stdout, stderr = run(
            ["systemctl", "start", unit], timeout=timeout
        )
        if rc == 0:
            return ApplyResult(ok=True, method="start")
        # Restore.
        try:
            if had_old and old is not None:
                path.write_bytes(old)
            elif path.exists():
                path.unlink()
        except OSError:
            pass
        journal_text = journal_tail()
        detail = _tail(stderr or stdout) or f"exit {rc}"
        err = f"systemctl start {unit} failed: {detail}"
        if journal_text:
            err += f"\njournal ({unit}):\n{journal_text}"
        return ApplyResult(
            ok=False, method="none", detail=redact(err), journal=journal_text
        )
    except OSError as exc:
        return ApplyResult(
            ok=False, method="none", detail=redact(f"wireguard apply failed: {exc}")
        )
    finally:
        for candidate in (tmp_path, stripped_path):
            if candidate is not None:
                try:
                    candidate.unlink(missing_ok=True)
                except OSError:
                    pass
