"""Shared validated-atomic config writer (Phase 5, item 7).

``app.xray.write_and_validate`` and ``app.singbox.write_and_validate``
were near-identical (~80 lines each: temp file -> structural
validation -> binary check -> atomic rename). Both are thin wrappers
around :func:`write_and_validate_config` now; the only differences
are the validator, the binary, the check command and the name in
error messages.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

__all__ = ["write_and_validate_config"]


def write_and_validate_config(
    cfg: dict,
    path: str | Path,
    *,
    binary: str,
    name: str,
    check_label: str,
    check_cmd: Callable[[str, str], list[str]],
    validate: Callable[[dict], tuple[bool, list[str]]],
    timeout: int = 10,
) -> tuple[bool, list[str]]:
    """Write ``cfg`` to ``path`` after validation, atomically.

    Writes ``path + ".tmp.json"``, runs the structural ``validate``
    first, then the binary check (``check_cmd(binary, tmp)``) when
    the binary exists (``timeout`` seconds), and atomically renames
    the temp file into place only on success — a rejected config
    never replaces the live one. When the binary is absent (panel
    not installed yet, or this machine is not the server) only the
    JSON structure is validated and the file is still written,
    returning ``(True, ["binary not present — JSON validated
    only"])``. Never raises for a missing binary, a failed
    validation or a bad path: those come back as ``(False, errors)``.
    """
    target = Path(path)
    tmp = Path(str(target) + ".tmp.json")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError) as exc:
        return False, [f"cannot write temp config {tmp}: {exc}"]

    ok, errors = validate(cfg)
    if not ok:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, errors

    binary_path = binary
    if not (os.path.isfile(binary_path) and os.access(binary_path, os.X_OK)):
        resolved = shutil.which(binary)
        binary_path = resolved or ""
    if not binary_path:
        try:
            os.replace(tmp, target)
        except OSError as exc:
            return False, [f"cannot move temp config into place: {exc}"]
        return True, ["binary not present — JSON validated only"]

    try:
        proc = subprocess.run(
            check_cmd(binary_path, str(tmp)),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, [f"{name} validation timed out after {timeout}s"]
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False, [f"could not run {name} binary: {exc}"]

    if proc.returncode == 0:
        try:
            os.replace(tmp, target)
        except OSError as exc:
            return False, [f"cannot move temp config into place: {exc}"]
        return True, []

    detail = (proc.stderr or proc.stdout or "").strip()
    lines = detail.splitlines()[-10:] if detail else []
    try:
        tmp.unlink(missing_ok=True)
    except OSError:
        pass
    message = f"{name} {check_label} failed (exit {proc.returncode})"
    if lines:
        message += ": " + " | ".join(line.strip() for line in lines if line.strip())
    return False, [message]
