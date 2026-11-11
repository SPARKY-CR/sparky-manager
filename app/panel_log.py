"""Panel logging for sparky-manager (v12).

One log file, written by the panel itself (no syslog, no external
service):

* ``<data>/logs/panel.log`` — rotating file (5 MB, 3 backups) plus
  console output to stderr (so the systemd journal keeps a copy).
* Level is INFO by default and changeable from the Settings page
  (``log_level`` setting); it applies at runtime, no restart needed.

Secrets policy: the panel NEVER logs a secret in full. Call sites
log metadata only (tags, ports, counts, exit codes, truncated
hashes). :func:`redact` is a safety net that masks anything that
looks like a credential in a message that is about to be logged
(UUIDs, private keys, passwords, shared secrets, subscription
tokens). Anything the redactor cannot recognise is still only ever
logged through call sites that were written not to pass secrets.
"""

from __future__ import annotations

import hashlib
import logging
import logging.handlers
import re
from pathlib import Path
from typing import Any

__all__ = [
    "LOG_LEVELS",
    "DEFAULT_LEVEL",
    "LOG_FILE_NAME",
    "MAX_BYTES",
    "BACKUP_COUNT",
    "get_log_dir",
    "get_log_path",
    "setup_panel_logging",
    "apply_log_level",
    "current_level",
    "redact",
    "token_fingerprint",
    "read_log_lines",
    "list_log_files",
    "clear_log",
]

LOGGER_NAME = "sparky-manager"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_LEVEL = "INFO"
LOG_FILE_NAME = "panel.log"
MAX_BYTES = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 3

_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ---------------------------------------------------------------------------
# Secret redaction (safety net — call sites must already avoid secrets)
# ---------------------------------------------------------------------------

# A client UUID (vless/vmess/tuic credential) anywhere in a message.
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)
# `label = value` / `label: value` for known secret labels. The value
# is one whitespace-delimited token (keys/passwords never contain
# spaces in this panel).
_SECRET_LABEL_RE = re.compile(
    r"(?i)\b(private[_-]?key|preshared[_-]?key|shared[_-]?secret|"
    r"password|passwd|psk|sub[_-]?token|admin[_-]?password|"
    r"eap[_-]?password|client[_-]?secret)\b(\s*[:=]\s*)\S+"
)
# A token carried in a URL query string.
_TOKEN_QUERY_RE = re.compile(r"([?&]token=)[^&\s\"']+")
# A bare 43-char base64url token (Reality key / WG key without
# padding) or 44-char base64 key with padding — only when it follows
# "key" on the same line, so innocent base64 (share links) is left
# alone.
_KEY_VALUE_RE = re.compile(
    r"(?i)(key\b[^=\n]{0,24}=\s*)[A-Za-z0-9+/=_-]{43,44}(?![A-Za-z0-9+/=_-])"
)


def redact(text: Any) -> str:
    """Mask anything credential-shaped in ``text``.

    UUIDs, secret-labelled values, ``?token=`` query values and
    key-labelled base64 values are replaced with ``<redacted>``.
    Non-string input is stringified first. Never raises.
    """
    try:
        out = str(text)
    except Exception:  # noqa: BLE001
        return "<unprintable>"
    out = _UUID_RE.sub("<redacted>", out)
    out = _SECRET_LABEL_RE.sub(r"\1\2<redacted>", out)
    out = _TOKEN_QUERY_RE.sub(r"\1<redacted>", out)
    out = _KEY_VALUE_RE.sub(r"\1<redacted>", out)
    return out


def token_fingerprint(token: str) -> str:
    """Short SHA-256 fingerprint of a subscription token (first 12 hex).

    Safe to log: it identifies a token in the log without revealing
    it (a 12-hex prefix cannot be reversed into the token).
    """
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Paths / setup
# ---------------------------------------------------------------------------

def _data_dir() -> Path:
    """Panel data dir (``/opt/sparky-manager/data`` in production)."""
    try:
        from app.config import DATA_DIR
    except Exception:  # noqa: BLE001
        return Path("/opt/sparky-manager/data")
    return Path(DATA_DIR)


def get_log_dir(data_dir: Path | str | None = None) -> Path:
    """``<data>/logs`` — created on demand by :func:`setup_panel_logging`."""
    base = Path(data_dir) if data_dir is not None else _data_dir()
    return base / "logs"


def get_log_path(data_dir: Path | str | None = None) -> Path:
    """Full path of the current log file."""
    return get_log_dir(data_dir) / LOG_FILE_NAME


def setup_panel_logging(
    data_dir: Path | str | None = None,
    level: str | None = None,
) -> Path:
    """Configure the ``sparky-manager`` logger (idempotent).

    Adds a rotating file handler (``panel.log``, 5 MB, 3 backups) and
    a console handler (stderr — the systemd journal). Calling it
    twice does not add duplicate handlers. ``level`` defaults to the
    logger's current level (or INFO on first setup), so re-running
    setup (e.g. after :func:`clear_log`) never resets a level the
    admin chose in Settings. Returns the log path.
    """
    log_dir = get_log_dir(data_dir)
    log_path = log_dir / LOG_FILE_NAME
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Read-only / missing home in a test env: console-only logging.
        log_path = None  # type: ignore[assignment]

    logger = logging.getLogger(LOGGER_NAME)
    wanted = _normalize_level(level) if level else current_level()
    if wanted not in LOG_LEVELS:
        wanted = DEFAULT_LEVEL
    logger.setLevel(getattr(logging, wanted))
    logger.propagate = False

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)
    # The file handler follows the log path: if setup is called again
    # with a different directory (tests, a moved data dir), the stale
    # handler is closed and replaced instead of writing to the old file.
    for handler in list(logger.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            if str(getattr(handler, "baseFilename", "")) != str(log_path):
                try:
                    handler.close()
                except Exception:  # noqa: BLE001
                    pass
                logger.removeHandler(handler)
    has_file = any(
        isinstance(h, logging.handlers.RotatingFileHandler)
        for h in logger.handlers
    )
    has_console = any(
        isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.handlers.RotatingFileHandler)
        for h in logger.handlers
    )
    if log_path is not None and not has_file:
        try:
            from logging.handlers import RotatingFileHandler

            handler = RotatingFileHandler(
                log_path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        except OSError:
            log_path = None  # type: ignore[assignment]
    if not has_console:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
    # Handlers follow the logger level (a DEBUG setting must reach
    # the file, not only the console).
    apply_log_level(wanted)
    return log_path if log_path is not None else log_dir / LOG_FILE_NAME


def _normalize_level(level: str) -> str:
    """``level`` upper-cased and validated, else the default."""
    candidate = (level or "").strip().upper()
    return candidate if candidate in LOG_LEVELS else DEFAULT_LEVEL


def apply_log_level(level: str) -> str:
    """Set the level on the panel logger and all its handlers.

    Takes effect immediately (no restart). Returns the level that
    was actually applied.
    """
    wanted = _normalize_level(level)
    numeric = getattr(logging, wanted)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric)
    for handler in logger.handlers:
        try:
            handler.setLevel(numeric)
        except (ValueError, TypeError, AttributeError):
            continue
    return wanted


def current_level() -> str:
    """The panel logger's effective level (as a name)."""
    return logging.getLevelName(logging.getLogger(LOGGER_NAME).level)


# ---------------------------------------------------------------------------
# Reading the log back (the /logs page)
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\[(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\]"
    r"\s+(?P<message>.*)$"
)
_LEVEL_ORDER = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}


def read_log_lines(
    log_path: Path | str | None = None,
    *,
    level: str | None = None,
    query: str | None = None,
    limit: int = 500,
) -> tuple[list[dict[str, str]], int]:
    """Read the current log file, newest first.

    Returns ``(lines, total)`` where each line is ``{"ts", "level",
    "message"}``. ``level`` keeps only entries at that level or
    above; ``query`` keeps only lines containing the (case-insensitive)
    text; ``limit`` caps the returned lines. Lines that do not match
    the log format (e.g. a multi-line traceback continuation) are
    attached to the previous entry's message. A missing file yields
    ``([], 0)`` instead of raising.
    """
    path = Path(log_path) if log_path is not None else get_log_path()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], 0
    min_level = _LEVEL_ORDER.get((level or "").strip().upper(), 0)
    needle = (query or "").strip().lower()
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        match = _LINE_RE.match(raw)
        if match:
            current = {
                "ts": match.group("ts"),
                "level": match.group("level"),
                "message": match.group("message"),
            }
            entries.append(current)
        elif current is not None and raw.strip():
            # Traceback / continuation line: keep it with its entry.
            current["message"] += "\n" + raw
    total = len(entries)
    filtered = [
        entry
        for entry in entries
        if _LEVEL_ORDER.get(entry["level"], 0) >= min_level
        and (not needle or needle in (entry["message"] + entry["ts"]).lower())
    ]
    # Newest first, capped.
    filtered.reverse()
    return filtered[: max(0, int(limit))], total


def list_log_files(
    data_dir: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Log files present on disk (current + rotated), newest first.

    Each entry: ``{"name", "size_bytes", "current": bool}``. Never
    raises — an unreadable directory yields ``[]``.
    """
    log_dir = get_log_dir(data_dir)
    try:
        names = sorted(
            (p for p in log_dir.iterdir() if p.is_file()),
            # Newest first; mtime ties break by name so the current
            # file ("panel.log") always sorts before its rotations.
            key=lambda p: (-p.stat().st_mtime, p.name),
        )
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for path in names:
        if not path.name.startswith(LOG_FILE_NAME):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        out.append(
            {
                "name": path.name,
                "size_bytes": size,
                "current": path.name == LOG_FILE_NAME,
            }
        )
    return out


def clear_log(data_dir: Path | str | None = None) -> bool:
    """Truncate the current log file (rotated backups are kept).

    The file handler's stream is closed first and re-opened after
    the truncate: truncating under an open append-mode stream would
    leave a hole of NUL bytes at the old offset. The logger level
    is preserved (see :func:`setup_panel_logging`). Returns False
    when the file could not be cleared.
    """
    path = get_log_path(data_dir)
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            try:
                handler.flush()
                handler.close()
            except Exception:  # noqa: BLE001
                pass
            logger.removeHandler(handler)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("")
    except OSError:
        return False
    setup_panel_logging(data_dir)
    return True
