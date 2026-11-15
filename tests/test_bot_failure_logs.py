"""Bot failure logs: copyable <pre> blocks, .log files when long.

Covers: a short error goes inline in a <pre> block (copyable with
a long press); a long one is sent as a .log file with a short
preview note; systemd's "See systemctl status ..." hint never
appears in bot messages; truncation never cuts mid-line; a failed
file send falls back to a truncated preview with a marker.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import bot as bot_mod
from app import main as main_mod
from app.i18n import t_for
from tests.test_telegram_bot import (
    FakeSender,
    _callback,
    _configure_bot,
    _dispatch,
)

FA = t_for("fa")

# The exact hint systemd appends to a failed `systemctl restart`
# (from the live OpenVPN failure, 2026-11-15).
SYSTEMD_HINT = (
    'See "systemctl status openvpn-server@sparky-manager.service" '
    'and "journalctl -xeu openvpn-server@sparky-manager.service" '
    "for details."
)


@pytest.fixture()
def sender():
    return FakeSender()


@pytest.fixture()
def fake_status(monkeypatch):
    """Stub app.system_status inside the bot (deterministic states)."""
    states = {
        "xray": "running",
        "sing-box": "running",
        "wireguard": "stopped",
        "amneziawg": "running",
        "openvpn": "unknown",
        "openconnect": "running",
        "ikev2": "stopped",
    }
    stub = SimpleNamespace(
        collect_server_status=lambda data_dir: {"services": dict(states)},
    )
    monkeypatch.setattr(bot_mod, "system_status_mod", stub)
    return states


def _ctx(db, sender):
    return bot_mod._Ctx(
        db=db,
        panel=main_mod,
        sender=sender,
        t=FA,
        chat_id=12345,
        now=datetime.now(timezone.utc),
    )


def _long_error(lines=40, width=50):
    return "\n".join(f"line {i:02d} " + "x" * (width - 8) for i in range(lines))


# ---------------------------------------------------------------------------
# The failure-note helper
# ---------------------------------------------------------------------------


def test_short_error_goes_inline_in_pre_block(db):
    sender = FakeSender()
    note = bot_mod._failure_note(
        _ctx(db, sender),
        "FAILED:",
        "restart of xray failed: exit 1\njournal line",
        "xray-restart-error.log",
    )
    assert note.startswith("FAILED:\n<pre>")
    assert note.endswith("</pre>")
    assert "restart of xray failed: exit 1" in note
    assert "journal line" in note
    assert sender.documents == []  # short enough: no file


def test_systemd_hint_stripped_from_error(db):
    sender = FakeSender()
    error = (
        "restart of openvpn-server@sparky-manager failed: "
        "Job for openvpn-server@sparky-manager.service failed.\n"
        f"{SYSTEMD_HINT}\n"
        "journal (openvpn-server@sparky-manager):\n"
        "Nov 15 18:23:54 i openvpn[1]: some real error"
    )
    note = bot_mod._failure_note(
        _ctx(db, sender), "FAILED:", error, "openvpn-restart-error.log"
    )
    assert "systemctl status" not in note
    assert "journalctl -xeu" not in note
    assert "some real error" in note
    assert "Job for openvpn-server@sparky-manager.service failed." in note


def test_error_that_is_only_the_hint_returns_title_only(db):
    sender = FakeSender()
    note = bot_mod._failure_note(
        _ctx(db, sender), "FAILED:", SYSTEMD_HINT, "x.log"
    )
    assert note == "FAILED:"
    assert "<pre>" not in note
    assert sender.documents == []


def test_long_error_sent_as_file_with_preview(db):
    sender = FakeSender()
    error = _long_error()
    assert len(error) > bot_mod._FAILURE_LOG_INLINE_BUDGET
    note = bot_mod._failure_note(
        _ctx(db, sender), "FAILED:", error, "rerender-error.log"
    )
    # The FULL log went as a file.
    assert len(sender.documents) == 1
    chat_id, filename, data = sender.documents[0]
    assert filename == "rerender-error.log"
    assert data.decode("utf-8") == error
    # The note shows only the first lines + the file marker.
    assert "line 00" in note and "line 04" in note
    assert "line 05" not in note
    assert "line 39" not in note
    assert "به صورت فایل ارسال شد" in note


def test_preview_never_cuts_mid_line(db):
    sender = FakeSender()
    # Lines of uneven length: the preview must end exactly at a
    # line boundary, never with a partial line.
    lines = ["short", "a" * 100, "b" * 100, "c" * 100, "d" * 100]
    lines += ["tail-line-" + "y" * 40] * 40  # push over the budget
    error = "\n".join(lines)
    assert len(error) > bot_mod._FAILURE_LOG_INLINE_BUDGET
    note = bot_mod._failure_note(_ctx(db, sender), "FAILED:", error, "x.log")
    assert len(sender.documents) == 1
    pre = note.split("<pre>")[1].split("</pre>")[0]
    assert pre == "\n".join(lines[:5])
    assert pre.endswith("d" * 100)  # a complete line, not a cut one


def test_document_send_failure_falls_back_to_truncated_preview(db):
    sender = FakeSender(document_ok=False)
    note = bot_mod._failure_note(
        _ctx(db, sender), "FAILED:", _long_error(), "x.log"
    )
    # The file was attempted (recorded) but Telegram refused it.
    assert len(sender.documents) == 1
    assert "کوتاه شده است" in note
    assert "به صورت فایل ارسال شد" not in note
    assert "line 00" in note and "line 39" not in note


def test_rerender_note_sends_file_on_long_errors(db):
    sender = FakeSender()
    note = bot_mod._rerender_note(_ctx(db, sender), [_long_error()])
    assert note is not None
    assert note.startswith("⚠️ ")
    assert len(sender.documents) == 1
    assert sender.documents[0][1] == "rerender-error.log"
    assert "به صورت فایل ارسال شد" in note


def test_rerender_note_none_without_errors(db):
    sender = FakeSender()
    assert bot_mod._rerender_note(_ctx(db, sender), []) is None


# ---------------------------------------------------------------------------
# End to end: service restart failure via the bot
# ---------------------------------------------------------------------------


def test_restart_failure_uses_pre_block_and_drops_hint(
    db, sender, fake_status, monkeypatch
):
    _configure_bot(db)
    error = (
        "restart of xray failed: Job for xray.service failed.\n"
        'See "systemctl status xray.service" and '
        '"journalctl -xeu xray.service" for details.\n'
        "journal (xray):\nNov 15 18:23:54 i xray[1]: bad config"
    )
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: error)
    _dispatch(db, _callback("s:rst:xray:ok"), sender)
    text = sender.edited[-1][2]
    assert "ناموفق بود" in text
    assert "<pre>" in text and "</pre>" in text
    assert "bad config" in text
    assert "systemctl status" not in text
    assert "journalctl -xeu" not in text
    assert sender.documents == []


def test_restart_failure_long_error_sends_file(
    db, sender, fake_status, monkeypatch
):
    _configure_bot(db)
    error = _long_error()
    monkeypatch.setattr(main_mod, "_restart_service", lambda name: error)
    _dispatch(db, _callback("s:rst:xray:ok"), sender)
    assert len(sender.documents) == 1
    assert sender.documents[0][1] == "xray-restart-error.log"
    assert sender.documents[0][2].decode("utf-8") == error
    text = sender.edited[-1][2]
    assert "ناموفق بود" in text
    assert "به صورت فایل ارسال شد" in text
    assert "line 39" not in text
