"""Read the macOS Application Firewall's answers from ``socketfilterfw``.

macOS 15 and later no longer keep the firewall's state in
``/Library/Preferences/com.apple.alf.plist`` (on macOS 26 the file does not
exist at all), so ``socketfilterfw`` is the source of truth. Its wording has
changed between releases, for example:

- ``--getglobalstate``: ``Firewall is enabled. (State = 1)``
- ``--getstealthmode``: ``Firewall stealth mode is off`` (macOS 15+) or
  ``Stealth mode disabled`` (older)
- ``--getblockall``: ``Firewall has block all state set to disabled.`` or
  ``Block all DISABLED!``
- ``--getallowsigned``: one line each for built-in and downloaded software,
  ending in ``ENABLED`` or ``DISABLED``

Every parser here returns True (on), False (off) or None (couldn't tell).
Output that is empty or unrecognised is None: "couldn't check", never "off".
These are pure functions; the modules run the commands themselves so the
command catalog and ``--trace`` show them.
"""

from __future__ import annotations

import os
import re

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

_OFF = re.compile(r"\b(disabled|off)\b", re.IGNORECASE)
_ON = re.compile(r"\b(enabled|on)\b", re.IGNORECASE)
_STATE = re.compile(r"\(\s*state\s*=\s*(\d+)\s*\)", re.IGNORECASE)


def _on_off(text: str | None) -> bool | None:
    if not text or not text.strip():
        return None
    if _OFF.search(text):
        return False
    if _ON.search(text):
        return True
    return None


def parse_global_state(stdout: str | None) -> bool | None:
    """``--getglobalstate``: State 0 is off; 1 (on) and 2 (block all) are on."""
    if not stdout:
        return None
    match = _STATE.search(stdout)
    if match:
        return match.group(1) != "0"
    if "blocking" in stdout.lower():
        return True
    return _on_off(stdout)


def parse_stealth_mode(stdout: str | None) -> bool | None:
    """``--getstealthmode``."""
    return _on_off(stdout)


def parse_block_all(stdout: str | None) -> bool | None:
    """``--getblockall``."""
    return _on_off(stdout)


def parse_allow_signed(stdout: str | None) -> bool | None:
    """``--getallowsigned``: True if any kind of signed software is auto-allowed.

    False only when every line it printed says DISABLED.
    """
    states = [_on_off(line) for line in (stdout or "").splitlines()]
    states = [s for s in states if s is not None]
    if not states:
        return None
    return any(states)


_APP_LINE = re.compile(r"^\s*\d+\s*:\s*(.+?)\s*$")
_STATUS = re.compile(r"\((allow|block)[^)]*\)", re.IGNORECASE)


def _app_name(path: str) -> str:
    name = os.path.basename(path.rstrip("/")) or path
    return name[:-4] if name.endswith(".app") else name


def parse_listapps(stdout: str | None) -> list[str] | None:
    """``--listapps``: names of the apps allowed to receive incoming connections.

    macOS prints each app as ``N : /path/to/App.app`` with its status,
    ``(Allow incoming connections)`` or ``(Block incoming connections)``, on
    the next line. Returns None if the output has no app list at all.
    """
    if not stdout or not stdout.strip():
        return None
    allowed: list[str] = []
    saw_list = "number of apps" in stdout.lower()
    pending: str | None = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        app = _APP_LINE.match(line)
        if app:
            saw_list = True
            pending = app.group(1)
            status = _STATUS.search(pending)
            if status:  # status printed on the same line
                pending = pending[: status.start()].strip()
                if status.group(1).lower() == "allow":
                    allowed.append(_app_name(pending))
                pending = None
            continue
        status = _STATUS.search(line)
        if status and pending is not None:
            if status.group(1).lower() == "allow":
                allowed.append(_app_name(pending))
            pending = None
    return allowed if saw_list else None
