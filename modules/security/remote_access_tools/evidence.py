"""Evidence about one remote-access tool: what a person needs to decide whose it is.

Kept apart from the module so each rule is small and testable on its own.

Connection logs are the sensitive part. They hold the other party's remote ID,
their display name, the local user name and session GUIDs. Nothing from a log
leaves these parsers except dates and a count: the parsers return
``(list[date], int)`` and never a string from the file. A line that doesn't
parse is skipped, never guessed, and a file that can't be read (missing,
binary, not a regular file) gives ``None``, which the check reports as
"Couldn't tell", never as "nobody connected".
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from rescue.runtime import load_content_module

_tools = load_content_module("modules/security/remote_access_tools/tools.py", "rescue_remote_access_tools_tools")
Tool = _tools.Tool if _tools is not None else object

LOG_CAP_BYTES = 1_048_576

_TV_FORMAT = "%d-%m-%Y %H:%M:%S"
_ISO_DATE = re.compile(r"(?<!\d)(\d{4})-(\d{2})-(\d{2})(?!\d)")


@dataclass
class Sighting:
    tool: Tool
    path: str | None = None
    added_on: date | None = None
    lets_in_unattended: bool | None = None
    unattended_via: str | None = None
    running_now: bool | None = None
    last_incoming: date | None = None
    incoming_count: int | None = None
    one_off: bool = False


def parse_teamviewer_incoming(text: str) -> tuple[list[date], int]:
    """TeamViewer's Connections_incoming.txt: tab-separated, one session per line.

    Only the third field (the session's start, ``DD-MM-YYYY HH:MM:SS``) is
    read. The others (remote ID, peer name, user, GUID) are never looked at.
    """
    dates: list[date] = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        try:
            dates.append(datetime.strptime(fields[2].strip(), _TV_FORMAT).date())
        except ValueError:
            continue
    return dates, len(dates)


def parse_anydesk_trace(text: str) -> tuple[list[date], int]:
    """AnyDesk's connection_trace.txt: only lines starting with ``Incoming``
    count, dated by the first ``YYYY-MM-DD`` on the line."""
    dates: list[date] = []
    for line in text.splitlines():
        if not line.lstrip().startswith("Incoming"):
            continue
        m = _ISO_DATE.search(line)
        if m is None:
            continue
        try:
            dates.append(date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError:
            continue
    return dates, len(dates)


PARSERS = {
    "teamviewer_incoming": parse_teamviewer_incoming,
    "anydesk_trace": parse_anydesk_trace,
}


def read_tail(path: Path, cap: int = LOG_CAP_BYTES) -> str | None:
    """The last ``cap`` bytes of a text file, from the first whole line.

    ``None`` when the file is missing, isn't a regular file, can't be read, or
    isn't text (a NUL byte, or not UTF-8): a damaged log is "couldn't tell".
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        start = max(0, st.st_size - cap)
        os.lseek(fd, start, os.SEEK_SET)
        chunks = []
        left = cap
        while left > 0:
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        raw = b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)
    if start > 0:
        # The first line was cut by the seek; drop it rather than misread it.
        nl = raw.find(b"\n")
        raw = raw[nl + 1:] if nl >= 0 else b""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def read_log(path: Path, fmt: str) -> tuple[list[date], int] | None:
    """Dates and count from one log, or None when it couldn't be read."""
    parser = PARSERS.get(fmt)
    if parser is None:
        return None
    text = read_tail(path)
    if text is None:
        return None
    return parser(text)


def date_from_mdls(text: str) -> date | None:
    """``kMDItemDateAdded`` as ``mdls -raw`` prints it (``2026-03-03 10:00:00 +0000``)."""
    value = (text or "").strip()
    if not value or value == "(null)":
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S %z").astimezone().date()
    except ValueError:
        return None


def date_from_install_date(value: str | None) -> date | None:
    """A Windows uninstall entry's ``InstallDate`` (``YYYYMMDD``)."""
    value = (value or "").strip()
    if not re.fullmatch(r"\d{8}", value):
        return None
    try:
        return date(int(value[:4]), int(value[4:6]), int(value[6:]))
    except ValueError:
        return None
