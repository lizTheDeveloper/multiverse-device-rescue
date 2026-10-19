"""Name the program a macOS crash report is about, from its file name.

macOS names reports ``<process>-<YYYY-MM-DD>-<HHMMSS>[.NNNN].ips`` (older
releases: ``<process>_<YYYY-MM-DD>-<HHMMSS>_<host>.crash``). The process name
itself can contain underscores and dashes, so splitting on the first or last
underscore is wrong: ``chrome_crashpad_handler-2026-10-15-101112.ips`` (Chrome's
crash-reporting helper) used to be counted as a crash of "chrome".
"""

from __future__ import annotations

import re
from pathlib import Path

_DATE_SUFFIX = re.compile(r"^(?P<name>.+?)[-_]\d{4}-\d{2}-\d{2}(?:[-_].*)?$")


def crash_report_app_name(crash_file: Path | str) -> str:
    """The process name a crash report file is about."""
    stem = Path(crash_file).name
    for ext in (".ips", ".crash", ".diag", ".hang", ".spin", ".panic"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    match = _DATE_SUFFIX.match(stem)
    return match.group("name") if match else stem
