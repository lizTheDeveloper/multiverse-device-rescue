"""crash_report_app_name: real crash report file names seen on macOS 26.3.1."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.crash_reports import crash_report_app_name


@pytest.mark.parametrize(
    "filename, expected",
    [
        # Chrome's crash-reporting helper used to be counted as "chrome" (88
        # "Chrome crashes" in 7 days on a Mac where Chrome itself never crashed).
        ("chrome_crashpad_handler-2026-10-15-101112.ips", "chrome_crashpad_handler"),
        ("browser_crashpad_handler-2026-10-10-090807.ips", "browser_crashpad_handler"),
        ("ExcUserFault_qlmanage-2026-10-12-111213.ips", "ExcUserFault_qlmanage"),
        ("Steam Helper-2026-10-01-010203.ips", "Steam Helper"),
        ("Device Rescue He-2026-10-17-151617.0002.ips", "Device Rescue He"),
        ("JetsamEvent-2026-10-16-121314.ips", "JetsamEvent"),
        # Older underscore layout
        ("Visual_Studio_Code_2026-07-06_001.crash", "Visual_Studio_Code"),
        ("Safari_2024-01-15-123456_MacBook.crash", "Safari"),
        ("weird-name.ips", "weird-name"),
    ],
)
def test_crash_report_app_name(filename, expected):
    assert crash_report_app_name(Path("/tmp") / filename) == expected
