"""Off macOS the launch agent action must refuse cleanly, with nothing mocked.

Runs on every OS. The other launch agent action tests are skipped on Windows.
"""

import sys

import pytest

from rescue.actions import launch_agent as la


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS supports this action")
def test_unsupported_off_mac_without_mocks(tmp_path):
    p = tmp_path / "com.example.job.plist"
    p.write_bytes(b"x")
    d = la.disable(str(p))
    assert d["status"] == "unsupported" and d["error"] == "unsupported_platform"
    assert la.NOT_SUPPORTED in d["message"]
    assert p.exists()
    assert la.restore("20260101T000000Z-x")["status"] == "unsupported"
