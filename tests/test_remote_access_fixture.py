"""The desktop app's removal-warning tests read the engine's real TeamViewer
finding from a fixture. This keeps the fixture in step with the module and
its walkthrough, so those tests always run against the real text."""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_remote_access_fixture_is_current():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "remote_access_fixture.py"), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_fixture_carries_the_warning_and_the_safety_note():
    row = json.loads((REPO_ROOT / "desktop" / "test" / "fixtures" / "remote-access-finding.json").read_text(encoding="utf-8"))
    assert row["name"] == "win_remote_access_audit"
    assert "removing it can alert them" in row["finding"]["description"]
    assert "removing it can alert them" in row["finding"]["remediation"]["safety_note"]
