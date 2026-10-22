"""The desktop app's removal-warning tests read the engine's real AnyDesk
finding (remote_access_tools, synthetic evidence) from a fixture. This keeps the fixture in step with the module and
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
    row = json.loads((REPO_ROOT / "desktop" / "test" / "fixtures" / "remote-access-finding.json").read_text())
    assert row["name"] == "remote_access_tools"
    assert row["finding"]["code"] == "security.remote_access_tools.tool_found"
    # The warning comes from safety_scope (by code) and the walkthrough, not the module's own words.
    assert row["finding"]["removal_alert"] is True
    assert "removing it can alert them" in row["finding"]["remediation"]["safety_note"]
    assert "removing it can alert them" not in row["finding"]["description"]
