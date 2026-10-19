"""The desktop app's city-mode tests read every description the monitoring
checks can write from a fixture. This keeps the fixture in step with the
modules, so those tests always run against the real text."""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_monitoring_descriptions_fixture_is_current():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "monitoring_descriptions.py"), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_fixture_has_every_monitoring_module_and_a_real_critical():
    import json

    rows = json.loads((REPO_ROOT / "desktop" / "test" / "fixtures" / "monitoring-descriptions.json").read_text())
    assert {r["module"] for r in rows} == {"stalkerware_scan", "mvt_spyware_scan", "keylogger_indicators"}
    assert any(
        r["code"] == "security.keylogger_indicators.known_keyloggers" and "turn off access" in r["description"]
        for r in rows
    )
