"""The desktop app's mission tests read the monitoring checks' real serialized
findings from a fixture (no made-up removal_alert). This keeps the fixture in
step with the modules and the serializer."""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_monitoring_findings_fixture_is_current():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "monitoring_findings_fixture.py"), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_the_stalkerware_finding_carries_no_removal_alert_of_its_own():
    doc = json.loads((REPO_ROOT / "desktop" / "test" / "fixtures" / "monitoring-findings.json").read_text())
    f = doc["stalkerware_scan"]["findings"][0]
    assert f["code"] == "security.stalkerware_scan.monitoring_software_found"
    assert not f.get("removal_alert")
    assert not (f.get("remediation") or {}).get("safety_note")
    assert doc["keylogger_indicators"]["findings"][0]["data"]["apps"] == ["com.example.keys"]
