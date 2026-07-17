import sys
import json
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
    return next(m for m in modules if m.name == "mvt_spyware_scan")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "mvt_spyware_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms
    assert Platform.LINUX in mod.platforms


def test_no_backups_no_findings():
    """No findings when no device backups are found."""
    mod = _get_module()
    with patch.object(Path, "exists", return_value=False):
        with patch.object(Path, "is_dir", return_value=False):
            result = mod.check(_make_profile())
    # Should report info that no backups were found, not an error
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_mvt_not_installed_reports_info():
    """When MVT is not installed, report as informational finding."""
    mod = _get_module()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(Path, "iterdir", return_value=[Path("/fake/backup")]):
                with patch("shutil.which", return_value=None):
                    result = mod.check(_make_profile())

    mvt_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_not_installed"
    ]
    assert len(mvt_findings) > 0
    assert mvt_findings[0].severity == Severity.INFO


def test_mvt_scan_with_detection():
    """When MVT finds spyware indicators, report as critical findings."""
    mod = _get_module()

    mvt_output = json.dumps(
        [
            {
                "module": "safari_history",
                "detected": True,
                "indicator": "suspicious-domain.com",
                "matched_indicator": {
                    "type": "domain-name",
                    "value": "suspicious-domain.com",
                },
            }
        ]
    )

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(
                Path, "iterdir", return_value=[Path("/fake/backup/abc123")]
            ):
                with patch("shutil.which", return_value="/usr/local/bin/mvt-ios"):
                    with patch("subprocess.run") as mock_run:
                        mock_result = MagicMock()
                        mock_result.returncode = 0
                        mock_result.stdout = ""
                        mock_run.return_value = mock_result
                        with patch.object(
                            mod,
                            "_parse_mvt_output",
                            return_value=[
                                {
                                    "module": "safari_history",
                                    "indicator": "suspicious-domain.com",
                                    "indicator_type": "domain-name",
                                }
                            ],
                        ):
                            result = mod.check(_make_profile())

    spyware_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_spyware_detected"
    ]
    assert len(spyware_findings) > 0
    assert spyware_findings[0].severity == Severity.CRITICAL


def test_fix_provides_guidance():
    """fix() provides informational guidance for spyware remediation."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="mvt_spyware_scan",
        findings=[
            Finding(
                title="Spyware indicator detected",
                description="Pegasus indicator in safari_history",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "mvt_spyware_detected",
                    "module": "safari_history",
                    "indicator": "suspicious-domain.com",
                },
            ),
        ],
    )

    fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.all_succeeded
    action_text = " ".join(a.description for a in fix.actions).lower()
    assert "factory reset" in action_text or "update" in action_text


def test_windows_reports_wsl_requirement():
    """On Windows, report that MVT requires WSL."""
    mod = _get_module()
    result = mod.check(_make_profile(platform=Platform.WIN32))

    wsl_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_requires_wsl"
    ]
    assert len(wsl_findings) > 0
