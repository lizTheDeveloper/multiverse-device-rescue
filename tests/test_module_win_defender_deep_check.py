import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_defender_deep_check")


def _fake_run(prefs_dict=None, status_dict=None):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Get-MpPreference command
        if "Get-MpPreference" in cmd_str:
            if prefs_dict:
                result.stdout = json.dumps(prefs_dict)
            else:
                result.stdout = "{}"

        # Get-MpComputerStatus command
        elif "Get-MpComputerStatus" in cmd_str:
            if status_dict:
                result.stdout = json.dumps(status_dict)
            else:
                result.stdout = "{}"

        return result

    return fake_run


# Healthy baseline configuration
HEALTHY_PREFS = {
    "DisableRealtimeMonitoring": False,
    "MAPSReporting": 2,
    "DisableTamperProtection": False,
    "PUAProtection": 1,
    "EnableControlledFolderAccess": 1,
    "ExclusionPath": ["C:\\Windows\\Temp"],
    "ExclusionExtension": [".tmp"],
    "ExclusionProcess": [],
}

HEALTHY_STATUS = {
    "FullScanEndTime": (datetime.now() - timedelta(days=7)).isoformat(),
}


def test_win_defender_deep_check_discovered():
    mod = _get_module()
    assert mod.name == "win_defender_deep_check"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_defender_deep_check_healthy():
    """Test when all checks pass."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_PREFS, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    # Should have INFO finding for all_passed
    assert result.has_issues
    assert any(f.data.get("check") == "all_passed" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_defender_deep_check_realtime_disabled():
    """Test detection of disabled real-time protection (CRITICAL)."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, DisableRealtimeMonitoring=True)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.data.get("check") == "realtime_disabled"]
    assert len(critical) > 0
    assert critical[0].severity == Severity.CRITICAL


def test_win_defender_deep_check_cloud_protection_off():
    """Test detection of disabled cloud protection (WARNING)."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, MAPSReporting=0)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.data.get("check") == "cloud_protection_off"]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING


def test_win_defender_deep_check_tamper_protection_disabled():
    """Test detection of disabled tamper protection (WARNING)."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, DisableTamperProtection=True)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.data.get("check") == "tamper_protection_disabled"]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING


def test_win_defender_deep_check_excessive_exclusions():
    """Test detection of excessive scan exclusions (WARNING)."""
    mod = _get_module()
    prefs = dict(
        HEALTHY_PREFS,
        ExclusionPath=[f"C:\\Exclude{i}" for i in range(8)],
        ExclusionExtension=[f".ext{i}" for i in range(4)],
    )
    # Total exclusions: 8 + 4 = 12 > 10
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.data.get("check") == "excessive_exclusions"]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING
    assert warning[0].data.get("exclusion_count") == 12


def test_win_defender_deep_check_pua_protection_disabled():
    """Test detection of disabled PUA protection (WARNING)."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, PUAProtection=0)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.data.get("check") == "pua_protection_disabled"]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING


def test_win_defender_deep_check_stale_full_scan():
    """Test detection of stale full scan (WARNING if >30 days)."""
    mod = _get_module()
    old_scan = (datetime.now() - timedelta(days=45)).isoformat()
    status = {"FullScanEndTime": old_scan}
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_PREFS, status)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.data.get("check") == "stale_full_scan"]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING


def test_win_defender_deep_check_recent_full_scan():
    """Test that recent full scan doesn't trigger warning."""
    mod = _get_module()
    recent_scan = (datetime.now() - timedelta(days=10)).isoformat()
    status = {"FullScanEndTime": recent_scan}
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_PREFS, status)):
        result = mod.check(_make_profile())
    # Should only have INFO for all_passed
    stale = [f for f in result.findings if f.data.get("check") == "stale_full_scan"]
    assert len(stale) == 0


def test_win_defender_deep_check_controlled_folder_access_disabled():
    """Test detection of disabled controlled folder access (WARNING)."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, EnableControlledFolderAccess=0)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [
        f for f in result.findings
        if f.data.get("check") == "controlled_folder_access_disabled"
    ]
    assert len(warning) > 0
    assert warning[0].severity == Severity.WARNING


def test_win_defender_deep_check_multiple_issues():
    """Test detection of multiple issues simultaneously."""
    mod = _get_module()
    prefs = dict(
        HEALTHY_PREFS,
        DisableRealtimeMonitoring=True,
        MAPSReporting=0,
        PUAProtection=0,
    )
    old_scan = (datetime.now() - timedelta(days=60)).isoformat()
    status = {"FullScanEndTime": old_scan}
    with patch("subprocess.run", side_effect=_fake_run(prefs, status)):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "realtime_disabled" in checks
    assert "cloud_protection_off" in checks
    assert "pua_protection_disabled" in checks
    assert "stale_full_scan" in checks


def test_win_defender_deep_check_fix_realtime_disabled():
    """Test fix recommendation for disabled real-time protection."""
    mod = _get_module()
    prefs = dict(HEALTHY_PREFS, DisableRealtimeMonitoring=True)
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    realtime_action = [a for a in fix.actions if "real-time" in a.title.lower()]
    assert len(realtime_action) > 0
    # Should be informational (not auto-enabled)
    assert not realtime_action[0].success


def test_win_defender_deep_check_fix_excessive_exclusions():
    """Test fix recommendation for excessive exclusions."""
    mod = _get_module()
    prefs = dict(
        HEALTHY_PREFS,
        ExclusionPath=[f"C:\\Exclude{i}" for i in range(12)],
    )
    with patch("subprocess.run", side_effect=_fake_run(prefs, HEALTHY_STATUS)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    exclusion_action = [a for a in fix.actions if "exclusion" in a.title.lower()]
    assert len(exclusion_action) > 0


def test_win_defender_deep_check_handles_missing_data():
    """Test graceful handling when prefs/status data is missing."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(None, None)):
        result = mod.check(_make_profile())
    # Should not crash
    assert isinstance(result.findings, list)


def test_win_defender_deep_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("PowerShell not available")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should not crash, findings should be empty
    assert isinstance(result.findings, list)
