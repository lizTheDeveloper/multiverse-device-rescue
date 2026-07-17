import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "system_age_check")


def _fake_run_current_hardware():
    """Mock subprocess for current/supported hardware (M2, 2023)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Hardware:
      Model Name: MacBook Pro
      Model Identifier: MacBookPro20,1
      Model Year: 2023
      Serial Number (system): XYZ123456ABC
      Chip: Apple M2 Max
      Total Number of Cores: 12
      Memory: 16 GB
"""
        elif "sw_vers" in cmd or (isinstance(cmd, list) and "sw_vers" in cmd[0]):
            if "-productVersion" in cmd or (isinstance(cmd, list) and "-productVersion" in cmd):
                result.stdout = "15.2\n"
            elif "-buildVersion" in cmd or (isinstance(cmd, list) and "-buildVersion" in cmd):
                result.stdout = "24B2091\n"
        elif "stat" in cmd or (isinstance(cmd, list) and "stat" in cmd[0]):
            result.stdout = ""
        return result
    return fake_run


def _fake_run_vintage_hardware():
    """Mock subprocess for vintage hardware (2017, 9 years old)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Hardware:
      Model Name: MacBook Pro
      Model Identifier: MacBookPro14,1
      Model Year: 2017
      Serial Number (system): ABC123456XYZ
      Chip: Intel Core i7
      Total Number of Cores: 4
      Memory: 8 GB
"""
        elif "sw_vers" in cmd or (isinstance(cmd, list) and "sw_vers" in cmd[0]):
            if "-productVersion" in cmd or (isinstance(cmd, list) and "-productVersion" in cmd):
                result.stdout = "13.5\n"
            elif "-buildVersion" in cmd or (isinstance(cmd, list) and "-buildVersion" in cmd):
                result.stdout = "22G74\n"
        elif "stat" in cmd or (isinstance(cmd, list) and "stat" in cmd[0]):
            result.stdout = ""
        return result
    return fake_run


def _fake_run_obsolete_hardware():
    """Mock subprocess for obsolete hardware (pre-2012, >10 years old)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Hardware:
      Model Name: MacBook Pro
      Model Identifier: MacBookPro9,2
      Model Year: 2011
      Serial Number (system): OLD123456789
      Chip: Intel Core i7
      Total Number of Cores: 4
      Memory: 4 GB
"""
        elif "sw_vers" in cmd or (isinstance(cmd, list) and "sw_vers" in cmd[0]):
            if "-productVersion" in cmd or (isinstance(cmd, list) and "-productVersion" in cmd):
                result.stdout = "10.7.5\n"
            elif "-buildVersion" in cmd or (isinstance(cmd, list) and "-buildVersion" in cmd):
                result.stdout = "11G63\n"
        elif "stat" in cmd or (isinstance(cmd, list) and "stat" in cmd[0]):
            result.stdout = ""
        return result
    return fake_run


def _fake_run_old_macos_version():
    """Mock subprocess for current hardware but old macOS version."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Hardware:
      Model Name: MacBook Pro
      Model Identifier: MacBookPro20,1
      Model Year: 2023
      Serial Number (system): XYZ123456ABC
      Chip: Apple M2 Max
      Total Number of Cores: 12
      Memory: 16 GB
"""
        elif "sw_vers" in cmd or (isinstance(cmd, list) and "sw_vers" in cmd[0]):
            if "-productVersion" in cmd or (isinstance(cmd, list) and "-productVersion" in cmd):
                result.stdout = "12.6.9\n"  # 3 major versions behind
            elif "-buildVersion" in cmd or (isinstance(cmd, list) and "-buildVersion" in cmd):
                result.stdout = "21G651\n"
        elif "stat" in cmd or (isinstance(cmd, list) and "stat" in cmd[0]):
            result.stdout = ""
        return result
    return fake_run


def test_system_age_check_discovered():
    mod = _get_module()
    assert mod.name == "system_age_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_system_age_check_current_hardware():
    """Test detection of current/supported hardware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_current_hardware()):
        result = mod.check(_make_profile())

    # Should have findings about hardware status
    assert result.has_issues
    status_findings = [f for f in result.findings if f.data.get("status")]
    assert len(status_findings) > 0

    # Should indicate current/supported status
    current_findings = [f for f in status_findings if f.data.get("status") == "current"]
    assert len(current_findings) > 0
    assert current_findings[0].severity == Severity.INFO
    assert "MacBook Pro" in current_findings[0].title
    assert "2023" in str(current_findings[0].data.get("year"))


def test_system_age_check_vintage_hardware():
    """Test detection of vintage hardware (7-10 years old)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vintage_hardware()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should detect vintage status
    vintage_findings = [f for f in result.findings if f.data.get("status") == "vintage"]
    assert len(vintage_findings) > 0
    assert vintage_findings[0].severity == Severity.WARNING
    assert "vintage" in vintage_findings[0].title.lower()
    assert "2017" in str(vintage_findings[0].data.get("year"))


def test_system_age_check_obsolete_hardware():
    """Test detection of obsolete hardware (>10 years old)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_obsolete_hardware()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should detect obsolete status
    obsolete_findings = [f for f in result.findings if f.data.get("status") == "obsolete"]
    assert len(obsolete_findings) > 0
    assert obsolete_findings[0].severity == Severity.CRITICAL
    assert "obsolete" in obsolete_findings[0].title.lower()
    assert "2011" in str(obsolete_findings[0].data.get("year"))


def test_system_age_check_old_macos_version():
    """Test detection of macOS version lag."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_macos_version()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should detect version lag
    lag_findings = [f for f in result.findings if "major version" in f.title.lower()]
    assert len(lag_findings) > 0
    assert lag_findings[0].severity == Severity.WARNING
    assert any("12" in str(lag_findings[0].data.get("current_version")) for _ in [1])


def test_system_age_check_fix_current_hardware():
    """Test fix actions for current hardware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_current_hardware()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0

    # All actions should be informational (success=True)
    assert all(a.success for a in fix.actions)

    # Should have action about supported lifecycle
    lifecycle_actions = [a for a in fix.actions if "supported" in a.title.lower()]
    assert len(lifecycle_actions) > 0


def test_system_age_check_fix_vintage_hardware():
    """Test fix actions for vintage hardware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vintage_hardware()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)

    # Should mention vintage status
    vintage_actions = [a for a in fix.actions if "vintage" in a.title.lower()]
    assert len(vintage_actions) > 0


def test_system_age_check_fix_obsolete_hardware():
    """Test fix actions for obsolete hardware."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_obsolete_hardware()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)

    # Should mention obsolete status
    obsolete_actions = [a for a in fix.actions if "obsolete" in a.title.lower()]
    assert len(obsolete_actions) > 0


def test_system_age_check_fix_version_lag():
    """Test fix actions for macOS version lag."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_macos_version()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)

    # Should mention upgrade suggestion
    upgrade_actions = [a for a in fix.actions if "upgrade" in a.title.lower()]
    assert len(upgrade_actions) > 0


def test_system_age_check_extracts_model_correctly():
    """Test that model information is correctly extracted."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_current_hardware()):
        result = mod.check(_make_profile())

    # Check that model is extracted
    status_findings = [f for f in result.findings if f.data.get("status")]
    assert len(status_findings) > 0
    assert status_findings[0].data.get("model") == "MacBook Pro"


def test_system_age_check_extracts_serial_correctly():
    """Test that serial number is extracted."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_current_hardware()):
        result = mod.check(_make_profile())

    # Check that serial is extracted
    status_findings = [f for f in result.findings if f.data.get("status")]
    assert len(status_findings) > 0
    assert status_findings[0].data.get("serial") == "XYZ123456ABC"


def test_system_age_check_subprocess_error_handling():
    """Test that module handles subprocess errors gracefully."""
    mod = _get_module()

    def fake_run_error(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    with patch("subprocess.run", side_effect=fake_run_error):
        result = mod.check(_make_profile())

    # Should have error finding
    assert result.has_issues
    assert any("Unable to determine hardware" in f.title for f in result.findings)
