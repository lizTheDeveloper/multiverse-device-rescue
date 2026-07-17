import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "smc_reset_check")


def _fake_run_apple_silicon():
    """Mock subprocess for Apple Silicon Mac."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "sysctl" in cmd or (isinstance(cmd, list) and "sysctl" in cmd[0]):
            result.stdout = "Apple M2 Pro\n"
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_intel_healthy():
    """Mock subprocess for healthy Intel Mac."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "sysctl" in cmd or (isinstance(cmd, list) and "sysctl" in cmd[0]):
            result.stdout = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz\n"
        elif "pmset" in cmd and "-g" in cmd and "batt" in cmd:
            result.stdout = """Now drawing from 'AC Power':
 -InternalBattery-0	95%; charging; 2:15 remaining present: true
"""
        elif "pmset" in cmd and "-g" in cmd and "therm" in cmd:
            result.stdout = """Thermal Warning Level: 0
CPU Speed Limit: 100%
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      System Power Settings:
      AC Adapter Information:
        Connected: Yes
        Wattage: 96
      Fan Information:
        CPU Fan:
          Current Speed: 3000 RPM
        System Fan:
          Current Speed: 2800 RPM
"""
        return result
    return fake_run


def _fake_run_intel_battery_not_charging():
    """Mock subprocess for Intel Mac with battery not charging."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "sysctl" in cmd or (isinstance(cmd, list) and "sysctl" in cmd[0]):
            result.stdout = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz\n"
        elif "pmset" in cmd and "-g" in cmd and "batt" in cmd:
            result.stdout = """Now drawing from 'AC Power':
 -InternalBattery-0	75%; not charging; 0:00 remaining present: true
"""
        elif "pmset" in cmd and "-g" in cmd and "therm" in cmd:
            result.stdout = """Thermal Warning Level: 0
CPU Speed Limit: 100%
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      Fan Information:
        CPU Fan:
          Current Speed: 2000 RPM
        System Fan:
          Current Speed: 1800 RPM
"""
        return result
    return fake_run


def _fake_run_intel_thermal_throttling():
    """Mock subprocess for Intel Mac with thermal throttling."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "sysctl" in cmd or (isinstance(cmd, list) and "sysctl" in cmd[0]):
            result.stdout = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz\n"
        elif "pmset" in cmd and "-g" in cmd and "batt" in cmd:
            result.stdout = """Now drawing from 'AC Power':
 -InternalBattery-0	90%; charging; 1:30 remaining present: true
"""
        elif "pmset" in cmd and "-g" in cmd and "therm" in cmd:
            result.stdout = """Thermal Warning Level: 2
CPU Speed Limit: 75%
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      Fan Information:
        CPU Fan:
          Current Speed: 5500 RPM
        System Fan:
          Current Speed: 5200 RPM
"""
        return result
    return fake_run


def _fake_run_intel_fans_at_max():
    """Mock subprocess for Intel Mac with fans at max."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "sysctl" in cmd or (isinstance(cmd, list) and "sysctl" in cmd[0]):
            result.stdout = "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz\n"
        elif "pmset" in cmd and "-g" in cmd and "batt" in cmd:
            result.stdout = """Now drawing from 'AC Power':
 -InternalBattery-0	85%; charging; 2:00 remaining present: true
"""
        elif "pmset" in cmd and "-g" in cmd and "therm" in cmd:
            result.stdout = """Thermal Warning Level: 0
CPU Speed Limit: 100%
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      Fan Information:
        CPU Fan:
          Current Speed: 7000 RPM
        System Fan:
          Current Speed: 6800 RPM
"""
        return result
    return fake_run


def test_smc_reset_check_discovered():
    mod = _get_module()
    assert mod.name == "smc_reset_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_smc_reset_check_apple_silicon():
    """Test detection of Apple Silicon Mac."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "apple_silicon" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_smc_reset_check_intel_healthy():
    """Test healthy Intel Mac with no SMC issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_smc_reset_check_battery_not_charging():
    """Test Intel Mac with battery not charging."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_battery_not_charging()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "battery_not_charging" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_smc_reset_check_thermal_throttling():
    """Test Intel Mac with thermal throttling."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_thermal_throttling()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "thermal_throttling" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_smc_reset_check_fans_at_max():
    """Test Intel Mac with fans running at maximum."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_fans_at_max()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "fans_at_max" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_smc_reset_check_fix_apple_silicon():
    """Test fix recommendation for Apple Silicon."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("restart" in a.description.lower() for a in fix.actions)


def test_smc_reset_check_fix_battery_not_charging():
    """Test fix recommendation for battery not charging."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_battery_not_charging()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("battery" in a.description.lower() for a in fix.actions)


def test_smc_reset_check_fix_thermal_throttling():
    """Test fix recommendation for thermal throttling."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_thermal_throttling()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("thermal" in a.description.lower() for a in fix.actions)


def test_smc_reset_check_fix_fans_at_max():
    """Test fix recommendation for fans at maximum."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_fans_at_max()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("fan" in a.description.lower() for a in fix.actions)


def test_smc_reset_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
