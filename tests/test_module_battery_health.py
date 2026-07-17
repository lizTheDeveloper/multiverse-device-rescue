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
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "battery_health")


def _fake_run_healthy_battery():
    """Mock subprocess for healthy battery."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "ioreg" in cmd or (isinstance(cmd, list) and "ioreg" in cmd[0]):
            result.stdout = """
+-o AppleSmartBattery  <class AppleSmartBattery>
    {
    "CycleCount" = 150
    "DesignCapacity" = 6900
    "MaxCapacity" = 6800
    "BatterySerialNumber" = "D123456789"
    "Voltage" = 12400
    "IsCharging" = Yes
    }
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      System Power Settings:
      Current System Profile: Custom
      AC Adapter Information:
      Connected: Yes
      Wattage: 96
      Battery Information:
      Model Information:
      Serial Number: D123456789
      Manufacturer: SMP
      Device Name: bq40z50
      Pack Lot Code: 0000
      PCB Lot Code: 00
      Firmware Version: 0001
      Hardware Version: 0005
      Cell Revision: 0219
      Charge Information:
      Charge remaining (mAh): 6700
      Fully charged: No
      Charging: Yes
      Full charge capacity (mAh): 6800
      Health Information:
      Cycle count: 150
      Condition: Normal
      Battery Installed: Yes
      Amperage (mA): 8900
      Voltage (mV): 12400
"""
        return result
    return fake_run


def _fake_run_high_cycle_battery():
    """Mock subprocess for battery with high cycle count."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "ioreg" in cmd or (isinstance(cmd, list) and "ioreg" in cmd[0]):
            result.stdout = """
+-o AppleSmartBattery  <class AppleSmartBattery>
    {
    "CycleCount" = 1200
    "DesignCapacity" = 6900
    "MaxCapacity" = 5000
    "BatterySerialNumber" = "D987654321"
    "IsCharging" = No
    }
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      Battery Information:
      Health Information:
      Cycle count: 1200
      Condition: Normal
      Battery Installed: Yes
"""
        return result
    return fake_run


def _fake_run_poor_condition_battery():
    """Mock subprocess for battery in poor condition."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "ioreg" in cmd or (isinstance(cmd, list) and "ioreg" in cmd[0]):
            result.stdout = """
+-o AppleSmartBattery  <class AppleSmartBattery>
    {
    "CycleCount" = 800
    "DesignCapacity" = 6900
    "MaxCapacity" = 4000
    "BatterySerialNumber" = "D555666777"
    }
"""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      Battery Information:
      Health Information:
      Cycle count: 800
      Condition: Replace Soon
      Battery Installed: Yes
"""
        return result
    return fake_run


def _fake_run_no_battery():
    """Mock subprocess for desktop with no battery."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "ioreg" in cmd or (isinstance(cmd, list) and "ioreg" in cmd[0]):
            result.stdout = ""
        elif "system_profiler" in cmd or (isinstance(cmd, list) and "system_profiler" in cmd[0]):
            result.stdout = """Power Information:
      AC Adapter Information:
      Connected: Yes
      Wattage: 140
      Battery Information:
      Battery Installed: No
"""
        return result
    return fake_run


def test_battery_health_discovered():
    mod = _get_module()
    assert mod.name == "battery_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_battery_health_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_battery()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_battery_health_high_cycle_count():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_cycle_battery()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "cycle_count" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_battery_health_poor_condition():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_poor_condition_battery()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "battery_condition" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_battery_health_no_battery():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_battery()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data.get("check") == "no_battery"


def test_battery_health_fix_high_cycle_count():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_cycle_battery()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions should be informational (success=True, no modifications)
    assert all(a.success for a in fix.actions)


def test_battery_health_fix_poor_condition():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_poor_condition_battery()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_battery_health_fix_no_battery():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_battery()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("desktop" in a.description.lower() for a in fix.actions)
