import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_battery")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _powershell_battery_healthy():
    """Battery at 85% capacity, AC power."""
    return """[
  {
    "BatteryStatus": 2,
    "DesignCapacity": 52000,
    "FullChargeCapacity": 44200,
    "EstimatedChargeRemaining": 44200
  }
]"""


def _powershell_battery_degraded():
    """Battery at 70% capacity, discharging."""
    return """[
  {
    "BatteryStatus": 1,
    "DesignCapacity": 52000,
    "FullChargeCapacity": 36400,
    "EstimatedChargeRemaining": 18200
  }
]"""


def _powershell_battery_critical():
    """Battery at 40% capacity, discharging."""
    return """[
  {
    "BatteryStatus": 1,
    "DesignCapacity": 52000,
    "FullChargeCapacity": 20800,
    "EstimatedChargeRemaining": 10400
  }
]"""


def _powershell_battery_charging():
    """Battery charging, status = 3."""
    return """[
  {
    "BatteryStatus": 3,
    "DesignCapacity": 52000,
    "FullChargeCapacity": 44200,
    "EstimatedChargeRemaining": 22100
  }
]"""


def _powershell_battery_charging_low():
    """Battery charging (low), status = 5."""
    return """[
  {
    "BatteryStatus": 5,
    "DesignCapacity": 52000,
    "FullChargeCapacity": 44200,
    "EstimatedChargeRemaining": 8840
  }
]"""


def _powershell_no_battery():
    """No battery installed."""
    return ""


def _powershell_single_battery_healthy():
    """Single battery object (not array)."""
    return """{
  "BatteryStatus": 2,
  "DesignCapacity": 52000,
  "FullChargeCapacity": 44200,
  "EstimatedChargeRemaining": 44200
}"""


def _fake_run_healthy():
    """PowerShell returns healthy battery."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_battery_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_degraded():
    """PowerShell returns degraded battery."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_battery_degraded())
        return _make_subprocess_result()
    return fake_run


def _fake_run_critical():
    """PowerShell returns battery at critical capacity."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_battery_critical())
        return _make_subprocess_result()
    return fake_run


def _fake_run_charging():
    """PowerShell returns battery charging."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_battery_charging())
        return _make_subprocess_result()
    return fake_run


def _fake_run_charging_low():
    """PowerShell returns battery charging (low)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_battery_charging_low())
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_battery():
    """PowerShell returns no battery."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_no_battery())
        return _make_subprocess_result()
    return fake_run


def _fake_run_single_battery_healthy():
    """PowerShell returns single battery object."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_single_battery_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_win_battery_discovered():
    mod = _get_module()
    assert mod.name == "win_battery"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_battery_healthy():
    """Battery at 85% capacity - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("healthy" in f.title.lower() for f in result.findings)


def test_win_battery_degraded():
    """Battery at 70% capacity - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_degraded()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about degraded capacity
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("degraded" in f.title.lower() for f in warning_findings)


def test_win_battery_critical():
    """Battery at 40% capacity - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical finding
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "40" in critical_findings[0].description


def test_win_battery_charging():
    """Battery charging (normal) - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_charging()):
        result = mod.check(_make_profile())
    # Charging status (3) is normal, so should show battery health
    assert len(result.findings) > 0


def test_win_battery_charging_low():
    """Battery charging (low), status = 5 - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_charging_low()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about charging issue
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_battery_no_battery():
    """No battery detected (desktop PC) - INFO."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_battery()):
        result = mod.check(_make_profile())
    # Should have INFO finding about no battery
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("no battery" in f.title.lower() for f in result.findings)


def test_win_battery_single_battery_object():
    """Single battery object (not array)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_battery_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_battery_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should have INFO finding about no battery (when WMI fails)
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("no battery" in f.title.lower() for f in result.findings)


def test_win_battery_fix_healthy():
    """Fix action for healthy battery."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_battery_fix_degraded():
    """Fix action for degraded battery."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_degraded()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_battery_fix_critical():
    """Fix action for critical battery."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE and mention replacement
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_battery_capacity_parsing():
    """Battery capacity is correctly parsed and displayed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_degraded()):
        result = mod.check(_make_profile())
    # Should have capacity percentage in findings
    finding_descriptions = [f.description for f in result.findings]
    assert any("70" in s for s in finding_descriptions)


def test_win_battery_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result2 = mod.check(_make_profile())
    # Results should be the same
    assert len(result1.findings) == len(result2.findings)
    if result1.findings and result2.findings:
        assert result1.findings[0].severity == result2.findings[0].severity
