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
    return next(m for m in modules if m.name == "win_driver_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _powershell_no_problem_devices():
    """No devices with driver errors."""
    return ""


def _powershell_one_problem_device():
    """One device with driver error code 22."""
    return """[
  {
    "Name": "PCI Device",
    "ConfigManagerErrorCode": 22
  }
]"""


def _powershell_multiple_problem_devices():
    """Multiple devices with driver errors."""
    return """[
  {
    "Name": "USB Unknown Device",
    "ConfigManagerErrorCode": 22
  },
  {
    "Name": "Network Adapter",
    "ConfigManagerErrorCode": 28
  },
  {
    "Name": "Graphics Controller",
    "ConfigManagerErrorCode": 10
  }
]"""


def _powershell_device_count_healthy():
    """PowerShell returns count of 45 devices (all healthy)."""
    return """
Count       : 45
"""


def _powershell_device_count_few():
    """PowerShell returns count of 5 devices."""
    return """
Count       : 5
"""


def _driverquery_no_unsigned():
    """driverquery output with no unsigned drivers."""
    return """
Module Name                 Signed
==============              ======
nvlddmkm.sys                Yes
display.sys                 Yes
amdxata.sys                 Yes
"""


def _driverquery_unsigned_drivers():
    """driverquery output with unsigned drivers."""
    return """
Module Name                 Signed
==============              ======
nvlddmkm.sys                Yes
unsigned_driver.sys         No
amdxata.sys                 Yes
custom_device.sys           No
"""


def _fake_run_all_healthy():
    """All drivers healthy - no errors, no unsigned."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            # Check more specific conditions first
            if "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_no_unsigned())
            elif "powershell" in cmd_str and "Measure-Object" in cmd_str:
                return _make_subprocess_result(_powershell_device_count_healthy())
            elif "powershell" in cmd_str and "Where-Object" in cmd_str:
                # No problem devices
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_one_problem_device():
    """One device with driver error."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_no_unsigned())
            elif "powershell" in cmd_str and "Measure-Object" in cmd_str:
                return _make_subprocess_result(_powershell_device_count_few())
            elif "powershell" in cmd_str and "Where-Object" in cmd_str:
                return _make_subprocess_result(_powershell_one_problem_device())
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_problem_devices():
    """Multiple devices with driver errors."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_no_unsigned())
            elif "powershell" in cmd_str and "Measure-Object" in cmd_str:
                return _make_subprocess_result(_powershell_device_count_few())
            elif "powershell" in cmd_str and "Where-Object" in cmd_str:
                return _make_subprocess_result(_powershell_multiple_problem_devices())
        return _make_subprocess_result()
    return fake_run


def _fake_run_unsigned_drivers():
    """Unsigned drivers detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_unsigned_drivers())
            elif "powershell" in cmd_str and "Measure-Object" in cmd_str:
                return _make_subprocess_result(_powershell_device_count_healthy())
            elif "powershell" in cmd_str and "Where-Object" in cmd_str:
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_both_errors_and_unsigned():
    """Both driver errors and unsigned drivers."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_unsigned_drivers())
            elif "powershell" in cmd_str and "Measure-Object" in cmd_str:
                return _make_subprocess_result(_powershell_device_count_few())
            elif "powershell" in cmd_str and "Where-Object" in cmd_str:
                return _make_subprocess_result(_powershell_multiple_problem_devices())
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd[0]:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_win_driver_check_discovered():
    mod = _get_module()
    assert mod.name == "win_driver_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_driver_check_all_healthy():
    """All drivers healthy - no errors, no unsigned."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO finding
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention all drivers healthy
    finding_strs = [f.description for f in result.findings]
    assert any("healthy" in s.lower() for s in finding_strs)


def test_win_driver_check_one_problem_device():
    """One device with driver error."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_one_problem_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for the device error
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    # Should mention the device
    assert any("PCI Device" in f.description for f in warning_findings)


def test_win_driver_check_multiple_problem_devices():
    """Multiple devices with driver errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_problem_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have multiple WARNINGs for each device
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 3  # At least 3 device errors
    # Should mention the devices
    device_names = ["USB Unknown Device", "Network Adapter", "Graphics Controller"]
    for device_name in device_names:
        assert any(device_name in f.description for f in warning_findings)


def test_win_driver_check_unsigned_drivers():
    """Unsigned drivers detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unsigned_drivers()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for unsigned drivers
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    # Should mention unsigned
    assert any("unsigned" in f.description.lower() for f in warning_findings)


def test_win_driver_check_both_errors_and_unsigned():
    """Both driver errors and unsigned drivers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_both_errors_and_unsigned()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNINGs for both errors and unsigned
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_driver_check_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # May return no findings or handle gracefully
    # The module should not crash


def test_win_driver_check_fix_all_healthy():
    """Fix action for healthy drivers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_healthy()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # Actions should be SAFE risk level
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_driver_check_fix_problem_device():
    """Fix action for device with driver error."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_one_problem_device()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_driver_check_fix_unsigned_drivers():
    """Fix action for unsigned drivers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unsigned_drivers()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True
