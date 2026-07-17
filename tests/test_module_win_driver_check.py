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


def _pnp_device_ok():
    """No problem devices."""
    return ""


def _pnp_device_problem():
    """One device with problem status."""
    return """[
  {
    "Status": "Error",
    "Class": "USB",
    "FriendlyName": "USB Unknown Device",
    "InstanceId": "USB\\\\VID_1234"
  }
]"""


def _pnp_device_multiple_problems():
    """Multiple devices with problem status."""
    return """[
  {
    "Status": "Error",
    "Class": "USB",
    "FriendlyName": "USB Unknown Device",
    "InstanceId": "USB\\\\VID_1234"
  },
  {
    "Status": "Degraded",
    "Class": "Net",
    "FriendlyName": "Network Adapter",
    "InstanceId": "PCI\\\\VEN_8086"
  }
]"""


def _unsigned_drivers_json():
    """JSON array of unsigned drivers."""
    return '["unsigned_driver1.sys", "unsigned_driver2.sys"]'


def _stopped_drivers_csv():
    """CSV output with stopped drivers."""
    return """"Driver Name","Module Name","Signed","State"
"Nvidia Driver","nvlddmkm.sys","Yes","Running"
"Custom Device","custom.sys","No","Stopped"
"Audio Driver","audio.sys","Yes","Stopped"
"""


def _recent_drivers_json():
    """JSON array of recent drivers."""
    return '["driver1.inf", "driver2.inf", "driver3.inf"]'


def _driverquery_output():
    """Basic driverquery output (with header and data lines)."""
    return """Driver Name                 Associated Module
=============               =================
Nvidia Driver              nvlddmkm.sys
Intel Chipset              iasti.sys
Realtek Audio              Rtaudio.sys
USB Driver                 usbhub.sys
Network Driver             e1g60x64.sys
"""


def _fake_run_all_healthy():
    """All drivers healthy."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            # Check for driverquery first with specific patterns
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                # Stopped drivers check - CSV format
                return _make_subprocess_result('""Driver Name"",""Status""\n"driver.sys","Running"')
            elif "driverquery" in cmd_str:
                # Total driver count
                return _make_subprocess_result(_driverquery_output())
            # Check Get-PnpDevice before other Get-WmiObject commands
            elif "Get-PnpDevice" in cmd_str:
                # No problem devices
                return _make_subprocess_result(_pnp_device_ok())
            elif "Get-WindowsDriver" in cmd_str:
                # No recent drivers
                return _make_subprocess_result("")
            elif "Win32_SystemDriver" in cmd_str:
                # No unsigned drivers
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_problem_devices():
    """Problem devices detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                return _make_subprocess_result('""Driver Name"",""Status""\n"driver.sys","Running"')
            elif "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_output())
            elif "Get-PnpDevice" in cmd_str:
                return _make_subprocess_result(_pnp_device_problem())
            elif "Get-WindowsDriver" in cmd_str:
                return _make_subprocess_result("")
            elif "Win32_SystemDriver" in cmd_str:
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_problem_devices():
    """Multiple problem devices detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                return _make_subprocess_result('""Driver Name"",""Status""\n"driver.sys","Running"')
            elif "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_output())
            elif "Get-PnpDevice" in cmd_str:
                return _make_subprocess_result(_pnp_device_multiple_problems())
            elif "Get-WindowsDriver" in cmd_str:
                return _make_subprocess_result("")
            elif "Win32_SystemDriver" in cmd_str:
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_unsigned_drivers():
    """Unsigned drivers detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                return _make_subprocess_result('""Driver Name"",""Status""\n"driver.sys","Running"')
            elif "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_output())
            elif "Get-PnpDevice" in cmd_str:
                return _make_subprocess_result(_pnp_device_ok())
            elif "Get-WindowsDriver" in cmd_str:
                return _make_subprocess_result("")
            elif "Win32_SystemDriver" in cmd_str:
                return _make_subprocess_result(_unsigned_drivers_json())
        return _make_subprocess_result()
    return fake_run


def _fake_run_stopped_drivers():
    """Stopped drivers detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                return _make_subprocess_result(_stopped_drivers_csv())
            elif "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_output())
            elif "Get-PnpDevice" in cmd_str:
                return _make_subprocess_result(_pnp_device_ok())
            elif "Get-WindowsDriver" in cmd_str:
                return _make_subprocess_result("")
            elif "Win32_SystemDriver" in cmd_str:
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_recent_drivers():
    """Recent drivers detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "driverquery" in cmd_str and "CSV" in cmd_str:
                return _make_subprocess_result('""Driver Name"",""Status""\n"driver.sys","Running"')
            elif "driverquery" in cmd_str:
                return _make_subprocess_result(_driverquery_output())
            elif "Get-PnpDevice" in cmd_str:
                return _make_subprocess_result(_pnp_device_ok())
            elif "Get-WindowsDriver" in cmd_str:
                return _make_subprocess_result(_recent_drivers_json())
            elif "Win32_SystemDriver" in cmd_str:
                return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def test_win_driver_check_discovered():
    mod = _get_module()
    assert mod.name == "win_driver_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_driver_check_all_healthy():
    """All drivers healthy - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO finding
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention healthy in description
    assert any("healthy" in f.description.lower() for f in result.findings)


def test_win_driver_check_problem_device():
    """One problem device detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problem_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for problem device
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    # Should mention the device
    assert any("USB Unknown Device" in f.description for f in critical_findings)


def test_win_driver_check_multiple_problem_devices():
    """Multiple problem devices detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_problem_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for each problem device
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 2
    # Check data consistency
    problem_data = [f for f in result.findings if f.data.get("check") == "problem_device"]
    assert len(problem_data) >= 2


def test_win_driver_check_unsigned_drivers():
    """Unsigned drivers detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unsigned_drivers()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for unsigned drivers
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    # Check data
    unsigned_data = [f for f in result.findings if f.data.get("check") == "unsigned_drivers"]
    assert len(unsigned_data) == 1
    assert unsigned_data[0].data["count"] == 2


def test_win_driver_check_stopped_drivers():
    """Stopped drivers detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stopped_drivers()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for stopped drivers
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    # Check data
    stopped_data = [f for f in result.findings if f.data.get("check") == "stopped_drivers"]
    assert len(stopped_data) == 1
    assert stopped_data[0].data["count"] == 2


def test_win_driver_check_recent_drivers():
    """Recently updated drivers detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_recent_drivers()):
        result = mod.check(_make_profile())
    # Should have INFO for recent drivers
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    # Check data
    recent_data = [f for f in result.findings if f.data.get("check") == "recent_drivers"]
    assert len(recent_data) == 1
    assert recent_data[0].data["count"] == 3


def test_win_driver_check_fix_problem_device():
    """Fix action for problem device."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problem_devices()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE risk level
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
    # Should have action for unsigned drivers
    unsigned_actions = [a for a in fix_result.actions if "unsigned" in a.title.lower()]
    assert len(unsigned_actions) > 0


def test_win_driver_check_fix_stopped_drivers():
    """Fix action for stopped drivers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stopped_drivers()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # Should have action for stopped drivers
    stopped_actions = [a for a in fix_result.actions if "stopped" in a.title.lower()]
    assert len(stopped_actions) > 0


def test_win_driver_check_fix_recent_drivers():
    """Fix action for recently updated drivers."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_recent_drivers()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # Should have action for recent drivers
    recent_actions = [a for a in fix_result.actions if "recent" in a.title.lower()]
    assert len(recent_actions) > 0
