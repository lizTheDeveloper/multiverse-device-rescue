import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    return next(m for m in modules if m.name == "win_bluetooth_check")


def _make_run_result(
    adapters=None,
    devices=None,
    service_status=None,
    adapter_query_fail=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Handle adapter query failure (but not for device query with PresentOnly)
        if adapter_query_fail and "powershell" in cmd_str and "Get-PnpDevice" in cmd_str and "Bluetooth" in cmd_str and "PresentOnly" not in cmd_str:
            result.returncode = 1
            return result

        # PowerShell: Get Bluetooth adapters or devices
        if "powershell" in cmd_str and "Get-PnpDevice" in cmd_str and "Bluetooth" in cmd_str:
            if "PresentOnly" in cmd_str:  # This is device query
                if devices:
                    result.stdout = json.dumps(devices)
                else:
                    result.stdout = json.dumps([])
            else:  # This is adapter query
                if adapters:
                    result.stdout = json.dumps(adapters)
                else:
                    result.stdout = json.dumps([
                        {
                            "FriendlyName": "Intel Wireless Bluetooth",
                            "Status": "OK",
                            "InstanceId": "PCI\\VEN_8086&DEV_9A2B&SUBSYS_00000000&REV_00\\4&2BA5EDBE&0&00E0"
                        }
                    ])

        # sc query: Get service status
        elif "sc" in cmd and "query" in cmd_str:
            if service_status:
                result.stdout = service_status
            else:
                # Default: service running, automatic startup
                result.stdout = (
                    "SERVICE_NAME: bthserv\n"
                    "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
                    "        STATE              : 4  RUNNING\n"
                    "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                    "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                    "        CHECKPOINT         : 0x0\n"
                    "        WAIT_HINT          : 0x0\n"
                    "        START_TYPE         : 2  AUTO_START\n"
                )

        return result

    return fake_run


def test_win_bluetooth_check_discovered():
    """Test that module is properly discovered."""
    mod = _get_module()
    assert mod.name == "win_bluetooth_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_bluetooth_check_adapter_found():
    """Test detection of working Bluetooth adapter."""
    mod = _get_module()
    adapters = [
        {
            "FriendlyName": "Intel Wireless Bluetooth",
            "Status": "OK",
            "InstanceId": "PCI\\VEN_8086&DEV_9A2B"
        }
    ]
    fake_run = _make_run_result(adapters=adapters)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "adapter_info" for f in result.findings)
    adapter_finding = [f for f in result.findings if f.data.get("check") == "adapter_info"]
    assert adapter_finding[0].severity == Severity.INFO


def test_win_bluetooth_check_adapter_error():
    """Test detection of Bluetooth adapter with error status."""
    mod = _get_module()
    adapters = [
        {
            "FriendlyName": "Intel Wireless Bluetooth",
            "Status": "Error",
            "InstanceId": "PCI\\VEN_8086&DEV_9A2B"
        }
    ]
    fake_run = _make_run_result(adapters=adapters)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "adapter_error" for f in result.findings)
    error_finding = [f for f in result.findings if f.data.get("check") == "adapter_error"]
    assert error_finding[0].severity == Severity.WARNING


def test_win_bluetooth_check_paired_device_error():
    """Test detection of paired device with error status."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "JBL Headphones",
            "Status": "Error"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_error" for f in result.findings)
    device_error = [f for f in result.findings if f.data.get("check") == "device_error"]
    assert device_error[0].severity == Severity.WARNING


def test_win_bluetooth_check_service_stopped():
    """Test detection of stopped Bluetooth service."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: bthserv\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 1  STOPPED\n"
        "        WIN32_EXIT_CODE    : 0  (0x0)\n"
        "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
        "        CHECKPOINT         : 0x0\n"
        "        WAIT_HINT          : 0x0\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_not_running" for f in result.findings)
    service_error = [f for f in result.findings if f.data.get("check") == "service_not_running"]
    assert service_error[0].severity == Severity.WARNING


def test_win_bluetooth_check_service_running():
    """Test when Bluetooth service is running."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: bthserv\n"
        "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
        "        STATE              : 4  RUNNING\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_status" for f in result.findings)
    service_info = [f for f in result.findings if f.data.get("check") == "service_status"]
    assert service_info[0].severity == Severity.INFO


def test_win_bluetooth_check_adapter_query_failed():
    """Test handling of failed adapter query."""
    mod = _get_module()
    fake_run = _make_run_result(adapter_query_fail=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "adapter_query_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "adapter_query_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_bluetooth_check_multiple_adapters():
    """Test detection of multiple Bluetooth adapters."""
    mod = _get_module()
    adapters = [
        {
            "FriendlyName": "Intel Wireless Bluetooth",
            "Status": "OK",
            "InstanceId": "PCI\\VEN_8086"
        },
        {
            "FriendlyName": "Broadcom Bluetooth",
            "Status": "OK",
            "InstanceId": "PCI\\VEN_14E4"
        }
    ]
    fake_run = _make_run_result(adapters=adapters)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    adapter_infos = [f for f in result.findings if f.data.get("check") == "adapter_info"]
    assert len(adapter_infos) == 2


def test_win_bluetooth_check_multiple_devices():
    """Test detection of multiple paired devices."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "JBL Headphones",
            "Status": "OK"
        },
        {
            "FriendlyName": "Logitech Mouse",
            "Status": "OK"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    device_infos = [f for f in result.findings if f.data.get("check") == "paired_device_info"]
    assert len(device_infos) == 2


def test_win_bluetooth_check_fix_adapter_error():
    """Test fix recommendation for adapter error."""
    mod = _get_module()
    adapters = [
        {
            "FriendlyName": "Intel Wireless Bluetooth",
            "Status": "Error",
            "InstanceId": "PCI\\VEN_8086"
        }
    ]
    fake_run = _make_run_result(adapters=adapters)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions
    assert len(fix.actions) > 0
    # Should have action related to adapter error
    assert any("adapter" in a.title.lower() for a in fix.actions)


def test_win_bluetooth_check_fix_device_error():
    """Test fix recommendation for device error."""
    mod = _get_module()
    devices = [
        {
            "FriendlyName": "JBL Headphones",
            "Status": "Error"
        }
    ]
    fake_run = _make_run_result(devices=devices)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    device_actions = [a for a in fix.actions if "device" in a.title.lower() or "pair" in a.title.lower()]
    assert len(device_actions) > 0


def test_win_bluetooth_check_fix_service_error():
    """Test fix recommendation for stopped service."""
    mod = _get_module()
    service_status = (
        "SERVICE_NAME: bthserv\n"
        "        STATE              : 1  STOPPED\n"
        "        START_TYPE         : 2  AUTO_START\n"
    )
    fake_run = _make_run_result(service_status=service_status)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    service_actions = [a for a in fix.actions if "service" in a.title.lower()]
    assert len(service_actions) > 0


def test_win_bluetooth_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should handle error gracefully
    assert isinstance(result.findings, list)
