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
    return next(m for m in modules if m.name == "bluetooth_diagnostics")


def _fake_system_profiler_run(
    bluetooth_on=True,
    paired_devices=None,
    firmware_version=None,
    error=None,
):
    """Mock subprocess.run for system_profiler SPBluetoothDataType."""
    if paired_devices is None:
        paired_devices = [
            {"name": "AirPods Pro", "connected": True, "battery": 85},
            {"name": "Magic Keyboard", "connected": True, "battery": 45},
        ]

    def fake_run(cmd, **kwargs):
        if error:
            raise error

        result = MagicMock()
        result.returncode = 0
        result.stdout = ""

        if (
            len(cmd) >= 2
            and cmd[0] == "system_profiler"
            and cmd[1] == "SPBluetoothDataType"
        ):
            lines = ["Bluetooth:"]
            if not bluetooth_on:
                lines.append("    State: Off")
            else:
                lines.append("    State: On")

            if firmware_version:
                lines.append(f"    Firmware Version: {firmware_version}")

            for device in paired_devices:
                lines.append("    Device:")
                lines.append(f"        Name: {device['name']}")
                lines.append(f"        Address: AA:BB:CC:DD:EE:{device['name'][:2]}")
                if device.get("connected"):
                    lines.append("        Connected: Yes")
                else:
                    lines.append("        Connected: No")
                if device.get("battery") is not None:
                    lines.append(f"        Battery Level: {device['battery']}%")
                if device.get("last_connected"):
                    lines.append(f"        Last Connected: {device['last_connected']}")

            result.stdout = "\n".join(lines)
        else:
            result.returncode = 1

        return result

    return fake_run


def test_bluetooth_diagnostics_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "bluetooth_diagnostics"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_bluetooth_off_with_paired_devices():
    """Test warning when Bluetooth is off but devices are paired."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": False, "battery": 50},
        {"name": "Magic Keyboard", "connected": False, "battery": 30},
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=False, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("off" in f.title.lower() for f in warning_findings)

    off_finding = next(
        (f for f in warning_findings if f.data.get("check") == "bluetooth_off_with_devices"),
        None,
    )
    assert off_finding is not None
    assert off_finding.data["paired_count"] == 2


def test_bluetooth_off_no_devices():
    """Test info when Bluetooth is off with no paired devices."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=False, paired_devices=[]
        ),
    ):
        result = mod.check(_make_profile())

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("off" in f.title.lower() for f in info_findings)


def test_bluetooth_low_battery_warning():
    """Test warning for devices with low battery."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 15},
        {"name": "Magic Keyboard", "connected": True, "battery": 45},
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    low_battery_findings = [
        f for f in result.findings if f.data.get("check") == "low_battery"
    ]
    assert len(low_battery_findings) == 1
    assert "AirPods Pro" in low_battery_findings[0].title
    assert low_battery_findings[0].severity == Severity.WARNING


def test_bluetooth_high_paired_count():
    """Test warning when paired device count exceeds 15."""
    mod = _get_module()
    paired_devices = [
        {"name": f"Device{i}", "connected": False, "battery": 50}
        for i in range(18)
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    high_count_findings = [
        f for f in result.findings if f.data.get("check") == "too_many_paired_devices"
    ]
    assert len(high_count_findings) == 1
    assert high_count_findings[0].severity == Severity.WARNING


def test_bluetooth_stale_devices():
    """Test warning for paired but never connected devices."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 85, "last_connected": "Today"},
        {"name": "Old Device", "connected": False, "battery": None, "last_connected": None},
        {"name": "Another Old", "connected": False, "battery": None, "last_connected": None},
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    stale_findings = [
        f for f in result.findings if f.data.get("check") == "stale_devices"
    ]
    assert len(stale_findings) == 1
    assert stale_findings[0].severity == Severity.WARNING
    assert stale_findings[0].data["stale_count"] == 2


def test_bluetooth_paired_devices_list_info():
    """Test INFO finding listing all paired devices."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 85},
        {"name": "Magic Keyboard", "connected": False, "battery": 45},
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    info_findings = [
        f for f in result.findings if f.data.get("check") == "paired_devices_list"
    ]
    assert len(info_findings) == 1
    assert info_findings[0].severity == Severity.INFO
    assert "AirPods Pro" in info_findings[0].description
    assert "Magic Keyboard" in info_findings[0].description


def test_bluetooth_firmware_version_info():
    """Test INFO finding for firmware version."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 85}
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True,
            paired_devices=paired_devices,
            firmware_version="2.0.6",
        ),
    ):
        result = mod.check(_make_profile())

    firmware_findings = [
        f for f in result.findings if f.data.get("check") == "firmware_version"
    ]
    assert len(firmware_findings) == 1
    assert firmware_findings[0].severity == Severity.INFO
    assert "2.0.6" in firmware_findings[0].data["version"]


def test_bluetooth_profiler_error():
    """Test handling when system_profiler fails."""
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    error_findings = [
        f for f in result.findings if f.data.get("check") == "profiler_error"
    ]
    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.WARNING


def test_bluetooth_fix_is_informational():
    """Test that fix() only provides guidance, doesn't modify system."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 15}
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # All actions should succeed but be SAFE
    assert fix.all_succeeded
    for action in fix.actions:
        assert action.success
        assert action.risk_level == RiskLevel.SAFE


def test_bluetooth_multiple_issues():
    """Test handling multiple issues simultaneously."""
    mod = _get_module()
    paired_devices = [
        {"name": f"Device{i}", "connected": False, "battery": 10 + i}
        for i in range(18)
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True, paired_devices=paired_devices
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have warnings for: too many devices, low battery (first device < 20)
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 2


def test_bluetooth_no_issues():
    """Test when Bluetooth is healthy."""
    mod = _get_module()
    paired_devices = [
        {"name": "AirPods Pro", "connected": True, "battery": 85},
        {"name": "Magic Keyboard", "connected": True, "battery": 75},
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_system_profiler_run(
            bluetooth_on=True,
            paired_devices=paired_devices,
            firmware_version="2.0.6",
        ),
    ):
        result = mod.check(_make_profile())

    # Should have INFO findings (devices list, firmware) but no warnings
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 0

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 2  # At least paired devices list and firmware


def test_bluetooth_subprocess_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_system_profiler_run(error=TimeoutError("timeout"))
    ):
        result = mod.check(_make_profile())

    # Should handle timeout gracefully
    assert result.has_issues
