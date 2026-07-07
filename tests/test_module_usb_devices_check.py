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
    return next(m for m in modules if m.name == "usb_devices_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_devices():
    """No USB devices connected"""

    def fake_run(cmd, **kwargs):
        output = "USB:\n\nUSB 3.1 Bus:\n    No devices\n"
        return _make_subprocess_result(output)

    return fake_run


def _fake_run_single_device():
    """Single USB 3.0 device connected"""

    def fake_run(cmd, **kwargs):
        output = """USB:

    USB 3.1 Bus:
      Host Controller Location: Built-in USB 3.1 Bus

        USB 3.0 Flash Drive:
          Product: Kingston DataTraveler
          Manufacturer: Kingston
          Serial Number: ABCD1234
          Location ID: 0x14100000 / 1
          Current Available (mA): 500
          Current Required (mA): 100
          Extra Operating Current (mA): 0
          Speed: Up to 5 Gb/s
          Manufacturer ID: 0x0951
          Product ID: 0x1666
"""
        return _make_subprocess_result(output)

    return fake_run


def _fake_run_hub_overloaded():
    """USB hub with 6 devices (exceeds 4 device limit)"""

    def fake_run(cmd, **kwargs):
        output = """USB:

    USB 3.1 Bus:
      Host Controller Location: Built-in USB 3.1 Bus

        USB 3.0 Hub:
          Product: USB 3.0 Hub
          Manufacturer: Apple Inc.
          Location ID: 0x14100000 / 1
          Current Available (mA): 500
          Current Required (mA): 0
          Speed: Up to 5 Gb/s

            Device 1:
              Product: Kingston DataTraveler
              Manufacturer: Kingston
              Location ID: 0x14110000 / 2
              Current Available (mA): 400
              Current Required (mA): 100

            Device 2:
              Product: External Drive
              Manufacturer: Seagate
              Location ID: 0x14110000 / 3
              Current Available (mA): 400
              Current Required (mA): 500

            Device 3:
              Product: USB Mouse
              Manufacturer: Logitech
              Location ID: 0x14110000 / 4
              Current Available (mA): 400
              Current Required (mA): 100

            Device 4:
              Product: USB Keyboard
              Manufacturer: Apple
              Location ID: 0x14110000 / 5
              Current Available (mA): 400
              Current Required (mA): 100

            Device 5:
              Product: USB Hub 2
              Manufacturer: Anker
              Location ID: 0x14110000 / 6
              Current Available (mA): 400
              Current Required (mA): 0

            Device 6:
              Product: Printer
              Manufacturer: Canon
              Location ID: 0x14110000 / 7
              Current Available (mA): 400
              Current Required (mA): 200
"""
        return _make_subprocess_result(output)

    return fake_run


def _fake_run_usb2_and_high_power():
    """USB 2.0 device and high-power device"""

    def fake_run(cmd, **kwargs):
        output = """USB:

    USB 3.1 Bus:
      Host Controller Location: Built-in USB 3.1 Bus

        USB 2.0 Hub:
          Product: USB 2.0 Hub
          Manufacturer: Generic
          Location ID: 0x14100000 / 1
          Speed: Up to 480 Mb/s (High-Speed)
          Current Required (mA): 0

            Old Camera:
              Product: USB 2.0 Camera
              Manufacturer: Canon
              Location ID: 0x14110000 / 2
              Speed: Up to 480 Mb/s (High-Speed)
              Current Required (mA): 250

    USB 3.1 Bus:
      Host Controller Location: Built-in USB 3.1 Bus

        High Power Device:
          Product: External SSD
          Manufacturer: Samsung
          Location ID: 0x14200000 / 1
          Speed: Up to 5 Gb/s
          Current Required (mA): 500
"""
        return _make_subprocess_result(output)

    return fake_run


def _fake_run_device_error():
    """Device in error state"""

    def fake_run(cmd, **kwargs):
        output = """USB:

    USB 3.1 Bus:
      Host Controller Location: Built-in USB 3.1 Bus

        Unknown Device (Error):
          Product: Unknown USB Device
          Manufacturer: Unknown
          Location ID: 0x14100000 / 1
          Current Available (mA): 500
          Current Required (mA): 0
          Speed: Unknown
          Status: Device not recognized
"""
        return _make_subprocess_result(output)

    return fake_run


def _fake_run_profiler_error():
    """system_profiler fails"""

    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)

    return fake_run


def test_usb_devices_check_discovered():
    mod = _get_module()
    assert mod.name == "usb_devices_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_usb_devices_check_no_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_devices()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_devices" for f in result.findings)


def test_usb_devices_check_single_device():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_device()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "device_list" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_usb_devices_check_hub_overloaded():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hub_overloaded()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have both device list and hub overload warnings
    assert any(f.data.get("check") == "device_list" for f in result.findings)
    assert any(f.data.get("check") == "hub_overload" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_usb_devices_check_usb2_devices():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_usb2_and_high_power()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "usb2_devices" for f in result.findings)
    assert any(f.data.get("check") == "high_power_device" for f in result.findings)


def test_usb_devices_check_high_power_device():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_usb2_and_high_power()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "high_power_device" and f.data.get("power_required") >= 400
        for f in result.findings
    )


def test_usb_devices_check_device_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_device_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "device_error" for f in result.findings
    )
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_usb_devices_check_profiler_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_profiler_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "profiler_error" for f in result.findings)


def test_usb_devices_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hub_overloaded()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
