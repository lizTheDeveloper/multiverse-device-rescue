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
    return next(m for m in modules if m.name == "input_devices")


def _fake_subprocess_run(
    key_repeat=2,
    initial_key_repeat=25,
    tap_to_click=True,
    scroll_direction=True,
    trackpad_scaling=1,
    mouse_scaling=1,
    usb_devices="",
    bluetooth_devices="",
    error=None,
):
    """Mock subprocess.run for input device calls."""

    def fake_run(cmd, **kwargs):
        if error:
            raise error

        result = MagicMock()
        result.returncode = 0

        # Handle defaults read commands
        if len(cmd) >= 3 and cmd[0] == "defaults" and cmd[1] == "read":
            if cmd[2] == "-g":
                if len(cmd) > 3:
                    key = cmd[3]
                    if key == "KeyRepeat":
                        result.stdout = str(key_repeat) if key_repeat is not None else ""
                        if key_repeat is None:
                            result.returncode = 1
                    elif key == "InitialKeyRepeat":
                        result.stdout = str(initial_key_repeat) if initial_key_repeat is not None else ""
                        if initial_key_repeat is None:
                            result.returncode = 1
                    elif key == "com.apple.trackpad.scaling":
                        result.stdout = str(trackpad_scaling) if trackpad_scaling is not None else ""
                        if trackpad_scaling is None:
                            result.returncode = 1
                    elif key == "com.apple.mouse.scaling":
                        result.stdout = str(mouse_scaling) if mouse_scaling is not None else ""
                        if mouse_scaling is None:
                            result.returncode = 1
                    else:
                        result.returncode = 1
                        result.stdout = ""
                else:
                    result.returncode = 1
                    result.stdout = ""
            elif cmd[2] == "com.apple.driver.AppleBluetoothMultitouch.trackpad":
                if len(cmd) > 3 and cmd[3] == "Clicking":
                    result.stdout = "1" if tap_to_click else "0"
                else:
                    result.returncode = 1
                    result.stdout = ""
            elif cmd[2] == "com.apple.swipescrolldirection":
                if len(cmd) > 3 and cmd[3] == "com.apple.swipescrolldirection":
                    result.stdout = "1" if scroll_direction else "0"
                else:
                    result.returncode = 1
                    result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
        # Handle system_profiler commands
        elif len(cmd) >= 2 and cmd[0] == "system_profiler":
            if cmd[1] == "SPUSBDataType":
                result.stdout = usb_devices
            elif cmd[1] == "SPBluetoothDataType":
                result.stdout = bluetooth_devices
            else:
                result.returncode = 1
                result.stdout = ""
        else:
            raise AssertionError(f"unexpected command {cmd}")

        return result

    return fake_run


def test_input_devices_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "input_devices"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_input_devices_check_default_settings():
    """Test check with default settings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run()):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 5  # keyboard, trackpad, mouse, usb, bluetooth


def test_input_devices_keyboard_settings():
    """Test keyboard settings reporting."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(key_repeat=10)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "Keyboard settings" in descriptions or "Key Repeat" in descriptions


def test_input_devices_trackpad_settings():
    """Test trackpad settings reporting."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(trackpad_scaling=2)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "Trackpad settings" in descriptions or "Tracking Speed" in descriptions


def test_input_devices_mouse_settings():
    """Test mouse settings reporting."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(mouse_scaling=2)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "Mouse settings" in descriptions or "Tracking Speed" in descriptions


def test_input_devices_slow_keyboard_repeat_warning():
    """Test warning for slow keyboard repeat rate."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(key_repeat=100)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("slow" in f.title.lower() for f in warnings)


def test_input_devices_fast_keyboard_repeat_warning():
    """Test warning for extremely fast keyboard repeat rate."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(key_repeat=1)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("fast" in f.title.lower() for f in warnings)


def test_input_devices_minimum_mouse_tracking_speed_warning():
    """Test warning for minimum mouse tracking speed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(mouse_scaling=0)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("minimum" in f.title.lower() and "tracking" in f.title.lower() for f in warnings)


def test_input_devices_minimum_trackpad_tracking_speed_warning():
    """Test warning for minimum trackpad tracking speed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(trackpad_scaling=-1)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("minimum" in f.title.lower() and "tracking" in f.title.lower() for f in warnings)


def test_input_devices_usb_devices():
    """Test USB device detection."""
    usb_output = """
USB:

  USB 3.1 Bus:
    HID Compliant Keyboard:
      Product ID: 0x0301
    Apple USB Optical Mouse:
      Product ID: 0x0302
    """
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(usb_devices=usb_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    findings = [f for f in result.findings if "USB" in f.title]
    assert len(findings) > 0
    assert "Keyboard" in findings[0].description or "Mouse" in findings[0].description


def test_input_devices_bluetooth_devices():
    """Test Bluetooth device detection."""
    bt_output = """
Bluetooth:

  Apple Wireless Keyboard:
    Address: AA:BB:CC:DD:EE:FF
    Connected: Yes

  Apple Magic Trackpad:
    Address: 11:22:33:44:55:66
    Connected: Yes
    """
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(bluetooth_devices=bt_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    findings = [f for f in result.findings if "Bluetooth" in f.title]
    assert len(findings) > 0


def test_input_devices_tap_to_click_enabled():
    """Test when tap to click is enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(tap_to_click=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "ENABLED" in descriptions or "tap" in descriptions.lower()


def test_input_devices_tap_to_click_disabled():
    """Test when tap to click is disabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(tap_to_click=False)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "disabled" in descriptions.lower() or "tap" in descriptions.lower()


def test_input_devices_scroll_direction_natural():
    """Test natural scroll direction."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(scroll_direction=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "natural" in descriptions.lower() or "scroll" in descriptions.lower()


def test_input_devices_scroll_direction_traditional():
    """Test traditional scroll direction."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(scroll_direction=False)):
        result = mod.check(_make_profile())

    assert result.has_issues
    descriptions = "\n".join(f.description for f in result.findings)
    assert "traditional" in descriptions.lower() or "scroll" in descriptions.lower()


def test_input_devices_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_subprocess_run(error=OSError("not found"))
    ):
        result = mod.check(_make_profile())

    # Should not crash, should report with defaults
    assert result.has_issues


def test_input_devices_fix_is_informational():
    """Test that fix() is informational and doesn't modify system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed but only provide guidance
    assert fix.all_succeeded
    for action in fix.actions:
        # Actions should be informational
        assert (
            "review" in action.title.lower()
            or "consider" in action.title.lower()
        )


def test_input_devices_slow_keyboard_fix():
    """Test fix suggestion for slow keyboard repeat."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(key_repeat=100)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    # Should have action for slow keyboard
    titles = [a.title for a in fix.actions]
    assert any("keyboard" in t.lower() for t in titles)


def test_input_devices_minimum_tracking_fix():
    """Test fix suggestion for minimum tracking speed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run(mouse_scaling=0)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    titles = [a.title for a in fix.actions]
    assert any("tracking" in t.lower() for t in titles)


def test_input_devices_timeout_handling():
    """Test graceful handling of system_profiler timeout."""
    import subprocess
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        if "system_profiler" in cmd:
            raise subprocess.TimeoutExpired(cmd, timeout=5)
        return _fake_subprocess_run()(cmd, **kwargs)

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())

    # Should not crash despite timeout
    assert result.has_issues


def test_input_devices_all_settings_none():
    """Test when no settings are available."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_subprocess_run(
            key_repeat=None,
            initial_key_repeat=None,
            trackpad_scaling=None,
            mouse_scaling=None,
        ),
    ):
        result = mod.check(_make_profile())

    # Should still report, with defaults
    assert result.has_issues
