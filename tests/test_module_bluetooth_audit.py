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
    return next(m for m in modules if m.name == "bluetooth_audit")


def _fake_run(power_state="1", discoverable_state="0", devices_output=""):
    """Factory for creating fake subprocess.run function."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            if "ControllerPowerState" in cmd:
                result.stdout = power_state + "\n"
            elif "DiscoverableState" in cmd:
                result.stdout = discoverable_state + "\n"
            elif "SPBluetoothDataType" in cmd:
                result.stdout = devices_output
        return result
    return fake_run


def test_bluetooth_audit_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "bluetooth_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_bluetooth_audit_healthy_no_devices():
    """Test healthy Bluetooth state with no paired devices."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="0",
        devices_output=""
    )):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_bluetooth_audit_info_with_devices():
    """Test that paired devices are reported as INFO."""
    mod = _get_module()
    devices_output = """Bluetooth:
    Apple Remote:
        Device Name: Apple Remote
        Address: 00:11:22:33:44:55
    iPhone:
        Device Name: iPhone
        Address: AA:BB:CC:DD:EE:FF
"""
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="0",
        devices_output=devices_output
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["check"] == "paired_devices"
    assert result.findings[0].data["device_count"] == 2
    assert "Apple Remote" in result.findings[0].data["devices"]
    assert "iPhone" in result.findings[0].data["devices"]


def test_bluetooth_audit_warning_discoverable():
    """Test that discoverable Bluetooth triggers WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="1",
        devices_output=""
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["check"] == "discoverable_state"
    assert "discoverable" in result.findings[0].title.lower()


def test_bluetooth_audit_warning_and_info():
    """Test warning for discoverable AND info for paired devices."""
    mod = _get_module()
    devices_output = """Bluetooth:
    Device Name: Test Device
"""
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="1",
        devices_output=devices_output
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 2

    # Check for both findings
    severities = {f.severity for f in result.findings}
    assert Severity.INFO in severities
    assert Severity.WARNING in severities


def test_bluetooth_audit_power_off():
    """Test Bluetooth power state off (no warning expected per spec)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="0",
        discoverable_state="0",
        devices_output=""
    )):
        result = mod.check(_make_profile())
    # Power off itself is not flagged as an issue, but would prevent discoverable warning
    assert not result.has_issues


def test_bluetooth_audit_fix_discoverable():
    """Test fix suggestion for discoverable state."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="1",
        devices_output=""
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) == 1
    assert "discoverability" in fix.actions[0].title.lower()
    assert fix.actions[0].success
    assert fix.actions[0].risk_level == RiskLevel.SAFE


def test_bluetooth_audit_fix_paired_devices():
    """Test fix suggestion for paired devices."""
    mod = _get_module()
    devices_output = """Bluetooth:
    Device Name: My Mouse
"""
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="0",
        devices_output=devices_output
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) == 1
    assert "paired" in fix.actions[0].title.lower() or "review" in fix.actions[0].title.lower()
    assert fix.actions[0].success
    assert fix.actions[0].risk_level == RiskLevel.SAFE


def test_bluetooth_audit_fix_multiple_issues():
    """Test fix suggestions for multiple issues."""
    mod = _get_module()
    devices_output = """Bluetooth:
    Device Name: My Mouse
"""
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="1",
        devices_output=devices_output
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) == 2
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_bluetooth_audit_handles_missing_preferences():
    """Test graceful handling when preferences files don't exist."""
    def failing_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Domain /Library/Preferences/com.apple.Bluetooth does not exist"
        result.stdout = ""
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=failing_run):
        result = mod.check(_make_profile())
    # Should not crash, should handle gracefully
    assert isinstance(result.has_issues, bool)


def test_bluetooth_audit_device_parsing():
    """Test correct parsing of multiple devices."""
    mod = _get_module()
    devices_output = """Bluetooth:
    Apple Remote:
        Device Name: Apple Remote
        Address: 00:11:22:33:44:55
    iPhone:
        Device Name: iPhone 14
        Address: AA:BB:CC:DD:EE:FF
    iPad:
        Device Name: iPad Pro
        Address: 11:22:33:44:55:66
"""
    with patch("subprocess.run", side_effect=_fake_run(
        power_state="1",
        discoverable_state="0",
        devices_output=devices_output
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].data["device_count"] == 3
    assert len(result.findings[0].data["devices"]) == 3


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.bluetooth_audit.") for c in declared)
