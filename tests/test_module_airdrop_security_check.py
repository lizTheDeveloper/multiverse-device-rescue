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
    return next(m for m in modules if m.name == "airdrop_security_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_airdrop_everyone():
    """AirDrop set to Everyone - risky configuration"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("2\n")  # Everyone
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")  # Bluetooth enabled
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power: On\n")  # Wi-Fi enabled
        elif "ActivityAdvertisingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")  # Handoff enabled
        elif "PrefKeyServicesEnabled" in cmd_str:
            return _make_subprocess_result("0\n")  # Bluetooth sharing disabled
        return _make_subprocess_result()
    return fake_run


def _fake_run_airdrop_contacts_only():
    """AirDrop set to Contacts Only - secure"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("1\n")  # Contacts Only
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")  # Bluetooth enabled
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power: On\n")  # Wi-Fi enabled
        elif "ActivityAdvertisingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")  # Handoff enabled
        elif "PrefKeyServicesEnabled" in cmd_str:
            return _make_subprocess_result("0\n")  # Bluetooth sharing disabled
        return _make_subprocess_result()
    return fake_run


def _fake_run_bluetooth_sharing_enabled():
    """Bluetooth sharing is enabled - risky"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("1\n")  # Contacts Only
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")  # Bluetooth enabled
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power: On\n")  # Wi-Fi enabled
        elif "ActivityAdvertisingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")  # Handoff enabled
        elif "PrefKeyServicesEnabled" in cmd_str:
            return _make_subprocess_result("1\n")  # Bluetooth sharing ENABLED
        return _make_subprocess_result()
    return fake_run


def _fake_run_all_disabled():
    """All sharing features disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("0\n")  # Off
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("0\n")  # Bluetooth disabled
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power: Off\n")  # Wi-Fi disabled
        elif "ActivityAdvertisingAllowed" in cmd_str:
            return _make_subprocess_result("0\n")  # Handoff disabled
        elif "PrefKeyServicesEnabled" in cmd_str:
            return _make_subprocess_result("0\n")  # Bluetooth sharing disabled
        return _make_subprocess_result()
    return fake_run


def test_airdrop_security_check_discovered():
    mod = _get_module()
    assert mod.name == "airdrop_security_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_airdrop_everyone_risky():
    """Test that AirDrop set to Everyone triggers a WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_everyone()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "airdrop_mode_everyone" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_airdrop_contacts_only_secure():
    """Test that AirDrop set to Contacts Only doesn't trigger WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_contacts_only()):
        result = mod.check(_make_profile())
    # Should have INFO findings but no WARNING about airdrop_mode_everyone
    assert not any(f.data.get("check") == "airdrop_mode_everyone" for f in result.findings)


def test_bluetooth_sharing_enabled_warning():
    """Test that Bluetooth sharing enabled triggers a WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bluetooth_sharing_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "bluetooth_sharing_enabled" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_all_sharing_disabled():
    """Test that all sharing disabled shows INFO but no warnings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())
    # Should have INFO but no WARNING findings
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 0


def test_airdrop_fix_is_informational():
    """Test that fix() always succeeds with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_everyone()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
