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
    return next(m for m in modules if m.name == "handoff_continuity")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_enabled():
    """All features enabled: Handoff, Bluetooth, Wi-Fi, iCloud"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ActivityReceivingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power (en0): On\n")
        elif "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result("(\n    {\n        MobileMeAccountDisplay = \"user@icloud.com\";\n    }\n)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_all_disabled():
    """All features disabled: Handoff, Bluetooth, Wi-Fi, iCloud"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ActivityReceivingAllowed" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power (en0): Off\n")
        elif "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result("", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_handoff_disabled_icloud_on():
    """Handoff disabled but iCloud signed in"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ActivityReceivingAllowed" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power (en0): On\n")
        elif "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result("(\n    {\n        MobileMeAccountDisplay = \"user@icloud.com\";\n    }\n)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_bluetooth_off_rest_on():
    """Bluetooth off, but everything else on"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ActivityReceivingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power (en0): On\n")
        elif "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result("(\n    {\n        MobileMeAccountDisplay = \"user@icloud.com\";\n    }\n)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_wifi_off():
    """Wi-Fi off"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ActivityReceivingAllowed" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "getairportpower" in cmd_str:
            return _make_subprocess_result("AirPort Power (en0): Off\n")
        elif "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result("(\n    {\n        MobileMeAccountDisplay = \"user@icloud.com\";\n    }\n)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_subprocess_error():
    """Simulate subprocess errors"""
    def fake_run(cmd, **kwargs):
        raise OSError("Command failed")
    return fake_run


def test_handoff_continuity_discovered():
    mod = _get_module()
    assert mod.name == "handoff_continuity"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_handoff_continuity_all_enabled():
    """All features enabled: should have only INFO findings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())

    # Should have findings for Handoff, Bluetooth, Wi-Fi, iCloud status
    assert len(result.findings) >= 4
    # No WARNING findings when everything is enabled
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 0


def test_handoff_continuity_all_disabled():
    """All features disabled: should have multiple WARNINGs"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())

    # Should have findings for all status checks
    assert len(result.findings) >= 4
    # Should have at least 2 WARNING findings (Bluetooth and iCloud)
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 2


def test_handoff_continuity_handoff_disabled_icloud_on():
    """Handoff disabled despite iCloud being on: should warn"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_handoff_disabled_icloud_on()):
        result = mod.check(_make_profile())

    # Should have a warning about Handoff being disabled
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check") == "handoff_warning" for f in warning_findings)


def test_handoff_continuity_bluetooth_off():
    """Bluetooth off: should warn about Bluetooth and impact on Continuity features"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bluetooth_off_rest_on()):
        result = mod.check(_make_profile())

    # Should have warning about Bluetooth being off
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check") == "bluetooth_warning" for f in warning_findings)


def test_handoff_continuity_wifi_off():
    """Wi-Fi off: should report it but not necessarily as critical"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_off()):
        result = mod.check(_make_profile())

    # Should have a Wi-Fi status finding
    wifi_findings = [f for f in result.findings if f.data.get("check") == "wifi_status"]
    assert len(wifi_findings) > 0


def test_handoff_continuity_subprocess_error():
    """Subprocess errors should not crash the module"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_subprocess_error()):
        result = mod.check(_make_profile())

    # Should still return a result, even if all checks fail
    assert result.module_name == "handoff_continuity"


def test_handoff_continuity_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded
    # Should have at least one action (for each finding)
    assert len(fix.actions) > 0
    # All actions should be SAFE
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_handoff_continuity_fix_all_disabled():
    """fix() with all features disabled should provide remediation guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have remediation actions
    assert len(fix.actions) >= 4
    # All should be successful and SAFE
    assert fix.all_succeeded
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_handoff_continuity_findings_data_structure():
    """Findings should have proper data structure"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())

    # Each finding should have a 'check' key in data
    for finding in result.findings:
        assert "check" in finding.data
        # Data should contain status information
        assert any(key in finding.data for key in ["enabled", "signed_in"])


def test_handoff_continuity_actions_have_descriptions():
    """All actions should have meaningful descriptions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    for action in fix.actions:
        assert action.title
        assert action.description
        # Description should contain actionable guidance
        assert len(action.description) > 20
