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
    return next(m for m in modules if m.name == "location_services")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_location_disabled():
    """Location Services is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.locationd LocationServicesEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_location_enabled_no_services():
    """Location Services is enabled but no system services have access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.locationd LocationServicesEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read com.apple.locationd SystemServices" in cmd_str:
            return _make_subprocess_result(stderr="not found", returncode=1)
        elif "defaults read com.apple.locationmenu" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "system_profiler SPHardwareDataType" in cmd_str:
            return _make_subprocess_result(stdout="Model Identifier: MacBookPro18,1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_location_enabled_with_find_my():
    """Location Services enabled with Find My service on MacBook"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.locationd LocationServicesEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read com.apple.locationd SystemServices" in cmd_str:
            return _make_subprocess_result(
                stdout="{\n    FindMyMac = 1;\n}\n"
            )
        elif "system_profiler SPHardwareDataType" in cmd_str:
            return _make_subprocess_result(stdout="Model Identifier: MacBookPro18,1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_location_enabled_with_find_my_desktop():
    """Location Services enabled with only Find My on desktop (Mac mini)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.locationd LocationServicesEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read com.apple.locationd SystemServices" in cmd_str:
            return _make_subprocess_result(
                stdout="{\n    FindMyMac = 1;\n}\n"
            )
        elif "system_profiler SPHardwareDataType" in cmd_str:
            return _make_subprocess_result(stdout="Model Identifier: Macmini9,1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_location_enabled_multiple_services():
    """Location Services enabled with multiple services"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.locationd LocationServicesEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read com.apple.locationd SystemServices" in cmd_str:
            return _make_subprocess_result(
                stdout="{\n    FindMyMac = 1;\n    TimeZone = 1;\n}\n"
            )
        elif "system_profiler SPHardwareDataType" in cmd_str:
            return _make_subprocess_result(stdout="Model Identifier: MacBookPro18,1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_location_status_unknown():
    """Unable to determine location services status"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # All commands fail
        if "defaults read" in cmd_str or "system_profiler" in cmd_str:
            return _make_subprocess_result(stderr="error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_location_services_discovered():
    mod = _get_module()
    assert mod.name == "location_services"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_location_services_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_disabled()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_location_services_enabled_no_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_enabled_no_services()):
        result = mod.check(_make_profile())
    # Should have at least one finding about Location Services being enabled
    assert result.has_issues
    assert any(f.data.get("check") == "location_services_enabled" for f in result.findings)


def test_location_services_enabled_with_find_my_laptop():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_enabled_with_find_my()):
        result = mod.check(_make_profile())
    # Should have findings about Location Services and services, but no warning
    assert result.has_issues
    assert any(f.data.get("check") == "location_services_enabled" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_location_services_enabled_with_find_my_desktop():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_enabled_with_find_my_desktop()):
        result = mod.check(_make_profile())
    # Should have warning about Location Services only for Find My on desktop
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "location_desktop_find_my_only" for f in result.findings)


def test_location_services_enabled_multiple_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_enabled_multiple_services()):
        result = mod.check(_make_profile())
    # Should have findings about multiple services, no warning
    assert result.has_issues
    assert any(f.data.get("check") == "location_system_services" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_location_services_status_unknown():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_status_unknown()):
        result = mod.check(_make_profile())
    # Should gracefully handle inability to read status
    assert not result.has_issues


def test_location_services_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_enabled_with_find_my()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the enabled Location Services finding
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.location_services.") for c in declared)
