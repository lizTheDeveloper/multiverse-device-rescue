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
    return next(m for m in modules if m.name == "find_my_mac_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_enabled():
    """Find My Mac enabled, Location Services enabled, iCloud signed in, Activation Lock enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Enabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_find_my_mac_disabled():
    """Find My Mac disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="0")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Disabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_location_services_disabled():
    """Location Services disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Enabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_icloud_not_signed_in():
    """iCloud not signed in"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(returncode=1, stderr="not found")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Disabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_all_disabled():
    """All checks fail"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="0")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(returncode=1, stderr="not found")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="No Activation Lock")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def test_find_my_mac_check_discovered():
    mod = _get_module()
    assert mod.name == "find_my_mac_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_find_my_mac_check_all_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO about proper configuration
    assert any(
        "properly configured" in f.title.lower() for f in result.findings
    )


def test_find_my_mac_check_find_my_mac_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_find_my_mac_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for disabled Find My Mac
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any("disabled" in f.title.lower() for f in critical_findings)


def test_find_my_mac_check_location_services_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_services_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for disabled Location Services
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(
        "location services" in f.title.lower() for f in warning_findings
    )


def test_find_my_mac_check_icloud_not_signed_in():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_icloud_not_signed_in()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for iCloud not signed in
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("icloud" in f.title.lower() for f in warning_findings)


def test_find_my_mac_check_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL and WARNING findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0


def test_find_my_mac_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_find_my_mac_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.find_my_mac_check.") for c in declared)
