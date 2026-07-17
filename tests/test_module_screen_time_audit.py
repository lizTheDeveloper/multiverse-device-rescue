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
    return next(m for m in modules if m.name == "screen_time_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_screen_time_disabled():
    """Screen Time disabled, no restrictions"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read com.apple.ScreenTimeAgent ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_screen_time_enabled_no_passcode():
    """Screen Time enabled but no passcode set"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "ContentPrivacyRestrictionsEnabled" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "DowntimeEnabled" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "AppLimits" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "CommunicationLimits" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_fully_configured():
    """Screen Time fully configured with all features"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "ContentPrivacyRestrictionsEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "DowntimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "AppLimits" in cmd_str:
            return _make_subprocess_result(
                stdout="(\n    {\n        category = 1;\n        limit = 3600;\n    }\n)\n"
            )
        elif "CommunicationLimits" in cmd_str:
            return _make_subprocess_result(
                stdout="(\n    contacts = (\n        123456789\n    );\n)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_partial_config():
    """Screen Time with passcode but only some features enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "ContentPrivacyRestrictionsEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "DowntimeEnabled" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "AppLimits" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "CommunicationLimits" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_screen_time_audit_discovered():
    mod = _get_module()
    assert mod.name == "screen_time_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_screen_time_audit_disabled():
    """Test when Screen Time is disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_time_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "screen_time_disabled" for f in result.findings
    )
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_screen_time_audit_enabled_no_passcode():
    """Test when Screen Time is enabled but passcode is not set"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_time_enabled_no_passcode()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "screen_time_enabled" for f in result.findings
    )
    # Should have a WARNING about missing passcode
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "screen_time_no_passcode"
        for f in result.findings
    )


def test_screen_time_audit_fully_configured():
    """Test when Screen Time is fully configured with all features"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fully_configured()):
        result = mod.check(_make_profile())
    # Should have findings but no warnings (all features configured)
    assert result.has_issues
    # Should have enabled status
    assert any(f.data.get("check") == "screen_time_enabled" for f in result.findings)
    # Should have content/privacy, downtime, app limits, communication limits
    checks = [f.data.get("check") for f in result.findings]
    assert "content_privacy_restrictions" in checks
    assert "downtime_enabled" in checks
    assert "app_limits_configured" in checks
    assert "communication_limits_configured" in checks
    # Should NOT have passcode warning
    assert not any(f.data.get("check") == "screen_time_no_passcode" for f in result.findings)


def test_screen_time_audit_partial_config():
    """Test when Screen Time is enabled with passcode and some features"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_partial_config()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have enabled and content/privacy
    assert any(f.data.get("check") == "screen_time_enabled" for f in result.findings)
    assert any(
        f.data.get("check") == "content_privacy_restrictions" for f in result.findings
    )
    # Should not have passcode warning (passcode is set)
    assert not any(f.data.get("check") == "screen_time_no_passcode" for f in result.findings)


def test_screen_time_audit_fix_is_informational():
    """Test that fix() provides informational guidance without modifying settings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_time_enabled_no_passcode()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_screen_time_audit_fix_has_guidance():
    """Test that fix() includes helpful setup guidance"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_time_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should suggest enabling Screen Time for family devices
    assert any("Enable Screen Time" in a.title for a in fix.actions)
