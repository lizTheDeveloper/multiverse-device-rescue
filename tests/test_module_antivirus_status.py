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
    return next(m for m in modules if m.name == "antivirus_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_fully_protected():
    """System with XProtect, MRT, and running third-party AV"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect Remediator" in cmd_str:
            return _make_subprocess_result(stdout="13.0.5\n")
        elif "defaults" in cmd_str and "MRT.app" in cmd_str:
            return _make_subprocess_result(stdout="1.96\n")
        elif "mdfind" in cmd_str and "Malwarebytes" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Malwarebytes.app\n")
        elif "pgrep" in cmd_str and "malwarebytes" in cmd_str:
            return _make_subprocess_result(stdout="12345\n")
        elif "mdfind" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "pgrep" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_only_apple_tools():
    """System with XProtect and MRT, no third-party AV"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect Remediator" in cmd_str:
            return _make_subprocess_result(stdout="13.0.5\n")
        elif "defaults" in cmd_str and "MRT.app" in cmd_str:
            return _make_subprocess_result(stdout="1.96\n")
        elif "mdfind" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "pgrep" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_av_not_running():
    """System with third-party AV installed but not running"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect Remediator" in cmd_str:
            return _make_subprocess_result(stdout="13.0.5\n")
        elif "defaults" in cmd_str and "MRT.app" in cmd_str:
            return _make_subprocess_result(stdout="1.96\n")
        elif "mdfind" in cmd_str and "Norton" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Norton Security.app\n")
        elif "mdfind" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "pgrep" in cmd_str and "Norton" in cmd_str.lower():
            return _make_subprocess_result(returncode=1)  # Not running
        elif "pgrep" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_missing_apple_tools():
    """System missing some Apple tools"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect Remediator" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Not found
        elif "defaults" in cmd_str and "MRT.app" in cmd_str:
            return _make_subprocess_result(stdout="1.96\n")
        elif "mdfind" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "pgrep" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_antivirus_status_discovered():
    """Module is properly discovered and has correct metadata"""
    mod = _get_module()
    assert mod.name == "antivirus_status"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_antivirus_status_fully_protected():
    """System with XProtect, MRT, and running third-party AV"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fully_protected()):
        result = mod.check(_make_profile())

    # Should have findings (informational)
    assert result.has_issues

    # Should report XProtect Remediator
    assert any(f.data.get("check") == "xprotect_remediator" for f in result.findings)

    # Should report MRT
    assert any(f.data.get("check") == "mrt" for f in result.findings)

    # Should report third-party AV detected
    assert any(f.data.get("check") == "third_party_av" for f in result.findings)

    # Should NOT have warning about AV not running
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_antivirus_status_only_apple_tools():
    """System with only Apple tools (XProtect, MRT)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_only_apple_tools()):
        result = mod.check(_make_profile())

    # Should have findings (informational)
    assert result.has_issues

    # Should report XProtect Remediator
    assert any(f.data.get("check") == "xprotect_remediator" for f in result.findings)

    # Should report MRT
    assert any(f.data.get("check") == "mrt" for f in result.findings)

    # Should report no third-party AV
    assert any(f.data.get("check") == "no_third_party_av" for f in result.findings)

    # All findings should be informational
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_antivirus_status_av_not_running():
    """System with third-party AV installed but not running (WARNING)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_av_not_running()):
        result = mod.check(_make_profile())

    # Should have issues
    assert result.has_issues

    # Should have a warning about AV not running
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(f.data.get("check") == "av_not_running" for f in warning_findings)


def test_antivirus_status_missing_apple_tools():
    """System missing XProtect Remediator"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_missing_apple_tools()):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues

    # Should report XProtect Remediator as not found
    xp_findings = [f for f in result.findings if f.data.get("check") == "xprotect_remediator"]
    assert len(xp_findings) > 0
    assert "Not found" in xp_findings[0].title or xp_findings[0].data.get("version") is None


def test_antivirus_status_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_av_not_running()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # If there are warnings, there should be corresponding actions
    warnings = [f for f in check.findings if f.severity == Severity.WARNING]
    if warnings:
        assert len(fix.actions) > 0


def test_antivirus_status_fix_no_warnings():
    """fix() with no warnings should return empty actions list"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_only_apple_tools()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should succeed and have no actions (all findings are INFO)
    assert fix.all_succeeded
    assert len(fix.actions) == 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.antivirus_status.") for c in declared)
