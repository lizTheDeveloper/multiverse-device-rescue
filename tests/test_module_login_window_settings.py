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
    return next(m for m in modules if m.name == "login_window_settings")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: secure login window settings"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        elif "SHOWFULLNAME" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "RetriesUntilHint" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_auto_login_enabled():
    """Auto-login is enabled - CRITICAL"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stdout="alice\n")
        elif "SHOWFULLNAME" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "RetriesUntilHint" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_user_list_shown():
    """Login window shows user list - WARNING"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        elif "SHOWFULLNAME" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "RetriesUntilHint" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_password_hints_enabled():
    """Password hints are enabled - WARNING"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="does not exist", returncode=1)
        elif "SHOWFULLNAME" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "RetriesUntilHint" in cmd_str:
            return _make_subprocess_result(stdout="3\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_issues():
    """Multiple issues: auto-login + user list + hints"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stdout="bob\n")
        elif "SHOWFULLNAME" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "RetriesUntilHint" in cmd_str:
            return _make_subprocess_result(stdout="2\n")
        return _make_subprocess_result()
    return fake_run


def test_login_window_settings_discovered():
    mod = _get_module()
    assert mod.name == "login_window_settings"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_login_window_settings_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Healthy case may still have INFO findings (login settings report)
    # but should not have CRITICAL or WARNING findings
    critical_warnings = [
        f for f in result.findings
        if f.severity in (Severity.CRITICAL, Severity.WARNING)
    ]
    assert len(critical_warnings) == 0


def test_login_window_settings_auto_login():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_auto_login_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.CRITICAL and f.data.get("check") == "auto_login"
        for f in result.findings
    )


def test_login_window_settings_user_list():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_user_list_shown()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "show_user_list"
        for f in result.findings
    )


def test_login_window_settings_password_hints():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_password_hints_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "password_hints"
        for f in result.findings
    )


def test_login_window_settings_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have at least CRITICAL and WARNING
    severities = [f.severity for f in result.findings]
    assert Severity.CRITICAL in severities
    assert Severity.WARNING in severities


def test_login_window_settings_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_auto_login_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action per finding
    assert len(fix.actions) >= len(check.findings)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.login_window_settings.") for c in declared)
