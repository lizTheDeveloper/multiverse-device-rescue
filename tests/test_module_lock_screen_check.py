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
    return next(m for m in modules if m.name == "lock_screen_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: all security settings are good"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "askForPasswordDelay" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "defaults read" in cmd_str and "askForPassword" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "pmset -g" in cmd_str or cmd == ["pmset", "-g"]:
            return _make_subprocess_result(
                "Currently in use:\n"
                " sleep            5\n"
                " displaysleep     5\n"
                " disksleep        10\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_password():
    """Screensaver password not required"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "askForPasswordDelay" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "defaults read" in cmd_str and "askForPassword" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "pmset -g" in cmd_str or cmd == ["pmset", "-g"]:
            return _make_subprocess_result(
                "Currently in use:\n"
                " sleep            5\n"
                " displaysleep     5\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_long_delay():
    """Screensaver password delay is too long"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "askForPasswordDelay" in cmd_str:
            return _make_subprocess_result("300\n")
        elif "defaults read" in cmd_str and "askForPassword" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "pmset -g" in cmd_str or cmd == ["pmset", "-g"]:
            return _make_subprocess_result(
                "Currently in use:\n"
                " sleep            5\n"
                " displaysleep     5\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_display_never_sleeps():
    """Display never sleeps"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "askForPasswordDelay" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "defaults read" in cmd_str and "askForPassword" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "pmset -g" in cmd_str or cmd == ["pmset", "-g"]:
            return _make_subprocess_result(
                "Currently in use:\n"
                " sleep            5\n"
                " displaysleep     0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_issues():
    """Multiple security issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "askForPasswordDelay" in cmd_str:
            return _make_subprocess_result("120\n")
        elif "defaults read" in cmd_str and "askForPassword" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "pmset -g" in cmd_str or cmd == ["pmset", "-g"]:
            return _make_subprocess_result(
                "Currently in use:\n"
                " sleep            5\n"
                " displaysleep     0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_command_fails():
    """Commands fail (e.g., unavailable command)"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stderr="Command not found", returncode=1)
    return fake_run


def test_lock_screen_check_discovered():
    mod = _get_module()
    assert mod.name == "lock_screen_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_lock_screen_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_lock_screen_check_no_password():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_password()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "screensaver_password" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_lock_screen_check_long_delay():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_long_delay()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "screensaver_delay" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_lock_screen_check_display_never_sleeps():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_display_never_sleeps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "display_sleep" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_lock_screen_check_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) >= 3
    checks = {f.data.get("check") for f in result.findings}
    assert "screensaver_password" in checks
    assert "screensaver_delay" in checks
    assert "display_sleep" in checks


def test_lock_screen_check_command_fails_gracefully():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_fails()):
        result = mod.check(_make_profile())
    # Should not crash, may or may not have findings depending on graceful handling


def test_lock_screen_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be informational (SAFE risk level)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_lock_screen_check_fix_covers_all_findings():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_password()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Each finding should have a corresponding action
    assert len(fix.actions) == len(check.findings)
