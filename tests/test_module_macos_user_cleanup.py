import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "macos_user_cleanup")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: active users, recent logins, reasonable sizes"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            # Return user list with UIDs
            return _make_subprocess_result(
                "root 0\nalice 501\nbob 502\nGuest 401\n_api 55\n"
            )
        elif "dscl" in cmd_str and "NFSHomeDirectory" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/alice\n")
            elif "bob" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/bob\n")
            else:
                return _make_subprocess_result("NFSHomeDirectory: /Users/root\n")
        elif "du -sk" in cmd_str:
            # Return small directory sizes (in 1K blocks)
            if "alice" in cmd_str:
                return _make_subprocess_result("5242880 /Users/alice\n")  # 5GB
            elif "bob" in cmd_str:
                return _make_subprocess_result("2097152 /Users/bob\n")  # 2GB
            else:
                return _make_subprocess_result("1024 /Users/root\n")
        elif "last" in cmd_str:
            if "alice" in cmd_str:
                # Alice logged in 30 days ago
                return _make_subprocess_result(
                    "alice    ttys000                   Dec  5 10:30   still logged in\n"
                )
            elif "bob" in cmd_str:
                # Bob logged in 7 days ago
                return _make_subprocess_result(
                    "bob      ttys001                   Dec 29 14:22   still logged in\n"
                )
            else:
                return _make_subprocess_result("root     console                      Dec 15 08:00 - 08:05  (00:05)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_unused_account():
    """Account with large home directory (>10GB) and old login"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root 0\nalice 501\njohnny 502\n_api 55\n"
            )
        elif "dscl" in cmd_str and "NFSHomeDirectory" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/alice\n")
            elif "johnny" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/johnny\n")
            else:
                return _make_subprocess_result("NFSHomeDirectory: /Users/root\n")
        elif "du -sk" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("5242880 /Users/alice\n")  # 5GB
            elif "johnny" in cmd_str:
                return _make_subprocess_result("11534336 /Users/johnny\n")  # 11GB (over 10GB threshold)
            else:
                return _make_subprocess_result("1024 /Users/root\n")
        elif "last" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result(
                    "alice    ttys000                   Dec  5 10:30   still logged in\n"
                )
            elif "johnny" in cmd_str:
                # Johnny hasn't logged in for 2 years
                return _make_subprocess_result("wtmp begins\n")
            else:
                return _make_subprocess_result("root     console                      Dec 15 08:00 - 08:05  (00:05)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_old_unused_account():
    """Account that hasn't been logged into in over 1 year"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root 0\nalice 501\nsarah 502\n_api 55\n"
            )
        elif "dscl" in cmd_str and "NFSHomeDirectory" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/alice\n")
            elif "sarah" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/sarah\n")
            else:
                return _make_subprocess_result("NFSHomeDirectory: /Users/root\n")
        elif "du -sk" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("5242880 /Users/alice\n")  # 5GB
            elif "sarah" in cmd_str:
                return _make_subprocess_result("3145728 /Users/sarah\n")  # 3GB (under 10GB threshold)
            else:
                return _make_subprocess_result("1024 /Users/root\n")
        elif "last" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result(
                    "alice    ttys000                   Dec  5 10:30   still logged in\n"
                )
            elif "sarah" in cmd_str:
                # Sarah hasn't logged in since 2 years ago
                return _make_subprocess_result("sarah    ttys001                   Dec 20 2024 09:15 - 09:45  (00:30)\n")
            else:
                return _make_subprocess_result("root     console                      Dec 15 08:00 - 08:05  (00:05)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_both_issues():
    """Account with both large size AND hasn't been logged in for 1+ year"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root 0\nalice 501\njohnny 502\n_api 55\n"
            )
        elif "dscl" in cmd_str and "NFSHomeDirectory" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/alice\n")
            elif "johnny" in cmd_str:
                return _make_subprocess_result("NFSHomeDirectory: /Users/johnny\n")
            else:
                return _make_subprocess_result("NFSHomeDirectory: /Users/root\n")
        elif "du -sk" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result("5242880 /Users/alice\n")  # 5GB
            elif "johnny" in cmd_str:
                return _make_subprocess_result("15728640 /Users/johnny\n")  # 15GB (way over 10GB)
            else:
                return _make_subprocess_result("1024 /Users/root\n")
        elif "last" in cmd_str:
            if "alice" in cmd_str:
                return _make_subprocess_result(
                    "alice    ttys000                   Dec  5 10:30   still logged in\n"
                )
            elif "johnny" in cmd_str:
                # Johnny last logged in 3 years ago
                return _make_subprocess_result("johnny   ttys001                   Nov 30 2023 15:22 - 16:00  (00:38)\n")
            else:
                return _make_subprocess_result("root     console                      Dec 15 08:00 - 08:05  (00:05)\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_users():
    """No user accounts found (edge case)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result("root 0\n_api 55\n")  # Only system users
        return _make_subprocess_result()
    return fake_run


def test_macos_user_cleanup_discovered():
    """Module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "macos_user_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_macos_user_cleanup_healthy():
    """Healthy case: active users with recent logins and reasonable sizes."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have an INFO finding with user summary, but no warnings
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0
    # Should have an INFO finding
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_macos_user_cleanup_large_unused_account():
    """Account with large home directory (>10GB) triggers WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_unused_account()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about large unused account
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any(f.data.get("type") == "large_unused_account" for f in warnings)


def test_macos_user_cleanup_old_unused_account():
    """Account not logged in for 1+ year triggers WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_unused_account()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about old unused account
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any(f.data.get("type") == "old_unused_account" for f in warnings)


def test_macos_user_cleanup_both_issues():
    """Account with both large size and old login triggers WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_both_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have at least one warning (could be both or one depending on logic)
    assert len(warnings) > 0


def test_macos_user_cleanup_no_users():
    """Edge case: no real user accounts found."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_users()):
        result = mod.check(_make_profile())
    # Should not have issues if no users found
    assert not result.has_issues


def test_macos_user_cleanup_fix_is_informational():
    """fix() method is informational and always succeeds."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_unused_account()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for warnings
    assert len(fix.actions) > 0


def test_macos_user_cleanup_fix_provides_guidance():
    """fix() provides helpful cleanup guidance."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_unused_account()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Actions should contain guidance about archiving or removing accounts
    action_texts = "\n".join([a.description for a in fix.actions])
    # Should mention archiving or removing options
    assert any(
        keyword in action_texts.lower()
        for keyword in ["archive", "backup", "remove", "delete"]
    )
