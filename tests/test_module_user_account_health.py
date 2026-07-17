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
    return next(m for m in modules if m.name == "user_account_health")


def _fake_run_healthy_accounts():
    """Mock subprocess for healthy user accounts."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "dscl" in cmd_str and "-list" in cmd_str and "/Users" in cmd_str:
            result.stdout = """testuser           500
admin_user         501
another_user       502
"""
        elif "dscl" in cmd_str and "-read" in cmd_str and "NFSHomeDirectory" in cmd_str:
            if "testuser" in cmd_str:
                result.stdout = "NFSHomeDirectory: /Users/testuser\n"
            elif "admin_user" in cmd_str:
                result.stdout = "NFSHomeDirectory: /Users/admin_user\n"
            else:
                result.stdout = ""
        elif "dscl" in cmd_str and "-read" in cmd_str and "UserShell" in cmd_str:
            result.stdout = "UserShell: /bin/zsh\n"
        elif "defaults" in cmd_str and "read" in cmd_str:
            result.stdout = "valid plist data"
            result.returncode = 0
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_duplicate_uids():
    """Mock subprocess for accounts with duplicate UIDs."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "dscl" in cmd_str and "-list" in cmd_str and "/Users" in cmd_str:
            result.stdout = """testuser           500
duplicate_user     500
another_user       502
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_missing_home_dir():
    """Mock subprocess for user with missing home directory."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "dscl" in cmd_str and "-list" in cmd_str and "/Users" in cmd_str:
            result.stdout = """testuser           500
"""
        elif "dscl" in cmd_str and "-read" in cmd_str and "NFSHomeDirectory" in cmd_str:
            result.stdout = "NFSHomeDirectory: /Users/testuser\n"
        elif "dscl" in cmd_str and "-read" in cmd_str and "UserShell" in cmd_str:
            result.stdout = "UserShell: /bin/zsh\n"
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_corrupted_preferences():
    """Mock subprocess for user with corrupted preferences."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "dscl" in cmd_str and "-list" in cmd_str and "/Users" in cmd_str:
            result.stdout = """testuser           500
"""
        elif "dscl" in cmd_str and "-read" in cmd_str and "NFSHomeDirectory" in cmd_str:
            result.stdout = "NFSHomeDirectory: /Users/testuser\n"
        elif "dscl" in cmd_str and "-read" in cmd_str and "UserShell" in cmd_str:
            result.stdout = "UserShell: /bin/zsh\n"
        elif "defaults" in cmd_str and "read" in cmd_str:
            result.returncode = 1
            result.stderr = "The domain/default pair of (file://..., GlobalPreferences) does not exist."
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_invalid_shell():
    """Mock subprocess for user with invalid shell."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "dscl" in cmd_str and "-list" in cmd_str and "/Users" in cmd_str:
            result.stdout = """testuser           500
"""
        elif "dscl" in cmd_str and "-read" in cmd_str and "NFSHomeDirectory" in cmd_str:
            result.stdout = "NFSHomeDirectory: /Users/testuser\n"
        elif "dscl" in cmd_str and "-read" in cmd_str and "UserShell" in cmd_str:
            result.stdout = "UserShell: /bin/invalid_shell\n"
        else:
            result.stdout = ""
        return result
    return fake_run


def test_user_account_health_discovered():
    mod = _get_module()
    assert mod.name == "user_account_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_user_account_health_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_accounts()):
        with patch("os.path.exists", return_value=True):
            with patch("os.environ.get", return_value="testuser"):
                with patch("os.path.expanduser", return_value="/Users/testuser"):
                    result = mod.check(_make_profile())
    # Should have INFO level finding about users found, no critical issues
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.data.get("check") == "user_accounts" for f in result.findings)


def test_user_account_health_duplicate_uids():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_duplicate_uids()):
        with patch("os.path.exists", return_value=True):
            with patch("os.environ.get", return_value=None):
                result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "duplicate_uid" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_user_account_health_missing_home_dir():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_missing_home_dir()):
        with patch("os.path.exists", return_value=False):
            with patch("os.environ.get", return_value="testuser"):
                result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "home_dir_missing" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_user_account_health_corrupted_preferences():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_corrupted_preferences()):
        with patch("os.path.exists", return_value=True):
            with patch("os.environ.get", return_value="testuser"):
                with patch("pathlib.Path.iterdir", return_value=[]):
                    result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "preferences_unreadable" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_user_account_health_invalid_shell():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_invalid_shell()):
        with patch("os.path.exists") as mock_exists:
            # /Users/testuser exists, but /bin/invalid_shell does not
            def exists_side_effect(path):
                if path == "/Users/testuser":
                    return True
                if "invalid_shell" in str(path):
                    return False
                return True
            mock_exists.side_effect = exists_side_effect
            with patch("os.environ.get", return_value="testuser"):
                with patch("pathlib.Path.iterdir", return_value=[]):
                    result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "shell_invalid" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_user_account_health_fix_duplicate_uids():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_duplicate_uids()):
        with patch("os.path.exists", return_value=True):
            with patch("os.environ.get", return_value=None):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_user_account_health_fix_missing_home_dir():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_missing_home_dir()):
        with patch("os.path.exists", return_value=False):
            with patch("os.environ.get", return_value="testuser"):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_user_account_health_fix_invalid_shell():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_invalid_shell()):
        with patch("os.path.exists") as mock_exists:
            def exists_side_effect(path):
                if path == "/Users/testuser":
                    return True
                if "invalid_shell" in str(path):
                    return False
                return True
            mock_exists.side_effect = exists_side_effect
            with patch("os.environ.get", return_value="testuser"):
                with patch("pathlib.Path.iterdir", return_value=[]):
                    check = mod.check(_make_profile())
                    fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
