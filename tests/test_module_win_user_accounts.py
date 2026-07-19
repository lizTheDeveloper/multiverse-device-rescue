import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10.0.19045",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_user_accounts")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no issues found"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net user" in cmd_str and "Guest" not in cmd_str and "Administrators" not in cmd_str:
            return _make_subprocess_result(
                "User accounts for \\\\DESKTOP-ABC123\n"
                "-------------------------------------------------------\n"
                "Administrator        alice                 bob\n"
                "Guest                 carol\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net user Guest" in cmd_str:
            return _make_subprocess_result(
                "User name                    Guest\n"
                "Full name\n"
                "Comment                      Built-in account for guest access\n"
                "User's comment\n"
                "Country/region code          000 (System Default)\n"
                "Account active               No\n"
                "Account expires              Never\n"
            )
        elif "net accounts" in cmd_str:
            return _make_subprocess_result(
                "Force user logoff how long after time expires?       Never\n"
                "Minimum password age (days)                           1\n"
                "Maximum password age (days)                          42\n"
                "Minimum password length                               8\n"
                "Length of password history maintained                 0\n"
                "Lockout threshold                                     5\n"
                "Lockout duration (minutes)                           30\n"
                "Lockout observation window (minutes)                 30\n"
            )
        elif "reg query" in cmd_str and "AutoAdminLogon" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    AutoAdminLogon    REG_SZ    0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_guest_enabled():
    """Guest account is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net user" in cmd_str and "Guest" not in cmd_str and "Administrators" not in cmd_str:
            return _make_subprocess_result(
                "User accounts for \\\\DESKTOP-ABC123\n"
                "-------------------------------------------------------\n"
                "Administrator        alice                 bob\n"
                "Guest                 carol\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net user Guest" in cmd_str:
            return _make_subprocess_result(
                "User name                    Guest\n"
                "Full name\n"
                "Comment                      Built-in account for guest access\n"
                "User's comment\n"
                "Country/region code          000 (System Default)\n"
                "Account active               Yes\n"
                "Account expires              Never\n"
            )
        elif "net accounts" in cmd_str:
            return _make_subprocess_result(
                "Force user logoff how long after time expires?       Never\n"
                "Minimum password age (days)                           1\n"
                "Maximum password age (days)                          42\n"
                "Minimum password length                               8\n"
                "Length of password history maintained                 0\n"
                "Lockout threshold                                     5\n"
                "Lockout duration (minutes)                           30\n"
                "Lockout observation window (minutes)                 30\n"
            )
        elif "reg query" in cmd_str and "AutoAdminLogon" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    AutoAdminLogon    REG_SZ    0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_auto_login():
    """Automatic login is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net user" in cmd_str and "Guest" not in cmd_str and "Administrators" not in cmd_str:
            return _make_subprocess_result(
                "User accounts for \\\\DESKTOP-ABC123\n"
                "-------------------------------------------------------\n"
                "Administrator        alice                 bob\n"
                "Guest                 carol\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net user Guest" in cmd_str:
            return _make_subprocess_result(
                "User name                    Guest\n"
                "Full name\n"
                "Comment                      Built-in account for guest access\n"
                "User's comment\n"
                "Country/region code          000 (System Default)\n"
                "Account active               No\n"
                "Account expires              Never\n"
            )
        elif "net accounts" in cmd_str:
            return _make_subprocess_result(
                "Force user logoff how long after time expires?       Never\n"
                "Minimum password age (days)                           1\n"
                "Maximum password age (days)                          42\n"
                "Minimum password length                               8\n"
                "Length of password history maintained                 0\n"
                "Lockout threshold                                     5\n"
                "Lockout duration (minutes)                           30\n"
                "Lockout observation window (minutes)                 30\n"
            )
        elif "reg query" in cmd_str and "AutoAdminLogon" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    AutoAdminLogon    REG_SZ    0x1\n"
            )
        elif "reg query" in cmd_str and "DefaultUserName" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    DefaultUserName    REG_SZ    alice\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_admins():
    """Multiple admin accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net user" in cmd_str and "Guest" not in cmd_str and "Administrators" not in cmd_str:
            return _make_subprocess_result(
                "User accounts for \\\\DESKTOP-ABC123\n"
                "-------------------------------------------------------\n"
                "Administrator        alice                 bob\n"
                "Guest                 carol\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "alice\n"
                "bob\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net user Guest" in cmd_str:
            return _make_subprocess_result(
                "User name                    Guest\n"
                "Full name\n"
                "Comment                      Built-in account for guest access\n"
                "User's comment\n"
                "Country/region code          000 (System Default)\n"
                "Account active               No\n"
                "Account expires              Never\n"
            )
        elif "net accounts" in cmd_str:
            return _make_subprocess_result(
                "Force user logoff how long after time expires?       Never\n"
                "Minimum password age (days)                           1\n"
                "Maximum password age (days)                          42\n"
                "Minimum password length                               8\n"
                "Length of password history maintained                 0\n"
                "Lockout threshold                                     5\n"
                "Lockout duration (minutes)                           30\n"
                "Lockout observation window (minutes)                 30\n"
            )
        elif "reg query" in cmd_str and "AutoAdminLogon" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    AutoAdminLogon    REG_SZ    0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_weak_password_policy():
    """Weak password policy (no minimum length)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net user" in cmd_str and "Guest" not in cmd_str and "Administrators" not in cmd_str:
            return _make_subprocess_result(
                "User accounts for \\\\DESKTOP-ABC123\n"
                "-------------------------------------------------------\n"
                "Administrator        alice                 bob\n"
                "Guest                 carol\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "net user Guest" in cmd_str:
            return _make_subprocess_result(
                "User name                    Guest\n"
                "Full name\n"
                "Comment                      Built-in account for guest access\n"
                "User's comment\n"
                "Country/region code          000 (System Default)\n"
                "Account active               No\n"
                "Account expires              Never\n"
            )
        elif "net accounts" in cmd_str:
            return _make_subprocess_result(
                "Force user logoff how long after time expires?       Never\n"
                "Minimum password age (days)                           1\n"
                "Maximum password age (days)                          42\n"
                "Minimum password length                               0\n"
                "Length of password history maintained                 0\n"
                "Lockout threshold                                     5\n"
                "Lockout duration (minutes)                           30\n"
                "Lockout observation window (minutes)                 30\n"
            )
        elif "reg query" in cmd_str and "AutoAdminLogon" in cmd_str:
            return _make_subprocess_result(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
                "    AutoAdminLogon    REG_SZ    0\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_win_user_accounts_discovered():
    mod = _get_module()
    assert mod.name == "win_user_accounts"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_win_user_accounts_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_user_accounts_guest_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "guest_enabled" for f in result.findings)


def test_win_user_accounts_auto_login():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_auto_login()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "auto_login" for f in result.findings)


def test_win_user_accounts_multiple_admins():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_admins()):
        result = mod.check(_make_profile())
    assert not result.has_issues or any(
        f.severity == Severity.INFO for f in result.findings
    )


def test_win_user_accounts_weak_password_policy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_weak_password_policy()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "password_policy" for f in result.findings)


def test_win_user_accounts_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_user_accounts.") for c in declared)
