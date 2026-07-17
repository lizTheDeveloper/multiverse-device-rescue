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
    return next(m for m in modules if m.name == "win_local_admin_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: only built-in Administrator, Guest disabled, 1 admin"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net localgroup Administrators" in cmd_str:
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
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "net user Administrator" in cmd_str:
            return _make_subprocess_result(
                "User name                    Administrator\n"
                "Full name\n"
                "Comment                      Built-in account for administering\n"
                "Account active               No\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
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

        if "net localgroup Administrators" in cmd_str:
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
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("True\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "net user Administrator" in cmd_str:
            return _make_subprocess_result(
                "User name                    Administrator\n"
                "Full name\n"
                "Comment                      Built-in account for administering\n"
                "Account active               No\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_builtin_admin_enabled():
    """Built-in Administrator account is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net localgroup Administrators" in cmd_str:
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
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("True\n")
        elif "net user Administrator" in cmd_str:
            return _make_subprocess_result(
                "User name                    Administrator\n"
                "Full name\n"
                "Comment                      Built-in account for administering\n"
                "Account active               Yes\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_excessive_admins():
    """More than 3 admin accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "alice\n"
                "bob\n"
                "carol\n"
                "dave\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "net user" in cmd_str:
            # Match any of the admin users
            return _make_subprocess_result(
                "User name                    testuser\n"
                "Full name\n"
                "Account active               Yes\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_blank_password():
    """Admin account with blank password"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "alice\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "net user Administrator" in cmd_str:
            return _make_subprocess_result(
                "User name                    Administrator\n"
                "Full name\n"
                "Comment                      Built-in account for administering\n"
                "Account active               No\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
            )
        elif "net user alice" in cmd_str:
            return _make_subprocess_result(
                "User name                    alice\n"
                "Full name\n"
                "Account active               Yes\n"
                "Password required            No\n"
                "Password never expires       No\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_password_never_expires():
    """Admin account with password never expires"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "net localgroup Administrators" in cmd_str:
            return _make_subprocess_result(
                "Alias name     Administrators\n"
                "Comment        Administrators have complete and unrestricted access\n"
                "\n"
                "Members\n"
                "-------------------------------------------------------\n"
                "Administrator\n"
                "bob\n"
                "-------------------------------------------------------\n"
                "The command completed successfully.\n"
            )
        elif "Get-LocalUser -Name Guest" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "Get-LocalUser -Name Administrator" in cmd_str:
            return _make_subprocess_result("False\n")
        elif "net user Administrator" in cmd_str:
            return _make_subprocess_result(
                "User name                    Administrator\n"
                "Full name\n"
                "Comment                      Built-in account for administering\n"
                "Account active               No\n"
                "Password required            Yes\n"
                "Password never expires       No\n"
            )
        elif "net user bob" in cmd_str:
            return _make_subprocess_result(
                "User name                    bob\n"
                "Full name\n"
                "Account active               Yes\n"
                "Password required            Yes\n"
                "Password never expires       Yes\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_win_local_admin_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_local_admin_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_win_local_admin_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should only have INFO about admin accounts, no warnings or criticals
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_local_admin_audit_guest_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.CRITICAL and f.data.get("check") == "guest_enabled"
        for f in result.findings
    )


def test_win_local_admin_audit_builtin_admin_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_builtin_admin_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "builtin_admin_enabled"
        for f in result.findings
    )


def test_win_local_admin_audit_excessive_admins():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_excessive_admins()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "excessive_admins"
        for f in result.findings
    )


def test_win_local_admin_audit_blank_password():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_blank_password()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.CRITICAL and f.data.get("check") == "blank_password"
        for f in result.findings
    )


def test_win_local_admin_audit_password_never_expires():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_password_never_expires()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.severity == Severity.WARNING and f.data.get("check") == "password_never_expires"
        for f in result.findings
    )


def test_win_local_admin_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
