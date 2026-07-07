import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_credential_guard")


def _make_run_result(
    credential_guard_enabled=False,
    windows_hello_configured=False,
    password_min_length=8,
    password_never_expire_users=None,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Check for Credential Guard registry query
        if "EnableVirtualizationBasedSecurity" in cmd_str:
            if credential_guard_enabled:
                result.stdout = (
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\n"
                    "    EnableVirtualizationBasedSecurity    REG_DWORD    0x1\n"
                )
            else:
                result.returncode = 1
                result.stdout = ""

        # Check for Windows Hello registry query
        elif "AllowSignInOptions" in cmd_str:
            if windows_hello_configured:
                result.stdout = (
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Settings\\AllowSignInOptions\n"
                    "    value    REG_DWORD    0x1\n"
                )
            else:
                result.returncode = 1
                result.stdout = ""

        # Check for password policy
        elif cmd[0] == "net" and len(cmd) > 1 and cmd[1] == "accounts":
            result.stdout = (
                "Force user logoff how long after time expires?:        Never\n"
                "Minimum password length:                        {}\n"
                "Password expires in:                            42 days\n"
                "Password inactive before forced logoff:         Never\n"
                "Lockout threshold:                              0\n"
            ).format(password_min_length)

        # Check for password never expires via PowerShell
        elif "powershell" in cmd_str and "PasswordNeverExpires" in cmd_str:
            if password_never_expire_users:
                result.stdout = "\n".join(password_never_expire_users) + "\n"
            else:
                result.stdout = ""

        return result

    return fake_run


def test_win_credential_guard_discovered():
    """Test that module is correctly discovered."""
    mod = _get_module()
    assert mod.name == "win_credential_guard"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_credential_guard_enabled():
    """Test when Credential Guard is enabled."""
    mod = _get_module()
    fake_run = _make_run_result(credential_guard_enabled=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # When credential guard is enabled, no finding should be present for it
    credential_guard_findings = [f for f in result.findings if f.data.get("check") == "credential_guard"]
    assert len(credential_guard_findings) == 0


def test_credential_guard_disabled():
    """Test when Credential Guard is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(credential_guard_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "credential_guard" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_windows_hello_configured():
    """Test when Windows Hello is configured."""
    mod = _get_module()
    fake_run = _make_run_result(windows_hello_configured=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "windows_hello" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_password_policy_sufficient_length():
    """Test when password minimum length meets requirement."""
    mod = _get_module()
    fake_run = _make_run_result(password_min_length=8)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # No finding for password length if it's >= 8
    password_findings = [f for f in result.findings if f.data.get("check") == "password_min_length"]
    assert len(password_findings) == 0


def test_password_policy_insufficient_length():
    """Test when password minimum length is below recommendation."""
    mod = _get_module()
    fake_run = _make_run_result(password_min_length=6)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "password_min_length" for f in result.findings)
    password_finding = [f for f in result.findings if f.data.get("check") == "password_min_length"][0]
    assert password_finding.severity == Severity.WARNING


def test_password_policy_no_minimum():
    """Test when password minimum length is 0."""
    mod = _get_module()
    fake_run = _make_run_result(password_min_length=0)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    password_findings = [f for f in result.findings if f.data.get("check") == "password_min_length"]
    assert len(password_findings) > 0
    assert password_findings[0].severity == Severity.WARNING


def test_password_never_expires_single_user():
    """Test when a single user has password set to never expire."""
    mod = _get_module()
    fake_run = _make_run_result(password_never_expire_users=["Administrator"])
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "password_never_expires" for f in result.findings)
    finding = [f for f in result.findings if f.data.get("check") == "password_never_expires"][0]
    assert finding.severity == Severity.WARNING
    assert "Administrator" in finding.data.get("users", [])


def test_password_never_expires_multiple_users():
    """Test when multiple users have passwords set to never expire."""
    mod = _get_module()
    users = ["Administrator", "Guest", "ServiceAccount"]
    fake_run = _make_run_result(password_never_expire_users=users)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = [f for f in result.findings if f.data.get("check") == "password_never_expires"][0]
    assert finding.severity == Severity.WARNING
    assert set(finding.data.get("users", [])) == set(users)


def test_password_never_expires_none():
    """Test when no users have passwords set to never expire."""
    mod = _get_module()
    fake_run = _make_run_result(password_never_expire_users=None)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # No finding for password never expires if none found
    never_expire_findings = [f for f in result.findings if f.data.get("check") == "password_never_expires"]
    assert len(never_expire_findings) == 0


def test_multiple_issues():
    """Test when multiple security issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        credential_guard_enabled=False,
        windows_hello_configured=False,
        password_min_length=4,
        password_never_expire_users=["Administrator"],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "credential_guard" in checks
    assert "password_min_length" in checks
    assert "password_never_expires" in checks


def test_all_secure():
    """Test when all security checks pass."""
    mod = _get_module()
    fake_run = _make_run_result(
        credential_guard_enabled=True,
        windows_hello_configured=True,
        password_min_length=12,
        password_never_expire_users=None,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have Windows Hello INFO finding
    assert any(f.data.get("check") == "windows_hello" for f in result.findings)
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_fix_credential_guard():
    """Test fix recommendations for disabled Credential Guard."""
    mod = _get_module()
    fake_run = _make_run_result(credential_guard_enabled=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    cred_guard_actions = [a for a in fix.actions if "credential guard" in a.title.lower()]
    assert len(cred_guard_actions) > 0
    assert "gpedit.msc" in cred_guard_actions[0].description


def test_fix_password_min_length():
    """Test fix recommendations for insufficient password length."""
    mod = _get_module()
    fake_run = _make_run_result(password_min_length=6)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    password_actions = [a for a in fix.actions if "password" in a.title.lower()]
    assert len(password_actions) > 0
    assert "8" in password_actions[0].description


def test_fix_password_never_expires():
    """Test fix recommendations for passwords that never expire."""
    mod = _get_module()
    users = ["Administrator", "Guest"]
    fake_run = _make_run_result(password_never_expire_users=users)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    expire_actions = [a for a in fix.actions if "expiration" in a.title.lower()]
    assert len(expire_actions) > 0


def test_fix_windows_hello():
    """Test fix recommendations for Windows Hello."""
    mod = _get_module()
    fake_run = _make_run_result(windows_hello_configured=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Windows Hello info should produce an informational action
    hello_actions = [a for a in fix.actions if "hello" in a.title.lower()]
    assert len(hello_actions) > 0
    assert hello_actions[0].success is True


def test_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_registry_query_not_found():
    """Test handling when registry keys are not found."""
    mod = _get_module()

    def not_found_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1  # Registry key not found
        result.stdout = ""
        result.stderr = "The system was unable to find the specified registry key or value."
        return result

    with patch("subprocess.run", side_effect=not_found_run):
        result = mod.check(_make_profile())
    # Should handle gracefully and report credential guard not enabled
    assert any(f.data.get("check") == "credential_guard" for f in result.findings)
