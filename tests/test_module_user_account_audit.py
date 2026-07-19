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
    return next(m for m in modules if m.name == "user_account_audit")


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

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root\n_api\nalice\nbob\n_guest\n"
            )
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(
                "GroupMembership: root\n"
            )
        elif "defaults read" in cmd_str and "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "defaults read" in cmd_str and "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_guest_enabled():
    """Guest account is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root\n_api\nalice\nbob\n_guest\n"
            )
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(
                "GroupMembership: root alice\n"
            )
        elif "defaults read" in cmd_str and "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_auto_login():
    """Automatic login is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root\n_api\nalice\nbob\n_guest\n"
            )
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(
                "GroupMembership: root alice\n"
            )
        elif "defaults read" in cmd_str and "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "defaults read" in cmd_str and "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stdout="alice\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_admins():
    """Multiple admin accounts"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(
                "root\n_api\nalice\nbob\ncarol\n"
            )
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(
                "GroupMembership: root alice bob\n"
            )
        elif "defaults read" in cmd_str and "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "defaults read" in cmd_str and "autoLoginUser" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_user_account_audit_discovered():
    mod = _get_module()
    assert mod.name == "user_account_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_user_account_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_user_account_audit_guest_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "guest_enabled" for f in result.findings)


def test_user_account_audit_auto_login():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_auto_login()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "auto_login" for f in result.findings)


def test_user_account_audit_multiple_admins():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_admins()):
        result = mod.check(_make_profile())
    assert not result.has_issues or any(
        f.severity == Severity.INFO for f in result.findings
    )


def test_user_account_audit_fix_is_informational():
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
    assert all(c.startswith("security.user_account_audit.") for c in declared)
