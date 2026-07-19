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
    return next(m for m in modules if m.name == "filevault_recovery")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_fv_disabled():
    """FileVault is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "fdesetup" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result("FileVault is Off.\n")
        elif "dscl" in cmd_str and "list /Users" in cmd_str:
            return _make_subprocess_result("root\nalice\nbob\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_fv_enabled_with_personal_key():
    """FileVault enabled with personal recovery key"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "fdesetup" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result("FileVault is On.\n")
        elif "fdesetup" in cmd_str and "haspersonalrecoverykey" in cmd_str:
            return _make_subprocess_result("Yes\n")
        elif "fdesetup" in cmd_str and "hasinstitutionalrecoverykey" in cmd_str:
            return _make_subprocess_result("No\n")
        elif "fdesetup" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result("alice,550e8400-e29b-41d4-a716-446655440000\nbob,660e8400-e29b-41d4-a716-446655440000\n")
        elif "dscl" in cmd_str and "list /Users" in cmd_str:
            return _make_subprocess_result("root\nalice\nbob\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_fv_enabled_no_recovery_key():
    """FileVault enabled but no recovery key exists (CRITICAL)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "fdesetup" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result("FileVault is On.\n")
        elif "fdesetup" in cmd_str and "haspersonalrecoverykey" in cmd_str:
            return _make_subprocess_result("No\n")
        elif "fdesetup" in cmd_str and "hasinstitutionalrecoverykey" in cmd_str:
            return _make_subprocess_result("No\n")
        elif "fdesetup" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result("alice,550e8400-e29b-41d4-a716-446655440000\n")
        elif "dscl" in cmd_str and "list /Users" in cmd_str:
            return _make_subprocess_result("root\nalice\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_fv_enabled_unknown_key_status():
    """FileVault enabled but recovery key status cannot be determined"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "fdesetup" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result("FileVault is On.\n")
        elif "fdesetup" in cmd_str and "haspersonalrecoverykey" in cmd_str:
            return _make_subprocess_result("Unknown error\n", returncode=1)
        elif "fdesetup" in cmd_str and "hasinstitutionalrecoverykey" in cmd_str:
            return _make_subprocess_result("No\n")
        elif "fdesetup" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result("alice,550e8400-e29b-41d4-a716-446655440000\n")
        elif "dscl" in cmd_str and "list /Users" in cmd_str:
            return _make_subprocess_result("root\nalice\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_fv_enabled_not_all_users():
    """FileVault enabled but not all users are FileVault-enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "fdesetup" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result("FileVault is On.\n")
        elif "fdesetup" in cmd_str and "haspersonalrecoverykey" in cmd_str:
            return _make_subprocess_result("Yes\n")
        elif "fdesetup" in cmd_str and "hasinstitutionalrecoverykey" in cmd_str:
            return _make_subprocess_result("No\n")
        elif "fdesetup" in cmd_str and "list" in cmd_str:
            # Only alice is FileVault-enabled
            return _make_subprocess_result("alice,550e8400-e29b-41d4-a716-446655440000\n")
        elif "dscl" in cmd_str and "list /Users" in cmd_str:
            # But both alice and bob exist
            return _make_subprocess_result("root\nalice\nbob\n")
        return _make_subprocess_result()
    return fake_run


def test_filevault_recovery_discovered():
    mod = _get_module()
    assert mod.name == "filevault_recovery"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_filevault_recovery_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_disabled()):
        result = mod.check(_make_profile())
    # Should have INFO findings
    assert any(f.data.get("check") == "fv_disabled" for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_filevault_recovery_enabled_with_personal_key():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_enabled_with_personal_key()):
        result = mod.check(_make_profile())
    # Should have INFO status finding, no CRITICAL or WARNING
    assert any(f.severity == Severity.INFO and f.data.get("check") == "fv_status" for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_filevault_recovery_enabled_no_key():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_enabled_no_recovery_key()):
        result = mod.check(_make_profile())
    # Should have CRITICAL finding
    assert any(f.severity == Severity.CRITICAL and f.data.get("check") == "no_recovery_key" for f in result.findings)


def test_filevault_recovery_unknown_key_status():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_enabled_unknown_key_status()):
        result = mod.check(_make_profile())
    # Should have WARNING finding
    assert any(f.severity == Severity.WARNING and f.data.get("check") == "recovery_key_unknown" for f in result.findings)


def test_filevault_recovery_not_all_users_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_enabled_not_all_users()):
        result = mod.check(_make_profile())
    # Should have WARNING finding about disabled users
    assert any(f.severity == Severity.WARNING and f.data.get("check") == "users_not_all_enabled" for f in result.findings)
    # Should also have INFO status
    assert any(f.severity == Severity.INFO and f.data.get("check") == "fv_status" for f in result.findings)


def test_filevault_recovery_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fv_enabled_no_recovery_key()):
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
    assert all(c.startswith("security.filevault_recovery.") for c in declared)
