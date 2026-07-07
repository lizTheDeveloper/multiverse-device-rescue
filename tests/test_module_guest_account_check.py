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
    return next(m for m in modules if m.name == "guest_account_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: Guest is disabled, no access to shared folders"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "guestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Key doesn't exist
        elif "AllowGuestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Key doesn't exist
        return _make_subprocess_result()
    return fake_run


def _fake_run_guest_enabled():
    """Guest account is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "guestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "AllowGuestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_guest_afp_access():
    """Guest has AFP file sharing access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "guestAccess" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "AllowGuestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_guest_smb_access():
    """Guest has SMB file sharing access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "guestAccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "AllowGuestAccess" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_all_guest_access():
    """All Guest access enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "GuestEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "guestAccess" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "AllowGuestAccess" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        return _make_subprocess_result()
    return fake_run


def test_guest_account_check_discovered():
    mod = _get_module()
    assert mod.name == "guest_account_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_guest_account_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert result.has_issues  # Should have INFO finding
    assert any(f.data.get("check") == "guest_disabled" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_guest_account_check_guest_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "guest_enabled" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_guest_account_check_guest_afp_access():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_afp_access()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "guest_afp_access" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_guest_account_check_guest_smb_access():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_guest_smb_access()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "guest_smb_access" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_guest_account_check_all_guest_access():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_guest_access()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) >= 3
    assert any(f.data.get("check") == "guest_enabled" for f in result.findings)
    assert any(f.data.get("check") == "guest_afp_access" for f in result.findings)
    assert any(f.data.get("check") == "guest_smb_access" for f in result.findings)


def test_guest_account_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_guest_access()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)
