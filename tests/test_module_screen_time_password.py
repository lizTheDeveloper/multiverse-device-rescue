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
    return next(m for m in modules if m.name == "screen_time_password")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


_ACCOUNTS = {
    "alice": ("502", "/bin/zsh", "/Users/alice"),
    "bob": ("503", "/bin/zsh", "/Users/bob"),
    "annhoward": ("501", "/bin/zsh", "/Users/annhoward"),
    "postgres": ("503", "/bin/bash", "/Library/PostgreSQL/17"),
    "daemon": ("1", "/usr/bin/false", "/var/root"),
}


def _dscl_account_read(cmd_str):
    """Fake `dscl . -read /Users/<u> UniqueID UserShell IsHidden NFSHomeDirectory`."""
    user = cmd_str.split("/Users/")[1].split()[0]
    if user not in _ACCOUNTS:
        return _make_subprocess_result(returncode=1)
    uid, shell, home = _ACCOUNTS[user]
    return _make_subprocess_result(
        stdout=f"NFSHomeDirectory: {home}\nUniqueID: {uid}\nUserShell: {shell}\n"
    )


def _fake_run_healthy():
    """Normal case: Screen Time enabled with passcode set, alice has parental controls"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "applicationaccess" in cmd_str:
            return _make_subprocess_result(stdout="some content\n")
        elif "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(stdout="root\n_api\nalice\n")
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(stdout="GroupMembership: root annhoward\n")
        elif "dscl" in cmd_str and "UniqueID" in cmd_str:
            return _dscl_account_read(cmd_str)
        elif "dscl" in cmd_str and "ParentalControls" in cmd_str:
            # alice has parental controls
            if "/Users/alice" in cmd_str:
                return _make_subprocess_result(stdout="ParentalControls: managed\n")
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_passcode():
    """Screen Time enabled but no passcode set"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Passcode not set
        elif "defaults read" in cmd_str and "applicationaccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(stdout="root\n_api\nalice\n")
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(stdout="GroupMembership: root annhoward\n")
        elif "dscl" in cmd_str and "UniqueID" in cmd_str:
            return _dscl_account_read(cmd_str)
        elif "dscl" in cmd_str and "ParentalControls" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_child_no_controls():
    """Child account exists without parental controls"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "defaults read" in cmd_str and "applicationaccess" in cmd_str:
            return _make_subprocess_result(stdout="some content\n")
        elif "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(stdout="root\n_api\nalice\nbob\n")
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(stdout="GroupMembership: root annhoward\n")
        elif "dscl" in cmd_str and "UniqueID" in cmd_str:
            return _dscl_account_read(cmd_str)
        elif "dscl" in cmd_str and "ParentalControls" in cmd_str:
            # No parental controls found for any user
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_disabled():
    """Screen Time disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "ScreenTimeEnabled" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Not enabled
        elif "defaults read" in cmd_str and "ScreenTimePasscodeSet" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "defaults read" in cmd_str and "applicationaccess" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(stdout="root\n_api\nalice\n")
        elif "dscl" in cmd_str and "/Groups/admin" in cmd_str:
            return _make_subprocess_result(stdout="GroupMembership: root annhoward\n")
        elif "dscl" in cmd_str and "UniqueID" in cmd_str:
            return _dscl_account_read(cmd_str)
        elif "dscl" in cmd_str and "ParentalControls" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_screen_time_password_discovered():
    """Test module is discovered with correct properties"""
    mod = _get_module()
    assert mod.name == "screen_time_password"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_screen_time_password_healthy():
    """Test healthy case: Screen Time enabled with passcode"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # No warnings expected in healthy case
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_screen_time_password_no_passcode():
    """Test warning when Screen Time enabled but no passcode"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_passcode()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "screen_time_no_passcode" and f.severity == Severity.WARNING
        for f in result.findings
    )


def test_screen_time_password_unmanaged_standard_accounts_not_child():
    """Ordinary standard accounts without controls are not 'child accounts'."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_child_no_controls()):
        result = mod.check(_make_profile())
    assert not any("child_account" in f.data.get("check", "") for f in result.findings)


def test_screen_time_password_admin_and_service_accounts_not_flagged():
    """Admin user and daemon/postgres service accounts never get child findings."""
    mod = _get_module()
    base = _fake_run_child_no_controls()

    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "dscl" in cmd_str and "-list /Users" in cmd_str:
            return _make_subprocess_result(stdout="root\ndaemon\nannhoward\npostgres\n")
        if "dscl" in cmd_str and "ParentalControls" in cmd_str:
            return _make_subprocess_result(stdout="ParentalControls: managed\n")
        return base(cmd, **kwargs)

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert not any("child_account" in f.data.get("check", "") for f in result.findings)


def test_screen_time_password_managed_standard_account_reported():
    mod = _get_module()
    base = _fake_run_child_no_controls()

    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "dscl" in cmd_str and "ParentalControls" in cmd_str and "/Users/bob" in cmd_str:
            return _make_subprocess_result(stdout="ParentalControls: managed\n")
        return base(cmd, **kwargs)

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert any(
        f.data.get("check") == "child_account_has_controls" and "bob" in f.title
        for f in result.findings
    )


def test_screen_time_password_disabled():
    """Test info when Screen Time is disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled()):
        result = mod.check(_make_profile())
    assert any(
        f.data.get("check") == "screen_time_disabled" for f in result.findings
    )


def test_screen_time_password_fix_is_informational():
    """Test fix() is informational and all actions succeed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_passcode()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
