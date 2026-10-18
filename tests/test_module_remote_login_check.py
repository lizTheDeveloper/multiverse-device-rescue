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
    return next(m for m in modules if m.name == "remote_login_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_disabled():
    """All remote services disabled (secure)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: Off\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: Off\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Key not found
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(returncode=1)  # Key not found
        return _make_subprocess_result()
    return fake_run


def _fake_run_ssh_enabled():
    """SSH enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: On\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: Off\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_screen_sharing_enabled():
    """Screen Sharing enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: Off\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: Off\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(stdout="ARD_AllLocalUsers = 1\n")
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_remote_management_enabled():
    """Remote Management enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: Off\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: Off\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(stdout="RemoteDesktop = 1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_remote_apple_events_enabled():
    """Remote Apple Events enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: Off\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: On\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_all_enabled():
    """All remote services enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemsetup" in cmd_str and "-getremotelogin" in cmd_str:
            return _make_subprocess_result(stdout="Remote Login: On\n")
        elif "systemsetup" in cmd_str and "-getremoteappleevents" in cmd_str:
            return _make_subprocess_result(stdout="Remote Apple Events: On\n")
        elif "defaults read" in cmd_str and "RemoteManagement" in cmd_str:
            return _make_subprocess_result(stdout="ARD_AllLocalUsers = 1\n")
        elif "defaults read" in cmd_str and "RemoteDesktop" in cmd_str:
            return _make_subprocess_result(stdout="RemoteDesktop = 1\n")
        return _make_subprocess_result()
    return fake_run


def test_remote_login_check_discovered():
    mod = _get_module()
    assert mod.name == "remote_login_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_remote_login_check_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())
    # Should have an INFO finding about all services being disabled
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_remote_login_check_ssh_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssh_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "ssh" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_remote_login_check_screen_sharing_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_sharing_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "screen_sharing" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_remote_login_check_remote_management_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_remote_management_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "remote_management" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_remote_login_check_remote_apple_events_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_remote_apple_events_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "remote_apple_events" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_remote_login_check_all_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for all 4 services
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 4


def test_remote_login_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ssh_enabled()):
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
    assert all(c.startswith("security.remote_login_check.") for c in declared)


# --- Review fix: Remote Login without admin (macOS 26.3.1) -----------------------
# systemsetup prints "You need administrator access..." to a non-admin user,
# which used to read as Remote Login "off" -- missing a Remote Login that's on.
# `launchctl print system/<label>` answers without admin.

_NO_ADMIN = "You need administrator access to run this tool... exiting!\n"


def _fake_macos26(loaded=(), print_fails=False):
    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["launchctl", "print"]:
            if print_fails:
                raise OSError("launchctl unavailable")
            label = cmd[2].split("/", 1)[1]
            if label in loaded:
                return _make_subprocess_result(f"system/{label} = {{\n\tstate = running\n}}\n")
            return _make_subprocess_result(
                f'Bad request.\nCould not find service "{label}" in domain for system\n',
                returncode=113)
        if cmd[0] == "systemsetup":
            return _make_subprocess_result(_NO_ADMIN)
        return _make_subprocess_result(returncode=1)
    return fake_run


def test_remote_login_on_is_seen_without_admin():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_macos26(loaded={"com.openssh.sshd"})):
        result = mod.check(_make_profile())
    assert any(f.code == "security.remote_login_check.ssh_enabled" for f in result.findings)


def test_remote_login_off_without_admin_is_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_macos26()):
        result = mod.check(_make_profile())
    assert [f.code for f in result.findings] == ["security.remote_login_check.all_disabled"]


def test_remote_login_unreadable_is_couldnt_check_not_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_macos26(print_fails=True)):
        result = mod.check(_make_profile())
    codes = [f.code for f in result.findings]
    assert codes == ["security.remote_login_check.remote_access_unknown"]
    assert result.findings[0].severity == Severity.INFO


def test_screen_sharing_daemon_loaded_is_reported():
    mod = _get_module()
    with patch("subprocess.run",
               side_effect=_fake_macos26(loaded={"com.apple.screensharing"})):
        result = mod.check(_make_profile())
    assert any(f.data.get("service") == "screen_sharing" for f in result.findings)
