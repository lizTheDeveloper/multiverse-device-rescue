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
    return next(m for m in modules if m.name == "sharing_services")


def _fake_run(
    launchctl_output="",
    ssh_enabled=False,
    printer_sharing_enabled=False,
):
    """Create a mock subprocess.run function."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        # cmd is a list, so check elements directly
        if "launchctl" in cmd and "list" in cmd:
            result.stdout = launchctl_output
        elif "systemsetup" in cmd and "-getremotelogin" in cmd:
            if ssh_enabled:
                result.stdout = "Remote Login: On\n"
            else:
                result.stdout = "Remote Login: Off\n"
        elif "defaults" in cmd and "read" in cmd:
            # Check if guestAccess is in the command
            has_guest_access = any("guestAccess" in str(arg) for arg in cmd)
            if has_guest_access:
                if printer_sharing_enabled:
                    result.stdout = "1\n"
                    result.returncode = 0
                else:
                    result.returncode = 1
                    result.stderr = "The specified key CFBundleIdentifier does not exist"
            else:
                # This is the second defaults read without guestAccess
                if printer_sharing_enabled:
                    result.stdout = "{\n    guestAccess = 1;\n}\n"
                    result.returncode = 0
                else:
                    result.returncode = 1
                    result.stderr = "The specified key CFBundleIdentifier does not exist"
        return result

    return fake_run


def test_sharing_services_discovered():
    mod = _get_module()
    assert mod.name == "sharing_services"
    assert mod.risk_level == RiskLevel.SAFE


def test_sharing_services_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output="")):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_sharing_services_screen_sharing_enabled():
    mod = _get_module()
    launchctl_output = (
        "   500  0 com.apple.screensharing\n"
        "   501  0 com.apple.smbd\n"
    )
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output=launchctl_output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "screen_sharing" for f in result.findings)
    assert any(f.data.get("service") == "file_sharing" for f in result.findings)


def test_sharing_services_ssh_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ssh_enabled=True)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "remote_login" for f in result.findings)


def test_sharing_services_printer_sharing_enabled():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(printer_sharing_enabled=True),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "printer_sharing" for f in result.findings)


def test_sharing_services_remote_management_enabled():
    mod = _get_module()
    launchctl_output = "   502  0 com.apple.RemoteDesktop.agent\n"
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output=launchctl_output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "remote_management" for f in result.findings)


def test_sharing_services_all_enabled():
    mod = _get_module()
    launchctl_output = (
        "   500  0 com.apple.screensharing\n"
        "   501  0 com.apple.smbd\n"
        "   502  0 com.apple.RemoteDesktop.agent\n"
    )
    with patch(
        "subprocess.run",
        side_effect=_fake_run(
            launchctl_output=launchctl_output,
            ssh_enabled=True,
            printer_sharing_enabled=True,
        ),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 5
    assert all(f.severity == Severity.WARNING for f in result.findings)


def test_sharing_services_fix_informational():
    mod = _get_module()
    launchctl_output = (
        "   500  0 com.apple.screensharing\n"
        "   501  0 com.apple.smbd\n"
    )
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output=launchctl_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed because it's informational
    assert fix.all_succeeded
    assert len(fix.actions) == 2
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_sharing_services_fix_contains_instructions():
    mod = _get_module()
    launchctl_output = "   500  0 com.apple.screensharing\n"
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output=launchctl_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) == 1
    assert "System Settings" in fix.actions[0].description
    assert "Screen Sharing" in fix.actions[0].description


def test_sharing_services_ssh_fallback_to_launchctl():
    """Test SSH check falls back to launchctl if systemsetup fails."""
    mod = _get_module()

    def fake_run_with_failure(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        if "systemsetup" in cmd:
            # systemsetup fails
            raise OSError("systemsetup not found")
        elif "launchctl" in cmd:
            # But launchctl shows SSH is enabled
            result.stdout = "   500  0 com.apple.sshd\n"
        return result

    with patch("subprocess.run", side_effect=fake_run_with_failure):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "remote_login" for f in result.findings)


def test_sharing_services_launchctl_format_handling():
    """Test correct handling of launchctl output format."""
    mod = _get_module()
    # Services with "-" in the PID column are not running
    launchctl_output = (
        "   -  0 com.apple.screensharing\n"
        "   500  0 com.apple.smbd\n"
    )
    with patch("subprocess.run", side_effect=_fake_run(launchctl_output=launchctl_output)):
        result = mod.check(_make_profile())
    # Only smbd should be reported as enabled
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].data.get("service") == "file_sharing"
