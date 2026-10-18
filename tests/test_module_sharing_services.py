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
        elif cmd == ["cupsctl"]:
            # Real cupsctl output on macOS 26.3.1 (printer sharing off)
            share = "1" if printer_sharing_enabled else "0"
            result.stdout = (
                "_debug_logging=0\n_remote_admin=0\n_remote_any=0\n"
                f"_share_printers={share}\n_user_cancel_any=0\n"
            )
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


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.sharing_services.") for c in declared)


# --- Regression: macOS 26.3.1 ---------------------------------------------------
# Printer sharing used to be read from the AFP file server's prefs, which exist
# on most Macs, so "Printer Sharing is enabled" showed with cupsctl reporting
# _share_printers=0. The per-user screensharing helpers must not count either.

_LAUNCHCTL_USER_MACOS26 = (
    "PID\tStatus\tLabel\n"
    "-\t0\tcom.apple.screensharing.agent\n"
    "-\t0\tcom.apple.screensharing.menuextra\n"
    "812\t0\tcom.apple.screensharing.MessagesAgent\n"
)


def test_macos26_afp_prefs_do_not_mean_printer_sharing():
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if cmd == ["cupsctl"]:
            result.stdout = "_remote_admin=0\n_share_printers=0\n"
        elif cmd[0] == "defaults":
            result.stdout = '{\n    kerberosPrincipal = "REDACTED";\n}\n'
        elif "launchctl" in cmd:
            result.stdout = _LAUNCHCTL_USER_MACOS26
        else:
            result.stdout = "You need administrator access to run this tool... exiting!\n"
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    services = {f.data.get("service") for f in result.findings}
    assert "printer_sharing" not in services
    assert "screen_sharing" not in services
