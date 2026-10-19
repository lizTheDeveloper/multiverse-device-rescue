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


# Real `launchctl print system/<label>` output on macOS 26.3.1 (no admin).
_SYSTEM_LABELS = ("com.apple.screensharing", "com.apple.smbd", "com.openssh.sshd")


def _print_result(label, loaded):
    result = MagicMock()
    result.stderr = ""
    if loaded:
        result.returncode = 0
        result.stdout = f"system/{label} = {{\n\tactive count = 1\n\tpath = /System/Library/LaunchDaemons/x.plist\n\tstate = running\n}}\n"
    else:
        result.returncode = 113
        result.stdout = f'Bad request.\nCould not find service "{label}" in domain for system\n'
    return result


def _fake_run(
    launchctl_output="",
    ssh_enabled=False,
    printer_sharing_enabled=False,
):
    """Create a mock subprocess.run function.

    System daemons named in ``launchctl_output`` with a PID count as loaded
    (what ``launchctl print system/<label>`` would show); ``ssh_enabled``
    loads com.openssh.sshd. The user's ``launchctl list`` itself never lists
    system daemons, so it only carries user agents.
    """
    loaded = set()
    user_lines = []
    for line in launchctl_output.splitlines():
        parts = line.split()
        if parts and parts[-1] in _SYSTEM_LABELS:
            if parts[0] != "-":
                loaded.add(parts[-1])
        else:
            user_lines.append(line)
    if ssh_enabled:
        loaded.add("com.openssh.sshd")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        if cmd[:2] == ["launchctl", "print"]:
            label = cmd[2].split("/", 1)[1]
            return _print_result(label, label in loaded)
        if cmd == ["launchctl", "list"]:
            result.stdout = "\n".join(user_lines) + "\n"
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


def test_remote_login_read_without_admin():
    """Remote Login comes from `launchctl print system/com.openssh.sshd`;
    systemsetup (admin only) is never needed."""
    mod = _get_module()
    calls = []
    fake = _fake_run(ssh_enabled=True)

    def spy(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "systemsetup":
            raise AssertionError("systemsetup needs admin; must not be used")
        return fake(cmd, **kwargs)

    with patch("subprocess.run", side_effect=spy):
        result = mod.check(_make_profile())
    assert any(f.data.get("service") == "remote_login" for f in result.findings)
    assert ["launchctl", "print", "system/com.openssh.sshd"] in calls


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


# --- Review fixes: system daemons are on/off/unknown from launchctl print -------


def test_screen_and_file_sharing_on_are_reported():
    """The user's `launchctl list` never has these daemons; only `launchctl
    print system/<label>` can see them on."""
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["launchctl", "print"]:
            label = cmd[2].split("/", 1)[1]
            return _print_result(label, label in ("com.apple.screensharing", "com.apple.smbd"))
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = (_LAUNCHCTL_USER_MACOS26 if cmd == ["launchctl", "list"]
                         else "_share_printers=0\n")
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    services = {f.data.get("service") for f in result.findings}
    assert {"screen_sharing", "file_sharing"} <= services
    assert "remote_login" not in services


def test_all_sharing_off_on_macos26():
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["launchctl", "print"]:
            return _print_result(cmd[2].split("/", 1)[1], False)
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = (_LAUNCHCTL_USER_MACOS26 if cmd == ["launchctl", "list"]
                         else "_share_printers=0\n")
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert not result.findings


def test_unreadable_sharing_is_couldnt_check_not_off():
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        if cmd == ["cupsctl"] or cmd[:2] == ["launchctl", "print"]:
            raise OSError("not permitted")
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert [f.code for f in result.findings] == ["security.sharing_services.sharing_unknown"]
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["services"] == [
        "Screen Sharing", "File Sharing", "Remote Login", "Printer Sharing"]
