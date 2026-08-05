"""Tests for linux_service_health."""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_service_health")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Fedora 40",
        os_version="6.9.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _result(args, stdout="", returncode=0, error=None) -> CommandResult:
    return CommandResult(
        args=list(args), returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, error=error, duration_s=0.01, truncated=False,
    )


def _systemctl(mod, failed="", running="", restarts=0, time_active=True, available=True):
    def fake(args, **kwargs):
        if not available:
            return _result(args, error="No such file or directory")
        if args[1] == "list-units" and "--failed" in args:
            return _result(args, failed)
        if args[1] == "list-units":
            return _result(args, running)
        if args[1] == "is-active":
            unit = args[2]
            if unit.startswith(("systemd-timesyncd", "chronyd", "ntpd", "ntpsec")):
                return _result(args, "active" if time_active else "inactive")
            return _result(args, "active")
        if args[1] == "show":
            return _result(args, f"NRestarts={restarts}")
        return _result(args, "")

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.WIN32)).supported is False


def test_missing_systemctl_is_unsupported_not_healthy():
    """A non-systemd distribution gets an honest 'cannot check', not a pass."""
    mod = _get_module()
    with _systemctl(mod, available=False):
        result = mod.check(_profile())
    assert result.supported is False
    assert "systemd" in result.unsupported_reason


def test_healthy_system_produces_no_findings():
    mod = _get_module()
    with _systemctl(mod):
        result = mod.check(_profile())
    assert not result.has_issues


def test_failed_unit_is_reported():
    mod = _get_module()
    failed = "cups.service loaded failed failed CUPS Scheduler\n"
    with _systemctl(mod, failed=failed):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("failed_unit"))
    assert finding.data["unit"] == "cups.service"
    assert finding.severity is Severity.WARNING


def test_failed_backup_unit_is_escalated_to_critical():
    """A silently dead backup is the finding whose cost arrives months later."""
    mod = _get_module()
    failed = "restic-backup.service loaded failed failed Restic backup\n"
    with _systemctl(mod, failed=failed):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("failed_backup_unit"))
    assert finding.severity is Severity.CRITICAL


def test_restart_loop_is_reported():
    mod = _get_module()
    running = "flaky.service loaded active running Flaky thing\n"
    with _systemctl(mod, running=running, restarts=27):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("restart_loop"))
    assert finding.data["restarts"] == 27


def test_occasional_restarts_are_not_a_loop():
    mod = _get_module()
    running = "normal.service loaded active running Normal thing\n"
    with _systemctl(mod, running=running, restarts=1):
        result = mod.check(_profile())
    assert "integrity.linux_service_health.restart_loop" not in _codes(result)


def test_missing_time_sync_is_reported():
    mod = _get_module()
    with _systemctl(mod, time_active=False):
        result = mod.check(_profile())
    assert "integrity.linux_service_health.time_sync_inactive" in _codes(result)


def test_fix_is_guidance_only():
    mod = _get_module()
    with _systemctl(mod, failed="cups.service loaded failed failed CUPS\n"):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.actions
    assert fix.executed_mutations == []
