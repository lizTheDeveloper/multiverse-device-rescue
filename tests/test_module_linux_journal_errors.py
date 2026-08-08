"""Tests for linux_journal_errors.

The classification is the product here: hardware signals must be CRITICAL, a
single application segfault must stay quiet, and an unreadable journal must
report "not checked" instead of a clean result.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_journal_errors")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Debian 12",
        os_version="6.1.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _journal(mod, stdout="", returncode=0, error=None):
    def fake(args, **kwargs):
        return CommandResult(
            args=list(args), returncode=returncode, stdout=stdout, stderr="",
            timed_out=False, error=error, duration_s=0.01, truncated=False,
        )

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.DARWIN)).supported is False


def test_missing_journalctl_is_unsupported():
    mod = _get_module()
    with _journal(mod, error="No such file or directory"):
        result = mod.check(_profile())
    assert result.supported is False


def test_unreadable_journal_is_unsupported_not_healthy():
    """Non-root users cannot read the system journal on many distributions."""
    mod = _get_module()
    with _journal(mod, stdout="", returncode=1):
        result = mod.check(_profile())
    assert result.supported is False
    assert "sudo" in result.unsupported_reason


def test_quiet_journal_produces_no_findings():
    mod = _get_module()
    with _journal(mod, stdout="Jun 01 10:00:00 host systemd[1]: Started something.\n"):
        result = mod.check(_profile())
    assert not result.has_issues


def test_storage_io_errors_are_critical():
    mod = _get_module()
    lines = (
        "Jun 01 10:00:00 host kernel: blk_update_request: I/O error, dev sda, sector 12345\n"
        "Jun 01 10:00:01 host kernel: blk_update_request: I/O error, dev sda, sector 12346\n"
    )
    with _journal(mod, stdout=lines):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("storage_io_error"))
    assert finding.severity is Severity.CRITICAL
    assert finding.data["count"] == 2


def test_memory_errors_are_critical():
    mod = _get_module()
    with _journal(mod, stdout="Jun 01 10:00:00 host kernel: mce: [Hardware Error]: CPU 0\n"):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("memory_error"))
    assert finding.severity is Severity.CRITICAL


def test_filesystem_corruption_is_critical():
    mod = _get_module()
    line = "Jun 01 10:00:00 host kernel: EXT4-fs error (device sda1): htree_dirblock_to_tree\n"
    with _journal(mod, stdout=line):
        result = mod.check(_profile())
    assert "integrity.linux_journal_errors.filesystem_error" in _codes(result)


def test_oom_kills_are_reported_as_warnings():
    mod = _get_module()
    line = "Jun 01 10:00:00 host kernel: Out of memory: Killed process 1234 (firefox)\n"
    with _journal(mod, stdout=line):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("oom_kill"))
    assert finding.severity is Severity.WARNING


def test_a_single_segfault_is_not_reported():
    """One crash is an application bug, not a machine problem."""
    mod = _get_module()
    line = "Jun 01 10:00:00 host kernel: gedit[999]: segfault at 0 ip 00007f\n"
    with _journal(mod, stdout=line):
        result = mod.check(_profile())
    assert "integrity.linux_journal_errors.segfault" not in _codes(result)


def test_repeated_segfaults_are_reported():
    mod = _get_module()
    lines = "".join(
        f"Jun 01 10:00:0{i} host kernel: gedit[99{i}]: segfault at 0 ip 00007f\n"
        for i in range(4)
    )
    with _journal(mod, stdout=lines):
        result = mod.check(_profile())
    assert "integrity.linux_journal_errors.segfault" in _codes(result)


def test_repeated_identical_errors_are_grouped_in_the_sample():
    mod = _get_module()
    lines = "".join(
        f"Jun 01 10:00:00 host kernel: blk_update_request: I/O error, dev sda, sector {i}\n"
        for i in range(10)
    )
    with _journal(mod, stdout=lines):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("storage_io_error"))
    assert finding.data["count"] == 10
    # Sector numbers differ, so grouping only works if numbers are normalised.
    assert len(finding.data["samples"]) == 1


def test_fix_tells_you_to_back_up_before_diagnosing_a_failing_drive():
    mod = _get_module()
    line = "Jun 01 10:00:00 host kernel: blk_update_request: I/O error, dev sda, sector 1\n"
    with _journal(mod, stdout=line):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.executed_mutations == []
    assert "Back up" in fix.actions[0].title
