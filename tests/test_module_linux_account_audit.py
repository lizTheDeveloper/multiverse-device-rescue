"""Tests for linux_account_audit.

The distinction that has to hold: an unreadable /etc/shadow reports "not
checked", never "no empty passwords found".
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "jane:x:1000:1000:Jane:/home/jane:/bin/bash\n"
)


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_account_audit")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Debian 12",
        os_version="6.1.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=2,
        ram_bytes=4 * 1024**3,
    )


def _configure(mod, tmp_path, passwd=PASSWD, shadow=None, group="", sudoers=None):
    (tmp_path / "passwd").write_text(passwd)
    mod.passwd_path = str(tmp_path / "passwd")
    if shadow is None:
        mod.shadow_path = str(tmp_path / "absent-shadow")
    else:
        (tmp_path / "shadow").write_text(shadow)
        mod.shadow_path = str(tmp_path / "shadow")
    (tmp_path / "group").write_text(group)
    mod.group_path = str(tmp_path / "group")
    if sudoers is None:
        mod.sudoers_path = str(tmp_path / "absent-sudoers")
    else:
        (tmp_path / "sudoers").write_text(sudoers)
        mod.sudoers_path = str(tmp_path / "sudoers")
    mod.sudoers_dir = str(tmp_path / "sudoers.d")
    return mod


def _no_commands(mod):
    def fake(args, **kwargs):
        return CommandResult(
            args=list(args), returncode=None, stdout="", stderr="",
            timed_out=False, error="not available", duration_s=0.0, truncated=False,
        )

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.DARWIN)).supported is False


def test_unreadable_passwd_is_an_error_not_a_clean_result(tmp_path):
    mod = _get_module()
    mod.passwd_path = str(tmp_path / "nope")
    with _no_commands(mod):
        result = mod.check(_profile())
    assert result.error is not None
    assert not result.has_issues


def test_second_uid0_account_is_critical(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        passwd=PASSWD + "backdoor:x:0:0::/root:/bin/bash\n",
    )
    with _no_commands(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("extra_uid0_account"))
    assert finding.severity is Severity.CRITICAL
    assert finding.data["account"] == "backdoor"


def test_root_itself_is_not_reported_as_an_extra_uid0(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    with _no_commands(mod):
        result = mod.check(_profile())
    assert "security.linux_account_audit.extra_uid0_account" not in _codes(result)


def test_unreadable_shadow_reports_not_checked(tmp_path):
    mod = _configure(_get_module(), tmp_path, shadow=None)
    with _no_commands(mod):
        result = mod.check(_profile())
    codes = _codes(result)
    assert "security.linux_account_audit.shadow_unreadable" in codes
    assert "security.linux_account_audit.empty_password" not in codes


def test_empty_password_on_a_loginable_account_is_critical(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        shadow="root:$6$hash:19000:0:99999:7:::\njane::19000:0:99999:7:::\n",
    )
    with _no_commands(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("empty_password"))
    assert finding.data["account"] == "jane"
    assert finding.severity is Severity.CRITICAL


def test_empty_password_on_a_nologin_system_account_is_ignored(tmp_path):
    """daemon has no password and no shell; reporting it would be noise."""
    mod = _configure(
        _get_module(), tmp_path,
        shadow="daemon::19000:0:99999:7:::\njane:$6$hash:19000:0:99999:7:::\n",
    )
    with _no_commands(mod):
        result = mod.check(_profile())
    assert "security.linux_account_audit.empty_password" not in _codes(result)


def test_nopasswd_sudo_rule_is_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        sudoers="root ALL=(ALL:ALL) ALL\njane ALL=(ALL) NOPASSWD: ALL\n",
    )
    with _no_commands(mod):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("passwordless_sudo"))
    assert finding.data["principal"] == "jane"


def test_commented_out_nopasswd_rule_is_not_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        sudoers="# jane ALL=(ALL) NOPASSWD: ALL\n",
    )
    with _no_commands(mod):
        result = mod.check(_profile())
    assert "security.linux_account_audit.passwordless_sudo" not in _codes(result)


def test_inventory_lists_admin_group_members(tmp_path):
    mod = _configure(_get_module(), tmp_path, group="sudo:x:27:jane\nusers:x:100:jane\n")
    with _no_commands(mod):
        result = mod.check(_profile())
    inventory = next(f for f in result.findings if f.code.endswith("admin_inventory"))
    assert inventory.data["admin_groups"]["sudo"] == ["jane"]
    assert inventory.severity is Severity.INFO


def test_fix_is_guidance_only(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        passwd=PASSWD + "backdoor:x:0:0::/root:/bin/bash\n",
    )
    with _no_commands(mod):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.actions
    assert fix.executed_mutations == []


# ---------------- offline: a Linux disk mounted elsewhere ----------------

from rescue.profiler.base import gather_target_profile  # noqa: E402


def _offline(linux_disk):
    return gather_target_profile(linux_disk, Platform.LINUX)


def test_account_audit_offline_reads_target_files(linux_disk):
    with open(linux_disk / "etc/passwd", "a") as f:
        f.write("toor:x:0:0::/root:/bin/bash\n")
    (linux_disk / "etc/sudoers.d").mkdir()
    (linux_disk / "etc/sudoers.d/90-sam").write_text("sam ALL=(ALL) NOPASSWD:ALL\n")
    result = _get_module().check(_offline(linux_disk))
    uid0 = [f for f in result.findings if f.data.get("check") == "extra_uid0_account"]
    assert [f.data["account"] for f in uid0] == ["toor"]
    sudo = [f for f in result.findings if f.data.get("check") == "passwordless_sudo"]
    assert sudo and sudo[0].data["path"] == "/etc/sudoers.d/90-sam"
    assert str(linux_disk) not in sudo[0].description


def test_account_audit_offline_ignores_host_files(linux_disk):
    result = _get_module().check(_offline(linux_disk))
    inv = next(f for f in result.findings if f.data.get("check") == "admin_inventory")
    assert set(inv.data["accounts"]) == {"root", "sam"}
    assert not any(f.data.get("check") == "extra_uid0_account" for f in result.findings)


def test_account_audit_offline_follows_symlinks_inside_the_disk(linux_disk):
    (linux_disk / "etc/passwd").unlink()
    (linux_disk / "real-passwd").write_text("root:x:0:0:r:/root:/bin/sh\nev:x:0:0::/:/bin/sh\n")
    (linux_disk / "etc/passwd").symlink_to("/real-passwd")
    result = _get_module().check(_offline(linux_disk))
    assert any(f.data.get("account") == "ev" for f in result.findings)


def test_account_audit_offline_missing_shadow_says_not_checked(linux_disk):
    result = _get_module().check(_offline(linux_disk))
    assert any(f.data.get("check") == "shadow_unreadable" for f in result.findings)


def test_account_audit_is_offline_capable():
    assert _get_module().offline_capable is True


_ADMIN_ONLY = "some files only an administrator can read"
_as_root = pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 1)() == 0, reason="root can read mode-000 files"
)


@_as_root
def test_account_audit_offline_unreadable_sudoers_d_is_not_checked(linux_disk):
    d = linux_disk / "etc/sudoers.d"
    d.mkdir()
    for name in ("10-a", "20-b"):
        (d / name).write_text("sam ALL=(ALL) NOPASSWD:ALL\n")
        (d / name).chmod(0)
    try:
        result = _get_module().check(_offline(linux_disk))
    finally:
        for name in ("10-a", "20-b"):
            (d / name).chmod(0o644)
    assert result.not_checked.count(_ADMIN_ONLY) == 1


def test_account_audit_offline_readable_disk_has_no_admin_only_entry(linux_disk):
    (linux_disk / "etc/sudoers.d").mkdir()
    (linux_disk / "etc/sudoers.d/10-a").write_text("# nothing\n")
    assert _ADMIN_ONLY not in _get_module().check(_offline(linux_disk)).not_checked
