"""Tests for linux_account_audit.

The distinction that has to hold: an unreadable /etc/shadow reports "not
checked", never "no empty passwords found".
"""

import sys
from pathlib import Path
from unittest.mock import patch

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
