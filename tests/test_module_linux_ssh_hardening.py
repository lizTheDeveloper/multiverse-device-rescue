"""Tests for linux_ssh_hardening.

Two properties matter: the severity of a permissive setting depends on whether
sshd is actually running, and a machine with no SSH server at all produces no
findings rather than a pile of them.
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
    return next(m for m in modules if m.name == "linux_ssh_hardening")


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


def _result(args, stdout="", returncode=0, error=None) -> CommandResult:
    return CommandResult(
        args=list(args),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        timed_out=False,
        error=error,
        duration_s=0.01,
        truncated=False,
    )


def _patched(mod, sshd_t=None, running=False):
    def fake(args, **kwargs):
        if args[0] == "sshd" and sshd_t is not None:
            return _result(args, sshd_t)
        if args[0] == "systemctl":
            return _result(args, "active" if running else "inactive")
        return _result(args, error="No such file or directory")

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    result = _get_module().check(_profile(Platform.WIN32))
    assert result.supported is False


def test_no_sshd_config_means_no_findings(tmp_path):
    """No SSH server installed is not a hardening problem."""
    mod = _get_module()
    mod.sshd_config_path = str(tmp_path / "absent")
    with _patched(mod):
        result = mod.check(_profile())
    assert not result.has_issues


def test_root_login_yes_while_running_is_critical():
    mod = _get_module()
    config = "permitrootlogin yes\npasswordauthentication no\npermitemptypasswords no\n"
    with _patched(mod, sshd_t=config, running=True):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("root_login_permitted"))
    assert finding.severity is Severity.CRITICAL


def test_root_login_yes_while_stopped_is_only_a_warning():
    """Exposure changes severity: a stopped server is latent, not open."""
    mod = _get_module()
    config = "permitrootlogin yes\npasswordauthentication no\npermitemptypasswords no\n"
    with _patched(mod, sshd_t=config, running=False):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("root_login_permitted"))
    assert finding.severity is Severity.WARNING


def test_key_only_root_login_is_informational():
    mod = _get_module()
    config = "permitrootlogin prohibit-password\npasswordauthentication no\n"
    with _patched(mod, sshd_t=config, running=True):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("root_login_permitted"))
    assert finding.severity is Severity.INFO


def test_password_authentication_is_flagged():
    mod = _get_module()
    with _patched(mod, sshd_t="passwordauthentication yes\n", running=True):
        result = mod.check(_profile())
    assert "security.linux_ssh_hardening.password_auth_enabled" in _codes(result)


def test_empty_passwords_are_critical_regardless_of_state():
    mod = _get_module()
    with _patched(mod, sshd_t="permitemptypasswords yes\n", running=False):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("empty_passwords_permitted"))
    assert finding.severity is Severity.CRITICAL


def test_hardened_config_produces_no_findings():
    mod = _get_module()
    config = (
        "permitrootlogin no\npasswordauthentication no\n"
        "kbdinteractiveauthentication no\npermitemptypasswords no\n"
        "listenaddress 192.168.1.10\n"
    )
    with _patched(mod, sshd_t=config, running=True):
        result = mod.check(_profile())
    assert not result.has_issues


def test_falls_back_to_the_config_file_with_lower_confidence(tmp_path):
    mod = _get_module()
    config_file = tmp_path / "sshd_config"
    config_file.write_text("# comment\nPermitRootLogin yes\n")
    mod.sshd_config_path = str(config_file)
    with _patched(mod, sshd_t=None, running=True):
        result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("root_login_permitted"))
    assert finding.confidence is not None and finding.confidence < 0.95
    assert finding.data["source"] == str(config_file)


def test_fix_is_guidance_only_and_warns_about_lockout():
    mod = _get_module()
    with _patched(mod, sshd_t="permitrootlogin yes\npasswordauthentication yes\n", running=True):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.executed_mutations == []
    assert any("lock" in a.description.lower() for a in fix.actions)


# ---------------- offline: a Linux disk mounted elsewhere ----------------

from rescue.profiler.base import gather_target_profile  # noqa: E402


def _offline(linux_disk):
    return gather_target_profile(linux_disk, Platform.LINUX)


def _no_host_commands(mod):
    return patch.object(
        sys.modules[type(mod).__module__], "run",
        side_effect=AssertionError("no host commands offline"),
    )


def _root_finding(r):
    return next(f for f in r.findings if "root logins" in f.title)


def test_ssh_offline_reads_target_config_and_include(linux_disk):
    ssh = linux_disk / "etc/ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    (ssh / "sshd_config").write_text("Include sshd_config.d/*.conf\n")
    (ssh / "sshd_config.d/50-x.conf").write_text("PermitRootLogin yes\n")
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    f = _root_finding(r)
    assert "set to start automatically" in f.description
    assert f.data["source"] == "/etc/ssh/sshd_config on the checked disk"
    assert r.not_checked == ["whether SSH was running"]


def test_ssh_offline_not_enabled_sentence(linux_disk):
    (linux_disk / "etc/systemd/system/multi-user.target.wants/ssh.service").unlink()
    (linux_disk / "etc/ssh").mkdir(parents=True)
    (linux_disk / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    assert "isn't set to start automatically" in _root_finding(r).description


def test_ssh_offline_sshd_service_name_counts(linux_disk):
    wants = linux_disk / "etc/systemd/system/multi-user.target.wants"
    (wants / "ssh.service").unlink()
    (wants / "sshd.service").symlink_to("/nowhere/sshd.service")
    (linux_disk / "etc/ssh").mkdir(parents=True)
    (linux_disk / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    assert "set to start automatically" in _root_finding(r).description


def test_ssh_offline_no_config_is_no_findings(linux_disk):
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    assert r.findings == []
    assert r.not_checked == ["whether SSH was running"]


def test_ssh_offline_include_loop_is_bounded(linux_disk):
    ssh = linux_disk / "etc/ssh"
    ssh.mkdir(parents=True)
    (ssh / "sshd_config").write_text("Include /etc/ssh/sshd_config\nInclude /etc/ssh/a.conf\n")
    (ssh / "a.conf").write_text("Include sshd_config\nPasswordAuthentication yes\n")
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    assert "security.linux_ssh_hardening.password_auth_enabled" in _codes(r)


def test_ssh_offline_include_cap(linux_disk):
    ssh = linux_disk / "etc/ssh"
    (ssh / "d").mkdir(parents=True)
    (ssh / "sshd_config").write_text("Include d/*.conf\n")
    for i in range(70):
        (ssh / "d" / f"{i:03d}.conf").write_text("PermitEmptyPasswords no\n")
    (ssh / "d" / "999.conf").write_text("PermitEmptyPasswords yes\n")
    mod = _get_module()
    with _no_host_commands(mod):
        r = mod.check(_offline(linux_disk))
    assert "security.linux_ssh_hardening.empty_passwords_permitted" not in _codes(r)


def _write_ssh(disk, main, dropins=None):
    ssh = disk / "etc/ssh"
    (ssh / "sshd_config.d").mkdir(parents=True, exist_ok=True)
    (ssh / "sshd_config").write_text(main)
    for name, text in (dropins or {}).items():
        (ssh / "sshd_config.d" / name).write_text(text)


def _run_offline(disk):
    mod = _get_module()
    with _no_host_commands(mod):
        return mod.check(_offline(disk))


def test_ssh_offline_password_auth_copy_says_starts_automatically(linux_disk):
    _write_ssh(linux_disk, "PasswordAuthentication yes\n")
    f = next(f for f in _run_offline(linux_disk).findings if "password logins" in f.title)
    assert "set to start automatically" in f.description
    assert "currently active" not in f.description
    (linux_disk / "etc/systemd/system/multi-user.target.wants/ssh.service").unlink()
    f = next(f for f in _run_offline(linux_disk).findings if "password logins" in f.title)
    assert "isn't set to start automatically" in f.description


def test_ssh_offline_listening_copy_makes_no_runtime_claim(linux_disk):
    _write_ssh(linux_disk, "PermitRootLogin no\n")
    f = next(f for f in _run_offline(linux_disk).findings if "open to all" in f.title)
    assert "bound" not in f.description
    assert "once SSH starts" in f.description


def test_ssh_offline_data_has_sshd_enabled_not_running(linux_disk):
    _write_ssh(linux_disk, "PermitRootLogin yes\nPasswordAuthentication yes\n")
    checked = 0
    for f in _run_offline(linux_disk).findings:
        if f.data["check"] in ("root_login_permitted", "password_auth_enabled"):
            checked += 1
            assert f.data["sshd_enabled"] is True
            assert "sshd_running" not in f.data
    assert checked == 2


def test_ssh_offline_main_setting_before_include_wins(linux_disk):
    _write_ssh(linux_disk, "PermitRootLogin no\nInclude sshd_config.d/*.conf\n",
               {"50-x.conf": "PermitRootLogin yes\n"})
    assert not [f for f in _run_offline(linux_disk).findings if "root logins" in f.title]


def test_ssh_offline_first_dropin_wins(linux_disk):
    _write_ssh(linux_disk, "Include sshd_config.d/*.conf\n",
               {"00-a.conf": "PermitRootLogin yes\n", "99-b.conf": "PermitRootLogin no\n"})
    assert [f for f in _run_offline(linux_disk).findings if "root logins" in f.title]
    _write_ssh(linux_disk, "Include sshd_config.d/*.conf\n",
               {"00-a.conf": "PermitRootLogin no\n", "99-b.conf": "PermitRootLogin yes\n"})
    assert not [f for f in _run_offline(linux_disk).findings if "root logins" in f.title]


def test_ssh_offline_symlink_loop_config_does_not_raise(linux_disk):
    ssh = linux_disk / "etc/ssh"
    ssh.mkdir(parents=True)
    (ssh / "sshd_config").symlink_to("/etc/ssh/sshd_config")
    r = _run_offline(linux_disk)
    assert r.not_checked == ["whether SSH was running"]


def _root_open(disk):
    return [f for f in _run_offline(disk).findings if "root logins" in f.title]


def test_ssh_offline_early_match_block_does_not_mask_later_global_yes(linux_disk):
    _write_ssh(linux_disk, "Include sshd_config.d/*.conf\nPermitRootLogin yes\n",
               {"00-match.conf": "Match User backup\n    PermitRootLogin no\n"})
    assert _root_open(linux_disk)
    # In the main file too: the Match block runs to the end of the file.
    _write_ssh(linux_disk, "Match User x\n  PermitRootLogin no\n")
    assert not _root_open(linux_disk)
    _write_ssh(linux_disk, "Match User x\n  PermitRootLogin yes\n")
    assert not _root_open(linux_disk)  # only inside the Match: not a global setting


def test_ssh_offline_match_all_returns_to_global(linux_disk):
    _write_ssh(linux_disk, "Match User x\n  PermitRootLogin no\nMatch all\nPermitRootLogin yes\n")
    assert _root_open(linux_disk)


def test_ssh_offline_match_in_include_ends_at_that_file(linux_disk):
    _write_ssh(linux_disk, "Include sshd_config.d/*.conf\nPermitRootLogin yes\n",
               {"00-a.conf": "Match Address 10.0.0.0/8\n"})
    assert _root_open(linux_disk)


def test_ssh_offline_include_inside_match_stays_in_match(linux_disk):
    _write_ssh(linux_disk, "Match User x\nInclude sshd_config.d/*.conf\n",
               {"00-a.conf": "PermitRootLogin yes\n"})
    assert not _root_open(linux_disk)


def test_ssh_offline_socket_activation_counts_as_enabled(linux_disk):
    (linux_disk / "etc/systemd/system/multi-user.target.wants/ssh.service").unlink()
    sockets = linux_disk / "etc/systemd/system/sockets.target.wants"
    sockets.mkdir(parents=True)
    (sockets / "ssh.socket").symlink_to("/lib/systemd/system/ssh.socket")
    _write_ssh(linux_disk, "PermitRootLogin yes\n")
    f = _root_open(linux_disk)[0]
    assert "set to start automatically" in f.description
    assert "isn't set" not in f.description
    assert f.severity == Severity.CRITICAL  # same as the service-enabled case


def test_ssh_offline_sshd_alias_counts_as_enabled(linux_disk):
    (linux_disk / "etc/systemd/system/multi-user.target.wants/ssh.service").unlink()
    (linux_disk / "etc/systemd/system/sshd.service").symlink_to("/lib/systemd/system/ssh.service")
    _write_ssh(linux_disk, "PermitRootLogin yes\n")
    assert _root_open(linux_disk)[0].severity == Severity.CRITICAL


def test_ssh_offline_include_cap_is_reported_not_checked(linux_disk):
    ssh = linux_disk / "etc/ssh"
    (ssh / "d").mkdir(parents=True)
    (ssh / "sshd_config").write_text("Include d/*.conf\n")
    for i in range(65):
        (ssh / "d" / f"{i:03d}.conf").write_text("PermitEmptyPasswords no\n")
    r = _run_offline(linux_disk)
    assert "some SSH settings files (more than 64)" in r.not_checked
    (ssh / "d" / "064.conf").unlink()
    assert "some SSH settings files (more than 64)" not in _run_offline(linux_disk).not_checked


def test_ssh_offline_match_all_spellings_return_to_global(linux_disk):
    for spelling in ('Match "all"', "Match=all", "Match = all", "MATCH all # back to global"):
        _write_ssh(linux_disk, f"Match User x\n  PermitRootLogin no\n{spelling}\nPermitRootLogin yes\n")
        assert _root_open(linux_disk), spelling


def test_ssh_offline_match_with_equals_is_still_a_match_block(linux_disk):
    _write_ssh(linux_disk, "Match=User x\n  PermitRootLogin no\nMatch all\nPermitRootLogin yes\n")
    assert _root_open(linux_disk)


def test_ssh_offline_unreadable_match_line_keeps_the_settings_after_it(linux_disk):
    _write_ssh(linux_disk, 'Match User "x\nPermitRootLogin yes\n')
    assert _root_open(linux_disk)
