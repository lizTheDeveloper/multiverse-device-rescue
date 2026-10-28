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
