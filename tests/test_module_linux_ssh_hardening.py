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
