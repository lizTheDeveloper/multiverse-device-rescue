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
    return next(m for m in modules if m.name == "sudo_config_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_clean_sudoers():
    """No NOPASSWD entries"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
%admin ALL=(ALL) ALL
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 5 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo" in cmd:
            return _make_subprocess_result(returncode=1)
        elif isinstance(cmd, list) and "dscl" in cmd:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_nopasswd_all():
    """Has NOPASSWD ALL (critical)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
%admin ALL=(ALL) NOPASSWD: ALL
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 15 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo" in cmd:
            return _make_subprocess_result(returncode=1)
        elif isinstance(cmd, list) and "dscl" in cmd:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_nopasswd_partial():
    """Has NOPASSWD for specific commands"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
user ALL=(ALL) NOPASSWD: /usr/bin/systemctl
user ALL=(ALL) NOPASSWD: /usr/sbin/reboot
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 15 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo" in cmd:
            return _make_subprocess_result(returncode=1)
        elif isinstance(cmd, list) and "dscl" in cmd:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_long_timeout():
    """Sudo timestamp timeout is very long"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
%admin ALL=(ALL) ALL
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 120 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo" in cmd:
            return _make_subprocess_result(returncode=1)
        elif isinstance(cmd, list) and "dscl" in cmd:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_touchid_enabled():
    """TouchID is enabled for sudo"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
%admin ALL=(ALL) ALL
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 15 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo_local" in cmd:
            return _make_subprocess_result(
                stdout="# pam-1.0\nauth       sufficient     pam_tid.so\nauth       sufficient     pam_smartcard.so\n"
            )
        elif isinstance(cmd, list) and "dscl" in cmd:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_root_enabled():
    """Root account is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "cat" in cmd and "/etc/sudoers" in cmd:
            return _make_subprocess_result(
                stdout="""# sudoers file
root ALL=(ALL) ALL
%admin ALL=(ALL) ALL
"""
            )
        elif isinstance(cmd, list) and "sudo" in cmd and "-V" in cmd:
            return _make_subprocess_result(
                stdout="authentication timestamp timeout: 15 minutes\n"
            )
        elif isinstance(cmd, list) and "cat" in cmd and "/etc/pam.d/sudo" in cmd:
            return _make_subprocess_result(returncode=1)
        elif isinstance(cmd, list) and "dscl" in cmd and "root" in cmd:
            return _make_subprocess_result(
                stdout="AuthenticationAuthority: ;ShadowHash;\n"
            )
        return _make_subprocess_result(stdout="")
    return fake_run


def test_sudo_config_audit_discovered():
    """Module is discoverable and has correct metadata"""
    mod = _get_module()
    assert mod.name == "sudo_config_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_sudo_config_audit_clean():
    """Clean sudoers with no issues"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean_sudoers()):
        result = mod.check(_make_profile())
    # Should have findings for timestamp (INFO) and touchid (INFO) and root (INFO)
    # but no critical/warning issues
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_sudo_config_audit_nopasswd_all():
    """NOPASSWD ALL is detected as CRITICAL"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nopasswd_all()):
        result = mod.check(_make_profile())
    # Should have at least one CRITICAL finding
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any(f.data.get("check_type") == "nopasswd_all" for f in critical_findings)


def test_sudo_config_audit_nopasswd_partial():
    """NOPASSWD for specific commands is detected as INFO"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nopasswd_partial()):
        result = mod.check(_make_profile())
    # Should have finding about NOPASSWD partial
    assert any(f.data.get("check_type") == "nopasswd_partial" for f in result.findings)


def test_sudo_config_audit_long_timeout():
    """Long timestamp timeout is detected as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_long_timeout()):
        result = mod.check(_make_profile())
    # Should have WARNING for long timeout
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check_type") == "timestamp_long" for f in warning_findings)
    # Check that timeout value is captured
    timestamp_finding = next(
        f for f in warning_findings if f.data.get("check_type") == "timestamp_long"
    )
    assert timestamp_finding.data.get("timeout_minutes") == 120


def test_sudo_config_audit_touchid_enabled():
    """TouchID enabled is reported as INFO"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_touchid_enabled()):
        result = mod.check(_make_profile())
    # Should have INFO for TouchID enabled
    touchid_findings = [
        f for f in result.findings if f.data.get("check_type") == "touchid_enabled"
    ]
    assert len(touchid_findings) > 0


def test_sudo_config_audit_root_enabled():
    """Root account enabled is detected as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_root_enabled()):
        result = mod.check(_make_profile())
    # Should have WARNING for root enabled
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check_type") == "root_enabled" for f in warning_findings)


def test_sudo_config_audit_fix_nopasswd_all():
    """fix() creates informational action for NOPASSWD ALL"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nopasswd_all()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for findings
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
    # Should have action for NOPASSWD ALL
    assert any("NOPASSWD ALL" in a.title for a in fix.actions)


def test_sudo_config_audit_fix_creates_actions_per_finding():
    """fix() creates one action per finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_long_timeout()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have one action per finding
    assert len(fix.actions) == len(check.findings)
