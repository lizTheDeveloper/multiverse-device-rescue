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
    return next(m for m in modules if m.name == "gatekeeper_quarantine_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_secure():
    """All security checks pass"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # spctl --status (Gatekeeper enabled)
        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        # csrutil status (SIP enabled)
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: enabled.\n")
        # xattr for quarantine flags (all apps have it)
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            return _make_subprocess_result(stdout="0\n", returncode=0)
        # spctl assessment
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Safari.app: accepted\n")

        return _make_subprocess_result()

    return fake_run


def _fake_run_gatekeeper_disabled():
    """Gatekeeper is disabled"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments disabled\n")
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: enabled.\n")
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            return _make_subprocess_result(stdout="0\n", returncode=0)
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Safari.app: accepted\n")

        return _make_subprocess_result()

    return fake_run


def _fake_run_sip_disabled():
    """SIP is disabled"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: disabled.\n")
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            return _make_subprocess_result(stdout="0\n", returncode=0)
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Safari.app: accepted\n")

        return _make_subprocess_result()

    return fake_run


def _fake_run_quarantine_removed():
    """Some apps have quarantine flags removed"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: enabled.\n")
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            # Firefox.app and Discord.app don't have quarantine
            if "Firefox.app" in cmd_str or "Discord.app" in cmd_str:
                return _make_subprocess_result(stderr="xattr: com.apple.quarantine: No such file\n", returncode=1)
            else:
                return _make_subprocess_result(stdout="0\n", returncode=0)
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(stdout="/Applications/Safari.app: accepted\n")

        return _make_subprocess_result()

    return fake_run


def _fake_path_exists_applications():
    """Mock for Path.exists to return True for /Applications apps"""
    def fake_exists(self):
        path_str = str(self)
        if path_str.startswith("/Applications/"):
            app_name = path_str.split("/")[-1]
            # Make most apps exist except a couple
            return app_name in [
                "Safari.app", "Firefox.app", "Google Chrome.app",
                "Visual Studio Code.app", "Spotify.app", "Discord.app",
                "Slack.app", "Telegram.app", "VLC.app"
            ]
        return True
    return fake_exists


def _fake_run_assessment_failed():
    """Gatekeeper assessment fails"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: enabled.\n")
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            return _make_subprocess_result(stdout="0\n", returncode=0)
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="Error: assessment failed\n")

        return _make_subprocess_result()

    return fake_run


def _fake_run_multiple_issues():
    """Multiple security issues: Gatekeeper disabled, SIP disabled, quarantine removed"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments disabled\n")
        elif "csrutil" in cmd_str and "status" in cmd_str:
            return _make_subprocess_result(stdout="System Integrity Protection status: disabled.\n")
        elif "xattr" in cmd_str and "com.apple.quarantine" in cmd_str:
            if "Firefox.app" in cmd_str or "Slack.app" in cmd_str:
                return _make_subprocess_result(stderr="xattr: com.apple.quarantine: No such file\n", returncode=1)
            else:
                return _make_subprocess_result(stdout="0\n", returncode=0)
        elif "spctl" in cmd_str and "--assess" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="Error\n")

        return _make_subprocess_result()

    return fake_run


def test_gatekeeper_quarantine_check_discovered():
    mod = _get_module()
    assert mod.name == "gatekeeper_quarantine_check"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_gatekeeper_quarantine_check_all_secure():
    """Test when all security checks pass"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_secure()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have 4 INFO findings: gatekeeper_enabled, sip_enabled, gatekeeper_working, and no quarantine found
    checks = [f.data.get("check") for f in result.findings]
    assert "gatekeeper_enabled" in checks
    assert "sip_enabled" in checks
    assert "gatekeeper_working" in checks
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 3


def test_gatekeeper_quarantine_check_gatekeeper_disabled():
    """Test when Gatekeeper is disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "gatekeeper_disabled" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "gatekeeper_disabled"]
    assert len(critical) == 1
    assert critical[0].severity == Severity.CRITICAL


def test_gatekeeper_quarantine_check_sip_disabled():
    """Test when SIP is disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_sip_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "sip_disabled" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "sip_disabled"]
    assert len(critical) == 1
    assert critical[0].severity == Severity.CRITICAL


def test_gatekeeper_quarantine_check_quarantine_removed():
    """Test detection of quarantine flags removed from apps"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_quarantine_removed()), \
         patch("pathlib.Path.exists", _fake_path_exists_applications()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "quarantine_removed" for f in result.findings)
    quarantine_findings = [f for f in result.findings if f.data.get("check") == "quarantine_removed"]
    assert len(quarantine_findings) == 1
    assert quarantine_findings[0].severity == Severity.WARNING
    apps = quarantine_findings[0].data.get("apps", [])
    assert "Firefox.app" in apps
    assert "Discord.app" in apps


def test_gatekeeper_quarantine_check_assessment_failed():
    """Test when Gatekeeper assessment fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_assessment_failed()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "gatekeeper_assessment_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "gatekeeper_assessment_failed"]
    assert len(failed) == 1
    assert failed[0].severity == Severity.WARNING


def test_gatekeeper_quarantine_check_multiple_issues():
    """Test when multiple critical issues are detected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()), \
         patch("pathlib.Path.exists", _fake_path_exists_applications()):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "gatekeeper_disabled" in checks
    assert "sip_disabled" in checks
    assert "quarantine_removed" in checks
    # Should have 2 CRITICAL findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 2


def test_gatekeeper_quarantine_check_fix_gatekeeper_disabled():
    """Test fix recommendation for disabled Gatekeeper"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    gatekeeper_action = [a for a in fix.actions if "gatekeeper" in a.title.lower()]
    assert len(gatekeeper_action) > 0
    assert all(a.risk_level == RiskLevel.SAFE for a in gatekeeper_action)


def test_gatekeeper_quarantine_check_fix_sip_disabled():
    """Test fix recommendation for disabled SIP"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_sip_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    sip_action = [a for a in fix.actions if "sip" in a.title.lower() or "integrity" in a.title.lower()]
    assert len(sip_action) > 0


def test_gatekeeper_quarantine_check_fix_quarantine_removed():
    """Test fix recommendation for quarantine removal"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_quarantine_removed()), \
         patch("pathlib.Path.exists", _fake_path_exists_applications()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    quarantine_action = [a for a in fix.actions if "quarantine" in a.title.lower()]
    assert len(quarantine_action) > 0


def test_gatekeeper_quarantine_check_fix_all_informational():
    """Test that all fix actions are informational (safe)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()), \
         patch("pathlib.Path.exists", _fake_path_exists_applications()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # All fix actions should succeed (informational)
    assert fix.all_succeeded
    # All should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_gatekeeper_quarantine_check_subprocess_error_graceful():
    """Test graceful handling of subprocess errors"""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.gatekeeper_quarantine_check.") for c in declared)
