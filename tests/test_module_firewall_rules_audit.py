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
    return next(m for m in modules if m.name == "firewall_rules_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_firewall_enabled_secure():
    """Firewall enabled, stealth on, few apps, strict settings"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "--listapps" in cmd_str:
            return _make_subprocess_result(
                stdout="com.apple.Safari (Allow incoming)\ncom.apple.Mail (Allow incoming)\n"
            )
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_firewall_disabled():
    """Firewall is disabled"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--listapps" in cmd_str:
            return _make_subprocess_result(stdout="")
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_stealth_disabled():
    """Firewall enabled but stealth mode disabled"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--listapps" in cmd_str:
            return _make_subprocess_result(stdout="com.apple.Safari (Allow incoming)\n")
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_too_many_apps():
    """Firewall enabled but too many apps allowed (>30)"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "--listapps" in cmd_str:
            apps = "\n".join([f"com.app{i} (Allow incoming)" for i in range(1, 36)])
            return _make_subprocess_result(stdout=apps)
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_allow_signed_enabled():
    """Firewall enabled with allow signed software enabled"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "--listapps" in cmd_str:
            return _make_subprocess_result(stdout="com.apple.Safari (Allow incoming)\n")
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_all_issues():
    """All firewall issues present"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "globalstate" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "stealthenabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--listapps" in cmd_str:
            apps = "\n".join([f"com.app{i} (Allow incoming)" for i in range(1, 36)])
            return _make_subprocess_result(stdout=apps)
        elif "--getblockall" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "--getallowsigned" in cmd_str:
            return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def test_firewall_rules_audit_discovered():
    mod = _get_module()
    assert mod.name == "firewall_rules_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_firewall_enabled_secure():
    """Firewall is enabled with secure settings - should only have summary"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_enabled_secure()):
        result = mod.check(_make_profile())
    # Should have findings (at least the summary)
    assert result.has_issues
    # Only summary finding, no warnings/critical
    assert len(result.findings) == 1
    assert result.findings[0].data.get("check") == "firewall_summary"
    assert result.findings[0].severity == Severity.INFO


def test_firewall_disabled_critical():
    """Firewall is disabled - should flag as CRITICAL"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical finding for disabled firewall plus summary
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].data.get("check") == "alf_disabled"


def test_stealth_mode_disabled_warning():
    """Stealth mode disabled - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stealth_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for stealth disabled and summary
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "stealth_disabled"


def test_too_many_apps_warning():
    """Too many apps allowed - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_too_many_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for too many apps
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "too_many_apps"
    assert warning_findings[0].data.get("count") == 35


def test_allow_signed_enabled_warning():
    """Allow signed software enabled - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_allow_signed_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for allow signed
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "allow_signed_enabled"


def test_all_issues_present():
    """All firewall issues present"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical for disabled firewall, summary, plus potentially others
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].data.get("check") == "alf_disabled"


def test_firewall_rules_audit_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_firewall_rules_audit_fix_creates_actions():
    """fix() should create actions for each issue"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for each non-summary finding
    issue_findings = [f for f in check.findings if f.data.get("check") != "firewall_summary"]
    assert len(fix.actions) >= len(issue_findings)


def test_firewall_summary_has_all_fields():
    """Firewall summary should include all configuration fields"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_enabled_secure()):
        result = mod.check(_make_profile())
    assert result.has_issues
    summary_findings = [f for f in result.findings if f.data.get("check") == "firewall_summary"]
    assert len(summary_findings) == 1
    summary = summary_findings[0]
    assert "alf_enabled" in summary.data
    assert "stealth_enabled" in summary.data
    assert "block_all" in summary.data
    assert "allow_signed" in summary.data
    assert "allowed_apps_count" in summary.data
