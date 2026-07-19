import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "xprotect_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _format_date(days_ago=0):
    """Format a date string for days_ago in the past"""
    date = datetime.now().date() - timedelta(days=days_ago)
    return date.strftime("%Y-%m-%d")


def _fake_run_gatekeeper_enabled_healthy_xp():
    """Gatekeeper enabled, XProtect healthy, MRT present"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(stdout="4001\n")
        elif "system_profiler" in cmd_str:
            return _make_subprocess_result(
                stdout=f"XProtect: 4001 {_format_date(5)}\nMRT: 1.2 {_format_date(3)}\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_gatekeeper_disabled():
    """Gatekeeper disabled - CRITICAL issue"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments disabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(stdout="4001\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_xprotect_outdated():
    """XProtect version is outdated (below minimum)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(stdout="2500\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_xprotect_old():
    """XProtect definitions are old (>30 days)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(stdout="4001\n")
        elif "system_profiler" in cmd_str:
            return _make_subprocess_result(
                stdout=f"XProtect: 4001 {_format_date(35)}\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_mrt_outdated():
    """MRT is outdated (>30 days)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(stdout="4001\n")
        elif "system_profiler" in cmd_str:
            return _make_subprocess_result(
                stdout=f"XProtect: 4001 {_format_date(5)}\nMRT: 1.2 {_format_date(40)}\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_xprotect_missing():
    """XProtect bundle is missing"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "spctl" in cmd_str and "--status" in cmd_str:
            return _make_subprocess_result(stdout="assessments enabled\n")
        elif "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            return _make_subprocess_result(
                stdout="",
                stderr="The domain/default pair does not exist",
                returncode=1,
            )
        return _make_subprocess_result()
    return fake_run


def test_xprotect_status_discovered():
    mod = _get_module()
    assert mod.name == "xprotect_status"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_gatekeeper_enabled_xprotect_healthy():
    """Healthy case: Gatekeeper enabled, XProtect up-to-date"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_enabled_healthy_xp()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have: gatekeeper_status, xprotect_version, mrt_version
    assert len(result.findings) >= 2
    # All should be INFO severity
    assert all(f.severity == Severity.INFO for f in result.findings)
    assert any(f.data.get("check") == "gatekeeper_status" for f in result.findings)


def test_gatekeeper_disabled_critical():
    """Critical case: Gatekeeper is disabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for disabled Gatekeeper
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    assert any(f.data.get("check") == "gatekeeper_disabled" for f in critical_findings)


def test_xprotect_version_outdated():
    """Warning case: XProtect version below minimum"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_xprotect_outdated()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for outdated version
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 1
    assert any(f.data.get("check") == "xprotect_outdated" for f in warning_findings)


def test_xprotect_definitions_old():
    """Warning case: XProtect definitions haven't been updated in >30 days"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_xprotect_old()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for old definitions
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 1
    assert any(f.data.get("check") == "xprotect_old" for f in warning_findings)


def test_mrt_outdated():
    """Warning case: MRT is outdated (>30 days)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mrt_outdated()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for outdated MRT
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 1
    assert any(f.data.get("check") == "mrt_outdated" for f in warning_findings)


def test_xprotect_missing_bundle():
    """Critical case: XProtect bundle is missing"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_xprotect_missing()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for missing bundle
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    assert any(f.data.get("check") == "xprotect_missing" for f in critical_findings)


def test_fix_gatekeeper_disabled():
    """Fix for disabled Gatekeeper"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action to re-enable Gatekeeper
    assert any("Gatekeeper" in a.title for a in fix.actions)
    assert fix.all_succeeded


def test_fix_xprotect_outdated():
    """Fix for outdated XProtect"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_xprotect_outdated()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action to update
    assert any("Update" in a.title or "Software Update" in a.description for a in fix.actions)
    assert fix.all_succeeded


def test_fix_mrt_outdated():
    """Fix for outdated MRT"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mrt_outdated()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should suggest updating
    assert fix.all_succeeded
    assert len(fix.actions) >= 1


def test_fix_healthy():
    """Fix for healthy state: no actions needed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_gatekeeper_enabled_healthy_xp()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have no actions
    assert len(fix.actions) == 0
    assert fix.all_succeeded


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.xprotect_status.") for c in declared)
