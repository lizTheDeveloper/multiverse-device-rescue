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
    return next(m for m in modules if m.name == "xprotect_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """XProtect is present and up-to-date (version >= MINIMUM_XPROTECT_VERSION)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            # Return a current version (above minimum)
            return _make_subprocess_result(stdout="4001\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_outdated():
    """XProtect is present but outdated (version < MINIMUM_XPROTECT_VERSION)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            # Return an outdated version (below minimum)
            return _make_subprocess_result(stdout="2500\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_missing_bundle():
    """XProtect bundle is missing or unreadable"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            # Simulate bundle missing or unreadable
            return _make_subprocess_result(
                stdout="",
                stderr="The domain/default pair of (com.apple.xprotect, Version) does not exist",
                returncode=1,
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_invalid_version():
    """XProtect version output is invalid (non-numeric)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "XProtect.meta.plist" in cmd_str:
            # Return an invalid version string
            return _make_subprocess_result(stdout="invalid_version\n")
        return _make_subprocess_result()
    return fake_run


def test_xprotect_status_discovered():
    mod = _get_module()
    assert mod.name == "xprotect_status"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_xprotect_status_healthy():
    """Healthy case: up-to-date XProtect definitions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Has issues because there's always at least an INFO finding
    assert result.has_issues
    # Should have exactly one finding (INFO only)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["check"] == "xprotect_version"


def test_xprotect_status_outdated():
    """Outdated case: XProtect definitions below minimum version"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_outdated()):
        result = mod.check(_make_profile())
    # Should have issues
    assert result.has_issues
    # Should have two findings: INFO (version) and WARNING (outdated)
    assert len(result.findings) == 2
    severities = [f.severity for f in result.findings]
    assert Severity.INFO in severities
    assert Severity.WARNING in severities
    # Verify the outdated warning is present
    assert any(f.data.get("check") == "xprotect_outdated" for f in result.findings)


def test_xprotect_status_missing_bundle():
    """Missing bundle case: XProtect bundle is missing or unreadable"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_missing_bundle()):
        result = mod.check(_make_profile())
    # Should have issues
    assert result.has_issues
    # Should have exactly one finding (CRITICAL)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["check"] == "xprotect_missing"


def test_xprotect_status_invalid_version():
    """Invalid version case: XProtect version output cannot be parsed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_invalid_version()):
        result = mod.check(_make_profile())
    # Should treat unparseable version as missing/unreadable
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL


def test_xprotect_status_fix_outdated():
    """Fix for outdated XProtect: informational action"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_outdated()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed (informational)
    assert fix.all_succeeded
    # Should suggest updating XProtect
    assert any("Update XProtect" in a.title for a in fix.actions)


def test_xprotect_status_fix_missing():
    """Fix for missing XProtect: informational action"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_missing_bundle()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed (informational)
    assert fix.all_succeeded
    # Should suggest restoring XProtect
    assert any("Restore XProtect" in a.title for a in fix.actions)


def test_xprotect_status_fix_healthy():
    """Fix for healthy XProtect: no actions needed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should succeed (no issues to fix)
    assert fix.all_succeeded
    # Should have no actions for healthy state
    assert len(fix.actions) == 0
