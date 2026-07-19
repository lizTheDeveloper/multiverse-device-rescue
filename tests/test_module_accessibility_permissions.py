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
    return next(m for m in modules if m.name == "accessibility_permissions")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no apps with accessibility access"""
    def fake_run(cmd, **kwargs):
        # Both databases return empty results
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_few_known_apps():
    """Few well-known apps with accessibility access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            # User database has a few well-known apps
            if "Library/Application Support" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.Finder\ncom.apple.Terminal\ncom.microsoft.VSCode\n"
                )
            # System database is empty
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_suspicious_apps():
    """Mix of well-known and suspicious apps"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            # User database has both well-known and suspicious apps
            if "Library/Application Support" in cmd_str:
                return _make_subprocess_result(
                    stdout="com.apple.Finder\ncom.apple.Terminal\ncom.malicious.app\ncom.unknown.spy\n"
                )
            # System database is empty
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_excessive_apps():
    """More than 10 apps with accessibility access"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            # User database has many apps
            if "Library/Application Support" in cmd_str:
                apps = "\n".join([
                    f"com.app.{i}" for i in range(12)
                ])
                return _make_subprocess_result(stdout=apps + "\n")
            # System database is empty
            return _make_subprocess_result(stdout="")
        return _make_subprocess_result()
    return fake_run


def _fake_run_database_error():
    """Database query fails (permission denied, file not found, etc)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "sqlite3" in cmd_str:
            # Simulate permission denied or database not found
            return _make_subprocess_result(stderr="Error: unable to open database", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_accessibility_permissions_discovered():
    mod = _get_module()
    assert mod.name == "accessibility_permissions"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_accessibility_permissions_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_accessibility_permissions_few_known_apps():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_few_known_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO finding about accessibility access
    assert any(f.data.get("check") == "accessibility_access" for f in result.findings)
    # Should be INFO, not WARNING (only well-known apps, count <= 10)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should have 3 apps in the list
    acc_finding = next(f for f in result.findings if f.data.get("check") == "accessibility_access")
    assert len(acc_finding.data.get("apps", [])) == 3


def test_accessibility_permissions_with_suspicious_apps():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_suspicious_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about suspicious apps
    assert any(f.data.get("check") == "suspicious_accessibility" for f in result.findings)
    # Should have suspicious apps identified
    suspicious_finding = next(
        (f for f in result.findings if f.data.get("check") == "suspicious_accessibility"),
        None
    )
    assert suspicious_finding is not None
    assert len(suspicious_finding.data.get("apps", [])) == 2


def test_accessibility_permissions_excessive_apps():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_excessive_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about excessive apps
    assert any(f.data.get("check") == "excessive_accessibility" for f in result.findings)
    excessive_finding = next(
        (f for f in result.findings if f.data.get("check") == "excessive_accessibility"),
        None
    )
    assert excessive_finding is not None
    assert excessive_finding.data.get("count") == 12


def test_accessibility_permissions_database_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_database_error()):
        result = mod.check(_make_profile())
    # On database error, should return no findings (graceful failure)
    assert not result.has_issues


def test_accessibility_permissions_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_suspicious_apps()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) > 0
    # Actions should describe how to manage accessibility permissions
    assert any("Accessibility" in a.title or "accessibility" in a.description for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.accessibility_permissions.") for c in declared)
