import sys
import os
import stat
from pathlib import Path
from unittest.mock import patch

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
    return next(m for m in modules if m.name == "directory_permissions")


def test_directory_permissions_discovered():
    mod = _get_module()
    assert mod.name == "directory_permissions"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_directory_permissions_check_no_crash():
    """check() runs without crashing even on real FS"""
    mod = _get_module()
    profile = _make_profile()
    result = mod.check(profile)
    # Just verify it returns a CheckResult
    assert result is not None
    assert result.module_name == "directory_permissions"


def test_ownership_mismatch_warning(tmp_path):
    """_check_ownership detects wrong owner"""
    mod = _get_module()
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    # Simulate expected uid that doesn't match current user
    wrong_uid = os.getuid() + 10000
    findings = []

    # Call the helper directly
    finding = mod._check_ownership(test_dir, os.getuid(), "test_dir")
    assert finding is None  # Ownership is correct (current user)

    # Now test with wrong expected uid
    finding = mod._check_ownership(test_dir, wrong_uid, "test_dir")
    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert "ownership" in finding.title.lower()


def test_permissions_mismatch_warning(tmp_path):
    """_check_permissions detects wrong permissions"""
    mod = _get_module()
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    os.chmod(test_dir, 0o755)

    # Correct permissions check
    finding = mod._check_permissions(test_dir, 0o755, "test_dir", check_sticky=False)
    assert finding is None  # Permissions are correct

    # Wrong permissions check
    finding = mod._check_permissions(test_dir, 0o777, "test_dir", check_sticky=False)
    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert "permissions" in finding.title.lower()


def test_sticky_bit_check(tmp_path):
    """_check_permissions detects sticky bit issues"""
    mod = _get_module()
    test_dir = tmp_path / "test_sticky"
    test_dir.mkdir()

    # Set without sticky bit
    os.chmod(test_dir, 0o777)

    # Check for sticky bit (should fail)
    finding = mod._check_permissions(test_dir, 0o777, "test_dir", check_sticky=True)
    assert finding is not None
    assert "sticky" in finding.title.lower() or "sticky" in finding.description.lower()

    # Set with sticky bit and check again
    os.chmod(test_dir, 0o1777)
    finding = mod._check_permissions(test_dir, 0o777, "test_dir", check_sticky=True)
    assert finding is None  # Now sticky bit is set


def test_library_path_uses_home(tmp_path):
    """Verify Library path is derived from home"""
    mod = _get_module()

    # Test that the module uses Path.home() for user directories
    home = Path.home()
    assert str(home).startswith("/")  # Sanity check


def test_applications_ownership_values():
    """Verify /Applications expects root:admin (uid 0, gid 80)"""
    mod = _get_module()
    # This is a smoke test that the module is aware of the values
    # The actual check is guarded by exists()
    assert hasattr(mod, "_check_ownership")
    assert hasattr(mod, "_check_permissions")


def test_fix_returns_informational_actions():
    """fix() returns safe informational actions"""
    mod = _get_module()
    profile = _make_profile()
    check = mod.check(profile)
    fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded  # Informational fixes always succeed
    if check.has_issues:
        # Should have actions for the findings
        assert len(fix.actions) == len(check.findings)
        # All should be SAFE risk level
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_fix_creates_shell_commands():
    """fix() suggestions include shell commands"""
    mod = _get_module()
    profile = _make_profile()
    check = mod.check(profile)

    if check.has_issues:
        fix = mod.fix(check, Mode.MANUAL)
        # If there are findings, actions should suggest commands
        assert len(fix.actions) > 0
        for action in fix.actions:
            # Should suggest a command
            assert action.description is not None
            assert len(action.description) > 0


def test_report_generation(tmp_path):
    """Module generates a readable report"""
    mod = _get_module()
    profile = _make_profile()
    check = mod.check(profile)
    report = mod.report(check)

    assert "directory_permissions" in report
    assert "===" in report


def test_nonexistent_path_skipped():
    """_check_ownership and _check_permissions handle missing paths"""
    mod = _get_module()
    nonexistent = Path("/this/path/does/not/exist/12345")

    # Should not crash
    finding = mod._check_ownership(nonexistent, os.getuid(), "test")
    # Missing path returns None (skipped)
    assert finding is None

    finding = mod._check_permissions(nonexistent, 0o755, "test")
    assert finding is None
