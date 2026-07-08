import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from tempfile import TemporaryDirectory
import os

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
    return next(m for m in modules if m.name == "core_services_reset")


def test_core_services_reset_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "core_services_reset"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_core_services_reset_cache_not_found():
    """Test when Launch Services cache is not found."""
    mod = _get_module()

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[]):
            result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("cache not found" in f.title.lower() for f in info_findings)


def test_core_services_reset_normal_database_size():
    """Test when Launch Services database size is normal (5-20MB)."""
    mod = _get_module()

    # Create mock .csstore files with normal size (10MB)
    normal_size = 10 * 1024 * 1024

    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = normal_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=75
            ):
                result = mod.check(_make_profile())

    # Should not have WARNING for database size
    size_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "bloated" in f.title.lower()
    ]
    assert len(size_warnings) == 0

    # Should have INFO status
    assert any("status" in f.title.lower() for f in result.findings)


def test_core_services_reset_bloated_database():
    """Test when Launch Services database is bloated (>50MB)."""
    mod = _get_module()

    # Create mock .csstore files with large size (75MB)
    large_size = 75 * 1024 * 1024

    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = large_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=75
            ):
                result = mod.check(_make_profile())

    # Should have WARNING for bloated database
    assert result.has_issues
    size_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "bloated" in f.title.lower()
    ]
    assert len(size_warnings) == 1
    assert "75" in size_warnings[0].title  # Should mention size


def test_core_services_reset_high_registration_count():
    """Test when app registration count is high (>100)."""
    mod = _get_module()

    normal_size = 10 * 1024 * 1024
    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = normal_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=150
            ):
                result = mod.check(_make_profile())

    # Should have WARNING for high registration count
    assert result.has_issues
    reg_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "registration" in f.title.lower()
    ]
    assert len(reg_warnings) == 1
    assert "150" in reg_warnings[0].title


def test_core_services_reset_normal_registration_count():
    """Test when app registration count is normal."""
    mod = _get_module()

    normal_size = 10 * 1024 * 1024
    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = normal_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=60
            ):
                result = mod.check(_make_profile())

    # Should not have WARNING for registration count
    reg_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "registration" in f.title.lower()
    ]
    assert len(reg_warnings) == 0

    # Should have INFO status
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("status" in f.title.lower() for f in info_findings)


def test_core_services_reset_multiple_csstore_files():
    """Test with multiple .csstore files."""
    mod = _get_module()

    # Create multiple mock files that together exceed 50MB
    mock_file1 = MagicMock()
    mock_file1.stat.return_value.st_size = 30 * 1024 * 1024

    mock_file2 = MagicMock()
    mock_file2.stat.return_value.st_size = 25 * 1024 * 1024

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file1, mock_file2]):
            with patch.object(
                mod, "_count_app_registrations", return_value=75
            ):
                result = mod.check(_make_profile())

    # Should have WARNING for bloated database
    size_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "bloated" in f.title.lower()
    ]
    assert len(size_warnings) == 1
    # Total should be 55MB
    assert "55" in size_warnings[0].title


def test_core_services_reset_count_app_registrations():
    """Test the _count_app_registrations method."""
    mod = _get_module()

    lsregister_output = """
    bundle id:                 com.apple.Finder
    bundle id:                 com.apple.Safari
    bundle id:                 com.apple.Mail
    bundle id:                 com.apple.TextEdit
    """

    with patch("os.path.exists", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = lsregister_output
            mock_run.return_value = mock_result

            count = mod._count_app_registrations()

    assert count == 4


def test_core_services_reset_lsregister_not_found():
    """Test when lsregister binary is not found."""
    mod = _get_module()

    with patch("os.path.exists", return_value=False):
        count = mod._count_app_registrations()

    assert count is None


def test_core_services_reset_lsregister_error():
    """Test graceful handling of lsregister errors."""
    mod = _get_module()

    with patch("os.path.exists", return_value=True):
        with patch("subprocess.run", side_effect=OSError("command not found")):
            count = mod._count_app_registrations()

    assert count is None


def test_core_services_reset_lsregister_returncode_error():
    """Test graceful handling of lsregister non-zero return code."""
    mod = _get_module()

    with patch("os.path.exists", return_value=True):
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_run.return_value = mock_result

            count = mod._count_app_registrations()

    assert count is None


def test_core_services_reset_fix_cache_not_found():
    """Test fix() for missing cache."""
    mod = _get_module()

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[]):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed
    assert fix.all_succeeded
    # Should provide guidance on rebuilding
    descriptions = "\n".join(a.description for a in fix.actions)
    assert "lsregister" in descriptions


def test_core_services_reset_fix_bloated_database():
    """Test fix() for bloated database."""
    mod = _get_module()

    large_size = 75 * 1024 * 1024
    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = large_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=75
            ):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed
    assert fix.all_succeeded
    # Should provide command to rebuild database
    descriptions = "\n".join(a.description for a in fix.actions)
    assert "lsregister" in descriptions
    assert "-kill" in descriptions


def test_core_services_reset_fix_high_registrations():
    """Test fix() for high registration count."""
    mod = _get_module()

    normal_size = 10 * 1024 * 1024
    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = normal_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=150
            ):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed
    assert fix.all_succeeded
    # Should provide command to reset registrations
    descriptions = "\n".join(a.description for a in fix.actions)
    assert "lsregister" in descriptions


def test_core_services_reset_fix_is_informational():
    """Test that fix() is informational and doesn't execute commands."""
    mod = _get_module()

    normal_size = 10 * 1024 * 1024
    mock_file = MagicMock()
    mock_file.stat.return_value.st_size = normal_size

    with patch("os.path.expanduser", return_value="/fake/home"):
        with patch("pathlib.Path.glob", return_value=[mock_file]):
            with patch.object(
                mod, "_count_app_registrations", return_value=75
            ):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.AUTO)

    # All actions should be informational (success=True, SAFE risk level)
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
    # Command-based actions (those with newlines) should mention Terminal
    for action in fix.actions:
        if "\n" in action.description and "lsregister" in action.description:
            assert "Terminal" in action.description
