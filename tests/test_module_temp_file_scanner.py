import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile,
    Platform,
    Mode,
    Severity,
    RiskLevel,
)
from rescue.registry import discover_modules


def _make_test_profile() -> SystemProfile:
    """Create a minimal test SystemProfile."""
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def test_temp_file_scanner_module_discovered():
    """Test that temp_file_scanner module is discovered."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "temp_file_scanner" in names


def test_temp_file_scanner_module_metadata():
    """Test module metadata is correct."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    assert mod.name == "temp_file_scanner"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_temp_file_scanner_no_findings_when_directories_missing():
    """Test that no findings are reported when directories don't exist."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    # Mock _get_directory_size to return 0 for all directories
    with patch.object(mod, "_get_directory_size", return_value=0):
        result = mod.check(profile)
        assert not result.has_issues


def test_temp_file_scanner_finds_large_caches(tmp_path):
    """Test that large caches are detected."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    # Create mock directories with sizes
    def mock_get_size(path):
        if "Caches" in str(path):
            return 200 * 1024 * 1024  # 200 MB
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    # Should have finding for total waste and caches
    assert len(result.findings) >= 2
    assert any("caches" in f.title.lower() for f in result.findings)
    assert any("reclaimable" in f.title.lower() for f in result.findings)


def test_temp_file_scanner_finds_large_logs(tmp_path):
    """Test that large logs are detected."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "Logs" in str(path) or "log" in str(path):
            return 150 * 1024 * 1024  # 150 MB
        return 0

    def mock_count_old(path, days=30):
        if "Logs" in str(path) or "log" in str(path):
            return 42
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    log_findings = [f for f in result.findings if "logs" in f.title.lower()]
    assert len(log_findings) > 0
    # Note: count_old_files is called twice (system logs + user logs), so total is 84
    assert log_findings[0].data.get("old_files_count") == 84


def test_temp_file_scanner_finds_large_temps(tmp_path):
    """Test that large temp files are detected."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "/tmp" in str(path) or "/var/folders" in str(path):
            return 250 * 1024 * 1024  # 250 MB
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    temp_findings = [f for f in result.findings if "temporary" in f.title.lower()]
    assert len(temp_findings) > 0


def test_temp_file_scanner_finds_xcode_derived_data(tmp_path):
    """Test that Xcode derived data is detected."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "DerivedData" in str(path):
            return 5 * 1024 * 1024 * 1024  # 5 GB
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    xcode_findings = [f for f in result.findings if "xcode" in f.title.lower()]
    assert len(xcode_findings) > 0


def test_temp_file_scanner_finds_homebrew_cache(tmp_path):
    """Test that Homebrew cache is detected."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "Homebrew" in str(path):
            return 500 * 1024 * 1024  # 500 MB
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    brew_findings = [f for f in result.findings if "homebrew" in f.title.lower()]
    assert len(brew_findings) > 0


def test_temp_file_scanner_fix_is_informational():
    """Test that fix() is informational and always succeeds."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    assert mod.risk_level == RiskLevel.SAFE

    profile = _make_test_profile()

    def mock_get_size(path):
        if "Caches" in str(path):
            return 200 * 1024 * 1024
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            check = mod.check(profile)

    fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions should be informational (success=True, no errors)
    for action in fix.actions:
        assert action.success is True
        assert action.error is None


def test_temp_file_scanner_get_directory_size(tmp_path):
    """Test directory size calculation."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    # Create test files
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "file1.txt").write_text("a" * 1000)  # 1000 bytes
    (test_dir / "file2.txt").write_text("b" * 2000)  # 2000 bytes
    subdir = test_dir / "subdir"
    subdir.mkdir()
    (subdir / "file3.txt").write_text("c" * 3000)  # 3000 bytes

    size = mod._get_directory_size(test_dir)
    assert size == 6000  # Total bytes


def test_temp_file_scanner_get_directory_size_nonexistent():
    """Test that nonexistent directories return 0."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    nonexistent = Path("/nonexistent/path/that/does/not/exist")
    size = mod._get_directory_size(nonexistent)
    assert size == 0


def test_temp_file_scanner_count_old_files(tmp_path):
    """Test counting old files."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    # Create test files with different modification times
    test_dir = tmp_path / "logs"
    test_dir.mkdir()

    # Create a recent file
    recent = test_dir / "recent.log"
    recent.write_text("recent")
    recent.touch()

    # Create an old file (40 days old)
    old = test_dir / "old.log"
    old.write_text("old")
    old_time = (datetime.now() - timedelta(days=40)).timestamp()
    os.utime(str(old), (old_time, old_time))

    # Count files older than 30 days
    old_count = mod._count_old_files(test_dir, days=30)
    assert old_count == 1


def test_temp_file_scanner_count_old_files_nonexistent():
    """Test that nonexistent directories return 0 old files."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    nonexistent = Path("/nonexistent/path/that/does/not/exist")
    old_count = mod._count_old_files(nonexistent, days=30)
    assert old_count == 0


def test_temp_file_scanner_findings_have_required_data():
    """Test that findings contain required data fields."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "Caches" in str(path):
            return 200 * 1024 * 1024
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            result = mod.check(profile)

    assert result.has_issues
    for finding in result.findings:
        assert finding.title is not None
        assert finding.description is not None
        assert finding.severity is not None
        assert finding.category == "performance"
        assert "type" in finding.data
        assert "size_bytes" in finding.data
        assert "size_formatted" in finding.data


def test_temp_file_scanner_actions_include_instructions(tmp_path):
    """Test that actions include instructions for cleaning."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "temp_file_scanner")

    profile = _make_test_profile()

    def mock_get_size(path):
        if "Caches" in str(path):
            return 200 * 1024 * 1024
        if "Homebrew" in str(path):
            return 300 * 1024 * 1024
        if "DerivedData" in str(path):
            return 1 * 1024 * 1024 * 1024
        return 0

    def mock_count_old(path, days=30):
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_size):
        with patch.object(mod, "_count_old_files", side_effect=mock_count_old):
            check = mod.check(profile)

    fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0

    # Check for meaningful descriptions
    descriptions = [a.description for a in fix.actions]
    all_desc = " ".join(descriptions).lower()

    # Should mention ways to clean
    assert "brew cleanup" in all_desc or "rm -rf" in all_desc
