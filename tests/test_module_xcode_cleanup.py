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
    return next(m for m in modules if m.name == "xcode_cleanup")


def test_xcode_cleanup_discovered():
    """Module is discoverable and has correct metadata."""
    mod = _get_module()
    assert mod.name == "xcode_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_xcode_cleanup_no_directories():
    """No issues when Xcode directories don't exist."""
    mod = _get_module()

    def mock_get_dir_size(path):
        # All directories return 0 size (don't exist)
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert not result.has_issues
    assert len(result.findings) == 0


def test_xcode_cleanup_small_directories():
    """INFO severity for small Xcode directories."""
    mod = _get_module()

    def mock_get_dir_size(path):
        # 100 MB for each directory
        return 100 * 1024 * 1024

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_xcode_cleanup_large_derived_data():
    """WARNING severity when DerivedData exceeds 5 GB."""
    mod = _get_module()

    def mock_get_dir_size(path):
        path_str = str(path)
        if "DerivedData" in path_str:
            return 6 * 1024 * 1024 * 1024  # 6 GB
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("type") == "derived_data" for f in warnings)


def test_xcode_cleanup_large_core_simulator():
    """WARNING severity when CoreSimulator exceeds 10 GB."""
    mod = _get_module()

    def mock_get_dir_size(path):
        path_str = str(path)
        if "CoreSimulator" in path_str:
            return 11 * 1024 * 1024 * 1024  # 11 GB
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("type") == "core_simulator" for f in warnings)


def test_xcode_cleanup_total_exceeds_threshold():
    """WARNING severity when total Xcode usage exceeds 20 GB."""
    mod = _get_module()

    def mock_get_dir_size(path):
        # Each returns 8 GB, total > 20 GB
        return 8 * 1024 * 1024 * 1024

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("type") == "total_xcode" for f in warnings)


def test_xcode_cleanup_all_locations_reported():
    """All Xcode locations are reported in findings."""
    mod = _get_module()

    def mock_get_dir_size(path):
        # Each returns 1 GB (small but present)
        return 1 * 1024 * 1024 * 1024

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    types = {f.data.get("type") for f in result.findings}
    expected_types = {
        "derived_data",
        "archives",
        "device_support",
        "core_simulator",
        "xcode_caches",
    }
    assert expected_types.issubset(types)


def test_xcode_cleanup_fix_is_informational():
    """fix() method is informational and always succeeds."""
    mod = _get_module()

    def mock_get_dir_size(path):
        path_str = str(path)
        if "DerivedData" in path_str:
            return 2 * 1024 * 1024 * 1024  # 2 GB
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)
