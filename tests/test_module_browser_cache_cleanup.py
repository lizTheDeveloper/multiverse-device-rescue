import sys
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
    return next(m for m in modules if m.name == "browser_cache_cleanup")


def _create_cache_files(cache_dir: Path, size_bytes: int):
    """Create dummy files in cache directory to reach target size."""
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Create files in chunks to reach target size
    chunk_size = 1024 * 1024  # 1 MB chunks
    chunks = size_bytes // chunk_size
    remainder = size_bytes % chunk_size

    for i in range(chunks):
        file_path = cache_dir / f"file_{i}.cache"
        with open(file_path, "wb") as f:
            f.write(b"x" * chunk_size)

    if remainder > 0:
        file_path = cache_dir / "file_remainder.cache"
        with open(file_path, "wb") as f:
            f.write(b"x" * remainder)


def test_browser_cache_cleanup_discovered():
    """Test that module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "browser_cache_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_browser_cache_cleanup_no_caches(tmp_path):
    """Test case: no browser caches present."""
    mod = _get_module()

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # No caches means no findings
    assert not result.has_issues


def test_browser_cache_cleanup_small_safari_cache(tmp_path):
    """Test case: small Safari cache only."""
    mod = _get_module()

    # Create small Safari cache (100 MB)
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    _create_cache_files(safari_cache, 100 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have one INFO finding about Safari
    assert result.has_issues
    assert any(f.data.get("browser") == "Safari" for f in result.findings)
    # Should be INFO severity, not WARNING
    assert all(f.severity != Severity.WARNING for f in result.findings)


def test_browser_cache_cleanup_small_all_browsers(tmp_path):
    """Test case: small caches for all browsers."""
    mod = _get_module()

    # Create small caches for each browser (500 MB each = 2 GB total, under limit)
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    firefox_cache = tmp_path / "Library/Caches/Firefox/Profiles"
    edge_cache = tmp_path / "Library/Caches/Microsoft Edge"

    _create_cache_files(safari_cache, 500 * 1024 * 1024)
    _create_cache_files(chrome_cache, 500 * 1024 * 1024)
    _create_cache_files(firefox_cache, 500 * 1024 * 1024)
    _create_cache_files(edge_cache, 500 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have findings for each browser, all INFO severity
    assert result.has_issues
    assert len([f for f in result.findings if f.data.get("type") == "browser_cache"]) == 4
    # No WARNING severity since under 2GB individual and 5GB total
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_browser_cache_cleanup_large_single_browser(tmp_path):
    """Test case: one browser cache exceeds 2 GB."""
    mod = _get_module()

    # Create large Chrome cache (3 GB)
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    _create_cache_files(chrome_cache, 3 * 1024 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have findings with at least one WARNING
    assert result.has_issues
    # Should have a large_browser_cache warning for Chrome
    assert any(
        f.data.get("type") == "large_browser_cache" and f.data.get("browser") == "Chrome"
        for f in result.findings
    )
    # Should have WARNING severity
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_browser_cache_cleanup_high_total_cache(tmp_path):
    """Test case: total browser cache exceeds 5 GB."""
    mod = _get_module()

    # Create caches that total > 5 GB but each < 2GB
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    firefox_cache = tmp_path / "Library/Caches/Firefox/Profiles"
    edge_cache = tmp_path / "Library/Caches/Microsoft Edge"

    _create_cache_files(safari_cache, 2 * 1024 * 1024 * 1024)  # 2 GB
    _create_cache_files(chrome_cache, 1500 * 1024 * 1024)  # 1.5 GB
    _create_cache_files(firefox_cache, 1500 * 1024 * 1024)  # 1.5 GB
    _create_cache_files(edge_cache, 1 * 1024 * 1024 * 1024)  # 1 GB
    # Total: 6 GB

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have WARNING for total cache
    assert result.has_issues
    assert any(
        f.data.get("type") == "total_browser_cache" for f in result.findings
    )
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_browser_cache_cleanup_multiple_large_browsers(tmp_path):
    """Test case: multiple browsers with caches > 2 GB each."""
    mod = _get_module()

    # Create multiple large caches
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"

    _create_cache_files(safari_cache, 3 * 1024 * 1024 * 1024)  # 3 GB
    _create_cache_files(chrome_cache, 2.5 * 1024 * 1024 * 1024)  # 2.5 GB

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have WARNINGs for both large individual caches and high total
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 2  # At least warnings for both browsers
    assert any(
        f.data.get("type") == "large_browser_cache" for f in warning_findings
    )


def test_browser_cache_cleanup_fix_is_informational(tmp_path):
    """Test that fix() is informational and always succeeds."""
    mod = _get_module()

    # Create a cache that triggers warnings
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    _create_cache_files(chrome_cache, 3 * 1024 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should succeed
    assert all(a.success for a in fix.actions)


def test_browser_cache_cleanup_fix_actions_count(tmp_path):
    """Test that fix() generates appropriate actions for each finding."""
    mod = _get_module()

    # Create multiple caches with warnings
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    _create_cache_files(safari_cache, 100 * 1024 * 1024)
    _create_cache_files(chrome_cache, 200 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)
    # All should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_browser_cache_cleanup_large_total_and_individual(tmp_path):
    """Test case: both individual browser and total exceed thresholds."""
    mod = _get_module()

    # Create scenario where we exceed both thresholds
    safari_cache = tmp_path / "Library/Caches/com.apple.Safari"
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"

    _create_cache_files(safari_cache, 2.5 * 1024 * 1024 * 1024)  # 2.5 GB (> 2 GB)
    _create_cache_files(chrome_cache, 3 * 1024 * 1024 * 1024)  # 3 GB (> 2 GB)
    # Total: 5.5 GB (> 5 GB)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have WARNING for total and for individual large caches
    assert result.has_issues
    assert any(
        f.data.get("type") == "total_browser_cache" for f in result.findings
    )
    assert any(
        f.data.get("type") == "large_browser_cache" for f in result.findings
    )
    warning_count = len([f for f in result.findings if f.severity == Severity.WARNING])
    assert warning_count >= 2  # At least total warning + individual warning


def test_browser_cache_cleanup_path_handling(tmp_path):
    """Test that module handles missing cache directories gracefully."""
    mod = _get_module()

    # Create only one browser cache, others don't exist
    chrome_cache = tmp_path / "Library/Caches/Google/Chrome"
    _create_cache_files(chrome_cache, 50 * 1024 * 1024)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should handle missing directories gracefully
    assert result.has_issues
    # Should only report Chrome
    assert len([f for f in result.findings if f.data.get("browser") == "Chrome"]) >= 1
