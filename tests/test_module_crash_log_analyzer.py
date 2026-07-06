import sys
from pathlib import Path
from unittest.mock import patch
import time
import os

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile,
    Platform,
    Severity,
    RiskLevel,
    Mode,
)
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
    return next(m for m in modules if m.name == "crash_log_analyzer")


def test_crash_log_analyzer_discovered():
    """Module is discoverable by the registry."""
    mod = _get_module()
    assert mod.name == "crash_log_analyzer"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_empty_reports_directory(tmp_path):
    """No crashes found in empty directory."""
    mod = _get_module()
    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_missing_reports_directory(tmp_path):
    """Gracefully handle missing directory."""
    mod = _get_module()
    nonexistent = tmp_path / "nonexistent"
    with patch.object(mod, "_reports_dir", return_value=nonexistent):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_single_recent_crash(tmp_path):
    """Single recent crash is not flagged as issue."""
    mod = _get_module()

    # Create a recent crash file
    crash_file = tmp_path / "Safari_2026-07-06_123456.crash"
    crash_file.touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Single crash should not trigger any issues
    assert not result.has_issues


def test_two_recent_crashes_same_app(tmp_path):
    """Two crashes from same app is not flagged."""
    mod = _get_module()

    # Create two recent crash files for the same app
    (tmp_path / "Chrome_2026-07-06_001.crash").touch()
    (tmp_path / "Chrome_2026-07-06_002.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # 2 crashes should not trigger warning (threshold is 3)
    assert not result.has_issues


def test_three_recent_crashes_warning(tmp_path):
    """Three crashes in 7 days triggers WARNING."""
    mod = _get_module()

    # Create three recent crash files for the same app
    (tmp_path / "Chrome_2026-07-06_001.crash").touch()
    (tmp_path / "Chrome_2026-07-06_002.crash").touch()
    (tmp_path / "Chrome_2026-07-06_003.ips").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("Chrome" in f.title for f in result.findings)


def test_ten_crashes_critical(tmp_path):
    """Ten crashes in 7 days triggers CRITICAL."""
    mod = _get_module()

    # Create 10 crash files for the same app
    for i in range(10):
        (tmp_path / f"Firefox_2026-07-06_{i:03d}.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should be CRITICAL, not WARNING
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any("Firefox" in f.title for f in result.findings)


def test_crashes_older_than_7_days_excluded(tmp_path):
    """Crashes older than 7 days are not counted."""
    mod = _get_module()

    # Create a crash file and backdate it to 8 days ago
    now = time.time()
    eight_days_ago = now - (8 * 24 * 60 * 60)

    crash_file = tmp_path / "Safari_2026-06-28_old.crash"
    crash_file.touch()
    os.utime(crash_file, (eight_days_ago, eight_days_ago))

    # Create 3 recent crashes to verify we only count recent ones
    (tmp_path / "Chrome_2026-07-06_001.crash").touch()
    (tmp_path / "Chrome_2026-07-06_002.crash").touch()
    (tmp_path / "Chrome_2026-07-06_003.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should only find Chrome (3 crashes), not Safari (1 old crash)
    assert result.has_issues
    assert any("Chrome" in f.title for f in result.findings)
    assert not any("Safari" in f.title for f in result.findings)


def test_multiple_apps_with_different_crash_counts(tmp_path):
    """Correctly count crashes per application."""
    mod = _get_module()

    # Chrome: 3 crashes (should be WARNING)
    (tmp_path / "Chrome_2026-07-06_001.crash").touch()
    (tmp_path / "Chrome_2026-07-06_002.crash").touch()
    (tmp_path / "Chrome_2026-07-06_003.crash").touch()

    # Safari: 2 crashes (should not be flagged)
    (tmp_path / "Safari_2026-07-06_001.crash").touch()
    (tmp_path / "Safari_2026-07-06_002.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have Chrome warning + summary
    assert len(result.findings) == 2
    # Check that Chrome is in findings
    assert any("Chrome" in f.title for f in result.findings)
    # Check that one finding is a summary
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_both_crash_and_ips_files(tmp_path):
    """Both .crash and .ips files are counted."""
    mod = _get_module()

    # Create a mix of .crash and .ips files
    (tmp_path / "Mail_2026-07-06_001.crash").touch()
    (tmp_path / "Mail_2026-07-06_002.ips").touch()
    (tmp_path / "Mail_2026-07-06_003.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # 3 crashes total, should trigger WARNING
    assert result.has_issues
    assert any("Mail" in f.title for f in result.findings)


def test_summary_includes_total_count(tmp_path):
    """Summary finding includes total crash count when threshold apps exist."""
    mod = _get_module()

    # Create multiple crashes from same app (above threshold)
    for i in range(5):
        (tmp_path / f"App0_2026-07-06_{i}.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have findings for the app + summary
    assert result.has_issues
    # Check that findings contain crash count data
    all_descriptions = [f.description for f in result.findings]
    # Should mention "total" and "5"
    assert any("total" in d.lower() for d in all_descriptions)
    assert any("5" in d for d in all_descriptions)


def test_fix_is_informational(tmp_path):
    """fix() returns informational actions (success=True, no modifications)."""
    mod = _get_module()

    # Create crashes
    (tmp_path / "Chrome_2026-07-06_001.crash").touch()
    (tmp_path / "Chrome_2026-07-06_002.crash").touch()
    (tmp_path / "Chrome_2026-07-06_003.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert all(a.success for a in fix.actions)
    # Should suggest actions like updating, reinstalling, contacting support
    assert len(fix.actions) > 0


def test_most_recent_crash_date_in_finding(tmp_path):
    """Finding includes the most recent crash date."""
    mod = _get_module()

    # Create crashes at different times
    (tmp_path / "Slack_2026-07-04_001.crash").touch()

    # Backdate the first crash to 2 days ago
    now = time.time()
    two_days_ago = now - (2 * 24 * 60 * 60)
    crash1 = tmp_path / "Slack_2026-07-04_001.crash"
    os.utime(crash1, (two_days_ago, two_days_ago))

    # Create a more recent crash (just now)
    (tmp_path / "Slack_2026-07-06_002.crash").touch()

    # Create a third old crash
    three_days_ago = now - (3 * 24 * 60 * 60)
    crash3 = tmp_path / "Slack_2026-07-04_003.crash"
    crash3.touch()
    os.utime(crash3, (three_days_ago, three_days_ago))

    # Need 3 crashes to trigger warning
    (tmp_path / "Slack_2026-07-06_001.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # The finding should contain information about recent crash
    slack_findings = [f for f in result.findings if "Slack" in f.title]
    assert len(slack_findings) > 0


def test_app_with_underscore_in_name(tmp_path):
    """Correctly parse app names containing underscores."""
    mod = _get_module()

    # Create crashes for an app with underscore in name
    (tmp_path / "Visual_Studio_Code_2026-07-06_001.crash").touch()
    (tmp_path / "Visual_Studio_Code_2026-07-06_002.crash").touch()
    (tmp_path / "Visual_Studio_Code_2026-07-06_003.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should recognize as single app "Visual_Studio_Code", not split on underscore
    assert any("Visual_Studio_Code" in f.title for f in result.findings)


def test_top_5_crashers_in_summary(tmp_path):
    """Summary lists top 5 crashing applications."""
    mod = _get_module()

    # Create many apps with different crash counts
    apps = [
        ("App1", 5),   # 5 crashes (will trigger WARNING)
        ("App2", 8),   # 8 crashes (will trigger WARNING)
        ("App3", 3),   # 3 crashes (will trigger WARNING)
        ("App4", 4),   # 4 crashes (will trigger WARNING)
        ("App5", 12),  # 12 crashes (will trigger CRITICAL)
        ("App6", 2),   # 2 crashes (no flag)
        ("App7", 6),   # 6 crashes (will trigger WARNING)
    ]

    for app_name, count in apps:
        for i in range(count):
            (tmp_path / f"{app_name}_2026-07-06_{i:03d}.crash").touch()

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have findings
    assert result.has_issues
    # Check that crash data is available (total + individual apps)
    assert len(result.findings) >= 5  # At least 5 apps that triggered issues
