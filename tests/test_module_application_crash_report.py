import sys
import os
import time
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
    return next(m for m in modules if m.name == "application_crash_report")


def test_application_crash_report_discovered():
    mod = _get_module()
    assert mod.name == "application_crash_report"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_application_crash_report_no_crashes(tmp_path):
    """Test healthy case with no crash files"""
    mod = _get_module()
    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_application_crash_report_empty_directory(tmp_path):
    """Test with directory that exists but has no crash files"""
    mod = _get_module()
    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_application_crash_report_missing_directory():
    """Test with missing directory"""
    mod = _get_module()
    nonexistent = Path("/nonexistent/path/to/reports")
    with patch.object(mod, "_reports_dir", return_value=nonexistent):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_application_crash_report_high_frequency(tmp_path):
    """Test warning for app with >5 crashes in 30 days"""
    mod = _get_module()
    now = time.time()

    # Create 7 crash files for TestApp within 30 days
    for i in range(7):
        mtime = now - (i * 24 * 60 * 60)  # Spread across days
        crash_file = tmp_path / f"TestApp_2026-07-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have WARNING for high frequency + INFO for summary
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Check that TestApp is mentioned in findings
    assert any(f.data.get("app_name") == "TestApp" for f in result.findings)


def test_application_crash_report_system_app_crash(tmp_path):
    """Test warning for system app crashes"""
    mod = _get_module()
    now = time.time()

    # Create crash files for Finder (system app)
    for i in range(2):
        mtime = now - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"Finder_2026-07-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should flag system app crashes as WARNING regardless of count
    assert any(
        f.severity == Severity.WARNING and f.data.get("is_system_app")
        for f in result.findings
    )


def test_application_crash_report_system_apps_critical(tmp_path):
    """Test all critical system apps are flagged"""
    mod = _get_module()
    now = time.time()

    critical_apps = ["Finder", "WindowServer", "loginwindow"]

    # Create crash files for each critical system app
    for app_idx, app_name in enumerate(critical_apps):
        mtime = now - (app_idx * 24 * 60 * 60)
        crash_file = tmp_path / f"{app_name}_2026-07-0{app_idx}_00{app_idx}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    system_warnings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and f.data.get("is_system_app")
    ]
    assert len(system_warnings) >= 3


def test_application_crash_report_old_crashes_ignored(tmp_path):
    """Test that crashes older than 30 days are ignored"""
    mod = _get_module()
    now = time.time()
    forty_days_ago = now - (40 * 24 * 60 * 60)

    # Create crash files older than 30 days
    for i in range(10):
        mtime = forty_days_ago - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"OldApp_2026-06-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Old crashes should be ignored
    assert not result.has_issues


def test_application_crash_report_mixed_timeframes(tmp_path):
    """Test mix of recent and old crashes"""
    mod = _get_module()
    now = time.time()

    # Recent crashes (6 = above threshold)
    for i in range(6):
        mtime = now - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"RecentApp_2026-07-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    # Old crashes (should be ignored)
    forty_days_ago = now - (40 * 24 * 60 * 60)
    for i in range(5):
        mtime = forty_days_ago - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"OldApp_2026-06-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Only recent crashes count
    assert result.has_issues
    assert any(f.data.get("app_name") == "RecentApp" for f in result.findings)
    assert not any(f.data.get("app_name") == "OldApp" for f in result.findings)


def test_application_crash_report_summary_finding(tmp_path):
    """Test summary finding includes top crashers"""
    mod = _get_module()
    now = time.time()

    # Create crashes for multiple apps
    apps = [("AppA", 8), ("AppB", 5), ("AppC", 2)]
    for app_name, count in apps:
        for i in range(count):
            mtime = now - (i * 24 * 60 * 60)
            crash_file = tmp_path / f"{app_name}_2026-07-0{i:02d}_00{i:02d}.crash"
            crash_file.touch()
            os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have summary INFO finding
    summary = next(
        (f for f in result.findings if f.severity == Severity.INFO),
        None,
    )
    assert summary is not None
    assert summary.data.get("total_crashes") == 15


def test_application_crash_report_ips_files(tmp_path):
    """Test that .ips files are also counted"""
    mod = _get_module()
    now = time.time()

    # Create mix of .crash and .ips files
    for i in range(3):
        mtime = now - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"TestApp_2026-07-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    for i in range(3, 6):
        mtime = now - (i * 24 * 60 * 60)
        ips_file = tmp_path / f"TestApp_2026-07-0{i}_00{i}.ips"
        ips_file.touch()
        os.utime(ips_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        result = mod.check(_make_profile())

    assert result.has_issues
    # TestApp should have 6 crashes total
    app_findings = [f for f in result.findings if f.data.get("app_name") == "TestApp"]
    assert any(f.data.get("crash_count") == 6 for f in app_findings)


def test_application_crash_report_parse_app_name():
    """Test app name parsing from crash filenames"""
    mod = _get_module()

    test_cases = [
        ("TestApp_2026-07-06_001.crash", "TestApp"),
        ("Visual_Studio_Code_2026-07-06_001.crash", "Visual_Studio_Code"),
        ("MyApp_2026-07-05_042.ips", "MyApp"),
        ("Safari_2026-07-04_100.crash", "Safari"),
    ]

    for filename, expected_name in test_cases:
        result = mod._parse_app_name(Path(filename))
        assert result == expected_name


def test_application_crash_report_fix_is_informational(tmp_path):
    """Test that fix() provides informational guidance only"""
    mod = _get_module()
    now = time.time()

    # Create crash files to trigger findings
    for i in range(7):
        mtime = now - (i * 24 * 60 * 60)
        crash_file = tmp_path / f"TestApp_2026-07-0{i}_00{i}.crash"
        crash_file.touch()
        os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_application_crash_report_fix_addresses_system_apps(tmp_path):
    """Test that fix provides specific guidance for system apps"""
    mod = _get_module()
    now = time.time()

    # Create crash file for Finder
    mtime = now - (24 * 60 * 60)
    crash_file = tmp_path / "Finder_2026-07-01_001.crash"
    crash_file.touch()
    os.utime(crash_file, (mtime, mtime))

    with patch.object(mod, "_reports_dir", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    # Should have action addressing system app
    system_actions = [a for a in fix.actions if "system app" in a.title.lower()]
    assert len(system_actions) > 0
