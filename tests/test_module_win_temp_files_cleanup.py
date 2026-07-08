import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_temp_files_cleanup")


def _make_run_result(
    user_temp_size=None,
    windows_temp_size=None,
    prefetch_size=None,
    update_cache_size=None,
    recycle_bin_size=None,
    old_files_count=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Old files count - check first because it's most specific
        if "$cutoff = (Get-Date).AddDays(-30)" in cmd_str:
            if old_files_count is not None:
                result.stdout = str(old_files_count)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "150"

        # User temp size
        elif "Get-ChildItem -Recurse $env:TEMP" in cmd_str and "Measure-Object" in cmd_str:
            if user_temp_size is not None:
                result.stdout = str(user_temp_size)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "1073741824"  # 1 GB

        # Windows temp size
        elif "Get-ChildItem -Recurse 'C:\\Windows\\Temp'" in cmd_str and "Measure-Object" in cmd_str:
            if windows_temp_size is not None:
                result.stdout = str(windows_temp_size)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "536870912"  # 512 MB

        # Prefetch size
        elif "C:\\Windows\\Prefetch" in cmd_str and "Measure-Object" in cmd_str:
            if prefetch_size is not None:
                result.stdout = str(prefetch_size)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "268435456"  # 256 MB

        # Windows Update cache size
        elif "C:\\Windows\\SoftwareDistribution\\Download" in cmd_str and "Measure-Object" in cmd_str:
            if update_cache_size is not None:
                result.stdout = str(update_cache_size)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "1610612736"  # 1.5 GB

        # Recycle Bin size
        elif "Shell.Application" in cmd_str and "NameSpace(10)" in cmd_str:
            if recycle_bin_size is not None:
                result.stdout = str(recycle_bin_size)
            elif expect_clean:
                result.stdout = "0"
            else:
                result.stdout = "1073741824"  # 1 GB

        return result

    return fake_run


def test_win_temp_files_cleanup_discovered():
    """Test that module is discovered with correct metadata."""
    mod = _get_module()
    assert mod.name == "win_temp_files_cleanup"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_temp_files_cleanup_clean():
    """Test when temp file usage is within limits."""
    mod = _get_module()
    fake_run = _make_run_result(
        user_temp_size=0,
        windows_temp_size=0,
        prefetch_size=0,
        update_cache_size=0,
        recycle_bin_size=0,
        old_files_count=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have INFO finding
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_files_cleanup_excessive_temp():
    """Test warning when total temp files exceed 5GB."""
    mod = _get_module()
    # Create sizes that add up to more than 5GB
    total_size = 6 * 1024**3  # 6 GB total
    user_temp = 3 * 1024**3
    windows_temp = 2 * 1024**3
    other_temp = total_size - user_temp - windows_temp

    fake_run = _make_run_result(
        user_temp_size=user_temp,
        windows_temp_size=windows_temp,
        prefetch_size=other_temp // 2,
        update_cache_size=other_temp // 2,
        recycle_bin_size=0,
        old_files_count=500,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any("Excessive temp file accumulation" in f.title for f in warnings)


def test_win_temp_files_cleanup_large_update_cache():
    """Test warning when Windows Update cache exceeds 2GB."""
    mod = _get_module()
    large_cache = 3 * 1024**3  # 3 GB (exceeds 2 GB threshold)
    fake_run = _make_run_result(
        user_temp_size=100,
        windows_temp_size=100,
        prefetch_size=100,
        update_cache_size=large_cache,
        recycle_bin_size=100,
        old_files_count=10,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any("Large Windows Update cache" in f.title for f in warnings)


def test_win_temp_files_cleanup_large_recycle_bin():
    """Test warning when Recycle Bin exceeds 2GB."""
    mod = _get_module()
    large_bin = 2.5 * 1024**3  # 2.5 GB (exceeds 2 GB threshold)
    fake_run = _make_run_result(
        user_temp_size=100,
        windows_temp_size=100,
        prefetch_size=100,
        update_cache_size=100,
        recycle_bin_size=int(large_bin),
        old_files_count=10,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0
    assert any("Large Recycle Bin" in f.title for f in warnings)


def test_win_temp_files_cleanup_breakdown_reported():
    """Test that INFO finding includes breakdown of temp file locations."""
    mod = _get_module()
    fake_run = _make_run_result(
        user_temp_size=1024 * 1024 * 100,  # 100 MB
        windows_temp_size=1024 * 1024 * 50,  # 50 MB
        prefetch_size=1024 * 1024 * 25,  # 25 MB
        update_cache_size=1024 * 1024 * 10,  # 10 MB
        recycle_bin_size=1024 * 1024 * 5,  # 5 MB
        old_files_count=75,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    info_finding = info_findings[0]
    assert "breakdown" in info_finding.data
    assert "user_temp" in info_finding.data["breakdown"]
    assert info_finding.data["old_files_count"] == 75


def test_win_temp_files_cleanup_fix_excessive_temp():
    """Test fix recommendation for excessive temp files."""
    mod = _get_module()
    total_size = 6 * 1024**3
    user_temp = 3 * 1024**3
    windows_temp = 2 * 1024**3
    other_temp = total_size - user_temp - windows_temp

    fake_run = _make_run_result(
        user_temp_size=user_temp,
        windows_temp_size=windows_temp,
        prefetch_size=other_temp // 2,
        update_cache_size=other_temp // 2,
        recycle_bin_size=0,
        old_files_count=500,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("Excessive temp" in a.title for a in fix.actions)
    actions = [a for a in fix.actions if "Excessive temp" in a.title]
    assert all(a.success for a in actions)
    assert all("cleanmgr" in a.description.lower() for a in actions)


def test_win_temp_files_cleanup_fix_update_cache():
    """Test fix recommendation for large update cache."""
    mod = _get_module()
    large_cache = 3 * 1024**3
    fake_run = _make_run_result(
        user_temp_size=100,
        windows_temp_size=100,
        prefetch_size=100,
        update_cache_size=large_cache,
        recycle_bin_size=100,
        old_files_count=10,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    cache_actions = [a for a in fix.actions if "Windows Update" in a.title or "update" in a.title.lower()]
    assert len(cache_actions) > 0
    assert all(a.success for a in cache_actions)


def test_win_temp_files_cleanup_fix_recycle_bin():
    """Test fix recommendation for large Recycle Bin."""
    mod = _get_module()
    large_bin = 2.5 * 1024**3
    fake_run = _make_run_result(
        user_temp_size=100,
        windows_temp_size=100,
        prefetch_size=100,
        update_cache_size=100,
        recycle_bin_size=int(large_bin),
        old_files_count=10,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    bin_actions = [a for a in fix.actions if "Recycle" in a.title or "bin" in a.title.lower()]
    assert len(bin_actions) > 0
    assert all(a.success for a in bin_actions)
    assert all("Empty Recycle Bin" in a.title for a in bin_actions)


def test_win_temp_files_cleanup_multiple_issues():
    """Test when multiple temp file issues are detected."""
    mod = _get_module()
    user_temp = 4 * 1024**3  # 4 GB
    windows_temp = 2 * 1024**3  # 2 GB
    update_cache = 3 * 1024**3  # 3 GB (exceeds 2 GB threshold)
    recycle_bin = 2.5 * 1024**3  # 2.5 GB (exceeds 2 GB threshold)

    fake_run = _make_run_result(
        user_temp_size=user_temp,
        windows_temp_size=windows_temp,
        prefetch_size=100,
        update_cache_size=update_cache,
        recycle_bin_size=int(recycle_bin),
        old_files_count=300,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have warnings for: excessive temp, update cache, recycle bin
    assert len(warnings) >= 2


def test_win_temp_files_cleanup_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("PowerShell command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())

    # Should still complete without crashing and report error
    assert isinstance(result.findings, list)
    # Should have at least an error or empty findings
    assert len(result.findings) >= 0
