import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_temp_files")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_clean():
    """No significant temp files"""
    def fake_run(cmd, **kwargs):
        # Convert list to string for matching
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # Small sizes for all locations
        if "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB (WU cache)
        elif "Installer" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        elif "Local\\Temp" in cmd_str:
            return _make_subprocess_result("41943040")  # 40 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB (Recycle Bin)
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_wu_cache():
    """Large Windows Update cache (exceeds 1GB threshold)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 2 GB Windows Update cache
        if "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("2147483648")  # 2 GB
        elif "Installer" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        elif "Local\\Temp" in cmd_str:
            return _make_subprocess_result("41943040")  # 40 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_installer_cache():
    """Large Windows Installer cache"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Installer" in cmd_str:
            return _make_subprocess_result("1610612736")  # 1.5 GB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        elif "Local\\Temp" in cmd_str:
            return _make_subprocess_result("41943040")  # 40 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_high_total():
    """Total exceeds 5GB threshold"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        elif "Installer" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        elif "Local\\Temp" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("1610612736")  # 1.5 GB (total = 5.5 GB)
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell returns error"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_temp_files_discovered():
    mod = _get_module()
    assert mod.name == "win_temp_files"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_temp_files_clean_system():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should have findings for small amounts
    assert result.has_issues
    # All should be INFO (none exceed thresholds)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_temp_files_large_wu_cache():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_wu_cache()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for Windows Update cache (exceeds 1GB)
    assert any(f.data.get("type") == "windows_update" and f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_files_large_installer_cache():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_installer_cache()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO for installer cache
    assert any(f.data.get("type") == "installer_cache" for f in result.findings)


def test_win_temp_files_high_total():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_total()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for total (exceeds 5GB)
    assert any(f.data.get("type") == "total_reclaimable" and f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_files_powershell_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should not crash, just return empty findings
    assert not result.has_issues


def test_win_temp_files_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_wu_cache()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_temp_files_all_locations_reported():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should report all 5 locations plus total
    location_types = {f.data.get("type") for f in result.findings}
    expected = {"total_reclaimable", "windows_update", "installer_cache", "prefetch", "user_temp", "recycle_bin"}
    assert expected == location_types
