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
    return next(m for m in modules if m.name == "win_temp_cleanup")


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
        if "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("5242880")  # 5 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_temp():
    """Large temp directory"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 2 GB in temp, rest normal
        if "$env:TEMP" in cmd_str:
            return _make_subprocess_result("2147483648")  # 2 GB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("5242880")  # 5 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_windows_update():
    """Large Windows Update cache"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("3221225472")  # 3 GB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_full_recycle_bin():
    """Full Recycle Bin"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("5242880")  # 5 MB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("5368709120")  # 5 GB
        elif "Prefetch" in cmd_str:
            return _make_subprocess_result("31457280")  # 30 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell returns error"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_temp_cleanup_discovered():
    mod = _get_module()
    assert mod.name == "win_temp_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_temp_cleanup_clean_system():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should still have findings for small amounts
    assert result.has_issues
    # All should be INFO (none exceed 1 GB threshold)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_temp_cleanup_large_temp():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_temp()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for total and for user temp
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("type") == "user_temp" and f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_cleanup_large_windows_update():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_windows_update()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("type") == "windows_update" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_cleanup_full_recycle_bin():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_full_recycle_bin()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("type") == "recycle_bin" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_temp_cleanup_powershell_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should not crash, just return empty findings
    assert not result.has_issues


def test_win_temp_cleanup_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_temp()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_temp_cleanup_total_reclaimable():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should have a total reclaimable finding
    assert any(f.data.get("type") == "total_reclaimable" for f in result.findings)
    # Total should be sum of all locations
    total_finding = next(f for f in result.findings if f.data.get("type") == "total_reclaimable")
    # 50 + 10 + 5 + 20 + 30 = 115 MB
    assert total_finding.data["size_bytes"] == 115 * 1024 * 1024
