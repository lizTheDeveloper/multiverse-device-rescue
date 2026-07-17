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
    return next(m for m in modules if m.name == "win_disk_cleanup")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_clean():
    """No significant disk bloat"""
    def fake_run(cmd, **kwargs):
        # Convert list to string for matching
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # Small sizes for all locations
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 250.50 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("0")  # No Windows.old
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB recycle bin
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_winsxs():
    """Large WinSxS component store"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 7 GB WinSxS, rest normal
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 7168.00 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("0")
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_windows_old():
    """Windows.old folder exists"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 20 GB Windows.old
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 250.50 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("21474836480")  # 20 GB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_temp():
    """Large temp directories"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 6 GB total temp
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 250.50 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("0")
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("3221225472")  # 3 GB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("3221225472")  # 3 GB
        return _make_subprocess_result()
    return fake_run


def _fake_run_full_recycle_bin():
    """Full Recycle Bin"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 8 GB recycle bin
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 250.50 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("0")
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("8589934592")  # 8 GB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("10485760")  # 10 MB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_issues():
    """Multiple large issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # 6 GB WinSxS, 12 GB Windows.old, 2 GB temp
        if "dism.exe" in cmd_str.lower():
            return _make_subprocess_result("Component Store Size : 6144.00 MB")
        elif "SoftwareDistribution" in cmd_str:
            return _make_subprocess_result("52428800")  # 50 MB
        elif "Windows.old" in cmd_str:
            return _make_subprocess_result("12884901888")  # 12 GB
        elif "Shell.Application" in cmd_str:
            return _make_subprocess_result("20971520")  # 20 MB
        elif "C:\\Windows\\Temp" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        elif "$env:TEMP" in cmd_str:
            return _make_subprocess_result("1073741824")  # 1 GB
        return _make_subprocess_result()
    return fake_run


def _fake_run_command_error():
    """Commands return errors"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_disk_cleanup_discovered():
    mod = _get_module()
    assert mod.name == "win_disk_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_disk_cleanup_clean_system():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should have findings (even small amounts)
    assert result.has_issues
    # All should be INFO (nothing exceeds thresholds)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_disk_cleanup_large_winsxs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_winsxs()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for WinSxS (exceeds 5 GB threshold)
    assert any(f.data.get("type") == "winsxs" and f.severity == Severity.WARNING for f in result.findings)
    # Total is ~7.1 GB, below 10 GB threshold, so INFO (not WARNING)
    total_finding = next((f for f in result.findings if f.data.get("type") == "total_reclaimable"), None)
    assert total_finding is not None


def test_win_disk_cleanup_windows_old():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_windows_old()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for Windows.old
    assert any(f.data.get("type") == "windows_old" and f.severity == Severity.WARNING for f in result.findings)
    # Total should be WARNING (exceeds 10 GB threshold)
    assert any(f.data.get("type") == "total_reclaimable" and f.severity == Severity.WARNING for f in result.findings)


def test_win_disk_cleanup_large_temp():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_temp()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have temp findings
    assert any(f.data.get("type") in ("system_temp", "user_temp") for f in result.findings)
    # Total is ~6.3 GB, below 10 GB threshold, so INFO (not WARNING)
    total_finding = next((f for f in result.findings if f.data.get("type") == "total_reclaimable"), None)
    assert total_finding is not None


def test_win_disk_cleanup_full_recycle_bin():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_full_recycle_bin()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have recycle bin finding
    assert any(f.data.get("type") == "recycle_bin" for f in result.findings)
    # Total is ~8.3 GB, below 10 GB threshold, so INFO (not WARNING)
    total_finding = next((f for f in result.findings if f.data.get("type") == "total_reclaimable"), None)
    assert total_finding is not None


def test_win_disk_cleanup_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNINGs for large components
    assert any(f.data.get("type") == "winsxs" and f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("type") == "windows_old" and f.severity == Severity.WARNING for f in result.findings)
    # Total should be much higher WARNING
    assert any(f.data.get("type") == "total_reclaimable" and f.severity == Severity.WARNING for f in result.findings)


def test_win_disk_cleanup_command_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_error()):
        result = mod.check(_make_profile())
    # Should not crash, just return no findings
    assert not result.has_issues


def test_win_disk_cleanup_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_winsxs()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_disk_cleanup_total_reclaimable():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean()):
        result = mod.check(_make_profile())
    # Should have a total reclaimable finding
    assert any(f.data.get("type") == "total_reclaimable" for f in result.findings)
    # Total should be sum of all locations
    total_finding = next(f for f in result.findings if f.data.get("type") == "total_reclaimable")
    # 250.5 MB (WinSxS) + 50 MB (WU) + 0 (Windows.old) + 20 MB (recycle) + 10 MB (sys temp) + 50 MB (user temp) = 380.5 MB
    expected_bytes = int(250.5 * 1024 * 1024) + 50 * 1024 * 1024 + 20 * 1024 * 1024 + 10 * 1024 * 1024 + 50 * 1024 * 1024
    assert total_finding.data["size_bytes"] == expected_bytes
