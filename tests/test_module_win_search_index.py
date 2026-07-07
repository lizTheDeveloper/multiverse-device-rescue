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
    return next(m for m in modules if m.name == "win_search_index")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Healthy search index: service running, low CPU, reasonable size"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-Service WSearch" in cmd_str:
            return _make_subprocess_result("Running")
        elif "Get-Process SearchIndexer" in cmd_str:
            return _make_subprocess_result("8.5")  # 8.5% CPU
        elif "DataDirectory" in cmd_str:
            return _make_subprocess_result("C:\\ProgramData\\Microsoft\\Windows\\Caches")
        elif "Measure-Object" in cmd_str:
            return _make_subprocess_result("2.3")  # 2.3 GB
        elif "ItemCount" in cmd_str:
            return _make_subprocess_result("1250000")  # 1.25 million items
        return _make_subprocess_result()
    return fake_run


def _fake_run_service_stopped():
    """Search service is stopped"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-Service WSearch" in cmd_str:
            return _make_subprocess_result("Stopped")
        elif "Get-Process SearchIndexer" in cmd_str:
            return _make_subprocess_result("")
        elif "DataDirectory" in cmd_str:
            return _make_subprocess_result("C:\\ProgramData\\Microsoft\\Windows\\Caches")
        elif "Measure-Object" in cmd_str:
            return _make_subprocess_result("2.3")
        elif "ItemCount" in cmd_str:
            return _make_subprocess_result("1250000")
        return _make_subprocess_result()
    return fake_run


def _fake_run_high_cpu():
    """SearchIndexer using high CPU"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-Service WSearch" in cmd_str:
            return _make_subprocess_result("Running")
        elif "Get-Process SearchIndexer" in cmd_str:
            return _make_subprocess_result("42.5")  # 42.5% CPU
        elif "DataDirectory" in cmd_str:
            return _make_subprocess_result("C:\\ProgramData\\Microsoft\\Windows\\Caches")
        elif "Measure-Object" in cmd_str:
            return _make_subprocess_result("2.3")
        elif "ItemCount" in cmd_str:
            return _make_subprocess_result("1250000")
        return _make_subprocess_result()
    return fake_run


def _fake_run_bloated_index():
    """Search index is bloated (>5 GB)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-Service WSearch" in cmd_str:
            return _make_subprocess_result("Running")
        elif "Get-Process SearchIndexer" in cmd_str:
            return _make_subprocess_result("5.2")
        elif "DataDirectory" in cmd_str:
            return _make_subprocess_result("C:\\ProgramData\\Microsoft\\Windows\\Caches")
        elif "Measure-Object" in cmd_str:
            return _make_subprocess_result("7.8")  # 7.8 GB
        elif "ItemCount" in cmd_str:
            return _make_subprocess_result("3500000")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_issues():
    """Multiple issues: stopped service, high CPU, bloated index"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-Service WSearch" in cmd_str:
            return _make_subprocess_result("Stopped")
        elif "Get-Process SearchIndexer" in cmd_str:
            return _make_subprocess_result("50.0")  # 50% CPU
        elif "DataDirectory" in cmd_str:
            return _make_subprocess_result("C:\\ProgramData\\Microsoft\\Windows\\Caches")
        elif "Measure-Object" in cmd_str:
            return _make_subprocess_result("8.5")  # 8.5 GB
        elif "ItemCount" in cmd_str:
            return _make_subprocess_result("4000000")
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell returns errors"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_search_index_discovered():
    """Module should be discoverable with correct metadata"""
    mod = _get_module()
    assert mod.name == "win_search_index"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_search_index_healthy_system():
    """Healthy search index should report info"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO finding for healthy status
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("healthy" in f.title.lower() for f in result.findings)


def test_win_search_index_service_stopped():
    """Stopped service should flag WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_stopped()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("stopped" in f.title.lower() for f in result.findings)


def test_win_search_index_high_cpu():
    """High CPU usage should flag WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_cpu()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("high cpu" in f.title.lower() for f in result.findings)
    # Check data contains CPU value
    cpu_finding = next(f for f in result.findings if "high cpu" in f.title.lower())
    assert cpu_finding.data.get("cpu_percent") == 42.5


def test_win_search_index_bloated():
    """Bloated index (>5 GB) should flag WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bloated_index()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("bloated" in f.title.lower() for f in result.findings)
    # Check data contains size
    size_finding = next(f for f in result.findings if "bloated" in f.title.lower())
    assert size_finding.data.get("index_size_gb") == 7.8


def test_win_search_index_multiple_issues():
    """Multiple issues should all be flagged"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNINGs for all three issues
    warning_count = sum(1 for f in result.findings if f.severity == Severity.WARNING)
    assert warning_count >= 2  # At least stopped service + high CPU or bloated


def test_win_search_index_powershell_error():
    """PowerShell errors should not crash module"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should not crash, returns findings (may have info that values couldn't be determined)
    assert isinstance(result.findings, list)


def test_win_search_index_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_cpu()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions for findings that need fixing
    if check.has_issues:
        assert len(fix.actions) > 0


def test_win_search_index_fix_multiple_issues():
    """fix() should provide appropriate actions for each issue"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Check for service restart action
    assert any("restart" in a.title.lower() or "start" in a.title.lower() for a in fix.actions)
    # Check for rebuild/fix actions
    assert any("rebuild" in a.description.lower() or "rebuild" in a.title.lower() for a in fix.actions)
