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
        os_version="11.0",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _make_profile_old_windows():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="6.1",  # Windows 7
        architecture="x86_64",
        cpu_model="Intel Core i5",
        cpu_cores=4,
        ram_bytes=4 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_memory_diagnostics")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _powershell_ram_info_healthy():
    """Normal RAM info: 16GB total, 8GB available."""
    return """{
  "TotalVisibleMemorySize": 16777216,
  "FreePhysicalMemory": 8388608
}"""


def _powershell_ram_info_low_memory():
    """Low memory: 16GB total, 1GB available (< 10%)."""
    return """{
  "TotalVisibleMemorySize": 16777216,
  "FreePhysicalMemory": 1048576
}"""


def _powershell_ram_info_critical():
    """Critical memory: 4GB total, 256MB available."""
    return """{
  "TotalVisibleMemorySize": 4194304,
  "FreePhysicalMemory": 262144
}"""


def _powershell_diagnostic_no_errors():
    """Diagnostic ran successfully with no errors."""
    return """[
  {
    "TimeCreated": "2026-07-05T10:30:00",
    "Message": "Windows Memory Diagnostic completed successfully. No problems detected."
  }
]"""


def _powershell_diagnostic_with_errors():
    """Diagnostic ran and found errors."""
    return """[
  {
    "TimeCreated": "2026-07-04T14:20:00",
    "Message": "Windows Memory Diagnostic detected errors in RAM. Test failed on slot 1. Hardware failure detected."
  }
]"""


def _powershell_diagnostic_never_run():
    """No diagnostic events found - never run."""
    return ""


def _powershell_multiple_diagnostics():
    """Multiple diagnostic runs - most recent is healthy."""
    return """[
  {
    "TimeCreated": "2026-07-05T10:30:00",
    "Message": "Windows Memory Diagnostic completed successfully. No problems detected."
  },
  {
    "TimeCreated": "2026-06-28T15:45:00",
    "Message": "Windows Memory Diagnostic completed successfully. No problems detected."
  }
]"""


def _fake_run_healthy_ram_no_diagnostics():
    """Healthy RAM, no diagnostics run yet."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_healthy())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_diagnostic_never_run())
        return _make_subprocess_result()
    return fake_run


def _fake_run_healthy_with_successful_diagnostic():
    """Healthy RAM with successful diagnostic."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_healthy())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_diagnostic_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_low_memory():
    """Low memory pressure."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_low_memory())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_diagnostic_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_critical_memory():
    """Critical memory low."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_critical())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_diagnostic_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_diagnostic_errors():
    """Diagnostic found errors."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_healthy())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_diagnostic_with_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_diagnostics():
    """Multiple diagnostics - most recent is healthy."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_info_healthy())
            elif "Get-WinEvent" in cmd_str and "MemoryDiagnostics" in cmd_str:
                return _make_subprocess_result(_powershell_multiple_diagnostics())
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_win_memory_diagnostics_discovered():
    mod = _get_module()
    assert mod.name == "win_memory_diagnostics"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_memory_diagnostics_healthy_no_diagnostics():
    """Healthy RAM but no diagnostics run yet."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ram_no_diagnostics()):
        result = mod.check(_make_profile())
    # Should have INFO for healthy RAM
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should have WARNING for never run on old machine if os_version indicates old Windows
    # On Windows 11, no warning for never run


def test_win_memory_diagnostics_healthy_with_diagnostic():
    """Healthy RAM with successful diagnostic."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention no diagnostic errors
    finding_strs = [f.description for f in result.findings]
    assert any("diagnostic" in s.lower() for s in finding_strs)


def test_win_memory_diagnostics_low_memory():
    """Low memory pressure warning."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_memory()):
        result = mod.check(_make_profile())
    # Should have WARNING for low memory
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("low memory" in f.title.lower() for f in warning_findings)


def test_win_memory_diagnostics_critical_memory():
    """Critical memory pressure."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical_memory()):
        result = mod.check(_make_profile())
    # Should have WARNING for critical memory
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("memory" in f.title.lower() for f in warning_findings)


def test_win_memory_diagnostics_diagnostic_errors():
    """Diagnostic found errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diagnostic_errors()):
        result = mod.check(_make_profile())
    # Should have WARNING for diagnostic errors
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("diagnostic" in f.title.lower() for f in warning_findings)
    assert any("error" in f.title.lower() for f in warning_findings)


def test_win_memory_diagnostics_multiple_diagnostics():
    """Multiple diagnostic runs."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_diagnostics()):
        result = mod.check(_make_profile())
    # Should have INFO for healthy status
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_memory_diagnostics_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should have WARNING about failed retrieval
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_memory_diagnostics_old_windows_never_run():
    """Old Windows with no diagnostics run."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ram_no_diagnostics()):
        result = mod.check(_make_profile_old_windows())
    # Should have WARNING for never run on old machine
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("never been run" in f.title.lower() for f in warning_findings)


def test_win_memory_diagnostics_fix_diagnostic_errors():
    """Fix action for diagnostic errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_diagnostic_errors()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be safe and informational
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_memory_diagnostics_fix_low_memory():
    """Fix action for low memory."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_memory()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_memory_diagnostics_fix_healthy():
    """Fix action for healthy system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_memory_diagnostics_fix_all_succeeded():
    """All fix actions should succeed (informational)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.MANUAL)
    # fix() should always succeed with informational actions
    assert fix_result.all_succeeded


def test_win_memory_diagnostics_memory_pressure_calculation():
    """Memory pressure percentage is calculated correctly."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_memory()):
        result = mod.check(_make_profile())
    # Find the low memory finding
    low_mem_findings = [
        f for f in result.findings if f.data.get("check") == "low_memory_pressure"
    ]
    if low_mem_findings:
        finding = low_mem_findings[0]
        percent = finding.data.get("percent_available", 0)
        assert percent < 10  # Should be low


def test_win_memory_diagnostics_format_bytes():
    """RAM capacity is correctly formatted in findings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        result = mod.check(_make_profile())
    # Check that capacity is formatted in GB/MB/TB
    finding_strs = [f.description for f in result.findings]
    assert any("GB" in s or "MB" in s for s in finding_strs)


def test_win_memory_diagnostics_multiple_checks_consistent():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_successful_diagnostic()):
        result2 = mod.check(_make_profile())
    # Results should be consistent
    assert len(result1.findings) == len(result2.findings)
    if result1.findings and result2.findings:
        # Check at least one finding is the same severity
        severities1 = [f.severity for f in result1.findings]
        severities2 = [f.severity for f in result2.findings]
        assert severities1 == severities2
