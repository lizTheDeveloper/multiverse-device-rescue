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


def _powershell_physical_memory_2x8gb_3200mhz():
    """Two 8GB modules at 3200 MHz."""
    return """[
  {
    "BankLabel": "BANK 0",
    "Capacity": 8589934592,
    "Speed": 3200,
    "Manufacturer": "Kingston",
    "MemoryType": 26,
    "FormFactor": 12
  },
  {
    "BankLabel": "BANK 1",
    "Capacity": 8589934592,
    "Speed": 3200,
    "Manufacturer": "Kingston",
    "MemoryType": 26,
    "FormFactor": 12
  }
]"""


def _powershell_physical_memory_mismatched_speed():
    """Two modules with different speeds."""
    return """[
  {
    "BankLabel": "BANK 0",
    "Capacity": 8589934592,
    "Speed": 3200,
    "Manufacturer": "Kingston",
    "MemoryType": 26,
    "FormFactor": 12
  },
  {
    "BankLabel": "BANK 1",
    "Capacity": 8589934592,
    "Speed": 2666,
    "Manufacturer": "Corsair",
    "MemoryType": 26,
    "FormFactor": 12
  }
]"""


def _powershell_physical_memory_mismatched_capacity():
    """Two modules with different capacities."""
    return """[
  {
    "BankLabel": "BANK 0",
    "Capacity": 8589934592,
    "Speed": 3200,
    "Manufacturer": "Kingston",
    "MemoryType": 26,
    "FormFactor": 12
  },
  {
    "BankLabel": "BANK 1",
    "Capacity": 16106127360,
    "Speed": 3200,
    "Manufacturer": "Kingston",
    "MemoryType": 26,
    "FormFactor": 12
  }
]"""


def _powershell_physical_memory_low_ram():
    """2GB total RAM."""
    return """[
  {
    "BankLabel": "BANK 0",
    "Capacity": 2147483648,
    "Speed": 1333,
    "Manufacturer": "Micron",
    "MemoryType": 24,
    "FormFactor": 12
  }
]"""


def _powershell_ram_utilization_healthy():
    """16GB total, 10GB usable (all available)."""
    return """{
  "TotalVisibleMemorySize": 16777216,
  "FreePhysicalMemory": 10485760
}"""


def _powershell_ram_utilization_degraded():
    """16GB total, only 14.4GB usable (10% missing)."""
    return """{
  "TotalVisibleMemorySize": 16777216,
  "FreePhysicalMemory": 1048576
}"""


def _powershell_memory_errors_found():
    """Memory diagnostic found 3 errors."""
    return """Count
-----
    3"""


def _powershell_memory_errors_none():
    """No memory errors found."""
    return """Count
-----
    0"""


def _fake_run_healthy_2x8gb():
    """Healthy: 2x8GB matched modules."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_2x8gb_3200mhz())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_none())
            elif "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_utilization_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_mismatched_speed():
    """Mismatched RAM speeds."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_mismatched_speed())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_none())
            elif "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_utilization_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_mismatched_capacity():
    """Mismatched RAM capacities."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_mismatched_capacity())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_none())
            elif "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_utilization_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_low_ram():
    """System with only 2GB RAM."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_low_ram())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_none())
            elif "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result("""{
  "TotalVisibleMemorySize": 2097152,
  "FreePhysicalMemory": 524288
}""")
        return _make_subprocess_result()
    return fake_run


def _fake_run_memory_errors():
    """System with memory errors detected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_2x8gb_3200mhz())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_found())
            elif "Win32_OperatingSystem" in cmd_str:
                return _make_subprocess_result(_powershell_ram_utilization_healthy())
        return _make_subprocess_result()
    return fake_run


def _fake_run_degraded_ram():
    """System with 10% of RAM missing (bad DIMM).
    Physical: 16GB, but OS only sees 14.4GB usable."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Win32_PhysicalMemory" in cmd_str:
                return _make_subprocess_result(_powershell_physical_memory_2x8gb_3200mhz())
            elif "MemoryDiagnostics-Results" in cmd_str:
                return _make_subprocess_result(_powershell_memory_errors_none())
            elif "Win32_OperatingSystem" in cmd_str:
                # 16GB physical, but only 14.4GB visible (90% of total)
                return _make_subprocess_result("""{
  "TotalVisibleMemorySize": 15099494,
  "FreePhysicalMemory": 1048576
}""")
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


def test_win_memory_diagnostics_healthy_matched_ram():
    """Healthy matched RAM configuration."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_2x8gb()):
        result = mod.check(_make_profile())
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("RAM configuration" in f.title for f in result.findings)


def test_win_memory_diagnostics_mismatched_speed():
    """Mismatched RAM speeds detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mismatched_speed()):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("Mismatched" in f.title for f in warning_findings)


def test_win_memory_diagnostics_mismatched_capacity():
    """Mismatched RAM capacities detected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mismatched_capacity()):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("Mismatched" in f.title for f in warning_findings)


def test_win_memory_diagnostics_low_ram():
    """Low RAM warning for < 4GB."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_ram()):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("Low RAM" in f.title for f in warning_findings)


def test_win_memory_diagnostics_memory_errors_critical():
    """Memory diagnostic errors flagged as CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_memory_errors()):
        result = mod.check(_make_profile())
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any("Memory diagnostic errors" in f.title for f in critical_findings)


def test_win_memory_diagnostics_degraded_ram():
    """Degraded RAM (usable < 90% of installed)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_degraded_ram()):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("Usable RAM" in f.title for f in warning_findings)


def test_win_memory_diagnostics_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_memory_diagnostics_fix_mismatched():
    """Fix action for mismatched RAM."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mismatched_speed()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_memory_diagnostics_fix_memory_errors():
    """Fix action for memory errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_memory_errors()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True
