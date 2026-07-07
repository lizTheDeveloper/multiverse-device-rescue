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
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_disk_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _powershell_disks_healthy_ssd():
    """Single healthy SSD disk."""
    return """[
  {
    "MediaType": "SSD",
    "HealthStatus": "Healthy",
    "OperationalStatus": "OK",
    "Size": 536870912000
  }
]"""


def _powershell_disks_healthy_mixed():
    """Multiple healthy disks (SSD and HDD)."""
    return """[
  {
    "MediaType": "SSD",
    "HealthStatus": "Healthy",
    "OperationalStatus": "OK",
    "Size": 536870912000
  },
  {
    "MediaType": "HDD",
    "HealthStatus": "Healthy",
    "OperationalStatus": "OK",
    "Size": 2199023255552
  }
]"""


def _powershell_disks_unhealthy():
    """Unhealthy SSD disk."""
    return """[
  {
    "MediaType": "SSD",
    "HealthStatus": "Unhealthy",
    "OperationalStatus": "Error",
    "Size": 536870912000
  }
]"""


def _powershell_disks_degraded():
    """Degraded HDD disk."""
    return """[
  {
    "MediaType": "HDD",
    "HealthStatus": "Degraded",
    "OperationalStatus": "Degraded",
    "Size": 1099511627776
  }
]"""


def _powershell_single_disk_healthy_hdd():
    """Single healthy HDD disk."""
    return """{
  "MediaType": "HDD",
  "HealthStatus": "Healthy",
  "OperationalStatus": "OK",
  "Size": 1099511627776
}"""


def _powershell_event_count_with_errors():
    """Measure-Object output showing 5 disk error events."""
    return """
Count       : 5
"""


def _powershell_event_count_no_errors():
    """Measure-Object output showing no disk error events."""
    return """
Count       : 0
"""


def _fake_run_healthy_ssd():
    """PowerShell returns healthy SSD."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            # Check which PowerShell command
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_disks_healthy_ssd())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_healthy_mixed():
    """PowerShell returns healthy SSD and HDD."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_disks_healthy_mixed())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_unhealthy_ssd():
    """PowerShell returns unhealthy SSD."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_disks_unhealthy())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_degraded_hdd_with_errors():
    """PowerShell returns degraded HDD and disk errors."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_disks_degraded())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_with_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_healthy_with_errors():
    """PowerShell returns healthy disks but with errors in event log."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_disks_healthy_ssd())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_with_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_single_disk_healthy_hdd():
    """PowerShell returns single healthy HDD."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            cmd_str = " ".join(cmd)
            if "Get-PhysicalDisk" in cmd_str:
                return _make_subprocess_result(_powershell_single_disk_healthy_hdd())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result(_powershell_event_count_no_errors())
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_win_disk_health_discovered():
    mod = _get_module()
    assert mod.name == "win_disk_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_disk_health_healthy_ssd():
    """Single healthy SSD - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ssd()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention SSD
    finding_strs = [f.description for f in result.findings]
    assert any("SSD" in s for s in finding_strs)


def test_win_disk_health_healthy_mixed():
    """Mixed SSD and HDD both healthy - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_mixed()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention both disk types
    finding_strs = [f.description for f in result.findings]
    assert any("SSD" in s for s in finding_strs) and any("HDD" in s for s in finding_strs)


def test_win_disk_health_unhealthy_ssd():
    """Unhealthy SSD - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unhealthy_ssd()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Find the critical finding
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "unhealthy" in critical_findings[0].title.lower()


def test_win_disk_health_degraded_hdd_with_errors():
    """Degraded HDD with errors - CRITICAL + WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_degraded_hdd_with_errors()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical for degraded disk and warning for errors
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) > 0
    assert len(warning_findings) > 0


def test_win_disk_health_healthy_with_errors():
    """Healthy disks but with errors in event log - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_errors()):
        result = mod.check(_make_profile())
    # Should have both INFO (for healthy disks) and WARNING (for errors)
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("error" in f.title.lower() for f in warning_findings)


def test_win_disk_health_single_disk_healthy_hdd():
    """Single healthy HDD - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_disk_healthy_hdd()):
        result = mod.check(_make_profile())
    # Should have INFO finding (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention HDD
    finding_strs = [f.description for f in result.findings]
    assert any("HDD" in s for s in finding_strs)


def test_win_disk_health_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about failed disk info
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert "Could not retrieve" in warning_findings[0].title


def test_win_disk_health_fix_critical():
    """Fix action for CRITICAL unhealthy disk."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unhealthy_ssd()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # Action should be informational (SAFE risk level)
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_disk_health_fix_warning():
    """Fix action for WARNING disk errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_errors()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_disk_health_fix_healthy():
    """Fix action for healthy disk."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ssd()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_disk_health_capacity_parsing():
    """Disk capacity is correctly parsed and displayed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_mixed()):
        result = mod.check(_make_profile())
    # Check that total capacity is in findings
    finding_strs = [f.description for f in result.findings]
    # Should mention capacity in GB or TB
    assert any("GB" in s or "TB" in s for s in finding_strs)


def test_win_disk_health_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_ssd()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_healthy_ssd()):
        result2 = mod.check(_make_profile())
    # Results should be the same
    assert len(result1.findings) == len(result2.findings)
    if result1.findings and result2.findings:
        assert result1.findings[0].severity == result2.findings[0].severity
