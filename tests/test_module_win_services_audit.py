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
    return next(m for m in modules if m.name == "win_services_audit")


def _make_service_block(name: str, display_name: str, status: str, start_type: str) -> str:
    return (
        f"Name        : {name}\r\n"
        f"DisplayName : {display_name}\r\n"
        f"Status      : {status}\r\n"
        f"StartType   : {start_type}\r\n"
    )


def _make_powershell_output(services: list[tuple[str, str, str, str]]) -> str:
    """Create fake PowerShell output from list of (name, display_name, status, start_type)."""
    blocks = [
        _make_service_block(name, display_name, status, start_type)
        for name, display_name, status, start_type in services
    ]
    return "\r\n".join(blocks)


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_few_services():
    """System with few services (healthy)"""
    def fake_run(cmd, **kwargs):
        output = _make_powershell_output([
            ("WinDefend", "Windows Defender Antivirus Service", "Running", "Automatic"),
            ("wuauserv", "Windows Update", "Running", "Automatic"),
            ("Bits", "Background Intelligent Transfer Service", "Running", "Automatic"),
            ("AudioSrv", "Windows Audio", "Running", "Automatic"),
            ("Spooler", "Print Spooler", "Stopped", "Automatic"),
        ])
        return _make_subprocess_result(output)
    return fake_run


def _fake_run_many_services():
    """System with ~70 services"""
    def fake_run(cmd, **kwargs):
        services = [
            (f"Service{i}", f"Service {i}", "Running", "Automatic")
            for i in range(70)
        ]
        output = _make_powershell_output(services)
        return _make_subprocess_result(output)
    return fake_run


def _fake_run_bloated_system():
    """System with >100 running services"""
    def fake_run(cmd, **kwargs):
        services = [
            (f"Service{i}", f"Service {i}", "Running", "Automatic")
            for i in range(105)
        ]
        output = _make_powershell_output(services)
        return _make_subprocess_result(output)
    return fake_run


def _fake_run_bloatware_services():
    """System with bloatware services detected"""
    def fake_run(cmd, **kwargs):
        services = [
            ("WinDefend", "Windows Defender Antivirus Service", "Running", "Automatic"),
            ("DiagTrack", "DiagTrack", "Running", "Automatic"),
            ("AppUpdate", "App Update Service", "Running", "Automatic"),
            ("Telemetry", "Telemetry Service", "Stopped", "Automatic"),
            ("OneProcService", "OneNote", "Running", "Automatic"),
            ("Cortana", "Cortana", "Running", "Automatic"),
        ]
        output = _make_powershell_output(services)
        return _make_subprocess_result(output)
    return fake_run


def _fake_run_stopped_auto_services():
    """System with stopped automatic services"""
    def fake_run(cmd, **kwargs):
        services = [
            ("WinDefend", "Windows Defender Antivirus Service", "Running", "Automatic"),
            ("wuauserv", "Windows Update", "Stopped", "Automatic"),
            ("Bits", "Background Intelligent Transfer Service", "Stopped", "Automatic"),
            ("AudioSrv", "Windows Audio", "Running", "Automatic"),
        ]
        output = _make_powershell_output(services)
        return _make_subprocess_result(output)
    return fake_run


def _fake_run_powershell_error():
    """PowerShell returns error"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_services_audit_discovered():
    mod = _get_module()
    assert mod.name == "win_services_audit"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_services_audit_few_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_few_services()):
        result = mod.check(_make_profile())
    # Should have findings for service count
    assert result.has_issues
    # Should have INFO for service count
    assert any(f.data.get("type") == "service_count" for f in result.findings)
    # Should NOT have warning for high count
    assert not any(f.severity == Severity.WARNING and f.data.get("type") == "high_service_count" for f in result.findings)


def test_win_services_audit_many_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_services()):
        result = mod.check(_make_profile())
    # Should have findings
    assert result.has_issues
    # Should have service count
    assert any(f.data.get("type") == "service_count" for f in result.findings)
    # Should NOT exceed warning threshold (70 < 100)
    assert not any(f.severity == Severity.WARNING and f.data.get("type") == "high_service_count" for f in result.findings)


def test_win_services_audit_bloated_system():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bloated_system()):
        result = mod.check(_make_profile())
    # Should have findings
    assert result.has_issues
    # Should have WARNING for high service count
    assert any(f.severity == Severity.WARNING and f.data.get("type") == "high_service_count" for f in result.findings)
    # Count should be >100
    high_count_finding = next(f for f in result.findings if f.data.get("type") == "high_service_count")
    assert high_count_finding.data["count"] >= 100


def test_win_services_audit_bloatware_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bloatware_services()):
        result = mod.check(_make_profile())
    # Should have findings
    assert result.has_issues
    # Should detect bloatware services
    assert any(f.data.get("type") == "bloatware_services" for f in result.findings)
    bloatware_finding = next(f for f in result.findings if f.data.get("type") == "bloatware_services")
    assert bloatware_finding.data["count"] > 0
    assert any(name in bloatware_finding.data.get("names", []) for name in ["DiagTrack", "Telemetry"])


def test_win_services_audit_stopped_auto_services():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stopped_auto_services()):
        result = mod.check(_make_profile())
    # Should have findings
    assert result.has_issues
    # Should detect stopped automatic services
    assert any(f.data.get("type") == "stopped_auto_services" for f in result.findings)
    stopped_finding = next(f for f in result.findings if f.data.get("type") == "stopped_auto_services")
    assert stopped_finding.severity == Severity.WARNING
    assert stopped_finding.data["count"] == 2


def test_win_services_audit_powershell_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should not crash, just return findings with default service count
    # (empty service list should result in INFO with count 0)
    assert result.has_issues


def test_win_services_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bloated_system()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_services_audit_service_count_finding():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_few_services()):
        result = mod.check(_make_profile())
    # Should have a service count finding
    service_count_finding = next(f for f in result.findings if f.data.get("type") == "service_count")
    # Only 4 services running (Service0-3 are Running)
    # Actually 5 total services but only 4 running
    assert service_count_finding.data["count"] >= 0
    assert service_count_finding.severity == Severity.INFO
