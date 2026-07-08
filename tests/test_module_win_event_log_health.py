import json
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
    return next(m for m in modules if m.name == "win_event_log_health")


def _make_run_result(
    service_running=True,
    system_errors=0,
    bsod_events=0,
    shutdown_events=0,
    service_crashes=0,
    security_failures=0,
    log_sizes=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sc query EventLog for service status
        if cmd[0] == "sc" and "query" in cmd_str and "EventLog" in cmd_str:
            if service_running:
                result.stdout = (
                    "SERVICE_NAME: EventLog\n"
                    "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
                    "        STATE              : 4  RUNNING\n"
                    "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                )
            else:
                result.stdout = (
                    "SERVICE_NAME: EventLog\n"
                    "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
                    "        STATE              : 1  STOPPED\n"
                )

        # PowerShell commands
        elif "powershell" in cmd_str:
            # System errors query
            if "Get-WinEvent -LogName System" in cmd_str and "Where-Object" in cmd_str:
                result.stdout = f"Count : {system_errors}\n"

            # BSOD events (Event ID 1001)
            elif "Id=1001" in cmd_str:
                result.stdout = f"Count : {bsod_events}\n"

            # Unexpected shutdown (Event ID 41)
            elif "Id=41" in cmd_str:
                result.stdout = f"Count : {shutdown_events}\n"

            # Service crashes (Event ID 7031,7034)
            elif "Id=7031,7034" in cmd_str:
                result.stdout = f"Count : {service_crashes}\n"

            # Security failures
            elif "Get-WinEvent -LogName Security" in cmd_str:
                result.stdout = f"Count : {security_failures}\n"

            # Log sizes query
            elif "Get-WinEvent -ListLog" in cmd_str and "ConvertTo-Json" in cmd_str:
                if log_sizes:
                    result.stdout = json.dumps(log_sizes)
                else:
                    # Default clean log sizes
                    default_sizes = [
                        {
                            "LogName": "System",
                            "FileSize": 5242880,  # 5 MB
                            "MaxSize": 20971520,  # 20 MB
                        },
                        {
                            "LogName": "Application",
                            "FileSize": 3145728,  # 3 MB
                            "MaxSize": 20971520,  # 20 MB
                        },
                        {
                            "LogName": "Security",
                            "FileSize": 2097152,  # 2 MB
                            "MaxSize": 20971520,  # 20 MB
                        },
                    ]
                    result.stdout = json.dumps(default_sizes)

        return result

    return fake_run


def test_win_event_log_health_discovered():
    mod = _get_module()
    assert mod.name == "win_event_log_health"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_event_log_health_all_pass():
    """Test when event logs are healthy (no issues found)."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues  # Should have INFO finding
    assert any(f.data.get("check") == "log_health_good" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_event_log_health_service_not_running():
    """Test detection of Event Log service not running."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "event_log_service_stopped" for f in result.findings
    )
    critical = [
        f for f in result.findings if f.data.get("check") == "event_log_service_stopped"
    ]
    assert critical[0].severity == Severity.CRITICAL


def test_win_event_log_health_system_errors():
    """Test detection of critical/error events in System log."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, system_errors=5)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "system_errors" for f in result.findings)
    system_err = [f for f in result.findings if f.data.get("check") == "system_errors"]
    assert system_err[0].severity == Severity.WARNING
    assert system_err[0].data.get("error_count") == 5


def test_win_event_log_health_bsod_events():
    """Test detection of BSOD events (Event ID 1001)."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, bsod_events=2)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "bsod_events" for f in result.findings)
    bsod = [f for f in result.findings if f.data.get("check") == "bsod_events"]
    assert bsod[0].severity == Severity.WARNING
    assert bsod[0].data.get("count") == 2


def test_win_event_log_health_shutdown_events():
    """Test detection of unexpected shutdown events (Event ID 41)."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, shutdown_events=3)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "shutdown_events" for f in result.findings)
    shutdown = [f for f in result.findings if f.data.get("check") == "shutdown_events"]
    assert shutdown[0].severity == Severity.WARNING
    assert shutdown[0].data.get("count") == 3


def test_win_event_log_health_service_crashes():
    """Test detection of service crash events (Event ID 7031/7034)."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, service_crashes=4)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_crashes" for f in result.findings)
    crashes = [f for f in result.findings if f.data.get("check") == "service_crashes"]
    assert crashes[0].severity == Severity.WARNING
    assert crashes[0].data.get("count") == 4


def test_win_event_log_health_security_failures():
    """Test detection of security failure events."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, security_failures=3)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "security_failures" for f in result.findings)
    security = [f for f in result.findings if f.data.get("check") == "security_failures"]
    assert security[0].severity == Severity.WARNING
    assert security[0].data.get("count") == 3


def test_win_event_log_health_logs_full():
    """Test detection of full event logs (>90% capacity)."""
    mod = _get_module()
    # Create log sizes where System log is 95% full
    log_sizes = [
        {
            "LogName": "System",
            "FileSize": 19922944,  # 95% of 20971520
            "MaxSize": 20971520,  # 20 MB
        },
        {
            "LogName": "Application",
            "FileSize": 3145728,  # 15% full
            "MaxSize": 20971520,
        },
    ]
    fake_run = _make_run_result(service_running=True, log_sizes=log_sizes)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "log_full" for f in result.findings)
    full_logs = [f for f in result.findings if f.data.get("check") == "log_full"]
    assert full_logs[0].severity == Severity.WARNING
    assert full_logs[0].data.get("log_name") == "System"
    assert full_logs[0].data.get("capacity_percent") == 95


def test_win_event_log_health_multiple_logs_full():
    """Test when multiple logs are full."""
    mod = _get_module()
    log_sizes = [
        {
            "LogName": "System",
            "FileSize": 19922944,  # 95% full
            "MaxSize": 20971520,
        },
        {
            "LogName": "Security",
            "FileSize": 20466688,  # 97% full
            "MaxSize": 20971520,
        },
    ]
    fake_run = _make_run_result(service_running=True, log_sizes=log_sizes)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    full_logs = [f for f in result.findings if f.data.get("check") == "log_full"]
    assert len(full_logs) == 2


def test_win_event_log_health_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    log_sizes = [
        {
            "LogName": "System",
            "FileSize": 19922944,  # 95% full
            "MaxSize": 20971520,
        }
    ]
    fake_run = _make_run_result(
        service_running=True,
        system_errors=5,
        bsod_events=2,
        shutdown_events=1,
        log_sizes=log_sizes,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "system_errors" in checks
    assert "bsod_events" in checks
    assert "shutdown_events" in checks
    assert "log_full" in checks


def test_win_event_log_health_fix_service_not_running():
    """Test fix recommendation for Event Log service not running."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("Event Log" in a.title for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_win_event_log_health_fix_bsod_events():
    """Test fix recommendation for BSOD events."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, bsod_events=2)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    bsod_action = [a for a in fix.actions if "BSOD" in a.title]
    assert len(bsod_action) > 0
    assert bsod_action[0].success


def test_win_event_log_health_fix_logs_full():
    """Test fix recommendation for full logs."""
    mod = _get_module()
    log_sizes = [
        {
            "LogName": "System",
            "FileSize": 19922944,
            "MaxSize": 20971520,
        }
    ]
    fake_run = _make_run_result(service_running=True, log_sizes=log_sizes)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    full_action = [a for a in fix.actions if "full" in a.title.lower()]
    assert len(full_action) > 0
    assert full_action[0].success


def test_win_event_log_health_fix_all_pass():
    """Test fix recommendation when all logs are healthy."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    healthy_action = [
        a for a in fix.actions if "good" in a.title.lower() or "healthy" in a.title.lower()
    ]
    assert len(healthy_action) > 0


def test_win_event_log_health_fix_multiple_issues():
    """Test fix recommendations for multiple issues."""
    mod = _get_module()
    log_sizes = [
        {
            "LogName": "System",
            "FileSize": 19922944,
            "MaxSize": 20971520,
        }
    ]
    fake_run = _make_run_result(
        service_running=True,
        system_errors=5,
        bsod_events=2,
        shutdown_events=1,
        service_crashes=1,
        security_failures=2,
        log_sizes=log_sizes,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for each finding
    assert len(fix.actions) >= 6
    assert all(a.success for a in fix.actions)


def test_win_event_log_health_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    # When service check fails, it treats it as stopped (critical)
    assert len(result.findings) > 0
    assert result.findings[0].data.get("check") == "event_log_service_stopped"


def test_win_event_log_health_handles_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise TimeoutError("Command timed out")

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_event_log_health_no_zero_counts():
    """Test that zero event counts don't trigger findings."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        system_errors=0,
        bsod_events=0,
        shutdown_events=0,
        service_crashes=0,
        security_failures=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have the health_good finding
    assert len(result.findings) == 1
    assert result.findings[0].data.get("check") == "log_health_good"
