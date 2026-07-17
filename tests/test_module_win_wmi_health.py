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
    return next(m for m in modules if m.name == "win_wmi_health")


def _make_run_result(
    service_running=True,
    repo_valid=True,
    repo_size_mb=100,
    wmi_query_success=True,
    wmi_os_info=None,
    wmi_error_count=0,
):
    """Create a fake subprocess.run that returns appropriate results."""

    # Set default WMI OS info if not provided
    if wmi_os_info is None:
        wmi_os_info = {
            "Caption": "Microsoft Windows 11 Professional",
            "Version": "10.0.22621",
        }

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sc query winmgmt - service status
        if cmd and cmd[0] == "sc" and "query" in cmd_str:
            if service_running:
                result.stdout = "SERVICE_NAME: winmgmt\nSTATE              : 4  RUNNING\n"
            else:
                result.stdout = "SERVICE_NAME: winmgmt\nSTATE              : 1  STOPPED\n"

        # winmgmt /verifyrepository - repository verification
        elif "winmgmt" in cmd_str and "verifyrepository" in cmd_str:
            result.returncode = 0 if repo_valid else 1
            result.stdout = (
                "WMI repository is consistent\n"
                if repo_valid
                else "WMI repository is corrupted\n"
            )

        # PowerShell commands
        elif "powershell" in cmd_str:
            # Get-WmiObject Win32_OperatingSystem - WMI query test
            if "Get-WmiObject" in cmd_str and "Win32_OperatingSystem" in cmd_str:
                if wmi_query_success:
                    result.stdout = json.dumps(wmi_os_info)
                else:
                    result.returncode = 1
                    result.stderr = "WMI query failed"

            # Get WMI repository size
            elif "wbem\\Repository" in cmd_str and "Measure-Object" in cmd_str:
                size_bytes = repo_size_mb * 1024 * 1024
                result.stdout = str(size_bytes)

            # Get WMI errors from event log
            elif "WMI-Activity" in cmd_str and "Measure-Object" in cmd_str:
                # PowerShell Measure-Object output format
                result.stdout = f"Count : {wmi_error_count}\n"

        return result

    return fake_run


def test_win_wmi_health_discovered():
    mod = _get_module()
    assert mod.name == "win_wmi_health"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_wmi_health_all_healthy():
    """Test when WMI is completely healthy."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        repo_valid=True,
        repo_size_mb=100,
        wmi_query_success=True,
        wmi_error_count=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues  # Should have INFO finding
    assert any(f.data.get("check") == "wmi_healthy" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_wmi_health_service_not_running():
    """Test when WMI service is not running."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_not_running" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "service_not_running"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_wmi_health_repository_corrupted():
    """Test when WMI repository is corrupted."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        repo_valid=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "repo_corrupted" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "repo_corrupted"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_wmi_health_repository_bloated():
    """Test when WMI repository exceeds 500MB."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        repo_valid=True,
        repo_size_mb=650,
        wmi_query_success=True,
        wmi_error_count=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "repo_bloated" for f in result.findings)
    bloated = [f for f in result.findings if f.data.get("check") == "repo_bloated"]
    assert bloated[0].severity == Severity.WARNING


def test_win_wmi_health_wmi_errors_in_log():
    """Test when WMI errors are found in event log."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        repo_valid=True,
        repo_size_mb=100,
        wmi_query_success=True,
        wmi_error_count=5,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "wmi_errors" for f in result.findings)
    errors = [f for f in result.findings if f.data.get("check") == "wmi_errors"]
    assert errors[0].severity == Severity.WARNING


def test_win_wmi_health_service_check_failed():
    """Test when service status check fails."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        # Fail service status check only
        if cmd and cmd[0] == "sc":
            raise OSError("Command failed")
        return result

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_check_failed" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "service_check_failed"]
    assert warning[0].severity == Severity.WARNING


def test_win_wmi_health_repo_verify_failed():
    """Test when repository verification check fails."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        # Fail repo verification only
        if "winmgmt" in cmd_str and "verifyrepository" in cmd_str:
            raise OSError("Command failed")
        else:
            fake_result = _make_run_result(service_running=True)
            return fake_result(cmd, **kwargs)

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "repo_verify_failed" for f in result.findings)


def test_win_wmi_health_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        repo_valid=True,
        repo_size_mb=600,
        wmi_query_success=True,
        wmi_error_count=3,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "repo_bloated" in checks
    assert "wmi_errors" in checks


def test_win_wmi_health_fix_service_not_running():
    """Test fix recommendation for stopped WMI service."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("not running" in a.title.lower() for a in fix.actions)
    # Fix actions should be informational and success=True
    action = [a for a in fix.actions if "not running" in a.title.lower()][0]
    assert action.success is True


def test_win_wmi_health_fix_repository_corrupted():
    """Test fix recommendation for corrupted repository."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=True, repo_valid=False)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    corrupt_action = [a for a in fix.actions if "corrupted" in a.title.lower()]
    assert len(corrupt_action) > 0
    assert "salvagerepository" in corrupt_action[0].description


def test_win_wmi_health_fix_repository_bloated():
    """Test fix recommendation for bloated repository."""
    mod = _get_module()
    fake_run = _make_run_result(repo_size_mb=650)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    bloated_action = [a for a in fix.actions if "bloated" in a.title.lower()]
    assert len(bloated_action) > 0


def test_win_wmi_health_fix_wmi_errors():
    """Test fix recommendation for WMI errors."""
    mod = _get_module()
    fake_run = _make_run_result(wmi_error_count=5)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    error_action = [a for a in fix.actions if "error" in a.title.lower()]
    assert len(error_action) > 0


def test_win_wmi_health_fix_healthy():
    """Test fix when WMI is healthy."""
    mod = _get_module()
    fake_run = _make_run_result()
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    healthy_action = [a for a in fix.actions if "healthy" in a.title.lower()]
    assert len(healthy_action) > 0
    assert healthy_action[0].success is True


def test_win_wmi_health_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
