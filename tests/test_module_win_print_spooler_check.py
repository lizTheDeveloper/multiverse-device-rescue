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
    return next(m for m in modules if m.name == "win_print_spooler_check")


def _make_run_result(
    spooler_running=True,
    printers=None,
    stuck_jobs=None,
    queue_size_mb=None,
    accepts_remote=None,
    drivers=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sc query Spooler
        if cmd[0] == "sc" and "query" in cmd_str:
            if spooler_running:
                result.stdout = (
                    "SERVICE_NAME: Spooler\n"
                    "        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n"
                    "        STATE              : 4  RUNNING\n"
                    "        WIN32_EXIT_CODE    : 0  (0x0)\n"
                    "        SERVICE_EXIT_CODE  : 0  (0x0)\n"
                )
            else:
                result.stdout = (
                    "SERVICE_NAME: Spooler\n"
                    "        STATE              : 1  STOPPED\n"
                )

        # PowerShell commands
        elif "powershell" in cmd_str:
            # Get-Printer
            if "Get-Printer" in cmd_str and "ConvertTo-Json" in cmd_str:
                if printers is not None:
                    result.stdout = json.dumps(printers)
                elif expect_clean:
                    result.stdout = "[]"
                else:
                    result.stdout = json.dumps([
                        {"Name": "HP LaserJet Pro", "DriverName": "HP LaserJet Pro v4 Class Driver", "PortName": "IP_192.168.1.100", "PrinterStatus": "Normal"},
                        {"Name": "Canon Pixma", "DriverName": "Canon Pixma MX920", "PortName": "USB001", "PrinterStatus": "Normal"},
                    ])

            # Get-PrinterDriver
            elif "Get-PrinterDriver" in cmd_str:
                if drivers is not None:
                    result.stdout = json.dumps(drivers)
                elif expect_clean:
                    result.stdout = "[]"
                else:
                    result.stdout = json.dumps([
                        {"Name": "HP LaserJet Pro v4 Class Driver", "Manufacturer": "HP", "PrinterEnvironment": "Windows x64", "Version": "5.0.2024.01"},
                        {"Name": "Canon Pixma MX920", "Manufacturer": "Canon", "PrinterEnvironment": "Windows x64", "Version": "3.1.2023.10"},
                    ])

            # Get-PrintJob (stuck jobs)
            elif "Get-PrintJob" in cmd_str:
                if stuck_jobs is not None:
                    result.stdout = json.dumps(stuck_jobs)
                elif expect_clean:
                    result.stdout = "[]"
                else:
                    result.stdout = json.dumps([
                        {"PrinterName": "HP LaserJet Pro", "JobStatus": "Error", "DocumentName": "Report.pdf", "Size": 2097152},
                        {"PrinterName": "Canon Pixma", "JobStatus": "Paused", "DocumentName": "Invoice.docx", "Size": 1048576},
                    ])

            # Get-ChildItem for queue size
            elif "Get-ChildItem" in cmd_str and "spool" in cmd_str:
                if queue_size_mb is not None:
                    result.stdout = str(queue_size_mb * 1024 * 1024)
                elif expect_clean:
                    result.stdout = "0"
                else:
                    result.stdout = str(150 * 1024 * 1024)  # 150 MB

            # Get-NetTCPConnection for remote connections
            elif "Get-NetTCPConnection" in cmd_str:
                if accepts_remote is not None:
                    result.stdout = "1" if accepts_remote else "0"
                elif expect_clean:
                    result.stdout = "0"
                else:
                    result.stdout = "1"

        return result

    return fake_run


def test_win_print_spooler_check_discovered():
    """Test that the module is discovered with correct metadata."""
    mod = _get_module()
    assert mod.name == "win_print_spooler_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_print_spooler_check_all_pass():
    """Test when all checks pass (spooler running, no issues)."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        stuck_jobs=[],
        queue_size_mb=10,
        accepts_remote=False,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have at least INFO findings
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_print_spooler_check_remote_connection_critical():
    """Test CRITICAL finding when spooler running and accepting remote."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        accepts_remote=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert any("PrintNightmare" in f.title or "CVE" in f.description for f in critical)


def test_win_print_spooler_check_stuck_jobs_warning():
    """Test WARNING when stuck print jobs detected."""
    mod = _get_module()
    stuck_jobs = [
        {"PrinterName": "HP LaserJet", "JobStatus": "Error", "DocumentName": "test.pdf", "Size": 1024},
        {"PrinterName": "Canon", "JobStatus": "Paused", "DocumentName": "doc.docx", "Size": 2048},
    ]
    fake_run = _make_run_result(
        spooler_running=True,
        stuck_jobs=stuck_jobs,
        accepts_remote=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.data.get("check") == "stuck_print_jobs"]
    assert len(warnings) > 0
    assert warnings[0].severity == Severity.WARNING
    assert "2" in warnings[0].description  # Should mention 2 stuck jobs


def test_win_print_spooler_check_large_queue_warning():
    """Test WARNING when spooler queue too large."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        queue_size_mb=250,  # > 100MB
        accepts_remote=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.data.get("check") == "queue_size_large"]
    assert len(warnings) > 0
    assert warnings[0].severity == Severity.WARNING
    assert "250" in warnings[0].description


def test_win_print_spooler_check_queue_size_ok():
    """Test no warning when queue size is acceptable."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        queue_size_mb=50,  # < 100MB
        accepts_remote=False,
        stuck_jobs=[],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have queue_size_large warning
    assert not any(f.data.get("check") == "queue_size_large" for f in result.findings)


def test_win_print_spooler_check_spooler_stopped_with_printers():
    """Test WARNING when spooler stopped but printers installed."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=False,
        printers=[
            {"Name": "HP LaserJet", "DriverName": "HP Driver", "PortName": "IP_192.168.1.100", "PrinterStatus": "Normal"},
            {"Name": "Canon", "DriverName": "Canon Driver", "PortName": "USB001", "PrinterStatus": "Normal"},
        ],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.data.get("check") == "spooler_stopped_with_printers"]
    assert len(warnings) > 0
    assert warnings[0].severity == Severity.WARNING
    assert "2" in warnings[0].description  # Should mention 2 printers


def test_win_print_spooler_check_spooler_stopped_no_printers():
    """Test no warning when spooler stopped and no printers."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=False,
        printers=[],
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have warning about stopped spooler
    assert not any(f.data.get("check") == "spooler_stopped_with_printers" for f in result.findings)


def test_win_print_spooler_check_status_info():
    """Test INFO finding with printer status."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        printers=[
            {"Name": "Printer1", "DriverName": "Driver1", "PortName": "Port1", "PrinterStatus": "Normal"},
        ],
        accepts_remote=False,
        stuck_jobs=[],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    info = [f for f in result.findings if f.data.get("check") == "spooler_status_info"]
    assert len(info) > 0
    assert info[0].severity == Severity.INFO
    assert "running" in info[0].description.lower()
    assert "1" in info[0].description  # Mentions 1 printer


def test_win_print_spooler_check_multiple_issues():
    """Test when multiple issues detected."""
    mod = _get_module()
    stuck_jobs = [{"PrinterName": "HP", "JobStatus": "Error", "DocumentName": "test.pdf", "Size": 1024}]
    fake_run = _make_run_result(
        spooler_running=True,
        stuck_jobs=stuck_jobs,
        queue_size_mb=200,
        accepts_remote=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "remote_spooler_running" in checks
    assert "stuck_print_jobs" in checks
    assert "queue_size_large" in checks


def test_win_print_spooler_check_fix_remote_connection():
    """Test fix recommendation for remote connections."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        accepts_remote=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("remote" in a.title.lower() or "nightmar" in a.description.lower() for a in fix.actions)


def test_win_print_spooler_check_fix_stuck_jobs():
    """Test fix recommendation for stuck jobs."""
    mod = _get_module()
    stuck_jobs = [{"PrinterName": "HP", "JobStatus": "Error", "DocumentName": "test.pdf", "Size": 1024}]
    fake_run = _make_run_result(
        spooler_running=True,
        stuck_jobs=stuck_jobs,
        accepts_remote=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    actions = [a for a in fix.actions if "stuck" in a.title.lower()]
    assert len(actions) > 0


def test_win_print_spooler_check_fix_large_queue():
    """Test fix recommendation for large queue."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        queue_size_mb=250,
        accepts_remote=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    actions = [a for a in fix.actions if "queue" in a.title.lower() or "large" in a.title.lower()]
    assert len(actions) > 0


def test_win_print_spooler_check_fix_spooler_stopped():
    """Test fix recommendation for stopped spooler with printers."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=False,
        printers=[
            {"Name": "Printer1", "DriverName": "Driver1", "PortName": "Port1", "PrinterStatus": "Normal"},
        ],
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    actions = [a for a in fix.actions if "stopped" in a.title.lower()]
    assert len(actions) > 0
    assert any("net start spooler" in a.description for a in actions)


def test_win_print_spooler_check_fix_status_info():
    """Test fix for status info (informational)."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least one action (for info finding)
    assert len(fix.actions) > 0
    # All actions should be safe
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_win_print_spooler_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_print_spooler_check_empty_queue_size():
    """Test handling of empty queue folder."""
    mod = _get_module()
    fake_run = _make_run_result(
        spooler_running=True,
        queue_size_mb=0,
        accepts_remote=False,
        stuck_jobs=[],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not warn about queue size
    assert not any(f.data.get("check") == "queue_size_large" for f in result.findings)
