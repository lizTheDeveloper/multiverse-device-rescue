import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "printer_diagnostics")


def _fake_run_healthy_printers():
    """Mock subprocess for healthy printer setup."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str:
            if "-r" in cmd_str:
                # CUPS scheduler is running
                result.stdout = "scheduler is running"
            elif "-d" in cmd_str:
                # Default printer
                result.stdout = "system default destination: HP-OfficeJet-Pro"
            elif "-o" in cmd_str:
                # Empty queue
                result.stdout = ""
            elif "-p" in cmd_str:
                # List of printers
                result.stdout = """printer HP-OfficeJet-Pro is idle. enabled since Wed 01 Jan 2025 10:00:00 AM PST
printer Brother-HL-L2350DW is idle. enabled since Wed 01 Jan 2025 11:00:00 AM PST
"""
        return result
    return fake_run


def _fake_run_cups_not_running():
    """Mock subprocess for CUPS scheduler not running."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "lpstat: error - unable to connect to server"

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-r" in cmd_str:
            result.stdout = ""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_disabled_printer():
    """Mock subprocess for disabled printer."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str:
            if "-r" in cmd_str:
                result.stdout = "scheduler is running"
            elif "-d" in cmd_str:
                result.stdout = "system default destination: HP-OfficeJet-Pro"
            elif "-o" in cmd_str:
                result.stdout = ""
            elif "-p" in cmd_str:
                result.stdout = """printer HP-OfficeJet-Pro is idle. disabled since Wed 01 Jan 2025 02:00:00 PM PST
printer Brother-HL-L2350DW is idle. enabled since Wed 01 Jan 2025 11:00:00 AM PST
"""
        return result
    return fake_run


def _fake_run_stuck_jobs():
    """Mock subprocess for stuck print jobs."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str:
            if "-r" in cmd_str:
                result.stdout = "scheduler is running"
            elif "-d" in cmd_str:
                result.stdout = "system default destination: HP-OfficeJet-Pro"
            elif "-o" in cmd_str:
                result.stdout = """HP-OfficeJet-Pro-1   user@localhost 1024   Wed 01 Jan 2025 10:00:00 AM PST
HP-OfficeJet-Pro-2   user@localhost 2048   Wed 01 Jan 2025 10:05:00 AM PST
HP-OfficeJet-Pro-3   user@localhost 512    Wed 01 Jan 2025 10:10:00 AM PST
"""
            elif "-p" in cmd_str:
                result.stdout = """printer HP-OfficeJet-Pro is idle. enabled since Wed 01 Jan 2025 10:00:00 AM PST
"""
        return result
    return fake_run


def _fake_run_no_printers():
    """Mock subprocess for no printers configured."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str:
            if "-r" in cmd_str:
                result.stdout = "scheduler is running"
            elif "-d" in cmd_str:
                result.stdout = ""
            elif "-o" in cmd_str:
                result.stdout = ""
            elif "-p" in cmd_str:
                result.stdout = ""
        return result
    return fake_run


def test_printer_diagnostics_discovered():
    mod = _get_module()
    assert mod.name == "printer_diagnostics"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_printer_diagnostics_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_printers()):
        result = mod.check(_make_profile())
    # Should have findings (info about printers) but no issues/warnings/critical
    assert result.has_issues is False


def test_printer_diagnostics_cups_not_running():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_cups_not_running()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "cups_scheduler" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_printer_diagnostics_disabled_printer():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled_printer()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "printer_error" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_printer_diagnostics_stuck_jobs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_jobs()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "print_queue" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Check that job count is correct
    queue_finding = next(f for f in result.findings if f.data.get("check") == "print_queue")
    assert queue_finding.data.get("jobs") == 3


def test_printer_diagnostics_no_printers():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_printers()):
        result = mod.check(_make_profile())
    # Should report no printers (info level, but has_issues is still False for info-only)
    assert any(f.data.get("check") == "no_printers" for f in result.findings)


def test_printer_diagnostics_fix_cups_not_running():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_cups_not_running()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
    assert any("restart" in a.title.lower() or "restart" in a.description.lower() for a in fix.actions)


def test_printer_diagnostics_fix_stuck_jobs():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_jobs()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("clear" in a.title.lower() or "clear" in a.description.lower() for a in fix.actions)


def test_printer_diagnostics_fix_disabled_printer():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled_printer()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("enable" in a.title.lower() or "enable" in a.description.lower() for a in fix.actions)
