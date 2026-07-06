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
    return next(m for m in modules if m.name == "printer_queue")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: one enabled printer, no stuck jobs"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-p" in cmd_str:
            return _make_subprocess_result(
                "printer HP-Printer is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST\n"
            )
        elif "lpstat" in cmd_str and "-o" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_printers():
    """Multiple printers configured"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-p" in cmd_str:
            return _make_subprocess_result(
                "printer HP-LaserJet is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST\n"
                "printer Canon-Pixma is idle.  enabled since Sat 01 Jan 2024 11:00:00 AM PST\n"
                "printer Brother-HL is idle.  enabled since Sat 01 Jan 2024 12:00:00 AM PST\n"
            )
        elif "lpstat" in cmd_str and "-o" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_disabled_printer():
    """One printer disabled/paused"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-p" in cmd_str:
            return _make_subprocess_result(
                "printer HP-Printer is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST\n"
                "printer Canon-Printer is idle.  disabled since Sat 01 Jan 2024 09:00:00 AM PST\n"
            )
        elif "lpstat" in cmd_str and "-o" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_stuck_jobs():
    """Stuck jobs in queue"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-p" in cmd_str:
            return _make_subprocess_result(
                "printer HP-Printer is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST\n"
            )
        elif "lpstat" in cmd_str and "-o" in cmd_str:
            return _make_subprocess_result(
                "charlie-123    [job 2]    \"test.pdf\"    100%  stopped\n"
                "alice-456      [job 1]    \"document.pdf\" 100%  processing\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_lpstat_fails():
    """lpstat command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str:
            raise OSError("lpstat not found")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_disabled():
    """Multiple printers, several disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "lpstat" in cmd_str and "-p" in cmd_str:
            return _make_subprocess_result(
                "printer HP-Printer is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST\n"
                "printer Canon-Printer is idle.  disabled since Sat 01 Jan 2024 09:00:00 AM PST\n"
                "printer Brother-Printer is idle.  disabled since Sat 01 Jan 2024 08:00:00 AM PST\n"
            )
        elif "lpstat" in cmd_str and "-o" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def test_printer_queue_discovered():
    """Test that the printer_queue module is discovered"""
    mod = _get_module()
    assert mod.name == "printer_queue"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_printer_queue_healthy():
    """Test healthy printer queue: one enabled printer, no jobs"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should only report printer count as INFO, no warnings
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_printer_queue_multiple_printers():
    """Test multiple printers configured"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_printers()):
        result = mod.check(_make_profile())
    # Should have printer count finding, no warnings
    assert any(f.data.get("check") == "printer_count" for f in result.findings)
    assert all(f.severity == Severity.INFO for f in result.findings)
    # Find the printer count finding
    count_finding = next(f for f in result.findings if f.data.get("check") == "printer_count")
    assert count_finding.data.get("count") == 3
    assert count_finding.severity == Severity.INFO


def test_printer_queue_disabled_printer():
    """Test with disabled/paused printer"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled_printer()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "disabled_printers" for f in result.findings)
    # Check that we have both printer count and disabled printers findings
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_printer_queue_stuck_jobs():
    """Test with stuck jobs in queue"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_jobs()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "stuck_jobs" for f in result.findings)
    # Should have stuck jobs warning
    stuck_finding = next(f for f in result.findings if f.data.get("check") == "stuck_jobs")
    assert stuck_finding.severity == Severity.WARNING


def test_printer_queue_lpstat_fails():
    """Test when lpstat command fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_lpstat_fails()):
        result = mod.check(_make_profile())
    # Should have a finding about check failure
    assert any(f.data.get("check") == "check_failed" for f in result.findings)
    # All findings should be INFO when lpstat fails
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_printer_queue_multiple_disabled():
    """Test with multiple disabled printers"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    disabled_finding = next(f for f in result.findings if f.data.get("check") == "disabled_printers")
    assert disabled_finding.data.get("disabled_count") == 2


def test_printer_queue_fix_is_informational():
    """Test that fix() provides informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_disabled_printer()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for disabled printers
    assert len(fix.actions) > 0
    # All actions should have success=True
    assert all(a.success for a in fix.actions)


def test_printer_queue_fix_stuck_jobs():
    """Test fix actions for stuck jobs"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stuck_jobs()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have action for clearing stuck jobs
    assert any("cancel" in a.description.lower() for a in fix.actions)


def test_printer_queue_fix_check_failed():
    """Test fix actions when check fails"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_lpstat_fails()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have an action for the check failure
    assert any("CUPS" in a.description or "lpstat" in a.description for a in fix.actions)
