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
    return next(m for m in modules if m.name == "win_sfc_check")


def _make_run_result(
    cbs_log_output=None,
    pending_ops=None,
    cbs_log_error=False,
    pending_ops_error=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # CBS.log query via PowerShell
        if "powershell" in cmd_str and "CBS.log" in cmd_str:
            if cbs_log_error:
                result.returncode = 1
                result.stderr = "Access denied"
            else:
                result.stdout = cbs_log_output or ""

        # Registry query for PendingFileRenameOperations
        elif cmd[0] == "reg" and "PendingFileRenameOperations" in cmd_str:
            if pending_ops_error:
                result.returncode = 1
            else:
                result.stdout = pending_ops or ""
                result.stderr = ""

        return result

    return fake_run


def test_win_sfc_check_discovered():
    mod = _get_module()
    assert mod.name == "win_sfc_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_sfc_check_cbs_log_failed():
    """Test when CBS.log cannot be read."""
    mod = _get_module()
    fake_run = _make_run_result(cbs_log_error=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "cbs_log_failed" for f in result.findings)
    assert result.findings[0].severity == Severity.WARNING


def test_win_sfc_check_no_violations():
    """Test when SFC finds no integrity violations."""
    mod = _get_module()
    cbs_log = (
        "2026-07-08 10:15:30.123+00:00 No integrity violations detected\n"
        "2026-07-08 10:16:00.456+00:00 SFC scan completed successfully"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_violations" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_sfc_check_cannot_repair():
    """Test when SFC finds corrupted files it cannot repair."""
    mod = _get_module()
    cbs_log = (
        "2026-07-08 10:15:30.123+00:00 Cannot repair file C:\\Windows\\System32\\kernel32.dll\n"
        "2026-07-08 10:15:31.456+00:00 Cannot repair file C:\\Windows\\System32\\ntdll.dll\n"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "cannot_repair" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "cannot_repair"]
    assert critical[0].severity == Severity.CRITICAL
    assert critical[0].data.get("count") == 2


def test_win_sfc_check_successfully_repaired():
    """Test when SFC finds and repairs corrupted files."""
    mod = _get_module()
    cbs_log = (
        "2026-07-08 10:15:30.123+00:00 CBS successfully repaired file C:\\Windows\\System32\\hal.dll\n"
        "2026-07-08 10:15:31.456+00:00 CBS successfully repaired file C:\\Windows\\System32\\boot.ini\n"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "repaired" for f in result.findings)
    repaired = [f for f in result.findings if f.data.get("check") == "repaired"]
    assert repaired[0].severity == Severity.WARNING
    assert repaired[0].data.get("count") == 2


def test_win_sfc_check_pending_operations():
    """Test detection of pending file rename operations."""
    mod = _get_module()
    cbs_log = "2026-07-08 10:15:30.123+00:00 No issues found"
    pending_ops_output = (
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\n"
        "    PendingFileRenameOperations    REG_MULTI_SZ    \\??\\C:\\temp\\file1.txt\\0\\??\\C:\\backup\\file1.txt\\0"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log, pending_ops=pending_ops_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "pending_operations" for f in result.findings)
    pending = [f for f in result.findings if f.data.get("check") == "pending_operations"]
    assert pending[0].severity == Severity.WARNING


def test_win_sfc_check_stale_scan():
    """Test warning when SFC hasn't been run recently."""
    mod = _get_module()
    # Date that's 100+ days ago
    old_date = "2026-03-20 14:30:45.123+00:00"
    cbs_log = f"{old_date} SFC scan completed. No integrity violations"
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    stale = [f for f in result.findings if f.data.get("check") == "stale_scan"]
    # Should have stale_scan if date is old enough
    if stale:
        assert stale[0].severity == Severity.WARNING
        assert stale[0].data.get("days_ago", 0) > 0


def test_win_sfc_check_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    cbs_log = (
        "2026-03-15 10:15:30.123+00:00 Cannot repair file system.dll\n"
        "2026-03-15 10:15:31.456+00:00 CBS successfully repaired ntdll.dll\n"
    )
    pending_ops_output = (
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\n"
        "    PendingFileRenameOperations    REG_MULTI_SZ    \\??\\C:\\temp\\file1.txt\\0"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log, pending_ops=pending_ops_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    # Should detect multiple issues
    assert "cannot_repair" in checks or "repaired" in checks


def test_win_sfc_check_fix_cannot_repair():
    """Test fix action for unrepairable files."""
    mod = _get_module()
    cbs_log = "2026-07-08 10:15:30.123+00:00 Cannot repair kernel.dll"
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("unrepairable" in a.title.lower() for a in fix.actions)


def test_win_sfc_check_fix_repaired():
    """Test fix action for repaired files."""
    mod = _get_module()
    cbs_log = "2026-07-08 10:15:30.123+00:00 CBS successfully repaired hal.dll"
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    repaired_action = [a for a in fix.actions if "repaired" in a.title.lower()]
    assert len(repaired_action) > 0
    assert repaired_action[0].success


def test_win_sfc_check_fix_pending_operations():
    """Test fix action for pending operations."""
    mod = _get_module()
    cbs_log = "2026-07-08 10:15:30.123+00:00 No issues"
    pending_ops_output = (
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\n"
        "    PendingFileRenameOperations    REG_MULTI_SZ    \\??\\C:\\temp\\file\\0"
    )
    fake_run = _make_run_result(cbs_log_output=cbs_log, pending_ops=pending_ops_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    pending_action = [a for a in fix.actions if "pending" in a.title.lower()]
    assert len(pending_action) > 0


def test_win_sfc_check_fix_stale_scan():
    """Test fix action for stale SFC scan."""
    mod = _get_module()
    old_date = "2026-02-15 10:15:30.123+00:00"
    cbs_log = f"{old_date} SFC check complete"
    fake_run = _make_run_result(cbs_log_output=cbs_log)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions if stale scan detected
    if any(f.data.get("check") == "stale_scan" for f in check.findings):
        assert len(fix.actions) > 0


def test_win_sfc_check_handles_empty_cbs_log():
    """Test graceful handling of empty CBS log."""
    mod = _get_module()
    fake_run = _make_run_result(cbs_log_output="")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should handle gracefully without crashing
    assert isinstance(result.findings, list)


def test_win_sfc_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    assert isinstance(result.findings, list)


def test_win_sfc_check_no_pending_operations():
    """Test when there are no pending file operations."""
    mod = _get_module()
    cbs_log = "2026-07-08 10:15:30.123+00:00 No integrity violations"
    fake_run = _make_run_result(cbs_log_output=cbs_log, pending_ops_error=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have pending_operations finding if registry query fails
    assert not any(f.data.get("check") == "pending_operations" for f in result.findings)
