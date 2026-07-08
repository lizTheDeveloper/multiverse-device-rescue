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
    return next(m for m in modules if m.name == "win_update_history")


def _make_run_result(
    service_running=True,
    update_history=None,
    pending_count=None,
    failed_count=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sc query wuauserv command
        if "sc" in cmd_str and "query" in cmd_str and "wuauserv" in cmd_str:
            if service_running:
                result.stdout = "SERVICE_NAME: wuauserv\nSTATUS        : 4  RUNNING\n"
            else:
                result.stdout = "SERVICE_NAME: wuauserv\nSTATUS        : 1  STOPPED\n"

        # PowerShell commands
        elif "powershell" in cmd_str:
            # Get-HotFix command
            if "Get-HotFix" in cmd_str:
                if expect_clean:
                    result.stdout = "[]"
                elif update_history is not None:
                    result.stdout = json.dumps(update_history)
                else:
                    # Default test update history
                    result.stdout = json.dumps(
                        [
                            {"KB": "KB5028997", "InstalledOn": "2024-01-15"},
                            {"KB": "KB5027231", "InstalledOn": "2024-01-08"},
                            {"KB": "KB5026372", "InstalledOn": "2023-12-12"},
                        ]
                    )

            # Microsoft.Update.Session check for pending updates
            elif "Microsoft.Update.Session" in cmd_str:
                if pending_count is not None:
                    result.stdout = str(pending_count)
                elif expect_clean:
                    result.stdout = "0"
                else:
                    result.stdout = "0"

            # Get-WinEvent for failed updates
            elif "Get-WinEvent" in cmd_str:
                if failed_count is not None:
                    if failed_count > 0:
                        result.stdout = f"Count : {failed_count}\n"
                    else:
                        result.stdout = "Count : 0\n"
                elif expect_clean:
                    result.stdout = "Count : 0\n"
                else:
                    result.stdout = "Count : 0\n"

        return result

    return fake_run


def test_win_update_history_discovered():
    mod = _get_module()
    assert mod.name == "win_update_history"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_update_history_service_running_with_updates():
    """Test when service is running and recent updates are present."""
    mod = _get_module()
    update_history = [
        {"KB": "KB5028997", "InstalledOn": "2024-01-15"},
        {"KB": "KB5027231", "InstalledOn": "2024-01-08"},
    ]
    fake_run = _make_run_result(service_running=True, update_history=update_history)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "recent_updates" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_update_history_service_stopped():
    """Test detection of stopped Windows Update service."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "service_stopped" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "service_stopped"]
    assert warning[0].severity == Severity.WARNING


def test_win_update_history_no_updates_90_days():
    """Test critical severity when no updates in 90+ days."""
    mod = _get_module()
    # Old update from 3+ months ago
    update_history = [
        {"KB": "KB5020000", "InstalledOn": "2023-10-01"},
    ]
    fake_run = _make_run_result(service_running=True, update_history=update_history)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.data.get("check") == "no_updates_90_days"]
    assert len(critical) > 0
    assert critical[0].severity == Severity.CRITICAL


def test_win_update_history_no_updates_30_days():
    """Test warning severity when no updates in 30-89 days."""
    mod = _get_module()
    # Update from 30-90 days ago (approximately 58 days based on the math)
    # Current date is 2026-07-07, so 2026-05-10 is about 58 days ago
    update_history = [
        {"KB": "KB5022000", "InstalledOn": "2026-05-10"},
    ]
    fake_run = _make_run_result(service_running=True, update_history=update_history)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.data.get("check") == "no_updates_30_days"]
    # Should have warning about 30+ days
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_update_history_pending_updates():
    """Test detection of pending updates."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        update_history=[{"KB": "KB5028997", "InstalledOn": "2024-01-15"}],
        pending_count=3,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "pending_updates" for f in result.findings)
    pending = [f for f in result.findings if f.data.get("check") == "pending_updates"]
    assert pending[0].severity == Severity.INFO


def test_win_update_history_failed_updates():
    """Test detection of failed updates."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        update_history=[{"KB": "KB5028997", "InstalledOn": "2024-01-15"}],
        failed_count=2,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "failed_updates" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "failed_updates"]
    assert failed[0].severity == Severity.WARNING


def test_win_update_history_all_clean():
    """Test when everything is healthy."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        update_history=[{"KB": "KB5028997", "InstalledOn": "2024-01-15"}],
        pending_count=0,
        failed_count=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding about recent updates
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_update_history_no_update_history():
    """Test when Get-HotFix returns empty."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        update_history=[],
        pending_count=0,
        failed_count=0,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_update_history" for f in result.findings)


def test_win_update_history_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    old_update_history = [{"KB": "KB5000000", "InstalledOn": "2023-09-01"}]
    fake_run = _make_run_result(
        service_running=False,
        update_history=old_update_history,
        pending_count=2,
        failed_count=1,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "service_stopped" in checks
    assert "pending_updates" in checks
    assert "failed_updates" in checks


def test_win_update_history_fix_service_stopped():
    """Test fix recommendation for stopped service."""
    mod = _get_module()
    fake_run = _make_run_result(service_running=False, expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("service" in a.title.lower() for a in fix.actions)
    service_action = [a for a in fix.actions if "service" in a.title.lower()][0]
    assert service_action.success


def test_win_update_history_fix_critical_no_updates():
    """Test fix recommendation for no updates in 90+ days."""
    mod = _get_module()
    old_history = [{"KB": "KB5000000", "InstalledOn": "2023-09-01"}]
    fake_run = _make_run_result(
        service_running=True, update_history=old_history, expect_clean=False
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for critical no updates
    critical_actions = [a for a in fix.actions if "critical" in a.title.lower()]
    assert len(critical_actions) > 0


def test_win_update_history_fix_pending_updates():
    """Test fix recommendation for pending updates."""
    mod = _get_module()
    fake_run = _make_run_result(
        service_running=True,
        update_history=[{"KB": "KB5028997", "InstalledOn": "2024-01-15"}],
        pending_count=2,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    pending_actions = [a for a in fix.actions if "pending" in a.title.lower()]
    assert len(pending_actions) > 0


def test_win_update_history_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
