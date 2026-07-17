import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "win_windows_update_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ===== Mock data generators =====


def _sc_query_service_running():
    """sc query wuauserv output for running service."""
    return """SERVICE_NAME: wuauserv
DISPLAY_NAME: Windows Update
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0"""


def _sc_query_service_stopped():
    """sc query wuauserv output for stopped service."""
    return """SERVICE_NAME: wuauserv
DISPLAY_NAME: Windows Update
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0"""


def _sc_query_service_disabled():
    """sc query wuauserv output for disabled service."""
    return """SERVICE_NAME: wuauserv
DISPLAY_NAME: Windows Update
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        START_TYPE         : 4  DISABLED"""


def _ps_last_update_recent():
    """PowerShell Get-HotFix output: recent update."""
    return "7/5/2026 10:30:00 AM"


def _ps_last_update_old():
    """PowerShell Get-HotFix output: old update (100+ days ago)."""
    days_back = 100
    old_date = datetime.now() - timedelta(days=days_back)
    return old_date.strftime("%m/%d/%Y %I:%M:%S %p")


def _ps_last_update_stale():
    """PowerShell Get-HotFix output: stale update (40 days ago)."""
    days_back = 40
    old_date = datetime.now() - timedelta(days=days_back)
    return old_date.strftime("%m/%d/%Y %I:%M:%S %p")


def _ps_pending_updates_none():
    """PowerShell pending updates: none."""
    return ""


def _ps_pending_updates_mandatory():
    """PowerShell pending updates: 2 mandatory."""
    return """[
  {
    "Title": "2024-06 Cumulative Update for Windows 11 (KB5000123)",
    "IsMandatory": true
  },
  {
    "Title": "2024-06 Security Update for Microsoft Defender (KB5000124)",
    "IsMandatory": true
  }
]"""


def _ps_pending_updates_mixed():
    """PowerShell pending updates: 1 mandatory, 2 optional."""
    return """[
  {
    "Title": "2024-06 Cumulative Update for Windows 11 (KB5000123)",
    "IsMandatory": true
  },
  {
    "Title": "Optional Update KB5000125",
    "IsMandatory": false
  },
  {
    "Title": "Optional Update KB5000126",
    "IsMandatory": false
  }
]"""


def _ps_failed_updates_count_0():
    """PowerShell Measure-Object output: 0 failed updates."""
    return """Count       : 0"""


def _ps_failed_updates_count_3():
    """PowerShell Measure-Object output: 3 failed updates."""
    return """Count       : 3"""


def _ps_pause_registry_active():
    """PowerShell registry query: pause is active."""
    return 'PauseUpdatesExpiryTime    REG_DWORD    0x637a8d00'


def _ps_pause_registry_not_found():
    """PowerShell registry query: pause not set (no updates paused)."""
    return "ERROR: The system was unable to find the specified registry key or value."


# ===== Fake subprocess.run functions =====


def _fake_run_service_running_recent_updates():
    """Service running, recent updates, no pending."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_recent())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_none())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_0())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(
                        _ps_pause_registry_not_found(), returncode=1
                    )
        return _make_subprocess_result()
    return fake_run


def _fake_run_service_disabled():
    """Service is disabled."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "sc" in cmd and "query" in cmd:
            return _make_subprocess_result(_sc_query_service_disabled())
        return _make_subprocess_result()
    return fake_run


def _fake_run_service_stopped():
    """Service is stopped (not running)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "sc" in cmd and "query" in cmd:
            return _make_subprocess_result(_sc_query_service_stopped())
        return _make_subprocess_result()
    return fake_run


def _fake_run_old_updates():
    """No updates in 100+ days (CRITICAL)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_old())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_none())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_0())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(
                        _ps_pause_registry_not_found(), returncode=1
                    )
        return _make_subprocess_result()
    return fake_run


def _fake_run_stale_updates():
    """No updates in 40 days (WARNING)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_stale())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_none())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_0())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(
                        _ps_pause_registry_not_found(), returncode=1
                    )
        return _make_subprocess_result()
    return fake_run


def _fake_run_mandatory_updates_pending():
    """2 mandatory updates pending."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_recent())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_mandatory())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_0())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(
                        _ps_pause_registry_not_found(), returncode=1
                    )
        return _make_subprocess_result()
    return fake_run


def _fake_run_failed_updates():
    """3 failed updates in event log."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_recent())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_none())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_3())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(
                        _ps_pause_registry_not_found(), returncode=1
                    )
        return _make_subprocess_result()
    return fake_run


def _fake_run_updates_paused():
    """Updates are paused."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "sc" in cmd and "query" in cmd and "wuauserv" in cmd:
                return _make_subprocess_result(_sc_query_service_running())
            elif "powershell" in cmd:
                if "Get-HotFix" in cmd_str:
                    return _make_subprocess_result(_ps_last_update_recent())
                elif "Search" in cmd_str and "IsInstalled=0" in cmd_str:
                    return _make_subprocess_result(_ps_pending_updates_none())
                elif "Get-WinEvent" in cmd_str:
                    return _make_subprocess_result(_ps_failed_updates_count_0())
                elif "PauseUpdatesExpiryTime" in cmd_str:
                    return _make_subprocess_result(_ps_pause_registry_active())
        return _make_subprocess_result()
    return fake_run


# ===== Tests =====


def test_win_windows_update_status_discovered():
    """Module is discoverable with correct metadata."""
    mod = _get_module()
    assert mod.name == "win_windows_update_status"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_windows_update_status_healthy():
    """Service running, recent updates, no pending - healthy status."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_running_recent_updates()):
        result = mod.check(_make_profile())
    # Should have INFO finding for healthy status
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention "installed" in title or "current"/"healthy" in description
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    # At least one should mention updates/installation
    all_text = " ".join([f.title + " " + f.description for f in info_findings]).lower()
    assert "install" in all_text or "update" in all_text


def test_win_windows_update_status_service_disabled():
    """Service is disabled - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert "disabled" in critical[0].title.lower()


def test_win_windows_update_status_service_not_running():
    """Service is stopped - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_stopped()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning) > 0
    assert "not running" in warning[0].title.lower()


def test_win_windows_update_status_no_recent_updates_critical():
    """No updates in 100+ days - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_updates()):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert "no updates" in critical[0].title.lower() or "critical" in critical[0].description.lower()


def test_win_windows_update_status_stale_updates_warning():
    """No updates in 40 days - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stale_updates()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning) > 0
    # Should mention stale or old updates
    warning_titles = [f.title.lower() for f in warning]
    assert any("update" in t and "day" in t for t in warning_titles)


def test_win_windows_update_status_mandatory_updates():
    """Mandatory updates pending - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mandatory_updates_pending()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning) > 0
    assert "mandatory" in warning[0].title.lower()


def test_win_windows_update_status_failed_updates():
    """Failed updates in event log - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_failed_updates()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning) > 0
    assert "failed" in warning[0].title.lower()


def test_win_windows_update_status_updates_paused():
    """Updates are paused - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_updates_paused()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning) > 0
    assert "paused" in warning[0].title.lower()


def test_win_windows_update_status_fix_service_disabled():
    """Fix action for disabled service."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_disabled()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_windows_update_status_fix_mandatory_updates():
    """Fix action for pending mandatory updates."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_mandatory_updates_pending()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_windows_update_status_fix_healthy():
    """Fix action for healthy status."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_running_recent_updates()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True
