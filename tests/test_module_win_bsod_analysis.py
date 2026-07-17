import json
import sys
from datetime import datetime, timedelta, timezone
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
    return next(m for m in modules if m.name == "win_bsod_analysis")


def _make_bsod_event(hours_ago=0, days_ago=0, stop_code="0x0000007E"):
    """Create a realistic BSOD event JSON object."""
    timestamp = datetime.now(timezone.utc) - timedelta(hours=hours_ago, days=days_ago)
    return {
        "TimeCreated": timestamp.isoformat().replace("+00:00", "Z"),
        "StopCode": stop_code,
    }


def _make_run_result(bsod_events=None, minidump_exists=False):
    """Create a fake subprocess.run that returns appropriate BSOD results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Handle Get-WinEvent commands for BSOD events
        if "powershell" in cmd_str and "Get-WinEvent" in cmd_str:
            if bsod_events is not None:
                result.stdout = json.dumps(bsod_events)
            else:
                result.stdout = ""

        # Handle Test-Path for minidump files
        elif "powershell" in cmd_str and "Test-Path" in cmd_str:
            if minidump_exists:
                result.stdout = "True\n"
            else:
                result.stdout = "False\n"

        return result

    return fake_run


def test_win_bsod_analysis_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "win_bsod_analysis"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_bsod_analysis_no_events():
    """Test when no BSOD events are found (clean system)."""
    mod = _get_module()
    fake_run = _make_run_result(bsod_events=None, minidump_exists=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_bsod_events" for f in result.findings)
    info_finding = [f for f in result.findings if f.data.get("check") == "no_bsod_events"]
    assert info_finding[0].severity == Severity.INFO


def test_win_bsod_analysis_recent_24h():
    """Test when BSOD occurred in last 24 hours (CRITICAL)."""
    mod = _get_module()
    # Create an event 2 hours ago
    events = [_make_bsod_event(hours_ago=2, stop_code="0x0000007E")]
    fake_run = _make_run_result(bsod_events=events, minidump_exists=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any(f.data.get("check") == "recent_bsod_24h" for f in critical_findings)


def test_win_bsod_analysis_recurring_7d():
    """Test when multiple BSODs in last 7 days (WARNING)."""
    mod = _get_module()
    # Create two events in the last 7 days
    events = [
        _make_bsod_event(days_ago=1, stop_code="0x0000007F"),
        _make_bsod_event(days_ago=5, stop_code="0x0000007E"),
    ]
    fake_run = _make_run_result(bsod_events=events, minidump_exists=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(f.data.get("check") == "recurring_bsod_7d" for f in warning_findings)


def test_win_bsod_analysis_history():
    """Test BSOD history INFO finding."""
    mod = _get_module()
    events = [
        _make_bsod_event(hours_ago=48, stop_code="0x0000007E"),
        _make_bsod_event(days_ago=10, stop_code="0x00000050"),
        _make_bsod_event(days_ago=20, stop_code="0x0000007E"),
    ]
    fake_run = _make_run_result(bsod_events=events, minidump_exists=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.data.get("check") == "bsod_history"]
    assert len(info_findings) > 0
    assert info_findings[0].data.get("total_events") == 3
    assert info_findings[0].data.get("minidump_exists") is True


def test_win_bsod_analysis_stop_code_mapping():
    """Test that stop codes are properly mapped to descriptions."""
    mod = _get_module()
    events = [_make_bsod_event(hours_ago=12, stop_code="0x0000007E")]
    fake_run = _make_run_result(bsod_events=events)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have CRITICAL finding mentioning the stop code
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) > 0
    assert "0x0000007E" in critical[0].description


def test_win_bsod_analysis_fix_critical():
    """Test fix recommendations for recent BSOD."""
    mod = _get_module()
    events = [_make_bsod_event(hours_ago=3, stop_code="0x00000050")]
    fake_run = _make_run_result(bsod_events=events)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for the critical finding
    critical_action = [a for a in fix.actions if "24 hours" in a.title.lower() or "critical" in a.title.lower()]
    assert len(critical_action) > 0


def test_win_bsod_analysis_fix_recurring():
    """Test fix recommendations for recurring BSODs."""
    mod = _get_module()
    events = [
        _make_bsod_event(days_ago=2, stop_code="0x0000007F"),
        _make_bsod_event(days_ago=5, stop_code="0x0000007F"),
    ]
    fake_run = _make_run_result(bsod_events=events)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for recurring BSODs
    recurring_action = [a for a in fix.actions if "recurring" in a.title.lower()]
    assert len(recurring_action) > 0


def test_win_bsod_analysis_multiple_stop_codes():
    """Test handling of multiple different stop codes."""
    mod = _get_module()
    events = [
        _make_bsod_event(days_ago=1, stop_code="0x0000007E"),
        _make_bsod_event(days_ago=3, stop_code="0x00000050"),
        _make_bsod_event(days_ago=6, stop_code="0x0000007F"),
    ]
    fake_run = _make_run_result(bsod_events=events)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # History finding should capture all stop codes
    history = [f for f in result.findings if f.data.get("check") == "bsod_history"]
    assert len(history) > 0
    stop_codes = history[0].data.get("stop_codes", {})
    assert len(stop_codes) >= 3


def test_win_bsod_analysis_single_old_event():
    """Test with a single BSOD event older than 7 days."""
    mod = _get_module()
    events = [_make_bsod_event(days_ago=15, stop_code="0x0000007E")]
    fake_run = _make_run_result(bsod_events=events, minidump_exists=False)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should only have history info, not CRITICAL or WARNING
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical) == 0
    assert len(warning) == 0
    # But should have history
    history = [f for f in result.findings if f.data.get("check") == "bsod_history"]
    assert len(history) > 0


def test_win_bsod_analysis_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("PowerShell command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should complete without crashing, return no events found
    assert isinstance(result.findings, list)
    assert any(f.data.get("check") == "no_bsod_events" for f in result.findings)


def test_win_bsod_analysis_empty_json():
    """Test handling of empty PowerShell JSON output."""
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should handle gracefully as no events
    assert any(f.data.get("check") == "no_bsod_events" for f in result.findings)


def test_win_bsod_analysis_minidump_check():
    """Test minidump file existence check."""
    mod = _get_module()
    events = [_make_bsod_event(days_ago=5, stop_code="0x0000007E")]
    # Test with minidump files
    fake_run = _make_run_result(bsod_events=events, minidump_exists=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    history = [f for f in result.findings if f.data.get("check") == "bsod_history"]
    assert history[0].data.get("minidump_exists") is True

    # Test without minidump files
    fake_run_no_dump = _make_run_result(bsod_events=events, minidump_exists=False)
    with patch("subprocess.run", side_effect=fake_run_no_dump):
        result = mod.check(_make_profile())
    history = [f for f in result.findings if f.data.get("check") == "bsod_history"]
    assert history[0].data.get("minidump_exists") is False


def test_win_bsod_analysis_fix_no_events():
    """Test fix action for no BSOD events."""
    mod = _get_module()
    fake_run = _make_run_result(bsod_events=None)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action confirming system is stable
    stable_action = [a for a in fix.actions if "stable" in a.title.lower()]
    assert len(stable_action) > 0
