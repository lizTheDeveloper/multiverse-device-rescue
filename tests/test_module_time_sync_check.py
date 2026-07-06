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
    return next(m for m in modules if m.name == "time_sync_check")


NTP_ENABLED = "Network Time: On\n"
NTP_DISABLED = "Network Time: Off\n"
NTP_SERVER = "Network time server: time.apple.com\n"
TIMEZONE_AUTO_ENABLED = "1\n"
TIMEZONE_AUTO_DISABLED = "0\n"
CURRENT_TIME = "Mon Jul  6 10:30:45 PDT 2026\n"


def _fake_run(ntp_enabled=True, ntp_server=NTP_SERVER, tz_auto=True, current_time=CURRENT_TIME):
    def fake_run(cmd, **kwargs):
        if cmd[0] == "systemsetup":
            result = MagicMock()
            result.returncode = 0
            if "-getusingnetworktime" in cmd:
                result.stdout = NTP_ENABLED if ntp_enabled else NTP_DISABLED
            elif "-getnetworktimeserver" in cmd:
                result.stdout = ntp_server
            else:
                raise AssertionError(f"unexpected systemsetup command {cmd}")
            return result
        elif cmd[0] == "defaults":
            result = MagicMock()
            result.stdout = TIMEZONE_AUTO_ENABLED if tz_auto else TIMEZONE_AUTO_DISABLED
            result.returncode = 0
            return result
        elif cmd[0] == "date":
            result = MagicMock()
            result.stdout = current_time
            result.returncode = 0
            return result
        raise AssertionError(f"unexpected command {cmd}")
    return fake_run


def test_time_sync_check_discovered():
    mod = _get_module()
    assert mod.name == "time_sync_check"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "integrity"


def test_time_sync_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ntp_enabled=True)):
        result = mod.check(_make_profile())
    # Should have findings about NTP server and current time (INFO level)
    # but no WARNING about NTP disabled
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_time_sync_check_ntp_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ntp_enabled=False)):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = next(f for f in result.findings if f.data["check"] == "ntp_enabled")
    assert finding.severity == Severity.WARNING
    assert finding.data["enabled"] is False


def test_time_sync_check_ntp_server_reported():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run()):
        result = mod.check(_make_profile())
    finding = next(f for f in result.findings if f.data["check"] == "ntp_server")
    assert finding.data["server"] == "time.apple.com"
    assert finding.severity == Severity.INFO


def test_time_sync_check_timezone_auto_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(tz_auto=False)):
        result = mod.check(_make_profile())
    finding = next((f for f in result.findings if f.data["check"] == "timezone_auto"), None)
    assert finding is not None
    assert finding.data["auto"] is False
    assert finding.severity == Severity.INFO


def test_time_sync_check_current_time_reported():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run()):
        result = mod.check(_make_profile())
    finding = next(f for f in result.findings if f.data["check"] == "current_time")
    assert "10:30:45" in finding.data["time"]
    assert finding.severity == Severity.INFO


def test_time_sync_check_fix_ntp_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ntp_enabled=False)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "Set date and time automatically" in fix.actions[0].description
    assert "systemsetup -setusingnetworktime on" in fix.actions[0].description


def test_time_sync_check_fix_ntp_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(ntp_enabled=True)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # No NTP warning, so no actions needed
    assert len(fix.actions) == 0


def test_time_sync_check_systemsetup_error():
    """Test graceful handling when systemsetup fails."""
    def fake_run_error(cmd, **kwargs):
        if cmd[0] == "systemsetup":
            raise OSError("systemsetup not available")
        result = MagicMock()
        result.stdout = CURRENT_TIME
        result.returncode = 0
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_error):
        result = mod.check(_make_profile())
    # Should not crash, just skip NTP checks
    assert not result.has_issues or all(
        f.data["check"] != "ntp_enabled" for f in result.findings
    )


def test_time_sync_check_defaults_error():
    """Test graceful handling when defaults command fails."""
    def fake_run_error(cmd, **kwargs):
        if cmd[0] == "defaults":
            raise OSError("defaults not available")
        result = MagicMock()
        if cmd[0] == "systemsetup":
            result.stdout = NTP_ENABLED
            result.returncode = 0
        else:
            result.stdout = CURRENT_TIME
            result.returncode = 0
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_error):
        result = mod.check(_make_profile())
    # Should not crash, just skip timezone check
    ntp_findings = [f for f in result.findings if f.data["check"] == "ntp_enabled"]
    assert len(ntp_findings) == 0  # NTP is "enabled", so no warning
