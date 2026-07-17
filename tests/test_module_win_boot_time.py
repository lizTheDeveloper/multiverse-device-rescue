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
    return next(m for m in modules if m.name == "win_boot_time")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_fast_boot(
    last_boot_time_str="7/7/2026 10:30:45 AM",
    boot_duration_ms="45000",
    fast_startup_enabled=True,
):
    """Mock subprocess for fast boot scenario (< 60s, < 30 days uptime, Fast Startup enabled)"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "LastBootUpTime" in cmd_str:
            return _make_subprocess_result(last_boot_time_str + "\n")
        elif "Get-WinEvent" in cmd_str:
            return _make_subprocess_result(boot_duration_ms + "\n")
        elif "reg query" in cmd_str:
            if fast_startup_enabled:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x1\n"
                )
            else:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x0\n"
                )
        return _make_subprocess_result()

    return fake_run


def _fake_run_slow_boot(
    last_boot_time_str="7/6/2026 9:00:00 AM",
    boot_duration_ms="95000",
    fast_startup_enabled=False,
):
    """Mock subprocess for slow boot scenario (> 60s, Fast Startup disabled)"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "LastBootUpTime" in cmd_str:
            return _make_subprocess_result(last_boot_time_str + "\n")
        elif "Get-WinEvent" in cmd_str:
            return _make_subprocess_result(boot_duration_ms + "\n")
        elif "reg query" in cmd_str:
            if fast_startup_enabled:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x1\n"
                )
            else:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x0\n"
                )
        return _make_subprocess_result()

    return fake_run


def _fake_run_needs_restart(
    last_boot_time_str="6/6/2026 8:15:30 AM",  # 31 days ago
    boot_duration_ms="55000",
    fast_startup_enabled=True,
):
    """Mock subprocess for system needing restart (> 30 days uptime)"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "LastBootUpTime" in cmd_str:
            return _make_subprocess_result(last_boot_time_str + "\n")
        elif "Get-WinEvent" in cmd_str:
            return _make_subprocess_result(boot_duration_ms + "\n")
        elif "reg query" in cmd_str:
            if fast_startup_enabled:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x1\n"
                )
            else:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x0\n"
                )
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_boot_event(
    last_boot_time_str="7/7/2026 10:30:45 AM",
    fast_startup_enabled=True,
):
    """Mock subprocess when boot event cannot be retrieved"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "LastBootUpTime" in cmd_str:
            return _make_subprocess_result(last_boot_time_str + "\n")
        elif "Get-WinEvent" in cmd_str:
            return _make_subprocess_result("N/A\n")
        elif "reg query" in cmd_str:
            if fast_startup_enabled:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x1\n"
                )
            else:
                return _make_subprocess_result(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\n"
                    "    HiberbootEnabled    REG_DWORD    0x0\n"
                )
        return _make_subprocess_result()

    return fake_run


def test_win_boot_time_discovered():
    mod = _get_module()
    assert mod.name == "win_boot_time"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_boot_time_fast_boot():
    """Test with fast boot time and recent startup"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_fast_boot()):
        result = mod.check(_make_profile())
    # Should only have INFO finding
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    # Verify boot duration is recorded
    assert any(f.data.get("boot_duration_seconds") == 45 for f in result.findings)


def test_win_boot_time_slow_boot():
    """Test with slow boot time (exceeds 60s threshold)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_slow_boot()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should have warning about boot time
    assert any(
        "slow boot" in f.title.lower() and f.severity == Severity.WARNING
        for f in result.findings
    )
    # Verify boot duration is recorded
    assert any(f.data.get("boot_duration_seconds") == 95 for f in result.findings)


def test_win_boot_time_needs_restart():
    """Test with system uptime exceeding 30 days"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_needs_restart()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should have warning about restart needed
    assert any(
        "restart" in f.title.lower() and f.severity == Severity.WARNING
        for f in result.findings
    )
    # Verify uptime is recorded
    assert any(f.data.get("uptime_days") >= 31 for f in result.findings)


def test_win_boot_time_no_boot_event():
    """Test when boot event log entry is not available"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_boot_event()):
        result = mod.check(_make_profile())
    # Should still have INFO finding without boot duration
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Boot duration should be None
    assert any(f.data.get("boot_duration_seconds") is None for f in result.findings)


def test_win_boot_time_fix_is_informational():
    """Test that fix() produces informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_slow_boot()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for slow boot
    assert len(fix.actions) > 0
    # Verify actions are about boot optimization or restart
    action_descriptions = " ".join(a.description for a in fix.actions).lower()
    assert any(
        keyword in action_descriptions
        for keyword in ["fast startup", "restart", "boot", "startup"]
    )


def test_win_boot_time_fast_startup_status():
    """Test that Fast Startup status is correctly reported"""
    mod = _get_module()
    # Test with Fast Startup enabled
    with patch("subprocess.run", side_effect=_fake_run_fast_boot(fast_startup_enabled=True)):
        result = mod.check(_make_profile())
    assert any(
        f.data.get("fast_startup_enabled") is True for f in result.findings
    )

    # Test with Fast Startup disabled
    with patch(
        "subprocess.run",
        side_effect=_fake_run_fast_boot(
            boot_duration_ms="75000", fast_startup_enabled=False
        ),
    ):
        result = mod.check(_make_profile())
    assert any(
        f.data.get("fast_startup_enabled") is False for f in result.findings
    )
