import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "safe_boot_check")


def _fake_run_normal_boot():
    """Mock subprocess for normal boot (not in Safe Mode, recent boot)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "sysctl" in cmd_str:
            if "kern.safeboot" in cmd:
                result.stdout = "kern.safeboot: 0\n"
            elif "kern.boottime" in cmd:
                # Boot time 1 day ago
                boot_timestamp = int((datetime.now() - timedelta(days=1)).timestamp())
                result.stdout = f"kern.boottime: {{ sec = {boot_timestamp}, usec = 123456 }} Wed Jun 28 14:00:34 2023\n"
        elif "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            result.stdout = "boot-args\t\n"

        return result
    return fake_run


def _fake_run_safe_mode():
    """Mock subprocess for Safe Mode boot."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "sysctl" in cmd_str:
            if "kern.safeboot" in cmd:
                result.stdout = "kern.safeboot: 1\n"
            elif "kern.boottime" in cmd:
                boot_timestamp = int((datetime.now() - timedelta(days=2)).timestamp())
                result.stdout = f"kern.boottime: {{ sec = {boot_timestamp}, usec = 123456 }} Wed Jun 28 14:00:34 2023\n"
        elif "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            result.stdout = "boot-args\t-x\n"

        return result
    return fake_run


def _fake_run_verbose_boot():
    """Mock subprocess for verbose boot enabled."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "sysctl" in cmd_str:
            if "kern.safeboot" in cmd:
                result.stdout = "kern.safeboot: 0\n"
            elif "kern.boottime" in cmd:
                boot_timestamp = int((datetime.now() - timedelta(days=1)).timestamp())
                result.stdout = f"kern.boottime: {{ sec = {boot_timestamp}, usec = 123456 }} Wed Jun 28 14:00:34 2023\n"
        elif "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            result.stdout = "boot-args\t-v\n"

        return result
    return fake_run


def _fake_run_long_uptime():
    """Mock subprocess for system with long uptime (>30 days)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "sysctl" in cmd_str:
            if "kern.safeboot" in cmd:
                result.stdout = "kern.safeboot: 0\n"
            elif "kern.boottime" in cmd:
                # Boot time 45 days ago
                boot_timestamp = int((datetime.now() - timedelta(days=45)).timestamp())
                result.stdout = f"kern.boottime: {{ sec = {boot_timestamp}, usec = 123456 }} Wed Jun 28 14:00:34 2023\n"
        elif "bless" in cmd_str:
            result.stdout = "/dev/disk0s1\n"
        elif "nvram" in cmd_str:
            result.stdout = "boot-args\t\n"

        return result
    return fake_run


def test_safe_boot_check_discovered():
    mod = _get_module()
    assert mod.name == "safe_boot_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_safe_boot_check_normal_boot():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        result = mod.check(_make_profile())
    # Normal boot should have findings (boot volume, uptime info) but no issues
    assert result.has_issues is False or all(f.severity == Severity.INFO for f in result.findings)


def test_safe_boot_check_safe_mode():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safe_mode()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "safe_mode" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_safe_boot_check_verbose_boot():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_verbose_boot()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "verbose_boot" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_safe_boot_check_long_uptime():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_long_uptime()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "uptime_exceeds_30days" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_safe_boot_check_fix_safe_mode():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safe_mode()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least one action for safe mode
    assert any(a.title == "Exit Safe Mode" for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_safe_boot_check_fix_long_uptime():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_long_uptime()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least one action for long uptime
    assert any(a.title == "Consider restarting your Mac" for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_safe_boot_check_fix_all_succeeded():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
