import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import time

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
    return next(m for m in modules if m.name == "safe_mode_check")


def _fake_run_normal_boot():
    """Mock subprocess for normal boot, no issues."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "nvram" in cmd_str and "boot-args" in cmd_str:
            # Normal boot-args without -x or -v
            result.stdout = "boot-args\tarch=arm64"
        elif "sysctl" in cmd_str and "kern.safeboot" in cmd_str:
            result.stdout = "0"
        elif "bless" in cmd_str:
            result.stdout = "/Volumes/Macintosh HD"
        elif "sysctl" in cmd_str and "kern.boottime" in cmd_str:
            result.stdout = "{ sec = 1704067200, usec = 123456 }"
        elif "diskutil" in cmd_str and "info" in cmd_str:
            result.stdout = """Device Identifier:         disk0s2
Device Node:                /dev/disk0s2
Type:                       APFS
Name:                       Macintosh HD
Mounted:                    Yes
Mount Point:               /"""

        return result

    return fake_run


def _fake_run_safe_mode_nvram():
    """Mock subprocess for Safe Mode (via nvram boot-args)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "nvram" in cmd_str and "boot-args" in cmd_str:
            result.stdout = "boot-args\tarch=arm64 -x"
        elif "sysctl" in cmd_str and "kern.safeboot" in cmd_str:
            result.stdout = "0"
        elif "bless" in cmd_str:
            result.stdout = "/Volumes/Macintosh HD"
        elif "sysctl" in cmd_str and "kern.boottime" in cmd_str:
            result.stdout = "{ sec = 1704067200, usec = 123456 }"
        elif "diskutil" in cmd_str:
            result.stdout = "Type:                       APFS"

        return result

    return fake_run


def _fake_run_safe_mode_sysctl():
    """Mock subprocess for Safe Mode (via sysctl)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "nvram" in cmd_str and "boot-args" in cmd_str:
            result.stdout = "boot-args\tarch=arm64"
        elif "sysctl" in cmd_str and "kern.safeboot" in cmd_str:
            result.stdout = "1"
        elif "bless" in cmd_str:
            result.stdout = "/Volumes/Macintosh HD"
        elif "sysctl" in cmd_str and "kern.boottime" in cmd_str:
            result.stdout = "{ sec = 1704067200, usec = 123456 }"
        elif "diskutil" in cmd_str:
            result.stdout = "Type:                       APFS"

        return result

    return fake_run


def _fake_run_verbose_boot():
    """Mock subprocess for verbose boot enabled."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        if "nvram" in cmd_str and "boot-args" in cmd_str:
            result.stdout = "boot-args\tarch=arm64 -v"
        elif "sysctl" in cmd_str and "kern.safeboot" in cmd_str:
            result.stdout = "0"
        elif "bless" in cmd_str:
            result.stdout = "/Volumes/Macintosh HD"
        elif "sysctl" in cmd_str and "kern.boottime" in cmd_str:
            result.stdout = "{ sec = 1704067200, usec = 123456 }"
        elif "diskutil" in cmd_str:
            result.stdout = "Type:                       APFS"

        return result

    return fake_run


def test_safe_mode_check_discovered():
    mod = _get_module()
    assert mod.name == "safe_mode_check"
    assert mod.category == "integrity"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_safe_mode_check_normal_boot():
    """Test normal boot with no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO finding for boot diagnostics
    assert any(f.data.get("check") == "boot_diagnostics" for f in result.findings)
    # Should not have Safe Mode warning
    assert not any(f.data.get("check") == "safe_mode_enabled" for f in result.findings)
    # Should not have panic warning
    assert not any(f.data.get("check") == "multiple_panics" for f in result.findings)


def test_safe_mode_check_safe_mode_nvram():
    """Test detection of Safe Mode via nvram."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safe_mode_nvram()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "safe_mode_enabled" for f in result.findings)
    safe_mode_finding = [f for f in result.findings if f.data.get("check") == "safe_mode_enabled"]
    assert safe_mode_finding[0].severity == Severity.WARNING


def test_safe_mode_check_safe_mode_sysctl():
    """Test detection of Safe Mode via sysctl."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safe_mode_sysctl()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "safe_mode_enabled" for f in result.findings)
    safe_mode_finding = [f for f in result.findings if f.data.get("check") == "safe_mode_enabled"]
    assert safe_mode_finding[0].severity == Severity.WARNING


def test_safe_mode_check_verbose_boot():
    """Test detection of verbose boot flag."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_verbose_boot()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            result = mod.check(_make_profile())
    assert result.has_issues
    diagnostics = [f for f in result.findings if f.data.get("check") == "boot_diagnostics"]
    assert diagnostics[0].data.get("verbose_boot") is True


def test_safe_mode_check_multiple_panics():
    """Test detection of multiple kernel panics."""
    mod = _get_module()
    panic_files = [
        "/Users/test/Library/Logs/DiagnosticReports/panic1.panic",
        "/Users/test/Library/Logs/DiagnosticReports/panic2.panic",
    ]
    # Use a timestamp from 1 day ago (within 7 days)
    recent_timestamp = time.time() - (24 * 3600)
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.os.path.exists", return_value=True):
            with patch("modules.integrity.safe_mode_check.glob.glob", return_value=panic_files):
                with patch("modules.integrity.safe_mode_check.os.path.getmtime") as mock_getmtime:
                    mock_getmtime.return_value = recent_timestamp
                    result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "multiple_panics" for f in result.findings)
    panic_finding = [f for f in result.findings if f.data.get("check") == "multiple_panics"]
    assert panic_finding[0].severity == Severity.CRITICAL
    assert panic_finding[0].data.get("count") == 2


def test_safe_mode_check_single_panic():
    """Test detection of single kernel panic (not flagged as multiple)."""
    mod = _get_module()
    panic_files = [
        "/Users/test/Library/Logs/DiagnosticReports/panic1.panic",
    ]
    # Use a timestamp from 1 day ago (within 7 days)
    recent_timestamp = time.time() - (24 * 3600)
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.os.path.exists", return_value=True):
            with patch("modules.integrity.safe_mode_check.glob.glob", return_value=panic_files):
                with patch("modules.integrity.safe_mode_check.os.path.getmtime") as mock_getmtime:
                    mock_getmtime.return_value = recent_timestamp
                    result = mod.check(_make_profile())
    assert result.has_issues
    # Should NOT have multiple_panics check
    assert not any(f.data.get("check") == "multiple_panics" for f in result.findings)
    diagnostics = [f for f in result.findings if f.data.get("check") == "boot_diagnostics"]
    assert diagnostics[0].data.get("panic_count") == 1


def test_safe_mode_check_old_panics():
    """Test that panics older than 7 days are not counted."""
    mod = _get_module()
    panic_files = [
        "/Users/test/Library/Logs/DiagnosticReports/panic_old.panic",
        "/Users/test/Library/Logs/DiagnosticReports/panic_old2.panic",
    ]
    # Use a timestamp from 14 days ago (older than 7 days)
    old_timestamp = time.time() - (14 * 24 * 3600)
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.os.path.exists", return_value=True):
            with patch("modules.integrity.safe_mode_check.glob.glob", return_value=panic_files):
                with patch("modules.integrity.safe_mode_check.os.path.getmtime") as mock_getmtime:
                    mock_getmtime.return_value = old_timestamp
                    result = mod.check(_make_profile())
    assert result.has_issues
    diagnostics = [f for f in result.findings if f.data.get("check") == "boot_diagnostics"]
    assert diagnostics[0].data.get("panic_count") == 0


def test_safe_mode_check_fix_safe_mode():
    """Test fix recommendation for Safe Mode."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safe_mode_nvram()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("exit" in a.title.lower() or "safe mode" in a.title.lower() for a in fix.actions)
    # Actions should be informational (success=True)
    assert all(a.success for a in fix.actions)


def test_safe_mode_check_fix_multiple_panics():
    """Test fix recommendation for multiple panics."""
    mod = _get_module()
    panic_files = [
        "/Users/test/Library/Logs/DiagnosticReports/panic1.panic",
        "/Users/test/Library/Logs/DiagnosticReports/panic2.panic",
    ]
    # Use a timestamp from 1 day ago (within 7 days)
    recent_timestamp = time.time() - (24 * 3600)
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.os.path.exists", return_value=True):
            with patch("modules.integrity.safe_mode_check.glob.glob", return_value=panic_files):
                with patch("modules.integrity.safe_mode_check.os.path.getmtime") as mock_getmtime:
                    mock_getmtime.return_value = recent_timestamp
                    check = mod.check(_make_profile())
                    fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("panic" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_safe_mode_check_fix_normal_boot():
    """Test fix recommendation for normal boot."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_normal_boot()):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have "normal" action
    assert any("normal" in a.title.lower() or "no action" in a.description.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_safe_mode_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        with patch("modules.integrity.safe_mode_check.glob.glob", return_value=[]):
            result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    # Should have at least the boot_diagnostics INFO finding
    assert any(f.data.get("check") == "boot_diagnostics" for f in result.findings)
