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
        os_name="Windows 10",
        os_version="10.0.19045",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_safe_mode_check")


def _make_run_result(
    current_safeboot=None,
    bootmgr_safeboot=False,
    last_boot_time=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # bcdedit /enum {current}
        if "bcdedit" in cmd_str and "{current}" in cmd_str:
            if current_safeboot:
                result.stdout = (
                    "Windows Boot Loader\n"
                    "identifier              {12345678-1234-1234-1234-123456789012}\n"
                    "device                  partition=C:\n"
                    "path                    \\Windows\\system32\\winload.exe\n"
                )
                if current_safeboot == "minimal":
                    result.stdout += "safeboot               Minimal\n"
                elif current_safeboot == "network":
                    result.stdout += "safeboot               Network\n"
                elif current_safeboot == "dsrepair":
                    result.stdout += "safeboot               DsRepair\n"
            else:
                result.stdout = (
                    "Windows Boot Loader\n"
                    "identifier              {12345678-1234-1234-1234-123456789012}\n"
                    "device                  partition=C:\n"
                    "path                    \\Windows\\system32\\winload.exe\n"
                )

        # bcdedit /enum bootmgr
        elif "bcdedit" in cmd_str and "bootmgr" in cmd_str:
            if bootmgr_safeboot:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n"
                    "safeboot               Yes\n"
                )
            else:
                result.stdout = (
                    "Windows Boot Manager\n"
                    "identifier              {bootmgr}\n"
                )

        # PowerShell Get-CimInstance for uptime
        elif "powershell" in cmd_str and "Win32_OperatingSystem" in cmd_str:
            if last_boot_time:
                uptime_data = {"LastBootUpTime": last_boot_time}
                result.stdout = json.dumps(uptime_data)
            else:
                # Default to 5 days ago
                result.stdout = json.dumps({"LastBootUpTime": "2026-07-02T10:00:00"})

        return result

    return fake_run


def test_win_safe_mode_check_discovered():
    mod = _get_module()
    assert mod.name == "win_safe_mode_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_safe_mode_check_normal_boot():
    """Test when system is booting normally (not in Safe Mode)."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "boot_normal" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_safe_mode_check_minimal_safe_mode():
    """Test detection of system running in Minimal Safe Mode."""
    mod = _get_module()
    fake_run = _make_run_result(current_safeboot="minimal")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "current_safeboot" for f in result.findings)
    safe_mode_finding = [f for f in result.findings if f.data.get("check") == "current_safeboot"]
    assert len(safe_mode_finding) > 0
    assert safe_mode_finding[0].severity == Severity.WARNING
    assert safe_mode_finding[0].data.get("mode") == "Minimal"


def test_win_safe_mode_check_network_safe_mode():
    """Test detection of system running in Network Safe Mode."""
    mod = _get_module()
    fake_run = _make_run_result(current_safeboot="network")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "current_safeboot" for f in result.findings)
    safe_mode_finding = [f for f in result.findings if f.data.get("check") == "current_safeboot"]
    assert safe_mode_finding[0].data.get("mode") == "Network"


def test_win_safe_mode_check_safeboot_default():
    """Test detection of Safe Mode as default boot."""
    mod = _get_module()
    fake_run = _make_run_result(bootmgr_safeboot=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "safeboot_default" for f in result.findings)
    default_finding = [f for f in result.findings if f.data.get("check") == "safeboot_default"]
    assert default_finding[0].severity == Severity.WARNING


def test_win_safe_mode_check_high_uptime():
    """Test detection of high uptime (>30 days)."""
    mod = _get_module()
    # 35 days ago
    fake_run = _make_run_result(last_boot_time="2026-06-02T10:00:00")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "high_uptime" for f in result.findings)
    uptime_finding = [f for f in result.findings if f.data.get("check") == "high_uptime"]
    assert uptime_finding[0].severity == Severity.WARNING
    assert uptime_finding[0].data.get("days") >= 30


def test_win_safe_mode_check_low_uptime():
    """Test system with low uptime (<30 days)."""
    mod = _get_module()
    # 5 days ago
    fake_run = _make_run_result(last_boot_time="2026-07-02T10:00:00")
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have high_uptime warning
    assert not any(f.data.get("check") == "high_uptime" for f in result.findings)


def test_win_safe_mode_check_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        current_safeboot="minimal",
        bootmgr_safeboot=True,
        last_boot_time="2026-06-01T10:00:00",  # 36 days ago
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "current_safeboot" in checks
    assert "safeboot_default" in checks
    assert "high_uptime" in checks


def test_win_safe_mode_check_fix_current_safeboot():
    """Test fix recommendation for current Safe Mode."""
    mod = _get_module()
    fake_run = _make_run_result(current_safeboot="minimal")
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    safe_mode_action = [a for a in fix.actions if "safe mode" in a.title.lower()]
    assert len(safe_mode_action) > 0
    assert safe_mode_action[0].success


def test_win_safe_mode_check_fix_safeboot_default():
    """Test fix recommendation for Safe Mode as default."""
    mod = _get_module()
    fake_run = _make_run_result(bootmgr_safeboot=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    default_action = [a for a in fix.actions if "default" in a.title.lower()]
    assert len(default_action) > 0


def test_win_safe_mode_check_fix_high_uptime():
    """Test fix recommendation for high uptime."""
    mod = _get_module()
    fake_run = _make_run_result(last_boot_time="2026-05-30T10:00:00")  # 38 days ago
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    uptime_action = [a for a in fix.actions if "restart" in a.title.lower() or "uptime" in a.title.lower()]
    assert len(uptime_action) > 0


def test_win_safe_mode_check_fix_normal_boot():
    """Test fix action for normal boot (INFO message)."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for normal boot status
    assert any(a.success for a in fix.actions)


def test_win_safe_mode_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
