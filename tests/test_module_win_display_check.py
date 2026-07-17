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
    return next(m for m in modules if m.name == "win_display_check")


def _make_run_result(
    displays=None,
    monitor_count=0,
    dpi_level=96,
    display_fail=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # PowerShell commands
        if "powershell" in cmd_str:
            # Get-CimInstance Win32_VideoController
            if "Win32_VideoController" in cmd_str:
                if display_fail:
                    result.returncode = 1
                    result.stderr = "Failed"
                elif displays:
                    result.stdout = json.dumps(displays)
                else:
                    # Default: single display with normal driver date
                    default_display = [
                        {
                            "Name": "NVIDIA GeForce RTX 3070",
                            "VideoModeDescription": "1920 x 1080 x 4294967296 colors",
                            "CurrentHorizontalResolution": 1920,
                            "CurrentVerticalResolution": 1080,
                            "CurrentRefreshRate": 60,
                            "DriverVersion": "536.23",
                            "DriverDate": "20231101000000.000000+000",
                            "AdapterRAM": 8589934592,
                        }
                    ]
                    result.stdout = json.dumps(default_display)
            # Get-CimInstance Win32_DesktopMonitor
            elif "Win32_DesktopMonitor" in cmd_str and "Measure-Object" in cmd_str:
                result.stdout = f"Count             : {monitor_count}\n"
            # reg query for LogPixels
            elif "reg query" in cmd_str and "LogPixels" in cmd_str:
                if dpi_level:
                    hex_val = f"{dpi_level:x}"
                    result.stdout = f'    LogPixels    REG_DWORD    0x{hex_val}\n'
                else:
                    result.returncode = 1

        return result

    return fake_run


def test_win_display_check_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "win_display_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_display_check_healthy_display():
    """Test when display is healthy with normal configuration."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "1920 x 1080 x 4294967296 colors",
            "CurrentHorizontalResolution": 1920,
            "CurrentVerticalResolution": 1080,
            "CurrentRefreshRate": 60,
            "DriverVersion": "536.23",
            "DriverDate": "20231101000000.000000+000",
            "AdapterRAM": 8589934592,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "display_config" for f in result.findings)
    config_finding = [f for f in result.findings if f.data.get("check") == "display_config"]
    assert config_finding[0].severity == Severity.INFO


def test_win_display_check_outdated_driver():
    """Test detection of outdated display driver."""
    mod = _get_module()
    # Driver date from 4 years ago (2020)
    displays = [
        {
            "Name": "Intel HD Graphics 620",
            "VideoModeDescription": "1366 x 768 x 4294967296 colors",
            "CurrentHorizontalResolution": 1366,
            "CurrentVerticalResolution": 768,
            "CurrentRefreshRate": 60,
            "DriverVersion": "27.20.100.9316",
            "DriverDate": "20200315000000.000000+000",
            "AdapterRAM": 1073741824,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "outdated_driver" for f in result.findings)
    outdated = [f for f in result.findings if f.data.get("check") == "outdated_driver"]
    assert outdated[0].severity == Severity.WARNING


def test_win_display_check_high_dpi_scaling():
    """Test detection of high DPI scaling."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "3840 x 2160 x 4294967296 colors",
            "CurrentHorizontalResolution": 3840,
            "CurrentVerticalResolution": 2160,
            "CurrentRefreshRate": 60,
            "DriverVersion": "536.23",
            "DriverDate": "20231101000000.000000+000",
            "AdapterRAM": 8589934592,
        }
    ]
    # DPI 144 (high scaling)
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=144)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "high_dpi_scaling" for f in result.findings)
    dpi_finding = [f for f in result.findings if f.data.get("check") == "high_dpi_scaling"]
    assert dpi_finding[0].severity == Severity.WARNING


def test_win_display_check_multiple_monitors():
    """Test detection of multiple monitors."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "1920 x 1080 x 4294967296 colors",
            "CurrentHorizontalResolution": 1920,
            "CurrentVerticalResolution": 1080,
            "CurrentRefreshRate": 60,
            "DriverVersion": "536.23",
            "DriverDate": "20231101000000.000000+000",
            "AdapterRAM": 8589934592,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=2, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    config_finding = [f for f in result.findings if f.data.get("check") == "display_config"]
    assert config_finding[0].data.get("monitor_count") == 2


def test_win_display_check_info_finding():
    """Test informational finding about display config."""
    mod = _get_module()
    displays = [
        {
            "Name": "AMD Radeon RX 6800",
            "VideoModeDescription": "2560 x 1440 x 4294967296 colors",
            "CurrentHorizontalResolution": 2560,
            "CurrentVerticalResolution": 1440,
            "CurrentRefreshRate": 144,
            "DriverVersion": "23.50.1",
            "DriverDate": "20231115000000.000000+000",
            "AdapterRAM": 16106127360,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_win_display_check_display_query_fails():
    """Test graceful handling when display query fails."""
    mod = _get_module()
    fake_run = _make_run_result(display_fail=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "display_info_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "display_info_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_display_check_fix_outdated_driver():
    """Test fix recommendation for outdated driver."""
    mod = _get_module()
    displays = [
        {
            "Name": "Intel HD Graphics 620",
            "VideoModeDescription": "1366 x 768 x 4294967296 colors",
            "CurrentHorizontalResolution": 1366,
            "CurrentVerticalResolution": 768,
            "CurrentRefreshRate": 60,
            "DriverVersion": "27.20.100.9316",
            "DriverDate": "20200315000000.000000+000",
            "AdapterRAM": 1073741824,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    driver_actions = [a for a in fix.actions if "update" in a.title.lower()]
    assert len(driver_actions) > 0
    assert driver_actions[0].success


def test_win_display_check_fix_high_dpi():
    """Test fix recommendation for high DPI scaling."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "3840 x 2160 x 4294967296 colors",
            "CurrentHorizontalResolution": 3840,
            "CurrentVerticalResolution": 2160,
            "CurrentRefreshRate": 60,
            "DriverVersion": "536.23",
            "DriverDate": "20231101000000.000000+000",
            "AdapterRAM": 8589934592,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=144)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    dpi_actions = [a for a in fix.actions if "dpi" in a.title.lower()]
    assert len(dpi_actions) > 0
    assert dpi_actions[0].success


def test_win_display_check_fix_display_config():
    """Test fix recommendation for display config (informational)."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "1920 x 1080 x 4294967296 colors",
            "CurrentHorizontalResolution": 1920,
            "CurrentVerticalResolution": 1080,
            "CurrentRefreshRate": 60,
            "DriverVersion": "536.23",
            "DriverDate": "20231101000000.000000+000",
            "AdapterRAM": 8589934592,
        }
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=1, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    config_actions = [a for a in fix.actions if "configuration" in a.title.lower()]
    assert len(config_actions) > 0
    assert config_actions[0].success


def test_win_display_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_win_display_check_multiple_displays_and_outdated():
    """Test with multiple displays where one has outdated driver."""
    mod = _get_module()
    displays = [
        {
            "Name": "NVIDIA GeForce RTX 3070",
            "VideoModeDescription": "1920 x 1080 x 4294967296 colors",
            "CurrentHorizontalResolution": 1920,
            "CurrentVerticalResolution": 1080,
            "CurrentRefreshRate": 60,
            "DriverVersion": "551.78",
            "DriverDate": "20260501000000.000000+000",
            "AdapterRAM": 8589934592,
        },
        {
            "Name": "Intel HD Graphics 630",
            "VideoModeDescription": "1024 x 768 x 4294967296 colors",
            "CurrentHorizontalResolution": 1024,
            "CurrentVerticalResolution": 768,
            "CurrentRefreshRate": 60,
            "DriverVersion": "27.20.100.8000",
            "DriverDate": "20210615000000.000000+000",
            "AdapterRAM": 1073741824,
        },
    ]
    fake_run = _make_run_result(displays=displays, monitor_count=2, dpi_level=96)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    outdated = [f for f in result.findings if f.data.get("check") == "outdated_driver"]
    assert len(outdated) == 1  # Only Intel driver is outdated
    assert "Intel HD Graphics 630" in outdated[0].data.get("adapter_name")
