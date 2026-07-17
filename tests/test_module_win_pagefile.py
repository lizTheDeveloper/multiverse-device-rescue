import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(ram_mb: int = 8192):
    """Create a Windows system profile."""
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=ram_mb * 1024 * 1024,
    )


def _get_module():
    """Discover and return the win_pagefile module."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_pagefile")


def _make_pagefile_settings_json(location: str, initial_size: int, max_size: int) -> str:
    """Create JSON for Get-WmiObject Win32_PageFileSetting output."""
    return json.dumps({
        "Name": location,
        "InitialSize": initial_size,
        "MaximumSize": max_size,
    })


def _make_pagefile_usage_json(current_usage: int, allocated_size: int) -> str:
    """Create JSON for Get-WmiObject Win32_PageFileUsage output."""
    return json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": current_usage,
        "AllocatedBaseSize": allocated_size,
    })


def test_win_pagefile_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "win_pagefile"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_pagefile_disabled():
    """Test detection of disabled pagefile."""
    mod = _get_module()

    # Mock subprocess calls
    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = json.dumps({"Name": None, "InitialSize": 0, "MaximumSize": 0})

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(0, 0)

    call_count = 0

    def mock_run(cmd, **kwargs):
        nonlocal call_count
        if "PageFileSetting" in str(cmd):
            call_count += 1
            return settings_mock
        else:
            return usage_mock

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("type") == "pagefile_disabled" for f in result.findings)


def test_win_pagefile_healthy():
    """Test healthy pagefile configuration (8GB RAM, 8GB pagefile)."""
    mod = _get_module()

    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = _make_pagefile_settings_json("C:\\pagefile.sys", 8192, 8192)

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(1024, 8192)

    drive_mock = MagicMock()
    drive_mock.returncode = 0
    drive_mock.stdout = json.dumps({"SizeRemaining": 100000000000, "Size": 500000000000})

    call_count = 0

    def mock_run(cmd, **kwargs):
        nonlocal call_count
        if "PageFileSetting" in str(cmd):
            return settings_mock
        elif "PageFileUsage" in str(cmd):
            return usage_mock
        elif "Get-Volume" in str(cmd):
            return drive_mock
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    # Should only have INFO finding about pagefile status
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert not any(
        f.severity == Severity.WARNING for f in result.findings
    )


def test_win_pagefile_too_small_low_ram():
    """Test warning for pagefile smaller than RAM on <8GB system."""
    mod = _get_module()

    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = _make_pagefile_settings_json("C:\\pagefile.sys", 2048, 2048)

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(512, 2048)

    drive_mock = MagicMock()
    drive_mock.returncode = 0
    drive_mock.stdout = json.dumps({"SizeRemaining": 50000000000, "Size": 500000000000})

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return settings_mock
        elif "PageFileUsage" in str(cmd):
            return usage_mock
        elif "Get-Volume" in str(cmd):
            return drive_mock
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=4096))  # 4GB RAM, 2GB pagefile

    assert result.has_issues
    warning_findings = [
        f for f in result.findings
        if f.data.get("type") == "pagefile_too_small"
    ]
    assert warning_findings
    assert warning_findings[0].severity == Severity.WARNING


def test_win_pagefile_drive_nearly_full():
    """Test warning for pagefile on nearly-full drive."""
    mod = _get_module()

    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = _make_pagefile_settings_json("D:\\pagefile.sys", 4096, 4096)

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(500, 4096)

    drive_mock = MagicMock()
    drive_mock.returncode = 0
    # Only 5% free (500GB of 10TB total)
    drive_mock.stdout = json.dumps({"SizeRemaining": 500000000000, "Size": 10000000000000})

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return settings_mock
        elif "PageFileUsage" in str(cmd):
            return usage_mock
        elif "Get-Volume" in str(cmd):
            return drive_mock
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    assert result.has_issues
    warning_findings = [
        f for f in result.findings
        if f.data.get("type") == "pagefile_drive_full"
    ]
    assert warning_findings
    assert warning_findings[0].severity == Severity.WARNING


def test_win_pagefile_fix_is_informational():
    """Test that fix() returns informational actions."""
    mod = _get_module()

    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = json.dumps({"Name": None, "InitialSize": 0, "MaximumSize": 0})

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(0, 0)

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return settings_mock
        else:
            return usage_mock

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert "pagefile" in fix.actions[0].description.lower()


def test_win_pagefile_usage_percentage():
    """Test correct calculation of pagefile usage percentage."""
    mod = _get_module()

    settings_mock = MagicMock()
    settings_mock.returncode = 0
    settings_mock.stdout = _make_pagefile_settings_json("C:\\pagefile.sys", 4096, 4096)

    usage_mock = MagicMock()
    usage_mock.returncode = 0
    usage_mock.stdout = _make_pagefile_usage_json(2048, 4096)  # 50% usage

    drive_mock = MagicMock()
    drive_mock.returncode = 0
    drive_mock.stdout = json.dumps({"SizeRemaining": 100000000000, "Size": 500000000000})

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return settings_mock
        elif "PageFileUsage" in str(cmd):
            return usage_mock
        elif "Get-Volume" in str(cmd):
            return drive_mock
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    status_finding = next(
        (f for f in result.findings if f.data.get("type") == "pagefile_status"),
        None,
    )
    assert status_finding
    assert status_finding.data["usage_percent"] == 50
