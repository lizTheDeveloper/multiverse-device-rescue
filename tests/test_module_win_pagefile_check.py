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
    """Discover and return the win_pagefile_check module."""
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_pagefile_check")


def test_win_pagefile_check_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "win_pagefile_check"
    assert mod.category == "performance"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_no_pagefile_exists():
    """Test detection when no pagefile exists (CRITICAL)."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        # Return empty output for both settings and usage
        return MagicMock(returncode=0, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("type") == "no_pagefile" for f in result.findings)
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert critical_findings


def test_pagefile_too_small():
    """Test warning when pagefile max < RAM."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 4096,
        "MaximumSize": 4096,  # 4GB pagefile
    })

    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 1024,
        "AllocatedBaseSize": 4096,
        "PeakUsage": 2048,
    })

    drive_json = json.dumps({
        "SizeRemaining": 100000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        # 8GB RAM with 4GB pagefile should warn
        result = mod.check(_make_profile(ram_mb=8192))

    assert result.has_issues
    too_small_findings = [f for f in result.findings if f.data.get("type") == "pagefile_too_small"]
    assert too_small_findings
    assert too_small_findings[0].severity == Severity.WARNING


def test_pagefile_high_usage():
    """Test warning when pagefile usage > 80%."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 4096,
        "MaximumSize": 4096,
    })

    # 3300MB of 4096MB = 80.5% usage
    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 3300,
        "AllocatedBaseSize": 4096,
        "PeakUsage": 3500,
    })

    drive_json = json.dumps({
        "SizeRemaining": 100000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    assert result.has_issues
    high_usage_findings = [f for f in result.findings if f.data.get("type") == "pagefile_high_usage"]
    assert high_usage_findings
    assert high_usage_findings[0].severity == Severity.WARNING


def test_pagefile_drive_nearly_full():
    """Test warning when pagefile drive has <10% free."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "D:\\pagefile.sys",
        "InitialSize": 8192,
        "MaximumSize": 8192,
    })

    usage_json = json.dumps({
        "Name": "D:\\pagefile.sys",
        "CurrentUsage": 1024,
        "AllocatedBaseSize": 8192,
        "PeakUsage": 2048,
    })

    # Only 5% free space
    drive_json = json.dumps({
        "SizeRemaining": 500000000000,
        "Size": 10000000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    assert result.has_issues
    drive_full_findings = [f for f in result.findings if f.data.get("type") == "pagefile_drive_nearly_full"]
    assert drive_full_findings
    assert drive_full_findings[0].severity == Severity.WARNING


def test_pagefile_healthy():
    """Test healthy pagefile configuration (8GB pagefile for 8GB RAM)."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 8192,
        "MaximumSize": 8192,
    })

    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 1024,
        "AllocatedBaseSize": 8192,
        "PeakUsage": 2048,
    })

    drive_json = json.dumps({
        "SizeRemaining": 100000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    # Should have at least the INFO status finding, no warnings
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert not warning_findings
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert info_findings


def test_pagefile_status_info_finding():
    """Test that pagefile status info finding is always present."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 4096,
        "MaximumSize": 8192,
    })

    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 2048,
        "AllocatedBaseSize": 8192,
        "PeakUsage": 3000,
    })

    drive_json = json.dumps({
        "SizeRemaining": 150000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    status_findings = [f for f in result.findings if f.data.get("type") == "pagefile_status"]
    assert status_findings
    assert status_findings[0].severity == Severity.INFO
    assert "C:\\pagefile.sys" in status_findings[0].description
    assert "8192MB" in status_findings[0].description  # RAM size


def test_pagefile_fix_is_informational():
    """Test that fix() returns informational actions without modifying system."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 2048,
        "MaximumSize": 2048,
    })

    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 512,
        "AllocatedBaseSize": 2048,
        "PeakUsage": 1024,
    })

    drive_json = json.dumps({
        "SizeRemaining": 100000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile(ram_mb=8192))
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # Actions should suggest steps, not actually modify
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success


def test_pagefile_fix_no_pagefile_critical():
    """Test fix suggestions for missing pagefile (CRITICAL finding)."""
    mod = _get_module()

    def mock_run(cmd, **kwargs):
        return MagicMock(returncode=0, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    # Should have action for enabling pagefile
    enable_actions = [a for a in fix.actions if "enable" in a.title.lower()]
    assert enable_actions


def test_pagefile_fix_too_small_warning():
    """Test fix suggestions for too-small pagefile."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 4096,
        "MaximumSize": 4096,
    })

    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 1024,
        "AllocatedBaseSize": 4096,
        "PeakUsage": 2048,
    })

    drive_json = json.dumps({
        "SizeRemaining": 100000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile(ram_mb=8192))
        fix = mod.fix(check, Mode.AUTO)

    # Should have action for increasing pagefile
    increase_actions = [a for a in fix.actions if "increase" in a.title.lower()]
    assert increase_actions


def test_multiple_issues_in_findings():
    """Test that multiple issues are reported correctly."""
    mod = _get_module()

    settings_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "InitialSize": 2048,
        "MaximumSize": 2048,  # Too small for 8GB RAM
    })

    # High usage: 1800/2048 = 87.9%
    usage_json = json.dumps({
        "Name": "C:\\pagefile.sys",
        "CurrentUsage": 1800,
        "AllocatedBaseSize": 2048,
        "PeakUsage": 1900,
    })

    # Only 8% free space
    drive_json = json.dumps({
        "SizeRemaining": 40000000000,
        "Size": 500000000000,
    })

    def mock_run(cmd, **kwargs):
        if "PageFileSetting" in str(cmd):
            return MagicMock(returncode=0, stdout=settings_json)
        elif "PageFileUsage" in str(cmd):
            return MagicMock(returncode=0, stdout=usage_json)
        elif "Get-Volume" in str(cmd):
            return MagicMock(returncode=0, stdout=drive_json)
        return MagicMock(returncode=1, stdout="")

    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile(ram_mb=8192))

    # Should have multiple issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 2  # Too small + high usage + drive nearly full
    types = [f.data.get("type") for f in warning_findings]
    assert "pagefile_too_small" in types
    assert "pagefile_high_usage" in types
    assert "pagefile_drive_nearly_full" in types
