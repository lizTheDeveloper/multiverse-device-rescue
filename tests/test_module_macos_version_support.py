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
    return next(m for m in modules if m.name == "macos_version_support")


def _make_subprocess_mock(version, build, model, model_name, architecture):
    """Create a mock subprocess.run for different macOS versions."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            cmd_str = cmd[0]
        else:
            cmd_str = cmd

        if "sw_vers" in cmd_str:
            if "-productVersion" in cmd or (isinstance(cmd, list) and "-productVersion" in cmd):
                result.stdout = version
            elif "-buildVersion" in cmd or (isinstance(cmd, list) and "-buildVersion" in cmd):
                result.stdout = build
        elif "sysctl" in cmd_str:
            result.stdout = f"hw.model: {model}"
        elif "system_profiler" in cmd_str:
            result.stdout = f"""Hardware:
    Model Name: {model_name}
    Model Identifier: {model}
    System Serial Number: ABC123
"""
        elif "uname" in cmd_str:
            result.stdout = architecture

        return result

    return fake_run


def test_module_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "macos_version_support"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_sequoia_apple_silicon():
    """Test macOS Sequoia (15) on Apple Silicon."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "15.2\n", "24G12\n", "MacBookPro18,3", "MacBook Pro (16-inch, Jan 2023)", "arm64\n"
    )):
        result = mod.check(_make_profile())

    # Should have an INFO finding for version info
    version_findings = [f for f in result.findings if f.data.get("check") == "version_info"]
    assert len(version_findings) == 1
    assert version_findings[0].severity == Severity.INFO
    assert "15.2" in version_findings[0].description


def test_sonoma_apple_silicon():
    """Test macOS Sonoma (14) on Apple Silicon."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "14.6\n", "23G80\n", "MacBookAir13,20", "MacBook Air (M2, 2023)", "arm64\n"
    )):
        result = mod.check(_make_profile())

    version_findings = [f for f in result.findings if f.data.get("check") == "version_info"]
    assert len(version_findings) == 1
    assert version_findings[0].severity == Severity.INFO


def test_ventura_intel():
    """Test macOS Ventura (13) on Intel."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "13.6\n", "22G120\n", "MacBookPro16,2", "MacBook Pro (16-inch, 2021)", "x86_64\n"
    )):
        result = mod.check(_make_profile())

    # Should have version info and Intel warning
    version_findings = [f for f in result.findings if f.data.get("check") == "version_info"]
    intel_findings = [f for f in result.findings if f.data.get("check") == "intel_mac"]

    assert len(version_findings) == 1
    assert len(intel_findings) == 1
    assert intel_findings[0].severity == Severity.WARNING


def test_monterey_limited_support():
    """Test macOS Monterey (12) - limited security updates only."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "12.7\n", "22G720\n", "iMac21,2", "iMac (24-inch, 2021)", "arm64\n"
    )):
        result = mod.check(_make_profile())

    # Should have version info and limited updates warning
    version_findings = [f for f in result.findings if f.data.get("check") == "version_info"]
    limited_findings = [f for f in result.findings if f.data.get("check") == "limited_updates"]

    assert len(version_findings) == 1
    assert len(limited_findings) == 1
    assert limited_findings[0].severity == Severity.WARNING


def test_big_sur_unsupported():
    """Test macOS Big Sur (11) - no longer supported."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "11.7\n", "20G1225\n", "MacBookPro16,1", "MacBook Pro (16-inch, 2019)", "x86_64\n"
    )):
        result = mod.check(_make_profile())

    # Should have version info, unsupported critical, and Intel warning
    version_findings = [f for f in result.findings if f.data.get("check") == "version_info"]
    unsupported_findings = [f for f in result.findings if f.data.get("check") == "unsupported_version"]
    intel_findings = [f for f in result.findings if f.data.get("check") == "intel_mac"]

    assert len(version_findings) == 1
    assert len(unsupported_findings) == 1
    assert unsupported_findings[0].severity == Severity.CRITICAL
    assert len(intel_findings) == 1


def test_catalina_unsupported():
    """Test macOS Catalina (10.15) - very old and unsupported."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "10.15.7\n", "19H2\n", "MacBookAir5,2", "MacBook Air (13-inch, Early 2013)", "x86_64\n"
    )):
        result = mod.check(_make_profile())

    unsupported_findings = [f for f in result.findings if f.data.get("check") == "unsupported_version"]
    assert len(unsupported_findings) == 1
    assert unsupported_findings[0].severity == Severity.CRITICAL
    assert "no longer receiving security updates" in unsupported_findings[0].description.lower()


def test_version_unavailable():
    """Test when macOS version cannot be determined."""
    def fake_run_error(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run_error):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "version_unavailable" for f in result.findings)


def test_fix_sequoia():
    """Test fix for Sequoia version info."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "15.2\n", "24G12\n", "MacBookPro18,3", "MacBook Pro", "arm64\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions for current version should be informational
    assert all(a.success for a in fix.actions)


def test_fix_monterey():
    """Test fix for Monterey limited updates."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "12.7\n", "22G720\n", "iMac21,2", "iMac", "arm64\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    # Should have actions for version info and upgrade guidance
    limited_actions = [a for a in fix.actions if "macOS Monterey" in a.title or "upgrade" in a.description.lower()]
    assert len(limited_actions) > 0


def test_fix_big_sur_unsupported():
    """Test fix for Big Sur unsupported version."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "11.7\n", "20G1225\n", "MacBookPro16,1", "MacBook Pro", "x86_64\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    # Should have multiple actions: version info, unsupported upgrade, and Intel guidance
    assert len(fix.actions) >= 3

    # Should have an upgrade action for unsupported version
    upgrade_actions = [a for a in fix.actions if "upgrade" in a.title.lower()]
    assert len(upgrade_actions) > 0


def test_fix_intel_mac():
    """Test fix for Intel Mac approach to end of support."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_subprocess_mock(
        "13.6\n", "22G120\n", "MacBookPro16,2", "MacBook Pro", "x86_64\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    intel_actions = [a for a in fix.actions if "Intel" in a.title or "Intel" in a.description]
    assert len(intel_actions) > 0
    assert all(a.success for a in intel_actions)


def test_module_properties():
    """Test module has correct properties."""
    mod = _get_module()
    assert mod.platforms == [Platform.DARWIN]
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.priority == 50
    assert mod.depends_on == []
    assert mod.estimated_duration == "3s"
