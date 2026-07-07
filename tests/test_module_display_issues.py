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
    return next(m for m in modules if m.name == "display_issues")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_retina_display():
    """Normal case: Retina display at native resolution, no mirroring."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Display:
    Display Name: Built-in Liquid Retina
    Resolution: 3072 x 1920
    Connector Type: Internal
    Refresh Rate: 120 Hz
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        else:
            return _make_subprocess_result()

    return fake_run


def _fake_run_scaled_non_retina():
    """Case: Non-Retina display with scaled resolution (blurry text)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Display:
    Display Name: External Display
    Resolution: 1920 x 1080 (Scaled)
    Connector Type: HDMI
    Refresh Rate: 60 Hz
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        else:
            return _make_subprocess_result()

    return fake_run


def _fake_run_non_native_resolution():
    """Case: Display running at non-native resolution."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Display:
    Display Name: MacBook Pro Display
    Resolution: 2560 x 1600 (non-native)
    Connector Type: Internal
    Refresh Rate: 60 Hz
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        else:
            return _make_subprocess_result()

    return fake_run


def _fake_run_external_monitor():
    """Case: External monitor connected."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Display:
    Display Name: Built-in Retina Display
    Resolution: 2560 x 1600
    Connector Type: Internal
    Refresh Rate: 120 Hz

  Display:
    Display Name: Dell UltraSharp
    Resolution: 3840 x 2160
    Connector Type: DisplayPort
    Refresh Rate: 60 Hz
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stdout="CoreBrightness {\n  ... data ...\n}\n", returncode=0)
        else:
            return _make_subprocess_result()

    return fake_run


def _fake_run_night_shift_enabled():
    """Case: Night Shift is enabled."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                stdout="""Graphics/Displays:

  Display:
    Display Name: Built-in Liquid Retina
    Resolution: 3072 x 1920
    Connector Type: Internal
    Refresh Rate: 120 Hz
"""
            )
        elif "defaults read" in cmd_str and "com.apple.CoreBrightness" in cmd_str and "CBUser" not in cmd_str:
            return _make_subprocess_result(
                stdout="""{
    ...
    NightShiftEnabled = 1;
    Schedule = {
        ...
    };
}
""",
                returncode=0,
            )
        elif "defaults read" in cmd_str and "CBUser" in cmd_str:
            return _make_subprocess_result(stdout="", returncode=1)
        else:
            return _make_subprocess_result()

    return fake_run


def _fake_run_no_display_info():
    """Case: No display information available."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(stdout="")
        else:
            return _make_subprocess_result()

    return fake_run


def test_display_issues_discovered():
    mod = _get_module()
    assert mod.name == "display_issues"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_display_issues_healthy_retina():
    """Test normal case with Retina display at native resolution."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_retina_display()):
        result = mod.check(_make_profile())
    # Should have at least display_config finding
    assert result.has_issues
    assert any(f.data.get("check") == "display_config" for f in result.findings)
    # Should not have warnings about scaled resolution
    assert not any(f.data.get("check") == "scaled_non_retina" for f in result.findings)


def test_display_issues_scaled_non_retina():
    """Test warning for scaled resolution on non-Retina display."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_non_retina()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "scaled_non_retina" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "scaled_non_retina")


def test_display_issues_non_native_resolution():
    """Test warning for non-native resolution."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_non_native_resolution()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "non_native_resolution" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings if f.data.get("check") == "non_native_resolution")


def test_display_issues_external_monitor():
    """Test detection of external monitor."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_external_monitor()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "external_monitor" for f in result.findings)


def test_display_issues_night_shift_enabled():
    """Test detection of Night Shift feature."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_night_shift_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "night_shift" for f in result.findings)


def test_display_issues_no_display_info():
    """Test handling of missing display information."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_display_info()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_display_info" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings if f.data.get("check") == "no_display_info")


def test_display_issues_fix_is_informational():
    """Test that fix() returns informational actions only."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_non_retina()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be marked success
    assert all(a.success for a in fix.actions)
