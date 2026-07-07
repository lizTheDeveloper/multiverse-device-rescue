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
    return next(m for m in modules if m.name == "display_config")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: single display at native resolution, Night Shift off"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                """Graphics/Displays:

    Apple M2:
      Cores: 8
      GPU Memory: Dynamic

    Display Name: Built-in Retina Display
    Resolution: 2560 x 1600 @ 120 Hz
    Connector Type: Internal
    Pixel Pitch: 0.125 mm
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "defaults read" in cmd_str and "AppleDisplayBrightness" in cmd_str:
            return _make_subprocess_result(
                'brightness = "0.75";\n',
                returncode=0,
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_scaled_resolution():
    """Display running at scaled resolution"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                """Graphics/Displays:

    Apple M2:
      Cores: 8
      GPU Memory: Dynamic

    Display Name: Built-in Retina Display
    Resolution: 1680 x 1050 Scaled @ 120 Hz
    Connector Type: Internal
    Pixel Pitch: 0.125 mm
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "defaults read" in cmd_str and "AppleDisplayBrightness" in cmd_str:
            return _make_subprocess_result('brightness = "0.75";\n', returncode=0)
        return _make_subprocess_result()
    return fake_run


def _fake_run_external_display():
    """Multiple displays: built-in + external"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                """Graphics/Displays:

    Apple M2:
      Cores: 8
      GPU Memory: Dynamic

    Display Name: Built-in Retina Display
    Resolution: 2560 x 1600 @ 120 Hz
    Connector Type: Internal
    Pixel Pitch: 0.125 mm

    Display Name: LG UltraFine 27UK650
    Resolution: 3840 x 2160 @ 60 Hz
    Connector Type: Thunderbolt 3
    Pixel Pitch: 0.156 mm
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "defaults read" in cmd_str and "AppleDisplayBrightness" in cmd_str:
            return _make_subprocess_result('brightness = "0.75";\n', returncode=0)
        return _make_subprocess_result()
    return fake_run


def _fake_run_night_shift_enabled():
    """Night Shift is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                """Graphics/Displays:

    Apple M2:
      Cores: 8
      GPU Memory: Dynamic

    Display Name: Built-in Retina Display
    Resolution: 2560 x 1600 @ 120 Hz
    Connector Type: Internal
    Pixel Pitch: 0.125 mm
"""
            )
        elif "defaults read" in cmd_str and "CoreBrightness" in cmd_str:
            return _make_subprocess_result(
                """{
    BlueReductionEnabled = 1;
    Schedule = {
        DayStartHour = 22;
        Enabled = 1;
    };
}""",
                returncode=0,
            )
        elif "defaults read" in cmd_str and "AppleDisplayBrightness" in cmd_str:
            return _make_subprocess_result('brightness = "0.75";\n', returncode=0)
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_display_info():
    """No display info available"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result("")
        elif "defaults read" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_display_config_discovered():
    mod = _get_module()
    assert mod.name == "display_config"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_display_config_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have findings (at least display_list)
    assert result.has_issues
    # Should find the built-in display
    assert any(f.data.get("check") == "display_list" for f in result.findings)


def test_display_config_scaled_resolution():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_resolution()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "scaled_resolution" for f in result.findings)
    # Should warn about scaled resolution
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("check") == "scaled_resolution"
        for f in result.findings
    )


def test_display_config_external_display():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_external_display()):
        result = mod.check(_make_profile())
    assert result.has_issues
    display_finding = next(
        (f for f in result.findings if f.data.get("check") == "display_list"),
        None,
    )
    assert display_finding is not None
    # Should detect 2 displays
    assert display_finding.data.get("count") == 2
    displays = display_finding.data.get("displays", [])
    assert len(displays) == 2
    assert any("LG" in d.get("name", "") for d in displays)


def test_display_config_night_shift_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_night_shift_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "night_shift" for f in result.findings)


def test_display_config_no_display_info():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_display_info()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_display_info" for f in result.findings)


def test_display_config_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scaled_resolution()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
