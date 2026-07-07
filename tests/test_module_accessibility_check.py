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
    return next(m for m in modules if m.name == "accessibility_check")


def _fake_defaults_run(
    zoom_enabled=False,
    voiceover_enabled=False,
    reduce_motion=False,
    increase_contrast=False,
    sticky_keys=False,
    slow_keys=False,
    font_smoothing=None,
    mouse_tracking_speed=None,
    trackpad_double_click=None,
    mouse_double_click=None,
    error=None,
):
    """Mock subprocess.run for defaults read calls."""

    def fake_run(cmd, **kwargs):
        if error:
            raise error

        result = MagicMock()
        result.returncode = 0

        # Handle defaults read commands
        if len(cmd) >= 3 and cmd[0] == "defaults" and cmd[1] == "read":
            if cmd[2] == "com.apple.universalaccess":
                if len(cmd) > 3:
                    key = cmd[3]
                    if key == "closeViewScaleMode":
                        result.stdout = "1" if zoom_enabled else "0"
                    elif key == "voiceOverOnOffKey":
                        result.stdout = "1" if voiceover_enabled else "0"
                    elif key == "reduceMotionEnabled":
                        result.stdout = "1" if reduce_motion else "0"
                    elif key == "increaseContrast":
                        result.stdout = "1" if increase_contrast else "0"
                    elif key == "stickyKeys":
                        result.stdout = "1" if sticky_keys else "0"
                    elif key == "slowKeys":
                        result.stdout = "1" if slow_keys else "0"
                    else:
                        result.returncode = 1
                        result.stdout = ""
            elif cmd[2] == "-g":
                if len(cmd) > 3:
                    key = cmd[3]
                    if key == "AppleFontSmoothing":
                        if font_smoothing is not None:
                            result.stdout = str(font_smoothing)
                        else:
                            result.returncode = 1
                            result.stdout = ""
                    elif key == "com.apple.trackpad.scaling":
                        if mouse_tracking_speed is not None:
                            result.stdout = str(mouse_tracking_speed)
                        else:
                            result.returncode = 1
                            result.stdout = ""
                    elif key == "com.apple.trackpad.doubleClickThreshold":
                        if trackpad_double_click is not None:
                            result.stdout = str(trackpad_double_click)
                        else:
                            result.returncode = 1
                            result.stdout = ""
                    elif key == "com.apple.mouse.doubleClickThreshold":
                        if mouse_double_click is not None:
                            result.stdout = str(mouse_double_click)
                        else:
                            result.returncode = 1
                            result.stdout = ""
                    else:
                        result.returncode = 1
                        result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
        else:
            raise AssertionError(f"unexpected command {cmd}")

        return result

    return fake_run


def test_accessibility_check_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "accessibility_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_accessibility_check_all_disabled():
    """Test when all accessibility features are disabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run()):
        result = mod.check(_make_profile())

    # Should have INFO findings about current settings and suggestions
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0

    # Should suggest enabling features
    titles = [f.title for f in info_findings]
    assert any("Accessibility settings summary" in t for t in titles)


def test_accessibility_check_zoom_enabled():
    """Test when Display Zoom is enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(zoom_enabled=True)
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    # Should still report settings and suggest other features
    assert any("summary" in f.title.lower() for f in info_findings)


def test_accessibility_check_voiceover_enabled():
    """Test when VoiceOver is enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(voiceover_enabled=True)
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("summary" in f.title.lower() for f in info_findings)


def test_accessibility_check_reduce_motion_enabled():
    """Test when Reduce Motion is enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(reduce_motion=True)
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_accessibility_check_increase_contrast_enabled():
    """Test when Increase Contrast is enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(increase_contrast=True)
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_accessibility_check_with_font_smoothing():
    """Test with font smoothing value."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(font_smoothing=2)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should report font smoothing value
    all_descriptions = "\n".join(f.description for f in result.findings)
    assert "Font Smoothing" in all_descriptions


def test_accessibility_check_with_mouse_tracking_speed():
    """Test with mouse tracking speed value."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(mouse_tracking_speed=2)
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    all_descriptions = "\n".join(f.description for f in result.findings)
    assert "Mouse Tracking Speed" in all_descriptions


def test_accessibility_check_with_double_click_speeds():
    """Test with double-click speed values."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_defaults_run(
            trackpad_double_click=600, mouse_double_click=600
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    all_descriptions = "\n".join(f.description for f in result.findings)
    assert "Double-click" in all_descriptions


def test_accessibility_check_subprocess_error():
    """Test graceful handling of defaults errors."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(error=OSError("not found"))
    ):
        result = mod.check(_make_profile())

    # Should not crash, should report default values (False/None)
    assert result.has_issues


def test_accessibility_check_all_enabled():
    """Test when most accessibility features are enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_defaults_run(
            zoom_enabled=True,
            voiceover_enabled=True,
            reduce_motion=True,
            increase_contrast=True,
            sticky_keys=True,
            slow_keys=True,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    # Should report summary
    assert any("summary" in f.title.lower() for f in info_findings)


def test_accessibility_check_fix_is_informational():
    """Test that fix() is informational and doesn't modify system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed but only provide guidance
    assert fix.all_succeeded
    for action in fix.actions:
        # Actions should be informational, suggesting settings
        assert (
            "settings" in action.title.lower()
            or "consider" in action.title.lower()
        )
