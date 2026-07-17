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
    return next(m for m in modules if m.name == "win_autorun")


def _fake_reg_query_run(autorun_value=None, autoplay_value=None):
    """Create a fake subprocess.run function for reg query commands."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        # Check if it's a reg query command
        if len(cmd) >= 3 and cmd[0] == "reg" and cmd[1] == "query":
            # cmd format: ["reg", "query", "HKLM\...", "/v", "ValueName"]
            if len(cmd) >= 5:
                hive_path = cmd[2]
                value_name = cmd[4]

                if "NoDriveTypeAutoRun" in value_name and autorun_value is not None:
                    result.stdout = f"    {value_name}    REG_DWORD    {autorun_value}\n"
                elif "DisableAutoplay" in value_name and autoplay_value is not None:
                    result.stdout = f"    {value_name}    REG_DWORD    {autoplay_value}\n"
                else:
                    # Simulate key not found
                    result.returncode = 1
                    result.stderr = "Error: The system was unable to find the specified registry key or value."

        return result

    return fake_run


def test_win_autorun_discovered():
    """Test that the module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "win_autorun"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_autorun_healthy():
    """Test when both AutoRun and AutoPlay are properly disabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0x91",
        autoplay_value="1"
    )):
        result = mod.check(_make_profile())

    # Should have 2 INFO findings (one for each setting being properly configured)
    assert result.has_issues
    assert len(result.findings) == 2
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_autorun_enabled_for_removable_drives():
    """Test WARNING when AutoRun is enabled for removable drives."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0",
        autoplay_value="1"
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have 1 WARNING (AutoRun enabled) + 1 INFO (AutoPlay disabled)
    assert len(result.findings) == 2
    autorun_findings = [f for f in result.findings if "AutoRun is enabled" in f.title]
    assert len(autorun_findings) == 1
    assert autorun_findings[0].severity == Severity.WARNING


def test_win_autorun_not_found():
    """Test when AutoRun registry value is not set (defaults to enabled)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value=None,
        autoplay_value="1"
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have 1 WARNING (AutoRun not found = enabled by default) + 1 INFO
    autorun_findings = [f for f in result.findings if "AutoRun is enabled" in f.title]
    assert len(autorun_findings) == 1
    assert autorun_findings[0].severity == Severity.WARNING


def test_win_autoplay_enabled():
    """Test WARNING when AutoPlay is enabled for removable media."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0x91",
        autoplay_value="0"
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have 1 INFO (AutoRun disabled) + 1 WARNING (AutoPlay enabled)
    assert len(result.findings) == 2
    autoplay_findings = [f for f in result.findings if "AutoPlay is enabled" in f.title]
    assert len(autoplay_findings) == 1
    assert autoplay_findings[0].severity == Severity.WARNING


def test_win_autoplay_not_found():
    """Test WARNING when AutoPlay registry value is not set (defaults to enabled)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0x91",
        autoplay_value=None
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have 1 INFO (AutoRun disabled) + 1 WARNING (AutoPlay not found = enabled)
    autoplay_findings = [f for f in result.findings if "AutoPlay is enabled" in f.title]
    assert len(autoplay_findings) == 1
    assert autoplay_findings[0].severity == Severity.WARNING


def test_win_autorun_both_enabled():
    """Test multiple WARNINGs when both AutoRun and AutoPlay are enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0",
        autoplay_value="0"
    )):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 2
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 2


def test_win_autorun_fix_provides_guidance():
    """Test that fix provides informational guidance without modifying system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0",
        autoplay_value="0"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have 2 actions (one for each warning)
    assert len(fix.actions) == 2
    # Both should be successful (informational only)
    assert fix.all_succeeded
    # Actions should contain guidance text
    assert any("Group Policy" in a.description for a in fix.actions)
    assert any("Settings" in a.description for a in fix.actions)


def test_win_autorun_fix_autorun_only():
    """Test fix when only AutoRun needs attention."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0",
        autoplay_value="1"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have 1 action (only AutoRun enabled)
    assert len(fix.actions) == 1
    assert "AutoRun" in fix.actions[0].title
    assert fix.all_succeeded


def test_win_autorun_fix_autoplay_only():
    """Test fix when only AutoPlay needs attention."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_reg_query_run(
        autorun_value="0x91",
        autoplay_value="0"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have 1 action (only AutoPlay enabled)
    assert len(fix.actions) == 1
    assert "AutoPlay" in fix.actions[0].title
    assert fix.all_succeeded
