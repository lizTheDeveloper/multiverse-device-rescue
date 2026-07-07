import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(ram_bytes=16 * 1024**3):
    """Create a test system profile with configurable RAM."""
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=ram_bytes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_visual_effects")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_best_appearance_high_ram():
    """Best Appearance on high RAM system - should be INFO only"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "VisualEffects" in cmd_str and "VisualFXSetting" in cmd_str:
            # Best Appearance = 0x3
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\n"
                "    VisualFXSetting    REG_DWORD    0x3\n"
            )
        elif "Personalize" in cmd_str and "EnableTransparency" in cmd_str:
            # Transparency enabled = 0x1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\n"
                "    EnableTransparency    REG_DWORD    0x1\n"
            )
        elif "WindowMetrics" in cmd_str and "MinAnimate" in cmd_str:
            # Animations enabled = 1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics\n"
                "    MinAnimate    REG_SZ    1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_best_appearance_low_ram():
    """Best Appearance on low RAM system - should flag WARNING"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "VisualEffects" in cmd_str and "VisualFXSetting" in cmd_str:
            # Best Appearance = 0x3
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\n"
                "    VisualFXSetting    REG_DWORD    0x3\n"
            )
        elif "Personalize" in cmd_str and "EnableTransparency" in cmd_str:
            # Transparency disabled = 0x0
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\n"
                "    EnableTransparency    REG_DWORD    0x0\n"
            )
        elif "WindowMetrics" in cmd_str and "MinAnimate" in cmd_str:
            # Animations enabled = 1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics\n"
                "    MinAnimate    REG_SZ    1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_best_performance():
    """Best Performance (optimized) on low RAM"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "VisualEffects" in cmd_str and "VisualFXSetting" in cmd_str:
            # Best Performance = 0x0
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\n"
                "    VisualFXSetting    REG_DWORD    0x0\n"
            )
        elif "Personalize" in cmd_str and "EnableTransparency" in cmd_str:
            # Transparency disabled = 0x0
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\n"
                "    EnableTransparency    REG_DWORD    0x0\n"
            )
        elif "WindowMetrics" in cmd_str and "MinAnimate" in cmd_str:
            # Animations disabled = 0
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics\n"
                "    MinAnimate    REG_SZ    0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_transparency_low_ram():
    """Transparency enabled on low RAM system"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "VisualEffects" in cmd_str and "VisualFXSetting" in cmd_str:
            # Custom = 0x1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\n"
                "    VisualFXSetting    REG_DWORD    0x1\n"
            )
        elif "Personalize" in cmd_str and "EnableTransparency" in cmd_str:
            # Transparency enabled = 0x1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\n"
                "    EnableTransparency    REG_DWORD    0x1\n"
            )
        elif "WindowMetrics" in cmd_str and "MinAnimate" in cmd_str:
            # Animations enabled = 1
            return _make_subprocess_result(
                "HKEY_CURRENT_USER\\Control Panel\\Desktop\\WindowMetrics\n"
                "    MinAnimate    REG_SZ    1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_registry_error():
    """Registry queries fail"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error accessing registry", 1)
    return fake_run


def test_win_visual_effects_discovered():
    """Module should be discoverable with correct metadata."""
    mod = _get_module()
    assert mod.name == "win_visual_effects"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_visual_effects_best_appearance_high_ram():
    """Best Appearance on high RAM should only be INFO."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_best_appearance_high_ram()):
        result = mod.check(_make_profile(ram_bytes=16 * 1024**3))
    # Should have findings (INFO about configuration)
    assert result.has_issues
    # All findings should be INFO (no warnings on high RAM)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_visual_effects_best_appearance_low_ram():
    """Best Appearance on low RAM should trigger WARNING."""
    mod = _get_module()
    low_ram_profile = _make_profile(ram_bytes=4 * 1024**3)
    with patch("subprocess.run", side_effect=_fake_run_best_appearance_low_ram()):
        result = mod.check(low_ram_profile)
    assert result.has_issues
    # Should have warning about best appearance on low RAM
    assert any(
        f.severity == Severity.WARNING
        and f.data.get("issue") == "best_appearance_low_ram"
        for f in result.findings
    )


def test_win_visual_effects_best_performance():
    """Best Performance setting on low RAM should be optimal."""
    mod = _get_module()
    low_ram_profile = _make_profile(ram_bytes=4 * 1024**3)
    with patch("subprocess.run", side_effect=_fake_run_best_performance()):
        result = mod.check(low_ram_profile)
    # Configuration is reported as INFO only
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_visual_effects_transparency_low_ram():
    """Transparency on low RAM should trigger WARNING."""
    mod = _get_module()
    low_ram_profile = _make_profile(ram_bytes=6 * 1024**3)
    with patch("subprocess.run", side_effect=_fake_run_transparency_low_ram()):
        result = mod.check(low_ram_profile)
    assert result.has_issues
    # Should have warning about transparency on low RAM
    assert any(
        f.severity == Severity.WARNING
        and "Transparency" in f.title
        for f in result.findings
    )


def test_win_visual_effects_registry_error():
    """Should gracefully handle registry query errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_registry_error()):
        result = mod.check(_make_profile())
    # Should still return a result even if queries fail
    # (may have INFO findings if default values work, or no findings)
    assert isinstance(result.findings, list)


def test_win_visual_effects_fix_is_informational():
    """fix() should be informational with successful actions."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_best_appearance_low_ram()):
        check = mod.check(_make_profile(ram_bytes=4 * 1024**3))
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
    # Should have actions for warnings and config report
    assert len(fix.actions) > 0
    # All actions should be marked successful
    assert all(a.success for a in fix.actions)


def test_win_visual_effects_fix_actions_for_warnings():
    """fix() should provide actionable suggestions for warnings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_best_appearance_low_ram()):
        check = mod.check(_make_profile(ram_bytes=4 * 1024**3))
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action suggesting to reduce visual effects
    action_descriptions = [a.description for a in fix.actions]
    assert any("Best Performance" in desc or "visual effects" in desc.lower() for desc in action_descriptions)


def test_win_visual_effects_check_data_structure():
    """Check result should include structured data about settings."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_best_appearance_high_ram()):
        result = mod.check(_make_profile())
    # Should have findings with data about configuration
    config_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(config_findings) > 0
    # Data should include setting, transparency, animations, ram_gb
    data = config_findings[0].data
    assert "setting" in data
    assert "transparency" in data
    assert "animations" in data
    assert "ram_gb" in data
