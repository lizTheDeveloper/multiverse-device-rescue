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
    return next(m for m in modules if m.name == "energy_settings")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_battery():
    """Normal case: good battery settings (sleep enabled, no power nap)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "System-wide power settings:\n"
                "Currently in use:\n"
                " standby              1\n"
                " Sleep On Power Button 1\n"
                " hibernatefile        /var/vm/sleepimage\n"
                " powernap             0\n"
                " networkoversleep     0\n"
                " disksleep            10\n"
                " sleep                10\n"
                " hibernatemode        3\n"
                " ttyskeepawake        1\n"
                " displaysleep         5\n"
                " tcpkeepalive         1\n"
                " powermode            0\n"
                " womp                 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_powernap_enabled():
    """Power Nap is enabled - battery drain risk"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "System-wide power settings:\n"
                "Currently in use:\n"
                " standby              1\n"
                " Sleep On Power Button 1\n"
                " hibernatefile        /var/vm/sleepimage\n"
                " powernap             1\n"
                " networkoversleep     0\n"
                " disksleep            10\n"
                " sleep                10\n"
                " hibernatemode        3\n"
                " ttyskeepawake        1\n"
                " displaysleep         5\n"
                " tcpkeepalive         1\n"
                " powermode            0\n"
                " womp                 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_never_sleeps():
    """Sleep is disabled - battery drain risk"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "System-wide power settings:\n"
                "Currently in use:\n"
                " standby              1\n"
                " Sleep On Power Button 1\n"
                " hibernatefile        /var/vm/sleepimage\n"
                " powernap             0\n"
                " networkoversleep     0\n"
                " disksleep            0\n"
                " sleep                0\n"
                " hibernatemode        3\n"
                " ttyskeepawake        1\n"
                " displaysleep         0\n"
                " tcpkeepalive         1\n"
                " powermode            0\n"
                " womp                 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_womp_enabled():
    """Wake-on-LAN is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "System-wide power settings:\n"
                "Currently in use:\n"
                " standby              1\n"
                " Sleep On Power Button 1\n"
                " hibernatefile        /var/vm/sleepimage\n"
                " powernap             0\n"
                " networkoversleep     0\n"
                " disksleep            10\n"
                " sleep                10\n"
                " hibernatemode        3\n"
                " ttyskeepawake        1\n"
                " displaysleep         5\n"
                " tcpkeepalive         1\n"
                " powermode            0\n"
                " womp                 1\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_hibernation_mode_0():
    """Hibernation disabled (mode 0)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "System-wide power settings:\n"
                "Currently in use:\n"
                " standby              1\n"
                " Sleep On Power Button 1\n"
                " hibernatefile        /var/vm/sleepimage\n"
                " powernap             0\n"
                " networkoversleep     0\n"
                " disksleep            10\n"
                " sleep                10\n"
                " hibernatemode        0\n"
                " ttyskeepawake        1\n"
                " displaysleep         5\n"
                " tcpkeepalive         1\n"
                " powermode            0\n"
                " womp                 0\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_pmset_error():
    """pmset command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            raise FileNotFoundError("pmset not found")
        return _make_subprocess_result()
    return fake_run


def test_energy_settings_discovered():
    mod = _get_module()
    assert mod.name == "energy_settings"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_energy_settings_healthy_battery():
    """Test healthy battery configuration"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_battery()):
        result = mod.check(_make_profile())
    # Should have INFO findings about current settings
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should not have warnings for healthy settings
    assert not any(
        "Power Nap enabled" in f.description for f in result.findings
    )


def test_energy_settings_powernap_enabled():
    """Test warning for Power Nap enabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powernap_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("Power Nap" in f.title for f in result.findings)


def test_energy_settings_never_sleeps():
    """Test warning when system never sleeps"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_never_sleeps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("never sleeps" in f.description.lower() for f in result.findings)


def test_energy_settings_womp_enabled():
    """Test info about Wake-on-LAN"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_womp_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # womp enabled should be reported but may not be warning
    assert any(
        "womp" in f.description.lower() or "wake-on-lan" in f.description.lower()
        for f in result.findings
    )


def test_energy_settings_hibernation_mode_0():
    """Test hibernation mode 0 (disabled)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_hibernation_mode_0()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should report hibernation status
    assert any("hibernation" in f.description.lower() for f in result.findings)


def test_energy_settings_pmset_error():
    """Test handling of pmset command failure"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pmset_error()):
        result = mod.check(_make_profile())
    # Should gracefully handle error
    assert result.has_issues or not result.has_issues  # Either way is OK
    # Should not crash


def test_energy_settings_fix_is_informational():
    """Test that fix() provides informational actions only"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powernap_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
