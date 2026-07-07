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
        ram_bytes=8 * 1024**3,  # 8 GB
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "thermal_throttle")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no thermal throttling, CPU at full speed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "therm" in cmd_str:
            return _make_subprocess_result(
                "Thermal state: Normal\n"
            )
        elif "hw.cpufrequency" in cmd_str and "max" in cmd_str:
            # 3.2 GHz max
            return _make_subprocess_result(
                "hw.cpufrequency_max: 3200000000\n"
            )
        elif "hw.cpufrequency" in cmd_str:
            # 3.2 GHz current (at max)
            return _make_subprocess_result(
                "hw.cpufrequency: 3200000000\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_throttling():
    """Warning: CPU is being thermally throttled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "therm" in cmd_str:
            return _make_subprocess_result(
                "Thermal state: Throttled\n"
            )
        elif "hw.cpufrequency" in cmd_str and "max" in cmd_str:
            # 3.2 GHz max
            return _make_subprocess_result(
                "hw.cpufrequency_max: 3200000000\n"
            )
        elif "hw.cpufrequency" in cmd_str:
            # 1.6 GHz current (50% of max due to throttling)
            return _make_subprocess_result(
                "hw.cpufrequency: 1600000000\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_critical_throttling():
    """Critical: CPU is being severely thermally throttled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "therm" in cmd_str:
            return _make_subprocess_result(
                "Thermal state: Critical\n"
            )
        elif "hw.cpufrequency" in cmd_str and "max" in cmd_str:
            # 3.2 GHz max
            return _make_subprocess_result(
                "hw.cpufrequency_max: 3200000000\n"
            )
        elif "hw.cpufrequency" in cmd_str:
            # 800 MHz current (25% of max due to critical throttling)
            return _make_subprocess_result(
                "hw.cpufrequency: 800000000\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_reduced_frequency():
    """Warning: CPU running at 80% of max but not actively throttling"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "therm" in cmd_str:
            return _make_subprocess_result(
                "Thermal state: Normal\n"
            )
        elif "hw.cpufrequency" in cmd_str and "max" in cmd_str:
            # 3.2 GHz max
            return _make_subprocess_result(
                "hw.cpufrequency_max: 3200000000\n"
            )
        elif "hw.cpufrequency" in cmd_str:
            # 2.56 GHz current (80% of max)
            return _make_subprocess_result(
                "hw.cpufrequency: 2560000000\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_pmset():
    """Fallback when pmset is not available"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "therm" in cmd_str:
            # pmset command fails
            return _make_subprocess_result(returncode=1)
        elif "hw.cpufrequency" in cmd_str and "max" in cmd_str:
            return _make_subprocess_result(
                "hw.cpufrequency_max: 3200000000\n"
            )
        elif "hw.cpufrequency" in cmd_str:
            return _make_subprocess_result(
                "hw.cpufrequency: 3200000000\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_thermal_throttle_module_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "thermal_throttle" in names


def test_thermal_throttle_module_metadata():
    mod = _get_module()
    assert mod.name == "thermal_throttle"
    assert mod.category == "performance"
    assert mod.platforms == [Platform.DARWIN]
    assert mod.risk_level == RiskLevel.SAFE


def test_thermal_throttle_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO findings but no warnings
    assert result.has_issues
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_thermal_throttle_active_throttling():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_throttling()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("throttl" in f.title.lower() for f in result.findings)


def test_thermal_throttle_critical_throttling():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_critical_throttling()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_thermal_throttle_reduced_frequency():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_reduced_frequency()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for low frequency + INFO for status
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("frequency" in f.title.lower() for f in result.findings)


def test_thermal_throttle_no_pmset():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_pmset()):
        result = mod.check(_make_profile())
    # Should handle gracefully even if pmset is unavailable
    assert isinstance(result.findings, list)


def test_thermal_throttle_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_throttling()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for any finding
    if check.has_issues:
        assert len(fix.actions) > 0


def test_thermal_throttle_fix_for_active_throttling():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_throttling()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    # Should have actions addressing throttling
    throttle_actions = [a for a in fix.actions if "throttl" in a.title.lower()]
    assert len(throttle_actions) > 0


def test_thermal_throttle_report():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_throttling()):
        check = mod.check(_make_profile())
        report = mod.report(check)
    assert "thermal_throttle" in report
