import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_power_plan")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_power_saver_active():
    """Power Saver plan is active"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f (Power Saver)"
            )
        elif "list" in cmd_str:
            return _make_subprocess_result(
                "Existing Power Schemes (* Active)\n"
                "-----------------------------------\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)\n"
                "Power Scheme GUID: 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f  (Power Saver)*\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2f  (High Performance)\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_balanced_active():
    """Balanced plan is active"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)"
            )
        elif "list" in cmd_str:
            return _make_subprocess_result(
                "Existing Power Schemes (* Active)\n"
                "-----------------------------------\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)*\n"
                "Power Scheme GUID: 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f  (Power Saver)\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2f  (High Performance)\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_high_performance_active():
    """High Performance plan is active"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2f (High Performance)"
            )
        elif "list" in cmd_str:
            return _make_subprocess_result(
                "Existing Power Schemes (* Active)\n"
                "-----------------------------------\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)\n"
                "Power Scheme GUID: 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f  (Power Saver)\n"
                "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2f  (High Performance)*\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_command_fails():
    """powercfg command fails"""
    def fake_run(cmd, **kwargs):
        raise OSError("Command failed")

    return fake_run


def test_win_power_plan_discovered():
    mod = _get_module()
    assert mod.name == "win_power_plan"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_power_plan_power_saver_active():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_active()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for power saver
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("type") == "power_saver_active" for f in result.findings)
    # Should also have INFO for active plan
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_power_plan_balanced_active():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_balanced_active()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO for active plan
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should have INFO for optimal plan
    assert any(f.data.get("type") == "optimal_plan" for f in result.findings)
    # Should NOT have WARNING
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_power_plan_high_performance_active():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_performance_active()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO for active plan
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should have INFO for optimal plan
    assert any(f.data.get("type") == "optimal_plan" for f in result.findings)
    # Should NOT have WARNING
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_power_plan_command_fails():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_fails()):
        result = mod.check(_make_profile())
    # Should not crash, just return empty findings
    assert not result.has_issues


def test_win_power_plan_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_active()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_power_plan_fix_includes_switch_advice():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_active()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action to switch from Power Saver
    assert any(a.title == "Switch from Power Saver mode" for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_win_power_plan_fix_balanced_advice():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_balanced_active()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have informational actions
    assert all(a.success for a in fix.actions)
    # Should confirm current plan and optimal status
    assert len(fix.actions) > 0
