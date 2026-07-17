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
    return next(m for m in modules if m.name == "win_power_plan_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_balanced_optimal():
    """Balanced plan, good settings"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)"
            )
        elif "PROCTHROTTLEMAX" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x64 (100)\n"
                "Current Battery Power Setting Index: 0x64 (100)"
            )
        elif "DISKIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x4b0 (1200)\n"
                "Current Battery Power Setting Index: 0x258 (600)"
            )
        elif "STANDBYIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x708 (1800)\n"
                "Current Battery Power Setting Index: 0x3c (60)"
            )
        elif "2a737441-1930-4402-8d77-b2bebba308a3" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x1 (1)\n"
                "Current Battery Power Setting Index: 0x1 (1)"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_power_saver_throttled():
    """Power Saver plan with throttling and short disk timeout"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f (Power Saver)"
            )
        elif "PROCTHROTTLEMAX" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x50 (80)\n"
                "Current Battery Power Setting Index: 0x32 (50)"
            )
        elif "DISKIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0xb4 (180)\n"
                "Current Battery Power Setting Index: 0x78 (120)"
            )
        elif "STANDBYIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x258 (600)\n"
                "Current Battery Power Setting Index: 0x78 (120)"
            )
        elif "2a737441-1930-4402-8d77-b2bebba308a3" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x1 (1)\n"
                "Current Battery Power Setting Index: 0x1 (1)"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_high_performance():
    """High Performance plan"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "getactivescheme" in cmd_str:
            return _make_subprocess_result(
                "Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2f (High Performance)"
            )
        elif "PROCTHROTTLEMAX" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x64 (100)\n"
                "Current Battery Power Setting Index: 0x64 (100)"
            )
        elif "DISKIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x0 (0)\n"
                "Current Battery Power Setting Index: 0x0 (0)"
            )
        elif "STANDBYIDLE" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x0 (0)\n"
                "Current Battery Power Setting Index: 0x0 (0)"
            )
        elif "2a737441-1930-4402-8d77-b2bebba308a3" in cmd_str:
            return _make_subprocess_result(
                "Current AC Power Setting Index: 0x0 (0)\n"
                "Current Battery Power Setting Index: 0x0 (0)"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_command_fails():
    """powercfg command fails"""
    def fake_run(cmd, **kwargs):
        raise OSError("Command failed")

    return fake_run


def test_win_power_plan_check_discovered():
    """Module is properly discovered and has correct metadata"""
    mod = _get_module()
    assert mod.name == "win_power_plan_check"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_power_plan_check_balanced_optimal():
    """Balanced plan with optimal settings"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_balanced_optimal()):
        result = mod.check(_make_profile())

    # Should have findings (informational)
    assert result.has_issues

    # Should report active plan
    assert any(f.data.get("type") == "active_plan" for f in result.findings)

    # Should report processor max state
    assert any(f.data.get("type") == "processor_max" for f in result.findings)

    # Should report disk timeout
    assert any(f.data.get("type") == "disk_timeout" for f in result.findings)

    # Should report sleep timeout
    assert any(f.data.get("type") == "sleep_timeout" for f in result.findings)

    # Should report USB selective suspend
    assert any(f.data.get("type") == "usb_selective_suspend" for f in result.findings)

    # Should NOT have warnings (all good settings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)

    # Should have INFO findings only
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_win_power_plan_check_power_saver_active():
    """Power Saver plan is active (WARNING)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should have WARNING for Power Saver
    assert any(f.severity == Severity.WARNING and f.data.get("type") == "power_saver_active" for f in result.findings)


def test_win_power_plan_check_processor_throttled():
    """Processor is throttled to less than 100%"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should have WARNING for processor throttling
    assert any(f.severity == Severity.WARNING and f.data.get("type") == "processor_limited" for f in result.findings)

    # Check that processor max state is reported
    processor_max = next(
        (f for f in result.findings if f.data.get("type") == "processor_max"),
        None,
    )
    assert processor_max is not None
    assert processor_max.data.get("value") == 80


def test_win_power_plan_check_disk_timeout_short():
    """Hard disk timeout is too short"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should have WARNING for short disk timeout
    assert any(f.severity == Severity.WARNING and f.data.get("type") == "disk_timeout_short" for f in result.findings)

    # Check disk timeout value
    disk_timeout = next(
        (f for f in result.findings if f.data.get("type") == "disk_timeout"),
        None,
    )
    assert disk_timeout is not None
    assert disk_timeout.data.get("seconds") == 180


def test_win_power_plan_check_high_performance():
    """High Performance plan with no sleep/disk timeout"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_performance()):
        result = mod.check(_make_profile())

    assert result.has_issues

    # Should report active plan
    assert any(f.data.get("type") == "active_plan" for f in result.findings)

    # Should report processor at 100%
    processor_max = next(
        (f for f in result.findings if f.data.get("type") == "processor_max"),
        None,
    )
    assert processor_max is not None
    assert processor_max.data.get("value") == 100

    # Should report disk timeout as 0 (never)
    disk_timeout = next(
        (f for f in result.findings if f.data.get("type") == "disk_timeout"),
        None,
    )
    assert disk_timeout is not None
    assert disk_timeout.data.get("seconds") == 0

    # Should NOT have warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_win_power_plan_check_command_fails():
    """powercfg command fails gracefully"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_fails()):
        result = mod.check(_make_profile())

    # Should not crash, just return empty findings
    assert not result.has_issues


def test_win_power_plan_check_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed
    assert fix.all_succeeded

    # Should have actions for findings
    assert len(fix.actions) > 0


def test_win_power_plan_check_fix_power_saver_advice():
    """fix() provides advice for Power Saver mode"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action to switch from Power Saver
    assert any(a.title == "Switch from Power Saver mode" for a in fix.actions)

    # Action should succeed and be SAFE
    power_saver_action = next(
        (a for a in fix.actions if a.title == "Switch from Power Saver mode"),
        None,
    )
    assert power_saver_action is not None
    assert power_saver_action.success
    assert power_saver_action.risk_level == RiskLevel.SAFE


def test_win_power_plan_check_fix_processor_throttle_advice():
    """fix() provides advice for processor throttling"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action about processor state
    assert any(
        a.title == "Increase maximum processor state to 100%"
        for a in fix.actions
    )


def test_win_power_plan_check_fix_disk_timeout_advice():
    """fix() provides advice for short disk timeout"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_power_saver_throttled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have action about disk timeout
    assert any(
        a.title == "Increase hard disk idle timeout"
        for a in fix.actions
    )


def test_win_power_plan_check_fix_balanced_optimal():
    """fix() with optimal settings still provides informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_balanced_optimal()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should succeed with informational messages
    assert fix.all_succeeded

    # Should have actions (informational)
    assert len(fix.actions) > 0

    # All actions should succeed
    assert all(a.success for a in fix.actions)
