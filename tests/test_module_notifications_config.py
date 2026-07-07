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
    return next(m for m in modules if m.name == "notifications_config")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_notifications_healthy():
    """Normal case: notifications enabled, DND not on, no privacy issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "NSStatusItem Visible FocusModes" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "com.apple.ncprefs" in cmd_str and "doNotDisturb" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "com.apple.ncprefs" in cmd_str and "enabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "show_in_lockscreen" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "com.apple.ncprefs" in cmd_str and "lockScreenNotifications" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_dnd_permanent():
    """Do Not Disturb is permanently enabled (no schedule)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "NSStatusItem Visible FocusModes" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "doNotDisturb" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "enabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "focusSchedules" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "com.apple.ncprefs" in cmd_str and "show_in_lockscreen" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "com.apple.ncprefs" in cmd_str and "lockScreenNotifications" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_dnd_scheduled():
    """Do Not Disturb enabled with schedule"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "NSStatusItem Visible FocusModes" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "doNotDisturb" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "enabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "focusSchedules" in cmd_str:
            return _make_subprocess_result(stdout="<schedule data>\n")
        elif "com.apple.ncprefs" in cmd_str and "show_in_lockscreen" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "com.apple.ncprefs" in cmd_str and "lockScreenNotifications" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_preview_on_lock():
    """Notification previews visible on lock screen"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "NSStatusItem Visible FocusModes" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "com.apple.ncprefs" in cmd_str and "doNotDisturb" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        elif "com.apple.ncprefs" in cmd_str and "enabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "show_in_lockscreen" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "lockScreenNotifications" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()
    return fake_run


def test_notifications_config_discovered():
    mod = _get_module()
    assert mod.name == "notifications_config"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_notifications_config_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_notifications_healthy()):
        result = mod.check(_make_profile())
    # Should have INFO findings about configuration, but no warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_notifications_config_dnd_permanent():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dnd_permanent()):
        result = mod.check(_make_profile())
    # Should have WARNING about permanent DND
    assert any(
        f.data.get("check") == "warning_dnd_enabled"
        and f.severity == Severity.WARNING
        for f in result.findings
    )


def test_notifications_config_dnd_scheduled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dnd_scheduled()):
        result = mod.check(_make_profile())
    # Should NOT have warning about permanent DND (it has schedule)
    assert not any(f.data.get("check") == "warning_dnd_enabled" for f in result.findings)


def test_notifications_config_preview_on_lock():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_preview_on_lock()):
        result = mod.check(_make_profile())
    # Should have WARNING about previews on lock screen
    assert any(
        f.data.get("check") == "warning_preview_on_lock"
        and f.severity == Severity.WARNING
        for f in result.findings
    )


def test_notifications_config_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dnd_permanent()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) > 0


def test_notifications_config_multiple_warnings():
    mod = _get_module()
    def fake_run_both_warnings(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "NSStatusItem Visible FocusModes" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "doNotDisturb" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "enabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "focusSchedules" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        elif "com.apple.ncprefs" in cmd_str and "show_in_lockscreen" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "com.apple.ncprefs" in cmd_str and "lockScreenNotifications" in cmd_str:
            return _make_subprocess_result(stdout="0\n")
        return _make_subprocess_result()

    with patch("subprocess.run", side_effect=fake_run_both_warnings):
        result = mod.check(_make_profile())
    # Should have both warnings
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) >= 2
    assert any(f.data.get("check") == "warning_dnd_enabled" for f in warnings)
    assert any(f.data.get("check") == "warning_preview_on_lock" for f in warnings)
