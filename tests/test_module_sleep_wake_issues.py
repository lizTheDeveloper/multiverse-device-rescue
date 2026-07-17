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
    return next(m for m in modules if m.name == "sleep_wake_issues")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no sleep issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g log" in cmd_str:
            return _make_subprocess_result(
                "2024-01-15 09:30:45 +0000  Wake from Normal Sleep due to LID OPEN\n"
                "2024-01-15 09:25:00 +0000  Wake from Normal Sleep due to KEYBOARD\n"
            )
        elif "pmset" in cmd_str and "-g assertions" in cmd_str:
            return _make_subprocess_result(
                "No assertions currently held\n"
            )
        elif "pmset" in cmd_str and "-g sched" in cmd_str:
            return _make_subprocess_result("")
        elif "defaults read" in cmd_str and "com.apple.Bluetooth" in cmd_str:
            # Bluetooth wake disabled - has BTPowerController = false
            return _make_subprocess_result(
                stdout="{\n    BTPowerController = 0;\n}\n",
                returncode=0
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_darkwake_issues():
    """Multiple DarkWake events"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g log" in cmd_str:
            darkwake_log = "\n".join([
                f"2024-01-15 {i:02d}:30:00 +0000  DarkWake"
                for i in range(15)
            ])
            return _make_subprocess_result(darkwake_log)
        elif "pmset" in cmd_str and "-g assertions" in cmd_str:
            return _make_subprocess_result(
                "No assertions currently held\n"
            )
        elif "pmset" in cmd_str and "-g sched" in cmd_str:
            return _make_subprocess_result("")
        elif "defaults read" in cmd_str and "com.apple.Bluetooth" in cmd_str:
            return _make_subprocess_result(stdout="{\n    BTPowerController = 0;\n}\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_bluetooth_wake():
    """Bluetooth wake enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g log" in cmd_str:
            return _make_subprocess_result(
                "2024-01-15 09:30:45 +0000  Wake from Normal Sleep due to LID OPEN\n"
            )
        elif "pmset" in cmd_str and "-g assertions" in cmd_str:
            return _make_subprocess_result(
                "No assertions currently held\n"
            )
        elif "pmset" in cmd_str and "-g sched" in cmd_str:
            return _make_subprocess_result("")
        elif "defaults read" in cmd_str and "com.apple.Bluetooth" in cmd_str:
            # Return empty to simulate Bluetooth wake enabled (default)
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_scheduled_events():
    """Scheduled wake events"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g log" in cmd_str:
            return _make_subprocess_result(
                "2024-01-15 09:30:45 +0000  Wake from Normal Sleep due to ALARM\n"
            )
        elif "pmset" in cmd_str and "-g assertions" in cmd_str:
            return _make_subprocess_result(
                "No assertions currently held\n"
            )
        elif "pmset" in cmd_str and "-g sched" in cmd_str:
            return _make_subprocess_result(
                "repeat alarm weekdays 7:00:00 wake 1\n"
                "repeat alarm weekdays 6:00:00 sleep 1\n"
            )
        elif "defaults read" in cmd_str and "com.apple.Bluetooth" in cmd_str:
            return _make_subprocess_result(stdout="{\n    BTPowerController = 0;\n}\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_assertions():
    """Active sleep prevention assertions"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g log" in cmd_str:
            return _make_subprocess_result(
                "2024-01-15 09:30:45 +0000  Wake from Normal Sleep due to KEYBOARD\n"
            )
        elif "pmset" in cmd_str and "-g assertions" in cmd_str:
            return _make_subprocess_result(
                "Assertion status system-wide:\n"
                "   PreventSystemSleep 1\n"
                "   PreventUserIdleDisplaySleep 1\n"
            )
        elif "pmset" in cmd_str and "-g sched" in cmd_str:
            return _make_subprocess_result("")
        elif "defaults read" in cmd_str and "com.apple.Bluetooth" in cmd_str:
            return _make_subprocess_result(stdout="{\n    BTPowerController = 0;\n}\n")
        return _make_subprocess_result()
    return fake_run


def test_sleep_wake_issues_discovered():
    mod = _get_module()
    assert mod.name == "sleep_wake_issues"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_sleep_wake_issues_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Healthy system may still report INFO findings (wake reasons)
    # but no WARNING or CRITICAL issues
    assert not any(f.severity == Severity.WARNING for f in result.findings)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_sleep_wake_issues_darkwake():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_darkwake_issues()):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "darkwake_events" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_sleep_wake_issues_bluetooth_wake():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bluetooth_wake()):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "bluetooth_wake" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_sleep_wake_issues_scheduled_events():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_scheduled_events()):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "scheduled_events" for f in result.findings)


def test_sleep_wake_issues_assertions():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_assertions()):
        result = mod.check(_make_profile())
    assert any(f.data.get("check") == "assertions" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_sleep_wake_issues_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_darkwake_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
