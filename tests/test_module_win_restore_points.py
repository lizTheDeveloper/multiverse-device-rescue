import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "win_restore_points")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_restore_disabled():
    """System Restore is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # Return empty for disabled restore
        if "Get-ComputerRestorePoint" in cmd_str:
            return _make_subprocess_result("", "", 1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_restore_enabled_with_points():
    """System Restore is enabled with recent restore points"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-ComputerRestorePoint" in cmd_str:
            now = datetime.now()
            points = [
                {
                    "SequenceNumber": 3,
                    "CreationTime": (now - timedelta(hours=2)).isoformat() + "Z",
                    "Description": "Windows Update"
                },
                {
                    "SequenceNumber": 2,
                    "CreationTime": (now - timedelta(days=5)).isoformat() + "Z",
                    "Description": "Scheduled checkpoint"
                },
                {
                    "SequenceNumber": 1,
                    "CreationTime": (now - timedelta(days=15)).isoformat() + "Z",
                    "Description": "Manual restore point"
                }
            ]
            return _make_subprocess_result(json.dumps(points))
        return _make_subprocess_result()
    return fake_run


def _fake_run_restore_enabled_no_points():
    """System Restore is enabled but no restore points exist"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-ComputerRestorePoint" in cmd_str:
            return _make_subprocess_result("", "", 0)
        return _make_subprocess_result()
    return fake_run


def _fake_run_restore_old_points():
    """System Restore has only old restore points (>30 days)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "Get-ComputerRestorePoint" in cmd_str:
            now = datetime.now()
            points = [
                {
                    "SequenceNumber": 2,
                    "CreationTime": (now - timedelta(days=45)).isoformat() + "Z",
                    "Description": "Old checkpoint"
                },
                {
                    "SequenceNumber": 1,
                    "CreationTime": (now - timedelta(days=60)).isoformat() + "Z",
                    "Description": "Very old restore point"
                }
            ]
            return _make_subprocess_result(json.dumps(points))
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell returns error"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)
    return fake_run


def test_win_restore_points_discovered():
    mod = _get_module()
    assert mod.name == "win_restore_points"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_restore_points_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.data.get("check") == "restore_disabled" for f in result.findings)


def test_win_restore_points_enabled_with_points():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_enabled_with_points()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO for healthy restore points
    assert any(f.data.get("check") == "restore_points_available" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_restore_points_no_points():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_enabled_no_points()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_restore_points" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_restore_points_old_points():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_old_points()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "old_restore_point" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_restore_points_powershell_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should handle error gracefully
    assert result.has_issues
    assert any(f.data.get("check") == "status_check_failed" for f in result.findings)


def test_win_restore_points_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)


def test_win_restore_points_fix_disabled_restore():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action explaining how to enable restore
    assert any("Enable" in a.title or "enable" in a.description.lower()
               for a in fix.actions)


def test_win_restore_points_fix_no_points():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_enabled_no_points()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action explaining how to create restore point
    assert any("create" in a.description.lower() for a in fix.actions)


def test_win_restore_points_fix_old_points():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_restore_old_points()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action recommending to create fresh restore point
    assert any("create" in a.description.lower() or "fresh" in a.description.lower()
               for a in fix.actions)
