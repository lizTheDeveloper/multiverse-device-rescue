import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "software_inventory")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Mock subprocess for healthy app inventory (recent apps, all 64-bit)."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "system_profiler" in cmd[0]:
            apps_data = {
                "SPApplicationsDataType": [
                    {
                        "_name": "Finder",
                        "version": "15.2",
                        "lastModified": (
                            datetime.now() - timedelta(days=30)
                        ).isoformat(),
                    },
                    {
                        "_name": "Safari",
                        "version": "18.1",
                        "lastModified": (
                            datetime.now() - timedelta(days=45)
                        ).isoformat(),
                    },
                    {
                        "_name": "VS Code",
                        "version": "1.90.0",
                        "lastModified": (
                            datetime.now() - timedelta(days=60)
                        ).isoformat(),
                    },
                    {
                        "_name": "Chrome",
                        "version": "127.0.0.1",
                        "lastModified": (
                            datetime.now() - timedelta(days=20)
                        ).isoformat(),
                    },
                ]
            }
            return _make_subprocess_result(stdout=json.dumps(apps_data))
        return _make_subprocess_result()
    return fake_run


def _fake_run_old_1year():
    """Mock subprocess for apps with >1 year old apps."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "system_profiler" in cmd[0]:
            apps_data = {
                "SPApplicationsDataType": [
                    {
                        "_name": "Finder",
                        "version": "15.2",
                        "lastModified": (
                            datetime.now() - timedelta(days=30)
                        ).isoformat(),
                    },
                    {
                        "_name": "Old App",
                        "version": "1.0.0",
                        "lastModified": (
                            datetime.now() - timedelta(days=400)
                        ).isoformat(),
                    },
                    {
                        "_name": "Very Old App",
                        "version": "2.3.1",
                        "lastModified": (
                            datetime.now() - timedelta(days=800)
                        ).isoformat(),
                    },
                ]
            }
            return _make_subprocess_result(stdout=json.dumps(apps_data))
        return _make_subprocess_result()
    return fake_run


def _fake_run_32bit():
    """Mock subprocess for inventory with 32-bit apps."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "system_profiler" in cmd[0]:
            apps_data = {
                "SPApplicationsDataType": [
                    {
                        "_name": "Finder",
                        "version": "15.2",
                        "lastModified": (
                            datetime.now() - timedelta(days=30)
                        ).isoformat(),
                    },
                    {
                        "_name": "Old 32-bit App",
                        "version": "1.0.0",
                        "_is32bit": True,
                        "lastModified": (
                            datetime.now() - timedelta(days=400)
                        ).isoformat(),
                    },
                    {
                        "_name": "Another 32-bit App",
                        "version": "2.0.0",
                        "_is32bit": True,
                        "lastModified": (
                            datetime.now() - timedelta(days=200)
                        ).isoformat(),
                    },
                ]
            }
            return _make_subprocess_result(stdout=json.dumps(apps_data))
        return _make_subprocess_result()
    return fake_run


def _fake_run_empty():
    """Mock subprocess for system with no applications."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "system_profiler" in cmd[0]:
            apps_data = {"SPApplicationsDataType": []}
            return _make_subprocess_result(stdout=json.dumps(apps_data))
        return _make_subprocess_result()
    return fake_run


def _fake_run_error():
    """Mock subprocess error."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "system_profiler" in cmd[0]:
            return _make_subprocess_result(returncode=1, stderr="Error")
        return _make_subprocess_result()
    return fake_run


def test_software_inventory_discovered():
    mod = _get_module()
    assert mod.name == "software_inventory"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_software_inventory_healthy():
    """Test healthy inventory with recent apps."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should only have INFO summary finding, no warnings
    assert any(f.data.get("check") == "software_summary" for f in result.findings)
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_software_inventory_old_1year():
    """Test inventory with apps older than 1 year."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_1year()):
        result = mod.check(_make_profile())
    # Should have WARNING findings for old apps
    assert any(f.data.get("check") == "old_1year_apps" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should also have 2-year old warning
    assert any(f.data.get("check") == "old_2year_apps" for f in result.findings)


def test_software_inventory_32bit():
    """Test inventory with 32-bit applications."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_32bit()):
        result = mod.check(_make_profile())
    # Should have WARNING for 32-bit apps
    assert any(f.data.get("check") == "32bit_apps" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should have app count in data
    assert any(
        f.data.get("apps_32bit_count") == 2 for f in result.findings
    )


def test_software_inventory_empty():
    """Test inventory with no applications."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_empty()):
        result = mod.check(_make_profile())
    # Should only have summary with zero count
    assert any(f.data.get("check") == "software_summary" for f in result.findings)
    assert any(
        f.data.get("total_apps") == 0 for f in result.findings
    )


def test_software_inventory_error():
    """Test handling of subprocess error."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_error()):
        result = mod.check(_make_profile())
    # Should handle gracefully with empty findings (no error bubble up)
    # When there's an error, we return empty apps list
    assert len(result.findings) == 0 or (
        len(result.findings) == 1
        and result.findings[0].data.get("check") == "software_summary"
    )


def test_software_inventory_fix_healthy():
    """Test fix for healthy inventory."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have at least summary action
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_software_inventory_fix_old_1year():
    """Test fix guidance for old apps."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_1year()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for both old-1year and old-2year
    assert any(
        "1+ year" in a.title or "year old" in a.title.lower()
        for a in fix.actions
    )
    assert any(
        "2+ year" in a.title or "2 years" in a.title.lower()
        for a in fix.actions
    )
    assert all(a.success for a in fix.actions)


def test_software_inventory_fix_32bit():
    """Test fix guidance for 32-bit apps."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_32bit()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have action for 32-bit apps
    assert any("32-bit" in a.title for a in fix.actions)
    assert any("Catalina" in a.description for a in fix.actions)
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_software_inventory_summary_contains_counts():
    """Test that summary contains app counts."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_1year()):
        result = mod.check(_make_profile())
    summary = next(
        f for f in result.findings if f.data.get("check") == "software_summary"
    )
    assert summary.data.get("total_apps") == 3
    assert summary.data.get("old_1year_count") == 1
    assert summary.data.get("old_2year_count") == 1
    assert summary.data.get("apps_32bit_count") == 0


def test_software_inventory_all_succeeded():
    """Test that fix always succeeds (informational only)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_32bit()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed
    assert fix.all_succeeded
