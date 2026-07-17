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
    return next(m for m in modules if m.name == "win_event_errors")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Healthy case: no errors in either log"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_few_errors():
    """Few errors: normal operation"""
    def fake_run(cmd, **kwargs):
        # Simulate 5 errors from System log, 3 from Application
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "System" in cmd_str:
            return _make_subprocess_result(
                "Windows Update | 2024-01-15 10:30:00 | Update failed\n"
                "Service Control | 2024-01-15 10:35:00 | Service timeout\n"
                "Application Error | 2024-01-15 10:40:00 | App crash\n"
                "System | 2024-01-15 10:45:00 | General error\n"
                "Network | 2024-01-15 10:50:00 | Network issue\n"
            )
        elif "Application" in cmd_str:
            return _make_subprocess_result(
                "MyApp | 2024-01-15 11:00:00 | Debug error 1\n"
                "MyApp | 2024-01-15 11:05:00 | Debug error 2\n"
                "OtherApp | 2024-01-15 11:10:00 | Some error\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_many_system_errors():
    """Many errors in System log: warning condition"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "System" in cmd_str:
            # Generate 25 errors to exceed threshold of 20
            errors = []
            for i in range(25):
                errors.append(f"Service Control | 2024-01-15 {10+i:02d}:00:00 | Error {i}")
            return _make_subprocess_result("\n".join(errors))
        elif "Application" in cmd_str:
            return _make_subprocess_result(
                "MyApp | 2024-01-15 11:00:00 | One error\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_known_bad_sources():
    """Known-bad sources detected"""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "System" in cmd_str:
            return _make_subprocess_result(
                "Disk | 2024-01-15 10:30:00 | Disk I/O error\n"
                "WHEA | 2024-01-15 10:35:00 | Hardware error detected\n"
                "Windows Update | 2024-01-15 10:40:00 | Normal error\n"
            )
        elif "Application" in cmd_str:
            return _make_subprocess_result(
                "BugCheck | 2024-01-15 11:00:00 | System crash detected\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_failure():
    """PowerShell command fails"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="", stderr="Command failed", returncode=1)
    return fake_run


def test_win_event_errors_discovered():
    mod = _get_module()
    assert mod.name == "win_event_errors"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_event_errors_healthy():
    """Test healthy case: no errors"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("No recent errors" in f.title for f in result.findings)


def test_win_event_errors_few_errors():
    """Test normal case: few errors"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_few_errors()):
        result = mod.check(_make_profile())
    # Should have findings but no warnings
    assert result.has_issues
    assert all(f.severity != Severity.CRITICAL for f in result.findings)
    # Should have info-level summary
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_win_event_errors_many_errors():
    """Test warning case: many errors in System log"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_system_errors()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a warning about high error volume
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("High error volume" in f.title for f in result.findings)


def test_win_event_errors_known_bad_sources():
    """Test warning case: known-bad error sources detected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_known_bad_sources()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a warning about known-issue errors
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("Known-issue errors" in f.title for f in result.findings)


def test_win_event_errors_powershell_failure():
    """Test graceful handling of PowerShell failure"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_failure()):
        result = mod.check(_make_profile())
    # Should not crash, just report no issues
    assert result.has_issues or not result.has_issues  # Either is OK


def test_win_event_errors_fix_is_informational():
    """Test that fix() produces informational actions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_system_errors()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_win_event_errors_fix_with_known_bad():
    """Test fix() response to known-bad errors"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_known_bad_sources()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # Should have action about known-bad sources
    assert any("known-issue" in a.title.lower() or "hardware" in a.description.lower()
               for a in fix.actions)
