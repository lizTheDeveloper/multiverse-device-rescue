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
    return next(m for m in modules if m.name == "system_extensions")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_extensions():
    """No system extensions installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result("")
        return _make_subprocess_result()
    return fake_run


def _fake_run_single_active_extension():
    """Single active network extension"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "[com.apple.ABCD1234] com.apple.networkext - version 1.0 - activated [Network Extension]\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_extensions():
    """Multiple extensions with different states and categories"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "[com.apple.ABCD1234] com.apple.networkext - version 1.0 - activated [Network Extension]\n"
                "[com.apple.EFGH5678] com.apple.endpointsec - version 2.0 - activated [Endpoint Security]\n"
                "[com.vendor.IJKL9999] com.vendor.driverkit - version 1.5 - deactivated [DriverKit]\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_extension_waiting_approval():
    """Extension waiting for user approval"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str and "list" in cmd_str:
            return _make_subprocess_result(
                "[com.apple.ABCD1234] com.apple.networkext - version 1.0 - waiting for user approval [Network Extension]\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_systemextensionsctl_not_available():
    """systemextensionsctl command not found (older macOS)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "systemextensionsctl" in cmd_str:
            return _make_subprocess_result("", "command not found", 127)
        return _make_subprocess_result()
    return fake_run


def test_system_extensions_discovered():
    mod = _get_module()
    assert mod.name == "system_extensions"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_system_extensions_no_extensions():
    """No system extensions installed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_extensions()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_system_extensions_single_active():
    """Single active extension reports as INFO"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_active_extension()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("activated" in f.title.lower() for f in result.findings)


def test_system_extensions_multiple_extensions():
    """Multiple extensions with different states and categories"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_extensions()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings for active extensions
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 2  # At least 2 active extensions


def test_system_extensions_waiting_approval():
    """Extension waiting for user approval reports as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_extension_waiting_approval()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("approval" in f.title.lower() or "unusual" in f.description.lower() for f in result.findings)


def test_system_extensions_not_available():
    """Gracefully handle systemextensionsctl not available"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_systemextensionsctl_not_available()):
        result = mod.check(_make_profile())
    # Should not crash, may have no findings or a note that it's not available
    assert isinstance(result, object)


def test_system_extensions_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_extensions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) == len(check.findings)
