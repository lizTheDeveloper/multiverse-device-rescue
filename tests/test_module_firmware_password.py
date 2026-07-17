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
    return next(m for m in modules if m.name == "firmware_password")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_apple_silicon():
    """Apple Silicon Mac (arm64)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="arm64\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_intel_password_set():
    """Intel Mac with firmware password set"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="x86_64\n")
        elif "firmwarepasswd" in cmd_str and "-check" in cmd_str:
            return _make_subprocess_result(stdout="Yes\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_intel_password_not_set():
    """Intel Mac with no firmware password"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="x86_64\n")
        elif "firmwarepasswd" in cmd_str and "-check" in cmd_str:
            return _make_subprocess_result(stdout="No\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_firmware_password_permission_error():
    """Intel Mac - permission denied for firmware password check"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(stdout="x86_64\n")
        elif "firmwarepasswd" in cmd_str and "-check" in cmd_str:
            raise PermissionError("Operation not permitted")
        return _make_subprocess_result()
    return fake_run


def _fake_run_chip_type_detection_fails():
    """Unable to detect chip type"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "uname" in cmd_str and "-m" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_firmware_password_discovered():
    mod = _get_module()
    assert mod.name == "firmware_password"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_firmware_password_apple_silicon():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon()):
        result = mod.check(_make_profile())
    assert result.has_issues  # Should have chip type info
    assert any(f.data.get("check") == "chip_type" for f in result.findings)
    assert any(f.data.get("chip_type") == "Apple Silicon" for f in result.findings)
    assert any(f.data.get("check") == "startup_security_info" for f in result.findings)


def test_firmware_password_intel_password_set():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_password_set()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "chip_type" for f in result.findings)
    assert any(f.data.get("chip_type") == "Intel" for f in result.findings)
    assert any(f.data.get("check") == "firmware_password_set" for f in result.findings)


def test_firmware_password_intel_password_not_set():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_password_not_set()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "firmware_password_not_set" for f in result.findings)
    # Should have a WARNING severity finding
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_firmware_password_permission_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firmware_password_permission_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "firmware_password_permission_denied" for f in result.findings)


def test_firmware_password_chip_detection_fails():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_chip_type_detection_fails()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "chip_type_detection" for f in result.findings)


def test_firmware_password_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_intel_password_not_set()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_firmware_password_fix_apple_silicon():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_apple_silicon()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
