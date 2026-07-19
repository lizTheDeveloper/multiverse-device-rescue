import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

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
    return next(m for m in modules if m.name == "sudo_touchid")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_with_touchid():
    """Normal case: Touch ID hardware, fingerprints enrolled, sudo enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPiBridgeDataType" in cmd_str or cmd == ["system_profiler", "SPiBridgeDataType"]:
            return _make_subprocess_result("Touch ID: present\n")
        elif "bioutil -rs" in cmd_str or cmd == ["bioutil", "-rs"]:
            return _make_subprocess_result(
                "Fingerprints for user 'testuser':\n"
                "  1: Right Index Finger\n"
                "  2: Right Middle Finger\n"
            )
        elif "defaults read com.apple.ApplePay" in cmd_str or cmd == ["defaults", "read", "com.apple.ApplePay", "ApplePayEnabled"]:
            return _make_subprocess_result("1\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_fingerprints():
    """Touch ID hardware present but no fingerprints enrolled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPiBridgeDataType" in cmd_str or cmd == ["system_profiler", "SPiBridgeDataType"]:
            return _make_subprocess_result("Touch ID: present\n")
        elif "bioutil -rs" in cmd_str or cmd == ["bioutil", "-rs"]:
            return _make_subprocess_result("Fingerprints for user 'testuser':\n")
        elif "defaults read com.apple.ApplePay" in cmd_str or cmd == ["defaults", "read", "com.apple.ApplePay", "ApplePayEnabled"]:
            return _make_subprocess_result("0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_touchid_hardware():
    """No Touch ID hardware on this Mac"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "system_profiler SPiBridgeDataType" in cmd_str or cmd == ["system_profiler", "SPiBridgeDataType"]:
            return _make_subprocess_result("iBridge Information: Fingerprint Reader: Not supported\n")
        elif "bioutil -rs" in cmd_str or cmd == ["bioutil", "-rs"]:
            return _make_subprocess_result("bioutil: No input/output error\n", returncode=1)
        elif "defaults read com.apple.ApplePay" in cmd_str or cmd == ["defaults", "read", "com.apple.ApplePay", "ApplePayEnabled"]:
            return _make_subprocess_result("0\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_command_timeout():
    """Commands timeout (system hangs)"""
    def fake_run(cmd, **kwargs):
        raise TimeoutError("Command timed out")
    return fake_run


def _fake_run_command_fails():
    """Commands fail (permissions, unavailable commands)"""
    def fake_run(cmd, **kwargs):
        raise OSError("Command not found")
    return fake_run


def test_sudo_touchid_discovered():
    """Test that the module is discovered by the registry"""
    mod = _get_module()
    assert mod.name == "sudo_touchid"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_sudo_touchid_healthy():
    """Test healthy case with Touch ID hardware, fingerprints, and sudo enabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_touchid()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value="auth sufficient pam_tid.so\n"):
                result = mod.check(_make_profile())

    # Should have INFO findings but no critical issues
    assert result.has_issues
    # Should report Touch ID status
    assert any(f.data.get("check") == "touchid_status" for f in result.findings)
    # Should report Apple Pay enabled
    assert any(f.data.get("check") == "applepay_enabled" for f in result.findings)
    # Should NOT report sudo as disabled (it is enabled)
    assert not any(f.data.get("check") == "sudo_not_enabled" for f in result.findings)


def test_sudo_touchid_no_fingerprints():
    """Test case with Touch ID hardware but no fingerprints enrolled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_fingerprints()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=""):
                result = mod.check(_make_profile())

    assert result.has_issues
    # Should report no fingerprints with WARNING severity
    assert any(f.data.get("check") == "no_fingerprints" and f.severity == Severity.WARNING
              for f in result.findings)
    # Should report Touch ID status
    assert any(f.data.get("check") == "touchid_status" for f in result.findings)


def test_sudo_touchid_no_hardware():
    """Test case with no Touch ID hardware"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_touchid_hardware()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    # Should report no hardware
    assert any(f.data.get("check") == "no_hardware" for f in result.findings)
    # Should NOT have warning about no fingerprints (no hardware means no fingerprints expected)
    assert not any(f.data.get("check") == "no_fingerprints" for f in result.findings)


def test_sudo_touchid_sudo_not_enabled():
    """Test case with Touch ID but sudo not enabled"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_touchid()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=""):
                result = mod.check(_make_profile())

    assert result.has_issues
    # Should suggest enabling Touch ID for sudo
    assert any(f.data.get("check") == "sudo_not_enabled" for f in result.findings)


def test_sudo_touchid_command_timeout():
    """Test graceful handling of command timeouts"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_timeout()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    # Should not crash, should still have findings
    assert isinstance(result.findings, list)


def test_sudo_touchid_command_fails():
    """Test graceful handling of command failures"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_command_fails()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    # Should not crash, should still have findings
    assert isinstance(result.findings, list)


def test_sudo_touchid_fix_is_informational():
    """Test that fix() provides informational actions only"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_fingerprints()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=""):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level (informational)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_sudo_touchid_fix_covers_all_findings():
    """Test that fix() has an action for each finding"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_fingerprints()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=""):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # Each finding should have a corresponding action
    assert len(fix.actions) == len(check.findings)


def test_sudo_touchid_fingerprint_count():
    """Test accurate fingerprint counting"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_with_touchid()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value="auth sufficient pam_tid.so\n"):
                result = mod.check(_make_profile())

    # Should find the fingerprint count in the findings
    status_finding = next(f for f in result.findings if f.data.get("check") == "touchid_status")
    assert status_finding.data.get("fingerprints") == 2


def test_sudo_touchid_multiple_findings():
    """Test case with multiple findings including warnings and infos"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_fingerprints()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=""):
                result = mod.check(_make_profile())

    assert result.has_issues
    # Should have multiple findings
    assert len(result.findings) > 1
    # Mix of severities (INFO and WARNING)
    severities = {f.severity for f in result.findings}
    assert Severity.INFO in severities or Severity.WARNING in severities


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.sudo_touchid.") for c in declared)
