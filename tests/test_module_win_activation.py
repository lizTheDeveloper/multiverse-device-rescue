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
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_activation")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _powershell_activation_licensed():
    """Windows is licensed (status 1)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 1
  }
]"""


def _powershell_activation_unlicensed():
    """Windows is unlicensed (status 0)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 0
  }
]"""


def _powershell_activation_oob_grace():
    """Windows is in OOB grace period (status 2)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 2
  }
]"""


def _powershell_activation_oot_grace():
    """Windows is in OOT grace period (status 3)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 3
  }
]"""


def _powershell_activation_nongenuine_grace():
    """Windows is in non-genuine grace period (status 4)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 4
  }
]"""


def _powershell_activation_notification():
    """Windows is showing notification (status 5)."""
    return """[
  {
    "Name": "Windows 11 Pro",
    "LicenseStatus": 5
  }
]"""


def _powershell_activation_no_data():
    """No activation data returned."""
    return ""


def _powershell_activation_single_object():
    """Single object (not array)."""
    return """{
  "Name": "Windows 11 Pro",
  "LicenseStatus": 1
}"""


def _fake_run_licensed():
    """PowerShell returns licensed status."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_licensed())
        return _make_subprocess_result()
    return fake_run


def _fake_run_unlicensed():
    """PowerShell returns unlicensed status."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_unlicensed())
        return _make_subprocess_result()
    return fake_run


def _fake_run_oob_grace():
    """PowerShell returns OOB grace period."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_oob_grace())
        return _make_subprocess_result()
    return fake_run


def _fake_run_oot_grace():
    """PowerShell returns OOT grace period."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_oot_grace())
        return _make_subprocess_result()
    return fake_run


def _fake_run_nongenuine_grace():
    """PowerShell returns non-genuine grace period."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_nongenuine_grace())
        return _make_subprocess_result()
    return fake_run


def _fake_run_notification():
    """PowerShell returns notification status."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_notification())
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_data():
    """PowerShell returns no data."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_no_data())
        return _make_subprocess_result()
    return fake_run


def _fake_run_single_object():
    """PowerShell returns single object."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(_powershell_activation_single_object())
        return _make_subprocess_result()
    return fake_run


def _fake_run_powershell_error():
    """PowerShell command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "powershell" in cmd:
            return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_win_activation_discovered():
    mod = _get_module()
    assert mod.name == "win_activation"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_activation_licensed():
    """Windows is licensed - INFO."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_licensed()):
        result = mod.check(_make_profile())
    # Should have INFO finding (licensed status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("activated" in f.title.lower() for f in result.findings)


def test_win_activation_unlicensed():
    """Windows is unlicensed - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unlicensed()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical finding
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any("not activated" in f.title.lower() for f in critical_findings)


def test_win_activation_oob_grace():
    """Windows is in OOB grace period - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_oob_grace()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about grace period
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("grace period" in f.title.lower() for f in warning_findings)


def test_win_activation_oot_grace():
    """Windows is in OOT grace period - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_oot_grace()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about grace period
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_activation_nongenuine_grace():
    """Windows is in non-genuine grace period - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_nongenuine_grace()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about grace period
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_activation_notification():
    """Windows is showing notification - INFO."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_notification()):
        result = mod.check(_make_profile())
    # Should have INFO finding about notification
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("notification" in f.title.lower() for f in result.findings)


def test_win_activation_no_data():
    """Unable to determine activation status - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_data()):
        result = mod.check(_make_profile())
    # Should have warning about unable to check
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any("unable" in f.title.lower() for f in result.findings)


def test_win_activation_single_object():
    """Single object response (not array)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_single_object()):
        result = mod.check(_make_profile())
    # Should handle single object correctly
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any("activated" in f.title.lower() for f in result.findings)


def test_win_activation_powershell_error():
    """PowerShell command fails."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powershell_error()):
        result = mod.check(_make_profile())
    # Should have warning about unable to check
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_win_activation_fix_licensed():
    """Fix action for licensed system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_licensed()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_activation_fix_unlicensed():
    """Fix action for unlicensed system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unlicensed()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True
        # Should mention activation
        assert "activat" in action.description.lower()


def test_win_activation_fix_grace_period():
    """Fix action for grace period."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_oob_grace()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_activation_license_status_parsing():
    """License status values are correctly parsed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_unlicensed()):
        result = mod.check(_make_profile())
    # Should have status info in findings
    assert result.has_issues
    assert any("0" in str(f.data.get("license_status")) for f in result.findings)
