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
    return next(m for m in modules if m.name == "win_recovery_options")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _reagentc_enabled():
    """reagentc /info output with WinRE enabled."""
    return """REAGENT.XML Information

Windows Recovery Environment (Windows RE) version 10.0
Reagent.xml state: Enabled
Windows RE enabled: Yes
Boot Configuration Data (BCD) identifier: {abcdef12-1234-1234-1234-123456789012}
Recovery partition: \\Device\\HarddiskVolume2

GUID: {abcdef12-1234-1234-1234-123456789012}
Offset: 350 MB
"""


def _reagentc_disabled():
    """reagentc /info output with WinRE disabled."""
    return """REAGENT.XML Information

Windows Recovery Environment (Windows RE) version 10.0
Reagent.xml state: Disabled
Windows RE enabled: No
"""


def _vssadmin_shadows_available():
    """vssadmin list shadows output with shadows available."""
    return """vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corporation

Successfully queried shadow copies on \\\\?\\Volume{12345678-1234-1234-1234-123456789012}

Shadow Copy Volume: \\\\?\\Volume{abcdef12-1234-1234-1234-123456789012}
Shadow Copy ID: {abcdef12-1234-1234-1234-123456789013}
"""


def _vssadmin_no_shadows():
    """vssadmin list shadows output with no shadows (System Restore disabled)."""
    return """vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corporation
"""


def _powershell_restore_points_multiple():
    """PowerShell Get-ComputerRestorePoint output with multiple points."""
    return """[
  {
    "Description": "Windows Update",
    "CreationTime": "2026-07-05T15:30:00"
  },
  {
    "Description": "Automatic Checkpoint",
    "CreationTime": "2026-07-01T10:15:00"
  },
  {
    "Description": "Before software installation",
    "CreationTime": "2026-06-15T09:00:00"
  }
]"""


def _powershell_restore_points_single():
    """PowerShell Get-ComputerRestorePoint output with single point."""
    return """{
  "Description": "Automatic Checkpoint",
  "CreationTime": "2026-07-05T14:30:00"
}"""


def _powershell_restore_points_empty():
    """PowerShell Get-ComputerRestorePoint output with no points."""
    return ""


def _powershell_restore_point_old():
    """PowerShell output with old restore point (>30 days)."""
    return """[
  {
    "Description": "Old Checkpoint",
    "CreationTime": "2026-05-01T10:00:00"
  }
]"""


def _fake_run_winre_enabled_with_restore_points():
    """All systems healthy: WinRE enabled, System Restore enabled, restore points available."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(_reagentc_enabled())
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_shadows_available())
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_points_multiple())
        return _make_subprocess_result()
    return fake_run


def _fake_run_winre_disabled():
    """WinRE disabled - CRITICAL."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(_reagentc_disabled())
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_shadows_available())
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_points_multiple())
        return _make_subprocess_result()
    return fake_run


def _fake_run_system_restore_disabled():
    """System Restore disabled - WARNING."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(_reagentc_enabled())
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_no_shadows(), returncode=1)
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_points_empty())
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_restore_points():
    """System Restore enabled but no restore points - WARNING."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(_reagentc_enabled())
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_shadows_available())
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_points_empty())
        return _make_subprocess_result()
    return fake_run


def _fake_run_old_restore_point():
    """Restore point older than 30 days - WARNING."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(_reagentc_enabled())
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_shadows_available())
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_point_old())
        return _make_subprocess_result()
    return fake_run


def _fake_run_reagentc_error():
    """reagentc command fails."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "reagentc" in cmd_str:
                return _make_subprocess_result(stderr="Error", returncode=1)
            elif "vssadmin" in cmd_str:
                return _make_subprocess_result(_vssadmin_shadows_available())
            elif "powershell" in cmd_str and "Get-ComputerRestorePoint" in cmd_str:
                return _make_subprocess_result(_powershell_restore_points_multiple())
        return _make_subprocess_result()
    return fake_run


def test_win_recovery_options_discovered():
    mod = _get_module()
    assert mod.name == "win_recovery_options"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_recovery_options_all_healthy():
    """All recovery options healthy: WinRE enabled, System Restore enabled, restore points available."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_enabled_with_restore_points()):
        result = mod.check(_make_profile())
    # Should have INFO findings (healthy status)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention WinRE enabled
    finding_strs = [f.description for f in result.findings]
    assert any("WinRE" in s or "Recovery Environment" in s for s in finding_strs)


def test_win_recovery_options_winre_disabled():
    """WinRE disabled - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for disabled WinRE
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "disabled" in critical_findings[0].title.lower()


def test_win_recovery_options_system_restore_disabled():
    """System Restore disabled - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_system_restore_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for disabled System Restore
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("System Restore" in f.title for f in warning_findings)


def test_win_recovery_options_no_restore_points():
    """No restore points available - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_restore_points()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for no restore points
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("restore point" in f.title.lower() for f in warning_findings)


def test_win_recovery_options_old_restore_point():
    """Restore point older than 30 days - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_old_restore_point()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for old restore point
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("old" in f.title.lower() or "days" in f.title.lower() for f in warning_findings)


def test_win_recovery_options_reagentc_error():
    """reagentc command fails - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_reagentc_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about failed check
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("Could not check" in f.title for f in warning_findings)


def test_win_recovery_options_fix_winre_disabled():
    """Fix action for CRITICAL disabled WinRE."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_disabled()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    # All actions should be SAFE risk level and successful
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_recovery_options_fix_system_restore_disabled():
    """Fix action for WARNING disabled System Restore."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_system_restore_disabled()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_recovery_options_fix_no_restore_points():
    """Fix action for no restore points."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_restore_points()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_recovery_options_fix_all_healthy():
    """Fix action for all healthy recovery options."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_enabled_with_restore_points()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_recovery_options_recovery_summary():
    """Recovery configuration summary is generated."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_enabled_with_restore_points()):
        result = mod.check(_make_profile())
    # Should have a summary finding
    summary_findings = [f for f in result.findings if f.data.get("check") == "recovery_summary"]
    assert len(summary_findings) > 0
    summary = summary_findings[0].description
    # Summary should mention recovery status
    assert "recovery" in summary.lower() or "WinRE" in summary or "Restore" in summary


def test_win_recovery_options_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_winre_enabled_with_restore_points()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_winre_enabled_with_restore_points()):
        result2 = mod.check(_make_profile())
    # Results should be the same
    assert len(result1.findings) == len(result2.findings)
    if result1.findings and result2.findings:
        # Check severity consistency
        severities1 = sorted([f.severity for f in result1.findings])
        severities2 = sorted([f.severity for f in result2.findings])
        assert severities1 == severities2
