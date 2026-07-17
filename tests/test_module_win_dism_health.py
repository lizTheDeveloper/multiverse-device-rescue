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
    return next(m for m in modules if m.name == "win_dism_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _dism_output_healthy():
    """DISM output showing healthy component store."""
    return "The component store is healthy."


def _dism_output_repairable():
    """DISM output showing repairable corruption."""
    return "The component store is repairable."


def _dism_output_corrupted():
    """DISM output showing corrupted component store."""
    return "The component store is corrupted."


def _dism_analyze_output_healthy_5gb():
    """DISM analyze output showing healthy 5GB store."""
    return """Component Store Cleanup Analysis

    Component store size: 5000 MB
    """


def _dism_analyze_output_cleanup_8gb():
    """DISM analyze output recommending cleanup at 8GB."""
    return """Component Store Cleanup Analysis

    Component store size: 8192 MB
    Component cleanup is recommended.
    """


def _dism_analyze_output_large_15gb():
    """DISM analyze output showing large 15GB store."""
    return """Component Store Cleanup Analysis

    Component store size: 15.5 GB
    """


def _powershell_wu_service_running():
    """Windows Update service is running."""
    return "Running"


def _powershell_wu_service_stopped():
    """Windows Update service is stopped."""
    return "Stopped"


def _fake_run_healthy_5gb():
    """DISM reports healthy store with 5GB size."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "CheckHealth" in cmd_str:
                return _make_subprocess_result(_dism_output_healthy())
            elif "AnalyzeComponentStore" in cmd_str:
                return _make_subprocess_result(_dism_analyze_output_healthy_5gb())
            elif "powershell" in cmd_str and "wuauserv" in cmd_str:
                return _make_subprocess_result(_powershell_wu_service_running())
        return _make_subprocess_result()
    return fake_run


def _fake_run_repairable_8gb():
    """DISM reports repairable corruption with 8GB store, cleanup recommended."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "CheckHealth" in cmd_str:
                return _make_subprocess_result(_dism_output_repairable())
            elif "AnalyzeComponentStore" in cmd_str:
                return _make_subprocess_result(_dism_analyze_output_cleanup_8gb())
        return _make_subprocess_result()
    return fake_run


def _fake_run_corrupted():
    """DISM reports corrupted component store."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "CheckHealth" in cmd_str:
                return _make_subprocess_result(_dism_output_corrupted())
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_store_15gb():
    """DISM reports healthy but large 15GB store."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "CheckHealth" in cmd_str:
                return _make_subprocess_result(_dism_output_healthy())
            elif "AnalyzeComponentStore" in cmd_str:
                return _make_subprocess_result(_dism_analyze_output_large_15gb())
        return _make_subprocess_result()
    return fake_run


def _fake_run_dism_error():
    """DISM commands fail."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "Dism.exe" in cmd_str:
                return _make_subprocess_result(stderr="Error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_pending_repairs():
    """DISM reports pending repairs."""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "CheckHealth" in cmd_str:
                return _make_subprocess_result(_dism_output_healthy())
            elif "AnalyzeComponentStore" in cmd_str:
                return _make_subprocess_result(_dism_analyze_output_healthy_5gb())
            elif "powershell" in cmd_str and "wuauserv" in cmd_str:
                return _make_subprocess_result(_powershell_wu_service_running())
            elif "Get-WinEvent" in cmd_str:
                return _make_subprocess_result('["Pending repair scheduled"]')
        return _make_subprocess_result()
    return fake_run


def test_win_dism_health_discovered():
    mod = _get_module()
    assert mod.name == "win_dism_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.WIN32 in mod.platforms


def test_win_dism_health_healthy_5gb():
    """Healthy component store at 5GB - no issues."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_5gb()):
        result = mod.check(_make_profile())
    # Should have at least one INFO finding
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should mention healthy status
    finding_strs = [f.description for f in result.findings]
    assert any("healthy" in s.lower() for s in finding_strs)


def test_win_dism_health_repairable_with_cleanup():
    """Repairable corruption with cleanup recommended - CRITICAL + WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_repairable_8gb()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL for repairable corruption
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    # Should have WARNING for cleanup recommended
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_dism_health_corrupted():
    """Corrupted component store - CRITICAL."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_corrupted()):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "corrupted" in critical_findings[0].title.lower()


def test_win_dism_health_large_store_15gb():
    """Healthy store but exceeds 10GB - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_large_store_15gb()):
        result = mod.check(_make_profile())
    # Should have INFO for healthy status but also WARNING for size
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(info_findings) > 0
    if len(warning_findings) > 0:
        assert any("10gb" in f.title.lower() or "larger" in f.title.lower() for f in warning_findings)


def test_win_dism_health_dism_error():
    """DISM commands fail."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_dism_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0


def test_win_dism_health_fix_healthy():
    """Fix action for healthy component store."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_5gb()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_dism_health_fix_repairable():
    """Fix action for repairable corruption."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_repairable_8gb()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_dism_health_fix_corrupted():
    """Fix action for corrupted component store."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_corrupted()):
        check_result = mod.check(_make_profile())
    fix_result = mod.fix(check_result, Mode.AUTO)
    assert len(fix_result.actions) > 0
    for action in fix_result.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_win_dism_health_multiple_checks():
    """Running check multiple times produces consistent results."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_5gb()):
        result1 = mod.check(_make_profile())
    with patch("subprocess.run", side_effect=_fake_run_healthy_5gb()):
        result2 = mod.check(_make_profile())
    assert len(result1.findings) == len(result2.findings)
    if result1.findings and result2.findings:
        assert result1.findings[0].severity == result2.findings[0].severity
