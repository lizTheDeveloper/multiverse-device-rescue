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
    return next(m for m in modules if m.name == "time_machine_exclusions")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_exclusions():
    """No directories excluded from Time Machine"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            # No exclusions
            return _make_subprocess_result(stdout="", returncode=1)
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            # Directory is not excluded
            return _make_subprocess_result(stdout="[Not Excluded]")
        return _make_subprocess_result()
    return fake_run


def _fake_run_documents_excluded():
    """Documents directory excluded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    "/Users/test/Documents"\n)'
            )
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            if "Documents" in cmd_str:
                return _make_subprocess_result(stdout="[Excluded]")
            else:
                return _make_subprocess_result(stdout="[Not Excluded]")
        return _make_subprocess_result()
    return fake_run


def _fake_run_desktop_excluded():
    """Desktop directory excluded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    "/Users/test/Desktop"\n)'
            )
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            if "Desktop" in cmd_str:
                return _make_subprocess_result(stdout="[Excluded]")
            else:
                return _make_subprocess_result(stdout="[Not Excluded]")
        return _make_subprocess_result()
    return fake_run


def _fake_run_pictures_excluded():
    """Pictures directory excluded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    "/Users/test/Pictures"\n)'
            )
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            if "Pictures" in cmd_str:
                return _make_subprocess_result(stdout="[Excluded]")
            else:
                return _make_subprocess_result(stdout="[Not Excluded]")
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_exclusions():
    """Multiple directories excluded"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            return _make_subprocess_result(
                stdout='(\n    "/Users/test/Documents",\n    "/Users/test/.cache",\n    "/Users/test/Downloads"\n)'
            )
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            if any(
                exc in cmd_str for exc in ["Documents", ".cache", "Downloads"]
            ):
                return _make_subprocess_result(stdout="[Excluded]")
            else:
                return _make_subprocess_result(stdout="[Not Excluded]")
        return _make_subprocess_result()
    return fake_run


def _fake_run_subprocess_error():
    """Subprocess fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults" in cmd_str and "ExcludeByPath" in cmd_str:
            return _make_subprocess_result(stderr="error", returncode=1)
        elif "tmutil" in cmd_str and "isexcluded" in cmd_str:
            return _make_subprocess_result(stderr="error", returncode=1)
        return _make_subprocess_result()
    return fake_run


def test_time_machine_exclusions_discovered():
    mod = _get_module()
    assert mod.name == "time_machine_exclusions"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_time_machine_exclusions_no_exclusions():
    """Test when no directories are excluded"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_exclusions()):
        result = mod.check(_make_profile())
    assert result.has_issues or len(result.findings) > 0
    # Should have INFO about no exclusions
    assert any(f.data.get("check") == "no_exclusions" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_time_machine_exclusions_documents_excluded():
    """Test when Documents directory is excluded"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_documents_excluded()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about Documents
    assert any(f.data.get("check") == "critical_excluded" for f in result.findings)
    assert any("Documents" in f.title for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should also have exclusion list
    assert any(f.data.get("check") == "exclusions_list" for f in result.findings)


def test_time_machine_exclusions_desktop_excluded():
    """Test when Desktop directory is excluded"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_desktop_excluded()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about Desktop
    assert any(f.data.get("check") == "critical_excluded" for f in result.findings)
    assert any("Desktop" in f.title for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_exclusions_pictures_excluded():
    """Test when Pictures directory is excluded"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pictures_excluded()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING about Pictures
    assert any(f.data.get("check") == "important_excluded" for f in result.findings)
    assert any("Pictures" in f.title for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_time_machine_exclusions_multiple_exclusions():
    """Test with multiple exclusions including critical ones"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_exclusions()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning about Documents
    assert any(
        f.data.get("check") == "critical_excluded" and "Documents" in f.title
        for f in result.findings
    )
    # Should have exclusion list
    assert any(f.data.get("check") == "exclusions_list" for f in result.findings)
    # Check that all exclusions are in the list
    exclusion_findings = [f for f in result.findings if f.data.get("check") == "exclusions_list"]
    if exclusion_findings:
        exclusions = exclusion_findings[0].data.get("exclusions", [])
        assert "/Users/test/Documents" in exclusions


def test_time_machine_exclusions_subprocess_error():
    """Test when subprocess calls fail"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_subprocess_error()):
        result = mod.check(_make_profile())
    # Should still produce findings (no exclusions info)
    assert len(result.findings) > 0
    # Should have INFO about no exclusions (fallback)
    assert any(f.data.get("check") == "no_exclusions" for f in result.findings)


def test_time_machine_exclusions_fix_is_informational():
    """Test that fix() returns informational actions only"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_documents_excluded()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the excluded directory
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_time_machine_exclusions_fix_documents_excluded():
    """Test fix guidance for excluded Documents directory"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_documents_excluded()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have action about Documents
    assert any("Documents" in a.title for a in fix.actions)
    # Should provide guidance on how to re-include
    assert any("System Settings" in a.description for a in fix.actions)


def test_time_machine_exclusions_fix_multiple_exclusions():
    """Test fix guidance for multiple exclusions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_exclusions()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have action for Documents
    assert any("Documents" in a.title for a in fix.actions)
    # All actions should be SAFE
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_time_machine_exclusions_parse_exclusions_output():
    """Test parsing of defaults read output"""
    mod = _get_module()
    output = '(\n    "/path/to/exclude1",\n    "/path/to/exclude2"\n)'
    result = mod._parse_exclusions_output(output)
    assert len(result) == 2
    assert "/path/to/exclude1" in result
    assert "/path/to/exclude2" in result


def test_time_machine_exclusions_parse_single_exclusion():
    """Test parsing single exclusion"""
    mod = _get_module()
    output = '(\n    "/path/to/exclude"\n)'
    result = mod._parse_exclusions_output(output)
    assert len(result) == 1
    assert "/path/to/exclude" in result


def test_time_machine_exclusions_parse_empty_output():
    """Test parsing empty output"""
    mod = _get_module()
    output = "(\n)"
    result = mod._parse_exclusions_output(output)
    assert len(result) == 0
