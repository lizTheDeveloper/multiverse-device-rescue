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
    return next(m for m in modules if m.name == "browser_hijack_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: all browsers have legitimate settings"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        # Safari checks
        if "defaults read" in cmd_str and "HomePage" in cmd_str:
            return _make_subprocess_result("https://www.google.com\n")
        elif "defaults read" in cmd_str and "SearchProviderIdentifier" in cmd_str:
            return _make_subprocess_result("com.google.Chrome\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_safari_hijacked():
    """Safari homepage and search engine hijacked"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "HomePage" in cmd_str:
            return _make_subprocess_result("https://search.suspicious-ads.com\n")
        elif "defaults read" in cmd_str and "SearchProviderIdentifier" in cmd_str:
            return _make_subprocess_result("com.malware.SearchProvider\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_browsers():
    """No browsers installed (all defaults fail)"""
    def fake_run(cmd, **kwargs):
        # Return errors for all defaults reads
        return _make_subprocess_result(returncode=1)

    return fake_run


def test_browser_hijack_check_discovered():
    mod = _get_module()
    assert mod.name == "browser_hijack_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_browser_hijack_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    # Should have at least the "all clean" info message
    assert len(result.findings) >= 1
    assert any(f.data.get("check") == "all_browsers_clean" for f in result.findings)


def test_browser_hijack_check_safari_hijacked():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safari_hijacked()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for both homepage and search engine
    assert any(
        f.data.get("check") == "safari_homepage_suspicious" for f in result.findings
    )
    assert any(
        f.data.get("check") == "safari_search_engine_suspicious" for f in result.findings
    )


def test_browser_hijack_check_no_browsers():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_browsers()):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    # Should have "all clean" message when no browsers found
    assert any(f.data.get("check") == "all_browsers_clean" for f in result.findings)


def test_browser_hijack_check_fix_safari_homepage():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safari_hijacked()):
        with patch("pathlib.Path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for fixing
    assert len(fix.actions) > 0
    # Should have action for Safari homepage
    assert any("Safari homepage" in a.title for a in fix.actions)


def test_browser_hijack_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_safari_hijacked()):
        with patch("pathlib.Path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    # All actions should be marked as successful (informational)
    for action in fix.actions:
        assert action.success is True
        assert action.error is None
        assert action.risk_level == RiskLevel.SAFE
