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
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "login_items_cleanup")


def _make_run_result(login_items_output=None, launch_agents=None):
    """Create a fake subprocess.run for osascript calls."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # osascript login items command
        if "osascript" in cmd_str and "System Events" in cmd_str:
            if login_items_output is not None:
                result.stdout = login_items_output
            else:
                result.stdout = ""

        return result

    return fake_run


def test_login_items_cleanup_discovered():
    """Test that the module is discovered with correct metadata."""
    mod = _get_module()
    assert mod.name == "login_items_cleanup"
    assert mod.category == "performance"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_login_items_cleanup_no_items():
    """Test when no login items are found."""
    mod = _get_module()
    fake_run = _make_run_result(login_items_output="")

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    # Should have no findings when no items
    assert not result.has_issues


def test_login_items_cleanup_few_items():
    """Test with a reasonable number of login items (no warnings)."""
    mod = _get_module()
    items_output = "Dropbox, Zoom, System Preferences"
    fake_run = _make_run_result(login_items_output=items_output)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "glob", return_value=[]):
                result = mod.check(_make_profile())

    # Should have INFO finding for the items
    assert result.has_issues
    assert any(f.data.get("type") == "login_items_list" for f in result.findings)
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    assert info_findings[0].data.get("count") == 3


def test_login_items_cleanup_excessive_items():
    """Test with more than 8 login items (warning)."""
    mod = _get_module()
    items = [
        "Dropbox",
        "Google Drive",
        "OneDrive",
        "Slack",
        "Discord",
        "Zoom",
        "Steam",
        "Spotify",
        "VLC",
    ]
    items_output = ", ".join(items)
    fake_run = _make_run_result(login_items_output=items_output)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "glob", return_value=[]):
                result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [
        f
        for f in result.findings
        if f.data.get("type") == "excessive_login_items"
    ]
    assert len(warning_findings) == 1
    assert warning_findings[0].severity == Severity.WARNING
    assert warning_findings[0].data.get("count") == 9


def test_login_items_cleanup_resource_heavy():
    """Test detection of resource-heavy apps."""
    mod = _get_module()
    items_output = "Dropbox, Google Drive, Spotify, Notes"
    fake_run = _make_run_result(login_items_output=items_output)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "glob", return_value=[]):
                result = mod.check(_make_profile())

    assert result.has_issues
    heavy_findings = [
        f for f in result.findings if f.data.get("type") == "resource_heavy_items"
    ]
    assert len(heavy_findings) == 1
    assert heavy_findings[0].severity == Severity.WARNING
    # Should detect Dropbox, Google Drive, and Spotify
    items_found = heavy_findings[0].data.get("items", [])
    assert any("Dropbox" in item for item in items_found)
    assert any("Google" in item for item in items_found)
    assert any("Spotify" in item for item in items_found)


def test_login_items_cleanup_broken_items():
    """Test detection of broken login items."""
    mod = _get_module()
    items_output = "Dropbox, OldApp, Notes"
    fake_run = _make_run_result(login_items_output=items_output)

    original_exists = Path.exists

    def mock_path_exists(self):
        # OldApp doesn't exist, others do
        if "OldApp" in str(self):
            return False
        return original_exists(self)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "glob", return_value=[]):
            with patch.object(Path, "exists", mock_path_exists):
                result = mod.check(_make_profile())

    assert result.has_issues
    broken_findings = [
        f for f in result.findings if f.data.get("type") == "broken_login_items"
    ]
    assert len(broken_findings) == 1
    assert broken_findings[0].severity == Severity.WARNING
    # Should detect OldApp as broken
    broken_items = broken_findings[0].data.get("items", [])
    assert "OldApp" in broken_items


def test_login_items_cleanup_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    items = [
        "Dropbox",
        "Google Drive",
        "OneDrive",
        "Slack",
        "Discord",
        "Zoom",
        "Steam",
        "Spotify",
        "OldApp",
        "BrokenApp",
    ]
    items_output = ", ".join(items)
    fake_run = _make_run_result(login_items_output=items_output)

    original_exists = Path.exists

    def mock_path_exists(self):
        # OldApp and BrokenApp don't exist
        if any(app in str(self) for app in ["OldApp", "BrokenApp"]):
            return False
        return original_exists(self)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "glob", return_value=[]):
            with patch.object(Path, "exists", mock_path_exists):
                result = mod.check(_make_profile())

    assert result.has_issues
    # Should have excessive items warning
    assert any(
        f.data.get("type") == "excessive_login_items" for f in result.findings
    )
    # Should have resource heavy warning
    assert any(
        f.data.get("type") == "resource_heavy_items" for f in result.findings
    )
    # Should have broken items warning
    assert any(
        f.data.get("type") == "broken_login_items" for f in result.findings
    )


def test_login_items_cleanup_fix_excessive():
    """Test fix action for excessive login items."""
    mod = _get_module()
    items = ["App1", "App2", "App3", "App4", "App5", "App6", "App7", "App8", "App9"]
    items_output = ", ".join(items)
    fake_run = _make_run_result(login_items_output=items_output)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "glob", return_value=[]):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should have an action for excessive items
    excessive_actions = [
        a for a in fix.actions if "Excessive" in a.title or "excessive" in a.title
    ]
    assert len(excessive_actions) > 0
    # Fix actions should be informational, not actually succeeding
    assert excessive_actions[0].success  # Mark as success=True since informational


def test_login_items_cleanup_fix_resource_heavy():
    """Test fix action for resource-heavy items."""
    mod = _get_module()
    items_output = "Dropbox, Spotify, Notes"
    fake_run = _make_run_result(login_items_output=items_output)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "glob", return_value=[]):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should have action for resource-heavy items
    heavy_actions = [
        a
        for a in fix.actions
        if "resource" in a.title.lower() or "heavy" in a.title.lower()
    ]
    assert len(heavy_actions) > 0


def test_login_items_cleanup_fix_broken():
    """Test fix action for broken login items."""
    mod = _get_module()
    items_output = "OldApp, Notes"
    fake_run = _make_run_result(login_items_output=items_output)

    original_exists = Path.exists

    def mock_path_exists(self):
        return "OldApp" not in str(self)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "glob", return_value=[]):
            with patch.object(Path, "exists", mock_path_exists):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    broken_actions = [a for a in fix.actions if "Broken" in a.title]
    assert len(broken_actions) > 0


def test_login_items_cleanup_osascript_error():
    """Test graceful handling of osascript errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("osascript failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_login_items_cleanup_timeout():
    """Test graceful handling of osascript timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        import subprocess

        raise subprocess.TimeoutExpired("osascript", 5)

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)
