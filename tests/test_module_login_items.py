import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, RiskLevel, Severity, Mode
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
    return next(m for m in modules if m.name == "login_items")


def _fake_run_factory(osascript_output, btm_exists=False):
    """Factory for creating fake subprocess.run that mocks osascript."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if cmd[0] == "osascript":
            result.stdout = osascript_output
            result.returncode = 0
        else:
            raise AssertionError(f"unexpected command {cmd}")
        return result
    return fake_run


# Sample osascript outputs (comma-space separated, single line format)
OSASCRIPT_NO_ITEMS = ""
OSASCRIPT_FEW_ITEMS = "Firefox, Safari, Finder"
OSASCRIPT_MANY_ITEMS = "Spotify, Dropbox, Google Chrome, Adobe Reader, Microsoft AutoUpdate, Java Update Checker, GoToMeeting, Zoom, Slack, Figma, 1Password, Raycast, Bear"
OSASCRIPT_WITH_BLOATWARE = "Firefox, Spotify, Google Chrome, Adobe Reader"


def test_login_items_discovered():
    mod = _get_module()
    assert mod.name == "login_items"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "bloatware"


def test_known_bloatware_data_file_valid():
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "login_items" / "data" / "known_bloatware.json"
    )
    with open(data_file) as f:
        data = json.load(f)
    assert len(data) >= 5
    for entry in data:
        assert "name_pattern" in entry
        assert "name" in entry
        assert "description" in entry


def test_login_items_no_items():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_NO_ITEMS)):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert not result.has_issues


def test_login_items_few_items_no_bloatware():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_FEW_ITEMS)):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 3  # Three INFO items
    item_names = [f.data["item_name"] for f in result.findings]
    assert "Firefox" in item_names
    assert "Safari" in item_names
    assert "Finder" in item_names
    for finding in result.findings:
        assert finding.severity == Severity.INFO


def test_login_items_finds_bloatware():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_WITH_BLOATWARE)):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    # Should find Spotify, Adobe Reader, Google Chrome as bloatware (WARNING)
    # Firefox as regular item (INFO)
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    infos = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(warnings) >= 2  # At least Spotify and Adobe
    assert len(infos) >= 1  # At least Firefox


def test_login_items_many_items_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_MANY_ITEMS)):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    assert result.has_issues
    # Should have individual items plus a "too many" warning
    too_many = [f for f in result.findings if "Too many" in f.title]
    assert len(too_many) == 1
    assert too_many[0].severity == Severity.WARNING
    assert too_many[0].data["count"] == 13


def test_login_items_osascript_failure():
    """Test graceful handling when osascript fails."""
    mod = _get_module()
    def fake_run_failure(cmd, **kwargs):
        if cmd[0] == "osascript":
            raise FileNotFoundError("osascript not found")
        raise AssertionError(f"unexpected command {cmd}")

    with patch("subprocess.run", side_effect=fake_run_failure):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())
    # Should not crash, just return no findings
    assert not result.has_issues


def test_login_items_btm_file_exists():
    """Test that btm file existence doesn't break anything."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_FEW_ITEMS)):
        with patch("pathlib.Path.exists", return_value=True):
            result = mod.check(_make_profile())
    # Should still find the items from osascript
    assert result.has_issues
    assert len(result.findings) == 3


def test_login_items_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_WITH_BLOATWARE)):
        with patch("pathlib.Path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) >= 3


def test_login_items_fix_handles_too_many_items():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(OSASCRIPT_MANY_ITEMS)):
        with patch("pathlib.Path.exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    # Should have action for "Review and reduce login items"
    review_actions = [a for a in fix.actions if "Review" in a.title]
    assert len(review_actions) >= 1
