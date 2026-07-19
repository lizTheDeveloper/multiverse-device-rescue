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
    return next(m for m in modules if m.name == "automatic_updates")


def _fake_run(defaults_values=None):
    """
    Create a mock subprocess.run function.
    defaults_values is a dict mapping (domain, key) -> output_value.
    """
    if defaults_values is None:
        defaults_values = {}

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if cmd[0] == "defaults" and cmd[1] == "read":
            domain = cmd[2]
            key = cmd[3]
            result.stdout = defaults_values.get((domain, key), "")

        return result

    return fake_run


def test_automatic_updates_discovered():
    mod = _get_module()
    assert mod.name == "automatic_updates"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_automatic_updates_all_enabled():
    """Test when all automatic updates are enabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_automatic_updates_critical_disabled():
    """Test when critical updates are disabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "critical_update" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_automatic_updates_check_disabled():
    """Test when automatic check is disabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "automatic_check" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_automatic_updates_multiple_disabled():
    """Test when multiple update settings are disabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 2
    assert any(f.data.get("check") == "automatic_check" for f in result.findings)
    assert any(f.data.get("check") == "automatic_download" for f in result.findings)


def test_automatic_updates_config_data_disabled():
    """Test when config data updates are disabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "0",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "config_data" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_automatic_updates_app_store_disabled():
    """Test when App Store auto-updates are disabled."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "0",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "app_store_auto" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_automatic_updates_fix_all_findings():
    """Test that fix creates informational actions for all findings."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "0",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have 4 findings and 4 actions
    assert len(check.findings) == 4
    assert len(fix.actions) == 4
    # All actions should succeed (informational)
    assert fix.all_succeeded
    assert all(a.success for a in fix.actions)


def test_automatic_updates_fix_is_informational():
    """Test that fix provides instructions without making changes."""
    mod = _get_module()
    defaults_values = {
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): "0",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall"): "1",
        ("/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall"): "1",
        ("/Library/Preferences/com.apple.commerce", "AutoUpdate"): "1",
    }
    with patch("subprocess.run", side_effect=_fake_run(defaults_values)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) == 1
    action = fix.actions[0]
    assert "System Settings" in action.description
    assert action.success is True
    assert action.error is None


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.automatic_updates.") for c in declared)
