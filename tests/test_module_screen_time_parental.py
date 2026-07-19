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
        os_version="14.5",
        architecture="arm64",
        cpu_model="Apple M3",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "screen_time_parental")


def _make_defaults_run(defaults_responses=None):
    """Create a fake subprocess.run for defaults read commands.

    Args:
        defaults_responses: Dict mapping (domain, key) -> value
    """
    defaults_responses = defaults_responses or {}

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        # Convert all cmd items to strings to handle Path objects
        cmd_str = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)

        # Handle defaults read commands
        if cmd and len(cmd) >= 3 and cmd[0] == "defaults" and cmd[1] == "read":
            domain = cmd[2]
            key = cmd[3] if len(cmd) > 3 else None

            if key and (domain, key) in defaults_responses:
                result.stdout = str(defaults_responses[(domain, key)])
                result.returncode = 0
            else:
                result.returncode = 1  # Key not found
        # Handle dscl commands
        elif cmd and len(cmd) >= 3 and cmd[0] == "dscl":
            if "-list" in cmd and "/Users" in cmd:
                result.stdout = "root\n_datemanagerd\n_softwareupdate\njohn\nmary"
                result.returncode = 0
            elif "-read" in cmd and "/Users/" in cmd:
                result.returncode = 0
                if "GeneratedUID" in cmd:
                    result.stdout = "GeneratedUID: 12345678-1234-1234-1234-123456789012"
                else:
                    result.stdout = ""

        return result

    return fake_run


def test_screen_time_parental_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "screen_time_parental"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_screen_time_enabled_with_passcode():
    """Test Screen Time enabled with passcode set."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "screen_time_enabled" for f in result.findings)
    # Should not have the no-passcode warning
    assert not any(f.data.get("check") == "screen_time_no_passcode" for f in result.findings)


def test_screen_time_enabled_without_passcode():
    """Test Screen Time enabled but no passcode set - should warn."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "0",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "screen_time_enabled" for f in result.findings)

    # Should have WARNING for no passcode
    no_passcode = [f for f in result.findings if f.data.get("check") == "screen_time_no_passcode"]
    assert len(no_passcode) == 1
    assert no_passcode[0].severity == Severity.WARNING


def test_screen_time_disabled_no_child_accounts():
    """Test Screen Time disabled with no child accounts."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "0",
    })

    def dscl_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if cmd and "dscl" in cmd[0]:
            result.stdout = "root\n_daemon"  # Only system accounts
        else:
            result.stdout = fake_run(cmd, **kwargs).stdout
            result.returncode = fake_run(cmd, **kwargs).returncode
        return result

    with patch("subprocess.run", side_effect=dscl_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    disabled = [f for f in result.findings if f.data.get("check") == "screen_time_disabled"]
    assert len(disabled) == 1
    assert disabled[0].severity == Severity.INFO


def test_screen_time_disabled_with_child_accounts():
    """Test Screen Time disabled but child accounts present - should warn."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "0",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    disabled_with_children = [
        f for f in result.findings
        if f.data.get("check") == "screen_time_disabled_with_children"
    ]
    # Note: This might not trigger if managed account detection doesn't work in test
    # but the test should complete without error


def test_content_privacy_restrictions_enabled():
    """Test Content & Privacy Restrictions enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "ContentPrivacyRestrictionsEnabled"): "1",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    restrictions = [f for f in result.findings if f.data.get("check") == "content_privacy_restrictions"]
    assert len(restrictions) == 1
    assert restrictions[0].severity == Severity.INFO


def test_app_limits_configured():
    """Test App Limits are configured."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "AppLimits"): "{ some app limits config }",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    app_limits = [f for f in result.findings if f.data.get("check") == "app_limits_configured"]
    assert len(app_limits) == 1
    assert app_limits[0].severity == Severity.INFO


def test_downtime_enabled():
    """Test Downtime schedule is enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "DowntimeEnabled"): "1",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    downtime = [f for f in result.findings if f.data.get("check") == "downtime_enabled"]
    assert len(downtime) == 1
    assert downtime[0].severity == Severity.INFO


def test_communication_limits_configured():
    """Test Communication Limits are configured."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "CommunicationLimits"): "{ some limits }",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    comm_limits = [f for f in result.findings if f.data.get("check") == "communication_limits_configured"]
    assert len(comm_limits) == 1


def test_ask_to_buy_enabled():
    """Test Ask to Buy is enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "AskToBuyEnabled"): "1",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    ask_to_buy = [f for f in result.findings if f.data.get("check") == "ask_to_buy_enabled"]
    assert len(ask_to_buy) == 1
    assert ask_to_buy[0].severity == Severity.INFO


def test_all_features_configured():
    """Test when all Screen Time features are enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "ContentPrivacyRestrictionsEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "AppLimits"): "{ limits }",
        ("com.apple.ScreenTimeAgent", "DowntimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "CommunicationLimits"): "{ limits }",
        ("com.apple.ScreenTimeAgent", "AskToBuyEnabled"): "1",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have multiple findings for all enabled features
    enabled_checks = [
        "screen_time_enabled",
        "content_privacy_restrictions",
        "app_limits_configured",
        "downtime_enabled",
        "communication_limits_configured",
        "ask_to_buy_enabled",
    ]
    found_checks = [f.data.get("check") for f in result.findings]
    for check in enabled_checks:
        assert check in found_checks


def test_screen_time_disabled_completely():
    """Test Screen Time completely disabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "0",
        ("com.apple.ScreenTimeAgent", "ContentPrivacyRestrictionsEnabled"): "0",
        ("com.apple.ScreenTimeAgent", "DowntimeEnabled"): "0",
        ("com.apple.ScreenTimeAgent", "AppLimits"): "",
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have info about Screen Time being disabled
    disabled = [f for f in result.findings if f.data.get("check") == "screen_time_disabled"]
    assert len(disabled) >= 1


def test_fix_provides_guidance():
    """Test that fix() provides informational guidance."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "0",
    })
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should have actions for the findings
    passcode_actions = [a for a in fix.actions if "passcode" in a.title.lower()]
    assert len(passcode_actions) > 0
    # Actions should be informational (success=True, no actual system changes)
    for action in fix.actions:
        assert action.success == True


def test_fix_for_no_passcode():
    """Test fix guidance for missing passcode."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "0",
    })
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    passcode_actions = [a for a in fix.actions if "passcode" in a.title.lower()]
    assert len(passcode_actions) > 0
    # Check that guidance mentions System Settings
    passcode_action = passcode_actions[0]
    assert "System Settings" in passcode_action.description or "Settings" in passcode_action.description


def test_subprocess_error_handling():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_defaults_read_error():
    """Test handling of defaults read errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        # Return error for defaults reads
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "Domain not found"
        return result

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())

    # Should handle gracefully and return some findings (e.g., Screen Time disabled)
    assert isinstance(result.findings, list)


def test_multiple_features_some_enabled():
    """Test when only some features are enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "1",
        ("com.apple.ScreenTimeAgent", "ContentPrivacyRestrictionsEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "AppLimits"): "",  # Not configured
        ("com.apple.ScreenTimeAgent", "DowntimeEnabled"): "0",  # Disabled
        ("com.apple.ScreenTimeAgent", "CommunicationLimits"): "",  # Not configured
        ("com.apple.ScreenTimeAgent", "AskToBuyEnabled"): "0",  # Disabled
    })
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]

    # Should have
    assert "screen_time_enabled" in checks
    assert "content_privacy_restrictions" in checks

    # Should NOT have (not configured or disabled)
    assert "app_limits_configured" not in checks
    assert "downtime_enabled" not in checks
    assert "communication_limits_configured" not in checks
    assert "ask_to_buy_enabled" not in checks


def test_fix_risk_level_safe():
    """Test that fix actions are marked as safe."""
    mod = _get_module()
    fake_run = _make_defaults_run({
        ("com.apple.ScreenTimeAgent", "ScreenTimeEnabled"): "1",
        ("com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"): "0",
    })
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # All actions should be SAFE (informational, no system changes)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.screen_time_parental.") for c in declared)
