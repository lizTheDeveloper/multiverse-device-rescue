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
    return next(m for m in modules if m.name == "privacy_audit")


def _fake_run(**defaults_responses):
    """Mock subprocess.run for defaults read commands.

    Args:
        defaults_responses: dict mapping preference paths to return values
    """
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        # Handle defaults read commands
        if isinstance(cmd, list) and "defaults" in cmd and "read" in cmd:
            # Extract the domain/path and key from the command
            try:
                if "-g" in cmd:
                    # Global preference
                    idx = cmd.index("-g")
                    key = cmd[idx + 1] if idx + 1 < len(cmd) else ""
                    full_key = f"-g {key}"
                else:
                    # Domain-specific preference
                    idx = cmd.index("read")
                    domain = cmd[idx + 1] if idx + 1 < len(cmd) else ""
                    key = cmd[idx + 2] if idx + 2 < len(cmd) else ""
                    full_key = f"{domain} {key}"

                if full_key in defaults_responses:
                    result.stdout = defaults_responses[full_key]
                else:
                    # Default: key not found
                    result.returncode = 1
                    result.stderr = f"The domain/default pair of ({full_key}) does not exist"
            except (IndexError, ValueError):
                result.returncode = 1
                result.stderr = "Invalid defaults command"

        return result

    return fake_run


def test_privacy_audit_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "privacy_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_privacy_audit_location_services_enabled():
    """Test when location services are enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "1",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "0",
            "com.apple.analytics CollectBotIdentifierEnabled": "0",
            "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled": "1",
        }
    )):
        result = mod.check(_make_profile())
    # Location services enabled is a finding
    assert result.has_issues


def test_privacy_audit_location_services_disabled():
    """Test when location services are disabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "0",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "0",
            "com.apple.analytics CollectBotIdentifierEnabled": "0",
        }
    )):
        result = mod.check(_make_profile())
    # Location services disabled is good - but might still have other issues
    # Just check it doesn't crash
    assert isinstance(result.findings, list)


def test_privacy_audit_personalized_ads_enabled():
    """Test when personalized ads are enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "0",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "1",
            "com.apple.analytics CollectBotIdentifierEnabled": "0",
        }
    )):
        result = mod.check(_make_profile())
    # Personalized ads enabled is a finding
    assert result.has_issues
    assert any(f.data.get("check") == "personalized_ads" for f in result.findings)


def test_privacy_audit_analytics_enabled():
    """Test when analytics are enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "0",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "0",
            "com.apple.analytics CollectBotIdentifierEnabled": "1",
        }
    )):
        result = mod.check(_make_profile())
    # Analytics enabled is a finding
    assert result.has_issues
    assert any(f.data.get("check") == "analytics" for f in result.findings)


def test_privacy_audit_all_secure():
    """Test when all privacy settings are secure."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "0",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "0",
            "com.apple.analytics CollectBotIdentifierEnabled": "0",
        }
    )):
        result = mod.check(_make_profile())
    # All secure - no findings
    assert not result.has_issues


def test_privacy_audit_graceful_missing_prefs():
    """Test graceful handling when preference files are missing."""
    mod = _get_module()
    # Empty responses - all preferences "not found"
    with patch("subprocess.run", side_effect=_fake_run()):
        result = mod.check(_make_profile())
    # Should not crash, should have handled missing preferences
    assert isinstance(result.findings, list)


def test_privacy_audit_fix_is_informational():
    """Test that fix() is informational and doesn't make changes."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "1",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "1",
            "com.apple.analytics CollectBotIdentifierEnabled": "1",
        }
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Fix should produce informational actions, not actual changes
    assert isinstance(fix.actions, list)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        # Informational actions should be marked as successful (no actual changes)
        assert action.success


def test_privacy_audit_all_findings_safe_risk_level():
    """Test that all findings have SAFE or INFO severity."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        **{
            "com.apple.locationd LocationServicesEnabled": "1",
            "com.apple.privacymanagementd PersonalizedAdsOptIn": "1",
            "com.apple.analytics CollectBotIdentifierEnabled": "1",
        }
    )):
        result = mod.check(_make_profile())

    # All findings should be INFO severity (informational, not critical)
    for finding in result.findings:
        assert finding.severity == Severity.INFO
