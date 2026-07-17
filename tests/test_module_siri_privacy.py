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
    return next(m for m in modules if m.name == "siri_privacy")


def _fake_defaults_run(
    siri_enabled=False,
    hey_siri=False,
    siri_suggestions=False,
    siri_analytics=False,
    lockscreen_siri=False,
    error=None,
):
    """Mock subprocess.run for defaults read calls."""

    def fake_run(cmd, **kwargs):
        if error:
            raise error

        result = MagicMock()
        result.returncode = 0

        # Handle defaults read commands
        if len(cmd) >= 3 and cmd[0] == "defaults" and cmd[1] == "read":
            if cmd[2] == "com.apple.assistant.support":
                if len(cmd) > 3:
                    key = cmd[3]
                    if key == "Assistant Enabled":
                        result.stdout = "1" if siri_enabled else "0"
                    elif key == "Dictation Enabled":
                        result.stdout = "1" if hey_siri else "0"
                    elif key == "Siri Data Collection Opt-In":
                        result.stdout = "1" if siri_suggestions else "0"
                    elif key == "Siri Analytics Opt-In":
                        result.stdout = "1" if siri_analytics else "0"
                    else:
                        result.returncode = 1
                        result.stdout = ""
            elif cmd[2] == "com.apple.Siri":
                if len(cmd) > 3:
                    key = cmd[3]
                    if key == "LockscreenEnabled":
                        result.stdout = "1" if lockscreen_siri else "0"
                    else:
                        result.returncode = 1
                        result.stdout = ""
            else:
                result.returncode = 1
                result.stdout = ""
        else:
            raise AssertionError(f"unexpected command {cmd}")

        return result

    return fake_run


def test_siri_privacy_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "siri_privacy"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_siri_privacy_all_disabled():
    """Test when all Siri features are disabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run()):
        result = mod.check(_make_profile())

    # Should have INFO findings about configuration status
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_siri_privacy_siri_enabled():
    """Test when Siri is enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(siri_enabled=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("enabled" in f.title.lower() for f in info_findings)
    # Should report Siri enabled status
    assert any("Siri is enabled" in f.title for f in info_findings)


def test_siri_privacy_hey_siri_enabled():
    """Test when Hey Siri listening is enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(hey_siri=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("Hey Siri" in f.title for f in info_findings)


def test_siri_privacy_siri_suggestions_enabled():
    """Test when Siri Suggestions are enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(siri_suggestions=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("Suggestions" in f.title for f in info_findings)


def test_siri_privacy_siri_analytics_enabled():
    """Test when Siri analytics is enabled."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(siri_analytics=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("analytics" in f.title.lower() for f in info_findings)


def test_siri_privacy_lockscreen_enabled_warning():
    """Test that Siri on lock screen is flagged as WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(lockscreen_siri=True)):
        result = mod.check(_make_profile())

    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    # Should specifically warn about lock screen security risk
    assert any("lock screen" in f.title.lower() for f in warning_findings)
    assert any("security risk" in f.description.lower() for f in warning_findings)


def test_siri_privacy_all_enabled():
    """Test when all Siri features are enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_defaults_run(
            siri_enabled=True,
            hey_siri=True,
            siri_suggestions=True,
            siri_analytics=True,
            lockscreen_siri=True,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have multiple INFO findings and one WARNING
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(info_findings) >= 4
    assert len(warning_findings) == 1  # Only lock screen is WARNING


def test_siri_privacy_subprocess_error():
    """Test graceful handling of defaults errors."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_defaults_run(error=OSError("not found"))
    ):
        result = mod.check(_make_profile())

    # Should not crash, should report default values (no Siri features)
    assert result.has_issues


def test_siri_privacy_fix_is_informational():
    """Test that fix() is informational and doesn't modify system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed but only provide guidance
    assert fix.all_succeeded
    for action in fix.actions:
        # Actions should be informational, suggesting settings
        assert (
            "consider" in action.title.lower()
            or "review" in action.title.lower()
            or "disable" in action.title.lower()
        )


def test_siri_privacy_fix_provides_guidance():
    """Test that fix actions provide specific guidance."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_defaults_run(
            siri_enabled=True, lockscreen_siri=True, hey_siri=True
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) >= 3
    # Check that descriptions contain System Settings guidance
    all_descriptions = "\n".join(a.description for a in fix.actions)
    assert "System Settings" in all_descriptions


def test_siri_privacy_lockscreen_finding_details():
    """Test that lock screen finding includes security impact details."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_defaults_run(lockscreen_siri=True)):
        result = mod.check(_make_profile())

    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    finding = warning_findings[0]
    assert "bypass" in finding.description.lower() or "security" in finding.description.lower()
