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
    return next(m for m in modules if m.name == "find_my_mac")


def _fake_run(outputs):
    """Factory that returns a function simulating subprocess.run with multiple calls."""
    call_count = [0]

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if call_count[0] < len(outputs):
            result.stdout = outputs[call_count[0]]
            result.returncode = 0
        call_count[0] += 1
        return result

    return fake_run


def test_find_my_mac_discovered():
    mod = _get_module()
    assert mod.name == "find_my_mac"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_find_my_mac_enabled():
    """All Find My Mac features are enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["1", "1", "fmm-mobileme-token\n"]),
    ):
        result = mod.check(_make_profile())
    # Should have one INFO finding about proper configuration
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    assert any("properly configured" in f.title.lower() for f in info_findings)


def test_find_my_mac_disabled():
    """Find My Mac is disabled - CRITICAL."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["0", "1", "fmm-mobileme-token\n"]),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "Find My Mac is disabled" in critical_findings[0].title


def test_send_last_location_disabled():
    """Send Last Location is disabled - WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["1", "0", "fmm-mobileme-token\n"]),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert "Send Last Location is disabled" in warning_findings[0].title


def test_activation_lock_unknown():
    """Activation Lock status is not present in nvram - still INFO."""
    mod = _get_module()
    # When nvram returns output without fmm-mobileme-token, activation_lock is False
    # but Find My Mac and Send Last Location are enabled, so we get "properly configured"
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["1", "1", "other-token\n"]),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("properly configured" in f.title.lower() for f in info_findings)


def test_find_my_mac_all_disabled():
    """All features are disabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["0", "0", ""]),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have at least CRITICAL for Find My Mac disabled
    assert len(critical_findings) > 0


def test_find_my_mac_fix():
    """fix() returns informational actions."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(["0", "0", ""]),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # All actions should succeed (informational)
    assert fix.all_succeeded
    # Should have actions for enabling Find My Mac
    assert any("Find My Mac" in a.title for a in fix.actions)
    # Actions should reference System Settings
    assert any("System Settings" in a.description for a in fix.actions)
