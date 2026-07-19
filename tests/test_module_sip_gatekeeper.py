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
    return next(m for m in modules if m.name == "sip_gatekeeper")


def _fake_run(sip_output, gatekeeper_output, defaults_output="1\n", set_returncode=0):
    """Fake subprocess.run for mocking csrutil, spctl, and defaults commands."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        # cmd can be a list or string, convert to string for checking
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "csrutil" in cmd_str and "status" in cmd_str:
            result.stdout = sip_output
        elif "spctl" in cmd_str and "--status" in cmd_str:
            result.stdout = gatekeeper_output
        elif "defaults" in cmd_str and "LSQuarantine" in cmd_str:
            result.stdout = defaults_output
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Operation not permitted"
        elif "spctl" in cmd_str:
            # For any other spctl command
            result.stdout = ""
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Operation not permitted"

        return result
    return fake_run


def test_sip_gatekeeper_discovered():
    mod = _get_module()
    assert mod.name == "sip_gatekeeper"
    assert mod.risk_level == RiskLevel.SAFE


def test_sip_gatekeeper_healthy():
    """SIP enabled and Gatekeeper enabled - no findings."""
    mod = _get_module()
    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=_fake_run(
        "System Integrity Protection status: enabled.\n",
        "assessments enabled\n"
    )):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_sip_disabled():
    """SIP disabled - should flag WARNING."""
    mod = _get_module()
    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=_fake_run(
        "System Integrity Protection status: disabled.\n",
        "assessments enabled\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING and "SIP" in f.title for f in result.findings)
    assert any(f.data.get("check") == "sip_status" for f in result.findings)


def test_gatekeeper_disabled():
    """Gatekeeper disabled - should flag WARNING."""
    mod = _get_module()
    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=_fake_run(
        "System Integrity Protection status: enabled.\n",
        "assessments disabled\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING and "Gatekeeper" in f.title for f in result.findings)
    assert any(f.data.get("check") == "gatekeeper_status" for f in result.findings)


def test_both_disabled():
    """Both SIP and Gatekeeper disabled - should have 2 findings."""
    mod = _get_module()
    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=_fake_run(
        "System Integrity Protection status: disabled.\n",
        "assessments disabled\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 2
    severities = [f.severity for f in result.findings]
    assert all(s == Severity.WARNING for s in severities)


def test_sip_gatekeeper_fix_is_informational():
    """fix() should be informational and not modify system."""
    mod = _get_module()
    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=_fake_run(
        "System Integrity Protection status: disabled.\n",
        "assessments disabled\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions describing how to fix
    assert len(fix.actions) > 0
    # All actions should succeed (they're just info)
    assert fix.all_succeeded
    # Actions should describe how to re-enable
    action_titles = [a.title for a in fix.actions]
    assert any("SIP" in title for title in action_titles)
    assert any("Gatekeeper" in title for title in action_titles)


def test_sip_gatekeeper_csrutil_error():
    """csrutil command error handling."""
    mod = _get_module()

    def failing_csrutil(cmd, **kwargs):
        result = MagicMock()
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "csrutil" in cmd_str:
            result.returncode = 1
            result.stderr = "Error running csrutil"
            result.stdout = ""
        else:
            result.returncode = 0
            result.stderr = ""
            result.stdout = "assessments enabled\n"
        return result

    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=failing_csrutil):
        result = mod.check(_make_profile())
        # Should handle error gracefully, not crash
        assert isinstance(result.findings, list)


def test_sip_gatekeeper_spctl_error():
    """spctl command error handling."""
    mod = _get_module()

    def failing_spctl(cmd, **kwargs):
        result = MagicMock()
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        if "spctl" in cmd_str:
            result.returncode = 1
            result.stderr = "Error running spctl"
            result.stdout = ""
        else:
            result.returncode = 0
            result.stderr = ""
            result.stdout = "System Integrity Protection status: enabled.\n"
        return result

    with patch("modules.security.sip_gatekeeper.subprocess.run", side_effect=failing_spctl):
        result = mod.check(_make_profile())
        # Should handle error gracefully
        assert isinstance(result.findings, list)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.sip_gatekeeper.") for c in declared)
