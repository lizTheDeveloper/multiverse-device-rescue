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
    return next(m for m in modules if m.name == "firewall_audit")


def _fake_run(global_state_output, stealth_output, set_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "--getglobalstate" in cmd:
            result.stdout = global_state_output
        elif "--getstealthmode" in cmd:
            result.stdout = stealth_output
        elif "--setglobalstate" in cmd or "--setstealthmode" in cmd:
            result.stdout = ""
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Operation not permitted"
        return result
    return fake_run


def test_firewall_audit_discovered():
    mod = _get_module()
    assert mod.name == "firewall_audit"
    assert mod.risk_level == RiskLevel.MODERATE


def test_firewall_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is enabled. (State = 1)\n", "Stealth mode is enabled.\n"
    )):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_firewall_audit_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is enabled.\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["check"] == "global_state"


def test_firewall_audit_stealth_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is enabled. (State = 1)\n", "Stealth mode is disabled.\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["check"] == "stealth_mode"


def test_firewall_audit_fix_enables_firewall():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is disabled.\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 2


def test_firewall_audit_fix_handles_permission_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is enabled.\n", set_returncode=1
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert "Operation not permitted" in fix.actions[0].error


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.firewall_audit.") for c in declared)
