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
    return next(m for m in modules if m.name == "sharing_preferences_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_disabled():
    """All sharing services disabled, AirDrop safe"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "launchctl list" in cmd_str:
            # No sharing services in the list
            return _make_subprocess_result(
                "this is a normal launchctl output\nno sharing services here\n"
            )
        elif "systemsetup" in cmd_str and "getremotelogin" in cmd_str:
            return _make_subprocess_result("Remote Login: Off\n")
        elif "cupsctl" in cmd_str:
            return _make_subprocess_result("_share_printers=0\n")
        elif "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("ContactsOnly\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_all_enabled():
    """All sharing services enabled, AirDrop set to Everyone"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "launchctl list" in cmd_str:
            # All sharing services enabled
            return _make_subprocess_result(
                "1234  0  com.apple.screensharing\n"
                "5678  0  com.apple.smbd\n"
                "9012  0  com.apple.ARDAgent\n"
                "3456  0  other.service\n"
            )
        elif "systemsetup" in cmd_str and "getremotelogin" in cmd_str:
            return _make_subprocess_result("Remote Login: On\n")
        elif "cupsctl" in cmd_str:
            return _make_subprocess_result("_share_printers=1\n")
        elif "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Everyone\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_screen_sharing_only():
    """Only Screen Sharing enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "launchctl list" in cmd_str:
            return _make_subprocess_result(
                "1234  0  com.apple.screensharing\n"
                "5678  0  other.service\n"
            )
        elif "systemsetup" in cmd_str and "getremotelogin" in cmd_str:
            return _make_subprocess_result("Remote Login: Off\n")
        elif "cupsctl" in cmd_str:
            return _make_subprocess_result("_share_printers=0\n")
        elif "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("ContactsOnly\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_airdrop_everyone():
    """Only AirDrop set to Everyone"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "launchctl list" in cmd_str:
            return _make_subprocess_result(
                "1234  0  other.service\n"
                "5678  0  another.service\n"
            )
        elif "systemsetup" in cmd_str and "getremotelogin" in cmd_str:
            return _make_subprocess_result("Remote Login: Off\n")
        elif "cupsctl" in cmd_str:
            return _make_subprocess_result("_share_printers=0\n")
        elif "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Everyone\n")
        return _make_subprocess_result()
    return fake_run


def test_sharing_preferences_audit_discovered():
    mod = _get_module()
    assert mod.name == "sharing_preferences_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_sharing_preferences_audit_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())
    assert not result.has_issues or all(
        f.severity == Severity.INFO for f in result.findings
    )


def test_sharing_preferences_audit_all_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warnings for each enabled service
    warning_count = sum(
        1 for f in result.findings if f.severity == Severity.WARNING
    )
    assert warning_count >= 5  # 5 sharing services + AirDrop


def test_sharing_preferences_audit_screen_sharing_only():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_screen_sharing_only()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "screen_sharing" for f in result.findings)


def test_sharing_preferences_audit_airdrop_everyone():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_everyone()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("service") == "airdrop" for f in result.findings)


def test_sharing_preferences_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.sharing_preferences_audit.") for c in declared)
