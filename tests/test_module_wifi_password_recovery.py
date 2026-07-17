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
    return next(m for m in modules if m.name == "wifi_password_recovery")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_networks():
    """Normal case: multiple saved networks, connected to one"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            return _make_subprocess_result(
                "Preferred networks on en0:\n"
                "Home WiFi\n"
                "Office Network\n"
                "Coffee Shop\n"
            )
        elif "airport" in cmd_str and "-I" in cmd_str:
            return _make_subprocess_result(
                "SSID: Home WiFi\n"
                "BSSID: aa:bb:cc:dd:ee:ff\n"
                "state: running\n"
                "agrctlrssi: -60\n"
                "MCS index: 7\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_too_many_networks():
    """Case: more than 30 saved networks"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            networks = ["Network " + str(i) for i in range(35)]
            output = "Preferred networks on en0:\n" + "\n".join(networks)
            return _make_subprocess_result(output)
        elif "airport" in cmd_str and "-I" in cmd_str:
            return _make_subprocess_result(
                "SSID: Network 0\n"
                "state: running\n"
                "agrctlrssi: -55\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_not_in_preferred_list():
    """Case: currently connected but not in preferred list"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            return _make_subprocess_result(
                "Preferred networks on en0:\n"
                "Home WiFi\n"
                "Office Network\n"
            )
        elif "airport" in cmd_str and "-I" in cmd_str:
            return _make_subprocess_result(
                "SSID: Guest Network\n"
                "state: running\n"
                "agrctlrssi: -65\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_saved_networks():
    """Case: no saved networks"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            return _make_subprocess_result("Preferred networks on en0:\n")
        elif "airport" in cmd_str and "-I" in cmd_str:
            return _make_subprocess_result(
                "state: running\n"
                "agrctlrssi: -50\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_not_connected():
    """Case: no current connection"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            return _make_subprocess_result(
                "Preferred networks on en0:\n"
                "Home WiFi\n"
                "Office Network\n"
            )
        elif "airport" in cmd_str and "-I" in cmd_str:
            return _make_subprocess_result(
                "SSID: <none>\n"
                "state: init\n"
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_query_failed():
    """Case: networksetup command fails"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networksetup" in cmd_str and "listpreferredwirelessnetworks" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="Error")
        return _make_subprocess_result()

    return fake_run


def test_wifi_password_recovery_discovered():
    mod = _get_module()
    assert mod.name == "wifi_password_recovery"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_wifi_password_recovery_healthy():
    """Test normal case with multiple saved networks"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_networks()):
        result = mod.check(_make_profile())
    # Should have INFO findings about networks
    assert result.has_issues
    assert any(f.data.get("check") == "saved_networks_info" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should not have warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_password_recovery_too_many_networks():
    """Test warning for too many saved networks"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_too_many_networks()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "too_many_networks" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_password_recovery_not_in_preferred_list():
    """Test warning when connected but not in preferred list"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_in_preferred_list()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("check") == "current_not_in_preferred" for f in result.findings
    )
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_password_recovery_no_saved_networks():
    """Test normal case with no saved networks"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_saved_networks()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_saved_networks" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_wifi_password_recovery_not_connected():
    """Test case where no network is currently connected"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_connected()):
        result = mod.check(_make_profile())
    # Should have INFO about saved networks, no warnings about current connection
    assert result.has_issues
    assert any(f.data.get("check") == "saved_networks_info" for f in result.findings)


def test_wifi_password_recovery_query_failed():
    """Test handling of failed networksetup command"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_query_failed()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "unable_to_query" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_password_recovery_fix_is_informational():
    """Test that fix() returns informational actions only"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_networks()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_wifi_password_recovery_no_password_extraction():
    """Verify that the module does NOT extract passwords"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_networks()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Check that no actions contain password-extraction language
    for action in fix.actions:
        # Verify it mentions Keychain Access for finding passwords
        if "saved_networks" in action.title.lower():
            assert "Keychain Access" in action.description
            assert "NOT extract" in action.description or "not extract" in action.description.lower()
