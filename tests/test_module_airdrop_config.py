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
    return next(m for m in modules if m.name == "airdrop_config")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_airdrop_everyone():
    """AirDrop set to Everyone (security risk)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Everyone\n")
        elif "defaults read" in cmd_str and "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "networksetup" in cmd_str and "getairportpower" in cmd_str:
            return _make_subprocess_result("Wi-Fi Power (en0): On\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_airdrop_contacts():
    """AirDrop set to Contacts Only (recommended)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Contacts Only\n")
        elif "defaults read" in cmd_str and "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "networksetup" in cmd_str and "getairportpower" in cmd_str:
            return _make_subprocess_result("Wi-Fi Power (en0): On\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_airdrop_off():
    """AirDrop disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Off\n")
        elif "defaults read" in cmd_str and "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "networksetup" in cmd_str and "getairportpower" in cmd_str:
            return _make_subprocess_result("Wi-Fi Power (en0): On\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_bluetooth_disabled():
    """AirDrop set to Everyone but Bluetooth disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Everyone\n")
        elif "defaults read" in cmd_str and "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("0\n")
        elif "networksetup" in cmd_str and "getairportpower" in cmd_str:
            return _make_subprocess_result("Wi-Fi Power (en0): On\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_wifi_disabled():
    """AirDrop set to Everyone but Wi-Fi disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "DiscoverableMode" in cmd_str:
            return _make_subprocess_result("Everyone\n")
        elif "defaults read" in cmd_str and "ControllerPowerState" in cmd_str:
            return _make_subprocess_result("1\n")
        elif "networksetup" in cmd_str and "getairportpower" in cmd_str:
            return _make_subprocess_result("Wi-Fi Power (en0): Off\n")
        return _make_subprocess_result()
    return fake_run


def test_airdrop_config_discovered():
    mod = _get_module()
    assert mod.name == "airdrop_config"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_airdrop_config_everyone():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_everyone()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "airdrop_mode" for f in result.findings)


def test_airdrop_config_contacts_only():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_contacts()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any(f.data.get("check") == "airdrop_mode" for f in result.findings)


def test_airdrop_config_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_off()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any(f.data.get("check") == "airdrop_mode" for f in result.findings)


def test_airdrop_config_bluetooth_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bluetooth_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "bluetooth_status" for f in result.findings)


def test_airdrop_config_wifi_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.WARNING for f in result.findings)
    assert any(f.data.get("check") == "wifi_status" for f in result.findings)


def test_airdrop_config_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_airdrop_everyone()):
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
    assert all(c.startswith("security.airdrop_config.") for c in declared)
