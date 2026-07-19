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
    return next(m for m in modules if m.name == "vpn_config")


def _fake_scutil_run(vpn_list_output, status_output=None):
    """Create a fake subprocess.run for scutil commands."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list) and len(cmd) >= 3:
            if cmd[1] == "--nc" and cmd[2] == "list":
                result.stdout = vpn_list_output
            elif cmd[1] == "--nc" and cmd[2] == "status":
                result.stdout = status_output or "Connected"

        return result
    return fake_run


def _fake_systemextensionsctl_run(extension_output):
    """Create a fake subprocess.run for systemextensionsctl commands."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list) and "systemextensionsctl" in cmd:
            result.stdout = extension_output

        return result
    return fake_run


def test_vpn_config_discovered():
    """Test that the module is discovered."""
    mod = _get_module()
    assert mod.name == "vpn_config"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "security"


def test_vpn_config_no_vpn():
    """Test when no VPN is configured."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run("")):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) >= 1
    # First finding should be about no VPN
    no_vpn_finding = next(
        (f for f in result.findings if f.data.get("check") == "no_vpn"),
        None
    )
    assert no_vpn_finding is not None
    assert no_vpn_finding.severity == Severity.INFO


def test_vpn_config_with_ikev2():
    """Test when IKEv2 VPN is configured."""
    vpn_list_output = """
    *
    0. VPN-IKEv2 : IKEv2
    1. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have a finding about the VPN list
    vpn_list_finding = next(
        (f for f in result.findings if f.data.get("check") == "vpn_list"),
        None
    )
    assert vpn_list_finding is not None
    assert "IKEv2" in vpn_list_finding.description


def test_vpn_config_with_pptp():
    """Test when PPTP VPN is configured (should warn)."""
    vpn_list_output = """
    *
    0. VPN-Legacy : PPTP
    1. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have a CRITICAL warning about PPTP
    pptp_finding = next(
        (f for f in result.findings if f.data.get("check") == "pptp_detected"),
        None
    )
    assert pptp_finding is not None
    assert pptp_finding.severity == Severity.WARNING
    assert "PPTP" in pptp_finding.description


def test_vpn_config_with_l2tp():
    """Test when L2TP VPN is configured."""
    vpn_list_output = """
    *
    0. VPN-L2TP : L2TP
    1. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    vpn_list_finding = next(
        (f for f in result.findings if f.data.get("check") == "vpn_list"),
        None
    )
    assert vpn_list_finding is not None
    assert "L2TP" in vpn_list_finding.description


def test_vpn_config_with_openvpn():
    """Test when OpenVPN is configured."""
    vpn_list_output = """
    *
    0. My-OpenVPN : OpenVPN
    1. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    vpn_list_finding = next(
        (f for f in result.findings if f.data.get("check") == "vpn_list"),
        None
    )
    assert vpn_list_finding is not None
    assert "OpenVPN" in vpn_list_finding.description


def test_vpn_config_multiple_vpns():
    """Test when multiple VPNs are configured."""
    vpn_list_output = """
    *
    0. VPN-IKEv2 : IKEv2
    1. VPN-L2TP : L2TP
    2. VPN-Legacy : PPTP
    3. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have warning about PPTP
    pptp_finding = next(
        (f for f in result.findings if f.data.get("check") == "pptp_detected"),
        None
    )
    assert pptp_finding is not None

    # Should have info about all VPNs
    vpn_list_finding = next(
        (f for f in result.findings if f.data.get("check") == "vpn_list"),
        None
    )
    assert vpn_list_finding is not None
    assert vpn_list_finding.data["vpn_count"] == 3


def test_vpn_config_with_third_party_apps():
    """Test detection of third-party VPN apps."""
    vpn_list_output = ""
    extension_output = """
    com.mullvad.vpn [enabled]
    com.expressvpn.app [enabled]
    """

    mod = _get_module()

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if isinstance(cmd, list):
            if "scutil" in cmd:
                result.stdout = vpn_list_output
            elif "systemextensionsctl" in cmd:
                result.stdout = extension_output

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    # Should have finding about third-party apps
    third_party_finding = next(
        (f for f in result.findings if f.data.get("check") == "third_party_vpns"),
        None
    )
    assert third_party_finding is not None
    assert len(third_party_finding.data["apps"]) > 0


def test_vpn_config_fix_no_vpn():
    """Test fix action for no VPN configured."""
    vpn_list_output = ""

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should succeed (they're informational)
    assert all(a.success for a in fix.actions)


def test_vpn_config_fix_pptp_warning():
    """Test fix action for PPTP warning."""
    vpn_list_output = """
    *
    0. VPN-Legacy : PPTP
    1. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions for PPTP and VPN list
    assert len(fix.actions) >= 2
    # All actions should succeed (they're informational)
    assert all(a.success for a in fix.actions)
    # Should have guidance about replacing PPTP
    pptp_actions = [a for a in fix.actions if "PPTP" in a.title or "PPTP" in a.description]
    assert len(pptp_actions) > 0


def test_vpn_config_fix_multiple_vpns():
    """Test fix action for multiple VPNs."""
    vpn_list_output = """
    *
    0. VPN-IKEv2 : IKEv2
    1. VPN-L2TP : L2TP
    2. Wi-Fi : Wi-Fi
    """

    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_scutil_run(vpn_list_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # Should have actions
    assert len(fix.actions) > 0
    # All actions should succeed (they're informational)
    assert all(a.success for a in fix.actions)


def test_vpn_config_scutil_error():
    """Test graceful handling of scutil errors."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "Error"
        result.stdout = ""
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    # Should still complete without crashing
    # Will report no VPN found
    assert isinstance(result, type(mod.check(_make_profile())))


def test_vpn_config_extract_vpn_name():
    """Test VPN name extraction from scutil output."""
    mod = _get_module()

    # Test various formats
    line1 = "0. My-VPN : IKEv2"
    name1 = mod._extract_vpn_name(line1)
    assert "My-VPN" in name1 or "VPN" in name1

    line2 = "VPN-Service : L2TP"
    name2 = mod._extract_vpn_name(line2)
    assert "VPN-Service" in name2 or "Service" in name2


def test_vpn_config_extract_vpn_type():
    """Test VPN type extraction from scutil output."""
    mod = _get_module()

    assert mod._extract_vpn_type("0. VPN : IKEv2") == "IKEv2"
    assert mod._extract_vpn_type("0. VPN : L2TP") == "L2TP"
    assert mod._extract_vpn_type("0. VPN : PPTP") == "PPTP"
    assert mod._extract_vpn_type("0. VPN : OpenVPN") == "OpenVPN"
    assert mod._extract_vpn_type("0. VPN : WiFi") is None


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.vpn_config.") for c in declared)
