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
    return next(m for m in modules if m.name == "network_interfaces_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_network():
    """Normal healthy network configuration with Ethernet and Wi-Fi"""

    def fake_run(cmd, **kwargs):
        if "-listallnetworkservices" in cmd:
            return _make_subprocess_result("Ethernet\nWi-Fi\n")
        elif "-listnetworkserviceorder" in cmd:
            return _make_subprocess_result(
                "(1) Ethernet (en0)\n(2) Wi-Fi (en1)\n"
            )
        elif "-getinfo" in cmd and "Ethernet" in cmd:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\n"
                "Subnet Mask: 255.255.255.0\n"
                "Router: 192.168.1.1\n"
                "IPv6 Address: fe80::1\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en0\n"
            )
        elif "-getinfo" in cmd and "Wi-Fi" in cmd:
            return _make_subprocess_result(
                "IP Address: 192.168.1.101\n"
                "Router: 192.168.1.1\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en1\n"
            )
        elif "-getdnsservers" in cmd:
            return _make_subprocess_result("8.8.8.8\n8.8.4.4\n")
        elif "-getipv6" in cmd:
            return _make_subprocess_result("Automatic\n")
        return _make_subprocess_result("")

    return fake_run


def _fake_run_self_assigned_ip():
    """Network with self-assigned IP (DHCP failure)"""

    def fake_run(cmd, **kwargs):
        if "-listallnetworkservices" in cmd:
            return _make_subprocess_result("Wi-Fi\n")
        elif "-listnetworkserviceorder" in cmd:
            return _make_subprocess_result("(1) Wi-Fi (en0)\n")
        elif "-getinfo" in cmd:
            return _make_subprocess_result(
                "IP Address: 169.254.1.1\n"
                "Subnet Mask: 255.255.0.0\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en0\n"
            )
        elif "-getdnsservers" in cmd:
            return _make_subprocess_result("8.8.8.8\n")
        elif "-getipv6" in cmd:
            return _make_subprocess_result("Automatic\n")
        return _make_subprocess_result("")

    return fake_run


def _fake_run_problematic_dns():
    """Network with problematic DNS configuration"""

    def fake_run(cmd, **kwargs):
        if "-listallnetworkservices" in cmd:
            return _make_subprocess_result("Ethernet\n")
        elif "-listnetworkserviceorder" in cmd:
            return _make_subprocess_result("(1) Ethernet (en0)\n")
        elif "-getinfo" in cmd:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\n"
                "Router: 192.168.1.1\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en0\n"
            )
        elif "-getdnsservers" in cmd:
            return _make_subprocess_result("127.0.0.1\n")
        elif "-getipv6" in cmd:
            return _make_subprocess_result("Automatic\n")
        return _make_subprocess_result("")

    return fake_run


def _fake_run_vpn_interface():
    """Network with VPN interface"""

    def fake_run(cmd, **kwargs):
        if "-listallnetworkservices" in cmd:
            return _make_subprocess_result("Wi-Fi\nVPN (OpenVPN)\n")
        elif "-listnetworkserviceorder" in cmd:
            return _make_subprocess_result("(1) Wi-Fi (en0)\n(2) VPN (utun0)\n")
        elif "-getinfo" in cmd and "Wi-Fi" in cmd:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\n"
                "Router: 192.168.1.1\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en0\n"
            )
        elif "-getinfo" in cmd and "VPN" in cmd:
            return _make_subprocess_result(
                "IP Address: 10.8.0.2\n"
                "Router: 10.8.0.1\n"
                "Interface Name: utun0\n"
            )
        elif "-getdnsservers" in cmd:
            return _make_subprocess_result("8.8.8.8\n")
        elif "-getipv6" in cmd:
            return _make_subprocess_result("Off\n")
        return _make_subprocess_result("")

    return fake_run


def _fake_run_ipv6_disabled():
    """Network with IPv6 disabled"""

    def fake_run(cmd, **kwargs):
        if "-listallnetworkservices" in cmd:
            return _make_subprocess_result("Ethernet\n")
        elif "-listnetworkserviceorder" in cmd:
            return _make_subprocess_result("(1) Ethernet (en0)\n")
        elif "-getinfo" in cmd:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\n"
                "Router: 192.168.1.1\n"
                "DHCP Configuration: Enabled\n"
                "Interface Name: en0\n"
            )
        elif "-getdnsservers" in cmd:
            return _make_subprocess_result("8.8.8.8\n")
        elif "-getipv6" in cmd:
            return _make_subprocess_result("Off\n")
        return _make_subprocess_result("")

    return fake_run


def _fake_run_service_retrieval_error():
    """Service retrieval fails"""

    def fake_run(cmd, **kwargs):
        return _make_subprocess_result("", "Error", 1)

    return fake_run


def test_network_interfaces_check_discovered():
    mod = _get_module()
    assert mod.name == "network_interfaces_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_interfaces_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_network()):
        result = mod.check(_make_profile())
    # Should have at least interface summary
    assert any(f.data.get("check") == "interface_summary" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_network_interfaces_check_self_assigned_ip():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "self_assigned_ip" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_network_interfaces_check_problematic_dns():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_problematic_dns()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "problematic_dns" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_network_interfaces_check_vpn_interface():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_interface()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "vpn_interface" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_network_interfaces_check_ipv6_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_ipv6_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "ipv6_disabled" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_network_interfaces_check_service_retrieval_error():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_service_retrieval_error()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "services_retrieval" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_network_interfaces_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
