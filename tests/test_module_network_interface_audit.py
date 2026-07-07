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
    return next(m for m in modules if m.name == "network_interface_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: all interfaces healthy"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\nBluetooth PAN\n")
        elif "getinfo Wi-Fi" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo Ethernet" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.101\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo Bluetooth PAN" in cmd_str:
            return _make_subprocess_result(
                "IP Address: Not Configured\nSubnet Mask: Not Configured\nRouter: Not Configured\n"
            )
        elif "listnetworkserviceorder" in cmd_str:
            return _make_subprocess_result("1) Wi-Fi\n2) Ethernet\n3) Bluetooth PAN\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_self_assigned_ip():
    """One interface has self-assigned IP (DHCP failure)"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\n")
        elif "getinfo Wi-Fi" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 169.254.1.5\nSubnet Mask: 255.255.0.0\nRouter: Not Available\n"
            )
        elif "getinfo Ethernet" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.101\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "listnetworkserviceorder" in cmd_str:
            return _make_subprocess_result("1) Wi-Fi\n2) Ethernet\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_duplicate_ips():
    """Multiple interfaces with same IP"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Wi-Fi\nEthernet\nVPN\n")
        elif "getinfo Wi-Fi" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo Ethernet" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo VPN" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 10.0.0.5\nSubnet Mask: 255.255.255.0\nRouter: 10.0.0.1\n"
            )
        elif "listnetworkserviceorder" in cmd_str:
            return _make_subprocess_result("1) Wi-Fi\n2) Ethernet\n3) VPN\n")
        return _make_subprocess_result()

    return fake_run


def _fake_run_wifi_not_priority():
    """Wi-Fi is not first in priority order"""

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "listallnetworkservices" in cmd_str:
            return _make_subprocess_result("Ethernet\nWi-Fi\nVPN\n")
        elif "getinfo Ethernet" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.100\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo Wi-Fi" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 192.168.1.101\nSubnet Mask: 255.255.255.0\nRouter: 192.168.1.1\n"
            )
        elif "getinfo VPN" in cmd_str:
            return _make_subprocess_result(
                "IP Address: 10.0.0.5\nSubnet Mask: 255.255.255.0\nRouter: 10.0.0.1\n"
            )
        elif "listnetworkserviceorder" in cmd_str:
            return _make_subprocess_result("1) Ethernet\n2) Wi-Fi\n3) VPN\n")
        return _make_subprocess_result()

    return fake_run


def test_network_interface_audit_discovered():
    mod = _get_module()
    assert mod.name == "network_interface_audit"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_interface_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have at least INFO finding about interfaces
    assert any(f.data.get("check_type") == "interfaces_list" for f in result.findings)
    # Should not have warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_network_interface_audit_self_assigned_ip():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check_type") == "self_assigned_ip" for f in result.findings)
    assert any(
        f.severity == Severity.WARNING
        and "169.254" in f.data.get("ip", "")
        for f in result.findings
    )


def test_network_interface_audit_duplicate_ips():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_duplicate_ips()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check_type") == "duplicate_ip" for f in result.findings)
    assert any(
        f.severity == Severity.WARNING
        and len(f.data.get("interfaces", [])) > 1
        for f in result.findings
    )


def test_network_interface_audit_wifi_not_priority():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_not_priority()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check_type") == "wifi_priority" for f in result.findings)


def test_network_interface_audit_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_self_assigned_ip()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_network_interface_audit_lists_all_interfaces():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should list all interfaces
    interface_findings = [
        f for f in result.findings if f.data.get("check_type") == "interfaces_list"
    ]
    assert len(interface_findings) > 0
    # Description should contain interface names
    assert any(
        "Wi-Fi" in f.description for f in result.findings
    ) or any("Ethernet" in f.description for f in result.findings)
