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
    return next(m for m in modules if m.name == "vpn_leak_check")


def _fake_run_no_vpn():
    """Mock subprocess for no VPN configured."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list) and "scutil" in cmd[0] and "--nc" in cmd:
            result.stdout = "* (none)\n"
        elif isinstance(cmd, list) and "netstat" in cmd[0]:
            result.stdout = """Routing tables

Internet:
Destination        Gateway            Flags           Netif
default            192.168.1.1        UGc             en0
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_vpn_connected_no_leak():
    """Mock subprocess for VPN connected with no DNS leak."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list) and "scutil" in cmd[0] and "--nc" in cmd:
            if "list" in cmd:
                result.stdout = """(
    'ProtonVPN' : {
        ID : 'com.protonvpn.ios'
        State : Connected
    }
)
"""
            elif "status" in cmd and "ProtonVPN" in cmd:
                result.stdout = "Connected\n"
            elif "status" in cmd:
                result.stdout = "Not Connected\n"
        elif isinstance(cmd, list) and "scutil" in cmd[0] and "--dns" in cmd:
            result.stdout = """DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 185.217.116.16
  nameserver[1] : 185.217.117.16
"""
        elif isinstance(cmd, list) and "netstat" in cmd[0]:
            result.stdout = """Routing tables

Internet:
Destination        Gateway            Flags           Netif
default            192.168.1.1        UGc             utun0
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_vpn_connected_dns_leak():
    """Mock subprocess for VPN connected with DNS leak."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list) and "scutil" in cmd[0] and "--nc" in cmd:
            if "list" in cmd:
                result.stdout = """(
    'ExpressVPN' : {
        ID : 'com.expressvpn.ios'
        State : Connected
    }
)
"""
            elif "status" in cmd and "ExpressVPN" in cmd:
                result.stdout = "Connected\n"
            elif "status" in cmd:
                result.stdout = "Not Connected\n"
        elif isinstance(cmd, list) and "scutil" in cmd[0] and "--dns" in cmd:
            result.stdout = """DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 8.8.8.8
  nameserver[1] : 1.1.1.1
"""
        elif isinstance(cmd, list) and "netstat" in cmd[0]:
            result.stdout = """Routing tables

Internet:
Destination        Gateway            Flags           Netif
default            192.168.1.1        UGc             utun0
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_vpn_connected_split_tunnel():
    """Mock subprocess for VPN connected with split tunneling."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list) and "scutil" in cmd[0] and "--nc" in cmd:
            if "list" in cmd:
                result.stdout = """(
    'NordVPN' : {
        ID : 'com.nordvpn.ios'
        State : Connected
    }
)
"""
            elif "status" in cmd and "NordVPN" in cmd:
                result.stdout = "Connected\n"
            elif "status" in cmd:
                result.stdout = "Not Connected\n"
        elif isinstance(cmd, list) and "scutil" in cmd[0] and "--dns" in cmd:
            result.stdout = """DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 103.86.96.100
  nameserver[1] : 103.86.99.100
"""
        elif isinstance(cmd, list) and "netstat" in cmd[0]:
            result.stdout = """Routing tables

Internet:
Destination        Gateway            Flags           Netif
default            192.168.1.1        UGc             en0
default            10.0.0.1           UGc             utun0
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def _fake_run_vpn_not_connected():
    """Mock subprocess for VPN configured but not connected."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list) and "scutil" in cmd[0] and "--nc" in cmd:
            if "list" in cmd:
                result.stdout = """(
    'WireGuard' : {
        ID : 'com.wireguard.ios'
        State : Disconnected
    }
)
"""
            elif "status" in cmd:
                result.stdout = "Not Connected\n"
        elif isinstance(cmd, list) and "scutil" in cmd[0] and "--dns" in cmd:
            result.stdout = """DNS configuration:

resolver #0
  search domain[0] : local
  nameserver[0] : 8.8.8.8
"""
        elif isinstance(cmd, list) and "netstat" in cmd[0]:
            result.stdout = """Routing tables

Internet:
Destination        Gateway            Flags           Netif
default            192.168.1.1        UGc             en0
"""
        else:
            result.stdout = ""
        return result
    return fake_run


def test_vpn_leak_check_discovered():
    mod = _get_module()
    assert mod.name == "vpn_leak_check"
    assert mod.category == "network"
    assert mod.risk_level == RiskLevel.SAFE


def test_vpn_leak_check_no_vpn():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_vpn()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "no_vpns_configured" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_vpn_leak_check_connected_no_leak():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_connected_no_leak()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "vpn_config_summary" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_vpn_leak_check_connected_dns_leak():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_connected_dns_leak()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "dns_leak" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_vpn_leak_check_connected_split_tunnel():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_connected_split_tunnel()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "split_tunneling" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_vpn_leak_check_not_connected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_not_connected()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "vpn_not_connected" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_vpn_leak_check_fix_dns_leak():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_connected_dns_leak()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("dns" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_vpn_leak_check_fix_split_tunnel():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_connected_split_tunnel()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("split" in a.title.lower() or "tunnel" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_vpn_leak_check_fix_not_connected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_vpn_not_connected()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("connect" in a.title.lower() or "vpn" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)
