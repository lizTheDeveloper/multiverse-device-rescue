import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import socket
import subprocess

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
    return next(m for m in modules if m.name == "network_diagnostics")


class TestNetworkDiagnosticsDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "network_diagnostics"
        assert mod.category == "integrity"
        assert mod.risk_level == RiskLevel.SAFE


class TestDNSResolution:
    def test_dns_resolution_works(self):
        mod = _get_module()
        with patch("socket.getaddrinfo") as mock_socket:
            mock_socket.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "google.com", ("142.250.80.46", 80))
            ]
            result = mod.check(_make_profile())
        # Should not have a DNS resolution finding
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 0

    def test_dns_resolution_fails(self):
        mod = _get_module()
        with patch("socket.getaddrinfo") as mock_socket:
            mock_socket.side_effect = socket.gaierror("Name or service not known")
            result = mod.check(_make_profile())
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.CRITICAL
        assert "DNS resolution failed" in dns_findings[0].title

    def test_dns_resolution_oserror(self):
        mod = _get_module()
        with patch("socket.getaddrinfo") as mock_socket:
            mock_socket.side_effect = OSError("Network is unreachable")
            result = mod.check(_make_profile())
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.CRITICAL


class TestDNSServers:
    def test_dns_servers_configured(self):
        mod = _get_module()
        dns_output = """
DNS configuration
resolver #0
  search domain[0] : local
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
"""
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 0
                result_mock.stdout = dns_output
                mock_run.return_value = result_mock
                result = mod.check(_make_profile())
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_servers"]
        assert len(dns_findings) == 0

    def test_dns_servers_not_configured(self):
        mod = _get_module()
        dns_output = "DNS configuration\nNo nameservers configured\n"
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 0
                result_mock.stdout = dns_output
                mock_run.return_value = result_mock
                result = mod.check(_make_profile())
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_servers"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.WARNING
        assert "No DNS servers configured" in dns_findings[0].title

    def test_scutil_dns_fails(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 1
                result_mock.stdout = ""
                mock_run.return_value = result_mock
                result = mod.check(_make_profile())
        # Should not crash and should not add dns_servers findings
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_servers"]
        assert len(dns_findings) == 0

    def test_scutil_dns_timeout(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    if cmd[0] == "scutil":
                        raise subprocess.TimeoutExpired(cmd, 5)
                    result_mock = MagicMock()
                    result_mock.returncode = 0
                    result_mock.stdout = ""
                    return result_mock

                mock_run.side_effect = side_effect
                # Should handle timeout gracefully
                result = mod.check(_make_profile())
        assert isinstance(result.findings, list)


class TestNetworkInterfaces:
    def test_all_interfaces_up(self):
        mod = _get_module()
        ifconfig_output = """lo0: flags=8049<UP,LOOPBACK,RUNNING,SIMPLEX> mtu 16384
	options=680003<RXCSUM,TXCSUM,LINKSTATE,RXCSUM_IPV6,TXCSUM_IPV6>
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400009b<RXCSUM,TXCSUM,VLAN_MTU,WOL,RXCSUM_IPV6,TXCSUM_IPV6>
	inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
"""
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    result_mock = MagicMock()
                    if cmd[0] == "ifconfig":
                        result_mock.returncode = 0
                        result_mock.stdout = ifconfig_output
                    else:
                        result_mock.returncode = 0
                        result_mock.stdout = ""
                    return result_mock

                mock_run.side_effect = side_effect
                result = mod.check(_make_profile())

        interface_findings = [f for f in result.findings if f.data.get("check_type") == "network_interfaces"]
        assert len(interface_findings) == 0

    def test_interface_down(self):
        mod = _get_module()
        ifconfig_output = """lo0: flags=8049<UP,LOOPBACK,RUNNING,SIMPLEX> mtu 16384
	options=680003<RXCSUM,TXCSUM,LINKSTATE,RXCSUM_IPV6,TXCSUM_IPV6>
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
	options=400009b<RXCSUM,TXCSUM,VLAN_MTU,WOL,RXCSUM_IPV6,TXCSUM_IPV6>
"""
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    result_mock = MagicMock()
                    result_mock.returncode = 0
                    result_mock.stdout = ifconfig_output if cmd[0] == "ifconfig" else ""
                    return result_mock

                mock_run.side_effect = side_effect
                result = mod.check(_make_profile())

        interface_findings = [f for f in result.findings if f.data.get("check_type") == "network_interfaces"]
        assert len(interface_findings) == 1
        assert "en0" in interface_findings[0].title
        assert interface_findings[0].severity == Severity.WARNING

    def test_ifconfig_fails(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 1
                result_mock.stdout = ""
                mock_run.return_value = result_mock
                result = mod.check(_make_profile())

        interface_findings = [f for f in result.findings if f.data.get("check_type") == "network_interfaces"]
        assert len(interface_findings) == 0


class TestGatewayReachability:
    def test_gateway_reachable(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    result_mock = MagicMock()
                    if cmd[0] == "ping":
                        result_mock.returncode = 0  # Ping successful
                    else:
                        result_mock.returncode = 0
                        result_mock.stdout = ""
                    return result_mock

                mock_run.side_effect = side_effect
                result = mod.check(_make_profile())

        gateway_findings = [f for f in result.findings if f.data.get("check_type") == "gateway"]
        assert len(gateway_findings) == 0

    def test_gateway_unreachable(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 1  # Ping failed
                result_mock.stdout = ""
                mock_run.return_value = result_mock
                result = mod.check(_make_profile())

        gateway_findings = [f for f in result.findings if f.data.get("check_type") == "gateway"]
        assert len(gateway_findings) == 1
        assert gateway_findings[0].severity == Severity.CRITICAL
        assert "Default gateway is unreachable" in gateway_findings[0].title

    def test_ping_timeout(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    if cmd[0] == "ping":
                        raise subprocess.TimeoutExpired(cmd, 3)
                    result_mock = MagicMock()
                    result_mock.returncode = 0
                    result_mock.stdout = ""
                    return result_mock

                mock_run.side_effect = side_effect
                result = mod.check(_make_profile())

        gateway_findings = [f for f in result.findings if f.data.get("check_type") == "gateway"]
        assert len(gateway_findings) == 0  # Should handle gracefully


class TestFix:
    def test_fix_dns_resolution_failure(self):
        mod = _get_module()
        with patch("socket.getaddrinfo") as mock_socket:
            mock_socket.side_effect = socket.gaierror("Name or service not known")
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    result_mock = MagicMock()
                    result_mock.returncode = 0
                    result_mock.stdout = ""
                    return result_mock

                mock_run.side_effect = side_effect
                check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        # Check that we have at least one action for DNS resolution failure
        dns_actions = [a for a in fix.actions if "DNS resolution failed" in a.title]
        assert len(dns_actions) == 1
        assert fix.actions[0].risk_level == RiskLevel.SAFE

    def test_fix_no_dns_servers(self):
        mod = _get_module()
        dns_output = "DNS configuration\nNo nameservers configured\n"
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 0
                result_mock.stdout = dns_output
                mock_run.return_value = result_mock
                check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        dns_actions = [a for a in fix.actions if "DNS servers unresponsive" in a.title]
        assert len(dns_actions) == 1
        assert fix.actions[0].risk_level == RiskLevel.SAFE

    def test_fix_gateway_unreachable(self):
        mod = _get_module()
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 1
                result_mock.stdout = ""
                mock_run.return_value = result_mock
                check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        assert len(fix.actions) >= 1
        gateway_actions = [a for a in fix.actions if "gateway" in a.title.lower()]
        assert len(gateway_actions) == 1
        assert fix.actions[0].risk_level == RiskLevel.SAFE

    def test_fix_interface_down(self):
        mod = _get_module()
        ifconfig_output = """en0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
	options=400009b<RXCSUM,TXCSUM,VLAN_MTU,WOL,RXCSUM_IPV6,TXCSUM_IPV6>
"""
        with patch("socket.getaddrinfo"):
            with patch("subprocess.run") as mock_run:
                result_mock = MagicMock()
                result_mock.returncode = 0
                result_mock.stdout = ifconfig_output
                mock_run.return_value = result_mock
                check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        interface_actions = [a for a in fix.actions if "en0" in a.title]
        assert len(interface_actions) == 1


class TestMultipleIssues:
    def test_multiple_issues_found(self):
        mod = _get_module()
        ifconfig_output = """en0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
	options=400009b<RXCSUM,TXCSUM,VLAN_MTU,WOL,RXCSUM_IPV6,TXCSUM_IPV6>
"""
        dns_output = "DNS configuration\nNo nameservers configured\n"

        with patch("socket.getaddrinfo") as mock_socket:
            mock_socket.side_effect = socket.gaierror("Name or service not known")
            with patch("subprocess.run") as mock_run:
                def side_effect(cmd, *args, **kwargs):
                    result_mock = MagicMock()
                    if cmd[0] == "ping":
                        result_mock.returncode = 1
                    else:
                        result_mock.returncode = 0
                        result_mock.stdout = ifconfig_output if cmd[0] == "ifconfig" else dns_output
                    return result_mock

                mock_run.side_effect = side_effect
                result = mod.check(_make_profile())

        assert result.has_issues
        assert len(result.findings) >= 3  # DNS resolution, DNS servers, interface, and gateway


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
