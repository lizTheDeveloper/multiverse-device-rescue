import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10.0.19045",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_network_diag")


class TestWinNetworkDiagDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "win_network_diag"
        assert mod.category == "integrity"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.WIN32 in mod.platforms


class TestDNSResolution:
    def test_dns_resolution_works(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "Server: 8.8.8.8\nAddress: 142.250.80.46"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 0

    def test_dns_resolution_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.WARNING
        assert "DNS resolution failed" in dns_findings[0].title

    def test_dns_resolution_timeout(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("nslookup", 5)
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.WARNING


class TestIPConfiguration:
    def test_ip_configuration_valid(self):
        mod = _get_module()
        ipconfig_output = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
"""
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ipconfig":
                    result_mock.returncode = 0
                    result_mock.stdout = ipconfig_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        ip_findings = [f for f in result.findings if f.data.get("check_type") == "ip_configuration"]
        assert len(ip_findings) == 0

    def test_no_ipv4_address(self):
        mod = _get_module()
        ipconfig_output = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
"""
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ipconfig":
                    result_mock.returncode = 0
                    result_mock.stdout = ipconfig_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        ip_findings = [f for f in result.findings if f.data.get("check_type") == "ip_configuration"]
        assert len(ip_findings) >= 1
        assert any("IPv4" in f.data.get("reason", "") for f in ip_findings)

    def test_no_dns_servers(self):
        mod = _get_module()
        ipconfig_output = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.1.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
"""
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ipconfig":
                    result_mock.returncode = 0
                    result_mock.stdout = ipconfig_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        ip_findings = [f for f in result.findings if f.data.get("check_type") == "ip_configuration"]
        assert len(ip_findings) >= 1
        assert any("DNS" in f.data.get("reason", "") for f in ip_findings)

    def test_ipconfig_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        ip_findings = [f for f in result.findings if f.data.get("check_type") == "ip_configuration"]
        assert len(ip_findings) == 0


class TestNetworkConnectivity:
    def test_network_connectivity_ok(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ping":
                    result_mock.returncode = 0
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        connectivity_findings = [f for f in result.findings if f.data.get("check_type") == "network_connectivity"]
        assert len(connectivity_findings) == 0

    def test_network_connectivity_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        connectivity_findings = [f for f in result.findings if f.data.get("check_type") == "network_connectivity"]
        assert len(connectivity_findings) == 1
        assert connectivity_findings[0].severity == Severity.WARNING
        assert "No network connectivity" in connectivity_findings[0].title

    def test_ping_timeout(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("ping", 5)
            result = mod.check(_make_profile())

        connectivity_findings = [f for f in result.findings if f.data.get("check_type") == "network_connectivity"]
        assert len(connectivity_findings) == 1
        assert connectivity_findings[0].severity == Severity.WARNING


class TestProxySettings:
    def test_no_proxy_configured(self):
        mod = _get_module()
        proxy_output = "Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).\n"
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "netsh":
                    result_mock.returncode = 0
                    result_mock.stdout = proxy_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        proxy_findings = [f for f in result.findings if f.data.get("check_type") == "proxy_settings"]
        assert len(proxy_findings) == 0

    def test_proxy_configured(self):
        mod = _get_module()
        proxy_output = "Current WinHTTP proxy settings:\n\n    Proxy Server(s) : proxy.example.com:8080\n"
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "netsh":
                    result_mock.returncode = 0
                    result_mock.stdout = proxy_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        proxy_findings = [f for f in result.findings if f.data.get("check_type") == "proxy_settings"]
        assert len(proxy_findings) >= 1

    def test_netsh_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "netsh":
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        proxy_findings = [f for f in result.findings if f.data.get("check_type") == "proxy_settings"]
        assert len(proxy_findings) == 0


class TestFix:
    def test_fix_dns_resolution_failure(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            mock_run.return_value = result_mock
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        dns_actions = [a for a in fix.actions if "DNS resolution failed" in a.title]
        assert len(dns_actions) >= 1
        assert fix.actions[0].risk_level == RiskLevel.SAFE

    def test_fix_no_connectivity(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ping":
                    result_mock.returncode = 1
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        connectivity_actions = [a for a in fix.actions if "connectivity" in a.title.lower()]
        assert len(connectivity_actions) >= 1
        assert fix.actions[0].risk_level == RiskLevel.SAFE

    def test_fix_proxy_settings(self):
        mod = _get_module()
        proxy_output = "Current WinHTTP proxy settings:\n\n    Proxy Server(s) : proxy.example.com:8080\n"
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "netsh":
                    result_mock.returncode = 0
                    result_mock.stdout = proxy_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        proxy_actions = [a for a in fix.actions if "Proxy" in a.title]
        assert len(proxy_actions) >= 1


class TestMultipleIssues:
    def test_multiple_issues_found(self):
        mod = _get_module()
        ipconfig_output = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if cmd[0] == "ping":
                    result_mock.returncode = 1
                elif cmd[0] == "nslookup":
                    result_mock.returncode = 1
                elif cmd[0] == "ipconfig":
                    result_mock.returncode = 0
                    result_mock.stdout = ipconfig_output
                else:
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        assert result.has_issues
        assert len(result.findings) >= 2  # Should have multiple issues


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
