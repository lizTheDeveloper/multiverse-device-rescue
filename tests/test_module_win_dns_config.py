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
    return next(m for m in modules if m.name == "win_dns_config")


class TestWinDnsConfigDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "win_dns_config"
        assert mod.category == "integrity"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.WIN32 in mod.platforms


class TestDnsServersConfiguration:
    def test_well_known_dns_servers(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "8.8.8.8\n1.1.1.1\n"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_info"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.INFO
        assert "optimal" in dns_findings[0].title.lower()

    def test_isp_default_dns_servers(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "192.168.1.1\n10.0.0.1\n"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "isp_dns"]
        assert len(dns_findings) == 1
        assert dns_findings[0].severity == Severity.WARNING
        assert "ISP" in dns_findings[0].title

    def test_cloudflare_dns_servers(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "1.1.1.1\n1.0.0.1\n"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_info"]
        assert len(dns_findings) == 1
        assert "Cloudflare" in dns_findings[0].description

    def test_quad9_dns_servers(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "9.9.9.9\n149.112.112.112\n"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_info"]
        assert len(dns_findings) == 1
        assert "Quad9" in dns_findings[0].description

    def test_mixed_dns_servers(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "8.8.8.8\n192.168.1.1\n"
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        # Mixed with well-known DNS is optimal
        dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_info"]
        assert len(dns_findings) == 1
        assert "optimal" in dns_findings[0].title.lower()

    def test_dns_servers_get_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 1
            result_mock.stdout = ""
            mock_run.return_value = result_mock
            result = mod.check(_make_profile())

        # When servers get fails, other DNS checks may still run
        server_findings = [f for f in result.findings if f.data.get("check_type") == "isp_dns" or f.data.get("check_type") == "dns_info"]
        assert len(server_findings) == 0


class TestDnsResolution:
    def test_dns_resolution_fast(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Resolve-DnsName" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "45.2"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        resolution_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(resolution_findings) == 0

    def test_dns_resolution_slow(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Resolve-DnsName" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "750.5"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        resolution_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(resolution_findings) == 1
        assert resolution_findings[0].severity == Severity.WARNING
        assert "slow" in resolution_findings[0].title.lower()

    def test_dns_resolution_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Resolve-DnsName" in str(cmd):
                    result_mock.returncode = 1
                    result_mock.stdout = ""
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        resolution_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(resolution_findings) == 1
        assert "failed" in resolution_findings[0].title.lower()

    def test_dns_resolution_timeout(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                if "Resolve-DnsName" in str(cmd):
                    raise subprocess.TimeoutExpired("powershell", 10)
                result_mock = MagicMock()
                result_mock.returncode = 0
                result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        resolution_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution"]
        assert len(resolution_findings) == 1
        assert "timed out" in resolution_findings[0].title.lower()


class TestDnsCache:
    def test_dns_cache_small(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Measure-Object" in str(cmd) and "DnsClientCache" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "1250"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        cache_findings = [f for f in result.findings if f.data.get("check_type") == "dns_cache_large"]
        assert len(cache_findings) == 0

    def test_dns_cache_large(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Measure-Object" in str(cmd) and "DnsClientCache" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "6500"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        cache_findings = [f for f in result.findings if f.data.get("check_type") == "dns_cache_large"]
        assert len(cache_findings) == 1
        assert cache_findings[0].severity == Severity.INFO
        assert "large" in cache_findings[0].title.lower()

    def test_dns_cache_check_fails(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                result_mock.returncode = 1
                result_mock.stdout = ""
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        cache_findings = [f for f in result.findings if f.data.get("check_type") == "dns_cache_large"]
        assert len(cache_findings) == 0


class TestFix:
    def test_fix_isp_dns(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            result_mock = MagicMock()
            result_mock.returncode = 0
            result_mock.stdout = "192.168.1.1\n"
            mock_run.return_value = result_mock
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        isp_actions = [a for a in fix.actions if "ISP" in a.title]
        assert len(isp_actions) >= 1
        assert "1.1.1.1" in fix.actions[0].description
        assert "8.8.8.8" in fix.actions[0].description

    def test_fix_dns_resolution_slow(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Resolve-DnsName" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "1200.0"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        resolution_actions = [a for a in fix.actions if "resolution" in a.title.lower()]
        assert len(resolution_actions) >= 1

    def test_fix_large_cache(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Measure-Object" in str(cmd) and "DnsClientCache" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "8000"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "8.8.8.8\n"
                return result_mock

            mock_run.side_effect = side_effect
            check = mod.check(_make_profile())

        fix = mod.fix(check, Mode.MANUAL)
        assert fix.all_succeeded
        cache_actions = [a for a in fix.actions if "cache" in a.title.lower()]
        assert len(cache_actions) >= 1
        assert "flushdns" in cache_actions[0].description.lower()


class TestMultipleIssues:
    def test_multiple_issues_found(self):
        mod = _get_module()
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, *args, **kwargs):
                result_mock = MagicMock()
                if "Resolve-DnsName" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "800.0"
                elif "Measure-Object" in str(cmd) and "DnsClientCache" in str(cmd):
                    result_mock.returncode = 0
                    result_mock.stdout = "7500"
                else:
                    result_mock.returncode = 0
                    result_mock.stdout = "192.168.1.1\n"
                return result_mock

            mock_run.side_effect = side_effect
            result = mod.check(_make_profile())

        assert result.has_issues
        assert len(result.findings) >= 2  # Should have multiple issues


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
