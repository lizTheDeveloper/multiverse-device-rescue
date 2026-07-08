from unittest import mock

import pytest

from modules.integrity.win_winsock_check import Module
from rescue.models import Mode, Platform, Severity, SystemProfile


@pytest.fixture
def module():
    return Module()


@pytest.fixture
def sample_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="10",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024 * 1024 * 1024,
    )


class TestWinsockCheck:
    def test_module_metadata(self, module):
        assert module.name == "win_winsock_check"
        assert module.category == "integrity"
        assert module.platforms == [Platform.WIN32]
        assert module.risk_level.value == "safe"

    def test_healthy_winsock_and_tcpip(self, module, sample_profile):
        """Test when Winsock and TCP/IP are healthy."""
        winsock_output = """
Catalog Entries:
  Entry 1:  Transport: TCP
  Entry 2:  Transport: UDP
  Entry 3:  Transport: DCCP
  Entry 4:  Transport: PGM
  Entry 5:  Transport: SCTP
        """

        tcpip_output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DefaultTTL    REG_DWORD    0x40
    KeepAliveTime REG_DWORD    0x6ddd0
    SynAttackProtect REG_DWORD 0x1
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            assert len(result.findings) >= 1
            # Should have at least one informational finding
            info_findings = [f for f in result.findings if f.severity == Severity.INFO]
            assert len(info_findings) >= 1

    def test_excessive_winsock_entries(self, module, sample_profile):
        """Test detection of excessive Winsock catalog entries."""
        winsock_output = "\n".join([f"  Entry {i}:  Transport: TEST" for i in range(1, 36)])

        tcpip_output = """
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DefaultTTL    REG_DWORD    0x40
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert any("excessive" in f.title.lower() for f in warning_findings)

    def test_suspicious_lsps_detected(self, module, sample_profile):
        """Test detection of suspicious Layered Service Providers."""
        winsock_output = """
Catalog Entries:
  Entry 1:  Transport: TCP
  Layered Service Provider = Symantec LSP
  Entry 2:  Transport: UDP
  Layered Service Provider = Norton Internet Security LSP
        """

        tcpip_output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DefaultTTL    REG_DWORD    0x40
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert any("lsp" in f.title.lower() for f in warning_findings)

    def test_unusual_ttl(self, module, sample_profile):
        """Test detection of unusual TTL values."""
        winsock_output = """
Catalog Entries:
  Entry 1:  Transport: TCP
  Entry 2:  Transport: UDP
        """

        tcpip_output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DefaultTTL    REG_DWORD    0x8
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert any("tcp/ip" in f.title.lower() for f in warning_findings)

    def test_winsock_query_failed(self, module, sample_profile):
        """Test handling of failed Winsock query."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=1, stdout="")

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert any("could not retrieve" in f.title.lower() for f in warning_findings)

    def test_fix_winsock_catalog_failed(self, module, sample_profile):
        """Test fix action for failed Winsock catalog query."""
        check_result = module.check(sample_profile)

        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=1, stdout="")):
            fix_result = module.fix(check_result, Mode.AUTO)

            assert len(fix_result.actions) > 0
            assert all(a.success for a in fix_result.actions)

    def test_fix_excessive_entries(self, module, sample_profile):
        """Test fix action for excessive Winsock entries."""
        winsock_output = "\n".join([f"  Entry {i}:  Transport: TEST" for i in range(1, 36)])
        tcpip_output = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" + "\n    DefaultTTL    REG_DWORD    0x40"

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            check_result = module.check(sample_profile)
            fix_result = module.fix(check_result, Mode.AUTO)

            assert len(fix_result.actions) > 0
            assert any("reset" in a.title.lower() for a in fix_result.actions)

    def test_ipv4_disabled(self, module, sample_profile):
        """Test detection of disabled IPv4."""
        winsock_output = """
Catalog Entries:
  Entry 1:  Transport: TCP
        """

        # DisabledComponents with bit 5 set (0x20) = IPv4 disabled
        tcpip_output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DisabledComponents    REG_DWORD    0x20
    DefaultTTL    REG_DWORD    0x40
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert any("ipv4" in f.title.lower() for f in warning_findings)

    def test_subprocess_timeout(self, module, sample_profile):
        """Test handling of subprocess timeout."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = TimeoutError()

            result = module.check(sample_profile)

            # Should have warning about failed query
            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert len(warning_findings) > 0

    def test_subprocess_oserror(self, module, sample_profile):
        """Test handling of OS errors during subprocess call."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Command not found")

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert len(warning_findings) > 0

    def test_multiple_warnings(self, module, sample_profile):
        """Test case with multiple issues."""
        winsock_output = "\n".join([f"  Entry {i}:  Transport: TEST" for i in range(1, 36)])
        winsock_output += "\n  Layered Service Provider = Norton Internet Security"

        tcpip_output = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    DefaultTTL    REG_DWORD    0x8
    KeepAliveTime REG_DWORD    0x3a98
        """

        with mock.patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                mock.Mock(returncode=0, stdout=winsock_output),
                mock.Mock(returncode=0, stdout=tcpip_output),
            ]

            result = module.check(sample_profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            # Should have warnings for excessive entries, LSPs, and unusual TTL
            assert len(warning_findings) >= 2
