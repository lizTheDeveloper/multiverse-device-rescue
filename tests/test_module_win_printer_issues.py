import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.integrity.win_printer_issues import Module
from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile


@pytest.fixture
def module():
    return Module()


@pytest.fixture
def system_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024 * 1024 * 1024,
    )


class TestWinPrinterIssuesModule:
    def test_module_metadata(self, module):
        assert module.name == "win_printer_issues"
        assert module.category == "integrity"
        assert module.platforms == [Platform.WIN32]
        assert module.risk_level == RiskLevel.SAFE

    @patch("subprocess.run")
    def test_check_with_healthy_printers(self, mock_run, module, system_profile):
        """Test check when printers are healthy and spooler is running."""
        # Mock Get-Printer output (Format-List)
        printer_list_output = """
Name                                         DriverName                          PortName        PrinterStatus Shared
----                                         ----------                          --------        ------------- ------
HP LaserJet Pro M404                         HP LaserJet Pro M404 PCL6 Class ... USB001                  Normal  False
Brother HL-L8360CDW                          Brother HL-L8360CDW series IPP D... BRN_E4C42B      Normal      False
"""

        # Mock printer status output (CSV)
        printer_status_output = """"Name","PrinterStatus"
"HP LaserJet Pro M404","Normal"
"Brother HL-L8360CDW","Normal"
"""

        spooler_output = """

Status
------
Running
"""

        job_count_output = """

Count
-----
    0
"""

        # Set up mock responses in order
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=printer_list_output),  # Get-Printer (list)
            MagicMock(returncode=0, stdout=printer_status_output),  # Check printer status (CSV)
            MagicMock(returncode=0, stdout=spooler_output),  # Get-Service Spooler
            MagicMock(returncode=0, stdout=job_count_output),  # Get-PrintJob
        ]

        result = module.check(system_profile)
        assert result.module_name == "win_printer_issues"
        # Should have one INFO finding for the printer list
        info_findings = [f for f in result.findings if f.severity == Severity.INFO]
        assert len(info_findings) == 1
        assert "Installed printers" in info_findings[0].title

    @patch("subprocess.run")
    def test_check_with_offline_printer(self, mock_run, module, system_profile):
        """Test check when a printer is offline."""
        printer_list_output = """
Name                                         DriverName                          PortName        PrinterStatus Shared
----                                         ----------                          --------        ------------- ------
HP LaserJet Pro M404                         HP LaserJet Pro M404 PCL6 Class ... USB001                  Normal  False
"""

        printer_status_output = """"Name","PrinterStatus"
"HP LaserJet Pro M404","Offline"
"""

        spooler_output = """

Status
------
Running
"""

        job_count_output = """

Count
-----
    0
"""

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=printer_list_output),  # Get-Printer (list)
            MagicMock(returncode=0, stdout=printer_status_output),  # Check printer status (CSV)
            MagicMock(returncode=0, stdout=spooler_output),  # Get-Service Spooler
            MagicMock(returncode=0, stdout=job_count_output),  # Get-PrintJob
        ]

        result = module.check(system_profile)
        warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
        # Should have at least one warning for offline printer
        assert any("offline" in f.title.lower() for f in warning_findings)

    @patch("subprocess.run")
    def test_check_with_stopped_spooler(self, mock_run, module, system_profile):
        """Test check when print spooler is stopped."""
        printer_list_output = """
Name                                         DriverName                          PortName        PrinterStatus Shared
----                                         ----------                          --------        ------------- ------
HP LaserJet Pro M404                         HP LaserJet Pro M404 PCL6 Class ... USB001                  Normal  False
"""

        printer_status_output = """"Name","PrinterStatus"
"HP LaserJet Pro M404","Normal"
"""

        spooler_output = """

Status
------
Stopped
"""

        job_count_output = """

Count
-----
    0
"""

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=printer_list_output),  # Get-Printer (list)
            MagicMock(returncode=0, stdout=printer_status_output),  # Check printer status (CSV)
            MagicMock(returncode=0, stdout=spooler_output),  # Get-Service Spooler
            MagicMock(returncode=0, stdout=job_count_output),  # Get-PrintJob
        ]

        result = module.check(system_profile)
        warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert any("spooler" in f.title.lower() and "stopped" in f.title.lower() for f in warning_findings)

    @patch("subprocess.run")
    def test_check_with_stuck_print_jobs(self, mock_run, module, system_profile):
        """Test check when there are stuck print jobs."""
        printer_list_output = """
Name                                         DriverName                          PortName        PrinterStatus Shared
----                                         ----------                          --------        ------------- ------
HP LaserJet Pro M404                         HP LaserJet Pro M404 PCL6 Class ... USB001                  Normal  False
"""

        printer_status_output = """"Name","PrinterStatus"
"HP LaserJet Pro M404","Normal"
"""

        spooler_output = """

Status
------
Running
"""

        job_count_output = """

Count
-----
    3
"""

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=printer_list_output),  # Get-Printer (list)
            MagicMock(returncode=0, stdout=printer_status_output),  # Check printer status (CSV)
            MagicMock(returncode=0, stdout=spooler_output),  # Get-Service Spooler
            MagicMock(returncode=0, stdout=job_count_output),  # Get-PrintJob
        ]

        result = module.check(system_profile)
        warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert any("stuck" in f.title.lower() for f in warning_findings)

    @patch("subprocess.run")
    def test_check_no_printers_installed(self, mock_run, module, system_profile):
        """Test check when no printers are installed."""
        empty_output = ""

        printer_status_output = """"Name","PrinterStatus"
"""

        spooler_output = """

Status
------
Running
"""

        job_count_output = """

Count
-----
    0
"""

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=empty_output),  # Get-Printer (list)
            MagicMock(returncode=0, stdout=printer_status_output),  # Check printer status (CSV, empty)
            MagicMock(returncode=0, stdout=spooler_output),  # Get-Service Spooler
            MagicMock(returncode=0, stdout=job_count_output),  # Get-PrintJob
        ]

        result = module.check(system_profile)
        info_findings = [f for f in result.findings if f.severity == Severity.INFO]
        assert any("no printers" in f.title.lower() for f in info_findings)

    @patch("subprocess.run")
    def test_fix_printer_offline(self, mock_run, module, system_profile):
        """Test fix provides guidance for offline printer."""
        check_result = module.check(system_profile)
        # Create a mock check with offline finding
        from rescue.models import CheckResult, Finding

        offline_finding = Finding(
            title="Printer 'HP LaserJet' is offline",
            description="Test printer offline",
            severity=Severity.WARNING,
            category="integrity",
            data={"check_type": "printer_offline", "printer_name": "HP LaserJet"},
        )
        check_result.findings = [offline_finding]

        fix_result = module.fix(check_result, Mode.MANUAL)
        assert fix_result.module_name == "win_printer_issues"
        assert len(fix_result.actions) == 1
        assert fix_result.actions[0].success
        assert "not responding" in fix_result.actions[0].description.lower() or "offline" in fix_result.actions[0].title.lower()

    @patch("subprocess.run")
    def test_fix_spooler_stopped(self, mock_run, module, system_profile):
        """Test fix provides guidance for stopped spooler."""
        from rescue.models import CheckResult, Finding

        spooler_finding = Finding(
            title="Print Spooler service is stopped",
            description="Test spooler stopped",
            severity=Severity.WARNING,
            category="integrity",
            data={"check_type": "spooler_stopped"},
        )
        check_result = module.check(system_profile)
        check_result.findings = [spooler_finding]

        fix_result = module.fix(check_result, Mode.MANUAL)
        assert len(fix_result.actions) == 1
        assert fix_result.actions[0].success
        assert "services.msc" in fix_result.actions[0].description

    @patch("subprocess.run")
    def test_fix_stuck_print_jobs(self, mock_run, module, system_profile):
        """Test fix provides guidance for stuck print jobs."""
        from rescue.models import CheckResult, Finding

        stuck_jobs_finding = Finding(
            title="Stuck print jobs detected (3)",
            description="Test stuck jobs",
            severity=Severity.WARNING,
            category="integrity",
            data={"check_type": "stuck_print_jobs", "count": 3},
        )
        check_result = module.check(system_profile)
        check_result.findings = [stuck_jobs_finding]

        fix_result = module.fix(check_result, Mode.MANUAL)
        assert len(fix_result.actions) == 1
        assert fix_result.actions[0].success
        assert "stuck" in fix_result.actions[0].title.lower()
        assert "delete" in fix_result.actions[0].description.lower() or "cancel" in fix_result.actions[0].description.lower()

    @patch("subprocess.run")
    def test_subprocess_timeout_handling(self, mock_run, module, system_profile):
        """Test that subprocess timeouts are handled gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)

        result = module.check(system_profile)
        # Should not crash, may have empty or minimal findings
        assert result.module_name == "win_printer_issues"

    @patch("subprocess.run")
    def test_subprocess_oserror_handling(self, mock_run, module, system_profile):
        """Test that OSErrors are handled gracefully."""
        mock_run.side_effect = OSError("Command not found")

        result = module.check(system_profile)
        # Should not crash, may have empty or minimal findings
        assert result.module_name == "win_printer_issues"

    def test_check_returns_check_result_type(self, module, system_profile):
        """Test that check returns CheckResult."""
        with patch("subprocess.run") as mock_run:
            empty_csv = """"Name","PrinterStatus"
"""
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=""),  # Get-Printer list
                MagicMock(returncode=0, stdout=empty_csv),  # Printer status CSV
                MagicMock(returncode=0, stdout=""),  # Spooler status
                MagicMock(returncode=0, stdout=""),  # Print jobs count
            ]
            result = module.check(system_profile)
            assert hasattr(result, "module_name")
            assert hasattr(result, "findings")

    def test_fix_returns_fix_result_type(self, module, system_profile):
        """Test that fix returns FixResult."""
        from rescue.models import CheckResult

        empty_result = CheckResult(module_name=module.name)
        fix_result = module.fix(empty_result, Mode.MANUAL)
        assert hasattr(fix_result, "module_name")
        assert hasattr(fix_result, "actions")
