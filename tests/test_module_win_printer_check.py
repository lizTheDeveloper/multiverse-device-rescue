import json
import unittest
from unittest.mock import MagicMock, patch

from rescue.models import (
    CheckResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)

# Import the module
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.integrity.win_printer_check import Module


class TestWinPrinterCheck(unittest.TestCase):
    def setUp(self):
        self.module = Module()
        self.profile = SystemProfile(
            platform=Platform.WIN32,
            os_name="Windows",
            os_version="10",
            architecture="x86_64",
            cpu_model="Intel",
            cpu_cores=4,
            ram_bytes=8000000000,
        )

    @patch("subprocess.run")
    def test_check_spooler_running_with_printers(self, mock_run):
        """Test check when Spooler is running and printers are present."""
        # Mock responses for different commands
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1234
        FLAGS              :
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell" and "Get-Printer" in cmd[3]:
                result.returncode = 0
                printers = [
                    {
                        "Name": "HP LaserJet Pro",
                        "PrinterStatus": "Normal",
                        "PortName": "IP_192.168.1.100",
                        "DriverName": "HP LaserJet Pro M404n",
                        "Shared": False,
                    },
                    {
                        "Name": "Microsoft Print to PDF",
                        "PrinterStatus": "Normal",
                        "PortName": "Ne00:",
                        "DriverName": "Microsoft Print to PDF",
                        "Shared": False,
                    },
                ]
                result.stdout = json.dumps(printers)
                return result
            elif cmd[0] == "powershell" and "Win32_Printer where Default=True" in cmd[3]:
                result.returncode = 0
                result.stdout = "HP LaserJet Pro"
                return result
            elif cmd[0] == "powershell" and "Get-PrintJob" in cmd[3]:
                result.returncode = 0
                result.stdout = ""  # No print jobs
                return result
            return result

        mock_run.side_effect = mock_subprocess

        result = self.module.check(self.profile)

        assert isinstance(result, CheckResult)
        assert result.module_name == "win_printer_check"
        # Should have info findings for spooler, printers, and default printer
        assert len(result.findings) > 0

        # Find severity counts
        info_count = sum(
            1 for f in result.findings if f.severity == Severity.INFO
        )
        warning_count = sum(
            1 for f in result.findings if f.severity == Severity.WARNING
        )
        critical_count = sum(
            1 for f in result.findings if f.severity == Severity.CRITICAL
        )

        assert info_count > 0
        assert warning_count == 0
        assert critical_count == 0

    @patch("subprocess.run")
    def test_check_spooler_stopped_critical(self, mock_run):
        """Test check flags CRITICAL when Spooler is stopped."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell":
                result.returncode = 0
                result.stdout = ""
                return result
            return result

        mock_run.side_effect = mock_subprocess

        result = self.module.check(self.profile)

        # Should have CRITICAL finding for stopped spooler
        critical_findings = [
            f for f in result.findings if f.severity == Severity.CRITICAL
        ]
        assert len(critical_findings) > 0
        assert any("not running" in f.title.lower() for f in critical_findings)

    @patch("subprocess.run")
    def test_check_printer_offline_warning(self, mock_run):
        """Test check flags WARNING for offline printers."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        STATE              : 4  RUNNING
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell" and "Get-Printer" in cmd[3]:
                result.returncode = 0
                printers = [
                    {
                        "Name": "Offline Printer",
                        "PrinterStatus": "Offline",
                        "PortName": "IP_192.168.1.101",
                        "DriverName": "Generic Printer",
                        "Shared": False,
                    },
                    {
                        "Name": "Error Printer",
                        "PrinterStatus": "Error",
                        "PortName": "LPT1:",
                        "DriverName": "Old Printer Driver",
                        "Shared": False,
                    },
                ]
                result.stdout = json.dumps(printers)
                return result
            elif cmd[0] == "powershell" and "Win32_Printer where Default=True" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            elif cmd[0] == "powershell" and "Get-PrintJob" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            return result

        mock_run.side_effect = mock_subprocess

        result = self.module.check(self.profile)

        # Should have WARNING findings for offline/error printers
        warning_findings = [
            f for f in result.findings if f.severity == Severity.WARNING
        ]
        assert len(warning_findings) > 0
        assert any("error or offline" in f.title.lower() for f in warning_findings)

    @patch("subprocess.run")
    def test_check_stuck_print_job_warning(self, mock_run):
        """Test check flags WARNING for stuck print jobs."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        STATE              : 4  RUNNING
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell" and "Get-Printer" in cmd[3]:
                result.returncode = 0
                printers = [
                    {
                        "Name": "HP LaserJet",
                        "PrinterStatus": "Normal",
                        "PortName": "IP_192.168.1.100",
                        "DriverName": "HP LaserJet Driver",
                        "Shared": False,
                    }
                ]
                result.stdout = json.dumps(printers)
                return result
            elif cmd[0] == "powershell" and "Win32_Printer where Default=True" in cmd[3]:
                result.returncode = 0
                result.stdout = "HP LaserJet"
                return result
            elif cmd[0] == "powershell" and "Get-PrintJob" in cmd[3]:
                result.returncode = 0
                jobs = [
                    {
                        "Name": "Test Document",
                        "Id": 1,
                        "PrinterName": "HP LaserJet",
                        "Status": "Error",
                    },
                    {
                        "Name": "Stuck Job",
                        "Id": 2,
                        "PrinterName": "HP LaserJet",
                        "Status": "Paused",
                    },
                ]
                result.stdout = json.dumps(jobs)
                return result
            return result

        mock_run.side_effect = mock_subprocess

        result = self.module.check(self.profile)

        # Should have WARNING findings for stuck jobs
        warning_findings = [
            f for f in result.findings if f.severity == Severity.WARNING
        ]
        assert len(warning_findings) > 0
        assert any("stuck" in f.title.lower() for f in warning_findings)

    @patch("subprocess.run")
    def test_check_no_printers(self, mock_run):
        """Test check when no printers are installed."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        STATE              : 4  RUNNING
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell" and "Get-Printer" in cmd[3]:
                result.returncode = 0
                result.stdout = ""  # No printers
                return result
            elif cmd[0] == "powershell" and "Win32_Printer where Default=True" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            elif cmd[0] == "powershell" and "Get-PrintJob" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            return result

        mock_run.side_effect = mock_subprocess

        result = self.module.check(self.profile)

        # Should indicate no default printer
        assert any(
            "no default printer" in f.title.lower() for f in result.findings
        )

    @patch("subprocess.run")
    def test_fix_spooler_stopped(self, mock_run):
        """Test fix for stopped spooler returns informational action."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        STATE              : 1  STOPPED
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell":
                result.returncode = 0
                result.stdout = ""
                return result
            return result

        mock_run.side_effect = mock_subprocess

        check_result = self.module.check(self.profile)
        fix_result = self.module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) > 0
        # Actions should all have success=True (informational)
        assert all(a.success for a in fix_result.actions)
        # All actions should be SAFE risk level
        assert all(a.risk_level == RiskLevel.SAFE for a in fix_result.actions)

    @patch("subprocess.run")
    def test_fix_printer_error(self, mock_run):
        """Test fix for printer in error state returns informational action."""
        def mock_subprocess(cmd, *args, **kwargs):
            result = MagicMock()
            if cmd[0] == "sc" and cmd[1] == "query" and cmd[2] == "Spooler":
                result.returncode = 0
                result.stdout = """
SERVICE_NAME: Spooler
        STATE              : 4  RUNNING
        START_TYPE         : 2  AUTO_START
                """
                return result
            elif cmd[0] == "powershell" and "Get-Printer" in cmd[3]:
                result.returncode = 0
                printers = [
                    {
                        "Name": "Broken Printer",
                        "PrinterStatus": "Error",
                        "PortName": "LPT1:",
                        "DriverName": "Old Driver",
                        "Shared": False,
                    }
                ]
                result.stdout = json.dumps(printers)
                return result
            elif cmd[0] == "powershell" and "Win32_Printer where Default=True" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            elif cmd[0] == "powershell" and "Get-PrintJob" in cmd[3]:
                result.returncode = 0
                result.stdout = ""
                return result
            return result

        mock_run.side_effect = mock_subprocess

        check_result = self.module.check(self.profile)
        fix_result = self.module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) > 0
        # Actions for error printer should be SAFE
        assert any(
            a.risk_level == RiskLevel.SAFE
            for a in fix_result.actions
            if "resolve" in a.title.lower()
        )

    def test_module_attributes(self):
        """Test module has correct attributes."""
        assert self.module.name == "win_printer_check"
        assert self.module.category == "integrity"
        assert self.module.platforms == [Platform.WIN32]
        assert self.module.risk_level == RiskLevel.SAFE
        assert isinstance(self.module.depends_on, list)
        assert isinstance(self.module.estimated_duration, str)


if __name__ == "__main__":
    unittest.main()
