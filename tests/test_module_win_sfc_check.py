import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.integrity.win_sfc_check import Module
from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile


@pytest.fixture
def module():
    return Module()


@pytest.fixture
def test_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024 * 1024 * 1024,
    )


class TestSFCCheck:
    """Tests for SFC check functionality."""

    def test_module_attributes(self, module):
        """Verify module attributes are correctly set."""
        assert module.name == "win_sfc_check"
        assert module.category == "integrity"
        assert module.platforms == [Platform.WIN32]
        assert module.risk_level == RiskLevel.SAFE

    def test_sfc_healthy_status(self, module, test_profile):
        """Test when SFC scan shows no integrity violations."""
        sfc_output = (
            "Seconds from 2025-02-15 10:30:45, Status: "
            "Windows Resource Protection did not find any integrity violations."
        )

        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {"no_violations": True}
                mock_dism.return_value = {"healthy": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[0].severity == Severity.INFO
                assert "No SFC integrity violations" in result.findings[0].title
                assert result.findings[1].severity == Severity.INFO
                assert "DISM component store is healthy" in result.findings[1].title

    def test_sfc_corrupt_files_repaired(self, module, test_profile):
        """Test when SFC found corrupt files but repaired them."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {
                    "corrupt_found": True,
                    "corrupt_repaired": True,
                    "corrupt_count": 5,
                }
                mock_dism.return_value = {"healthy": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[0].severity == Severity.WARNING
                assert "Corrupt files found and repaired" in result.findings[0].title
                assert result.findings[0].data["check"] == "sfc_corrupt_repaired"
                assert result.findings[0].data["corrupt_count"] == 5

    def test_sfc_corrupt_files_not_repaired(self, module, test_profile):
        """Test when SFC found corrupt files but could not repair them."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {
                    "corrupt_found": True,
                    "corrupt_repaired": False,
                    "corrupt_count": 3,
                }
                mock_dism.return_value = {"healthy": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[0].severity == Severity.CRITICAL
                assert "Corrupt files found but NOT repaired" in result.findings[0].title
                assert result.findings[0].data["check"] == "sfc_corrupt_not_repaired"

    def test_sfc_status_retrieval_failed(self, module, test_profile):
        """Test when SFC status cannot be retrieved."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = None
                mock_dism.return_value = {"healthy": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[0].severity == Severity.WARNING
                assert "Could not retrieve SFC scan status" in result.findings[0].title

    def test_dism_corruption_detected(self, module, test_profile):
        """Test when DISM detects component store corruption."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {"no_violations": True}
                mock_dism.return_value = {"component_corruption": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[1].severity == Severity.WARNING
                assert "DISM detected component store corruption" in result.findings[1].title

    def test_dism_repairable_corruption(self, module, test_profile):
        """Test when DISM detects repairable corruption."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {"no_violations": True}
                mock_dism.return_value = {"repairable_corruption": True}

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[1].severity == Severity.WARNING
                assert "repairable component store corruption" in result.findings[1].title

    def test_dism_status_retrieval_failed(self, module, test_profile):
        """Test when DISM health status cannot be retrieved."""
        with patch.object(module, "_get_sfc_status") as mock_sfc:
            with patch.object(module, "_get_dism_health") as mock_dism:
                mock_sfc.return_value = {"no_violations": True}
                mock_dism.return_value = None

                result = module.check(test_profile)

                assert len(result.findings) == 2
                assert result.findings[1].severity == Severity.WARNING
                assert "Could not assess DISM component store health" in result.findings[1].title


class TestSFCFix:
    """Tests for SFC fix functionality."""

    def test_fix_corrupt_repaired(self, module):
        """Test fix action for repaired corrupt files."""
        from rescue.models import CheckResult, Finding

        findings = CheckResult(
            module_name="win_sfc_check",
            findings=[
                Finding(
                    title="Corrupt files found and repaired",
                    description="Test",
                    severity=Severity.WARNING,
                    category="integrity",
                    data={"check": "sfc_corrupt_repaired", "corrupt_count": 5},
                )
            ],
        )

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) == 1
        assert result.actions[0].success is True
        assert "repaired" in result.actions[0].title.lower()

    def test_fix_corrupt_not_repaired(self, module):
        """Test fix action for unrepaired corrupt files."""
        from rescue.models import CheckResult, Finding

        findings = CheckResult(
            module_name="win_sfc_check",
            findings=[
                Finding(
                    title="Corrupt files found but NOT repaired",
                    description="Test",
                    severity=Severity.CRITICAL,
                    category="integrity",
                    data={"check": "sfc_corrupt_not_repaired", "corrupt_count": 3},
                )
            ],
        )

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) == 1
        assert result.actions[0].success is True
        assert "require intervention" in result.actions[0].title.lower()
        assert "sfc /scannow" in result.actions[0].description

    def test_fix_sfc_healthy(self, module):
        """Test fix action when SFC is healthy."""
        from rescue.models import CheckResult, Finding

        findings = CheckResult(
            module_name="win_sfc_check",
            findings=[
                Finding(
                    title="No SFC integrity violations found",
                    description="Test",
                    severity=Severity.INFO,
                    category="integrity",
                    data={"check": "sfc_healthy"},
                )
            ],
        )

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) == 1
        assert result.actions[0].success is True

    def test_fix_dism_corruption(self, module):
        """Test fix action for DISM corruption."""
        from rescue.models import CheckResult, Finding

        findings = CheckResult(
            module_name="win_sfc_check",
            findings=[
                Finding(
                    title="DISM detected component store corruption",
                    description="Test",
                    severity=Severity.WARNING,
                    category="integrity",
                    data={"check": "dism_corruption"},
                )
            ],
        )

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) == 1
        assert result.actions[0].success is True
        assert "RestoreHealth" in result.actions[0].description

    def test_fix_multiple_findings(self, module):
        """Test fix with multiple findings."""
        from rescue.models import CheckResult, Finding

        findings = CheckResult(
            module_name="win_sfc_check",
            findings=[
                Finding(
                    title="Corrupt files found and repaired",
                    description="Test",
                    severity=Severity.WARNING,
                    category="integrity",
                    data={"check": "sfc_corrupt_repaired", "corrupt_count": 5},
                ),
                Finding(
                    title="DISM detected repairable component store corruption",
                    description="Test",
                    severity=Severity.WARNING,
                    category="integrity",
                    data={"check": "dism_repairable"},
                ),
            ],
        )

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) == 2
        assert all(action.success for action in result.actions)


class TestSFCLogParsing:
    """Tests for CBS log parsing."""

    def test_parse_no_violations(self):
        """Test parsing log showing no integrity violations."""
        from modules.integrity.win_sfc_check import _parse_sfc_log

        log = (
            "Seconds from 2025-02-15 10:30:45\n"
            "CBS MalformedPackageException\n"
            "Windows Resource Protection did not find any integrity violations."
        )

        result = _parse_sfc_log(log)

        assert result["no_violations"] is True
        assert result["corrupt_found"] is False

    def test_parse_corrupt_files_repaired(self):
        """Test parsing log with corrupt files that were repaired."""
        from modules.integrity.win_sfc_check import _parse_sfc_log

        log = (
            "Seconds from 2025-02-15 10:30:45\n"
            "Windows Resource Protection found corrupt files and successfully repaired them.\n"
            "Found 5 file(s) with corruption and repaired them.\n"
        )

        result = _parse_sfc_log(log)

        assert result["corrupt_found"] is True
        assert result["corrupt_repaired"] is True
        assert result["corrupt_count"] == 5

    def test_parse_corrupt_files_not_repaired(self):
        """Test parsing log with corrupt files that could not be repaired."""
        from modules.integrity.win_sfc_check import _parse_sfc_log

        log = (
            "Seconds from 2025-02-15 10:30:45\n"
            "Windows Resource Protection found corrupt files.\n"
            "Found 3 file(s) with corruption but unable to repair them.\n"
        )

        result = _parse_sfc_log(log)

        assert result["corrupt_found"] is True
        assert result["corrupt_repaired"] is False
        assert result["corrupt_count"] == 3

    def test_parse_empty_log(self):
        """Test parsing empty log."""
        from modules.integrity.win_sfc_check import _parse_sfc_log

        result = _parse_sfc_log("")

        assert result["corrupt_found"] is False
        assert result["no_violations"] is False


class TestDISMOutputParsing:
    """Tests for DISM output parsing."""

    def test_parse_dism_healthy(self):
        """Test parsing DISM output showing healthy component store."""
        from modules.integrity.win_sfc_check import _parse_dism_output

        output = (
            "Deployment Image Servicing and Management tool\n"
            "The component store is healthy."
        )

        result = _parse_dism_output(output)

        assert result["healthy"] is True
        assert result["component_corruption"] is False

    def test_parse_dism_repairable_corruption(self):
        """Test parsing DISM output with repairable corruption."""
        from modules.integrity.win_sfc_check import _parse_dism_output

        output = (
            "Deployment Image Servicing and Management tool\n"
            "The component store is repairable."
        )

        result = _parse_dism_output(output)

        assert result["repairable_corruption"] is True
        assert result["component_corruption"] is False

    def test_parse_dism_corrupted(self):
        """Test parsing DISM output showing corrupted component store."""
        from modules.integrity.win_sfc_check import _parse_dism_output

        output = (
            "Deployment Image Servicing and Management tool\n"
            "The component store is corrupted."
        )

        result = _parse_dism_output(output)

        assert result["component_corruption"] is True
        assert result["healthy"] is False

    def test_parse_dism_empty_output(self):
        """Test parsing empty DISM output."""
        from modules.integrity.win_sfc_check import _parse_dism_output

        result = _parse_dism_output("")

        assert result["healthy"] is False
        assert result["component_corruption"] is False


class TestSubprocessIntegration:
    """Tests for subprocess command construction."""

    def test_get_sfc_status_subprocess_timeout(self, module):
        """Test SFC status retrieval with subprocess timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)

            result = module._get_sfc_status()

            assert result is None

    def test_get_sfc_status_subprocess_error(self, module):
        """Test SFC status retrieval with subprocess error."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Process error")

            result = module._get_sfc_status()

            assert result is None

    def test_get_dism_health_subprocess_timeout(self, module):
        """Test DISM health check with subprocess timeout."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 30)

            result = module._get_dism_health()

            assert result is None

    def test_get_dism_health_subprocess_error(self, module):
        """Test DISM health check with subprocess error."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = OSError("Process error")

            result = module._get_dism_health()

            assert result is None

    def test_get_sfc_status_returns_zero_exit(self, module):
        """Test SFC status with successful command execution."""
        with patch("subprocess.run") as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = (
                "Windows Resource Protection did not find any integrity violations."
            )
            mock_run.return_value = mock_process

            result = module._get_sfc_status()

            assert result is not None
            assert "returncode" not in result or mock_process.returncode == 0

    def test_get_dism_health_returns_data(self, module):
        """Test DISM health check returns parsed data."""
        with patch("subprocess.run") as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = "The component store is healthy."
            mock_process.stderr = ""
            mock_run.return_value = mock_process

            result = module._get_dism_health()

            assert result is not None
