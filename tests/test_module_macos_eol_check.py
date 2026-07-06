import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.integrity.macos_eol_check import Module, _parse_sysctl_output
from rescue.models import (
    CheckResult,
    Finding,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
    Mode,
)


@pytest.fixture
def module():
    return Module()


@pytest.fixture
def sample_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=8589934592,
    )


class TestMacOSEOLCheck:
    """Test suite for macOS EOL check module."""

    def test_module_metadata(self, module):
        """Test module metadata is correctly configured."""
        assert module.name == "macos_eol_check"
        assert module.category == "integrity"
        assert module.platforms == [Platform.DARWIN]
        assert module.risk_level == RiskLevel.SAFE

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_supported_version_sequoia(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check identifies Sequoia (15) as supported."""
        mock_sw_vers.return_value = ("15.0", "24A335")
        mock_sysctl.return_value = "MacBookPro18,1"

        result = module.check(sample_profile)

        assert isinstance(result, CheckResult)
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert "Sequoia" in result.findings[0].title
        assert "supported" in result.findings[0].description.lower()
        assert result.findings[0].data["version"] == "15.0"
        assert result.findings[0].data["build"] == "24A335"
        assert result.findings[0].data["model"] == "MacBookPro18,1"

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_supported_version_sonoma(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check identifies Sonoma (14) as supported."""
        mock_sw_vers.return_value = ("14.6.1", "23G80")
        mock_sysctl.return_value = "MacBookAir9,1"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert "Sonoma" in result.findings[0].title or "14" in result.findings[0].title
        assert "supported" in result.findings[0].description.lower()

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_supported_version_ventura(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check identifies Ventura (13) as supported (security updates only)."""
        mock_sw_vers.return_value = ("13.6.1", "23G80")
        mock_sysctl.return_value = "MacBookPro16,2"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.INFO
        assert "Ventura" in result.findings[0].title or "13" in result.findings[0].title
        assert "security" in result.findings[0].description.lower()

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_eol_monterey(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check flags Monterey (12) as EOL with WARNING."""
        mock_sw_vers.return_value = ("12.7.1", "21H20")
        mock_sysctl.return_value = "iMac21,1"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.WARNING
        assert "Monterey" in result.findings[0].title or "12" in result.findings[0].title
        assert "EOL" in result.findings[0].description

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_eol_big_sur(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check flags Big Sur (11) as EOL with WARNING."""
        mock_sw_vers.return_value = ("11.7.10", "20G1226")
        mock_sysctl.return_value = "MacBookPro16,1"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.WARNING
        assert "Big Sur" in result.findings[0].title or "11" in result.findings[0].title

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_eol_catalina(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check flags Catalina (10.15) as CRITICAL."""
        mock_sw_vers.return_value = ("10.15.7", "19H2")
        mock_sysctl.return_value = "MacBookPro15,2"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert "Catalina" in result.findings[0].title
        assert "CRITICAL" in result.findings[0].description

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_eol_mojave_or_older(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check flags Mojave (10.14) and older as CRITICAL."""
        mock_sw_vers.return_value = ("10.14.6", "18G103")
        mock_sysctl.return_value = "MacBookPro13,2"

        result = module.check(sample_profile)

        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert "Mojave" in result.findings[0].title or "10.14" in result.findings[0].description

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_handles_version_parsing_with_patch(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check correctly parses version with patch level."""
        mock_sw_vers.return_value = ("14.6.1", "23G80")
        mock_sysctl.return_value = "Mac14,2"

        result = module.check(sample_profile)

        assert result.findings[0].data["version"] == "14.6"

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_subprocess_error_handling(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check handles subprocess errors gracefully."""
        mock_sw_vers.side_effect = subprocess.CalledProcessError(1, "sw_vers")

        result = module.check(sample_profile)

        # Should have error finding
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_sysctl_error_handling(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check handles sysctl errors gracefully."""
        mock_sw_vers.return_value = ("14.0", "24A335")
        mock_sysctl.side_effect = subprocess.CalledProcessError(1, "sysctl")

        result = module.check(sample_profile)

        # Should still return result with version info
        assert len(result.findings) == 1
        assert result.findings[0].data.get("model") == "Unknown"

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_fix_supported_version(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test fix() returns appropriate action for supported version."""
        mock_sw_vers.return_value = ("14.6", "23G80")
        mock_sysctl.return_value = "MacBookPro18,1"

        check_result = module.check(sample_profile)
        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) == 1
        assert fix_result.actions[0].success is True
        assert "supported" in fix_result.actions[0].description.lower()

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_fix_eol_version(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test fix() returns upgrade guidance for EOL version."""
        mock_sw_vers.return_value = ("12.6.9", "21H20")
        mock_sysctl.return_value = "iMac21,1"

        check_result = module.check(sample_profile)
        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) == 1
        assert "upgrade" in fix_result.actions[0].description.lower()

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_fix_critical_version(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test fix() returns strong upgrade recommendation for critical version."""
        mock_sw_vers.return_value = ("10.15.7", "19H2")
        mock_sysctl.return_value = "MacBookPro15,2"

        check_result = module.check(sample_profile)
        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) == 1
        assert "critical" in fix_result.actions[0].description.lower() or "urgent" in fix_result.actions[0].description.lower()

    def test_parse_sysctl_output_valid(self):
        """Test parsing valid sysctl output."""
        output = "hw.model: MacBookPro18,1"
        result = _parse_sysctl_output(output)
        assert result == "MacBookPro18,1"

    def test_parse_sysctl_output_with_spaces(self):
        """Test parsing sysctl output with extra spaces."""
        output = "hw.model:   MacBookAir9,2  "
        result = _parse_sysctl_output(output)
        assert result == "MacBookAir9,2"

    def test_parse_sysctl_output_invalid(self):
        """Test parsing invalid sysctl output returns default."""
        output = "invalid output"
        result = _parse_sysctl_output(output)
        assert result == "Unknown"

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_no_findings_for_supported(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test that supported versions produce findings (for user info)."""
        mock_sw_vers.return_value = ("15.0", "24A335")
        mock_sysctl.return_value = "MacBookPro18,1"

        result = module.check(sample_profile)

        # Even supported versions produce an INFO finding
        assert result.has_issues or len(result.findings) > 0

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_version_12_minor_update(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check handles minor version updates correctly."""
        mock_sw_vers.return_value = ("12.0", "21A123")
        mock_sysctl.return_value = "iMac21,1"

        result = module.check(sample_profile)

        assert result.findings[0].severity == Severity.WARNING

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_version_10_16_not_real(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check handles edge case of 10.16 (non-existent)."""
        mock_sw_vers.return_value = ("10.16", "20A123")
        mock_sysctl.return_value = "MacBookPro16,1"

        result = module.check(sample_profile)

        # Should be treated as unknown/critical
        assert len(result.findings) >= 1

    @patch("modules.integrity.macos_eol_check.Module._run_sw_vers")
    @patch("modules.integrity.macos_eol_check.Module._run_sysctl")
    def test_check_version_13_0_zero(self, mock_sysctl, mock_sw_vers, module, sample_profile):
        """Test check handles version 13.0.0 correctly."""
        mock_sw_vers.return_value = ("13.0.0", "22A123")
        mock_sysctl.return_value = "MacBookPro18,2"

        result = module.check(sample_profile)

        assert result.findings[0].severity == Severity.INFO
        assert "Ventura" in result.findings[0].title

    def test_fix_with_empty_findings(self, module):
        """Test fix() handles empty findings list."""
        check_result = CheckResult(module_name=module.name, findings=[])
        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) == 0
