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
        os_version="13.5",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "wifi_security_audit")


def _make_run(current_network_output="", saved_networks_output="", profiler_output=""):
    """Create a mock subprocess.run function."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        # cmd can be a list or string depending on how it's called
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd

        if "getairportnetwork" in cmd_str:
            result.stdout = current_network_output
        elif "listpreferredwirelessnetworks" in cmd_str:
            result.stdout = saved_networks_output
        elif "system_profiler" in cmd_str:
            result.stdout = profiler_output

        return result

    return fake_run


class TestWiFiSecurityAudit:
    """Tests for the Wi-Fi Security Audit module."""

    def test_module_loads(self):
        """Test that the module loads correctly."""
        module = _get_module()
        assert module.name == "wifi_security_audit"
        assert module.category == "network"
        assert Platform.DARWIN in module.platforms
        assert module.risk_level == RiskLevel.SAFE

    def test_no_wifi_connected(self):
        """Test when Wi-Fi is off."""
        module = _get_module()
        profile = _make_profile()

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run("Wi-Fi is off.", ""),
        ):
            result = module.check(profile)

            # Should have no findings when Wi-Fi is off
            assert result.module_name == module.name
            assert not result.has_issues

    def test_wep_network_critical(self):
        """Test CRITICAL finding for WEP network."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: LegacyNetwork"
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: LegacyNetwork\n"
            "  Security: WEP\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, "", profiler_output),
        ):
            result = module.check(profile)

            # Should have critical finding for WEP
            critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
            assert len(critical_findings) > 0
            assert any("WEP" in f.title for f in critical_findings)

    def test_open_network_critical(self):
        """Test CRITICAL finding for open network."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: OpenWiFi"
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: OpenWiFi\n"
            "  Security: None\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, "", profiler_output),
        ):
            result = module.check(profile)

            critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
            assert len(critical_findings) > 0
            assert any("open" in f.title.lower() for f in critical_findings)

    def test_wpa2_only_warning(self):
        """Test WARNING for WPA2 (should upgrade to WPA3)."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: ModernNetwork"
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: ModernNetwork\n"
            "  Security: WPA2\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, "", profiler_output),
        ):
            result = module.check(profile)

            warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
            assert len(warning_findings) > 0
            assert any("WPA2" in f.title for f in warning_findings)

    def test_wpa3_secure(self):
        """Test no warning for WPA3."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: SecureNetwork"
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: SecureNetwork\n"
            "  Security: WPA3\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, "", profiler_output),
        ):
            result = module.check(profile)

            # WPA3 should not trigger security warnings
            security_warnings = [
                f
                for f in result.findings
                if f.severity == Severity.WARNING
                and ("WPA" in f.title or "encryption" in f.title.lower())
            ]
            # Should not have WPA2/WEP warnings
            assert not any("WPA2" in f.title for f in security_warnings)
            assert not any("WEP" in f.title for f in security_warnings)

    def test_saved_networks_wep(self):
        """Test WARNING for WEP networks in saved list."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: GoodNetwork"
        saved_networks = (
            "Preferred networks:\n"
            "OldNetwork\n"
            "GoodNetwork\n"
        )
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: GoodNetwork\n"
            "  Security: WPA3\n"
            "Network: OldNetwork\n"
            "  Security: WEP\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, saved_networks, profiler_output),
        ):
            result = module.check(profile)

            # Should warn about WEP in saved networks
            wep_warnings = [f for f in result.findings if "WEP" in f.title and f.severity == Severity.WARNING]
            assert len(wep_warnings) > 0

    def test_saved_networks_open(self):
        """Test WARNING for open networks in saved list."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: GoodNetwork"
        saved_networks = (
            "Preferred networks:\n"
            "PublicWiFi\n"
            "GoodNetwork\n"
        )
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: GoodNetwork\n"
            "  Security: WPA3\n"
            "Network: PublicWiFi\n"
            "  Security: None\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, saved_networks, profiler_output),
        ):
            result = module.check(profile)

            # Should warn about open networks in saved list
            open_warnings = [f for f in result.findings if "open" in f.title.lower() and f.severity == Severity.WARNING]
            assert len(open_warnings) > 0

    def test_fix_wep_connected(self):
        """Test fix actions for WEP connection."""
        module = _get_module()

        # Create a finding for WEP connection
        from rescue.models import Finding

        findings_data = [
            Finding(
                title="CRITICAL: Currently connected via WEP network",
                description="Test WEP connection",
                severity=Severity.CRITICAL,
                category="network",
                data={"check": "wep_connected"},
            )
        ]
        findings = type("FindingsResult", (), {"findings": findings_data, "module_name": "test"})()

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) > 0
        assert any("WEP" in a.title for a in result.actions)
        assert all(a.success for a in result.actions)

    def test_fix_open_network(self):
        """Test fix actions for open network."""
        module = _get_module()

        from rescue.models import Finding

        findings_data = [
            Finding(
                title="CRITICAL: Connected to open/unencrypted network",
                description="Test open network",
                severity=Severity.CRITICAL,
                category="network",
                data={"check": "open_network_connected"},
            )
        ]
        findings = type("FindingsResult", (), {"findings": findings_data, "module_name": "test"})()

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) > 0
        assert any("open" in a.title.lower() for a in result.actions)

    def test_fix_wpa2_upgrade(self):
        """Test fix actions for WPA2 upgrade suggestion."""
        module = _get_module()

        from rescue.models import Finding

        findings_data = [
            Finding(
                title="WARNING: Using WPA2 (consider upgrading to WPA3)",
                description="Test WPA2",
                severity=Severity.WARNING,
                category="network",
                data={"check": "wpa2_only"},
            )
        ]
        findings = type("FindingsResult", (), {"findings": findings_data, "module_name": "test"})()

        result = module.fix(findings, Mode.AUTO)

        assert len(result.actions) > 0
        assert any("WPA3" in a.title for a in result.actions)

    def test_summary_info_finding(self):
        """Test that summary info finding is generated."""
        module = _get_module()
        profile = _make_profile()

        current_network = "Current Wi-Fi Network: TestNetwork"
        saved_networks = "Preferred networks:\nTestNetwork\nOtherNetwork\n"
        profiler_output = (
            "Current Network Information:\n"
            "  SSID: TestNetwork\n"
            "  Security: WPA3\n"
        )

        with patch(
            "modules.network.wifi_security_audit.subprocess.run",
            side_effect=_make_run(current_network, saved_networks, profiler_output),
        ):
            result = module.check(profile)

            # Should have an info summary finding
            info_findings = [f for f in result.findings if f.severity == Severity.INFO]
            assert len(info_findings) > 0
            assert any("summary" in f.title.lower() for f in info_findings)
