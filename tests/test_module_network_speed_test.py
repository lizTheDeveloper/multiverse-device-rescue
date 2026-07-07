import pytest
from unittest.mock import Mock, patch, MagicMock

from modules.integrity.network_speed_test import Module
from rescue.models import (
    CheckResult,
    Mode,
    Platform,
    Severity,
    SystemProfile,
)


@pytest.fixture
def module():
    return Module()


@pytest.fixture
def mock_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=17179869184,
    )


class TestNetworkSpeedTestCheck:
    def test_check_with_all_healthy_metrics(self, module, mock_profile):
        """Test check when all network metrics are healthy."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            result = module.check(mock_profile)

            assert isinstance(result, CheckResult)
            assert result.module_name == "network_speed_test"
            # Should have 4 INFO findings
            assert len(result.findings) == 4
            assert all(f.severity == Severity.INFO for f in result.findings)

    def test_check_with_high_gateway_latency(self, module, mock_profile):
        """Test check when gateway latency exceeds threshold."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 15.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            result = module.check(mock_profile)

            assert len(result.findings) == 4
            gateway_findings = [f for f in result.findings if f.data.get("check_type") == "gateway_latency"]
            assert len(gateway_findings) == 1
            assert gateway_findings[0].severity == Severity.WARNING

    def test_check_with_high_internet_latency(self, module, mock_profile):
        """Test check when internet latency exceeds threshold."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 150.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            result = module.check(mock_profile)

            assert len(result.findings) == 4
            internet_findings = [f for f in result.findings if f.data.get("check_type") == "internet_latency"]
            assert len(internet_findings) == 1
            assert internet_findings[0].severity == Severity.WARNING

    def test_check_with_slow_dns(self, module, mock_profile):
        """Test check when DNS resolution is slow."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 600.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            result = module.check(mock_profile)

            assert len(result.findings) == 4
            dns_findings = [f for f in result.findings if f.data.get("check_type") == "dns_resolution_time"]
            assert len(dns_findings) == 1
            assert dns_findings[0].severity == Severity.WARNING

    def test_check_with_low_wifi_speed(self, module, mock_profile):
        """Test check when Wi-Fi speed is low."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 30.0}

            result = module.check(mock_profile)

            assert len(result.findings) == 4
            wifi_findings = [f for f in result.findings if f.data.get("check_type") == "wifi_speed"]
            assert len(wifi_findings) == 1
            assert wifi_findings[0].severity == Severity.WARNING

    def test_check_with_missing_metrics(self, module, mock_profile):
        """Test check when some metrics cannot be measured."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = None
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = None
            mock_wifi.return_value = {"speed_mbps": 200.0}

            result = module.check(mock_profile)

            # Should only have findings for internet and wifi
            assert len(result.findings) == 2


class TestNetworkSpeedTestFix:
    def test_fix_with_gateway_latency_issue(self, module, mock_profile):
        """Test fix suggestions for high gateway latency."""
        check_result = module.check(mock_profile)
        # Mock the check to have a gateway latency finding
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 15.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            check_result = module.check(mock_profile)

        fix_result = module.fix(check_result, Mode.AUTO)

        assert fix_result.module_name == "network_speed_test"
        assert len(fix_result.actions) > 0
        # Should have an action for gateway latency
        gateway_actions = [a for a in fix_result.actions if "local network latency" in a.title.lower()]
        assert len(gateway_actions) > 0

    def test_fix_with_internet_latency_issue(self, module, mock_profile):
        """Test fix suggestions for high internet latency."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 150.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            check_result = module.check(mock_profile)

        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) > 0
        internet_actions = [a for a in fix_result.actions if "internet" in a.title.lower()]
        assert len(internet_actions) > 0

    def test_fix_with_dns_issue(self, module, mock_profile):
        """Test fix suggestions for slow DNS."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 600.0}
            mock_wifi.return_value = {"speed_mbps": 200.0}

            check_result = module.check(mock_profile)

        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) > 0
        dns_actions = [a for a in fix_result.actions if "dns" in a.title.lower()]
        assert len(dns_actions) > 0

    def test_fix_with_wifi_speed_issue(self, module, mock_profile):
        """Test fix suggestions for low Wi-Fi speed."""
        with patch.object(module, "_check_gateway_latency") as mock_gateway, \
             patch.object(module, "_check_internet_latency") as mock_internet, \
             patch.object(module, "_check_dns_resolution_time") as mock_dns, \
             patch.object(module, "_check_wifi_link_speed") as mock_wifi:

            mock_gateway.return_value = {"latency_ms": 5.0, "gateway_ip": "192.168.1.1"}
            mock_internet.return_value = {"latency_ms": 50.0}
            mock_dns.return_value = {"time_ms": 100.0}
            mock_wifi.return_value = {"speed_mbps": 30.0}

            check_result = module.check(mock_profile)

        fix_result = module.fix(check_result, Mode.AUTO)

        assert len(fix_result.actions) > 0
        wifi_actions = [a for a in fix_result.actions if "wi-fi" in a.title.lower()]
        assert len(wifi_actions) > 0


class TestNetworkSpeedTestHelpers:
    def test_parse_ping_latency_valid_output(self, module):
        """Test parsing valid ping output."""
        ping_output = """PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=5.234 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=5.123 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=5.456 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=5.345 ms
64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=5.234 ms

--- 192.168.1.1 statistics ---
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 5.123/5.278/5.456/0.117 ms
"""
        latency = module._parse_ping_latency(ping_output)
        assert latency is not None
        assert abs(latency - 5.278) < 0.01

    def test_parse_ping_latency_no_match(self, module):
        """Test parsing ping output with no valid latency data."""
        ping_output = "Some invalid output"
        latency = module._parse_ping_latency(ping_output)
        assert latency is None

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_gateway_latency_success(self, mock_run, module):
        """Test successful gateway latency check."""
        # Mock route command
        route_result = Mock()
        route_result.returncode = 0
        route_result.stdout = """   route to: 0.0.0.0
destination: 0.0.0.0
       mask: 0.0.0.0
    gateway: 192.168.1.1
  interface: en0
      flags: UGSc
 recvpipe  sendpipe  expire
     0         0         0 """

        # Mock ping command
        ping_result = Mock()
        ping_result.returncode = 0
        ping_result.stdout = """PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=5.234 ms
---
round-trip min/avg/max/stddev = 5.123/5.278/5.456/0.117 ms
"""

        mock_run.side_effect = [route_result, ping_result]

        result = module._check_gateway_latency()

        assert result is not None
        assert result["gateway_ip"] == "192.168.1.1"
        assert abs(result["latency_ms"] - 5.278) < 0.01

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_gateway_latency_failure(self, mock_run, module):
        """Test gateway latency check when route fails."""
        route_result = Mock()
        route_result.returncode = 1
        mock_run.return_value = route_result

        result = module._check_gateway_latency()

        assert result is None

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_internet_latency_success(self, mock_run, module):
        """Test successful internet latency check."""
        ping_result = Mock()
        ping_result.returncode = 0
        ping_result.stdout = """PING 8.8.8.8 (8.8.8.8): 56 data bytes
64 bytes from 8.8.8.8: icmp_seq=0 ttl=119 time=45.234 ms
---
round-trip min/avg/max/stddev = 44.123/45.278/46.456/0.917 ms
"""
        mock_run.return_value = ping_result

        result = module._check_internet_latency()

        assert result is not None
        assert abs(result["latency_ms"] - 45.278) < 0.01

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_dns_resolution_time_success(self, mock_run, module):
        """Test successful DNS resolution time check."""
        dig_result = Mock()
        dig_result.returncode = 0
        dig_result.stdout = """; <<>> DiG 9.10.6
;google.com.				IN	A

;; Query time: 123 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
"""
        mock_run.return_value = dig_result

        result = module._check_dns_resolution_time()

        assert result is not None
        assert result["time_ms"] == 123.0

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_wifi_link_speed_success(self, mock_run, module):
        """Test successful Wi-Fi link speed check."""
        profiler_result = Mock()
        profiler_result.returncode = 0
        profiler_result.stdout = """AirPort:

  agrCtlRSSI: -52
  agrExtRSSI: 0
  agrCtlNoise: -80
  agrExtNoise: 0
  state: running
  op mode: Â station
  lastTxRate: 867
  maxRate: 867
  lastAssocStatus: 0
  802.11 auth: open
  link auth: wpa2-psk
  BSSID: aa:bb:cc:dd:ee:ff
  SSID: MyWiFi
  MCS: 9
  channel: 44,80
  Transmit Rate: 867 Mbps
"""
        mock_run.return_value = profiler_result

        result = module._check_wifi_link_speed()

        assert result is not None
        assert result["speed_mbps"] == 867.0

    @patch("modules.integrity.network_speed_test.subprocess.run")
    def test_check_wifi_link_speed_no_transmit_rate(self, mock_run, module):
        """Test Wi-Fi link speed check when transmit rate is not found."""
        profiler_result = Mock()
        profiler_result.returncode = 0
        profiler_result.stdout = "AirPort: Not connected"
        mock_run.return_value = profiler_result

        result = module._check_wifi_link_speed()

        assert result is None
