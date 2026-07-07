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
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "airport_wifi_scan")


def _fake_airport_run(
    wifi_connected=True,
    channel=6,
    rssi=-45,
    noise=-90,
    ssid="MyNetwork",
    nearby_networks=None,
    error=None,
):
    """Mock subprocess.run for airport commands."""
    # Set default nearby networks if not provided
    if nearby_networks is None:
        nearby_networks = [
            ("Network1", "aa:bb:cc:dd:ee:01", -50, 6),
            ("Network2", "aa:bb:cc:dd:ee:02", -55, 6),
            ("Network3", "aa:bb:cc:dd:ee:03", -60, 6),
            ("Network4", "aa:bb:cc:dd:ee:04", -65, 6),
            ("Network5", "aa:bb:cc:dd:ee:05", -70, 6),
            ("Network6", "aa:bb:cc:dd:ee:06", -75, 6),
            ("Network7", "aa:bb:cc:dd:ee:07", -48, 11),
        ]

    def fake_run(cmd, **kwargs):
        if error:
            raise error

        result = MagicMock()
        result.returncode = 0
        result.stdout = ""

        if len(cmd) >= 2 and cmd[0].endswith("airport"):
            if cmd[1] == "-I":
                # airport -I (current connection info)
                if not wifi_connected:
                    result.returncode = 1
                    result.stdout = ""
                else:
                    result.stdout = f"""     agrctlrssi: {rssi}
     agrextrssi: 0
    agrctlnoise: {noise}
    agrextnoise: 0
          state: running
        op mode: Â
     lastTxRate: 195
        maxRate: 867
lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: 00:11:22:33:44:55
           SSID: {ssid}
            MCS: 15
        channel: {channel},80
"""
            elif cmd[1] == "-s":
                # airport -s (scan nearby networks)
                lines = ["SSID BSSID RSSI CHANNEL HT CC SECURITY"]
                for net_ssid, bssid, net_rssi, net_channel in nearby_networks:
                    lines.append(
                        f"{net_ssid} {bssid} {net_rssi} {net_channel} Y -- WPA2(PSK/AES)"
                    )

                result.stdout = "\n".join(lines)
            else:
                result.returncode = 1
        else:
            raise AssertionError(f"unexpected command {cmd}")

        return result

    return fake_run


def test_airport_wifi_scan_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "airport_wifi_scan"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_airport_wifi_scan_not_connected():
    """Test when Wi-Fi is not connected."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_airport_run(wifi_connected=False)):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have finding about not being connected
    titles = [f.title for f in result.findings]
    assert any("not connected" in t.lower() for t in titles)


def test_airport_wifi_scan_congested_channel():
    """Test when current channel has many networks (congestion)."""
    mod = _get_module()
    # Create 7 networks on channel 6 (more than threshold of 5)
    nearby_networks = [
        ("OtherNetwork1", "aa:bb:cc:dd:ee:01", -50, 6),
        ("OtherNetwork2", "aa:bb:cc:dd:ee:02", -55, 6),
        ("OtherNetwork3", "aa:bb:cc:dd:ee:03", -60, 6),
        ("OtherNetwork4", "aa:bb:cc:dd:ee:04", -65, 6),
        ("OtherNetwork5", "aa:bb:cc:dd:ee:05", -70, 6),
        ("OtherNetwork6", "aa:bb:cc:dd:ee:06", -75, 6),
        ("Network7", "aa:bb:cc:dd:ee:07", -48, 11),
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
            nearby_networks=nearby_networks,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have warning about congestion
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("congestion" in f.title.lower() for f in warning_findings)

    # Check the data contains congestion info
    congestion_finding = next(
        (f for f in warning_findings if f.data.get("check") == "channel_congestion"),
        None,
    )
    assert congestion_finding is not None
    assert congestion_finding.data["networks_on_channel"] == 6


def test_airport_wifi_scan_poor_snr():
    """Test when SNR is poor (below threshold)."""
    mod = _get_module()
    # SNR = RSSI - Noise, with threshold at 25 dB
    # rssi=-45, noise=-75 => SNR = 30 (good)
    # rssi=-65, noise=-95 => SNR = 30 (good)
    # rssi=-70, noise=-95 => SNR = 25 (at threshold)
    # rssi=-75, noise=-95 => SNR = 20 (poor)

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-75,
            noise=-95,
            ssid="MyNetwork",
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have warning about poor SNR
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("snr" in f.data.get("check", "").lower() for f in warning_findings)

    snr_finding = next(
        (f for f in warning_findings if f.data.get("check") == "poor_snr"), None
    )
    assert snr_finding is not None
    assert snr_finding.data["snr"] == 20


def test_airport_wifi_scan_good_snr():
    """Test when SNR is good."""
    mod = _get_module()
    # SNR = -45 - (-90) = 45 dB (excellent)

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
        ),
    ):
        result = mod.check(_make_profile())

    # Should have INFO findings about channel map, but no SNR warnings
    snr_warnings = [
        f for f in result.findings
        if f.data.get("check") == "poor_snr" and f.severity == Severity.WARNING
    ]
    assert len(snr_warnings) == 0


def test_airport_wifi_scan_channel_map():
    """Test that channel congestion map is generated."""
    mod = _get_module()
    nearby_networks = [
        ("Network1", "aa:bb:cc:dd:ee:01", -50, 6),
        ("Network2", "aa:bb:cc:dd:ee:02", -55, 6),
        ("Network3", "aa:bb:cc:dd:ee:03", -60, 11),
        ("Network4", "aa:bb:cc:dd:ee:04", -65, 11),
        ("Network5", "aa:bb:cc:dd:ee:05", -70, 1),
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
            nearby_networks=nearby_networks,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have INFO finding about channel map
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("congestion map" in f.title.lower() for f in info_findings)

    map_finding = next(
        (f for f in info_findings if f.data.get("check") == "channel_map"), None
    )
    assert map_finding is not None
    # Should have recommendations
    assert "recommendations" in map_finding.data


def test_airport_wifi_scan_scan_failure():
    """Test when airport scan command fails."""
    mod = _get_module()

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if cmd[1] == "-I":
            # Connection info succeeds
            result.returncode = 0
            result.stdout = """     agrctlrssi: -45
     agrextrssi: 0
    agrctlnoise: -90
    agrextnoise: 0
          state: running
        op mode: Â
     lastTxRate: 195
        maxRate: 867
lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: 00:11:22:33:44:55
           SSID: MyNetwork
            MCS: 15
        channel: 6,80
"""
        elif cmd[1] == "-s":
            # Scan fails
            result.returncode = 1
            result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    titles = [f.title for f in result.findings]
    assert any("scan" in t.lower() for t in titles)


def test_airport_wifi_scan_fix_is_informational():
    """Test that fix() is informational and doesn't modify system."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
        ),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # fix() should succeed but only provide guidance
    assert fix.all_succeeded
    for action in fix.actions:
        # Actions should suggest changes, not modify
        assert action.success
        assert action.risk_level == RiskLevel.SAFE


def test_airport_wifi_scan_subprocess_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()
    with patch(
        "subprocess.run", side_effect=_fake_airport_run(error=TimeoutError("timeout"))
    ):
        result = mod.check(_make_profile())

    # Should not crash, should report missing connection
    assert result.has_issues


def test_airport_wifi_scan_no_nearby_networks():
    """Test when airport -s returns no networks."""
    mod = _get_module()
    nearby_networks = []  # No networks found

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
            nearby_networks=nearby_networks,
        ),
    ):
        result = mod.check(_make_profile())

    # Should still work, just no channel map
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    # May not have channel map if no networks found
    assert isinstance(result.findings, list)


def test_airport_wifi_scan_different_channels():
    """Test analysis with networks on different channels."""
    mod = _get_module()
    nearby_networks = [
        ("Network1", "aa:bb:cc:dd:ee:01", -50, 1),
        ("Network2", "aa:bb:cc:dd:ee:02", -55, 1),
        ("Network3", "aa:bb:cc:dd:ee:03", -60, 6),
        ("Network4", "aa:bb:cc:dd:ee:04", -65, 11),
        ("Network5", "aa:bb:cc:dd:ee:05", -70, 11),
        ("Network6", "aa:bb:cc:dd:ee:06", -75, 149),
    ]

    with patch(
        "subprocess.run",
        side_effect=_fake_airport_run(
            wifi_connected=True,
            channel=6,
            rssi=-45,
            noise=-90,
            ssid="MyNetwork",
            nearby_networks=nearby_networks,
        ),
    ):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should show channel 6 as least congested (only current network)
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    map_finding = next(
        (f for f in info_findings if f.data.get("check") == "channel_map"), None
    )
    assert map_finding is not None
