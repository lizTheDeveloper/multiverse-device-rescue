import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_wifi_diagnostics")


def _make_netsh_interfaces_output(
    ssid="MyNetwork",
    state="connected",
    signal="75 %",
    channel="6",
    band="2.4 GHz",
    speed="65 Mbps",
):
    """Create realistic netsh wlan show interfaces output."""
    return f"""Interface : Wi-Fi
    State                             : {state}
    SSID                              : {ssid}
    BSSID                             : aa:bb:cc:dd:ee:ff
    Network Type                      : Infrastructure
    Radio Type                        : 802.11n
    Authentication                   : WPA2-Personal
    Cipher                            : CCMP
    Connection Mode                   : Auto Connect
    Channel                           : {channel}
    Receive Rate (Mbps)               : 78
    Transmit Rate (Mbps)              : {speed}
    Signal                            : {signal}
    Profile                           : MyNetwork
    Hosted network status             : Not available
    Band                              : {band}
    TX Power                          : 100 %
    Power Saving Mode                 : On
"""


def _make_netsh_profiles_output(profile_count=15):
    """Create realistic netsh wlan show profiles output."""
    output = "Interface : Wi-Fi\n\n"
    for i in range(profile_count):
        output += f"All User Profile : Network{i}\n"
    return output


def _make_netsh_drivers_output(driver_date="07/15/2023"):
    """Create realistic netsh wlan show drivers output."""
    return f"""Interface Type : Native WiFi
Vendor                            : Intel Corporation
Native 802.11 driver version      : 23.40.1.1
Firmware version                  : Intel(R) Wireless WiFi Link Driver
Hardware version                  : Intel(R) Dual Band Wireless-AC 8260
Driver Name                       : iw4win10x64.inf
Radio types supported             : 802.11b 802.11g 802.11n 802.11ac
FIPS 140-2 mode supported         : Yes
Wireless statistics supported     : Yes
Number of MIMO power save options : 3
MIMO power save options           : Static mode, Dynamic mode, Reserved
QoS options supported             : WMM Over UAPSD
Driver Version                    : 23.40.1
Driver Date                       : {driver_date}
"""


def _make_run_result(
    interfaces_output=None,
    profiles_output=None,
    drivers_output=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # netsh wlan show interfaces
        if "wlan" in cmd_str and "show" in cmd_str and "interfaces" in cmd_str:
            if interfaces_output is not None:
                result.stdout = interfaces_output
            elif expect_clean:
                result.stdout = _make_netsh_interfaces_output()
            else:
                result.stdout = _make_netsh_interfaces_output()

        # netsh wlan show profiles
        elif "wlan" in cmd_str and "show" in cmd_str and "profiles" in cmd_str:
            if profiles_output is not None:
                result.stdout = profiles_output
            elif expect_clean:
                result.stdout = _make_netsh_profiles_output(profile_count=10)
            else:
                result.stdout = _make_netsh_profiles_output(profile_count=15)

        # netsh wlan show drivers
        elif "wlan" in cmd_str and "show" in cmd_str and "drivers" in cmd_str:
            if drivers_output is not None:
                result.stdout = drivers_output
            elif expect_clean:
                result.stdout = _make_netsh_drivers_output()
            else:
                result.stdout = _make_netsh_drivers_output()

        return result

    return fake_run


def test_win_wifi_diagnostics_discovered():
    """Test that the module is discoverable."""
    mod = _get_module()
    assert mod.name == "win_wifi_diagnostics"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_wifi_diagnostics_all_pass():
    """Test when all Wi-Fi checks pass (no warnings)."""
    mod = _get_module()
    fake_run = _make_run_result(
        interfaces_output=_make_netsh_interfaces_output(signal="85 %", channel="36"),
        expect_clean=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding for connection details
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should not have warnings
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0


def test_win_wifi_diagnostics_low_signal():
    """Test detection of low signal strength."""
    mod = _get_module()
    low_signal_output = _make_netsh_interfaces_output(signal="35 %", channel="6")
    fake_run = _make_run_result(interfaces_output=low_signal_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    low_signal_findings = [
        f for f in result.findings if f.data.get("check_type") == "low_signal"
    ]
    assert len(low_signal_findings) == 1
    assert low_signal_findings[0].severity == Severity.WARNING


def test_win_wifi_diagnostics_congested_channel():
    """Test detection of congested channel (1, 6, 11 on 2.4GHz)."""
    mod = _get_module()
    # Test channel 1
    congested_output = _make_netsh_interfaces_output(signal="70 %", channel="1")
    fake_run = _make_run_result(interfaces_output=congested_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    congested_findings = [
        f for f in result.findings if f.data.get("check_type") == "congested_channel"
    ]
    assert len(congested_findings) == 1
    assert congested_findings[0].severity == Severity.WARNING

    # Test channel 11
    congested_output = _make_netsh_interfaces_output(signal="70 %", channel="11")
    fake_run = _make_run_result(interfaces_output=congested_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    congested_findings = [
        f for f in result.findings if f.data.get("check_type") == "congested_channel"
    ]
    assert len(congested_findings) == 1


def test_win_wifi_diagnostics_5ghz_not_flagged():
    """Test that 5GHz channels are not flagged as congested."""
    mod = _get_module()
    output_5ghz = _make_netsh_interfaces_output(
        signal="70 %", channel="149", band="5 GHz"
    )
    fake_run = _make_run_result(interfaces_output=output_5ghz)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have connection info but no congestion warning
    congested_findings = [
        f for f in result.findings if f.data.get("check_type") == "congested_channel"
    ]
    assert len(congested_findings) == 0


def test_win_wifi_diagnostics_old_driver():
    """Test detection of outdated Wi-Fi driver."""
    mod = _get_module()
    old_driver_output = _make_netsh_drivers_output(driver_date="03/10/2018")
    fake_run = _make_run_result(drivers_output=old_driver_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    old_driver_findings = [
        f for f in result.findings if f.data.get("check_type") == "old_driver"
    ]
    assert len(old_driver_findings) == 1
    assert old_driver_findings[0].severity == Severity.WARNING


def test_win_wifi_diagnostics_too_many_profiles():
    """Test detection of too many saved profiles."""
    mod = _get_module()
    profiles_output = _make_netsh_profiles_output(profile_count=35)
    fake_run = _make_run_result(profiles_output=profiles_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    profile_findings = [
        f for f in result.findings if f.data.get("check_type") == "too_many_profiles"
    ]
    assert len(profile_findings) == 1
    assert profile_findings[0].severity == Severity.WARNING


def test_win_wifi_diagnostics_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    low_signal_output = _make_netsh_interfaces_output(
        signal="40 %", channel="6"  # low signal + congested channel
    )
    old_driver = _make_netsh_drivers_output(driver_date="01/05/2019")
    profiles_output = _make_netsh_profiles_output(profile_count=40)

    fake_run = _make_run_result(
        interfaces_output=low_signal_output,
        drivers_output=old_driver,
        profiles_output=profiles_output,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect low signal, congested channel, old driver, and too many profiles
    check_types = [f.data.get("check_type") for f in result.findings]
    assert "low_signal" in check_types
    assert "congested_channel" in check_types
    assert "old_driver" in check_types
    assert "too_many_profiles" in check_types


def test_win_wifi_diagnostics_fix_low_signal():
    """Test fix recommendation for low signal."""
    mod = _get_module()
    low_signal_output = _make_netsh_interfaces_output(signal="35 %")
    fake_run = _make_run_result(interfaces_output=low_signal_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    low_signal_actions = [a for a in fix.actions if "signal" in a.title.lower()]
    assert len(low_signal_actions) > 0
    assert low_signal_actions[0].success


def test_win_wifi_diagnostics_fix_old_driver():
    """Test fix recommendation for old driver."""
    mod = _get_module()
    old_driver = _make_netsh_drivers_output(driver_date="12/01/2017")
    fake_run = _make_run_result(drivers_output=old_driver)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    driver_actions = [a for a in fix.actions if "driver" in a.title.lower()]
    assert len(driver_actions) > 0


def test_win_wifi_diagnostics_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_win_wifi_diagnostics_parse_signal_percentage():
    """Test signal percentage parsing."""
    mod = _get_module()
    # Create instance to test the private method
    assert mod._parse_signal_percentage("75 %") == 75
    assert mod._parse_signal_percentage("100%") == 100
    assert mod._parse_signal_percentage("5 %") == 5
    assert mod._parse_signal_percentage("invalid") is None
    assert mod._parse_signal_percentage("") is None
