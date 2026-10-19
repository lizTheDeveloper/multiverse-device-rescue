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
    return next(m for m in modules if m.name == "wifi_diagnostics")


def _fake_run_healthy_wifi():
    """Mock subprocess for healthy Wi-Fi connection."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "airport" in cmd or (isinstance(cmd, list) and "airport" in cmd[0]):
            result.stdout = """
     agrctlrssi: -51
     agrextrssi: 0
    agrctlnoise: -86
    agrextnoise: 0
          state: running
        op mode: Â
     lastassocstatus: 0
         802.11 auth: open
           link auth: wpa2-psk
       MCS index: 7
    RSSI: -51
     MCS: 7
     channel: 149,80
     ht cap: 0x6f
     vht cap: 0x338001b2
"""
        return result
    return fake_run


def _fake_run_weak_signal_wifi():
    """Mock subprocess for Wi-Fi with weak signal."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "airport" in cmd or (isinstance(cmd, list) and "airport" in cmd[0]):
            result.stdout = """
     agrctlrssi: -75
     agrextrssi: 0
    agrctlnoise: -88
    agrextnoise: 0
          state: running
        op mode: Â
     lastassocstatus: 0
         802.11 auth: open
           link auth: wpa2-psk
       MCS index: 2
    RSSI: -75
     MCS: 2
     channel: 6
     ht cap: 0x6f
     vht cap: 0x338001b2
"""
        return result
    return fake_run


def _fake_run_low_tx_rate_wifi():
    """Mock subprocess for Wi-Fi with low TX rate."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "airport" in cmd or (isinstance(cmd, list) and "airport" in cmd[0]):
            result.stdout = """
     agrctlrssi: -60
     agrextrssi: 0
    agrctlnoise: -82
    agrextnoise: 0
          state: running
        op mode: Â
     lastassocstatus: 0
         802.11 auth: open
           link auth: wpa2-psk
       MCS index: 0
    RSSI: -60
     MCS: 0
     channel: 1
     ht cap: 0x6f
     vht cap: 0x338001b2
"""
        return result
    return fake_run


def _fake_run_wifi_off():
    """Mock subprocess when Wi-Fi is off (no airport tool, as on macOS 14.4+)."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if "airport" in cmd[0]:
            raise FileNotFoundError(cmd[0])
        result.returncode = 0
        result.stderr = ""
        result.stdout = "Wi-Fi:\n\n      Interfaces:\n        en0:\n          Status: Off\n"
        return result
    return fake_run


def _fake_run_wifi_disconnected():
    """Mock subprocess for Wi-Fi when disconnected."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "airport" in cmd or (isinstance(cmd, list) and "airport" in cmd[0]):
            result.stdout = """
          state: inactive
        op mode: Â
     lastassocstatus: 1
"""
        return result
    return fake_run


def test_wifi_diagnostics_discovered():
    mod = _get_module()
    assert mod.name == "wifi_diagnostics"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_wifi_diagnostics_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_wifi()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_wifi_diagnostics_weak_signal():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_weak_signal_wifi()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "signal_strength" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_diagnostics_low_tx_rate():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_tx_rate_wifi()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "tx_rate" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_diagnostics_wifi_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_off()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "wifi_status" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_wifi_diagnostics_disconnected():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_disconnected()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "connection_status" for f in result.findings)


def test_wifi_diagnostics_fix_weak_signal():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_weak_signal_wifi()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions should be informational (success=True, no modifications)
    assert all(a.success for a in fix.actions)


def test_wifi_diagnostics_fix_low_tx_rate():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_tx_rate_wifi()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_wifi_diagnostics_fix_wifi_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_wifi_off()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert any("Wi-Fi" in a.title or "wifi" in a.title.lower() for a in fix.actions)


# --- Regression: macOS 26.3.1 has no airport tool -----------------------------
# The airport utility was removed in macOS 14.4; its absence used to be
# reported as "Wi-Fi is off or unavailable" on a Mac connected over Wi-Fi.

_SP_AIRPORT_MACOS26 = """Wi-Fi:

      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4388)
          MAC Address: REDACTED
          Status: Connected
          Current Network Information:
            <redacted>:
              PHY Mode: 802.11ac
              Channel: 149 (5GHz, 80MHz)
              Security: WPA/WPA2 Personal
              Signal / Noise: -39 dBm / -92 dBm
              Transmit Rate: 866
              MCS Index: 9
          Other Local Wi-Fi Networks:
            <redacted>:
              Channel: 6 (2GHz, 20MHz)
              Signal / Noise: -85 dBm / -92 dBm
"""


def _fake_no_airport(sp_stdout=_SP_AIRPORT_MACOS26, sp_rc=0):
    def fake_run(cmd, **kwargs):
        if "airport" in cmd[0]:
            raise FileNotFoundError(cmd[0])
        result = MagicMock()
        result.returncode = sp_rc
        result.stderr = ""
        result.stdout = sp_stdout
        return result
    return fake_run


def test_macos26_connected_wifi_without_airport_tool_is_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_no_airport()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_macos26_weak_signal_read_from_current_network_only():
    mod = _get_module()
    weak = _SP_AIRPORT_MACOS26.replace("-39 dBm / -92 dBm", "-82 dBm / -92 dBm")
    with patch("subprocess.run", side_effect=_fake_no_airport(weak)):
        result = mod.check(_make_profile())
    info = mod._parse_system_profiler_output(weak)
    assert info["rssi"] == -82 and info["mcs"] == 9 and info["band"] == "5GHz"
    assert result.has_issues


def test_nothing_readable_is_couldnt_check_not_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_no_airport("", sp_rc=1)):
        result = mod.check(_make_profile())
    assert [f.data["check"] for f in result.findings] == ["wifi_unknown"]
    assert result.findings[0].severity == Severity.INFO
