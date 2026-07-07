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
    return next(m for m in modules if m.name == "network_quality")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy_network_quality():
    """networkQuality with good speeds and responsiveness"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "Measuring download...\n"
                    "Measuring upload...\n"
                    "Measuring responsiveness...\n"
                    "Downlink: 100.5 Mbps\n"
                    "Uplink: 50.3 Mbps\n"
                    "Responsiveness: 95 RPM\n"
                )
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_low_download_speed():
    """networkQuality with low download speed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "Downlink: 5.2 Mbps\n"
                    "Uplink: 2.1 Mbps\n"
                    "Responsiveness: 75 RPM\n"
                )
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_poor_responsiveness():
    """networkQuality with poor responsiveness"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "Downlink: 50.0 Mbps\n"
                    "Uplink: 25.0 Mbps\n"
                    "Responsiveness: 35 RPM\n"
                )
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_network_quality_not_available():
    """networkQuality command not available, fall back to ping"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            raise FileNotFoundError("networkQuality command not found")
        elif "ping" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n"
                    "64 bytes from 8.8.8.8: icmp_seq=0 ttl=119 time=25.3 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=1 ttl=119 time=24.8 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=2 ttl=119 time=26.1 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=3 ttl=119 time=25.5 ms\n"
                    "\n"
                    "--- 8.8.8.8 statistics ---\n"
                    "4 packets transmitted, 4 packets received, 0.0% packet loss\n"
                    "round-trip min/avg/max/stddev = 24.8/25.4/26.1/0.5 ms\n"
                )
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_high_latency():
    """ping test with high latency"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            raise FileNotFoundError("networkQuality command not found")
        elif "ping" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n"
                    "64 bytes from 8.8.8.8: icmp_seq=0 ttl=119 time=150.3 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=1 ttl=119 time=145.8 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=2 ttl=119 time=151.1 ms\n"
                    "64 bytes from 8.8.8.8: icmp_seq=3 ttl=119 time=148.5 ms\n"
                    "\n"
                    "--- 8.8.8.8 statistics ---\n"
                    "4 packets transmitted, 4 packets received, 0.0% packet loss\n"
                    "round-trip min/avg/max/stddev = 145.8/148.9/151.1/2.1 ms\n"
                )
            )
        return _make_subprocess_result()

    return fake_run


def _fake_run_no_connectivity():
    """No network connectivity"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "networkQuality" in cmd_str:
            raise FileNotFoundError("networkQuality command not found")
        elif "ping" in cmd_str:
            return _make_subprocess_result(
                stdout="", returncode=1  # ping failed
            )
        return _make_subprocess_result()

    return fake_run


def test_network_quality_discovered():
    mod = _get_module()
    assert mod.name == "network_quality"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_network_quality_healthy():
    """Test healthy network with networkQuality"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy_network_quality()):
        result = mod.check(_make_profile())

    # Should have INFO finding about network speed
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should not have warnings for good speeds
    assert not any(f.data.get("check") == "low_download_speed" for f in result.findings)
    assert not any(f.data.get("check") == "poor_responsiveness" for f in result.findings)


def test_network_quality_low_download_speed():
    """Test low download speed detection"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_download_speed()):
        result = mod.check(_make_profile())

    # Should have WARNING for low download speed
    warning = next(
        (f for f in result.findings if f.data.get("check") == "low_download_speed"),
        None,
    )
    assert warning is not None
    assert warning.severity == Severity.WARNING


def test_network_quality_poor_responsiveness():
    """Test poor responsiveness detection"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_poor_responsiveness()):
        result = mod.check(_make_profile())

    # Should have WARNING for poor responsiveness
    warning = next(
        (f for f in result.findings if f.data.get("check") == "poor_responsiveness"),
        None,
    )
    assert warning is not None
    assert warning.severity == Severity.WARNING


def test_network_quality_fallback_to_ping():
    """Test fallback to ping when networkQuality is not available"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_network_quality_not_available()):
        result = mod.check(_make_profile())

    # Should have findings from ping test (INFO about network speed + potentially warnings)
    # The ping should return good latency (24.8/25.4/26.1 ms average) so no high_latency warning
    assert len(result.findings) > 0
    # Should have RPM estimated from latency in the info finding
    assert any("rpm" in f.data for f in result.findings)


def test_network_quality_high_latency():
    """Test high latency detection from ping test"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_high_latency()):
        result = mod.check(_make_profile())

    # Should have WARNING for high latency
    warning = next(
        (f for f in result.findings if f.data.get("check") == "high_latency"),
        None,
    )
    assert warning is not None
    assert warning.severity == Severity.WARNING


def test_network_quality_no_connectivity():
    """Test when network is completely unavailable"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_connectivity()):
        result = mod.check(_make_profile())

    # Should have no findings when network test fails
    assert len(result.findings) == 0


def test_network_quality_fix_low_speed():
    """Test fix suggestions for low download speed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_low_download_speed()):
        check_result = mod.check(_make_profile())

    fix_result = mod.fix(check_result, Mode.AUTO)

    # Should have actions for each finding
    assert len(fix_result.actions) > 0
    # All actions should succeed (they're informational)
    assert all(a.success for a in fix_result.actions)
    # Check that speed information action is present
    assert any("speed" in a.title.lower() for a in fix_result.actions)


def test_network_quality_fix_poor_responsiveness():
    """Test fix suggestions for poor responsiveness"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_poor_responsiveness()):
        check_result = mod.check(_make_profile())

    fix_result = mod.fix(check_result, Mode.AUTO)

    # Should have action for poor responsiveness
    responsiveness_action = next(
        (a for a in fix_result.actions if "responsiveness" in a.title.lower()),
        None,
    )
    assert responsiveness_action is not None
    assert responsiveness_action.success is True
