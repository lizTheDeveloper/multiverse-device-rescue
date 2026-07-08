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
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "thermal_throttle_check")


def _make_subprocess_result(
    temp_celsius=None,
    current_freq_ghz=None,
    max_freq_ghz=None,
    throttled=False,
    fan_actual_rpm=None,
    fan_nominal_rpm=None,
):
    """Create a fake subprocess.run that returns thermal data based on parameters."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # powermetrics command
        if "powermetrics" in cmd_str:
            if temp_celsius is not None:
                result.stdout = f"CPU die temperature         : {temp_celsius:.1f} °C\n"
            else:
                result.stdout = ""

        # sysctl hw.cpufrequency
        elif "hw.cpufrequency" in cmd_str and "max" not in cmd_str:
            if current_freq_ghz is not None:
                freq_hz = int(current_freq_ghz * 1e9)
                result.stdout = f"hw.cpufrequency: {freq_hz}\n"
            else:
                result.stdout = ""

        # sysctl hw.cpufrequency_max
        elif "hw.cpufrequency_max" in cmd_str:
            if max_freq_ghz is not None:
                freq_hz = int(max_freq_ghz * 1e9)
                result.stdout = f"hw.cpufrequency_max: {freq_hz}\n"
            else:
                result.stdout = ""

        # pmset -g thermlog
        elif "pmset" in cmd_str and "thermlog" in cmd_str:
            if throttled:
                result.stdout = "Thermal conditions are active. Throttling is true.\n"
            else:
                result.stdout = "Thermal conditions are inactive. Throttling is false.\n"

        # ioreg for AppleSMCFan
        elif "ioreg" in cmd_str and "AppleSMCFan" in cmd_str:
            if fan_actual_rpm is not None and fan_nominal_rpm is not None:
                result.stdout = (
                    f'| |             "ActualSpeed" = {fan_actual_rpm}\n'
                    f'| |             "NominalSpeed" = {fan_nominal_rpm}\n'
                )
            else:
                result.stdout = ""

        # ioreg for AppleSMC
        elif "ioreg" in cmd_str and "AppleSMC" in cmd_str:
            if temp_celsius is not None:
                # ioreg uses millidegrees
                temp_millidegrees = int(temp_celsius * 1000)
                result.stdout = f'"CurrentReading" = {temp_millidegrees}\n'
            else:
                result.stdout = ""

        return result

    return fake_run


def test_thermal_throttle_check_discovered():
    """Test that the module is discovered with correct metadata."""
    mod = _get_module()
    assert mod.name == "thermal_throttle_check"
    assert mod.category == "performance"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_thermal_normal_temperature():
    """Test with normal CPU temperature."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=65.0,
        current_freq_ghz=2.8,
        max_freq_ghz=3.2,
        throttled=False,
        fan_actual_rpm=2000,
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have findings but no warnings/critical
    assert result.has_issues
    temp_findings = [f for f in result.findings if f.data.get("check") == "cpu_temperature"]
    assert len(temp_findings) > 0
    assert temp_findings[0].severity == Severity.INFO


def test_thermal_warning_temperature():
    """Test with elevated temperature (warning level)."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=85.0,
        current_freq_ghz=2.6,
        max_freq_ghz=3.2,
        throttled=True,
        fan_actual_rpm=4500,
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    temp_findings = [f for f in result.findings if f.data.get("check") == "cpu_temperature"]
    assert len(temp_findings) > 0
    assert temp_findings[0].severity == Severity.WARNING
    assert "85.0" in temp_findings[0].description


def test_thermal_critical_temperature():
    """Test with critical temperature."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=98.5,
        current_freq_ghz=1.8,
        max_freq_ghz=3.2,
        throttled=True,
        fan_actual_rpm=5000,
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    temp_findings = [f for f in result.findings if f.data.get("check") == "cpu_temperature"]
    assert len(temp_findings) > 0
    assert temp_findings[0].severity == Severity.CRITICAL
    assert "98.5" in temp_findings[0].description


def test_thermal_cpu_frequency_throttled():
    """Test when CPU frequency is reduced (throttling)."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=82.0,
        current_freq_ghz=1.6,  # 50% of max
        max_freq_ghz=3.2,
        throttled=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    freq_findings = [f for f in result.findings if f.data.get("check") == "cpu_frequency"]
    assert len(freq_findings) > 0
    # Should be warning because below 80% of max
    assert freq_findings[0].severity == Severity.WARNING
    assert "1.60 GHz" in freq_findings[0].description


def test_thermal_cpu_frequency_normal():
    """Test when CPU frequency is normal."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=65.0,
        current_freq_ghz=3.0,  # 94% of max (> 80%)
        max_freq_ghz=3.2,
        throttled=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    freq_findings = [f for f in result.findings if f.data.get("check") == "cpu_frequency"]
    assert len(freq_findings) > 0
    assert freq_findings[0].severity == Severity.INFO


def test_thermal_throttle_active():
    """Test when thermal throttling is active."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=88.0,
        current_freq_ghz=2.5,
        max_freq_ghz=3.2,
        throttled=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    throttle_findings = [f for f in result.findings if f.data.get("check") == "thermal_throttle_state"]
    assert len(throttle_findings) > 0
    assert throttle_findings[0].severity == Severity.WARNING
    assert "Thermal throttling is active" in throttle_findings[0].title


def test_thermal_throttle_inactive():
    """Test when thermal throttling is not active."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=60.0,
        current_freq_ghz=3.2,
        max_freq_ghz=3.2,
        throttled=False,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    throttle_findings = [f for f in result.findings if f.data.get("check") == "thermal_throttle_state"]
    assert len(throttle_findings) > 0
    assert throttle_findings[0].severity == Severity.INFO


def test_thermal_fans_at_max():
    """Test when fans are running at maximum speed."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=85.0,
        current_freq_ghz=2.5,
        max_freq_ghz=3.2,
        throttled=True,
        fan_actual_rpm=5000,  # 100% of nominal
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    fan_findings = [f for f in result.findings if f.data.get("check") == "fan_speed"]
    assert len(fan_findings) > 0
    assert fan_findings[0].severity == Severity.WARNING
    assert "high speed" in fan_findings[0].title.lower()


def test_thermal_fans_normal():
    """Test when fans are running at normal speed."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=60.0,
        current_freq_ghz=3.0,
        max_freq_ghz=3.2,
        throttled=False,
        fan_actual_rpm=1500,  # 30% of nominal
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    fan_findings = [f for f in result.findings if f.data.get("check") == "fan_speed"]
    assert len(fan_findings) > 0
    assert fan_findings[0].severity == Severity.INFO


def test_thermal_critical_fix():
    """Test fix recommendations for critical temperature."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=97.0,
        current_freq_ghz=1.5,
        max_freq_ghz=3.2,
        throttled=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    critical_actions = [a for a in fix.actions if "critical" in a.title.lower()]
    assert len(critical_actions) > 0
    assert "shut down" in critical_actions[0].description.lower()
    assert "thermal paste" in critical_actions[0].description.lower()


def test_thermal_warning_fix():
    """Test fix recommendations for warning temperature."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=85.0,
        current_freq_ghz=2.5,
        max_freq_ghz=3.2,
        throttled=True,
    )
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    warning_actions = [a for a in fix.actions if "warning" in a.title.lower()]
    assert len(warning_actions) > 0
    assert "compressed air" in warning_actions[0].description.lower()


def test_thermal_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_thermal_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_thermal_all_checks_combined():
    """Test when all thermal checks detect issues."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=92.0,  # WARNING
        current_freq_ghz=1.9,  # Throttled (59% of max)
        max_freq_ghz=3.2,
        throttled=True,  # Actively throttling
        fan_actual_rpm=4800,  # Near max (96%)
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    # Should have findings from multiple checks
    checks_found = {f.data.get("check") for f in result.findings}
    assert "cpu_temperature" in checks_found
    assert "cpu_frequency" in checks_found
    assert "thermal_throttle_state" in checks_found
    assert "fan_speed" in checks_found

    # Check severity levels
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warnings) > 0


def test_thermal_clean_system():
    """Test with a completely clean thermal system."""
    mod = _get_module()
    fake_run = _make_subprocess_result(
        temp_celsius=50.0,
        current_freq_ghz=3.2,
        max_freq_ghz=3.2,
        throttled=False,
        fan_actual_rpm=1200,
        fan_nominal_rpm=5000,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues  # Will have INFO findings
    # All findings should be INFO severity
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) == 0
    assert len(warning_findings) == 0
