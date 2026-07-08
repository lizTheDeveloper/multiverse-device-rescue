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
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "energy_saver_check")


def _make_run_result(pmset_output=None, pmset_sched_output=None):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()

        # pmset -g (general power settings)
        if "pmset" in cmd_list and "-g" in cmd_list and "sched" not in cmd_list:
            if pmset_output:
                result.stdout = pmset_output
            else:
                # Default normal output
                result.stdout = """\
 Boot Command:
  hibernatemode        3
  powernap             1
  displaysleep         10
  sleep                30
  disksleep            10
  wakeonlan            1
  disablesleep         0
  Currently in use:
  AC Power:
   hibernatemode        3
   powernap             1
   displaysleep         10
   sleep                30
   disksleep            10
   wakeonlan            1
  Battery Power:
   hibernatemode        3
   powernap             1
   displaysleep         10
   sleep                30
   disksleep            10
   wakeonlan            0
"""
        # pmset -g sched (scheduled events)
        elif "pmset" in cmd_list and "-g" in cmd_list and "sched" in cmd_list:
            if pmset_sched_output is not None:
                result.stdout = pmset_sched_output
            else:
                result.stdout = "No scheduled power on/off events.\n"

        return result

    return fake_run


def test_energy_saver_check_discovered():
    """Test that module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "energy_saver_check"
    assert mod.category == "performance"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_energy_saver_check_normal_config():
    """Test when power settings are normal."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 powernap             0
 displaysleep         10
 sleep                30
 disksleep            10
 wakeonlan            0
 disablesleep         0
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO findings for configuration
    assert any(f.severity == Severity.INFO for f in result.findings)
    assert any(f.data.get("check") == "config_normal" for f in result.findings)


def test_energy_saver_check_display_sleep_disabled():
    """Test detection of disabled display sleep."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 displaysleep         0
 sleep                30
 disksleep            10
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "display_sleep_disabled" for f in result.findings)
    assert any(
        f.severity == Severity.WARNING
        and "Display sleep disabled" in f.title
        for f in result.findings
    )


def test_energy_saver_check_computer_sleep_disabled():
    """Test detection of disabled computer sleep."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 displaysleep         10
 sleep                0
 disksleep            10
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "computer_sleep_disabled" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_energy_saver_check_disk_sleep_disabled():
    """Test detection of disabled disk sleep."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 displaysleep         10
 sleep                30
 disksleep            0
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "disk_sleep_disabled" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_energy_saver_check_power_nap_on_battery():
    """Test detection of Power Nap enabled on battery."""
    mod = _get_module()
    pmset_output = """\
 Currently in use:
 Battery Power:
  powernap             1
  displaysleep         10
  sleep                30
  disksleep            10
  wakeonlan            0
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "power_nap_on_battery" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_energy_saver_check_power_nap_on_ac():
    """Test Power Nap enabled on AC power (acceptable)."""
    mod = _get_module()
    pmset_output = """\
 Currently in use:
 AC Power:
  powernap             1
  displaysleep         10
  sleep                30
  disksleep            10
  wakeonlan            1
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "power_nap_enabled" for f in result.findings)
    power_nap_finding = [f for f in result.findings if f.data.get("check") == "power_nap_enabled"]
    assert power_nap_finding[0].severity == Severity.INFO


def test_energy_saver_check_wake_on_lan_battery():
    """Test Wake for network access enabled on battery."""
    mod = _get_module()
    pmset_output = """\
 Currently in use:
 Battery Power:
  powernap             0
  displaysleep         10
  sleep                30
  disksleep            10
  wakeonlan            1
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "wake_on_lan_battery" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_energy_saver_check_wake_on_lan_ac():
    """Test Wake for network access enabled on AC power."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 powernap             0
 displaysleep         10
 sleep                30
 disksleep            10
 wakeonlan            1
 Currently in use:
 AC Power
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "wake_on_lan_enabled" for f in result.findings)
    wol_findings = [f for f in result.findings if f.data.get("check") == "wake_on_lan_enabled"]
    assert len(wol_findings) > 0
    assert wol_findings[0].severity == Severity.INFO


def test_energy_saver_check_prevent_sleep_display_off():
    """Test detection of prevent sleep when display is off."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 displaysleep         10
 sleep                30
 disksleep            10
 disablesleep         1
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "prevent_sleep_display_off" for f in result.findings)


def test_energy_saver_check_hibernation_mode():
    """Test hibernation mode reporting."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        0
 displaysleep         10
 sleep                30
 disksleep            10
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "hibernation_mode" for f in result.findings)
    hib_finding = [f for f in result.findings if f.data.get("check") == "hibernation_mode"]
    assert hib_finding[0].data.get("value") == 0


def test_energy_saver_check_scheduled_events():
    """Test detection of scheduled wake/sleep events."""
    mod = _get_module()
    sched_output = """\
Scheduled power on/off events:
01/15/2024 08:00:00 [System]
01/20/2024 18:00:00 [Sleep]
"""
    fake_run = _make_run_result(
        pmset_output="displaysleep         10\nsleep                30",
        pmset_sched_output=sched_output,
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "scheduled_events" for f in result.findings)
    sched_finding = [f for f in result.findings if f.data.get("check") == "scheduled_events"]
    assert sched_finding[0].data.get("event_count") == 2


def test_energy_saver_check_no_scheduled_events():
    """Test when there are no scheduled events."""
    mod = _get_module()
    sched_output = "No scheduled power on/off events.\n"
    fake_run = _make_run_result(pmset_sched_output=sched_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should not have scheduled_events finding when none exist
    assert not any(f.data.get("check") == "scheduled_events" for f in result.findings)


def test_energy_saver_check_fix_display_sleep():
    """Test fix recommendation for disabled display sleep."""
    mod = _get_module()
    pmset_output = """\
 hibernatemode        3
 displaysleep         0
 sleep                30
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    display_actions = [a for a in fix.actions if "display" in a.title.lower()]
    assert len(display_actions) > 0
    assert "pmset" in display_actions[0].description or "Settings" in display_actions[0].description


def test_energy_saver_check_fix_power_nap_battery():
    """Test fix recommendation for Power Nap on battery."""
    mod = _get_module()
    pmset_output = """\
 Currently in use:
 Battery Power:
  powernap             1
  displaysleep         10
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    assert any("Power Nap" in a.title and "battery" in a.description.lower() for a in fix.actions)


def test_energy_saver_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing and return an empty result
    assert isinstance(result.findings, list)


def test_energy_saver_check_multiple_issues():
    """Test when multiple power issues are detected."""
    mod = _get_module()
    pmset_output = """\
 Currently in use:
 Battery Power:
  hibernatemode        3
  powernap             1
  displaysleep         0
  sleep                0
  disksleep            10
  wakeonlan            1
  disablesleep         1
"""
    fake_run = _make_run_result(pmset_output=pmset_output)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should detect multiple issues
    checks = [f.data.get("check") for f in result.findings]
    assert "display_sleep_disabled" in checks
    assert "computer_sleep_disabled" in checks
    assert "power_nap_on_battery" in checks
    assert "wake_on_lan_battery" in checks
