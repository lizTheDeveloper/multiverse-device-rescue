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
    return next(m for m in modules if m.name == "find_my_mac")


# Real output captured on macOS 26.3.1 (Apple M3 Max) with Find My Mac ON.
# Serial number, hardware UUID and provisioning UDID are redacted.
MACOS26_SYSTEM_PROFILER = """Hardware:

    Hardware Overview:

      Model Name: MacBook Pro
      Model Identifier: Mac15,8
      Chip: Apple M3 Max
      Total Number of Cores: 16 (12 Performance and 4 Efficiency)
      Memory: 64 GB
      System Firmware Version: 13822.81.10
      OS Loader Version: 13822.81.10
      Serial Number (system): REDACTED
      Hardware UUID: 00000000-0000-0000-0000-000000000000
      Provisioning UDID: 00000000-0000000000000000
      Activation Lock Status: Enabled
"""
# `defaults read <domain> <key>` for a key or domain that doesn't exist.
MISSING = (
    "",
    "2026-10-18 12:55:43.056 defaults[1:1] \n"
    "The domain/default pair of (com.apple.FindMyMac, FMMEnabled) does not exist\n",
    1,
)
SYSTEM_PLIST = "/Library/Preferences/com.apple.FindMyMac.plist"


def _result(stdout="", stderr="", returncode=0):
    r = MagicMock()
    r.stdout, r.stderr, r.returncode = stdout, stderr, returncode
    return r


def _fake_run(fmm, sll, activation_lock=MACOS26_SYSTEM_PROFILER, user_fmm=MISSING,
              user_sll=MISSING):
    """subprocess.run stand-in keyed on the command.

    ``fmm``/``sll`` are the system plist answers: "1", "0", or MISSING.
    """
    def as_result(v):
        return _result(*v) if isinstance(v, tuple) else _result(v + "\n")

    def fake_run(cmd, **kwargs):
        if cmd[0] == "system_profiler":
            return _result(activation_lock)
        if cmd[:2] == ["defaults", "read"]:
            domain, key = cmd[2], cmd[3]
            table = {
                (SYSTEM_PLIST, "FMMEnabled"): fmm,
                (SYSTEM_PLIST, "SendLastLocation"): sll,
                ("com.apple.FindMyMac", "FMMEnabled"): user_fmm,
                ("com.apple.FindMyMac", "SendLastLocation"): user_sll,
            }
            return as_result(table.get((domain, key), MISSING))
        return _result(returncode=1)

    return fake_run


def _codes(result):
    return {f.code for f in result.findings}


def test_find_my_mac_discovered():
    mod = _get_module()
    assert mod.name == "find_my_mac"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_find_my_mac_enabled():
    """All Find My Mac features are enabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("1", "1"),
    ):
        result = mod.check(_make_profile())
    # Should have one INFO finding about proper configuration
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    assert any("properly configured" in f.title.lower() for f in info_findings)


def test_find_my_mac_disabled():
    """Find My Mac is disabled - CRITICAL."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("0", "1"),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert "Find My Mac is turned off" in critical_findings[0].title


def test_send_last_location_disabled():
    """Send Last Location is disabled - WARNING."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("1", "0"),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert "Send Last Location is turned off" in warning_findings[0].title


def test_activation_lock_unknown():
    """No Activation Lock line (older Intel Mac) - unknown INFO, still configured."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("1", "1", activation_lock="Hardware Overview:\n"),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert any("properly configured" in f.title.lower() for f in info_findings)
    assert "security.find_my_mac.activation_lock_unknown" in _codes(result)


def test_find_my_mac_all_disabled():
    """All features are disabled."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("0", "0", activation_lock=""),
    ):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have at least CRITICAL for Find My Mac disabled
    assert len(critical_findings) > 0


def test_find_my_mac_fix():
    """fix() returns informational actions."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("0", "0", activation_lock=""),
    ):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # All actions should succeed (informational)
    assert fix.all_succeeded
    # Should have actions for enabling Find My Mac
    assert any("Find My Mac" in a.title for a in fix.actions)
    # Actions should reference System Settings
    assert any("System Settings" in a.description for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.find_my_mac.") for c in declared)


# --- Regression: "my scan says Find My Mac is off, but it isn't" -------------


def test_macos26_find_my_on_reads_as_on():
    """macOS 26: FMMEnabled = 1 lives only in the system plist; the user
    domain com.apple.FindMyMac does not exist. That used to read as "off"."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("1", MISSING)):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac.find_my_mac_disabled" not in codes
    assert "security.find_my_mac.send_last_location_disabled" not in codes
    assert "security.find_my_mac.configured_ok" in codes
    assert "security.find_my_mac.send_last_location_unknown" in codes
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_unreadable_setting_is_couldnt_check_not_off():
    """Nothing readable anywhere and no Activation Lock line: couldn't check."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(MISSING, MISSING, activation_lock=""),
    ):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac.find_my_mac_disabled" not in codes
    assert "security.find_my_mac.send_last_location_disabled" not in codes
    assert "security.find_my_mac.find_my_mac_unknown" in codes
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_activation_lock_enabled_means_find_my_is_on():
    """Pref unreadable but System Information says Activation Lock is on."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MISSING, MISSING)):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac.find_my_mac_disabled" not in codes
    assert "security.find_my_mac.configured_ok" in codes


def test_command_failure_is_not_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("no defaults")):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac.find_my_mac_disabled" not in codes
    assert "security.find_my_mac.find_my_mac_unknown" in codes


def test_legacy_user_domain_still_read():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(MISSING, MISSING, activation_lock="",
                              user_fmm="0", user_sll="0"),
    ):
        result = mod.check(_make_profile())
    assert "security.find_my_mac.find_my_mac_disabled" in _codes(result)


def test_parse_activation_lock_real_output():
    import importlib
    mod = _get_module()
    parse = importlib.import_module(type(mod).__module__).parse_activation_lock
    assert parse(MACOS26_SYSTEM_PROFILER) is True
    assert parse(MACOS26_SYSTEM_PROFILER.replace("Enabled", "Disabled")) is False
    assert parse("Hardware Overview:\n") is None
