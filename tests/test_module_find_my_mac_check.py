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
    return next(m for m in modules if m.name == "find_my_mac_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_all_enabled():
    """Find My Mac enabled, Location Services enabled, iCloud signed in, Activation Lock enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Enabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_find_my_mac_disabled():
    """Find My Mac disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="0")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Disabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_location_services_disabled():
    """Location Services disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Enabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_icloud_not_signed_in():
    """iCloud not signed in"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="1")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(returncode=1, stderr="not found")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="Activation Lock: Disabled")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(stdout="")
    return fake_run


def _fake_run_all_disabled():
    """All checks fail"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
            if "FindMyMac" in cmd_str:
                return _make_subprocess_result(stdout="0")
            elif "MobileMeAccounts" in cmd_str:
                return _make_subprocess_result(returncode=1, stderr="not found")
            elif "SPHardwareDataType" in cmd_str:
                return _make_subprocess_result(stdout="No Activation Lock")
            elif "locationd" in cmd_str:
                return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(stdout="")
    return fake_run


def test_find_my_mac_check_discovered():
    mod = _get_module()
    assert mod.name == "find_my_mac_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_find_my_mac_check_all_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have INFO about proper configuration
    assert any(
        "properly configured" in f.title.lower() for f in result.findings
    )


def test_find_my_mac_check_find_my_mac_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_find_my_mac_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL finding for disabled Find My Mac
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any("turned off" in f.title.lower() for f in critical_findings)


def test_find_my_mac_check_location_services_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_location_services_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for disabled Location Services
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(
        "location services" in f.title.lower() for f in warning_findings
    )


def test_find_my_mac_check_icloud_not_signed_in():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_icloud_not_signed_in()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have WARNING for iCloud not signed in
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any("icloud" in f.title.lower() for f in warning_findings)


def test_find_my_mac_check_all_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have CRITICAL and WARNING findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0


def test_find_my_mac_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_find_my_mac_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.find_my_mac_check.") for c in declared)


# --- Regression: real macOS 26.3.1 reads, Find My Mac ON ---------------------

# system_profiler SPHardwareDataType (identifiers redacted).
MACOS26_HARDWARE = (
    "Hardware:\n\n    Hardware Overview:\n\n"
    "      Model Name: MacBook Pro\n"
    "      Chip: Apple M3 Max\n"
    "      Serial Number (system): REDACTED\n"
    "      Hardware UUID: 00000000-0000-0000-0000-000000000000\n"
    "      Activation Lock Status: Enabled\n"
)


def _fake_run_macos26(fmm_stdout="1\n", fmm_rc=0):
    """Find My on; /var/db/locationd is root-only so the locationd read fails."""
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "FindMyMac" in cmd_str:
            return _make_subprocess_result(stdout=fmm_stdout, returncode=fmm_rc)
        if "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
        if "SPHardwareDataType" in cmd_str:
            return _make_subprocess_result(stdout=MACOS26_HARDWARE)
        if "locationd" in cmd_str:
            return _make_subprocess_result(
                stderr="The domain/default pair of (/var/db/locationd/Library/"
                "Preferences/ByHost/com.apple.locationd, LocationServicesEnabled) "
                "does not exist\n",
                returncode=1,
            )
        return _make_subprocess_result(returncode=1)
    return fake_run


def test_macos26_unreadable_location_services_is_not_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_macos26()):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.location_services_disabled" not in codes
    assert "security.find_my_mac_check.location_services_unknown" in codes
    assert "security.find_my_mac_check.configured_ok" in codes
    assert all(f.severity == Severity.INFO for f in result.findings)
    ok = next(f for f in result.findings if f.code.endswith("configured_ok"))
    assert ok.data["activation_lock_enabled"] is True
    assert "Activation Lock is on" in ok.description


def test_missing_fmm_pref_is_couldnt_check_not_off():
    mod = _get_module()
    hw_no_lock = "Hardware Overview:\n      Model Name: iMac\n"

    def fake_run(cmd, **kwargs):
        if "SPHardwareDataType" in " ".join(cmd):
            return _make_subprocess_result(stdout=hw_no_lock)
        return _fake_run_macos26(fmm_stdout="", fmm_rc=1)(cmd, **kwargs)

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.find_my_mac_unknown" in codes


def test_command_failure_is_not_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("boom")):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.location_services_disabled" not in codes
    assert "security.find_my_mac_check.send_last_location_disabled" not in codes
    assert "security.find_my_mac_check.find_my_mac_unknown" in codes


# --- Merged from the former find_my_mac module: Send Last Location, Activation
# Lock, the legacy user domain, and macOS 26 system-plist reads. ---------------

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
LOCATIOND = "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd"


def _fake_run(fmm, sll, activation_lock=MACOS26_SYSTEM_PROFILER, user_fmm=MISSING,
              user_sll=MISSING, location_services=MISSING):
    """subprocess.run stand-in keyed on the command.

    ``fmm``/``sll`` are the system plist answers: "1", "0", or MISSING.
    iCloud is signed in; Location Services is unreadable (root-only) unless
    ``location_services`` says otherwise.
    """
    def as_result(v):
        return (_make_subprocess_result(*v) if isinstance(v, tuple)
                else _make_subprocess_result(v + "\n"))

    def fake_run(cmd, **kwargs):
        if cmd[0] == "system_profiler":
            return _make_subprocess_result(activation_lock)
        if cmd[:2] == ["defaults", "read"]:
            if "MobileMeAccounts" in cmd[2]:
                return _make_subprocess_result(stdout="{ Accounts = ({...}); }")
            domain, key = cmd[2], cmd[3]
            table = {
                (SYSTEM_PLIST, "FMMEnabled"): fmm,
                (SYSTEM_PLIST, "SendLastLocation"): sll,
                ("com.apple.FindMyMac", "FMMEnabled"): user_fmm,
                ("com.apple.FindMyMac", "SendLastLocation"): user_sll,
                (LOCATIOND, "LocationServicesEnabled"): location_services,
            }
            return as_result(table.get((domain, key), MISSING))
        return _make_subprocess_result(returncode=1)

    return fake_run


def _codes(result):
    return {f.code for f in result.findings}


def test_send_last_location_disabled():
    """Send Last Location is disabled - WARNING."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("1", "0")):
        result = mod.check(_make_profile())
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("Send Last Location is turned off" in f.title for f in warning_findings)
    assert "security.find_my_mac_check.send_last_location_disabled" in _codes(result)
    assert "security.find_my_mac_check.configured_ok" not in _codes(result)


def test_send_last_location_fix_action():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("1", "0")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert any(a.title == "Enable Send Last Location" for a in fix.actions)


def test_all_on_reports_send_last_location_on():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("1", "1", location_services="1")):
        result = mod.check(_make_profile())
    assert all(f.severity == Severity.INFO for f in result.findings)
    ok = next(f for f in result.findings if f.code.endswith("configured_ok"))
    assert ok.data["send_last_location"] is True
    assert "Send Last Location is on" in ok.description


def test_activation_lock_unknown():
    """No Activation Lock line (older Intel Mac) - unknown INFO, still configured."""
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run("1", "1", activation_lock="Hardware Overview:\n"),
    ):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac_check.activation_lock_unknown" in codes
    assert "security.find_my_mac_check.configured_ok" in codes


def test_find_my_off_is_one_critical_finding():
    """A Mac with Find My off gets exactly one critical finding, not two."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("0", "0", activation_lock="")):
        result = mod.check(_make_profile())
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert [f.code for f in critical] == ["security.find_my_mac_check.find_my_mac_disabled"]


def test_find_my_off_fix_mentions_system_settings():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("0", "0", activation_lock="")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert any("Find My Mac" in a.title for a in fix.actions)
    assert any("System Settings" in a.description for a in fix.actions)


def test_macos26_find_my_on_reads_as_on():
    """macOS 26: FMMEnabled = 1 lives only in the system plist; the user
    domain com.apple.FindMyMac does not exist. That used to read as "off"."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("1", MISSING)):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.send_last_location_disabled" not in codes
    assert "security.find_my_mac_check.configured_ok" in codes
    assert "security.find_my_mac_check.send_last_location_unknown" in codes
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
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.send_last_location_disabled" not in codes
    assert "security.find_my_mac_check.find_my_mac_unknown" in codes
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_activation_lock_enabled_means_find_my_is_on():
    """Pref unreadable but System Information says Activation Lock is on."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(MISSING, MISSING)):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac_check.find_my_mac_disabled" not in codes
    assert "security.find_my_mac_check.configured_ok" in codes


def test_legacy_user_domain_still_read():
    mod = _get_module()
    with patch(
        "subprocess.run",
        side_effect=_fake_run(MISSING, MISSING, activation_lock="",
                              user_fmm="0", user_sll="0"),
    ):
        result = mod.check(_make_profile())
    codes = _codes(result)
    assert "security.find_my_mac_check.find_my_mac_disabled" in codes
    assert "security.find_my_mac_check.send_last_location_disabled" in codes


def test_parse_activation_lock_real_output():
    import importlib
    mod = _get_module()
    parse = importlib.import_module(type(mod).__module__).parse_activation_lock
    assert parse(MACOS26_SYSTEM_PROFILER) is True
    assert parse(MACOS26_SYSTEM_PROFILER.replace("Enabled", "Disabled")) is False
    assert parse("Hardware Overview:\n") is None


def test_former_find_my_mac_module_is_gone():
    modules_dir = Path(__file__).parent.parent / "modules"
    names = {m.name for m in discover_modules(modules_dir)}
    assert "find_my_mac" not in names
    assert "find_my_mac_check" in names
