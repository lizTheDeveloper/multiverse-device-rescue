import sys
from contextlib import contextmanager
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
    return next(m for m in modules if m.name == "keylogger_indicators")


def _make_run_result(
    input_monitoring_apps=None,
    keyboard_hooks=None,
    cgeventtap_processes=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # sqlite3 query for Input Monitoring: hex(client)|client_type|hex(csreq),
        # with no code requirement (nothing verified).
        if "sqlite3" in cmd_str and "kTCCServiceListenEvent" in cmd_str:
            if input_monitoring_apps and not expect_clean:
                result.stdout = "".join(f"{a.encode().hex().upper()}|0|\n" for a in input_monitoring_apps)
            else:
                result.stdout = ""

        # ioreg command for keyboard hooks
        elif "ioreg" in cmd_str and "-l" in cmd_str:
            if keyboard_hooks and not expect_clean:
                result.stdout = "\n".join(keyboard_hooks) + "\n"
            else:
                result.stdout = "Normal system output without keyboard hooks\n"

        # log command for CGEventTap
        elif "log" in cmd_str and "CGEventTap" in cmd_str:
            if cgeventtap_processes and not expect_clean:
                # Real `log show --style compact` output: a header, then
                # "date time type process[pid:tid] message" lines.
                result.stdout = "Timestamp               Ty Process[PID:TID]\n" + "".join(
                    f"2026-10-15 04:10:0{i}.123 Df {name} CGEventTapCreate\n"
                    for i, name in enumerate(cgeventtap_processes)
                )
            else:
                result.stdout = ""

        return result

    return fake_run


@contextmanager
def _commands(mod, fake):
    """Route both subprocess.run (the log query) and the module's bounded
    runner (TCC rows, code requirements) to ``fake``: no real command runs."""
    kmod = sys.modules[type(mod).__module__]
    with patch("subprocess.run", side_effect=fake), patch.object(kmod, "run", side_effect=fake):
        yield


def test_keylogger_indicators_discovered():
    """Test that the module is correctly discovered."""
    mod = _get_module()
    assert mod.name == "keylogger_indicators"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_keylogger_indicators_clean_system():
    """Test when system has no keylogger indicators."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    # Should have no findings when clean
    assert not result.has_issues


def test_keylogger_indicators_input_monitoring_info():
    """Test INFO finding for apps with Input Monitoring access."""
    mod = _get_module()
    apps = ["com.google.Chrome", "com.apple.Terminal"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.data.get("check") == "input_monitoring_access"]
    assert len(info_findings) > 0
    assert info_findings[0].severity == Severity.INFO


def test_keylogger_indicators_known_keylogger_critical():
    """Test CRITICAL severity for known keylogger process names."""
    mod = _get_module()
    # Include a known keylogger
    apps = ["com.apple.Terminal", "com.spyrix.spyware", "com.google.Chrome"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.data.get("check") == "known_keyloggers"]
    assert len(critical_findings) > 0
    assert critical_findings[0].severity == Severity.CRITICAL
    assert "spyrix" in critical_findings[0].data.get("apps", [])[0].lower()


def test_keylogger_indicators_suspicious_app_warning():
    """Test WARNING severity for suspicious apps with Input Monitoring."""
    mod = _get_module()
    apps = ["com.apple.Terminal", "com.suspicious.unknown_app", "com.sketchy.app"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    suspicious_findings = [f for f in result.findings if f.data.get("check") == "suspicious_input_monitoring"]
    assert len(suspicious_findings) > 0
    assert suspicious_findings[0].severity == Severity.WARNING


def test_keylogger_indicators_ioreg_dump_never_flagged_as_hooks():
    """An ordinary ioreg dump (IOKitDiagnostics fragments) is not a keyboard hook."""
    mod = _get_module()
    dump = ["HIDKeyboard device at IOService", "KeyboardEventTap registered",
            '"IOKitDiagnostics" = {"Classes"={"AppleHIDKeyboardEventDriver"=1}}']
    fake_run = _make_run_result(keyboard_hooks=dump)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert not [f for f in result.findings if f.data.get("check") == "keyboard_hooks"]
    assert not any("hook" in f.title.lower() for f in result.findings)


def test_keylogger_indicators_steam_is_not_suspicious():
    mod = _get_module()
    fake_run = _make_run_result(input_monitoring_apps=["com.valvesoftware.steam"])
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    checks = [f.data.get("check") for f in result.findings]
    assert "suspicious_input_monitoring" not in checks
    assert "input_monitoring_access" in checks


def test_keylogger_indicators_cgeventtap():
    """Test detection of CGEventTap usage."""
    mod = _get_module()
    processes = ["com.suspicious.app[12345]", "malware_process[67890]"]
    fake_run = _make_run_result(cgeventtap_processes=processes)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    cgeventtap_findings = [f for f in result.findings if f.data.get("check") == "cgeventtap_usage"]
    assert len(cgeventtap_findings) > 0
    assert cgeventtap_findings[0].severity == Severity.WARNING
    # The process names, never the date column or the header.
    assert cgeventtap_findings[0].data["processes"] == ["com.suspicious.app", "malware_process"]


def test_cgeventtap_query_excludes_only_the_system_log_tool():
    """Our own query is filtered by path; a process merely named "log" still counts."""
    mod = _get_module()
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        result = MagicMock()
        result.returncode = 0
        result.stdout = "2026-10-15 04:10:01.123 Df log[1:2] CGEventTapCreate\n"
        return result

    with _commands(mod, fake_run):
        names = mod._check_cgeventtap_usage()
    assert "processImagePath != '/usr/bin/log'" in " ".join(seen["cmd"])
    assert names == ["log"]


def test_keylogger_indicators_multiple_issues():
    """Test when multiple keylogger indicators are detected."""
    mod = _get_module()
    apps = ["com.cocospy.spyware", "com.unknown.app"]
    hooks = ["HIDKeyboard device"]
    processes = ["suspicious_process[12345]"]
    fake_run = _make_run_result(
        input_monitoring_apps=apps,
        keyboard_hooks=hooks,
        cgeventtap_processes=processes,
    )
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings for: input monitoring, known keyloggers, keyboard hooks, cgeventtap
    checks = [f.data.get("check") for f in result.findings]
    assert "input_monitoring_access" in checks
    assert "known_keyloggers" in checks
    assert "cgeventtap_usage" in checks


def test_keylogger_indicators_all_known_keyloggers():
    """Test detection of all known keylogger names."""
    mod = _get_module()
    # Test with a few different known keyloggers
    keyloggers = ["com.aobo.keylogger", "com.kidlogger.app", "com.mspy.monitor"]
    fake_run = _make_run_result(input_monitoring_apps=keyloggers)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    critical_findings = [f for f in result.findings if f.data.get("check") == "known_keyloggers"]
    assert len(critical_findings) > 0
    assert critical_findings[0].severity == Severity.CRITICAL


def test_keylogger_indicators_fix_input_monitoring():
    """Test fix action for Input Monitoring findings."""
    mod = _get_module()
    apps = ["com.suspicious.app"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for managing input monitoring
    assert any("Input Monitoring" in a.title for a in fix.actions)


def test_keylogger_indicators_fix_known_keyloggers():
    """Test fix action for known keyloggers (CRITICAL)."""
    mod = _get_module()
    apps = ["com.flexispy.spyware"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have critical action to remove keyloggers
    keylogger_actions = [a for a in fix.actions if "keylogger" in a.title.lower()]
    assert len(keylogger_actions) > 0


def test_keylogger_indicators_fix_cgeventtap():
    """Test fix action for CGEventTap usage."""
    mod = _get_module()
    processes = ["unknown_process[12345]"]
    fake_run = _make_run_result(cgeventtap_processes=processes)
    with _commands(mod, fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for investigating CGEventTap
    assert any("CGEventTap" in a.title for a in fix.actions)


def test_keylogger_indicators_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with _commands(mod, error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
    # Should have no findings when subprocess fails
    assert not result.has_issues


def test_keylogger_indicators_well_known_apps_not_flagged():
    """Test that well-known apps are not flagged as suspicious."""
    mod = _get_module()
    # Use well-known apps that shouldn't be flagged
    apps = ["com.apple.Terminal", "com.microsoft.VSCode", "com.sublimetext.3"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding but not WARNING for suspicious apps
    suspicious_findings = [f for f in result.findings if f.data.get("check") == "suspicious_input_monitoring"]
    assert len(suspicious_findings) == 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.keylogger_indicators.") for c in declared)


def test_vendor_prefixed_app_is_listed_as_unverified_info_not_dropped():
    # An app can use any bundle ID; it must stay visible, never silently cleared.
    mod = _get_module()
    fake_run = _make_run_result(
        input_monitoring_apps=["com.valvesoftware.impostor", "com.logitech.evil", "com.apple.impostor"]
    )
    with _commands(mod, fake_run):
        result = mod.check(_make_profile())
    claimed = [f for f in result.findings if f.data.get("check") == "claimed_vendor_input_monitoring"]
    assert len(claimed) == 1
    assert claimed[0].severity == Severity.INFO
    assert set(claimed[0].data["apps"]) == {
        "com.valvesoftware.impostor",
        "com.logitech.evil",
        "com.apple.impostor",
    }
    assert "not verified" in claimed[0].description.lower()
    assert not [f for f in result.findings if f.severity in (Severity.WARNING, Severity.CRITICAL)]
