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

        # sqlite3 query for Input Monitoring
        if "sqlite3" in cmd_str and "kTCCServiceListenEvent" in cmd_str:
            if input_monitoring_apps and not expect_clean:
                result.stdout = "\n".join(input_monitoring_apps) + "\n"
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
                result.stdout = "\n".join(cgeventtap_processes) + "\n"
            else:
                result.stdout = ""

        return result

    return fake_run


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
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no findings when clean
    assert not result.has_issues


def test_keylogger_indicators_input_monitoring_info():
    """Test INFO finding for apps with Input Monitoring access."""
    mod = _get_module()
    apps = ["com.google.Chrome", "com.apple.Terminal"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with patch("subprocess.run", side_effect=fake_run):
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
    with patch("subprocess.run", side_effect=fake_run):
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
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    suspicious_findings = [f for f in result.findings if f.data.get("check") == "suspicious_input_monitoring"]
    assert len(suspicious_findings) > 0
    assert suspicious_findings[0].severity == Severity.WARNING


def test_keylogger_indicators_keyboard_hooks():
    """Test detection of keyboard event hooks."""
    mod = _get_module()
    hooks = ["HIDKeyboard device at IOService", "KeyboardEventTap registered"]
    fake_run = _make_run_result(keyboard_hooks=hooks)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    hook_findings = [f for f in result.findings if f.data.get("check") == "keyboard_hooks"]
    assert len(hook_findings) > 0
    assert hook_findings[0].severity == Severity.WARNING


def test_keylogger_indicators_cgeventtap():
    """Test detection of CGEventTap usage."""
    mod = _get_module()
    processes = ["com.suspicious.app[12345]", "malware_process[67890]"]
    fake_run = _make_run_result(cgeventtap_processes=processes)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    cgeventtap_findings = [f for f in result.findings if f.data.get("check") == "cgeventtap_usage"]
    assert len(cgeventtap_findings) > 0
    assert cgeventtap_findings[0].severity == Severity.WARNING


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
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have findings for: input monitoring, known keyloggers, keyboard hooks, cgeventtap
    checks = [f.data.get("check") for f in result.findings]
    assert "input_monitoring_access" in checks
    assert "known_keyloggers" in checks
    assert "keyboard_hooks" in checks
    assert "cgeventtap_usage" in checks


def test_keylogger_indicators_all_known_keyloggers():
    """Test detection of all known keylogger names."""
    mod = _get_module()
    # Test with a few different known keyloggers
    keyloggers = ["com.aobo.keylogger", "com.kidlogger.app", "com.mspy.monitor"]
    fake_run = _make_run_result(input_monitoring_apps=keyloggers)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    critical_findings = [f for f in result.findings if f.data.get("check") == "known_keyloggers"]
    assert len(critical_findings) > 0
    assert critical_findings[0].severity == Severity.CRITICAL


def test_keylogger_indicators_fix_input_monitoring():
    """Test fix action for Input Monitoring findings."""
    mod = _get_module()
    apps = ["com.suspicious.app"]
    fake_run = _make_run_result(input_monitoring_apps=apps)
    with patch("subprocess.run", side_effect=fake_run):
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
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have critical action to remove keyloggers
    keylogger_actions = [a for a in fix.actions if "keylogger" in a.title.lower()]
    assert len(keylogger_actions) > 0


def test_keylogger_indicators_fix_keyboard_hooks():
    """Test fix action for keyboard hooks."""
    mod = _get_module()
    hooks = ["HIDKeyboard event detected"]
    fake_run = _make_run_result(keyboard_hooks=hooks)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    # Should have action for investigating hooks
    assert any("keyboard" in a.title.lower() for a in fix.actions)


def test_keylogger_indicators_fix_cgeventtap():
    """Test fix action for CGEventTap usage."""
    mod = _get_module()
    processes = ["unknown_process[12345]"]
    fake_run = _make_run_result(cgeventtap_processes=processes)
    with patch("subprocess.run", side_effect=fake_run):
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

    with patch("subprocess.run", side_effect=error_run):
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
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have INFO finding but not WARNING for suspicious apps
    suspicious_findings = [f for f in result.findings if f.data.get("check") == "suspicious_input_monitoring"]
    assert len(suspicious_findings) == 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.keylogger_indicators.") for c in declared)
