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
    return next(m for m in modules if m.name == "firewall_rules_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# Real socketfilterfw output, captured on macOS 26.3.1 (user paths redacted).
GLOBAL_ON = "Firewall is enabled. (State = 1)\n"
GLOBAL_OFF = "Firewall is disabled. (State = 0)\n"
STEALTH_ON = "Firewall stealth mode is on\n"
STEALTH_OFF = "Firewall stealth mode is off\n"
BLOCKALL_OFF = "Firewall has block all state set to disabled.\n"
SIGNED_ON = (
    "Automatically allow built-in signed software ENABLED.\n"
    "Automatically allow downloaded signed software ENABLED.\n"
)
SIGNED_OFF = (
    "Automatically allow built-in signed software DISABLED.\n"
    "Automatically allow downloaded signed software DISABLED.\n"
)


def _listapps(n, status="Allow incoming connections"):
    lines = [f"Total number of apps = {n} "]
    for i in range(1, n + 1):
        lines.append(f"{i} : /Applications/App{i}.app ")
        lines.append(f"             ({status})")
    return "\n".join(lines) + "\n"


LISTAPPS_MACOS26 = (
    "Total number of apps = 3 \n"
    "1 : /Users/REDACTED/Library/Caches/ms-playwright/chromium-1217/chrome-mac-arm64/"
    "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing "
    "Framework.framework/Versions/147.0.7727.15/Helpers/Google Chrome for Testing Helper.app \n"
    "             (Allow incoming connections)\n"
    "2 : /System/Applications/Utilities/Terminal.app \n"
    "             (Allow incoming connections)\n"
    "3 : /Applications/zoom.us.app/Contents/MacOS/zoom.us \n"
    "             (Block incoming connections)\n"
)


def _fake(globalstate=GLOBAL_ON, stealth=STEALTH_ON, listapps=None, blockall=BLOCKALL_OFF,
          allowsigned=SIGNED_OFF, fail=()):
    """A subprocess.run stand-in answering like socketfilterfw on macOS 26.

    ``fail`` names flags that exit non-zero (couldn't be read). The old
    com.apple.alf.plist does not exist on macOS 26, so ``defaults read`` of it
    fails like it does on a real Mac.
    """
    if listapps is None:
        listapps = _listapps(2)
    answers = {
        "--getglobalstate": globalstate,
        "--getstealthmode": stealth,
        "--listapps": listapps,
        "--getblockall": blockall,
        "--getallowsigned": allowsigned,
    }

    def fake_run(cmd, **kwargs):
        if cmd and cmd[0] == "defaults":
            return _make_subprocess_result(
                stderr="The domain/default pair of (/Library/Preferences/com.apple.alf, "
                "globalstate) does not exist", returncode=1)
        flag = cmd[-1]
        if flag in fail:
            return _make_subprocess_result(stderr="error", returncode=1)
        return _make_subprocess_result(stdout=answers.get(flag, ""))
    return fake_run


def _fake_run_firewall_enabled_secure():
    """Firewall enabled, stealth on, few apps, strict settings"""
    return _fake()


def _fake_run_firewall_disabled():
    """Firewall is disabled"""
    return _fake(globalstate=GLOBAL_OFF, stealth=STEALTH_OFF, listapps="Total number of apps = 0 \n")


def _fake_run_stealth_disabled():
    """Firewall enabled but stealth mode disabled"""
    return _fake(stealth=STEALTH_OFF, listapps=_listapps(1))


def _fake_run_too_many_apps():
    """Firewall enabled but too many apps allowed (>30)"""
    return _fake(listapps=_listapps(35))


def _fake_run_allow_signed_enabled():
    """Firewall enabled with allow signed software enabled"""
    return _fake(listapps=_listapps(1), allowsigned=SIGNED_ON)


def _fake_run_all_issues():
    """All firewall issues present"""
    return _fake(globalstate=GLOBAL_OFF, stealth=STEALTH_OFF, listapps=_listapps(35),
                 allowsigned=SIGNED_ON)


def test_firewall_rules_audit_discovered():
    mod = _get_module()
    assert mod.name == "firewall_rules_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_firewall_enabled_secure():
    """Firewall is enabled with secure settings - should only have summary"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_enabled_secure()):
        result = mod.check(_make_profile())
    # Should have findings (at least the summary)
    assert result.has_issues
    # Only summary finding, no warnings/critical
    assert len(result.findings) == 1
    assert result.findings[0].data.get("check") == "firewall_summary"
    assert result.findings[0].severity == Severity.INFO


def test_firewall_disabled_critical():
    """Firewall is disabled - should flag as CRITICAL"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical finding for disabled firewall plus summary
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].data.get("check") == "alf_disabled"


def test_stealth_mode_disabled_warning():
    """Stealth mode disabled - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_stealth_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for stealth disabled and summary
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "stealth_disabled"


def test_too_many_apps_warning():
    """Too many apps allowed - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_too_many_apps()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for too many apps
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "too_many_apps"
    assert warning_findings[0].data.get("count") == 35


def test_allow_signed_enabled_warning():
    """Allow signed software enabled - should flag as WARNING"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_allow_signed_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for allow signed
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) == 1
    assert warning_findings[0].data.get("check") == "allow_signed_enabled"


def test_all_issues_present():
    """All firewall issues present"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have critical for disabled firewall, summary, plus potentially others
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 1
    assert critical_findings[0].data.get("check") == "alf_disabled"


def test_firewall_rules_audit_fix_is_informational():
    """fix() should always succeed with informational messages"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_disabled()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should be SAFE risk level
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_firewall_rules_audit_fix_creates_actions():
    """fix() should create actions for each issue"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_all_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for each non-summary finding
    issue_findings = [f for f in check.findings if f.data.get("check") != "firewall_summary"]
    assert len(fix.actions) >= len(issue_findings)


def test_firewall_summary_has_all_fields():
    """Firewall summary should include all configuration fields"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_firewall_enabled_secure()):
        result = mod.check(_make_profile())
    assert result.has_issues
    summary_findings = [f for f in result.findings if f.data.get("check") == "firewall_summary"]
    assert len(summary_findings) == 1
    summary = summary_findings[0]
    assert "alf_enabled" in summary.data
    assert "stealth_enabled" in summary.data
    assert "block_all" in summary.data
    assert "allow_signed" in summary.data
    assert "allowed_apps_count" in summary.data


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.firewall_rules_audit.") for c in declared)


# --- Regression: macOS 26 has no com.apple.alf.plist -------------------------
# The module used to read `defaults read /Library/Preferences/com.apple.alf
# globalstate`, which fails on macOS 15+/26, and reported "Your Mac's firewall
# is turned off" on a Mac whose firewall was on.


def test_macos26_firewall_on_is_not_reported_off():
    """Observed on macOS 26.3.1: firewall on, stealth off, allow-signed on."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(
        stealth=STEALTH_OFF, listapps=LISTAPPS_MACOS26, allowsigned=SIGNED_ON,
    )):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.firewall_rules_audit.alf_disabled" not in codes
    assert "security.firewall_rules_audit.alf_unknown" not in codes
    assert "security.firewall_rules_audit.stealth_disabled" in codes
    assert "security.firewall_rules_audit.allow_signed_enabled" in codes
    summary = next(f for f in result.findings if f.data.get("check") == "firewall_summary")
    assert summary.data["alf_enabled"] is True
    assert summary.data["stealth_enabled"] is False
    assert summary.data["block_all"] is False
    assert summary.data["allow_signed"] is True
    assert "Firewall: On" in summary.description


def test_listapps_counts_only_allowed_apps_from_two_line_format():
    """macOS prints the status on the line after the app; it used to count 0."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(listapps=LISTAPPS_MACOS26)):
        result = mod.check(_make_profile())
    summary = next(f for f in result.findings if f.data.get("check") == "firewall_summary")
    assert summary.data["allowed_apps_count"] == 2
    assert summary.data["allowed_apps"] == ["Google Chrome for Testing Helper", "Terminal"]


def test_listapps_38_apps_flags_too_many():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(listapps=_listapps(38))):
        result = mod.check(_make_profile())
    too_many = [f for f in result.findings if f.data.get("check") == "too_many_apps"]
    assert too_many and too_many[0].data["count"] == 38


def test_unreadable_firewall_is_couldnt_check_not_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(fail=(
        "--getglobalstate", "--getstealthmode", "--listapps", "--getblockall",
        "--getallowsigned",
    ))):
        result = mod.check(_make_profile())
    assert all(f.severity == Severity.INFO for f in result.findings)
    codes = {f.code for f in result.findings}
    assert "security.firewall_rules_audit.alf_unknown" in codes
    assert "security.firewall_rules_audit.alf_disabled" not in codes
    summary = next(f for f in result.findings if f.data.get("check") == "firewall_summary")
    assert summary.data["alf_enabled"] is None
    assert "Couldn't check" in summary.description
    assert "Off" not in summary.description


def test_unrecognised_output_is_couldnt_check():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(globalstate="something new\n")):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.firewall_rules_audit.alf_unknown" in codes
    assert "security.firewall_rules_audit.alf_disabled" not in codes


def test_stealth_unreadable_while_firewall_on_is_info():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake(fail=("--getstealthmode",))):
        result = mod.check(_make_profile())
    codes = {f.code for f in result.findings}
    assert "security.firewall_rules_audit.stealth_unknown" in codes
    assert "security.firewall_rules_audit.stealth_disabled" not in codes


def test_does_not_read_alf_plist():
    """The old plist is gone on macOS 26; the module must not depend on it."""
    mod = _get_module()
    calls = []
    fake = _fake()

    def spy(cmd, **kwargs):
        calls.append(cmd)
        return fake(cmd, **kwargs)

    with patch("subprocess.run", side_effect=spy):
        mod.check(_make_profile())
    assert not any("com.apple.alf" in " ".join(c) for c in calls)
