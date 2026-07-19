import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import plistlib

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "appleid_security_check")


def _make_appleid_plist(signed_in=True):
    """Create mock plist content for MobileMeAccounts."""
    if signed_in:
        return {"Accounts": [{"AccountID": "user@icloud.com"}]}
    return {"Accounts": []}


def _make_run_result(
    appleid_signin=True,
    twofa_enabled=True,
    keychain_enabled=True,
    private_relay=False,
    mail_privacy=False,
    autoupdate_enabled=True,
    icloud_devices=None,
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # Check for two-factor auth
        if "com.apple.security.plist" in cmd_str:
            if twofa_enabled:
                result.stdout = "AppleIDAccount = 1;\n"
            else:
                result.returncode = 1

        # Check iCloud Keychain
        elif "com.apple.iCloudKeychain" in cmd_str:
            if keychain_enabled:
                result.stdout = "1\n"
            else:
                result.returncode = 1

        # Check Private Relay
        elif "com.apple.Safari" in cmd_str and "ICloudPrivateRelayEnabled" in cmd_str:
            if private_relay:
                result.stdout = "1\n"
            else:
                result.returncode = 1

        # Check Mail Privacy Protection
        elif "com.apple.mail-shared" in cmd_str:
            if mail_privacy:
                result.stdout = "1\n"
            else:
                result.returncode = 1

        # Check system_profiler for iCloud devices
        elif "system_profiler" in cmd_str and "SPiCloudDataType" in cmd_str:
            if icloud_devices:
                output_lines = ["iCloud Data:"]
                for device in icloud_devices:
                    output_lines.append(f"  Device Name: {device}")
                result.stdout = "\n".join(output_lines)
            else:
                result.stdout = ""

        # Check automatic updates
        elif "com.apple.SoftwareUpdate" in cmd_str:
            if autoupdate_enabled:
                result.stdout = "1\n"
            else:
                result.returncode = 1

        return result

    return fake_run


def test_appleid_security_check_discovered():
    mod = _get_module()
    assert mod.name == "appleid_security_check"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_appleid_all_secure():
    """Test when all Apple ID security features are enabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        appleid_signin=True,
        twofa_enabled=True,
        keychain_enabled=True,
        private_relay=True,
        mail_privacy=True,
        autoupdate_enabled=True,
        icloud_devices=["MacBook Pro", "iPad Pro"],
    )

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                result = mod.check(_make_profile())

    # Should have INFO finding with summary
    assert result.has_issues
    assert any(f.data.get("check") == "appleid_summary" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)
    # Should NOT have warnings
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_appleid_not_signed_in():
    """Test detection when Apple ID is not signed in."""
    mod = _get_module()
    fake_run = _make_run_result(appleid_signin=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(False)):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "appleid_signin" for f in result.findings)
    signin_finding = [f for f in result.findings if f.data.get("check") == "appleid_signin"]
    assert signin_finding[0].severity == Severity.WARNING


def test_appleid_keychain_disabled():
    """Test detection when iCloud Keychain is disabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        appleid_signin=True,
        keychain_enabled=False,
    )

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "icloud_keychain" for f in result.findings)
    keychain_finding = [f for f in result.findings if f.data.get("check") == "icloud_keychain"]
    assert keychain_finding[0].severity == Severity.WARNING


def test_appleid_autoupdate_disabled():
    """Test detection when automatic updates are disabled."""
    mod = _get_module()
    fake_run = _make_run_result(
        appleid_signin=True,
        autoupdate_enabled=False,
    )

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "autoupdate_disabled" for f in result.findings)
    update_finding = [f for f in result.findings if f.data.get("check") == "autoupdate_disabled"]
    assert update_finding[0].severity == Severity.WARNING


def test_appleid_multiple_issues():
    """Test when multiple security issues are detected."""
    mod = _get_module()
    fake_run = _make_run_result(
        appleid_signin=False,
        keychain_enabled=False,
        autoupdate_enabled=False,
    )

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(False)):
                result = mod.check(_make_profile())

    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "appleid_signin" in checks
    assert "icloud_keychain" in checks
    assert "autoupdate_disabled" in checks
    # Should have at least 3 findings (3 warnings + 1 summary info)
    assert len(result.findings) >= 3


def test_appleid_fix_signin():
    """Test fix recommendation for Apple ID signin."""
    mod = _get_module()
    fake_run = _make_run_result(appleid_signin=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(False)):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("sign in" in a.title.lower() for a in fix.actions)


def test_appleid_fix_keychain():
    """Test fix recommendation for iCloud Keychain."""
    mod = _get_module()
    fake_run = _make_run_result(keychain_enabled=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("keychain" in a.title.lower() for a in fix.actions)


def test_appleid_fix_autoupdate():
    """Test fix recommendation for automatic updates."""
    mod = _get_module()
    fake_run = _make_run_result(autoupdate_enabled=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("update" in a.title.lower() for a in fix.actions)


def test_appleid_handles_missing_plist():
    """Test graceful handling when MobileMeAccounts.plist is missing."""
    mod = _get_module()
    fake_run = _make_run_result(appleid_signin=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    # Should still complete and flag no signin
    assert result.has_issues
    assert any(f.data.get("check") == "appleid_signin" for f in result.findings)


def test_appleid_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        with patch("pathlib.Path.exists", return_value=False):
            result = mod.check(_make_profile())

    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_appleid_summary_info_always_present():
    """Test that summary info finding is always present."""
    mod = _get_module()
    fake_run = _make_run_result()

    with patch("subprocess.run", side_effect=fake_run):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("plistlib.load", return_value=_make_appleid_plist(True)):
                result = mod.check(_make_profile())

    # Summary should always be present
    assert any(f.data.get("check") == "appleid_summary" for f in result.findings)
    summary = [f for f in result.findings if f.data.get("check") == "appleid_summary"][0]
    assert summary.severity == Severity.INFO


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.appleid_security_check.") for c in declared)
