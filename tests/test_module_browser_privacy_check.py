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
        os_version="13.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "browser_privacy_check")


def _make_defaults_run(
    dnt_enabled=True,
    fraud_warning_enabled=True,
    cookies_policy=None,
    autofill_enabled=False,
):
    """Create a fake subprocess.run for defaults read command."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list) and cmd[0] == "defaults" and any("Safari" in str(x) for x in cmd):
            parts = []
            if not dnt_enabled:
                parts.append("SendDoNotTrackHTTPHeader = 0;")
            else:
                parts.append("SendDoNotTrackHTTPHeader = 1;")

            if not fraud_warning_enabled:
                parts.append("WarnAboutFraudulentWebsites = 0;")
            else:
                parts.append("WarnAboutFraudulentWebsites = 1;")

            if cookies_policy:
                parts.append(f'BlockStoragePolicy = "{cookies_policy}";')
            else:
                parts.append('BlockStoragePolicy = "BlockThirdParty";')

            if autofill_enabled:
                parts.append("AutoFillPasswords = 1;")
            else:
                parts.append("AutoFillPasswords = 0;")

            result.stdout = "\n".join(parts)

        return result

    return fake_run


def _make_security_run(password_count=5):
    """Create a fake subprocess.run for security command."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        if isinstance(cmd, list) and cmd[0] == "security":
            # Simulate password entries in keychain
            if password_count > 0:
                result.stdout = "\n".join([f"keychain: item {i}" for i in range(password_count)])
            else:
                result.returncode = 1
                result.stderr = "security: SecItemCopyMatching: The specified item could not be found in the keychain."

        return result

    return fake_run


def test_browser_privacy_check_discovered():
    """Test that module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "browser_privacy_check"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_browser_privacy_check_all_secure():
    """Test when all privacy settings are secure."""
    mod = _get_module()
    fake_run = _make_defaults_run(dnt_enabled=True, fraud_warning_enabled=True)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    # Should have clean summary
    assert result.has_issues
    assert any(f.data.get("check") == "privacy_summary" for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_browser_privacy_check_dnt_disabled():
    """Test when Do Not Track is disabled."""
    mod = _get_module()
    fake_run = _make_defaults_run(dnt_enabled=False, fraud_warning_enabled=True)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "do_not_track_disabled" for f in result.findings)
    dnt_finding = [f for f in result.findings if f.data.get("check") == "do_not_track_disabled"]
    assert dnt_finding[0].severity == Severity.WARNING


def test_browser_privacy_check_fraud_warning_disabled():
    """Test when fraud warning is disabled."""
    mod = _get_module()
    fake_run = _make_defaults_run(dnt_enabled=True, fraud_warning_enabled=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "fraud_warning_disabled" for f in result.findings)
    fraud_finding = [f for f in result.findings if f.data.get("check") == "fraud_warning_disabled"]
    assert fraud_finding[0].severity == Severity.WARNING


def test_browser_privacy_check_cookies_always_allow():
    """Test when cookies are always allowed."""
    mod = _get_module()
    fake_run = _make_defaults_run(cookies_policy="Always Allow")

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "cookies_always_allow" for f in result.findings)
    cookie_finding = [f for f in result.findings if f.data.get("check") == "cookies_always_allow"]
    assert cookie_finding[0].severity == Severity.WARNING


def test_browser_privacy_check_autofill_enabled():
    """Test when password autofill is enabled."""
    mod = _get_module()
    fake_run = _make_defaults_run(autofill_enabled=True)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "autofilll_passwords_enabled" for f in result.findings)
    autofill_finding = [f for f in result.findings if f.data.get("check") == "autofilll_passwords_enabled"]
    assert autofill_finding[0].severity == Severity.INFO


def test_browser_privacy_check_multiple_issues():
    """Test when multiple privacy issues are detected."""
    mod = _get_module()
    fake_run = _make_defaults_run(
        dnt_enabled=False,
        fraud_warning_enabled=False,
        cookies_policy="Always Allow",
        autofill_enabled=True,
    )

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "do_not_track_disabled" in checks
    assert "fraud_warning_disabled" in checks
    assert "cookies_always_allow" in checks
    assert "autofilll_passwords_enabled" in checks


def test_browser_privacy_check_chrome_installed():
    """Test detection of installed Chrome browser."""
    mod = _get_module()
    fake_defaults = _make_defaults_run()

    # Patch Path methods at instance level
    original_exists = Path.exists
    original_iterdir = Path.iterdir

    def mock_exists(self):
        if "Google/Chrome" in str(self):
            return True
        if "Firefox" in str(self):
            return False
        return original_exists(self)

    def mock_iterdir(self):
        if "Google/Chrome" in str(self):
            return iter([Path(f"/Users/test/Library/Application Support/Google/Chrome/Profile {i}") for i in range(2)])
        if "Firefox" in str(self):
            return iter([])
        return original_iterdir(self)

    with patch("subprocess.run", side_effect=fake_defaults):
        with patch.object(Path, "exists", mock_exists):
            with patch.object(Path, "iterdir", mock_iterdir):
                with patch.object(Path, "is_dir", return_value=True):
                    result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "installed_browsers" for f in result.findings)
    browser_finding = [f for f in result.findings if f.data.get("check") == "installed_browsers"]
    assert "Chrome" in browser_finding[0].description


def test_browser_privacy_check_firefox_installed():
    """Test detection of installed Firefox browser."""
    mod = _get_module()
    fake_defaults = _make_defaults_run()

    # Patch Path methods at instance level
    original_exists = Path.exists
    original_iterdir = Path.iterdir

    def mock_exists(self):
        if "Firefox" in str(self):
            return True
        if "Google/Chrome" in str(self):
            return False
        return original_exists(self)

    def mock_iterdir(self):
        if "Firefox" in str(self):
            return iter([Path(f"/Users/test/Library/Application Support/Firefox/Profiles/profile{i}") for i in range(1)])
        if "Google/Chrome" in str(self):
            return iter([])
        return original_iterdir(self)

    with patch("subprocess.run", side_effect=fake_defaults):
        with patch.object(Path, "exists", mock_exists):
            with patch.object(Path, "iterdir", mock_iterdir):
                with patch.object(Path, "is_dir", return_value=True):
                    result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "installed_browsers" for f in result.findings)
    browser_finding = [f for f in result.findings if f.data.get("check") == "installed_browsers"]
    assert "Firefox" in browser_finding[0].description


def test_browser_privacy_check_saved_passwords():
    """Test detection of saved passwords in keychain."""
    mod = _get_module()
    fake_defaults = _make_defaults_run()
    fake_security = _make_security_run(password_count=5)

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and cmd[0] == "defaults":
            return fake_defaults(cmd, **kwargs)
        elif isinstance(cmd, list) and cmd[0] == "security":
            return fake_security(cmd, **kwargs)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        return result

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "saved_passwords" for f in result.findings)
    password_finding = [f for f in result.findings if f.data.get("check") == "saved_passwords"]
    assert password_finding[0].data.get("count") == 5


def test_browser_privacy_check_fix_dnt():
    """Test fix recommendation for Do Not Track."""
    mod = _get_module()
    fake_run = _make_defaults_run(dnt_enabled=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("Do Not Track" in a.title for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_browser_privacy_check_fix_fraud_warning():
    """Test fix recommendation for fraud warning."""
    mod = _get_module()
    fake_run = _make_defaults_run(fraud_warning_enabled=False)

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("fraud warning" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_browser_privacy_check_fix_cookies():
    """Test fix recommendation for cookie policy."""
    mod = _get_module()
    fake_run = _make_defaults_run(cookies_policy="Always Allow")

    with patch("subprocess.run", side_effect=fake_run):
        with patch.object(Path, "exists", return_value=False):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("cookie" in a.title.lower() for a in fix.actions)
    assert all(a.success for a in fix.actions)


def test_browser_privacy_check_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_browser_privacy_check_no_findings_shows_summary():
    """Test that summary finding is shown when no issues are found."""
    mod = _get_module()

    def clean_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = "SendDoNotTrackHTTPHeader = 1;\nWarnAboutFraudulentWebsites = 1;\nBlockStoragePolicy = \"BlockThirdParty\";\nAutoFillPasswords = 0;"
        return result

    with patch("subprocess.run", side_effect=clean_run):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    summary_findings = [f for f in result.findings if f.data.get("check") == "privacy_summary"]
    assert len(summary_findings) == 1
    assert summary_findings[0].severity == Severity.INFO
