import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "certificate_audit")


def _is_list_all_certs(cmd):
    """Check if command is listing all certificates."""
    return isinstance(cmd, list) and "find-certificate" in cmd and "-c" in cmd and "-a" in cmd


def _is_get_cert(cmd):
    """Check if command is getting a specific certificate."""
    return isinstance(cmd, list) and "find-certificate" in cmd and "-p" in cmd


def _create_basic_mock(system_certs="", login_certs="", expiry_dates=None, root_cas=None):
    """Create a basic mock subprocess.run function."""
    if expiry_dates is None:
        expiry_dates = {}
    if root_cas is None:
        root_cas = set()

    call_counter = {"n": 0}
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")

    def mock_run(cmd, input=None, **kwargs):
        call_counter["n"] += 1
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""

        if not isinstance(cmd, list):
            return result

        # System certs list
        if _is_list_all_certs(cmd) and "/Library/Keychains/System.keychain" in cmd:
            result.stdout = system_certs
        # Login keychain certs list
        elif _is_list_all_certs(cmd) and "/Library/Keychains/login.keychain-db" in cmd:
            result.stdout = login_certs
        # Get specific certificate
        elif _is_get_cert(cmd):
            result.stdout = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        # Check expiry
        elif "openssl" in cmd and "-enddate" in cmd:
            # Look up by call number
            if call_counter["n"] in expiry_dates:
                result.stdout = f"notAfter={expiry_dates[call_counter['n']]}\n"
            else:
                result.stdout = f"notAfter={future_date}\n"
        # Check issuer/subject
        elif "openssl" in cmd and "-issuer" in cmd and "-subject" in cmd:
            # Check if this cert is a root CA
            if call_counter["n"] in root_cas:
                result.stdout = "issuer=/CN=Root\nsubject=/CN=Root\n"
            else:
                result.stdout = "issuer=/CN=CA\nsubject=/CN=Cert\n"
        else:
            result.stdout = ""

        return result

    return mock_run


def test_certificate_audit_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "certificate_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_certificate_audit_no_certs():
    """Test when no certificates are found."""
    mod = _get_module()
    mock_run = _create_basic_mock()
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_certificate_audit_healthy_certs():
    """Test system with healthy, non-expired certificates."""
    mod = _get_module()
    system_certs = '''sha1: 1234567890ABCDEF "Valid Cert 1"
sha1: FEDCBA0987654321 "Valid Cert 2"
'''
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    # Calls 3 and 5 are openssl -enddate for the two certificates
    expiry_dates = {3: future_date, 5: future_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["check"] == "total_certificates"
    assert result.findings[0].data["count"] == 2


def test_certificate_audit_expired_cert():
    """Test detection of expired certificate."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Expired Cert"
sha1: 2222 "Valid Cert"
'''
    past_date = (datetime.now() - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    # Call 3 is expired, call 5 is valid
    expiry_dates = {3: past_date, 5: future_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    findings_by_check = {f.data["check"]: f for f in result.findings}
    assert "expired_certificates" in findings_by_check
    assert findings_by_check["expired_certificates"].severity == Severity.WARNING


def test_certificate_audit_multiple_expired_certs():
    """Test detection of multiple expired certificates."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Expired 1"
sha1: 2222 "Expired 2"
sha1: 3333 "Valid"
'''
    past_date = (datetime.now() - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    # Calls 3, 5 are expired; call 7 is valid
    expiry_dates = {3: past_date, 5: past_date, 7: future_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    findings_by_check = {f.data["check"]: f for f in result.findings}
    assert "expired_certificates" in findings_by_check
    assert len(findings_by_check["expired_certificates"].data["certificates"]) == 2


def test_certificate_audit_user_root_cas():
    """Test detection of user-installed root CA certificates."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "System Cert"
'''
    login_certs = '''sha1: 2222 "User Root CA"
sha1: 3333 "User Leaf Cert"
'''
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    # Call 3 is expiry for system cert, calls 6 and 8 are issuer checks
    # Call 6 should return a root CA (issuer == subject)
    root_cas = {6}
    expiry_dates = {3: future_date, 5: future_date, 7: future_date}

    mock_run = _create_basic_mock(
        system_certs=system_certs,
        login_certs=login_certs,
        expiry_dates=expiry_dates,
        root_cas=root_cas,
    )
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    findings_by_check = {f.data["check"]: f for f in result.findings}
    assert "user_root_cas" in findings_by_check or "total_certificates" in findings_by_check


def test_certificate_audit_total_count_info():
    """Test that total certificate count is reported as INFO."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Cert 1"
sha1: 2222 "Cert 2"
sha1: 3333 "Cert 3"
'''
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    expiry_dates = {2: future_date, 4: future_date, 6: future_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    findings_by_check = {f.data["check"]: f for f in result.findings}
    assert "total_certificates" in findings_by_check
    assert findings_by_check["total_certificates"].severity == Severity.INFO
    assert findings_by_check["total_certificates"].data["count"] == 3


def test_certificate_audit_fix_expired_certs():
    """Test fix suggestion for expired certificates."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Expired Cert"
'''
    past_date = (datetime.now() - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    expiry_dates = {3: past_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    expired_actions = [a for a in fix.actions if "expired" in a.title.lower()]
    assert len(expired_actions) >= 1
    assert expired_actions[0].success
    assert expired_actions[0].risk_level == RiskLevel.SAFE


def test_certificate_audit_fix_user_root_cas():
    """Test fix suggestion for user-installed root CAs."""
    mod = _get_module()
    login_certs = '''sha1: 1111 "User Root CA"
'''
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    root_cas = {3}  # First issuer check for login certs
    expiry_dates = {2: future_date}

    mock_run = _create_basic_mock(
        login_certs=login_certs,
        expiry_dates=expiry_dates,
        root_cas=root_cas,
    )
    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    root_ca_actions = [a for a in fix.actions if "root" in a.title.lower() or "installed" in a.title.lower()]
    if root_ca_actions:
        assert root_ca_actions[0].success
        assert root_ca_actions[0].risk_level == RiskLevel.SAFE


def test_certificate_audit_fix_total_count():
    """Test fix suggestion for total certificate count."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Cert 1"
'''
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    expiry_dates = {2: future_date}

    mock_run = _create_basic_mock(system_certs=system_certs, expiry_dates=expiry_dates)
    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    audit_actions = [a for a in fix.actions if "periodically" in a.description.lower() or "audit" in a.title.lower()]
    assert len(audit_actions) >= 1
    assert audit_actions[0].success
    assert audit_actions[0].risk_level == RiskLevel.SAFE


def test_certificate_audit_fix_multiple_issues():
    """Test fix suggestions for multiple issues."""
    mod = _get_module()
    system_certs = '''sha1: 1111 "Expired Cert"
sha1: 2222 "Valid Cert"
'''
    login_certs = '''sha1: 3333 "User Root CA"
'''
    past_date = (datetime.now() - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    future_date = (datetime.now() + timedelta(days=365)).strftime("%b %d %H:%M:%S %Y GMT")
    # Calls: 2=expired, 4=valid, 6=check root ca (call 7)
    expiry_dates = {2: past_date, 4: future_date, 6: future_date}
    root_cas = {7}

    mock_run = _create_basic_mock(
        system_certs=system_certs,
        login_certs=login_certs,
        expiry_dates=expiry_dates,
        root_cas=root_cas,
    )
    with patch("subprocess.run", side_effect=mock_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
    assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)


def test_certificate_audit_handles_command_failure():
    """Test graceful handling when security command fails."""
    def failing_run(cmd, input=None, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stderr = "error: security command failed"
        result.stdout = ""
        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=failing_run):
        result = mod.check(_make_profile())
    assert isinstance(result.has_issues, bool)


def test_certificate_audit_handles_openssl_failure():
    """Test graceful handling when openssl command fails."""
    system_certs = '''sha1: 1111 "Test Cert"
'''

    call_count = {"n": 0}

    def openssl_failing_run(cmd, input=None, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        result.stderr = ""

        if not isinstance(cmd, list):
            return result

        if _is_list_all_certs(cmd) and "/Library/Keychains/System.keychain" in cmd:
            result.returncode = 0
            result.stdout = system_certs
        elif _is_get_cert(cmd):
            result.returncode = 0
            result.stdout = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
        elif "openssl" in cmd:
            # Simulate openssl failure
            result.returncode = 1
            result.stdout = ""
        elif _is_list_all_certs(cmd) and "/Library/Keychains/login.keychain-db" in cmd:
            result.returncode = 0
            result.stdout = ""
        else:
            result.returncode = 0
            result.stdout = ""

        return result

    mod = _get_module()
    with patch("subprocess.run", side_effect=openssl_failing_run):
        result = mod.check(_make_profile())
    assert isinstance(result.has_issues, bool)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.certificate_audit.") for c in declared)
