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
        cpu_model="Apple M3",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "certificate_trust_audit")


# Realistic PEM certificate samples
APPLE_ROOT_CERT = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----"""

SUSPICIOUS_PROXY_CERT = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----"""

SELF_SIGNED_CERT = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----"""

EXPIRED_CERT = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
-----END CERTIFICATE-----"""


def _make_run_result(
    certs_output=None,
    cert_details=None,
    expect_clean=False,
):
    """Create a fake subprocess.run that returns appropriate certificate results.

    Args:
        certs_output: Output from security find-certificate command
        cert_details: Dict mapping cert subject to (subject, notAfter, issuer) tuples
        expect_clean: If True, return empty results by default
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        # security find-certificate command
        if "security" in cmd_str and "find-certificate" in cmd_str:
            if certs_output is not None:
                result.stdout = certs_output
            elif expect_clean:
                result.stdout = ""
            else:
                # Default: one Apple cert and one user-added cert
                result.stdout = (
                    APPLE_ROOT_CERT + "\n" +
                    SUSPICIOUS_PROXY_CERT + "\n"
                )

        # openssl x509 -noout -subject -dates
        elif "openssl" in cmd_str and "x509" in cmd_str and "-subject" in cmd_str:
            # Parse from input PEM
            if "input" in kwargs:
                pem_input = kwargs.get("input", "")
                if cert_details:
                    # Match based on PEM content
                    for subject_key, (subject, not_after, issuer) in cert_details.items():
                        if subject_key in pem_input or len(cert_details) == 1:
                            result.stdout = f"subject=CN = {subject}\nnotAfter={not_after}\n"
                            break
                else:
                    result.stdout = "subject=CN = Test Certificate\nnotAfter=Aug 15 12:00:00 2025 GMT\n"

        # openssl x509 -noout -issuer
        elif "openssl" in cmd_str and "x509" in cmd_str and "-issuer" in cmd_str:
            if "input" in kwargs:
                pem_input = kwargs.get("input", "")
                if cert_details:
                    for subject_key, (subject, not_after, issuer) in cert_details.items():
                        if subject_key in pem_input or len(cert_details) == 1:
                            result.stdout = f"issuer={issuer}\n"
                            break
                else:
                    result.stdout = "issuer=CN = Test CA\n"

        return result

    return fake_run


def test_certificate_trust_audit_discovered():
    """Test that the module is discovered correctly."""
    mod = _get_module()
    assert mod.name == "certificate_trust_audit"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_certificate_trust_audit_clean():
    """Test when no certificates are found (clean system)."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no findings if no certs
    assert not result.has_issues


def test_certificate_trust_audit_suspicious_certificate():
    """Test detection of suspicious certificate names."""
    mod = _get_module()

    # Mock to return a suspicious proxy certificate
    cert_details = {
        "proxy": ("Corporate Proxy CA", "Aug 15 12:00:00 2025 GMT", "CN = Corporate Proxy CA"),
    }

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            result.stdout = "subject=CN = Corporate Proxy CA\nnotAfter=Aug 15 12:00:00 2025 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            result.stdout = "issuer=CN = Corporate Proxy CA\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    suspicious_findings = [f for f in result.findings if f.data.get("check") == "suspicious_certificates"]
    assert len(suspicious_findings) > 0
    assert suspicious_findings[0].severity == Severity.CRITICAL


def test_certificate_trust_audit_self_signed():
    """Test detection of self-signed root certificates."""
    mod = _get_module()

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            result.stdout = "subject=CN = My Custom Root CA\nnotAfter=Aug 15 12:00:00 2025 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            # Self-signed: issuer matches subject
            result.stdout = "issuer=CN = My Custom Root CA\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    self_signed_findings = [f for f in result.findings if f.data.get("check") == "self_signed_root_certs"]
    assert len(self_signed_findings) > 0
    assert self_signed_findings[0].severity == Severity.WARNING


def test_certificate_trust_audit_expired():
    """Test detection of expired certificates."""
    mod = _get_module()

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            # Expired date: past date
            result.stdout = "subject=CN = Expired Cert\nnotAfter=Aug 15 12:00:00 2020 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            result.stdout = "issuer=CN = Some CA\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    expired_findings = [f for f in result.findings if f.data.get("check") == "expired_certificates"]
    assert len(expired_findings) > 0
    assert expired_findings[0].severity == Severity.WARNING


def test_certificate_trust_audit_user_added():
    """Test listing of user-added certificates."""
    mod = _get_module()

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            result.stdout = "subject=CN = User Added Cert\nnotAfter=Aug 15 12:00:00 2030 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            result.stdout = "issuer=CN = Some Third Party CA\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    user_added_findings = [f for f in result.findings if f.data.get("check") == "user_added_certs"]
    assert len(user_added_findings) > 0
    assert user_added_findings[0].severity == Severity.INFO


def test_certificate_trust_audit_multiple_issues():
    """Test when multiple certificate issues are detected."""
    mod = _get_module()

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    cert_counter = 0

    def fake_run(cmd, **kwargs):
        nonlocal cert_counter
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            cert_counter += 1
            if cert_counter == 1:
                result.stdout = "subject=CN = Suspicious MITM Proxy\nnotAfter=Aug 15 12:00:00 2025 GMT\n"
            elif cert_counter == 2:
                result.stdout = "subject=CN = Self Signed Root\nnotAfter=Aug 15 12:00:00 2025 GMT\n"
            else:
                result.stdout = "subject=CN = Expired Old Cert\nnotAfter=Aug 15 12:00:00 2020 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            if cert_counter == 1:
                result.stdout = "issuer=CN = Suspicious MITM Proxy\n"
            elif cert_counter == 2:
                result.stdout = "issuer=CN = Self Signed Root\n"
            else:
                result.stdout = "issuer=CN = Expired Old Cert\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())

    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "suspicious_certificates" in checks
    assert "self_signed_root_certs" in checks
    assert "expired_certificates" in checks


def test_certificate_trust_audit_fix_suspicious():
    """Test fix action for suspicious certificates."""
    mod = _get_module()

    certs_output = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIICljCCAX4CCQCKz0Xu9dKJnDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV\n"
        "-----END CERTIFICATE-----\n"
    )

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = " ".join(cmd_list)

        if "security" in cmd_str and "find-certificate" in cmd_str:
            result.stdout = certs_output
        elif "openssl" in cmd_str and "-subject" in cmd_str:
            result.stdout = "subject=CN = Debug Proxy\nnotAfter=Aug 15 12:00:00 2025 GMT\n"
        elif "openssl" in cmd_str and "-issuer" in cmd_str:
            result.stdout = "issuer=CN = Debug Proxy\n"

        return result

    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    suspicious_actions = [a for a in fix.actions if "suspicious" in a.title.lower()]
    assert len(suspicious_actions) > 0


def test_certificate_trust_audit_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)


def test_certificate_trust_audit_timeout():
    """Test handling of command timeout."""
    mod = _get_module()

    import subprocess

    def timeout_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 5)

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())
    # Should still complete without crashing
    assert isinstance(result.findings, list)
