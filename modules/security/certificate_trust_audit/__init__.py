import subprocess
from datetime import datetime
from pathlib import Path

from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase


class Module(ModuleBase):
    name = "certificate_trust_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get user-added root certificates from system keychain
        certs = self._list_root_certificates()

        if not certs:
            return CheckResult(module_name=self.name, findings=findings)

        # Analyze certificates for suspicious properties
        suspicious_certs = []
        self_signed_certs = []
        expired_certs = []
        user_added_certs = []

        # Apple's standard root CAs (non-exhaustive, common ones)
        apple_roots = {
            "Apple Root CA",
            "Apple Certification Authority",
            "Apple Code Signing Certification Authority",
            "Apple Timestamp Authority",
            "Apple Worldwide Developer Relations",
        }

        for cert in certs:
            subject = cert.get("subject", "")
            is_apple = any(apple_name in subject for apple_name in apple_roots)
            is_self_signed = cert.get("self_signed", False)
            is_expired = cert.get("expired", False)
            is_suspicious = cert.get("suspicious", False)

            # Track user-added non-Apple certs
            if not is_apple:
                user_added_certs.append(subject)

            # Check for suspicious names (traffic interception indicators)
            suspicious_keywords = ["proxy", "inspect", "mitm", "debug"]
            if any(keyword in subject.lower() for keyword in suspicious_keywords):
                is_suspicious = True

            if is_suspicious:
                suspicious_certs.append(subject)

            if is_self_signed and not is_apple:
                self_signed_certs.append(subject)

            if is_expired:
                expired_certs.append(subject)

        # Flag CRITICAL for suspicious certificates (traffic interception)
        if suspicious_certs:
            findings.append(
                Finding(
                    title=f"Suspicious root certificates detected: {len(suspicious_certs)}",
                    description=(
                        f"Found {len(suspicious_certs)} root certificate(s) with names suggesting "
                        f"traffic interception or debugging:\n"
                        f"{', '.join(suspicious_certs)}\n"
                        "These certificates could be used to intercept HTTPS traffic. "
                        "Review their source and purpose in Keychain Access."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "suspicious_certificates", "certs": suspicious_certs},
                )
            )

        # Flag WARNING for self-signed non-Apple root CAs
        if self_signed_certs:
            findings.append(
                Finding(
                    title=f"Self-signed root certificates: {len(self_signed_certs)}",
                    description=(
                        f"{len(self_signed_certs)} self-signed root certificate(s) added by user:\n"
                        f"{', '.join(self_signed_certs)}\n"
                        "Self-signed certificates in the root store can allow HTTPS interception. "
                        "Verify these are from trusted sources and are necessary for your workflow."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "self_signed_root_certs", "certs": self_signed_certs},
                )
            )

        # Flag WARNING for expired certificates
        if expired_certs:
            findings.append(
                Finding(
                    title=f"Expired root certificates: {len(expired_certs)}",
                    description=(
                        f"{len(expired_certs)} expired root certificate(s) in keychain:\n"
                        f"{', '.join(expired_certs)}\n"
                        "Remove expired certificates to prevent potential security issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "expired_certificates", "certs": expired_certs},
                )
            )

        # Flag INFO listing all user-added certificates
        if user_added_certs:
            findings.append(
                Finding(
                    title=f"User-added root certificates: {len(user_added_certs)}",
                    description=(
                        f"{len(user_added_certs)} user-added root certificate(s) in system keychain:\n"
                        f"{', '.join(sorted(user_added_certs))}\n"
                        "Review these certificates to ensure they are from trusted sources."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "user_added_certs", "certs": user_added_certs},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            certs = finding.data.get("certs", [])

            if check == "suspicious_certificates":
                cert_list = ", ".join(certs)
                actions.append(
                    Action(
                        title="Review suspicious certificates in Keychain Access",
                        description=(
                            f"Certificates with names suggesting traffic interception: {cert_list}.\n"
                            "Open Keychain Access (Applications > Utilities) and search for these "
                            "certificates. Delete any that were not intentionally installed. "
                            "If unsure, research the certificate source before deletion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "self_signed_root_certs":
                cert_list = ", ".join(certs)
                actions.append(
                    Action(
                        title="Review self-signed root certificates",
                        description=(
                            f"Self-signed root certificates: {cert_list}.\n"
                            "Open Keychain Access and review each certificate's purpose. "
                            "Self-signed roots can enable traffic interception. Consider removing "
                            "those that are no longer needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "expired_certificates":
                cert_list = ", ".join(certs)
                actions.append(
                    Action(
                        title="Remove expired root certificates",
                        description=(
                            f"Expired certificates: {cert_list}.\n"
                            "Open Keychain Access, select each certificate, and press Delete. "
                            "Expired certificates should be removed to avoid confusion and "
                            "potential security issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "user_added_certs":
                actions.append(
                    Action(
                        title="Review user-added root certificates",
                        description=(
                            f"Found {len(certs)} user-added root certificate(s). "
                            "Periodically audit these in Keychain Access > System > Certificates "
                            "to ensure they are still necessary and from trusted sources."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _list_root_certificates(self) -> list[dict]:
        """Extract root certificates from system keychain.

        Returns list of cert dictionaries with subject, self_signed, expired, suspicious.
        Returns [] on any failure.
        """
        try:
            result = subprocess.run(
                ["security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            certs = []
            cert_pem = ""
            for line in result.stdout.split("\n"):
                cert_pem += line + "\n"
                if line == "-----END CERTIFICATE-----":
                    cert_data = self._parse_cert(cert_pem)
                    if cert_data:
                        certs.append(cert_data)
                    cert_pem = ""

            return certs
        except (subprocess.TimeoutExpired, OSError):
            return []
        except Exception:
            return []

    def _parse_cert(self, pem: str) -> dict | None:
        """Parse a single PEM certificate.

        Returns dict with subject, self_signed, expired, suspicious.
        Returns None if parsing fails.
        """
        try:
            # Use openssl to extract certificate details
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-dates"],
                input=pem,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            subject = ""
            not_after = None
            self_signed = False

            for line in result.stdout.split("\n"):
                if line.startswith("subject="):
                    # Extract subject CN
                    subject = line.replace("subject=", "").strip()
                    # Parse CN from subject
                    if "CN = " in subject:
                        cn = subject.split("CN = ")[1].split(",")[0]
                        subject = cn
                elif line.startswith("notAfter="):
                    not_after_str = line.replace("notAfter=", "").strip()
                    try:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    except ValueError:
                        pass

            # Check if self-signed
            issuer_result = subprocess.run(
                ["openssl", "x509", "-noout", "-issuer"],
                input=pem,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if issuer_result.returncode == 0:
                issuer_line = issuer_result.stdout.strip()
                # Self-signed if issuer matches subject
                self_signed = subject in issuer_line

            # Check expiration
            is_expired = False
            if not_after:
                is_expired = datetime.now() > not_after

            return {
                "subject": subject,
                "self_signed": self_signed,
                "expired": is_expired,
                "suspicious": False,  # Will be checked in check() method
            }
        except (subprocess.TimeoutExpired, OSError):
            return None
        except Exception:
            return None
