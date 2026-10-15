import re
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

    emits_codes = [
        "security.certificate_trust_audit.suspicious_certificates",
        "security.certificate_trust_audit.self_signed_root_certs",
        "security.certificate_trust_audit.expired_certificates",
        "security.certificate_trust_audit.user_added_certs",
    ]

    # Apple's per-machine system identity certificates. macOS generates these
    # self-signed certificates on every Mac, so they are not user-added roots.
    # Matched on the exact (CN, O) pair.
    SYSTEM_IDENTITY_CERTS = {
        ("com.apple.systemdefault", "System Identity"),
        ("com.apple.kerberos.kdc", "System Identity"),
    }

    @staticmethod
    def _trusted_cert_names() -> set[str] | None:
        """Names of certificates with admin or user trust settings (can be trusted for SSL).

        Returns None when the trust settings cannot be read, so callers fail safe
        (do not skip anything).
        """
        names: set[str] = set()
        for extra in (["-d"], []):
            try:
                result = subprocess.run(
                    ["security", "dump-trust-settings", *extra],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except (subprocess.TimeoutExpired, OSError):
                return None
            out = (result.stdout or "") + (result.stderr or "")
            if "No Trust Settings were found" in out:
                continue
            if result.returncode != 0:
                return None
            for m in re.finditer(r"^\s*Cert \d+:\s*(.+?)\s*$", out, re.MULTILINE):
                names.add(m.group(1))
        return names

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

        trusted_names: set[str] | None = None
        for cert in certs:
            subject = cert.get("subject", "")
            if (subject, cert.get("org", "")) in self.SYSTEM_IDENTITY_CERTS:
                # The (CN, O) pair is just a name; anyone can mint a root with it.
                # Only skip it if it is demonstrably not trusted for anything.
                if trusted_names is None:
                    trusted_names = self._trusted_cert_names()
                if trusted_names is not None and subject not in trusted_names:
                    continue
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
                    title=(
                        f"Certificates named for debugging or interception: {len(suspicious_certs)}"
                    ),
                    description=(
                        f"We found {len(suspicious_certs)} trusted certificates with names "
                        f"like {', '.join(suspicious_certs)}. These names are often used "
                        "by tools that secretly read or change your internet traffic.\n\n"
                        "If you did not install these yourself, they could allow someone "
                        "else to see your private messages. This is a serious sign that "
                        "your device may be monitored.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Open Keychain Access, find these certificates, and "
                        "check who added them. If you don't recognize them, ask a trusted "
                        "expert for help removing them safely."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.certificate_trust_audit.suspicious_certificates",
                    data={"check": "suspicious_certificates", "certs": suspicious_certs},
                )
            )

        # Flag WARNING for self-signed non-Apple root CAs
        if self_signed_certs:
            findings.append(
                Finding(
                    title=f"Self-signed certificates were added to this Mac: {len(self_signed_certs)}",
                    description=(
                        f"{len(self_signed_certs)} self-signed certificate(s) were added to "
                        f"this Mac: {', '.join(self_signed_certs)}. These "
                        "are not from major companies like Apple or Google.\n\n"
                        "Sometimes these are needed for work or school tools. However, "
                        "if you don't remember adding them, they could be used to trick "
                        "your Mac into trusting fake websites.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Open Keychain Access and look for these names. If "
                        "you don't know why they are there, ask a trusted tech friend "
                        "to help you identify them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.certificate_trust_audit.self_signed_root_certs",
                    data={"check": "self_signed_root_certs", "certs": self_signed_certs},
                )
            )

        # Flag WARNING for expired certificates
        if expired_certs:
            findings.append(
                Finding(
                    title=f"Old certificates that no longer work: {len(expired_certs)}",
                    description=(
                        f"We found {len(expired_certs)} certificates that have passed "
                        f"their expiration date: {', '.join(expired_certs)}.\n\n"
                        "Expired certificates aren't trusted for anything any more, so "
                        "this is just clutter.\n\n"
                        "What to do: Nothing. You can leave them, or delete them in "
                        "Keychain Access if you like a tidy list."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.certificate_trust_audit.expired_certificates",
                    data={"check": "expired_certificates", "certs": expired_certs},
                )
            )

        # Flag INFO listing all user-added certificates
        if user_added_certs:
            findings.append(
                Finding(
                    title=f"Root certificates added to this Mac: {len(user_added_certs)}",
                    description=(
                        f"{len(user_added_certs)} user-added root certificate(s) in system keychain:\n"
                        f"{', '.join(sorted(user_added_certs))}\n"
                        "Review these certificates to ensure they are from trusted sources."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.certificate_trust_audit.user_added_certs",
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
            org = ""

            for line in result.stdout.split("\n"):
                if line.startswith("subject="):
                    # Extract subject CN
                    subject = line.replace("subject=", "").strip()
                    # Parse CN (and O) from subject; openssl prints either
                    # "CN = x, O = y" or "CN=x, O=y" depending on version.
                    cn_match = re.search(r"CN\s*=\s*([^,]+)", subject)
                    org_match = re.search(r"\bO\s*=\s*([^,]+)", subject)
                    if org_match:
                        org = org_match.group(1).strip()
                    if cn_match:
                        subject = cn_match.group(1).strip()
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
                "org": org,
                "self_signed": self_signed,
                "expired": is_expired,
                "suspicious": False,  # Will be checked in check() method
            }
        except (subprocess.TimeoutExpired, OSError):
            return None
        except Exception:
            return None
