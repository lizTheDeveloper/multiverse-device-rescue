import subprocess
from datetime import datetime

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
    name = "certificate_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # List system keychain certificates
        system_certs = self._get_system_certificates()
        total_cert_count = len(system_certs)

        # Check for expired certificates
        expired_certs = self._find_expired_certificates(system_certs)
        if expired_certs:
            cert_names = ", ".join(
                [c.get("name", "Unknown") for c in expired_certs]
            )
            findings.append(
                Finding(
                    title=f"Found {len(expired_certs)} expired certificate(s)",
                    description=(
                        f"Expired certificates: {cert_names}. "
                        "Expired certificates can cause SSL/TLS errors, app crashes, and "
                        "connection failures. Review and remove them from the keychain."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "expired_certificates",
                        "count": len(expired_certs),
                        "certificates": [
                            {"name": c.get("name"), "expiry": c.get("expiry")}
                            for c in expired_certs
                        ],
                    },
                )
            )

        # Check for user-installed root CAs in login keychain
        user_root_cas = self._get_user_installed_root_cas()
        if user_root_cas:
            ca_names = ", ".join(
                [ca.get("name", "Unknown") for ca in user_root_cas]
            )
            findings.append(
                Finding(
                    title=f"Found {len(user_root_cas)} user-installed root CA(s)",
                    description=(
                        f"User-installed root CAs: {ca_names}. "
                        "User-installed root certificates can be a security risk if they "
                        "were added by corporate MDM, compromised, or unknown. Review them carefully."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "user_root_cas",
                        "count": len(user_root_cas),
                        "certificates": user_root_cas,
                    },
                )
            )

        # Flag INFO for total certificate count
        if total_cert_count > 0:
            findings.append(
                Finding(
                    title=f"System keychain contains {total_cert_count} certificate(s)",
                    description=(
                        f"The System keychain has {total_cert_count} total certificates. "
                        "Regularly audit certificates to remove expired or untrusted ones."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "total_certificates",
                        "count": total_cert_count,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "expired_certificates":
                actions.append(
                    Action(
                        title="Review and remove expired certificates",
                        description=(
                            "Open Keychain Access.app and navigate to System keychains. "
                            "Search for expired certificates (look for red X icons). "
                            "Right-click and delete expired certificates that are no longer needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "user_root_cas":
                actions.append(
                    Action(
                        title="Review user-installed root CA certificates",
                        description=(
                            "Open Keychain Access.app and check System > Certificates. "
                            "Look for root CAs marked as trusted. Verify that each is legitimate "
                            "and expected (e.g., corporate MDM). Remove any unknown or untrusted root CAs. "
                            "Use 'Delete' if it's not recognized or 'Get Info' to inspect details."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "total_certificates":
                actions.append(
                    Action(
                        title="Periodically audit system certificates",
                        description=(
                            "Regularly review certificates in Keychain Access.app to maintain a clean "
                            "and secure certificate store. Remove expired, untrusted, or unneeded certificates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_system_certificates(self) -> list[dict]:
        """Get list of certificates in System keychain."""
        certs = []
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-certificate",
                    "-a",
                    "-c",
                    "",
                    "-Z",
                    "/Library/Keychains/System.keychain",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse output to extract certificate information
                # Format: sha1: <hash> "<certificate name>"
                lines = result.stdout.split("\n")
                for line in lines:
                    line = line.strip()
                    if '"' in line:
                        # Extract certificate name from quotes
                        parts = line.split('"')
                        if len(parts) >= 2:
                            cert_name = parts[1]
                            if cert_name:
                                certs.append({"name": cert_name})
        except OSError:
            pass
        return certs

    def _find_expired_certificates(self, certs: list[dict]) -> list[dict]:
        """Find expired certificates by checking their expiry dates."""
        expired = []
        for cert in certs:
            expiry_date = self._get_certificate_expiry(cert.get("name", ""))
            if expiry_date and expiry_date < datetime.now():
                expired.append({
                    "name": cert.get("name"),
                    "expiry": expiry_date.strftime("%Y-%m-%d"),
                })
        return expired

    def _get_certificate_expiry(self, cert_name: str) -> datetime | None:
        """Get expiry date of a certificate by name."""
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-certificate",
                    "-c",
                    cert_name,
                    "-p",
                    "/Library/Keychains/System.keychain",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Use openssl to extract expiry date from PEM
                openssl_result = subprocess.run(
                    ["openssl", "x509", "-noout", "-enddate"],
                    input=result.stdout,
                    capture_output=True,
                    text=True,
                )
                if openssl_result.returncode == 0:
                    # Parse "notAfter=<date>" format
                    output = openssl_result.stdout.strip()
                    if output.startswith("notAfter="):
                        date_str = output.replace("notAfter=", "")
                        # Parse date (format: "Jan 15 10:30:00 2024 GMT")
                        try:
                            return datetime.strptime(
                                date_str, "%b %d %H:%M:%S %Y %Z"
                            )
                        except ValueError:
                            # Try without timezone
                            try:
                                return datetime.strptime(
                                    date_str.split()[0:3] + [date_str.split()[3]],
                                    "%b %d %H:%M:%S %Y",
                                )
                            except (ValueError, IndexError):
                                pass
        except OSError:
            pass
        return None

    def _get_user_installed_root_cas(self) -> list[dict]:
        """Get list of user-installed root CA certificates in login keychain."""
        root_cas = []
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-certificate",
                    "-a",
                    "-c",
                    "",
                    "-Z",
                    "/Library/Keychains/login.keychain-db",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse certificate names - Format: sha1: <hash> "<certificate name>"
                lines = result.stdout.split("\n")
                for line in lines:
                    line = line.strip()
                    if '"' in line:
                        parts = line.split('"')
                        if len(parts) >= 2:
                            cert_name = parts[1]
                            if cert_name:
                                # Check if this is a root CA
                                if self._is_root_ca(cert_name):
                                    root_cas.append({"name": cert_name})
        except OSError:
            pass
        return root_cas

    def _is_root_ca(self, cert_name: str) -> bool:
        """Check if a certificate is a root CA (issuer == subject)."""
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-certificate",
                    "-c",
                    cert_name,
                    "-p",
                    "/Library/Keychains/login.keychain-db",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Use openssl to check if issuer == subject
                openssl_result = subprocess.run(
                    ["openssl", "x509", "-noout", "-issuer", "-subject"],
                    input=result.stdout,
                    capture_output=True,
                    text=True,
                )
                if openssl_result.returncode == 0:
                    lines = openssl_result.stdout.split("\n")
                    issuer = ""
                    subject = ""
                    for line in lines:
                        if line.startswith("issuer="):
                            issuer = line.replace("issuer=", "").strip()
                        elif line.startswith("subject="):
                            subject = line.replace("subject=", "").strip()
                    # Root CA if issuer == subject
                    return issuer == subject and issuer != ""
        except OSError:
            pass
        return False
