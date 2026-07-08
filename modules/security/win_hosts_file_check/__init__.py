import os
import subprocess
import stat

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

# Antivirus and security update domains that should NEVER be blocked
ANTIVIRUS_UPDATE_DOMAINS = {
    "windowsupdate.com",
    "microsoft.com",
    "malwarebytes.com",
    "avast.com",
    "avg.com",
    "norton.com",
    "kaspersky.com",
    "mcafee.com",
    "sophos.com",
    "bitdefender.com",
    "f-secure.com",
    "trend.com",
    "symantec.com",
}

# Legitimate domains that should not be redirected to suspicious IPs
LEGITIMATE_DOMAINS = {
    "google.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "youtube.com",
    "github.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "linkedin.com",
    "github.com",
}

# Safe localhost IPs
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

# Hosts file path
HOSTS_FILE_PATH = "C:\\Windows\\System32\\drivers\\etc\\hosts"

# File size warning threshold (1MB)
FILE_SIZE_WARNING_THRESHOLD = 1024 * 1024


class Module(ModuleBase):
    name = "win_hosts_file_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Read hosts file
        hosts_content = self._read_hosts_file()
        if hosts_content is None:
            return CheckResult(module_name=self.name, findings=findings)

        # Parse entries
        entries = _parse_hosts_file(hosts_content)

        # Check 1: Blocked antivirus/security update domains (CRITICAL)
        blocked_security = _find_blocked_security_domains(entries)
        if blocked_security:
            findings.append(
                Finding(
                    title="Antivirus/security update domains blocked in hosts file",
                    description=(
                        f"The following critical security/antivirus update domains are "
                        f"blocked or redirected in the hosts file: {', '.join(blocked_security)}. "
                        f"This is a strong indicator of malware attempting to prevent security updates "
                        f"and antivirus signatures from being downloaded."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"blocked_domains": blocked_security, "check": "blocked_security_domains"},
                )
            )

        # Check 2: Redirected legitimate domains to non-localhost IPs (WARNING)
        redirected_legit = _find_redirected_legitimate_domains(entries)
        if redirected_legit:
            findings.append(
                Finding(
                    title="Legitimate domains redirected to suspicious IPs in hosts file",
                    description=(
                        f"The following legitimate domains are redirected to non-localhost IPs: "
                        f"{', '.join(redirected_legit)}. "
                        f"This may indicate malware or adware attempting to hijack traffic."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"redirected_domains": redirected_legit, "check": "redirected_legitimate"},
                )
            )

        # Check 3: Hosts file is unusually large (WARNING)
        file_size = self._get_hosts_file_size()
        if file_size is not None and file_size > FILE_SIZE_WARNING_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Hosts file is unusually large ({file_size} bytes)",
                    description=(
                        f"The hosts file is {file_size} bytes, which exceeds {FILE_SIZE_WARNING_THRESHOLD} bytes. "
                        f"Very large hosts files may indicate ad-blocker lists or malware tampering."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"file_size": file_size, "check": "large_file_size"},
                )
            )

        # Check 4: Hosts file permissions (WARNING if writable by non-admins)
        perm_issue = self._check_hosts_file_permissions()
        if perm_issue:
            findings.append(
                Finding(
                    title="Hosts file has incorrect permissions",
                    description=(
                        f"The hosts file has permissions that allow modification by non-administrative users. "
                        f"Only Administrators should have write access to this file. {perm_issue}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"permission_issue": perm_issue, "check": "file_permissions"},
                )
            )

        # Check 5: Entry count summary (INFO)
        if entries:
            findings.append(
                Finding(
                    title=f"Hosts file contains {len(entries)} entries",
                    description=(
                        f"The hosts file has {len(entries)} non-comment, non-empty entries. "
                        f"Review custom entries to ensure they are intentional."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"entry_count": len(entries), "check": "entry_count_summary"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check", "")

            if check_type == "blocked_security_domains":
                actions.append(
                    Action(
                        title="Review and remove security domain blocks from hosts file",
                        description=(
                            "Manually review and remove entries in "
                            "C:\\Windows\\System32\\drivers\\etc\\hosts that block antivirus "
                            "update domains. This is a critical malware signature. "
                            "Use Notepad as Administrator to edit the file."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review required",
                    )
                )
            elif check_type == "redirected_legitimate":
                actions.append(
                    Action(
                        title="Review and remove suspicious domain redirects",
                        description=(
                            "Review C:\\Windows\\System32\\drivers\\etc\\hosts and remove "
                            "entries that redirect legitimate domains to non-localhost IPs. "
                            "Only entries pointing to 127.0.0.1 or ::1 should be present for "
                            "legitimate domains."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review required",
                    )
                )
            elif check_type == "large_file_size":
                actions.append(
                    Action(
                        title="Review hosts file for large size and suspicious content",
                        description=(
                            "The hosts file is unusually large. Review "
                            "C:\\Windows\\System32\\drivers\\etc\\hosts for malware-added entries. "
                            "Consider restoring from a clean backup if compromised."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review required",
                    )
                )
            elif check_type == "file_permissions":
                actions.append(
                    Action(
                        title="Fix hosts file permissions",
                        description=(
                            "Run as Administrator: icacls C:\\Windows\\System32\\drivers\\etc\\hosts "
                            "/reset to restore default permissions. Only Administrators should have "
                            "write access."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual execution required",
                    )
                )
            elif check_type == "entry_count_summary":
                # INFO findings get a neutral action
                actions.append(
                    Action(
                        title="Review hosts file entries",
                        description=(
                            "Review the hosts file at "
                            "C:\\Windows\\System32\\drivers\\etc\\hosts to ensure all entries "
                            "are intentional and not added by malware."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review recommended",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _read_hosts_file(self) -> str | None:
        """Read Windows hosts file content using PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Content $env:windir\\System32\\drivers\\etc\\hosts",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_hosts_file_size(self) -> int | None:
        """Get the size of the hosts file in bytes."""
        try:
            # Use PowerShell to get file size
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-Item $env:windir\\System32\\drivers\\etc\\hosts).Length",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                try:
                    return int(result.stdout.strip())
                except ValueError:
                    return None
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_hosts_file_permissions(self) -> str | None:
        """Check if hosts file has appropriate permissions."""
        try:
            # Use PowerShell to get file permissions
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-Item $env:windir\\System32\\drivers\\etc\\hosts).GetAccessControl() | Select-Object -ExpandProperty Access",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None

            # Check if output indicates non-admin users have write access
            access_output = result.stdout.lower()
            if "modifyoneof" in access_output or "everyone" in access_output:
                if "write" in access_output or "modify" in access_output or "full" in access_output:
                    return "File is writable by users other than Administrators."

            return None
        except (OSError, subprocess.SubprocessError):
            return None


def _parse_hosts_file(content: str) -> list[dict]:
    """Parse hosts file content into IP/domain pairs.

    Args:
        content: Raw content of hosts file

    Returns:
        List of dicts with 'ip' and 'domains' keys
    """
    entries = []
    for line in content.splitlines():
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip = parts[0]
        domains = parts[1:]

        entries.append({"ip": ip, "domains": domains})

    return entries


def _find_blocked_security_domains(entries: list[dict]) -> list[str]:
    """Find antivirus/security update domains that are blocked or redirected.

    Args:
        entries: List of hosts file entries

    Returns:
        List of blocked antivirus/security domains
    """
    blocked = []
    for entry in entries:
        ip = entry["ip"].lower()
        domains = entry["domains"]

        for domain in domains:
            domain_lower = domain.lower()

            # Check if domain is a known antivirus/security domain
            for sec_domain in ANTIVIRUS_UPDATE_DOMAINS:
                # Exact match or subdomain match
                if domain_lower == sec_domain or domain_lower.endswith("." + sec_domain):
                    # Check if it's being blocked (pointing to non-localhost)
                    if ip not in LOCALHOST_IPS and not ip.startswith("::1") and not ip.startswith("127."):
                        blocked.append(domain)
                        break

    return blocked


def _find_redirected_legitimate_domains(entries: list[dict]) -> list[str]:
    """Find legitimate domains redirected to non-localhost IPs.

    Args:
        entries: List of hosts file entries

    Returns:
        List of suspicious domain redirects
    """
    redirected = []
    for entry in entries:
        ip = entry["ip"].lower()

        # Skip localhost IPs
        if ip in LOCALHOST_IPS or ip.startswith("::1") or ip.startswith("127."):
            continue

        domains = entry["domains"]
        for domain in domains:
            domain_lower = domain.lower()

            # Check if domain matches legitimate domains
            for legit_domain in LEGITIMATE_DOMAINS:
                if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                    redirected.append(f"{domain} -> {ip}")
                    break

    return redirected
