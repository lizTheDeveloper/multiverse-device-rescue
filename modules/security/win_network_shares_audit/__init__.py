import subprocess
import json
import re

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

# Default Windows shares that should be present
DEFAULT_ADMIN_SHARES = {"C$", "ADMIN$", "IPC$"}

# Sensitive directories that users should not be sharing
SENSITIVE_DIRS = ["Users", "Documents", "Desktop", "Downloads", "Pictures", "Videos"]


class Module(ModuleBase):
    name = "win_network_shares_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check SMBv1 status
        smb1_enabled = self._check_smb1_enabled()
        if smb1_enabled:
            findings.append(
                Finding(
                    title="SMBv1 protocol is enabled",
                    description=(
                        "SMBv1 is enabled on this system. SMBv1 is vulnerable to "
                        "WannaCry (CVE-2017-0144) and other critical exploits. "
                        "SMBv1 should be disabled as it is deprecated and poses "
                        "a severe security risk."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "smb1_enabled"},
                )
            )

        # Get all shares and their details
        shares = self._get_shares_with_details()

        if not shares:
            findings.append(
                Finding(
                    title="Unable to retrieve network shares",
                    description=(
                        "Could not enumerate network shares. This may indicate "
                        "a system issue or lack of permissions."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "shares_list", "shares_count": 0},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Analyze each share
        non_default_shares = []
        for share_name, share_info in shares.items():
            share_path = share_info.get("path", "")
            is_admin_share = share_name in DEFAULT_ADMIN_SHARES

            # Check for shares accessible to Everyone
            access_info = share_info.get("access", [])
            has_everyone_access = any(
                "Everyone" in acc.get("account", "") for acc in access_info
            )

            if has_everyone_access:
                # Check if write access
                everyone_access = next(
                    (acc for acc in access_info if "Everyone" in acc.get("account", "")),
                    None,
                )
                access_right = everyone_access.get("access_right", "") if everyone_access else ""

                if "FULL" in access_right or "CHANGE" in access_right:
                    findings.append(
                        Finding(
                            title=f"Share '{share_name}' accessible to Everyone with write access",
                            description=(
                                f"The share '{share_name}' (path: {share_path}) is accessible "
                                "to Everyone with write permissions. This allows any user on the "
                                "network to read and modify files, posing a significant data security risk."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "everyone_write_access",
                                "share": share_name,
                                "path": share_path,
                            },
                        )
                    )
                elif "READ" in access_right:
                    findings.append(
                        Finding(
                            title=f"Share '{share_name}' accessible to Everyone with read access",
                            description=(
                                f"The share '{share_name}' (path: {share_path}) is accessible "
                                "to Everyone with read-only permissions. While read-only is safer "
                                "than write access, exposing shares to Everyone still poses a risk."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "everyone_read_access",
                                "share": share_name,
                                "path": share_path,
                            },
                        )
                    )

            # Check for shares pointing to sensitive directories
            if not is_admin_share:
                for sensitive_dir in SENSITIVE_DIRS:
                    if sensitive_dir.lower() in share_path.lower():
                        findings.append(
                            Finding(
                                title=f"Share '{share_name}' points to sensitive directory",
                                description=(
                                    f"The share '{share_name}' (path: {share_path}) points to a "
                                    f"sensitive user directory. Sharing {sensitive_dir} can expose "
                                    "personal files, documents, and potentially sensitive data."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check": "sensitive_directory",
                                    "share": share_name,
                                    "path": share_path,
                                    "sensitive_dir": sensitive_dir,
                                },
                            )
                        )
                        break

            # Track non-default shares
            if not is_admin_share:
                non_default_shares.append(
                    {
                        "name": share_name,
                        "path": share_path,
                        "access": access_info,
                    }
                )

        # Add INFO finding with all shares
        findings.append(
            Finding(
                title="Network shares enumerated",
                description=(
                    f"Found {len(shares)} total shares on system. {len(non_default_shares)} "
                    "non-default shares detected. Review share permissions and purposes regularly."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "shares_enumerated",
                    "total_shares": len(shares),
                    "non_default_shares": len(non_default_shares),
                    "shares": {s["name"]: s["path"] for s in non_default_shares},
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "smb1_enabled":
                actions.append(
                    Action(
                        title="Disable SMBv1 protocol",
                        description=(
                            "To disable SMBv1, run the following PowerShell command as Administrator:\n"
                            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n"
                            "Or via registry: Set-ItemProperty -Path "
                            "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                            "-Name SMB1 -Value 0\n"
                            "After disabling, restart the system for changes to take effect."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                    )
                )

            elif check_type == "everyone_write_access":
                share_name = finding.data.get("share", "")
                actions.append(
                    Action(
                        title=f"Review and restrict permissions for share '{share_name}'",
                        description=(
                            f"The share '{share_name}' should have restricted permissions. "
                            "Consider removing Everyone access or using authenticated users only. "
                            "Use 'net share <share> /grant:' to modify permissions, or use "
                            "Computer Management > Shares > Permissions."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                    )
                )

            elif check_type == "everyone_read_access":
                share_name = finding.data.get("share", "")
                actions.append(
                    Action(
                        title=f"Review and restrict permissions for share '{share_name}'",
                        description=(
                            f"Consider whether share '{share_name}' should be accessible to Everyone. "
                            "Restrict access to specific users or groups if possible."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check_type == "sensitive_directory":
                share_name = finding.data.get("share", "")
                actions.append(
                    Action(
                        title=f"Remove or secure sensitive share '{share_name}'",
                        description=(
                            f"Share '{share_name}' points to a sensitive directory. "
                            "Consider if this share is necessary. If not needed, use "
                            f"'net share {share_name} /delete' to remove it. "
                            "If it must remain, restrict access to authorized users only."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_smb1_enabled(self) -> bool:
        """Check if SMBv1 is enabled via PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.strip().lower()
                return output == "true"
        except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return False

    def _get_shares_with_details(self) -> dict:
        """Get all shares and their details including permissions."""
        shares = {}

        # First, get list of shares via net share
        try:
            result = subprocess.run(
                ["net", "share"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return shares

            share_names = self._parse_net_share_output(result.stdout)
        except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            return shares

        # Then get details for each share via PowerShell
        for share_name in share_names:
            try:
                # Get share path and info
                result = subprocess.run(
                    [
                        "powershell",
                        "-Command",
                        f"Get-SmbShare -Name '{share_name}' | Select-Object Name, Path, Description | ConvertTo-Json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    try:
                        share_info = json.loads(result.stdout)
                        path = share_info.get("Path", "")
                    except (json.JSONDecodeError, KeyError):
                        path = ""
                else:
                    path = ""

                # Get share permissions
                access_list = self._get_share_permissions(share_name)

                shares[share_name] = {
                    "path": path,
                    "access": access_list,
                }
            except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
                continue

        return shares

    def _parse_net_share_output(self, output: str) -> list:
        """Parse output from 'net share' command to extract share names.

        Example output:
            Share name        C$
            Path              C:\\
            Remark            Default share

            Share name        Users
            Path              C:\\Users
            ...
        """
        shares = []

        for line in output.splitlines():
            # Look for lines that start with "Share name"
            if line.strip().startswith("Share name"):
                # Extract the share name (everything after "Share name")
                parts = line.split(None, 2)  # Split on whitespace, max 3 parts
                if len(parts) >= 2:
                    share_name = parts[2].strip()  # Third element is the share name
                    if share_name:
                        shares.append(share_name)

        return shares

    def _get_share_permissions(self, share_name: str) -> list:
        """Get permissions for a specific share via PowerShell."""
        access_list = []

        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    f"Get-SmbShareAccess -Name '{share_name}' | Select-Object Name, AccountName, AccessControlType, AccessRight | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    # Handle both single object and array responses
                    if isinstance(data, dict):
                        data = [data]
                    elif not isinstance(data, list):
                        return access_list

                    for item in data:
                        access_list.append(
                            {
                                "account": item.get("AccountName", ""),
                                "access_right": item.get("AccessRight", ""),
                                "control_type": item.get("AccessControlType", ""),
                            }
                        )
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
        except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        return access_list
