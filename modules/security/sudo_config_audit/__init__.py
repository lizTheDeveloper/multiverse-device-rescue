import subprocess

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
    name = "sudo_config_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.sudo_config_audit.nopasswd_all",
        "security.sudo_config_audit.nopasswd_partial",
        "security.sudo_config_audit.timestamp_long",
        "security.sudo_config_audit.timestamp_ok",
        "security.sudo_config_audit.touchid_enabled",
        "security.sudo_config_audit.touchid_disabled",
        "security.sudo_config_audit.root_enabled",
        "security.sudo_config_audit.root_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for NOPASSWD entries
        nopasswd_findings = self._check_nopasswd()
        findings.extend(nopasswd_findings)

        # Check sudo timestamp timeout
        timestamp_finding = self._check_timestamp_timeout()
        if timestamp_finding:
            findings.append(timestamp_finding)

        # Check TouchID configuration
        touchid_finding = self._check_touchid()
        if touchid_finding:
            findings.append(touchid_finding)

        # Check root account status
        root_finding = self._check_root_account()
        if root_finding:
            findings.append(root_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")

            if check_type == "nopasswd_all":
                actions.append(
                    Action(
                        title="Remove NOPASSWD ALL from sudoers",
                        description=(
                            "NOPASSWD ALL allows any user to run any command as root without "
                            "a password. This is a critical security risk.\n"
                            f"Found in: {finding.data.get('location', 'unknown')}\n"
                            "To fix:\n"
                            "1. Run: sudo visudo\n"
                            "2. Find and remove lines with NOPASSWD ALL\n"
                            "3. Save and exit\n\n"
                            "Alternatively, edit the specific sudoers file directly with sudo."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "nopasswd_partial":
                actions.append(
                    Action(
                        title="Review NOPASSWD entries in sudoers",
                        description=(
                            f"Found NOPASSWD entries that allow certain commands without a password:\n"
                            f"{finding.data.get('entries', '')}\n\n"
                            "Review these entries and consider removing NOPASSWD if the commands "
                            "don't require frequent use without password."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "timestamp_long":
                timeout = finding.data.get("timeout_minutes", 0)
                actions.append(
                    Action(
                        title="Consider reducing sudo timestamp timeout",
                        description=(
                            f"Current sudo timestamp timeout is {timeout} minutes.\n"
                            "A long timeout increases the window for unauthorized sudo access "
                            "if your session is compromised.\n\n"
                            "To reduce timeout:\n"
                            "1. Run: sudo visudo\n"
                            "2. Add a line like: Defaults timestamp_timeout=5\n"
                            "3. Save and exit"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "timestamp_ok":
                # Informational, no action needed but include one
                actions.append(
                    Action(
                        title="Sudo timestamp timeout is reasonable",
                        description=(
                            f"Your sudo timestamp is set to a reasonable value. "
                            "No changes needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "touchid_enabled":
                actions.append(
                    Action(
                        title="Touch ID is enabled for sudo",
                        description=(
                            "Touch ID authentication for sudo is already configured. "
                            "No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "touchid_disabled":
                actions.append(
                    Action(
                        title="Enable Touch ID for sudo (optional security improvement)",
                        description=(
                            "Touch ID can be used for sudo authentication on compatible Macs.\n\n"
                            "To enable:\n"
                            "1. Run: sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak\n"
                            "2. Run: sudo nano /etc/pam.d/sudo\n"
                            "3. Add this line at the TOP (before the first 'auth' line):\n"
                            "   auth       sufficient     pam_tid.so\n"
                            "4. Save (Ctrl+O, Enter, Ctrl+X)\n\n"
                            "After enabling, you'll be prompted to use Touch ID for sudo instead of typing your password."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "root_enabled":
                actions.append(
                    Action(
                        title="Consider disabling the root account",
                        description=(
                            "The root account is enabled on this system. On macOS, the root account "
                            "is generally not needed for system administration—use sudo instead.\n\n"
                            "To disable root:\n"
                            "1. Open Directory Utility (/System/Library/CoreServices/Applications/Directory Utility.app)\n"
                            "2. Click the lock icon and authenticate\n"
                            "3. Go to Edit > Disable Root User\n\n"
                            "This reduces the attack surface by eliminating an alternative privileged account."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check_type == "root_disabled":
                actions.append(
                    Action(
                        title="Root account is disabled",
                        description=(
                            "The root account is disabled on this system. "
                            "This is the recommended security configuration on macOS. No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_nopasswd(self) -> list[Finding]:
        """Check for NOPASSWD entries in sudoers files."""
        findings = []

        try:
            # Read sudoers file
            sudoers_content = self._read_sudoers_file("/etc/sudoers")
            if not sudoers_content:
                return findings

            # Check for NOPASSWD ALL (critical)
            # Match "NOPASSWD: ALL" or "NOPASSWD:ALL" but not "NOPASSWD: /path/to/command"
            nopasswd_all_lines = [
                line
                for line in sudoers_content.split("\n")
                if "NOPASSWD:" in line
                and not line.strip().startswith("#")
                and any(
                    part.strip() == "ALL"
                    for part in line.split("NOPASSWD:")[-1].split()
                    if part.strip()
                )
                and not any(
                    part.startswith("/") for part in line.split("NOPASSWD:")[-1].split()
                )
            ]

            if nopasswd_all_lines:
                findings.append(
                    Finding(
                        title="NOPASSWD ALL in sudoers",
                        description=(
                            "Your sudoers configuration allows running ALL commands without a password. "
                            "This is a critical security weakness—anyone with access to your user account "
                            "can run any command as root without authentication."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.sudo_config_audit.nopasswd_all",
                        data={
                            "check_type": "nopasswd_all",
                            "location": "/etc/sudoers",
                            "lines": nopasswd_all_lines,
                        },
                    )
                )
            else:
                # Check for partial NOPASSWD (info)
                nopasswd_lines = [
                    line
                    for line in sudoers_content.split("\n")
                    if "NOPASSWD" in line and not line.strip().startswith("#")
                ]

                if nopasswd_lines:
                    findings.append(
                        Finding(
                            title="NOPASSWD entries in sudoers",
                            description=(
                                "Your sudoers configuration has NOPASSWD entries that allow certain commands "
                                "to run without a password. Review these to ensure they're necessary."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            code="security.sudo_config_audit.nopasswd_partial",
                            data={
                                "check_type": "nopasswd_partial",
                                "entries": "\n".join(nopasswd_lines[:5]),
                            },
                        )
                    )

        except Exception:
            # Silently fail if we can't read sudoers
            pass

        return findings

    def _check_timestamp_timeout(self) -> Finding | None:
        """Check sudo timestamp timeout setting."""
        try:
            result = subprocess.run(
                ["sudo", "-V"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return None

            # Look for "authentication timestamp timeout" line
            for line in result.stdout.split("\n"):
                if "authentication timestamp timeout" in line.lower():
                    # Try to extract the timeout value (usually in minutes)
                    parts = line.split()
                    for i, part in enumerate(parts):
                        try:
                            timeout = int(part)
                            if timeout > 30:
                                return Finding(
                                    title=f"Long sudo timestamp timeout ({timeout} minutes)",
                                    description=(
                                        f"Your sudo timestamp timeout is {timeout} minutes. "
                                        "This means once you authenticate with sudo, you won't need to "
                                        "re-authenticate for {timeout} minutes. The default is often too long "
                                        "for security; consider reducing it to 5-15 minutes."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    code="security.sudo_config_audit.timestamp_long",
                                    data={
                                        "check_type": "timestamp_long",
                                        "timeout_minutes": timeout,
                                    },
                                )
                            else:
                                # Record INFO if it's reasonable
                                return Finding(
                                    title=f"Sudo timestamp timeout: {timeout} minutes",
                                    description=(
                                        f"Your sudo authentication remains valid for {timeout} minutes "
                                        "after the last sudo use. This is a reasonable security setting."
                                    ),
                                    severity=Severity.INFO,
                                    category=self.category,
                                    code="security.sudo_config_audit.timestamp_ok",
                                    data={
                                        "check_type": "timestamp_ok",
                                        "timeout_minutes": timeout,
                                    },
                                )
                        except ValueError:
                            continue

        except Exception:
            pass

        return None

    def _check_touchid(self) -> Finding | None:
        """Check if Touch ID is configured for sudo."""
        try:
            # Check /etc/pam.d/sudo_local first (if it exists)
            pam_sudo_local_path = "/etc/pam.d/sudo_local"
            pam_sudo_path = "/etc/pam.d/sudo"

            has_touchid = False
            location = None

            # Check sudo_local first
            try:
                result = subprocess.run(
                    ["cat", pam_sudo_local_path],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0 and "pam_tid" in result.stdout:
                    has_touchid = True
                    location = pam_sudo_local_path
            except Exception:
                pass

            # Check regular sudo file if not already found
            if not has_touchid:
                try:
                    result = subprocess.run(
                        ["cat", pam_sudo_path],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode == 0 and "pam_tid" in result.stdout:
                        has_touchid = True
                        location = pam_sudo_path
                except Exception:
                    pass

            if has_touchid:
                return Finding(
                    title="Touch ID enabled for sudo",
                    description=(
                        f"Touch ID is configured for sudo authentication in {location}. "
                        "This allows you to use Touch ID instead of typing your password for sudo commands."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sudo_config_audit.touchid_enabled",
                    data={
                        "check_type": "touchid_enabled",
                        "location": location,
                    },
                )
            else:
                return Finding(
                    title="Touch ID not enabled for sudo",
                    description=(
                        "Touch ID is not currently configured for sudo on this Mac. "
                        "You can optionally enable it to use biometric authentication for sudo commands."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sudo_config_audit.touchid_disabled",
                    data={
                        "check_type": "touchid_disabled",
                    },
                )

        except Exception:
            pass

        return None

    def _check_root_account(self) -> Finding | None:
        """Check if the root account is enabled."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"],
                capture_output=True,
                text=True,
            )

            # If returncode is 0, the root account exists and is enabled
            if result.returncode == 0:
                return Finding(
                    title="Root account is enabled",
                    description=(
                        "The root account is currently enabled on this macOS system. "
                        "On macOS, the root account is generally unnecessary and can be a security risk. "
                        "It's recommended to use sudo for administrative tasks instead."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sudo_config_audit.root_enabled",
                    data={
                        "check_type": "root_enabled",
                    },
                )
            else:
                # Root account is disabled
                return Finding(
                    title="Root account is disabled",
                    description=(
                        "The root account is disabled on this macOS system. "
                        "This is the recommended security configuration on macOS."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sudo_config_audit.root_disabled",
                    data={
                        "check_type": "root_disabled",
                    },
                )

        except Exception:
            pass

        return None

    def _read_sudoers_file(self, path: str) -> str | None:
        """Read sudoers file using sudo cat to handle permissions."""
        try:
            result = subprocess.run(
                ["sudo", "cat", path],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass

        return None
