import subprocess
import re
from shlex import quote

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
    name = "hostname_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            computer_name = self._get_scutil_value("ComputerName")
            local_hostname = self._get_scutil_value("LocalHostName")
            hostname = self._get_scutil_value("HostName")
        except (OSError, subprocess.SubprocessError):
            # scutil not available or other error
            return CheckResult(module_name=self.name, findings=findings)

        # Collect all names for info
        names_summary = f"ComputerName: {computer_name}"
        if local_hostname:
            names_summary += f", LocalHostName: {local_hostname}"
        if hostname:
            names_summary += f", HostName: {hostname}"

        findings.append(
            Finding(
                title="Hostname configuration",
                description=names_summary,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "hostname_info",
                    "computer_name": computer_name,
                    "local_hostname": local_hostname,
                    "hostname": hostname,
                },
            )
        )

        # Check for inconsistency between ComputerName and LocalHostName
        if computer_name and local_hostname:
            if computer_name.lower() != local_hostname.lower():
                findings.append(
                    Finding(
                        title="Your computer's two names don't match",
                        description=(
                            f"Your Mac has two internal names: the 'Computer Name' ({computer_name}) "
                            f"and the 'Local Host Name' ({local_hostname}). They are currently "
                            "different.\n\n"
                            "What to do: Open System Settings > General > "
                            "About > Computer Name to review the names. If you use file "
                            "sharing, consider making them match."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "inconsistent_names"},
                    )
                )

        # Check for spaces in hostnames (affects network issues)
        for name, label in [
            (computer_name, "ComputerName"),
            (local_hostname, "LocalHostName"),
            (hostname, "HostName"),
        ]:
            if name and " " in name:
                findings.append(
                    Finding(
                        title="Your computer's name has a space in it",
                        description=(
                            f"The {label} '{name}' includes a space.\n\n"
                            "What to do: Open "
                            "System Settings > General > About > Computer Name and rename "
                            "your Mac to a name without spaces (for example, 'MyMac' "
                            "instead of 'My Mac')."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "spaces_in_name", "field": label},
                    )
                )
                break  # Only report once

        # Check for special characters
        for name, label in [
            (computer_name, "ComputerName"),
            (local_hostname, "LocalHostName"),
            (hostname, "HostName"),
        ]:
            # Spaces are reported by the check above (and are normal in the
            # ComputerName, e.g. Apple's default "MacBook Pro"); counting them
            # again here said "unusual symbols" about a plain space.
            if name and not re.match(r"^[a-zA-Z0-9\- ]*$", name):
                findings.append(
                    Finding(
                        title="Your computer's name has unusual symbols",
                        description=(
                            f"The {label} '{name}' uses symbols that can cause connection "
                            "problems. Computer names should only use letters, numbers, "
                            "and hyphens.\n\n"
                            "What to do: Open System Settings > General "
                            "> About > Computer Name and change the name to use only "
                            "standard characters."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "special_characters", "field": label},
                    )
                )
                break  # Only report once

        # Check for default hostnames
        default_names = {"Mac", "MacBook", "mac", "macbook"}
        for name, label in [
            (computer_name, "ComputerName"),
            (local_hostname, "LocalHostName"),
            (hostname, "HostName"),
        ]:
            if name in default_names:
                findings.append(
                    Finding(
                        title=f"Your Mac is still using the default name '{name}'",
                        description=(
                            f"Your {label} is still set to '{name}', which is the factory "
                            "default.\n\n"
                            "What to do: Open System Settings > General > About "
                            "> Computer Name and give your Mac a unique name that you "
                            "will recognize."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "default_name", "field": label},
                    )
                )
                break  # Only report once

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "inconsistent_names":
                actions.append(
                    Action(
                        title="Sync hostname settings",
                        description=(
                            "To fix inconsistent hostnames, set both ComputerName and LocalHostName "
                            "to the same value:\n"
                            "  sudo scutil --set ComputerName 'YourName'\n"
                            "  sudo scutil --set LocalHostName 'yourname'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "spaces_in_name":
                field = finding.data.get("field")
                actions.append(
                    Action(
                        title=f"Remove spaces from {field}",
                        description=(
                            f"Replace the {field} with a version without spaces. Use hyphens instead:\n"
                            f"  sudo scutil --set {quote(str(field))} 'my-device-name'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "special_characters":
                field = finding.data.get("field")
                actions.append(
                    Action(
                        title=f"Remove special characters from {field}",
                        description=(
                            f"Replace the {field} with a name using only letters, numbers, and hyphens:\n"
                            f"  sudo scutil --set {quote(str(field))} 'my-device-name'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "default_name":
                field = finding.data.get("field")
                actions.append(
                    Action(
                        title=f"Rename {field} from default",
                        description=(
                            f"Set {field} to a more descriptive name:\n"
                            f"  sudo scutil --set {quote(str(field))} 'your-device-name'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_scutil_value(self, key: str) -> str:
        """Get a value from scutil, return empty string if not set or error."""
        try:
            result = subprocess.run(
                ["scutil", "--get", key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except (OSError, subprocess.SubprocessError):
            raise
