import re
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
    name = "system_extensions"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        extensions = self._list_system_extensions()
        if extensions is None:
            # systemextensionsctl not available (older macOS)
            return CheckResult(module_name=self.name, findings=findings)

        for ext in extensions:
            team_id = ext.get("team_id", "unknown")
            name = ext.get("name", "unknown")
            state = ext.get("state", "unknown").lower()
            category = ext.get("category", "unknown")
            version = ext.get("version", "unknown")

            # Unusual states warrant a WARNING
            if "waiting" in state or "approved" not in state and "activated" not in state:
                findings.append(
                    Finding(
                        title=f"System extension awaiting approval: {name}",
                        description=(
                            f"The system extension '{name}' (Team ID: {team_id}) "
                            f"is in state '{state}'. "
                            f"Category: {category}. Version: {version}. "
                            "This extension is not fully activated and may require user action. "
                            "Check System Settings > General > Login Items > Allow in the More Secure "
                            "Enclave to approve the extension."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "unusual_state",
                            "team_id": team_id,
                            "name": name,
                            "state": state,
                            "category": category,
                        },
                    )
                )
            # Active extensions are reported as INFO
            elif "activated" in state:
                findings.append(
                    Finding(
                        title=f"Activated system extension: {name}",
                        description=(
                            f"The system extension '{name}' (Team ID: {team_id}) "
                            f"is activated. Version: {version}. "
                            f"Category: {category}. "
                            "This extension is actively running and has system-level privileges. "
                            f"Ensure you trust this extension and understand its purpose. "
                            "If you no longer need it, you can disable it in "
                            "System Settings > General > Login Items > Allow in the More Secure Enclave."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "active_extension",
                            "team_id": team_id,
                            "name": name,
                            "state": state,
                            "category": category,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            name = finding.data.get("name", "unknown")
            state = finding.data.get("state", "unknown")

            if check == "active_extension":
                actions.append(
                    Action(
                        title=f"Review and manage active extension: {name}",
                        description=(
                            f"The system extension '{name}' is currently activated. "
                            "To manage this extension, open System Settings > "
                            "General > Login Items > Allow in the More Secure Enclave. "
                            "Review the extension and disable it if you no longer need it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "unusual_state":
                actions.append(
                    Action(
                        title=f"Review extension in unusual state: {name}",
                        description=(
                            f"The system extension '{name}' is in state '{state}'. "
                            "To resolve this, open System Settings > "
                            "General > Login Items > Allow in the More Secure Enclave and "
                            "approve the extension. If you don't trust this extension, "
                            "reject it or contact your system administrator."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _list_system_extensions(self) -> list[dict] | None:
        """List all system extensions via systemextensionsctl.

        Returns list of dicts with keys: team_id, name, version, state, category.
        Returns None if systemextensionsctl is not available (older macOS).
        """
        try:
            result = subprocess.run(
                ["systemextensionsctl", "list"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # Command failed or not found
                return None

            extensions = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                ext = self._parse_extension_line(line)
                if ext:
                    extensions.append(ext)
            return extensions
        except (OSError, FileNotFoundError):
            # systemextensionsctl not available
            return None
        except Exception:
            # Any other error
            return None

    def _parse_extension_line(self, line: str) -> dict | None:
        """Parse a single line of systemextensionsctl list output.

        Expected format:
        [TEAM_ID] bundle.id - version X.X - state [Category]

        Example:
        [com.apple.ABCD1234] com.apple.networkext - version 1.0 - activated [Network Extension]
        """
        # Pattern to match the format
        # [TEAM_ID] bundle.id - version X.X - state [Category]
        pattern = r"\[([^\]]+)\]\s+([^\s]+)\s+-\s+version\s+([^\s]+)\s+-\s+(.+?)\s+\[([^\]]+)\]"
        match = re.match(pattern, line.strip())

        if match:
            team_id, bundle_id, version, state, category = match.groups()
            return {
                "team_id": team_id,
                "name": bundle_id,
                "version": version,
                "state": state.strip(),
                "category": category.strip(),
            }
        return None
