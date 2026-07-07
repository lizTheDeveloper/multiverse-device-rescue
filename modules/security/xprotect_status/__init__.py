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

# XProtect bundle and related paths
XPROTECT_META_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
XPROTECT_REMEDIATOR_META = "/Library/Apple/System/Library/CoreServices/XProtect Remediator.bundle/Contents/Resources/XProtect Remediator.meta.plist"

# Minimum acceptable XProtect version (major version number).
# This is a baseline and should be periodically updated to reflect current security standards.
# As of 2026, XProtect definitions are updated regularly; a version below 3000 is considered outdated.
MINIMUM_XPROTECT_VERSION = 3000


class Module(ModuleBase):
    name = "xprotect_status"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check XProtect definitions version
        xprotect_version = self._get_xprotect_version()
        if xprotect_version is None:
            # XProtect bundle is missing or unreadable
            findings.append(
                Finding(
                    title="XProtect definitions bundle is missing or unreadable",
                    description=(
                        "The XProtect malware definitions bundle could not be read. "
                        "This may indicate a corrupted installation or system issue."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "xprotect_missing"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # XProtect bundle is readable - report current version
        findings.append(
            Finding(
                title=f"XProtect definitions are installed (version {xprotect_version})",
                description=(
                    f"XProtect malware definitions are at version {xprotect_version}. "
                    "This provides built-in protection against known macOS malware."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "xprotect_version", "version": xprotect_version},
            )
        )

        # Check if version is outdated
        if xprotect_version < MINIMUM_XPROTECT_VERSION:
            findings.append(
                Finding(
                    title="XProtect definitions are outdated",
                    description=(
                        f"XProtect definitions (version {xprotect_version}) are below "
                        f"the recommended minimum (version {MINIMUM_XPROTECT_VERSION}). "
                        "Run Software Update to get the latest malware definitions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "xprotect_outdated", "version": xprotect_version},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "xprotect_outdated":
                actions.append(
                    Action(
                        title="Update XProtect definitions",
                        description=(
                            "Run 'Software Update' (System Settings > General > Software Update) "
                            "to update XProtect definitions to the latest version."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "xprotect_missing":
                actions.append(
                    Action(
                        title="Restore XProtect definitions",
                        description=(
                            "The XProtect bundle may be corrupted. Run 'Software Update' or perform "
                            "a macOS repair/reinstall if the issue persists."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_xprotect_version(self) -> int | None:
        """
        Retrieve XProtect definitions version via defaults read.
        Returns the version as an integer, or None if the bundle is missing/unreadable.
        """
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    XPROTECT_META_PLIST,
                    "Version",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                # Bundle missing or unreadable
                return None
            version_str = result.stdout.strip()
            # Parse the version string to an integer (e.g., "4001" -> 4001)
            return int(version_str)
        except (OSError, ValueError):
            # OSError: command not found or execution failed
            # ValueError: version string is not a valid integer
            return None
