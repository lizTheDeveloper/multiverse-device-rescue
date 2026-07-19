import subprocess
from datetime import datetime, timedelta
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

# XProtect bundle and related paths
XPROTECT_META_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
XPROTECT_REMEDIATOR_META = "/Library/Apple/System/Library/CoreServices/XProtect Remediator.bundle/Contents/Resources/XProtect Remediator.meta.plist"

# Minimum acceptable XProtect version (major version number).
# This is a baseline and should be periodically updated to reflect current security standards.
# As of 2026, XProtect definitions are updated regularly; a version below 3000 is considered outdated.
MINIMUM_XPROTECT_VERSION = 3000

# Maximum age for XProtect/MRT definitions (in days)
DEFINITIONS_MAX_AGE_DAYS = 30


class Module(ModuleBase):
    name = "xprotect_status"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.xprotect_status.gatekeeper_disabled",
        "security.xprotect_status.gatekeeper_status",
        "security.xprotect_status.xprotect_missing",
        "security.xprotect_status.xprotect_version",
        "security.xprotect_status.xprotect_outdated",
        "security.xprotect_status.xprotect_old",
        "security.xprotect_status.mrt_version",
        "security.xprotect_status.mrt_outdated",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Gatekeeper status (CRITICAL if disabled)
        gatekeeper_status = self._get_gatekeeper_status()
        if gatekeeper_status == "disabled":
            findings.append(
                Finding(
                    title="Gatekeeper is disabled",
                    description=(
                        "Gatekeeper is disabled. This means macOS is not verifying that apps "
                        "are signed and notarized before running them. This is a significant "
                        "security risk. Re-enable Gatekeeper in System Settings > Privacy & Security."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.xprotect_status.gatekeeper_disabled",
                    data={"check": "gatekeeper_disabled"},
                )
            )
        elif gatekeeper_status:
            findings.append(
                Finding(
                    title=f"Gatekeeper status: {gatekeeper_status}",
                    description=(
                        f"Gatekeeper is {gatekeeper_status}. Gatekeeper verifies that apps "
                        "are signed and notarized before running them."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.xprotect_status.gatekeeper_status",
                    data={"check": "gatekeeper_status", "status": gatekeeper_status},
                )
            )

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
                    code="security.xprotect_status.xprotect_missing",
                    data={"check": "xprotect_missing"},
                )
            )
        else:
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
                    code="security.xprotect_status.xprotect_version",
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
                        code="security.xprotect_status.xprotect_outdated",
                        data={"check": "xprotect_outdated", "version": xprotect_version},
                    )
                )

            # Check last update date
            last_update = self._get_xprotect_last_update()
            if last_update:
                if not self._is_recent(last_update):
                    findings.append(
                        Finding(
                            title="XProtect definitions are old",
                            description=(
                                f"XProtect definitions were last updated on {last_update}, "
                                f"which is more than {DEFINITIONS_MAX_AGE_DAYS} days ago. "
                                "Run Software Update to get the latest definitions."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.xprotect_status.xprotect_old",
                            data={"check": "xprotect_old", "last_update": last_update},
                        )
                    )

        # Check MRT version and last update
        mrt_version, mrt_last_update = self._get_mrt_info()
        if mrt_version:
            findings.append(
                Finding(
                    title=f"MRT (Malware Removal Tool) version: {mrt_version}",
                    description=(
                        f"Malware Removal Tool version is {mrt_version}. "
                        f"Last update: {mrt_last_update or 'unknown'}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.xprotect_status.mrt_version",
                    data={"check": "mrt_version", "version": mrt_version, "last_update": mrt_last_update},
                )
            )

            # Check if MRT is old
            if mrt_last_update and not self._is_recent(mrt_last_update):
                findings.append(
                    Finding(
                        title="MRT (Malware Removal Tool) is outdated",
                        description=(
                            f"MRT was last updated on {mrt_last_update}, "
                            f"which is more than {DEFINITIONS_MAX_AGE_DAYS} days ago. "
                            "Run Software Update to get the latest version."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.xprotect_status.mrt_outdated",
                        data={"check": "mrt_outdated", "last_update": mrt_last_update},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        added_update_action = False

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "gatekeeper_disabled":
                actions.append(
                    Action(
                        title="Re-enable Gatekeeper",
                        description=(
                            "To re-enable Gatekeeper, open System Settings > Privacy & Security "
                            "and ensure 'Allow applications downloaded from:' is set to either "
                            "'App Store' or 'App Store and identified developers'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check in ("xprotect_outdated", "xprotect_old", "mrt_outdated"):
                # Only add one update action even if multiple things are outdated
                if not added_update_action:
                    actions.append(
                        Action(
                            title="Update XProtect and MRT definitions",
                            description=(
                                "Run 'Software Update' (System Settings > General > Software Update) "
                                "to update XProtect definitions and Malware Removal Tool to the latest versions."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                    added_update_action = True
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

    def _get_gatekeeper_status(self) -> str | None:
        """Get Gatekeeper status via spctl.

        Returns: 'enabled', 'disabled', or None if unable to determine
        """
        try:
            result = subprocess.run(
                ["spctl", "--status"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.strip().lower()
            if "disabled" in output:
                return "disabled"
            elif "enabled" in output:
                return "enabled"
            return None
        except Exception:
            return None

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

    def _get_xprotect_last_update(self) -> str | None:
        """Get XProtect last update date from system_profiler.

        Returns: date string in format "YYYY-MM-DD" or None
        """
        try:
            result = subprocess.run(
                ["system_profiler", "SPInstallHistoryDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None

            for line in result.stdout.split("\n"):
                if "XProtect" in line:
                    # Look for date patterns like "2024-07-15"
                    match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                    if match:
                        return match.group(1)
        except Exception:
            pass

        return None

    def _get_mrt_info(self) -> tuple[str | None, str | None]:
        """Get MRT (Malware Removal Tool) version and last update date.

        Returns: (version, last_update_date) tuple where last_update_date is in format "YYYY-MM-DD"
        """
        version = None
        last_update = None

        try:
            result = subprocess.run(
                ["system_profiler", "SPInstallHistoryDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None, None

            for line in result.stdout.split("\n"):
                if "MRT" in line or "Malware Removal" in line:
                    # Extract version (e.g., "1.2.3" or "4001")
                    version_match = re.search(r"(\d+(?:\.\d+)*)", line)
                    if version_match and not version:
                        version = version_match.group(1)

                    # Extract date (e.g., "2024-07-15")
                    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                    if date_match and not last_update:
                        last_update = date_match.group(1)

                    if version and last_update:
                        break
        except Exception:
            pass

        return version, last_update

    def _is_recent(self, date_str: str) -> bool:
        """Check if a date string is recent (within DEFINITIONS_MAX_AGE_DAYS).

        date_str should be in format "YYYY-MM-DD"
        Returns: True if within max age, False if older
        """
        try:
            date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
            today = datetime.now().date()
            age = (today - date_obj).days
            return age <= DEFINITIONS_MAX_AGE_DAYS
        except Exception:
            return True  # If we can't parse, assume it's recent
