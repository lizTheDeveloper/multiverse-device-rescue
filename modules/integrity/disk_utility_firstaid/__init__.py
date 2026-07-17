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
    name = "disk_utility_firstaid"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get filesystem type first
        fs_type = self._get_filesystem_type()
        if not fs_type:
            findings.append(
                Finding(
                    title="Could not determine filesystem type",
                    description=(
                        "Failed to run diskutil info /. Filesystem verification cannot be completed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "fs_type_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Run filesystem verification
        verify_result = self._verify_volume()
        if verify_result is None:
            findings.append(
                Finding(
                    title="Could not run filesystem verification",
                    description=(
                        "Failed to run diskutil verifyVolume /. Filesystem integrity check cannot be completed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "verify_failed", "filesystem": fs_type},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Parse verification output
        verify_status = verify_result.get("status")
        has_errors = verify_result.get("has_errors", False)
        needs_repair = verify_result.get("needs_repair", False)
        error_output = verify_result.get("error_output", "")

        # Determine severity based on verification result
        if has_errors or error_output:
            severity = Severity.CRITICAL
            title = "Filesystem integrity errors detected"
            check_type = "fs_errors"
        elif needs_repair:
            severity = Severity.WARNING
            title = "Filesystem needs repair"
            check_type = "fs_needs_repair"
        else:
            severity = Severity.INFO
            title = "Filesystem integrity check passed"
            check_type = "fs_healthy"

        findings.append(
            Finding(
                title=title,
                description=self._build_description(
                    fs_type, severity, verify_status, error_output
                ),
                severity=severity,
                category=self.category,
                data={
                    "check": check_type,
                    "filesystem": fs_type,
                    "verify_status": verify_status,
                    "error_output": error_output,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")
            fs_type = finding.data.get("filesystem", "Unknown")

            if check == "fs_errors":
                actions.append(
                    Action(
                        title="Filesystem integrity errors detected",
                        description=(
                            f"The filesystem ({fs_type}) has integrity errors. "
                            "Recommendations: (1) Restart into Recovery Mode (Cmd+R). "
                            "(2) Open Disk Utility. (3) Select your boot volume and click 'First Aid'. "
                            "(4) Let Disk Utility repair the filesystem. "
                            "(5) If errors persist, back up data and consider erasing and reinstalling macOS."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fs_needs_repair":
                actions.append(
                    Action(
                        title="Filesystem needs repair",
                        description=(
                            f"The filesystem ({fs_type}) indicates it may need repair. "
                            "Recommendations: (1) Restart into Recovery Mode (Cmd+R). "
                            "(2) Open Disk Utility. (3) Select your boot volume and click 'First Aid'. "
                            "(4) Let Disk Utility attempt to repair the filesystem. "
                            "(5) Restart and verify the system is operating normally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fs_healthy":
                actions.append(
                    Action(
                        title="Filesystem integrity is normal",
                        description=(
                            f"Your filesystem ({fs_type}) passed integrity verification. "
                            "No issues detected. Continue regular backups to protect your data."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "verify_failed":
                actions.append(
                    Action(
                        title="Unable to verify filesystem",
                        description=(
                            "The diskutil verifyVolume command failed. "
                            "Ensure you have sufficient permissions. "
                            "Try running 'diskutil verifyVolume /' manually in Terminal to diagnose."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fs_type_failed":
                actions.append(
                    Action(
                        title="Unable to determine filesystem type",
                        description=(
                            "The diskutil info command failed. "
                            "Ensure you have sufficient permissions and the disk is accessible. "
                            "Try running 'diskutil info /' manually in Terminal to diagnose."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_filesystem_type(self) -> str:
        """Get the filesystem type from diskutil info /."""
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode != 0:
                return None

            # Look for filesystem type
            for line in result.stdout.split("\n"):
                if "File System Personality:" in line:
                    fs_type = line.split(":", 1)[1].strip()
                    return fs_type

            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _verify_volume(self) -> dict:
        """Run diskutil verifyVolume and parse output."""
        try:
            result = subprocess.run(
                ["diskutil", "verifyVolume", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            return _parse_verify_output(output)

        except (OSError, subprocess.SubprocessError):
            return None

    def _build_description(
        self, fs_type: str, severity: Severity, status: str, error_output: str
    ) -> str:
        """Build a human-readable description of the verification result."""
        if severity == Severity.CRITICAL:
            return (
                f"Filesystem ({fs_type}) verification detected errors. "
                f"Status: {status}. "
                f"Error details: {error_output[:200]}... "
                "Run Disk Utility First Aid from Recovery Mode to repair."
            )
        elif severity == Severity.WARNING:
            return (
                f"Filesystem ({fs_type}) verification indicates repairs may be needed. "
                f"Status: {status}. "
                "Run Disk Utility First Aid from Recovery Mode to repair."
            )
        else:
            return (
                f"Filesystem ({fs_type}) verification passed. "
                f"Status: {status}. No issues detected."
            )


def _parse_verify_output(output: str) -> dict:
    """Parse diskutil verifyVolume output to determine filesystem status."""
    result = {
        "status": "Unknown",
        "has_errors": False,
        "needs_repair": False,
        "error_output": "",
    }

    # Check for "appears to be OK" - indicates clean filesystem
    if "appears to be OK" in output:
        result["status"] = "OK"
        return result

    # Check for error indicators
    error_keywords = [
        "error",
        "ERROR",
        "fail",
        "FAIL",
        "corrupt",
        "CORRUPT",
        "invalid",
        "INVALID",
        "bad block",
        "BAD BLOCK",
    ]

    has_error_keyword = any(keyword in output for keyword in error_keywords)
    if has_error_keyword:
        result["has_errors"] = True
        result["status"] = "Errors detected"
        # Extract error lines
        error_lines = [
            line
            for line in output.split("\n")
            if any(kw in line for kw in error_keywords)
        ]
        result["error_output"] = " ".join(error_lines[:3])
        return result

    # Check for repair indicators
    repair_keywords = ["repair", "REPAIR", "needs fixing", "NEEDS FIXING"]
    has_repair_keyword = any(keyword in output for keyword in repair_keywords)
    if has_repair_keyword:
        result["needs_repair"] = True
        result["status"] = "Needs repair"
        return result

    # If exit code was 0 but no explicit OK message, still mark as OK
    result["status"] = "OK"
    return result
