import subprocess
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
    name = "mdm_enrollment_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check MDM enrollment status
        enrollment_info = self._check_enrollment_status()

        # Check DEP status
        dep_status = self._check_dep_status()

        # Get list of installed configuration profiles
        profiles_info = self._get_profiles_list()

        # Check for MDM enrollment
        if enrollment_info["enrolled"]:
            mdm_server = enrollment_info.get("mdm_server", "Unknown")
            profile_count = profiles_info.get("profile_count", 0)

            findings.append(
                Finding(
                    title=f"MDM enrollment detected: {mdm_server}",
                    description=(
                        f"Device is enrolled in Mobile Device Management (MDM). "
                        f"MDM Server: {mdm_server}\n"
                        f"Installed configuration profiles: {profile_count}\n"
                        "This is typical for corporate or managed devices. "
                        "Contact your IT administrator for enrollment details."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "mdm_enrollment",
                        "mdm_server": mdm_server,
                        "profile_count": profile_count,
                    },
                )
            )

        # Check for restrictions profiles
        restrictions = profiles_info.get("restrictions_profiles", [])
        if restrictions:
            findings.append(
                Finding(
                    title=f"Configuration restrictions installed: {len(restrictions)} profile(s)",
                    description=(
                        f"Device has {len(restrictions)} restriction profile(s) installed: "
                        f"{', '.join(restrictions)}. "
                        "These may limit functionality like software installation, "
                        "system preferences access, or other capabilities. "
                        "Contact IT if restrictions are unexpected."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "restrictions_profiles",
                        "profiles": restrictions,
                    },
                )
            )

        # List all installed profiles if any exist
        all_profiles = profiles_info.get("all_profiles", [])
        if all_profiles:
            findings.append(
                Finding(
                    title=f"Configuration profiles: {len(all_profiles)} installed",
                    description=(
                        f"Installed configuration profiles:\n"
                        + "\n".join(f"  - {p}" for p in sorted(all_profiles))
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "all_profiles",
                        "profiles": all_profiles,
                    },
                )
            )

        # Check DEP status
        if dep_status.get("dep_enabled"):
            findings.append(
                Finding(
                    title="Device Enrollment Program (DEP) enabled",
                    description=(
                        "Device has Device Enrollment Program (DEP) enabled. "
                        "This allows automated device enrollment and management. "
                        "This is typical for enterprise-managed devices."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "dep_status"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "mdm_enrollment":
                mdm_server = finding.data.get("mdm_server", "your organization's MDM")
                actions.append(
                    Action(
                        title="Review MDM enrollment",
                        description=(
                            f"Your device is enrolled in MDM with server: {mdm_server}.\n"
                            "This is managed by your IT department. "
                            "If you have questions about the enrollment, "
                            "contact your IT support or administrator.\n\n"
                            "To view enrollment details, run:\n"
                            "  sudo profiles show -verbose"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "restrictions_profiles":
                profiles = finding.data.get("profiles", [])
                profile_list = ", ".join(profiles)
                actions.append(
                    Action(
                        title="Review configuration restrictions",
                        description=(
                            f"Configuration profiles with restrictions: {profile_list}.\n"
                            "These profiles may limit system functionality. "
                            "If restrictions are unexpected or problematic, "
                            "contact your IT administrator for assistance.\n"
                            "Do not attempt to remove MDM profiles yourself."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "all_profiles":
                actions.append(
                    Action(
                        title="Review installed configuration profiles",
                        description=(
                            "To manage configuration profiles, open System Settings > "
                            "General > Profiles & Device Management.\n"
                            "To view detailed profile information, run:\n"
                            "  sudo profiles list -verbose"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "dep_status":
                actions.append(
                    Action(
                        title="Review DEP status",
                        description=(
                            "Device Enrollment Program (DEP) is enabled on this device. "
                            "This is typical for corporate devices. "
                            "Contact your IT administrator if you have questions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_enrollment_status(self) -> dict:
        """Check if device is enrolled in MDM.

        Returns dict with 'enrolled' bool and 'mdm_server' string.
        """
        try:
            result = subprocess.run(
                ["profiles", "status", "-type", "enrollment"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return {"enrolled": False}

            output = result.stdout.lower()

            # Check if enrolled
            enrolled = "enrollment" in output and "yes" in output

            # Try to extract MDM server name
            mdm_server = "Unknown"
            for line in result.stdout.split("\n"):
                if "mdm enrollment server" in line.lower():
                    # Extract server name from line
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        mdm_server = parts[1].strip()
                        break

            return {"enrolled": enrolled, "mdm_server": mdm_server}
        except Exception:
            return {"enrolled": False}

    def _check_dep_status(self) -> dict:
        """Check if Device Enrollment Program (DEP) is enabled.

        Returns dict with 'dep_enabled' bool.
        """
        try:
            result = subprocess.run(
                ["profiles", "status", "-type", "bootstraptoken"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return {"dep_enabled": False}

            # Check if DEP/bootstrap token is present
            output = result.stdout.lower()
            dep_enabled = "bootstraptoken" in output or "yes" in output

            return {"dep_enabled": dep_enabled}
        except Exception:
            return {"dep_enabled": False}

    def _get_profiles_list(self) -> dict:
        """Get list of installed configuration profiles.

        Returns dict with:
        - 'profile_count': int
        - 'all_profiles': list of profile names
        - 'restrictions_profiles': list of restriction profile names
        """
        try:
            result = subprocess.run(
                ["sudo", "profiles", "list", "-verbose"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                # Try without sudo
                result = subprocess.run(
                    ["profiles", "list", "-verbose"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    return {
                        "profile_count": 0,
                        "all_profiles": [],
                        "restrictions_profiles": [],
                    }

            all_profiles = []
            restrictions_profiles = []

            # Parse profile list output
            # Format: attribute: name / value: <name>
            lines = result.stdout.split("\n")
            prev_is_name_attr = False
            for line in lines:
                line = line.strip()
                if not line:
                    prev_is_name_attr = False
                    continue

                if line.lower().startswith("attribute: name"):
                    prev_is_name_attr = True
                    continue

                if prev_is_name_attr and line.lower().startswith("value:"):
                    # Extract profile name from value line
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        profile_name = parts[1].strip()
                        if profile_name and profile_name not in all_profiles:
                            all_profiles.append(profile_name)

                            # Check if this is a restrictions profile
                            if any(
                                term in profile_name.lower()
                                for term in ["restrict", "parental", "managed", "content filter"]
                            ):
                                restrictions_profiles.append(profile_name)

                prev_is_name_attr = False

            return {
                "profile_count": len(all_profiles),
                "all_profiles": all_profiles,
                "restrictions_profiles": restrictions_profiles,
            }
        except Exception:
            return {
                "profile_count": 0,
                "all_profiles": [],
                "restrictions_profiles": [],
            }
