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
    name = "mdm_enrollment"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.mdm_enrollment.mdm_enrolled",
        "security.mdm_enrollment.supervised",
        "security.mdm_enrollment.no_mdm",
        "security.mdm_enrollment.profiles_installed",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check DEP enrollment status
        dep_enrolled = self._check_dep_enrollment()
        supervised = self._check_supervised()
        profiles_info = self._get_profiles_list()

        # If device has MDM enrollment, flag as WARNING
        if dep_enrolled:
            findings.append(
                Finding(
                    title="Device is MDM-enrolled",
                    description=(
                        "This device is enrolled in Mobile Device Management (MDM). "
                        "It may have restrictions on installing apps, modifying settings, "
                        "or other device behaviors depending on the MDM policies configured. "
                        "This is common on corporate or school-issued devices."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mdm_enrollment.mdm_enrolled",
                    data={"check": "mdm_enrolled"},
                )
            )

        # If device is supervised, flag as WARNING
        if supervised:
            findings.append(
                Finding(
                    title="Device is supervised",
                    description=(
                        "This device is in supervised mode, meaning it is fully managed "
                        "by Mobile Device Management (MDM). Supervised devices have "
                        "extensive restrictions on functionality, app installation, "
                        "and system modifications. This is typical for corporate or "
                        "school-managed devices."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mdm_enrollment.supervised",
                    data={"check": "supervised"},
                )
            )

        # If no MDM enrollment, flag as INFO
        if not dep_enrolled and not supervised:
            findings.append(
                Finding(
                    title="No MDM enrollment detected",
                    description=(
                        "This device does not appear to be enrolled in Mobile Device "
                        "Management. It is a personal device with no organizational "
                        "management policies applied."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment.no_mdm",
                    data={"check": "no_mdm"},
                )
            )

        # List installed profiles if any exist
        if profiles_info["profiles"]:
            profile_list = "\n".join(
                [
                    f"  - {p['name']} (Source: {p['source']})"
                    for p in profiles_info["profiles"]
                ]
            )
            findings.append(
                Finding(
                    title=f"Found {len(profiles_info['profiles'])} installed configuration profile(s)",
                    description=(
                        f"The following configuration profiles are installed:\n{profile_list}\n\n"
                        "These profiles may control device settings, security policies, "
                        "VPN configurations, email settings, or other system behavior."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment.profiles_installed",
                    data={
                        "check": "profiles_installed",
                        "count": len(profiles_info["profiles"]),
                        "profiles": profiles_info["profiles"],
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational guidance on MDM enrollment status.
        Does not actually remove MDM or profiles — this requires specific organizational tools.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "mdm_enrolled":
                actions.append(
                    Action(
                        title="Information: Device is MDM-enrolled",
                        description=(
                            "This device is managed by Mobile Device Management. "
                            "To remove MDM enrollment, contact your IT department or organization. "
                            "Unenrollment typically requires:\n"
                            "  1. Contacting your IT support team\n"
                            "  2. Backing up important data\n"
                            "  3. Using your organization's device management portal or app "
                            "to request unenrollment\n"
                            "  4. Factory resetting the device if necessary\n\n"
                            "Note: Some corporate and school devices cannot be unenrolled "
                            "without organizational approval."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "supervised":
                actions.append(
                    Action(
                        title="Information: Device is supervised",
                        description=(
                            "This device is in supervised mode under Mobile Device Management. "
                            "Supervised mode provides the organization with comprehensive control "
                            "over the device. To exit supervised mode:\n"
                            "  1. Contact your IT department for proper unenrollment procedures\n"
                            "  2. Ensure you have authorization to unenroll the device\n"
                            "  3. Back up your data before any unenrollment process\n"
                            "  4. A factory reset (Setup Assistant) may be required\n\n"
                            "Do not attempt to manually remove supervision as this may "
                            "require a complete device reset."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_mdm":
                actions.append(
                    Action(
                        title="Information: No MDM enrollment found",
                        description=(
                            "This device is not enrolled in Mobile Device Management. "
                            "No organizational restrictions are applied via MDM policies. "
                            "You have full control over device settings and app installation "
                            "(subject to standard macOS security policies like Gatekeeper)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "profiles_installed":
                profile_count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Information: {profile_count} configuration profile(s) installed",
                        description=(
                            f"Found {profile_count} configuration profile(s) on this device. "
                            "These may have been installed by:\n"
                            "  - Mobile Device Management (MDM)\n"
                            "  - Manual installation by an administrator\n"
                            "  - Automatic installation by enterprise software\n\n"
                            "To view profile details, run: sudo profiles list -verbose\n"
                            "To remove a profile, run: sudo profiles remove -identifier <profile_identifier>"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_dep_enrollment(self) -> bool:
        """
        Check if device is DEP-enrolled by running: profiles status -type enrollment
        Returns: True if enrolled, False otherwise
        """
        try:
            result = subprocess.run(
                ["/usr/bin/profiles", "status", "-type", "enrollment"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            output = result.stdout.lower()
            # DEP enrollment will show "enrolled: yes" or similar
            return "enrolled: yes" in output
        except (OSError, subprocess.SubprocessError):
            return False

    def _check_supervised(self) -> bool:
        """
        Check if device is supervised by looking for supervision indicator
        in profiles status output.
        Returns: True if supervised, False otherwise
        """
        try:
            result = subprocess.run(
                ["/usr/bin/profiles", "status"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            output = result.stdout.lower()
            # Supervised devices will show "supervised: yes" or similar
            return "supervised: yes" in output
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_profiles_list(self) -> dict:
        """
        Get list of installed configuration profiles.
        Returns: dict with 'profiles' key containing list of profiles with name and source
        """
        profiles = []
        try:
            result = subprocess.run(
                ["/usr/bin/profiles", "list", "-verbose"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {"profiles": []}

            # Parse output to extract profile names and sources
            lines = result.stdout.split("\n")
            current_profile = {}

            for line in lines:
                line = line.strip()
                if not line:
                    if current_profile and "name" in current_profile:
                        profiles.append(current_profile)
                        current_profile = {}
                    continue

                # Look for attribute: value format
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if key in ("name", "profileidentifier"):
                        current_profile["name"] = value
                    elif key == "source":
                        current_profile["source"] = value

            # Don't forget the last profile if file doesn't end with blank line
            if current_profile and "name" in current_profile:
                profiles.append(current_profile)

            return {"profiles": profiles}
        except (OSError, subprocess.SubprocessError):
            return {"profiles": []}
