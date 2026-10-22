import json
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
from rescue.runtime import content_file

# Device-management services an employer or school uses. A profile whose
# organization names one of these is listed as information; any other profile,
# or one whose organization couldn't be read, is a warning.
KNOWN_MDM_FILE = content_file("modules/security/mdm_enrollment/data/known_mdm.json")
# `profiles list -verbose` starts each line with the level and "attribute:".
_LINE_PREFIX = re.compile(r"^\S+\[\d+\]\s+attribute:\s*", re.IGNORECASE)


def _known_mdm() -> list[str]:
    with open(KNOWN_MDM_FILE) as f:
        return [n for n in json.load(f) if isinstance(n, str) and n.strip()]


def is_known_mdm(organization, known: list[str]) -> bool:
    """Whether a profile's organization names a known device-management service (whole words)."""
    if not isinstance(organization, str) or not organization.strip():
        return False
    return any(re.search(rf"\b{re.escape(n)}\b", organization, re.IGNORECASE) for n in known)


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
                    title="Your Mac is managed by an organization",
                    description=(
                        "Your Mac is enrolled in Mobile Device Management (MDM). This "
                        "is a system used by companies and schools to control devices. "
                        "It can restrict which apps you install or change certain settings. "
                        "If this is a work or school computer, this is normal. If this "
                        "is your personal device and you did not set this up, it is a "
                        "sign that someone else has administrative control over it.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: If this is a work or school device, ask your IT department "
                        "to confirm the enrollment is expected. If it is a personal device, "
                        "look in System Settings > General > Device Management (Privacy & Security > Profiles on older macOS) "
                        "to see who manages it."
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
                    title="Your Mac is in 'supervised' mode",
                    description=(
                        "Your Mac is in 'supervised' mode. This is a stricter level of "
                        "management than standard enrollment, usually used by schools "
                        "or businesses to lock down devices completely. It prevents you "
                        "from changing many system settings or installing certain apps. "
                        "If this is a personal device, you should not be in this mode "
                        "unless you specifically set it up for testing.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: If this is a personal device, look in "
                        "System Settings > General > Device Management (Privacy & Security > Profiles on older macOS). "
                        "If you don't recognize the organization, get help before "
                        "removing anything."
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
                    title="No work or school management found",
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
            known = _known_mdm()
            unknown = [
                p["name"] for p in profiles_info["profiles"]
                if not is_known_mdm(p.get("organization"), known)
            ]
            profile_list = "\n".join(
                [
                    f"  - {p['name']} (Source: {p.get('source', 'not known')}; "
                    f"Organization: {p.get('organization') or 'not known'})"
                    for p in profiles_info["profiles"]
                ]
            )
            description = (
                f"The following configuration profiles are installed:\n{profile_list}\n\n"
                "These profiles may control device settings, security policies, "
                "VPN configurations, email settings, or other system behavior."
            )
            if unknown:
                description += (
                    "\n\nNot from a device-management service this checkup knows: "
                    + ", ".join(unknown)
                    + ". A profile you didn't add, or one from an employer or school "
                    "you've left, can read or change what you do.\n\n"
                    "What to do: Open System Settings, search for Profiles, and look "
                    "at who each one is from."
                )
            findings.append(
                Finding(
                    title=(
                        f"Found {len(profiles_info['profiles'])} installed settings profile(s)"
                    ),
                    description=description,
                    severity=Severity.WARNING if unknown else Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment.profiles_installed",
                    data={
                        "check": "profiles_installed",
                        "count": len(profiles_info["profiles"]),
                        "profiles": profiles_info["profiles"],
                        "unknown_profiles": unknown,
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
                line = _LINE_PREFIX.sub("", line.strip())
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

                    if key == "name":
                        current_profile["name"] = value
                    elif key == "profileidentifier":
                        # The display name wins; the identifier names it only when there's no name.
                        current_profile["identifier"] = value
                        current_profile.setdefault("name", value)
                    elif key == "source":
                        current_profile["source"] = value
                    elif key in ("organization", "profileorganization"):
                        current_profile["organization"] = value

            # Don't forget the last profile if file doesn't end with blank line
            if current_profile and "name" in current_profile:
                profiles.append(current_profile)

            return {"profiles": profiles}
        except (OSError, subprocess.SubprocessError):
            return {"profiles": []}
