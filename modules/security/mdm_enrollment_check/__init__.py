import json
import re
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
from rescue.runtime import content_file

# Device-management services an employer or school uses (the same list as
# mdm_enrollment's). A profile whose organization names one is information;
# any other profile, or one whose organization couldn't be read, is a warning.
KNOWN_MDM_FILE = content_file("modules/security/mdm_enrollment_check/data/known_mdm.json")


def _known_mdm() -> list[str]:
    with open(KNOWN_MDM_FILE) as f:
        return [n for n in json.load(f) if isinstance(n, str) and n.strip()]


def is_known_mdm(organization, known: list[str]) -> bool:
    """Whether a profile's organization names a known device-management service (whole words)."""
    if not isinstance(organization, str) or not organization.strip():
        return False
    return any(re.search(rf"\b{re.escape(n)}\b", organization, re.IGNORECASE) for n in known)


class Module(ModuleBase):
    name = "mdm_enrollment_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.mdm_enrollment_check.mdm_enrollment",
        "security.mdm_enrollment_check.restrictions_profiles",
        "security.mdm_enrollment_check.all_profiles",
        "security.mdm_enrollment_check.dep_status",
    ]

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
                    title=f"Managed by: {mdm_server}",
                    description=(
                        f"Device is enrolled in Mobile Device Management (MDM). "
                        f"MDM Server: {mdm_server}\n"
                        f"Installed configuration profiles: {profile_count}\n"
                        "This is typical for corporate or managed devices. "
                        "Contact your IT administrator for enrollment details."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment_check.mdm_enrollment",
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
                    title=(
                        f"Restrictions are limiting your device: {len(restrictions)} profile(s)"
                    ),
                    description=(
                        f"Your device has {len(restrictions)} restriction profile(s) installed: "
                        f"{', '.join(restrictions)}. These profiles can block you from "
                        "installing apps, changing settings, or using certain features. "
                        "If you work for a company, this is likely normal. However, if "
                        "you do not work for a company or did not expect these restrictions, "
                        "it is important to check if someone else installed them to control "
                        "your device.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: If you have a job, ask your IT department if these "
                        "profiles are expected. If you do not have a job, or if you did "
                        "not expect these restrictions, look in "
                        "System Settings > General > Device Management (Privacy & Security > Profiles on older macOS)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.mdm_enrollment_check.restrictions_profiles",
                    data={
                        "check": "restrictions_profiles",
                        "profiles": restrictions,
                    },
                )
            )

        # List all installed profiles if any exist
        all_profiles = profiles_info.get("all_profiles", [])
        if all_profiles:
            organizations = profiles_info.get("organizations", {})
            known = _known_mdm()
            unknown = [p for p in all_profiles if not is_known_mdm(organizations.get(p), known)]
            description = (
                "Installed configuration profiles:\n"
                + "\n".join(f"  - {p}" for p in sorted(all_profiles))
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
                    title=f"Configuration profiles: {len(all_profiles)} installed",
                    description=description,
                    severity=Severity.WARNING if unknown else Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment_check.all_profiles",
                    data={
                        "check": "all_profiles",
                        "profiles": all_profiles,
                        "organizations": {p: organizations.get(p) for p in all_profiles},
                        "unknown_profiles": unknown,
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
                    code="security.mdm_enrollment_check.dep_status",
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
            # The organization each profile names (None when it names none).
            organizations = {}
            pending_org = None

            # Parse profile list output
            # Format: attribute: name / value: <name>, and attribute: organization / value: <org>
            lines = result.stdout.split("\n")
            prev_attr = None
            for line in lines:
                line = line.strip()
                if not line:
                    prev_attr = None
                    continue

                low = line.lower()
                if low.startswith("attribute: name"):
                    prev_attr = "name"
                    continue
                if low.startswith("attribute: organization"):
                    prev_attr = "organization"
                    continue

                if prev_attr and low.startswith("value:"):
                    parts = line.split(":", 1)
                    value = parts[1].strip() if len(parts) > 1 else ""
                    if prev_attr == "name" and value and value not in all_profiles:
                        all_profiles.append(value)
                        organizations[value] = pending_org
                        pending_org = None

                        # Check if this is a restrictions profile
                        if any(
                            term in value.lower()
                            for term in ["restrict", "parental", "managed", "content filter"]
                        ):
                            restrictions_profiles.append(value)
                    elif prev_attr == "organization" and value:
                        # It belongs to the profile just named, unless that one already has one
                        # (then to the next profile named).
                        if all_profiles and organizations.get(all_profiles[-1]) is None and pending_org is None:
                            organizations[all_profiles[-1]] = value
                        else:
                            pending_org = value

                prev_attr = None

            return {
                "profile_count": len(all_profiles),
                "all_profiles": all_profiles,
                "organizations": organizations,
                "restrictions_profiles": restrictions_profiles,
            }
        except Exception:
            return {
                "profile_count": 0,
                "all_profiles": [],
                "restrictions_profiles": [],
            }
