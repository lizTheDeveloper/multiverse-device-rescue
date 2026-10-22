from rescue.command import run
from rescue.macos_profiles import (
    MAX_LISTING_BYTES,
    load_known,
    parse_enrollment,
    parse_profiles_text,
    parse_profiles_xml,
    parse_system_profile_count,
    untrusted_profiles,
)
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
# mdm_enrollment's). A profile is information only when this Mac is enrolled
# in device management, the listing says this profile was installed by MDM, and
# its organization names one of these; anything else, or anything that
# couldn't be read, is a warning. (A profile's organization is written by
# whoever made the profile.)
KNOWN_MDM_FILE = content_file("modules/security/mdm_enrollment_check/data/known_mdm.json")
# `profiles` answers in well under a second; never wait long on it.
_TIMEOUT = 15
_RESTRICTION_TERMS = ["restrict", "parental", "managed", "content filter"]


def _known_mdm() -> list[str]:
    return load_known(KNOWN_MDM_FILE)


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
        complete = True

        # Check MDM enrollment status (None: `profiles` didn't answer)
        enrollment = self._check_enrollment_status()

        # Check DEP status
        dep_status = self._check_dep_status()

        # The system-wide profile count, and the profiles this check can read
        status = run(["/usr/bin/profiles", "status"], timeout=_TIMEOUT)
        system_count = parse_system_profile_count(status.stdout) if status.ok else None
        profiles = self._get_profiles()

        if enrollment is None and not status.ok and profiles is None:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "macOS's `profiles` tool didn't answer (it failed or took too long), "
                    "so device management couldn't be checked."
                ),
            )
        enrollment = enrollment or {"mdm": None, "dep": None, "server": None}
        if enrollment["mdm"] is None:
            complete = False
        if profiles is None:
            complete = False
            profiles = []
        unreadable = max(0, (system_count or 0) - len(profiles))
        if unreadable:
            complete = False
        all_profiles = [p["name"] for p in profiles]
        restrictions = [
            p["name"] for p in profiles if any(t in p["name"].lower() for t in _RESTRICTION_TERMS)
        ]

        # Check for MDM enrollment
        if enrollment["mdm"] is True:
            mdm_server = enrollment.get("server") or "Unknown"
            profile_count = len(profiles) + unreadable

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
        if all_profiles or unreadable:
            # Each organization belongs to the profile in its own block only.
            organizations = {p["name"]: p["organization"] for p in profiles}
            unknown = [p["name"] for p in untrusted_profiles(profiles, enrollment["mdm"], _known_mdm())]
            description = (
                "Installed configuration profiles:\n"
                + "\n".join(f"  - {p}" for p in sorted(all_profiles))
            ) if all_profiles else "Configuration profiles are installed."
            if unknown:
                description += (
                    "\n\nNot from a device-management service this checkup knows: "
                    + ", ".join(unknown)
                    + ". A profile names its own organization, so this checkup only "
                    "trusts one on a Mac enrolled in device management. A profile you "
                    "didn't add, or one from an employer or school you've left, can "
                    "read or change what you do.\n\n"
                    "What to do: Open System Settings, search for Profiles, and look "
                    "at who each one is from."
                )
            if unreadable:
                description += (
                    f"\n\nmacOS says {unreadable} more profile(s) are installed than this "
                    "checkup could read (listing them all needs an administrator password, "
                    "which this checkup never asks for). Open System Settings and search "
                    "for Profiles to see every one."
                )
            findings.append(
                Finding(
                    title=f"Configuration profiles: {len(all_profiles) + unreadable} installed",
                    description=description,
                    severity=Severity.WARNING if (unknown or unreadable) else Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment_check.all_profiles",
                    data={
                        "check": "all_profiles",
                        "profiles": all_profiles,
                        "organizations": organizations,
                        "unknown_profiles": unknown,
                        "unreadable_count": unreadable,
                        "enrolled_in_mdm": enrollment["mdm"],
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

        return CheckResult(module_name=self.name, findings=findings, complete=complete)

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

    def _check_enrollment_status(self) -> dict | None:
        """`profiles status -type enrollment`, parsed; None when it didn't answer."""
        result = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=_TIMEOUT)
        if not result.ok:
            return None
        return parse_enrollment(result.stdout)

    def _check_dep_status(self) -> dict:
        """Check if Device Enrollment Program (DEP) is enabled.

        Returns dict with 'dep_enabled' bool.
        """
        result = run(["/usr/bin/profiles", "status", "-type", "bootstraptoken"], timeout=_TIMEOUT)
        if not result.ok:
            return {"dep_enabled": False}
        output = result.stdout.lower()
        return {"dep_enabled": "bootstraptoken" in output or "yes" in output}

    def _get_profiles(self) -> list[dict] | None:
        """Installed profiles, one dict each; None when they couldn't be read.

        Structured (XML) output first; the text listing when that fails or is
        empty. Never with sudo.
        """
        xml = run(["/usr/bin/profiles", "show", "-output", "stdout-xml"],
                  timeout=_TIMEOUT, max_output=MAX_LISTING_BYTES)
        from_xml = parse_profiles_xml(xml.stdout) if xml.ok and not xml.truncated else None
        if from_xml:
            return from_xml
        text = run(["/usr/bin/profiles", "list", "-verbose"], timeout=_TIMEOUT, max_output=MAX_LISTING_BYTES)
        from_text = parse_profiles_text(text.stdout) if text.ok and not text.truncated else None
        return from_text if from_text is not None else from_xml
