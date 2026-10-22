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

# Device-management services an employer or school uses. A profile is listed
# as information only when this Mac is enrolled in device management, the
# profile came from it (when the listing says), and its organization names one
# of these; anything else, or anything that couldn't be read, is a warning.
# (A profile's organization is written by whoever made the profile.)
KNOWN_MDM_FILE = content_file("modules/security/mdm_enrollment/data/known_mdm.json")
# `profiles` answers in well under a second; never wait long on it.
_TIMEOUT = 15


def _known_mdm() -> list[str]:
    return load_known(KNOWN_MDM_FILE)


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
        complete = True

        enrollment = self._check_enrollment()
        status_out = self._profiles_status()
        supervised = bool(status_out) and "supervised: yes" in status_out.lower()
        system_count = parse_system_profile_count(status_out)
        profiles = self._get_profiles()

        if enrollment is None and status_out is None and profiles is None:
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
            # Couldn't tell whether this Mac is enrolled: never "no management found".
            complete = False
        managed = enrollment["mdm"] is True or enrollment["dep"] is True

        # If device has MDM enrollment, flag as WARNING
        if managed:
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

        # If no MDM enrollment, flag as INFO (only when macOS plainly said so)
        if enrollment["mdm"] is False and enrollment["dep"] is not True and not supervised:
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
        if profiles is None:
            complete = False
            profiles = []
        # `profiles status` counts the whole system; without an administrator
        # password the listing can show fewer. Those can't be called known.
        unreadable = max(0, (system_count or 0) - len(profiles))
        if unreadable:
            complete = False
        if profiles or unreadable:
            unknown = [p["name"] for p in untrusted_profiles(profiles, enrollment["mdm"], _known_mdm())]
            shown = [
                {k: p[k] for k in ("name", "identifier", "organization", "source", "installed_by_mdm", "level")}
                for p in profiles
            ]
            profile_list = "\n".join(
                [
                    f"  - {p['name']} (Source: {p.get('source') or 'not known'}; "
                    f"Organization: {p.get('organization') or 'not known'})"
                    for p in profiles
                ]
            )
            description = (
                f"The following configuration profiles are installed:\n{profile_list}\n\n"
                if profiles else ""
            ) + (
                "These profiles may control device settings, security policies, "
                "VPN configurations, email settings, or other system behavior."
            )
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
            count = len(profiles) + unreadable
            findings.append(
                Finding(
                    title=f"Found {count} installed settings profile(s)",
                    description=description,
                    severity=Severity.WARNING if (unknown or unreadable) else Severity.INFO,
                    category=self.category,
                    code="security.mdm_enrollment.profiles_installed",
                    data={
                        "check": "profiles_installed",
                        "count": count,
                        "profiles": shown,
                        "unknown_profiles": unknown,
                        "unreadable_count": unreadable,
                        "enrolled_in_mdm": enrollment["mdm"],
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings, complete=complete)

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

    def _check_enrollment(self) -> dict | None:
        """`profiles status -type enrollment`, parsed; None when it didn't answer."""
        result = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=_TIMEOUT)
        if not result.ok:
            return None
        return parse_enrollment(result.stdout)

    def _profiles_status(self) -> str | None:
        """`profiles status` output (supervision, system-wide profile count); None on failure."""
        result = run(["/usr/bin/profiles", "status"], timeout=_TIMEOUT)
        return result.stdout if result.ok else None

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
