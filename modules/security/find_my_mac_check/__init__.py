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


class Module(ModuleBase):
    name = "find_my_mac_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.find_my_mac_check.find_my_mac_disabled",
        "security.find_my_mac_check.location_services_disabled",
        "security.find_my_mac_check.icloud_not_signed_in",
        "security.find_my_mac_check.configured_ok",
        "security.find_my_mac_check.find_my_mac_unknown",
        "security.find_my_mac_check.location_services_unknown",
        "security.find_my_mac_check.send_last_location_disabled",
        "security.find_my_mac_check.send_last_location_unknown",
        "security.find_my_mac_check.activation_lock_unknown",
    ]

    # Where Find My Mac's switches live. macOS writes them to the system-wide
    # preferences file (root-owned, world-readable); older releases also kept a
    # copy in the user's com.apple.FindMyMac domain. On macOS 26 the user
    # domain does not exist at all, so reading only that one turned a Mac with
    # Find My on into a "Find My Mac is turned off" finding.
    _FMM_SOURCES = (
        "/Library/Preferences/com.apple.FindMyMac.plist",
        "com.apple.FindMyMac",
    )

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Find My Mac status
        find_my_mac_enabled = self._check_find_my_mac_enabled()

        # Check iCloud account status
        icloud_signed_in = self._check_icloud_signed_in()

        # Check Activation Lock status
        activation_lock_enabled = self._check_activation_lock()

        # Check Location Services status
        location_services_enabled = self._check_location_services_enabled()

        # Check Send Last Location status
        send_last_location = self._check_send_last_location()

        # Each read is True / False / None. None means the setting couldn't be
        # read (missing key, or a root-only file): report "couldn't check",
        # never "off".
        if find_my_mac_enabled is None and activation_lock_enabled is True:
            # Activation Lock is only ever on while Find My Mac is on.
            find_my_mac_enabled = True

        if find_my_mac_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether Find My Mac is on",
                    description=(
                        "Reclaim City couldn't read the Find My Mac setting on this "
                        "Mac, so it doesn't know whether it is on or off. This is not "
                        "a sign that anything is wrong.\n\n"
                        "To see for yourself: open System Settings, click your name at "
                        "the top, choose iCloud, and look at Find My Mac."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.find_my_mac_unknown",
                    data={"find_my_mac_enabled": None},
                )
            )

        # Flag CRITICAL if Find My Mac is disabled
        if find_my_mac_enabled is False:
            findings.append(
                Finding(
                    title="Find My Mac is turned off",
                    description=(
                        "Find My Mac is currently off. This means that if your Mac is "
                        "ever lost or stolen, you won't be able to see where it is, lock "
                        "it, or erase your data from a distance. This is a key safety "
                        "feature for recovering a missing device.\n\n"
                        "If someone else knows your Apple Account password, they will be "
                        "able to see where this Mac is too. If that worries you, change "
                        "the password first.\n\n"
                        "What to do: Open System Settings, click your name at the top, "
                        "choose iCloud, and turn on Find My Mac."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.find_my_mac_check.find_my_mac_disabled",
                    data={"find_my_mac_enabled": find_my_mac_enabled},
                )
            )

        if location_services_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether Location Services are on",
                    description=(
                        "macOS keeps the Location Services setting in a file that only "
                        "the system can read, so Reclaim City couldn't tell whether it "
                        "is on. Find My Mac needs it to show where this Mac is. This is "
                        "not a sign that anything is wrong.\n\n"
                        "To see for yourself: open System Settings > Privacy & Security "
                        "> Location Services."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.location_services_unknown",
                    data={"location_services_enabled": None},
                )
            )

        # Flag WARNING if Location Services are disabled
        if location_services_enabled is False:
            findings.append(
                Finding(
                    title="Location Services are turned off",
                    description=(
                        "Location Services are off, which stops Find My Mac from working. "
                        "Find My Mac needs to know your Mac's location to help you find "
                        "it if it goes missing. Turning this on allows the feature to "
                        "work as intended.\n\n"
                        "What to do: Go to System Settings > Privacy & Security > Location "
                        "Services and turn it on. Make sure Find My Mac is also checked "
                        "in the list below."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.find_my_mac_check.location_services_disabled",
                    data={"location_services_enabled": location_services_enabled},
                )
            )

        if send_last_location is None and find_my_mac_enabled is not False:
            findings.append(
                Finding(
                    title="Couldn't check Send Last Location",
                    description=(
                        "Reclaim City couldn't read the Send Last Location setting on "
                        "this Mac, so it doesn't know whether it is on or off. Newer "
                        "versions of macOS don't keep this setting where it can be read. "
                        "This is not a sign that anything is wrong."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.send_last_location_unknown",
                    data={"send_last_location": None},
                )
            )
        elif send_last_location is False:
            findings.append(
                Finding(
                    title="Send Last Location is turned off",
                    description=(
                        "Your Mac is not set to share its location when the battery runs "
                        "out. If your Mac is lost and the battery dies, this feature helps "
                        "you find it by sending its last known spot. Turning it on improves "
                        "your chances of getting the device back.\n\n"
                        "What to do: Open System Settings, click your name at the top, "
                        "then select 'iCloud'. Turn on 'Send Last Location'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.find_my_mac_check.send_last_location_disabled",
                    data={"send_last_location": send_last_location},
                )
            )

        if activation_lock_enabled is None:
            findings.append(
                Finding(
                    title="Activation Lock status is unknown",
                    description=(
                        "Could not verify Activation Lock status. This feature helps "
                        "prevent unauthorized access if Find My is enabled."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.activation_lock_unknown",
                    data={"activation_lock_enabled": None},
                )
            )

        # Flag WARNING if iCloud is not signed in
        if not icloud_signed_in:
            findings.append(
                Finding(
                    title="You are not signed in to iCloud",
                    description=(
                        "Find My Mac requires an active iCloud account to work, but you "
                        "are not currently signed in. Without a sign-in, the feature cannot "
                        "connect to your Apple ID to help locate the device.\n\n"
                        "What to do: Open System Settings and click 'Sign in' at the top "
                        "of the sidebar."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.find_my_mac_check.icloud_not_signed_in",
                    data={"icloud_signed_in": icloud_signed_in},
                )
            )

        # Flag INFO reporting Find My Mac and Activation Lock status
        if (
            find_my_mac_enabled is True
            and location_services_enabled is not False
            and send_last_location is not False
            and icloud_signed_in
        ):
            activation_status = {True: "on", False: "off"}.get(
                activation_lock_enabled, "unknown"
            )
            last_location_status = (
                "Send Last Location is on"
                if send_last_location
                else "Send Last Location couldn't be checked"
            )
            location_status = (
                "Location Services are on"
                if location_services_enabled
                else "Location Services couldn't be checked"
            )
            findings.append(
                Finding(
                    title="Find My Mac is properly configured",
                    description=(
                        f"Find My Mac is on and you're signed in to iCloud. "
                        f"{location_status}. "
                        f"{last_location_status}. "
                        f"Activation Lock is {activation_status}. "
                        "Your device can be located and remotely managed if lost or stolen."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.configured_ok",
                    data={
                        "find_my_mac_enabled": find_my_mac_enabled,
                        "location_services_enabled": location_services_enabled,
                        "send_last_location": send_last_location,
                        "icloud_signed_in": icloud_signed_in,
                        "activation_lock_enabled": activation_lock_enabled,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.code == "security.find_my_mac_check.find_my_mac_disabled":
                actions.append(
                    Action(
                        title="Enable Find My Mac",
                        description=(
                            "To enable Find My Mac:\n"
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Make sure you're signed in with your Apple ID\n"
                            "3. Toggle 'Find My Mac' ON\n"
                            "This requires an active iCloud account and Location Services to be enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac_check.send_last_location_disabled":
                actions.append(
                    Action(
                        title="Enable Send Last Location",
                        description=(
                            "Send Last Location must be enabled in Find My settings. "
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Click 'Find My'\n"
                            "3. Enable 'Send Last Location'\n"
                            "This ensures the device's final location is sent when battery is low."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac_check.location_services_disabled":
                actions.append(
                    Action(
                        title="Enable Location Services",
                        description=(
                            "To enable Location Services:\n"
                            "1. Open System Settings > Privacy & Security > Location Services\n"
                            "2. Toggle 'Location Services' ON\n"
                            "3. Ensure Find My Mac has location access enabled"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac_check.icloud_not_signed_in":
                actions.append(
                    Action(
                        title="Sign in to iCloud",
                        description=(
                            "To sign in to iCloud:\n"
                            "1. Open System Settings > [Your Name]\n"
                            "2. If not signed in, click 'Sign in with Apple ID'\n"
                            "3. Enter your Apple ID and password\n"
                            "4. Navigate to iCloud and enable Find My Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    @staticmethod
    def _parse_bool_default(result) -> bool | None:
        """`defaults read` result -> True/False, or None if missing/unreadable."""
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        if value == "1":
            return True
        if value == "0":
            return False
        return None

    def _read_bool_default(self, key: str) -> bool | None:
        """First True/False answer for ``key`` across ``_FMM_SOURCES``."""
        for domain in self._FMM_SOURCES:
            try:
                result = subprocess.run(
                    ["defaults", "read", domain, key],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            value = self._parse_bool_default(result)
            if value is not None:
                return value
        return None

    def _check_find_my_mac_enabled(self) -> bool | None:
        """Find My Mac switch: True, False, or None when it can't be read."""
        return self._read_bool_default("FMMEnabled")

    def _check_send_last_location(self) -> bool | None:
        """Send Last Location switch: True, False, or None when it can't be read."""
        return self._read_bool_default("SendLastLocation")

    def _check_icloud_signed_in(self) -> bool:
        """Check if iCloud account is signed in via defaults read."""
        try:
            home = str(Path.home())
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    f"{home}/Library/Preferences/MobileMeAccounts.plist",
                ],
                capture_output=True,
                text=True,
            )
            # If the file exists and has content, iCloud is likely signed in
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except Exception:
            return False

    def _check_activation_lock(self) -> bool | None:
        """Activation Lock from System Information's hardware overview.

        Apple silicon and T2 Macs print "Activation Lock Status: Enabled" (or
        Disabled). None when the line is missing.
        """
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return parse_activation_lock(result.stdout or "")

    def _check_location_services_enabled(self) -> bool | None:
        """Location Services switch, or None when it can't be read.

        The locationd preferences live under /var/db/locationd, which is
        readable only by the _locationd user, so without root this read fails
        and the answer is "couldn't check", not "off".
        """
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd",
                    "LocationServicesEnabled",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return self._parse_bool_default(result)


_ACTIVATION_LOCK_RE = re.compile(
    r"^\s*Activation Lock(?: Status)?:\s*(Enabled|Disabled)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def parse_activation_lock(system_profiler_output: str) -> bool | None:
    """Read Activation Lock from `system_profiler SPHardwareDataType` output."""
    match = _ACTIVATION_LOCK_RE.search(system_profiler_output)
    if not match:
        return None
    return match.group(1).lower() == "enabled"
