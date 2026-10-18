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
    name = "find_my_mac"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "2s"

    emits_codes = [
        "security.find_my_mac.find_my_mac_disabled",
        "security.find_my_mac.send_last_location_disabled",
        "security.find_my_mac.activation_lock_unknown",
        "security.find_my_mac.configured_ok",
        "security.find_my_mac.find_my_mac_unknown",
        "security.find_my_mac.send_last_location_unknown",
    ]

    # Find My Mac's on/off switch. macOS writes it to the system-wide
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

        # Each read is True (on), False (off) or None (couldn't tell). A missing
        # or unreadable setting is "couldn't check", never "off".
        activation_lock = self._check_activation_lock()
        fmm_enabled = self._check_find_my_mac_enabled()
        if fmm_enabled is None and activation_lock is True:
            # Activation Lock is only ever on while Find My Mac is on.
            fmm_enabled = True
        if fmm_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether Find My Mac is on",
                    description=(
                        "Device Rescue couldn't read the Find My Mac setting on this "
                        "Mac, so it doesn't know whether it is on or off. This is not "
                        "a sign that anything is wrong.\n\n"
                        "To see for yourself: open System Settings, click your name at "
                        "the top, then select 'iCloud' and look at 'Find My Mac'."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac.find_my_mac_unknown",
                    data={"find_my_mac_enabled": None},
                )
            )
        elif fmm_enabled is False:
            findings.append(
                Finding(
                    title="Find My Mac is turned off",
                    description=(
                        "Your Mac's 'Find My' feature is currently off. This is a safety "
                        "tool that lets you locate, lock, or erase your Mac if it is lost "
                        "or stolen. Because it is off, you cannot use these remote controls "
                        "right now.\n\n"
                        "If someone else knows your Apple Account password, they will be "
                        "able to see where this Mac is too. If that worries you, change "
                        "the password first.\n\n"
                        "What to do: Open System Settings, click your name at the top, "
                        "then select 'iCloud'. Turn on 'Find My Mac' and 'Send Last Location'."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.find_my_mac.find_my_mac_disabled",
                    data={"find_my_mac_enabled": fmm_enabled},
                )
            )

        # Check if Send Last Location is enabled
        send_last_location = self._check_send_last_location()
        if send_last_location is None and fmm_enabled is not False:
            findings.append(
                Finding(
                    title="Couldn't check Send Last Location",
                    description=(
                        "Device Rescue couldn't read the Send Last Location setting on "
                        "this Mac, so it doesn't know whether it is on or off. Newer "
                        "versions of macOS don't keep this setting where it can be read. "
                        "This is not a sign that anything is wrong."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac.send_last_location_unknown",
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
                    code="security.find_my_mac.send_last_location_disabled",
                    data={"send_last_location": send_last_location},
                )
            )

        if activation_lock is None:
            # Could not determine; provide INFO
            findings.append(
                Finding(
                    title="Activation Lock status is unknown",
                    description=(
                        "Could not verify Activation Lock status. This feature helps "
                        "prevent unauthorized access if Find My is enabled."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac.activation_lock_unknown",
                    data={"activation_lock": activation_lock},
                )
            )
        if fmm_enabled is True and send_last_location is not False:
            # All good
            findings.append(
                Finding(
                    title="Find My Mac is properly configured",
                    description=(
                        "Find My Mac is on"
                        + (" and Send Last Location is on. " if send_last_location else ". ")
                        + "Your device can be located and remotely managed if lost or stolen."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac.configured_ok",
                    data={
                        "find_my_mac_enabled": fmm_enabled,
                        "send_last_location": send_last_location,
                        "activation_lock": activation_lock,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.code == "security.find_my_mac.find_my_mac_disabled":
                actions.append(
                    Action(
                        title="Enable Find My Mac",
                        description=(
                            "Find My Mac must be enabled in System Settings. "
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Make sure you're signed in with your Apple ID\n"
                            "3. Toggle 'Find My Mac' ON\n"
                            "This requires an active iCloud account."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac.send_last_location_disabled":
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

        return FixResult(module_name=self.name, actions=actions)

    @staticmethod
    def _parse_bool_default(result) -> bool | None:
        """Turn a `defaults read <domain> <key>` result into True/False/None.

        A non-zero exit means the domain or key is missing (or unreadable):
        that is "couldn't tell", not "off".
        """
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        if value == "1":
            return True
        if value == "0":
            return False
        return None

    def _read_bool_default(self, key: str) -> bool | None:
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

    def _check_activation_lock(self) -> bool | None:
        """Activation Lock, from System Information's hardware overview.

        Apple silicon and T2 Macs print "Activation Lock Status: Enabled" or
        "Disabled". (The fmm-mobileme-token nvram variable this used to look
        for is hidden from `nvram -p` on Apple silicon.) None when the line is
        missing, e.g. on older Intel Macs without Activation Lock.
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
