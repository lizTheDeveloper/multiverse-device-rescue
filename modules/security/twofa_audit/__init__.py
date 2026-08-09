"""Inventory the second factors that are reachable from this device.

Nobody can tell from a laptop which of your accounts have two-factor
authentication switched on — that lives on each provider's servers. What a
laptop *can* answer is the question people get wrong right after a compromise:
"if I turn on 2FA now, what would I be turning it on with, and does it survive
this device being untrustworthy?"

So this module inventories the factors it can see locally — authenticator
applications, attached security keys, and FIDO-backed SSH keys — and says
plainly what it cannot see. It reads no codes, no seeds, and no accounts.
"""

import subprocess
from pathlib import Path
from typing import Any

from rescue.models import (
    Action,
    ActionKind,
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

# Applications that can hold time-based one-time-password secrets. Matched
# case-insensitively as substrings of application and installed-software names.
AUTHENTICATOR_APPS = {
    "1password": "1Password",
    "authy": "Authy",
    "bitwarden": "Bitwarden",
    "2fas": "2FAS",
    "ente auth": "Ente Auth",
    "keepassxc": "KeePassXC",
    "microsoft authenticator": "Microsoft Authenticator",
    "otp auth": "OTP Auth",
    "raivo": "Raivo OTP",
    "step two": "Step Two",
    "yubico authenticator": "Yubico Authenticator",
}

# Vendor strings that appear in USB device names for FIDO2/U2F security keys.
SECURITY_KEY_VENDORS = {
    "yubikey": "YubiKey",
    "yubico": "YubiKey",
    "feitian": "Feitian",
    "nitrokey": "Nitrokey",
    "solokey": "SoloKey",
    "onlykey": "OnlyKey",
    "titan security key": "Google Titan",
    "verimark": "Kensington VeriMark",
    "trezor": "Trezor",
}

# Prefixes of the OpenSSH key types that require a hardware authenticator. The
# full names carry an "@openssh.com" suffix.
FIDO_SSH_KEY_PREFIXES = ("sk-ssh-ed25519", "sk-ecdsa-sha2-nistp256")

_USB_ENUMERATION_TIMEOUT = 30

_SCOPE_CAVEAT = (
    "This is an inventory of what is available on this device. It cannot tell "
    "you which accounts actually have two-factor authentication enabled — only "
    "each provider's own security page can."
)


class Module(ModuleBase):
    name = "twofa_audit"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "20s"

    def __init__(self) -> None:
        self._sensitivity = "normal"

    def configure(self, config: dict[str, Any]) -> None:
        """Accept ``sensitivity`` from a profile's ``module_config``.

        At ``elevated`` sensitivity the module assumes this device may itself be
        compromised, so a software authenticator sitting on it is not treated as
        an independent second factor.
        """
        sensitivity = config.get("sensitivity")
        if isinstance(sensitivity, str) and sensitivity in {"normal", "elevated"}:
            self._sensitivity = sensitivity

    def check(self, profile: SystemProfile) -> CheckResult:
        apps = self._detect_authenticator_apps(profile)
        keys = self._detect_security_keys(profile)
        fido_ssh = self._detect_fido_ssh_keys()

        findings: list[Finding] = []
        if apps or keys or fido_ssh:
            findings.append(self._inventory_finding(apps, keys, fido_ssh))
        else:
            findings.append(self._no_factors_finding())
        if apps and not keys and self._sensitivity == "elevated":
            findings.append(self._single_device_finding(apps))
        findings.append(self._recovery_codes_finding())
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only. Enrolling a factor happens on the provider's site."""
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "no_second_factors":
                actions.append(self._enrol_action())
            elif check == "second_factors_available":
                actions.append(self._turn_on_action(finding))
            elif check == "factors_on_one_device":
                actions.append(self._separate_factor_action())
            elif check == "recovery_codes":
                actions.append(self._recovery_codes_action())
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- detection ----------------

    def _detect_authenticator_apps(self, profile: SystemProfile) -> list[dict]:
        found: dict[str, dict] = {}
        names = [entry.name for root in self._application_roots(profile.platform)
                 for entry in _list_dir(root)]
        names.extend(profile.installed_software)
        for name in names:
            lowered = name.lower()
            for needle, product in AUTHENTICATOR_APPS.items():
                if needle in lowered and product not in found:
                    found[product] = {"product": product, "evidence": name}
        return sorted(found.values(), key=lambda record: record["product"])

    def _detect_security_keys(self, profile: SystemProfile) -> list[dict]:
        """Look for an attached FIDO2/U2F key in the USB device list."""
        listing = self._enumerate_usb_devices(profile.platform)
        if not listing:
            return []
        lowered = listing.lower()
        found: dict[str, dict] = {}
        for needle, product in SECURITY_KEY_VENDORS.items():
            if needle in lowered and product not in found:
                found[product] = {"product": product, "evidence": needle}
        return sorted(found.values(), key=lambda record: record["product"])

    def _enumerate_usb_devices(self, platform: Platform) -> str:
        """Return the raw USB device listing, or "" if it cannot be collected."""
        if platform == Platform.DARWIN:
            command = ["system_profiler", "SPUSBDataType"]
        elif platform == Platform.WIN32:
            command = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_PnPEntity | Select-Object -ExpandProperty Name",
            ]
        else:
            return ""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=_USB_ENUMERATION_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if result.returncode != 0:
            return ""
        return result.stdout or ""

    def _detect_fido_ssh_keys(self) -> list[dict]:
        """Find SSH public keys that require a hardware authenticator.

        Only ``.pub`` files are opened. These contain public key material by
        definition; no private key is read.
        """
        found = []
        for pub in sorted(_list_dir(self._ssh_directory())):
            if pub.suffix != ".pub":
                continue
            try:
                first_line = pub.read_text(errors="replace").strip().split("\n")[0]
            except OSError:
                continue
            key_type = first_line.split(" ")[0] if first_line else ""
            if key_type.startswith(FIDO_SSH_KEY_PREFIXES):
                found.append({"key_type": key_type, "path": _display_path(pub)})
        return found

    def _application_roots(self, platform: Platform) -> list[Path]:
        if platform == Platform.DARWIN:
            return [
                Path("/Applications"),
                Path("/System/Applications"),
                Path.home() / "Applications",
            ]
        if platform == Platform.WIN32:
            return [
                Path("C:/Program Files"),
                Path("C:/Program Files (x86)"),
                Path.home() / "AppData" / "Local" / "Programs",
            ]
        return []

    def _ssh_directory(self) -> Path:
        return Path.home() / ".ssh"

    # ---------------- findings ----------------

    def _inventory_finding(
        self, apps: list[dict], keys: list[dict], fido_ssh: list[dict]
    ) -> Finding:
        lines = []
        for record in keys:
            lines.append(
                f"  • {record['product']} security key (attached to this computer)"
            )
        for record in apps:
            lines.append(f"  • {record['product']} (authenticator app on this device)")
        for record in fido_ssh:
            lines.append(
                f"  • Hardware-backed SSH key at {record['path']} ({record['key_type']})"
            )
        total = len(apps) + len(keys) + len(fido_ssh)
        return Finding(
            title=f"{total} second factor(s) available on this device",
            description=(
                "These second factors are available here:\n"
                + "\n".join(lines)
                + "\n\n"
                + _SCOPE_CAVEAT
                + " Work through email, banking, and anything holding a payment card "
                "and confirm each one is using a factor from this list rather than "
                "a text message."
            ),
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "second_factors_available",
                "authenticator_apps": apps,
                "security_keys": keys,
                "fido_ssh_keys": fido_ssh,
                "count": total,
                "confidence": "high",
            },
        )

    def _no_factors_finding(self) -> Finding:
        return Finding(
            title="No authenticator app or security key found on this device",
            description=(
                "No authenticator application is installed here, no security key is "
                "attached, and no hardware-backed SSH key exists. That usually means "
                "second factors are either not in use or are arriving by text "
                "message.\n\n"
                "Text-message codes are better than nothing and much weaker than the "
                "alternatives: a phone number can be moved to someone else's SIM by "
                "convincing a mobile-network agent, and that attack is routine.\n\n"
                + _SCOPE_CAVEAT
                + " An authenticator app on your phone will not show up here."
            ),
            severity=Severity.WARNING,
            category=self.category,
            data={
                "check": "no_second_factors",
                "searched_apps": sorted(set(AUTHENTICATOR_APPS.values())),
                "searched_key_vendors": sorted(set(SECURITY_KEY_VENDORS.values())),
                "confidence": "medium",
            },
        )

    def _single_device_finding(self, apps: list[dict]) -> Finding:
        products = ", ".join(record["product"] for record in apps)
        return Finding(
            title="Every detected second factor lives on this one device",
            description=(
                f"The only second factors found are software authenticators ({products}) "
                "running on the device being examined. If this device is the one that "
                "was compromised, then the password and the second factor were within "
                "reach of the same intruder, and turning on 2FA here does not lock "
                "them out.\n\n"
                "Add a factor that is not this machine: a hardware security key, or an "
                "authenticator app on a separate phone. Do the enrolment from a device "
                "you trust."
            ),
            severity=Severity.WARNING,
            category=self.category,
            data={
                "check": "factors_on_one_device",
                "authenticator_apps": apps,
                "confidence": "medium",
            },
        )

    def _recovery_codes_finding(self) -> Finding:
        return Finding(
            title="Recovery codes cannot be checked from this device",
            description=(
                "Every provider issues backup or recovery codes when two-factor "
                "authentication is switched on, and those codes are not stored "
                "anywhere this toolkit can see. This finding is a reminder, not a "
                "detection.\n\n"
                "Losing the second factor without the codes means losing the account, "
                "which is a more common way to lose access than an attacker is."
            ),
            severity=Severity.INFO,
            category=self.category,
            data={"check": "recovery_codes", "confidence": "high"},
        )

    # ---------------- guidance ----------------

    def _enrol_action(self) -> Action:
        return Action(
            title="Set up a second factor for your most important accounts",
            description=(
                "Order matters — start with the account that can reset the others:\n"
                "1. Primary email.\n"
                "2. Password manager.\n"
                "3. Banking and anything holding a payment card.\n"
                "4. Phone and cloud accounts (Apple, Google, Microsoft).\n\n"
                "For each one, open the provider's security settings yourself — never "
                "through a link in a message — and choose, in order of preference:\n"
                "- a hardware security key, if the provider supports one;\n"
                "- a passkey;\n"
                "- an authenticator app;\n"
                "- text messages, only if nothing else is offered.\n\n"
                "Ask your mobile network to add a port-out PIN or account lock while "
                "any account still falls back to text messages."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _turn_on_action(self, finding: Finding) -> Action:
        keys = [record["product"] for record in finding.data.get("security_keys", [])]
        apps = [record["product"] for record in finding.data.get("authenticator_apps", [])]
        preferred = keys[0] if keys else (apps[0] if apps else "your authenticator")
        return Action(
            title=f"Use {preferred} on the accounts that matter most",
            description=(
                f"{preferred} is already available, so the work is enrolment rather "
                "than setup. Go through email, password manager, banking, and cloud "
                "accounts and confirm each is using it.\n\n"
                "While you are in each provider's security settings:\n"
                "- Remove second factors you no longer recognise, especially phone "
                "numbers and authenticator devices you did not add.\n"
                "- Turn off text-message fallback once a stronger factor works, "
                "because an attacker will use the weakest method you leave enabled.\n"
                "- Download the new recovery codes and keep them on paper."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _separate_factor_action(self) -> Action:
        return Action(
            title="Add a second factor that does not live on this device",
            description=(
                "A software authenticator on the same machine as the password is one "
                "device away from being no second factor at all.\n\n"
                "1. Get a hardware security key, or install an authenticator app on a "
                "phone you have not had trouble with.\n"
                "2. Enrol it from a device you trust, not from this one, if this one "
                "may be compromised.\n"
                "3. Enrol two keys where the provider allows it, and keep the spare "
                "somewhere else. One key plus recovery codes also works.\n"
                "4. Once the new factor is proven, remove the ones you no longer "
                "recognise."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _recovery_codes_action(self) -> Action:
        return Action(
            title="Store recovery codes where you can reach them without this device",
            description=(
                "For each account with two-factor authentication turned on:\n"
                "1. Generate a fresh set of recovery codes. If the old set was stored "
                "on a device that may have been compromised, the old set is burnt.\n"
                "2. Print them, or write them out, and keep the paper somewhere "
                "physically secure.\n"
                "3. Do not keep the only copy inside the account it unlocks, or in a "
                "screenshot in your photo library.\n"
                "4. A password manager is a reasonable second copy — as long as the "
                "manager itself is not the account those codes unlock."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )


# ---------------- helpers ----------------


def _list_dir(path: Path) -> list[Path]:
    """Non-recursive listing that treats an unreadable directory as empty."""
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _display_path(path: Path) -> str:
    """Render a path with the home directory replaced by ``~``."""
    try:
        return "~/" + str(path.relative_to(Path.home())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")
