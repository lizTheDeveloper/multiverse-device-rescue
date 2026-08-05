"""Check what two-factor authentication capability exists on this device.

The roadmap named ``twofa_audit`` for the digital security reset and it was
never built. This is the real thing, with one deliberate limitation stated up
front: **a local tool cannot tell you whether 2FA is enabled on your accounts.**
That state lives at Google, at your bank, at your email provider. Finding out
requires logging in, and this tool will never ask for a credential.

So this module answers the question it actually can answer — "is this device
equipped to do 2FA, and does it show any local sign of platform 2FA?" — and says
plainly that account-level status was not checked. An unverified security
verdict presented as fact is worse than an admitted gap, especially for someone
working through a compromise who needs to know what has genuinely been
confirmed.

Concretely it reports:

- Authenticator apps installed on this machine.
- Platform 2FA signals that *are* locally observable: on macOS, whether the
  signed-in Apple ID advertises two-factor in its account preferences; on
  Windows, whether Windows Hello / a PIN is configured for the local account.
- A WARNING when neither an authenticator app nor any platform signal exists,
  because that combination means there is probably no second factor anywhere.
"""

import plistlib
from pathlib import Path

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
from rescue.command import run
from rescue.fsbounds import is_dir_nofollow

_COMMAND_TIMEOUT = 20

# Applications that generate or hold TOTP codes / manage hardware keys.
# More specific names first: matching is by prefix and first match wins.
_AUTHENTICATORS = [
    {"name": "1Password", "app": ["1Password"], "windows": ["1Password"]},
    {"name": "Microsoft Authenticator", "app": ["Microsoft Authenticator"], "windows": ["Microsoft Authenticator"]},
    {"name": "Authy", "app": ["Authy"], "windows": ["Authy"]},
    {"name": "Bitwarden", "app": ["Bitwarden"], "windows": ["Bitwarden"]},
    {"name": "Ente Auth", "app": ["Ente Auth", "Auth"], "windows": ["Ente Auth"]},
    {"name": "Raivo OTP", "app": ["Raivo"], "windows": []},
    {"name": "Step Two", "app": ["Step Two"], "windows": []},
    {"name": "KeePassXC", "app": ["KeePassXC"], "windows": ["KeePassXC"]},
    {"name": "YubiKey Manager", "app": ["YubiKey Manager", "ykman"], "windows": ["YubiKey Manager"]},
    {"name": "OTP Auth", "app": ["OTP Auth"], "windows": []},
]

_DARWIN_APP_DIRS = ["/Applications", "~/Applications"]

_WIN_UNINSTALL_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
]

_ACCOUNT_SCOPE_CAVEAT = (
    "This check looked only at this device. Whether two-factor authentication is "
    "actually switched on for your email, bank, or other accounts is stored by "
    "those providers, and confirming it requires signing in — which this tool "
    "will never do and never asks you to do here. Treat the account-level status "
    "as NOT CHECKED."
)


class Module(ModuleBase):
    name = "twofa_audit"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 79
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.twofa_audit.no_second_factor_capability",
        "security.twofa_audit.platform_2fa_unknown",
        "security.twofa_audit.inventory",
    ]

    # Read roots, overridable so tests never depend on the host machine.
    app_dirs: list[str] | None = None
    mobileme_plist_path: Path | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform not in (Platform.DARWIN, Platform.WIN32):
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "Two-factor capability detection is implemented for macOS and "
                    f"Windows; this host reports {profile.platform.value}."
                ),
            )

        findings: list[Finding] = []

        if profile.platform == Platform.DARWIN:
            authenticators = self._find_darwin_authenticators()
            platform_2fa, platform_detail = self._darwin_platform_2fa()
        else:
            authenticators = self._find_windows_authenticators()
            platform_2fa, platform_detail = self._windows_platform_2fa()

        if not authenticators and platform_2fa is not True:
            findings.append(
                Finding(
                    title="No second-factor capability found on this device",
                    description=(
                        "No authenticator app is installed and no platform two-factor "
                        "signal was found on this machine.\n\n"
                        "That does not prove your accounts are unprotected — you may use "
                        "an authenticator on your phone, or a hardware key. But if you "
                        "do not, a stolen password is enough to take over an account, and "
                        "that is the single most common way accounts are lost.\n\n"
                        + _ACCOUNT_SCOPE_CAVEAT
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.twofa_audit.no_second_factor_capability",
                    data={
                        "check": "no_second_factor_capability",
                        "authenticators": authenticators,
                        "platform_2fa": platform_2fa,
                    },
                )
            )

        if platform_2fa is None:
            findings.append(
                Finding(
                    title="Platform two-factor status could not be determined",
                    description=(
                        f"{platform_detail}\n\n"
                        "This is reported as unknown rather than guessed. A security "
                        "check that reports a state it did not actually observe is worse "
                        "than one that admits the gap."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.twofa_audit.platform_2fa_unknown",
                    data={
                        "check": "platform_2fa_unknown",
                        "detail": platform_detail,
                    },
                )
            )

        findings.append(
            Finding(
                title=(
                    f"Two-factor capability: {len(authenticators)} authenticator app(s)"
                ),
                description=(
                    "Authenticator apps found on this device: "
                    + (", ".join(authenticators) if authenticators else "none")
                    + f"\nPlatform two-factor signal: {platform_detail}"
                    + "\n\n"
                    + _ACCOUNT_SCOPE_CAVEAT
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.twofa_audit.inventory",
                data={
                    "check": "inventory",
                    "authenticators": authenticators,
                    "platform_2fa": platform_2fa,
                    "platform_detail": platform_detail,
                    "account_status_checked": False,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_second_factor_capability":
                actions.append(
                    Action(
                        title="Turn on two-factor authentication, highest-value accounts first",
                        description=(
                            "Order matters. Do them in this sequence, because each one "
                            "protects the next:\n\n"
                            "  1. Your email account. Everything else resets through it, "
                            "so it is the account an attacker wants most.\n"
                            "  2. Your password manager.\n"
                            "  3. Banking and payment accounts.\n"
                            "  4. Everything else that offers it.\n\n"
                            "Prefer, in order: a hardware security key (strongest, and "
                            "phishing-resistant), then an authenticator app, then SMS. "
                            "SMS is genuinely better than nothing, but it is defeated by "
                            "a SIM swap, so do not stop there for your email or bank.\n\n"
                            "Save each account's recovery codes when you set it up, on "
                            "paper or in your password manager — not in the authenticator "
                            "app itself, or losing the phone locks you out permanently.\n\n"
                            "Never type a one-time code or a recovery code into this tool. "
                            "Nothing legitimate will ever ask you to."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

            elif check == "platform_2fa_unknown":
                actions.append(
                    Action(
                        title="Confirm platform two-factor status yourself",
                        description=(
                            f"{finding.data.get('detail', '')}\n\n"
                            "Check it directly:\n"
                            "  macOS: System Settings > [your name] > Sign-In & Security > "
                            "Two-Factor Authentication\n"
                            "  Windows: Settings > Accounts > Sign-in options, and your "
                            "Microsoft account security page\n\n"
                            "This tool deliberately does not sign in to find out."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- detection ---------------------------------------------------------

    def _app_dirs(self) -> list[str]:
        return self.app_dirs if self.app_dirs is not None else _DARWIN_APP_DIRS

    def _find_darwin_authenticators(self) -> list[str]:
        found: set[str] = set()
        for raw_dir in self._app_dirs():
            directory = Path(raw_dir).expanduser()
            if not is_dir_nofollow(directory):
                continue
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.suffix != ".app":
                    continue
                bundle = entry.stem.lower()
                for app in _AUTHENTICATORS:
                    if any(bundle.startswith(a.lower()) for a in app["app"]):
                        found.add(app["name"])
                        break
        return sorted(found)

    def _find_windows_authenticators(self) -> list[str]:
        found: set[str] = set()
        for key in _WIN_UNINSTALL_KEYS:
            result = run(
                ["reg", "query", key, "/s", "/v", "DisplayName"],
                timeout=_COMMAND_TIMEOUT,
            )
            if not result.ok:
                continue
            for line in result.stdout.splitlines():
                if "DisplayName" not in line:
                    continue
                parts = line.split("REG_SZ")
                if len(parts) < 2:
                    continue
                display = parts[1].strip().lower()
                for app in _AUTHENTICATORS:
                    if any(display.startswith(w.lower()) for w in app["windows"]):
                        found.add(app["name"])
                        break
        return sorted(found)

    def _mobileme_plist(self) -> Path:
        if self.mobileme_plist_path is not None:
            return Path(self.mobileme_plist_path)
        return Path.home() / "Library/Preferences/MobileMeAccounts.plist"

    def _darwin_platform_2fa(self) -> tuple[bool | None, str]:
        """Read the signed-in Apple ID's advertised 2FA state, or admit we can't.

        MobileMeAccounts.plist records whether the signed-in account is a
        two-factor account. It is not authoritative for the Apple ID itself and
        it says nothing about any other account, so an absent or unreadable
        plist returns None ("unknown"), never False.
        """
        path = self._mobileme_plist()
        if not path.exists():
            return (
                None,
                "No signed-in Apple ID was found on this Mac, so there is no local "
                "record of its two-factor state.",
            )
        try:
            with open(path, "rb") as handle:
                plist = plistlib.load(handle)
        except (OSError, ValueError, plistlib.InvalidFileException):
            return (
                None,
                "The Apple ID account preferences could not be read, so the "
                "two-factor state was not determined.",
            )

        accounts = plist.get("Accounts") or []
        if not accounts:
            return (
                None,
                "No Apple ID account entry is present, so there is no local record "
                "of its two-factor state.",
            )

        for account in accounts:
            if not isinstance(account, dict):
                continue
            if account.get("SecureAccount") is True or account.get("isTwoFactor") is True:
                return (
                    True,
                    "The signed-in Apple ID is recorded locally as a two-factor account.",
                )

        return (
            None,
            "The signed-in Apple ID does not record a two-factor flag in local "
            "preferences. Apple does not reliably expose this offline, so this is "
            "reported as unknown rather than as disabled.",
        )

    def _windows_platform_2fa(self) -> tuple[bool | None, str]:
        """Detect a configured Windows Hello / PIN credential provider.

        Presence of an NGC container for the account means a Hello credential
        (PIN, face, or fingerprint) is enrolled. Absence of the key is not proof
        of absence of 2FA, so a failed query returns None.
        """
        result = run(
            [
                "reg",
                "query",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "/v",
                "EnableFirstLogonAnimation",
            ],
            timeout=_COMMAND_TIMEOUT,
        )
        ngc = run(
            ["reg", "query", r"HKLM\SOFTWARE\Policies\Microsoft\PassportForWork"],
            timeout=_COMMAND_TIMEOUT,
        )
        if ngc.ok and ngc.stdout.strip():
            return (
                True,
                "Windows Hello (Passport for Work) policy is present, indicating a "
                "Hello credential is configured on this device.",
            )
        if not result.ok and not ngc.ok:
            return (
                None,
                "The Windows sign-in configuration could not be queried, so the "
                "Windows Hello state was not determined.",
            )
        return (
            None,
            "No Windows Hello policy was found. Windows does not expose per-account "
            "Hello enrolment to a read-only query, so this is reported as unknown "
            "rather than as disabled.",
        )
