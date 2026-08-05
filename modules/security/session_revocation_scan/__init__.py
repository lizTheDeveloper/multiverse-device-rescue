"""Inventory the sign-in surfaces that survive a password change.

The roadmap named ``session_revocation_scan`` for the digital security reset and
it was never built. This is the check someone runs after a compromise, when the
question is not "how did they get in" but "what is *still* logged in, and what
do I have to kick out".

That question matters because changing a password does not, on its own, end
existing sessions. A live browser cookie, an OAuth grant, an app-specific
password, or an authorised SSH key all keep working afterwards. People routinely
change their password, believe they are done, and stay compromised.

What this module reports is the *surface*: how many browser profiles hold their
own cookie stores, which system accounts are configured, what remote-access
grants exist. It never reads a cookie database, a keychain item, a token value,
or private key material. For SSH it reports the comment and fingerprint-bearing
line count needed to identify an entry, not the key itself.

This deliberately overlaps with ``remote_login_check`` and ``ssh_key_audit``:
those answer "is remote access enabled and are these keys sane". This one
answers "what must I revoke", and orders the guidance so the password change
happens *before* the sign-out, which is the part people get backwards.
"""

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
from rescue.fsbounds import is_dir_nofollow, is_file_nofollow

_COMMAND_TIMEOUT = 20
_MAX_AUTHORIZED_KEYS_LINES = 500

_DARWIN_BROWSER_PROFILE_ROOTS = {
    "Google Chrome": "~/Library/Application Support/Google/Chrome",
    "Microsoft Edge": "~/Library/Application Support/Microsoft Edge",
    "Brave": "~/Library/Application Support/BraveSoftware/Brave-Browser",
    "Firefox": "~/Library/Application Support/Firefox/Profiles",
    "Safari": "~/Library/Safari",
}

_WIN_BROWSER_PROFILE_ROOTS = {
    "Google Chrome": "~/AppData/Local/Google/Chrome/User Data",
    "Microsoft Edge": "~/AppData/Local/Microsoft/Edge/User Data",
    "Brave": "~/AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "Firefox": "~/AppData/Roaming/Mozilla/Firefox/Profiles",
}

_SSH_AUTHORIZED_KEYS = "~/.ssh/authorized_keys"

_REVOCATION_ORDER = (
    "Do this in order. Revoking sessions before changing the password just lets "
    "whoever has the password sign straight back in:\n\n"
    "  1. Change the password — on the email account first, then everything that "
    "resets through it.\n"
    "  2. THEN sign out of all other devices/sessions, from the account's own "
    "security page.\n"
    "  3. Review and revoke third-party app access (OAuth grants). These survive "
    "both a password change and a sign-out-everywhere on many providers.\n"
    "  4. Revoke app-specific passwords and long-lived API tokens.\n"
    "  5. Remove any SSH keys and remote-access grants you do not recognise."
)


class Module(ModuleBase):
    name = "session_revocation_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 81
    depends_on = []
    estimated_duration = "15s"

    emits_codes = [
        "security.session_revocation_scan.browser_sessions",
        "security.session_revocation_scan.system_accounts",
        "security.session_revocation_scan.ssh_authorized_keys",
        "security.session_revocation_scan.inventory",
    ]

    # Read roots, overridable so tests never touch the host machine.
    browser_profile_roots: dict[str, str] | None = None
    authorized_keys_path: Path | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform not in (Platform.DARWIN, Platform.WIN32):
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "Session-surface inventory is implemented for macOS and "
                    f"Windows; this host reports {profile.platform.value}."
                ),
            )

        findings: list[Finding] = []

        browsers = self._browser_sessions(profile)
        accounts = self._system_accounts(profile)
        ssh_keys = self._authorized_keys_count()

        if browsers:
            total = sum(b["profiles"] for b in browsers)
            detail = "\n".join(
                f"  {b['browser']}: {b['profiles']} profile(s)" for b in browsers
            )
            findings.append(
                Finding(
                    title=f"{total} browser profile(s) hold their own sign-in sessions",
                    description=(
                        "Each browser profile keeps its own cookies, so each one can stay "
                        "signed in to your accounts independently — and stays signed in "
                        "after you change the password, until you explicitly sign out "
                        "everywhere.\n\n"
                        f"{detail}\n\n"
                        "Only the profile directories were counted. No cookie database, "
                        "saved password, or session token was opened or read."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.session_revocation_scan.browser_sessions",
                    data={
                        "check": "browser_sessions",
                        "browsers": browsers,
                        "profile_count": total,
                    },
                )
            )

        if accounts:
            findings.append(
                Finding(
                    title=f"{len(accounts)} system account(s) signed in on this device",
                    description=(
                        "These accounts are configured on the device itself and keep "
                        "their own tokens, independent of any browser session:\n\n"
                        + "\n".join(f"  {a}" for a in accounts)
                        + "\n\nAccount names are listed to identify them. No token or "
                        "credential value was read."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.session_revocation_scan.system_accounts",
                    data={"check": "system_accounts", "accounts": accounts},
                )
            )

        if ssh_keys > 0:
            findings.append(
                Finding(
                    title=f"{ssh_keys} SSH key(s) authorised for remote login to this machine",
                    description=(
                        f"~/.ssh/authorized_keys grants {ssh_keys} key(s) the ability to "
                        "log in to this machine remotely. An authorised key is unaffected "
                        "by changing your account password — it is a separate credential, "
                        "and it is a common way access is retained after a compromise.\n\n"
                        "Only the number of authorised entries was counted. No key "
                        "material was read or reported."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.session_revocation_scan.ssh_authorized_keys",
                    data={"check": "ssh_authorized_keys", "key_count": ssh_keys},
                )
            )

        findings.append(
            Finding(
                title="Session revocation surface inventory",
                description=(
                    f"Browser profiles: {sum(b['profiles'] for b in browsers)}\n"
                    f"System accounts: {len(accounts)}\n"
                    f"Authorised SSH keys: {ssh_keys}\n\n"
                    "This is the local surface only. Sessions held by your accounts at "
                    "their providers — active logins, OAuth app grants, app-specific "
                    "passwords — are not visible from this device and must be reviewed "
                    "on each provider's own security page."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.session_revocation_scan.inventory",
                data={
                    "check": "inventory",
                    "browser_profile_count": sum(b["profiles"] for b in browsers),
                    "system_account_count": len(accounts),
                    "ssh_key_count": ssh_keys,
                    "provider_sessions_checked": False,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        checks = {f.data.get("check") for f in findings.findings}

        actions.append(
            Action(
                title="Revoke sessions in the right order",
                description=_REVOCATION_ORDER,
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                success=True,
                data={"check": "revocation_order"},
            )
        )

        if "browser_sessions" in checks:
            actions.append(
                Action(
                    title="Sign out of browser sessions",
                    description=(
                        "After the password change, for each account:\n\n"
                        "  Google: myaccount.google.com > Security > Your devices > "
                        "Sign out\n"
                        "  Microsoft: account.microsoft.com/devices\n"
                        "  Apple: appleid.apple.com > Devices\n"
                        "  Facebook/Instagram: Settings > Password and security > "
                        "Where you're logged in\n\n"
                        "Then clear cookies in each browser profile so any local session "
                        "is gone too. Signing out on the provider is the part that "
                        "matters; clearing cookies alone does not revoke anything "
                        "server-side."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"check": "browser_sessions"},
                )
            )

        if "system_accounts" in checks:
            actions.append(
                Action(
                    title="Review accounts configured on this device",
                    description=(
                        "These hold their own tokens on the device:\n\n"
                        "  macOS: System Settings > Internet Accounts, and "
                        "System Settings > [your name]\n"
                        "  Windows: Settings > Accounts > Email & accounts, and "
                        "Access work or school\n\n"
                        "Remove any you do not recognise or no longer use. Removing an "
                        "account here deletes the device's stored token for it; it does "
                        "not delete the account."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"check": "system_accounts"},
                )
            )

        if "ssh_authorized_keys" in checks:
            actions.append(
                Action(
                    title="Review authorised SSH keys",
                    description=(
                        "Open ~/.ssh/authorized_keys and check every entry. Each line is "
                        "a key that can log in to this machine without your password.\n\n"
                        "  1. Remove any line you cannot account for.\n"
                        "  2. Compare the comment at the end of each line against the "
                        "machines you actually use.\n"
                        "  3. If you are unsure, remove them all and re-add the keys you "
                        "need — you will find out immediately what broke, and an "
                        "attacker's key will not be among what you re-add.\n\n"
                        "Also check ~/.ssh/config and any running remote-access tools; a "
                        "key is not the only way back in."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"check": "ssh_authorized_keys"},
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    # -- detection ---------------------------------------------------------

    def _browser_sessions(self, profile: SystemProfile) -> list[dict]:
        """Count profile directories per browser. Cookie stores are never opened."""
        if self.browser_profile_roots is not None:
            table = self.browser_profile_roots
        elif profile.platform == Platform.DARWIN:
            table = _DARWIN_BROWSER_PROFILE_ROOTS
        else:
            table = _WIN_BROWSER_PROFILE_ROOTS

        found = []
        for browser, raw_root in table.items():
            root = Path(raw_root).expanduser()
            if not is_dir_nofollow(root):
                continue
            count = self._count_profiles(browser, root)
            if count:
                found.append({"browser": browser, "profiles": count})
        return sorted(found, key=lambda b: b["browser"])

    @staticmethod
    def _count_profiles(browser: str, root: Path) -> int:
        """Chromium keeps 'Default' and 'Profile N' dirs; others are one profile."""
        try:
            entries = list(root.iterdir())
        except OSError:
            return 0

        if browser == "Safari":
            return 1

        named = [
            e
            for e in entries
            if is_dir_nofollow(e)
            and (e.name == "Default" or e.name.startswith("Profile "))
        ]
        if named:
            return len(named)
        # Firefox profile dirs are "<salt>.<name>"; anything else with content
        # counts as a single profile.
        firefox_like = [e for e in entries if is_dir_nofollow(e) and "." in e.name]
        return len(firefox_like) if firefox_like else 1

    def _system_accounts(self, profile: SystemProfile) -> list[str]:
        """List configured account identifiers. No token or password is read."""
        if profile.platform == Platform.DARWIN:
            result = run(
                ["defaults", "read", "MobileMeAccounts", "Accounts"],
                timeout=_COMMAND_TIMEOUT,
            )
            if not result.ok:
                return []
            accounts = []
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("AccountID"):
                    parts = stripped.split("=", 1)
                    if len(parts) == 2:
                        accounts.append(parts[1].strip().strip(';" '))
            return sorted(set(a for a in accounts if a))

        result = run(
            ["cmdkey", "/list"],
            timeout=_COMMAND_TIMEOUT,
        )
        if not result.ok:
            return []
        targets = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("target:"):
                targets.append(stripped.split(":", 1)[1].strip())
        return sorted(set(t for t in targets if t))

    def _authorized_keys_path(self) -> Path:
        if self.authorized_keys_path is not None:
            return Path(self.authorized_keys_path)
        return Path(_SSH_AUTHORIZED_KEYS).expanduser()

    def _authorized_keys_count(self) -> int:
        """Count authorised entries without reading key material.

        Lines are counted, never returned. Reading is bounded so a pathological
        file cannot stall the scan.
        """
        path = self._authorized_keys_path()
        if not is_file_nofollow(path):
            return 0
        count = 0
        try:
            with open(path, "r", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= _MAX_AUTHORIZED_KEYS_LINES:
                        break
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        count += 1
        except OSError:
            return 0
        return count
