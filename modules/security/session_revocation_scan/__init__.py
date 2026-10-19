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

import base64
import hashlib
import unicodedata
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

# Key types a line in authorized_keys can start its key with (after any options).
_KEY_TYPES = frozenset({
    "ssh-ed25519", "ssh-rsa", "ssh-dss",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
})


def _parse_key_line(line: str) -> dict | None:
    """One saved key, as fingerprints: the SHA-256 of the decoded key (what
    `ssh-keygen -l` fingerprints) and of the whole line (so a change to its
    options or comment shows), its type, its comment, and whether it has options. Never the key itself.
    None if the line isn't a key this can read."""
    # sshd separates fields by space or tab only; any other whitespace (a
    # vertical tab, a form feed...) is read differently by str.split().
    if any(ch.isspace() and ch not in " \t" for ch in line):
        return None
    options, rest = _split_options(line)
    if rest is None:
        return None
    # A backslash outside quotes is something sshd might read differently from us.
    if _odd_options(options):
        return None
    # A key-type word hidden in the options (say inside command="...") or
    # repeated later could make us fingerprint a different key than sshd uses.
    if any(t in options for t in _KEY_TYPES):
        return None
    tokens = rest.split()
    if len(tokens) < 2 or tokens[0] not in _KEY_TYPES:
        return None
    if any(t in _KEY_TYPES for t in tokens[2:]):
        return None
    try:
        blob = base64.b64decode(tokens[1], validate=True)
    except ValueError:
        return None
    if not blob:
        return None
    comment = " ".join(tokens[2:])
    comment = "".join(ch for ch in comment if unicodedata.category(ch) not in ("Cc", "Cf"))[:128]
    return {
        "type": tokens[0],
        "sha256": hashlib.sha256(blob).hexdigest(),
        "line_sha256": hashlib.sha256(line.encode("utf-8", "replace")).hexdigest(),
        "comment": comment,
        # Whether the line has options (cert-authority, command=, restrict...).
        # Only that it has some: an option's text can carry a command or a secret.
        "options": bool(options),
    }


def _odd_options(options: str) -> bool:
    in_quote = False
    i = 0
    while i < len(options):
        ch = options[i]
        if ch == "\\":
            if not in_quote:
                return True
            if i + 1 < len(options) and options[i + 1] == '"':
                i += 2
                continue
        elif ch == '"':
            in_quote = not in_quote
        i += 1
    return False


def _split_options(line: str) -> tuple[str, str | None]:
    """(options, rest) the way sshd reads a line: with no options the line
    starts with the key type; otherwise the options run to the first
    whitespace outside double quotes (a backslash escapes a quote inside
    them). rest is None if a quote never closes."""
    line = line.strip()
    first = line.split(None, 1)[0] if line else ""
    if first in _KEY_TYPES:
        return "", line
    in_quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_quote and i + 1 < len(line) and line[i + 1] == '"':
            i += 2
            continue
        if ch == '"':
            in_quote = not in_quote
        elif ch.isspace() and not in_quote:
            return line[:i], line[i:].strip()
        i += 1
    return line, None

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

_CMDKEY_PREFIXES = ("LegacyGeneric:target=", "Domain:target=", "WindowsLive:target=")


def _plain_target(name: str) -> str:
    """Drop Credential Manager's type prefix so the listed name is readable.

    Display only: ``data["accounts"]`` keeps the raw value.
    """
    for prefix in _CMDKEY_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


_REVOCATION_ORDER = (
    "Do this in order. Revoking sessions before changing the password just lets "
    "whoever has the password sign straight back in:\n\n"
    "  1. Change the password — on the email account first, then everything that "
    "resets through it.\n"
    "  2. THEN sign out of all other devices/sessions, from the account's own "
    "security page.\n"
    "  3. Review the apps and websites you have allowed to use the account "
    "(often listed as 'connected apps' or 'third-party access'; technically, OAuth "
    "grants) and remove any you do not recognise. On many providers these keep "
    "working after both a password change and a sign-out-everywhere.\n"
    "  4. Remove app passwords you made for older mail or calendar apps.\n"
    "  5. Remove any remote-login keys and remote-access tools you do not "
    "recognise."
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

        on_mac = profile.platform == Platform.DARWIN
        browser_total = sum(b["profiles"] for b in browsers)

        if browsers:
            detail = "\n".join(
                f"  {b['browser']}: {b['profiles']} profile(s)" for b in browsers
            )
            findings.append(
                Finding(
                    title=f"Your browsers have {browser_total} profile(s)",
                    description=(
                        "A browser profile is a separate set of bookmarks, history and "
                        "saved sign-ins inside one browser. Having several is normal. On "
                        "its own it does not mean anything is wrong.\n\n"
                        f"{detail}\n\n"
                        "Why it can matter: each profile stays signed in to the websites "
                        "you used in it, even after you change that website's password. "
                        "So if you are changing passwords because you think someone got "
                        "into an account, the new password alone may not sign them out.\n\n"
                        "We only counted the profile folders. We did not open them or read "
                        "any passwords or sign-in details.\n\n"
                        "What to do: Nothing, unless you are changing passwords after a "
                        "break-in. In that case, change the password first. Then, in that "
                        "website's security settings, choose 'Sign out of all devices', "
                        "and sign back in on this computer."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.session_revocation_scan.browser_sessions",
                    data={
                        "check": "browser_sessions",
                        "browsers": browsers,
                        "profile_count": browser_total,
                    },
                )
            )

        if accounts:
            listing = "\n".join(f"  {_plain_target(a)}" for a in accounts)
            if on_mac:
                title = (
                    "This Mac is signed in to an Apple Account"
                    if len(accounts) == 1
                    else f"This Mac is signed in to {len(accounts)} Apple Accounts"
                )
                description = (
                    "An Apple Account (it used to be called an Apple ID) is what this Mac "
                    "uses for iCloud. Through it, the Mac can share things like photos, "
                    "messages, notes, contacts, saved passwords and its location with "
                    "every other device signed in to the same account.\n\n"
                    f"{listing}\n\n"
                    "We only listed the names. We did not read any passwords.\n\n"
                    "Why it can matter: if this is your own account, this is normal. If "
                    "you don't recognize it, someone else's account could be receiving "
                    "what this Mac shares. And anyone who knows your Apple Account "
                    "password can see the same things from their own device.\n\n"
                    "If you think someone close to you set this up to monitor you, "
                    "changing it can alert them. Talk to an advocate first (US National "
                    "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                    "What to do: Check that the name above is yours. To see it on the "
                    "Mac, open System Settings and click your name at the top of the "
                    "sidebar (on older Macs: System Preferences > Apple ID). Scroll down "
                    "to see every device signed in with the same account. If one isn't "
                    "yours, or the account itself isn't yours, change your Apple Account "
                    "password and remove what you don't recognize."
                )
            else:
                title = f"Windows has {len(accounts)} saved sign-in(s)"
                description = (
                    "Windows keeps saved sign-ins so that apps and network drives (for "
                    "example OneDrive, Office, or a shared folder at work) can sign in "
                    "without asking you every time. These are the names they are saved "
                    "under:\n\n"
                    f"{listing}\n\n"
                    "We only listed the names. We did not read any passwords.\n\n"
                    "Why it can matter: most of these are put there by apps you use, and "
                    "are normal. One you don't recognize could mean someone set this "
                    "computer up to sign in to an account or computer of theirs, or "
                    "saved their own sign-in here.\n\n"
                    "If you think someone close to you set this up to monitor you, "
                    "removing it can alert them. Talk to an advocate first (US National "
                    "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                    "What to do: Search the Start menu for Credential Manager, open it, "
                    "and choose Windows Credentials. Remove any entry you don't recognize "
                    "or no longer use. Removing one only makes that app ask for the "
                    "password again; it does not delete the account."
                )
            findings.append(
                Finding(
                    title=title,
                    description=description,
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.session_revocation_scan.system_accounts",
                    data={"check": "system_accounts", "accounts": accounts},
                )
            )

        if ssh_keys > 0:
            findings.append(
                Finding(
                    title=f"{ssh_keys} saved key(s) could let another computer log in to this one",
                    description=(
                        f"This computer keeps a list of {ssh_keys} key(s). Each one lets "
                        "a computer that holds the matching key log in to this one over "
                        "the network, without a password. Changing your password does not "
                        "stop them. "
                        + (
                            "They only work while Remote Login is turned on.\n\n"
                            if on_mac
                            else "They only work if the OpenSSH Server feature is "
                            "installed and running.\n\n"
                        )
                        + "Most people never set this up. People who write software or "
                        "look after computers often do, for their own other machines.\n\n"
                        "We only counted the keys. We did not show or copy them.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: If you did not set these up yourself, ask a trusted "
                        "technical person to go through the list with you. "
                        + (
                            "To stop them working in the meantime, open System Settings > "
                            "General > Sharing and turn off Remote Login."
                            if on_mac
                            else "The list is the file .ssh\\authorized_keys in your "
                            "user folder."
                        )
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.session_revocation_scan.ssh_authorized_keys",
                    data=self._authorized_keys_data(ssh_keys),
                )
            )

        accounts_label = "Apple Accounts" if on_mac else "Saved Windows sign-ins"
        findings.append(
            Finding(
                title="What this check could and could not see",
                description=(
                    "On this computer we found:\n"
                    f"  Browser profiles: {browser_total}\n"
                    f"  {accounts_label}: {len(accounts)}\n"
                    f"  Keys that allow remote login: {ssh_keys}\n\n"
                    "This only covers what is stored on this computer. To see where your "
                    "accounts are signed in elsewhere (other phones and computers, and "
                    "apps you have allowed to use your account), go to each provider's "
                    "own security page, for example your email's. We can't see those "
                    "from here."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.session_revocation_scan.inventory",
                data={
                    "check": "inventory",
                    "browser_profile_count": browser_total,
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
                        "These stay signed in on the device by themselves:\n\n"
                        "  macOS: System Settings > [your name] (your Apple Account and "
                        "the devices signed in with it), and System Settings > Internet "
                        "Accounts (email, calendar and contacts accounts added to Mail, "
                        "Calendar and Contacts)\n"
                        "  Windows: Credential Manager > Windows Credentials (search the "
                        "Start menu for it), and Settings > Accounts > Email & accounts\n\n"
                        "Remove any you do not recognise or no longer use. Removing an "
                        "account here only signs this device out of it; it does not "
                        "delete the account."
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

    def _authorized_keys_data(self, count: int) -> dict:
        data = {"check": "ssh_authorized_keys", "key_count": count}
        digest = self._authorized_keys_sha256()
        if digest:
            data["list_sha256"] = digest
        # One entry per key, so the person can say which keys are theirs.
        # Only when every line reads as a key: otherwise the list is offered whole.
        entries = self._authorized_keys_entries()
        if entries is not None and len(entries) == count:
            data["keys"] = entries
        return data

    def _authorized_keys_entries(self) -> list[dict] | None:
        """Every saved key as fingerprints (see _parse_key_line), or None if
        the file can't be read, is too long, or has a line that isn't a key."""
        path = self._authorized_keys_path()
        if not is_file_nofollow(path):
            return None
        entries = []
        try:
            with open(path, "r", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= _MAX_AUTHORIZED_KEYS_LINES:
                        return None
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    entry = _parse_key_line(stripped)
                    if entry is None:
                        return None
                    entries.append(entry)
        except OSError:
            return None
        return entries or None

    def _authorized_keys_sha256(self) -> str | None:
        """A one-way fingerprint of the list of keys, so a key added or changed
        later can be told apart from the list the person said was theirs. The
        keys themselves are never returned or shown."""
        path = self._authorized_keys_path()
        if not is_file_nofollow(path):
            return None
        entries = []
        try:
            with open(path, "r", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= _MAX_AUTHORIZED_KEYS_LINES:
                        return None  # too long to pin: never markable
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        entries.append(stripped)
        except OSError:
            return None
        if not entries:
            return None
        blob = "\n".join(sorted(entries)).encode("utf-8", "replace")
        return hashlib.sha256(blob).hexdigest()

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
