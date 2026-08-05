"""Check whether this machine has a password manager, and where passwords live.

The roadmap named ``password_manager_check`` as part of the digital security
reset and it was never built; the profile was corrected by deleting the
reference. This is the real thing.

What it does *not* do is as important as what it does. It never opens a vault,
never reads a credential store, and never asks for a master password. It looks
only at whether password-manager software is installed and whether browsers are
configured to hold passwords themselves. That is enough to answer the question
the security-reset guide actually asks — "is there somewhere safe to put new
passwords before you start changing them?" — without this tool ever touching a
secret.

Browser-stored passwords are reported as a weaker posture, not as a finding of
wrongdoing: they are encrypted at rest by the browser, but they are unlocked by
the OS login session, sync to wherever that account syncs, and cannot be shared
or audited. Presence is detected from the profile directory only; the credential
database is never opened.
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
from rescue.fsbounds import is_dir_nofollow

_COMMAND_TIMEOUT = 20

# Dedicated password managers, keyed by the name shown to the user.
# "app" entries are matched against .app bundle names in the macOS application
# directories; "windows" entries are matched against installed-program display
# names. Matching is case-insensitive and by prefix, so version suffixes in
# Windows display names ("1Password 8") still match.
_MANAGERS = [
    {"name": "1Password", "app": ["1Password", "1Password 7", "1Password 8"], "windows": ["1Password"]},
    {"name": "Bitwarden", "app": ["Bitwarden"], "windows": ["Bitwarden"]},
    {"name": "KeePassXC", "app": ["KeePassXC"], "windows": ["KeePassXC"]},
    {"name": "KeePass", "app": ["KeePass"], "windows": ["KeePass"]},
    {"name": "Dashlane", "app": ["Dashlane"], "windows": ["Dashlane"]},
    {"name": "Enpass", "app": ["Enpass"], "windows": ["Enpass"]},
    {"name": "NordPass", "app": ["NordPass"], "windows": ["NordPass"]},
    {"name": "Proton Pass", "app": ["Proton Pass"], "windows": ["Proton Pass"]},
    {"name": "LastPass", "app": ["LastPass"], "windows": ["LastPass"]},
    {"name": "Strongbox", "app": ["Strongbox"], "windows": []},
    {"name": "Secrets", "app": ["Secrets"], "windows": []},
]

_DARWIN_APP_DIRS = ["/Applications", "~/Applications"]

_WIN_UNINSTALL_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
]

# Browser profile locations. Presence of the profile directory is the signal;
# the credential databases inside are never opened.
_DARWIN_BROWSER_PROFILES = {
    "Google Chrome": "~/Library/Application Support/Google/Chrome",
    "Microsoft Edge": "~/Library/Application Support/Microsoft Edge",
    "Brave": "~/Library/Application Support/BraveSoftware/Brave-Browser",
    "Firefox": "~/Library/Application Support/Firefox/Profiles",
    "Safari": "~/Library/Safari",
}

_WIN_BROWSER_PROFILES = {
    "Google Chrome": "~/AppData/Local/Google/Chrome/User Data",
    "Microsoft Edge": "~/AppData/Local/Microsoft/Edge/User Data",
    "Brave": "~/AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "Firefox": "~/AppData/Roaming/Mozilla/Firefox/Profiles",
}

# Built-in OS credential stores. Real password managers for the platform's own
# ecosystem, but they do not cover a second OS or a shared household, so their
# presence does not by itself clear the "no manager" warning.
_BUILTIN = {
    Platform.DARWIN: "Apple Passwords / iCloud Keychain",
    Platform.WIN32: "Windows Credential Manager",
}


class Module(ModuleBase):
    name = "password_manager_check"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 78
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.password_manager_check.no_password_manager",
        "security.password_manager_check.browser_stored_passwords",
        "security.password_manager_check.inventory",
    ]

    # Roots this module reads, as attributes so tests can point them at a
    # fixture tree rather than the running user's real machine.
    app_dirs: list[str] | None = None
    browser_profiles: dict[str, str] | None = None

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform not in (Platform.DARWIN, Platform.WIN32):
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "Password-manager detection is implemented for macOS and "
                    f"Windows; this host reports {profile.platform.value}."
                ),
            )

        findings: list[Finding] = []

        if profile.platform == Platform.DARWIN:
            managers = self._find_darwin_managers()
        else:
            managers = self._find_windows_managers()

        browsers = self._find_browser_profiles(profile)
        builtin = _BUILTIN.get(profile.platform)

        if not managers:
            findings.append(
                Finding(
                    title="No dedicated password manager found",
                    description=(
                        "No dedicated password manager is installed on this machine. "
                        f"{builtin} is available on this platform and is genuinely "
                        "better than reusing passwords, but it does not follow you to "
                        "another operating system and cannot be shared or audited.\n\n"
                        "This matters most right now if you are working through a "
                        "security reset: you need somewhere to put new, unique "
                        "passwords before you start changing them, or you will end up "
                        "reusing one again."
                        + (
                            "\n\nBrowsers holding passwords on this machine: "
                            + ", ".join(browsers)
                            if browsers
                            else ""
                        )
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.password_manager_check.no_password_manager",
                    data={
                        "check": "no_password_manager",
                        "browsers_with_profiles": browsers,
                        "platform_builtin": builtin,
                    },
                )
            )

        if browsers and not managers:
            findings.append(
                Finding(
                    title=f"Passwords may be stored in {len(browsers)} browser(s)",
                    description=(
                        "These browsers keep their own password stores and no dedicated "
                        "manager was found alongside them: "
                        + ", ".join(browsers)
                        + ".\n\n"
                        "Browser-stored passwords are encrypted on disk, but they unlock "
                        "with your operating-system login, so anything running as you can "
                        "read them, and they sync wherever that browser account syncs. "
                        "This module only looked at whether the browser profile exists — "
                        "it did not open any password database."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.password_manager_check.browser_stored_passwords",
                    data={
                        "check": "browser_stored_passwords",
                        "browsers": browsers,
                    },
                )
            )

        findings.append(
            Finding(
                title=(
                    f"Password storage inventory: {len(managers)} manager(s), "
                    f"{len(browsers)} browser profile(s)"
                ),
                description=(
                    "Password managers found: "
                    + (", ".join(managers) if managers else "none")
                    + "\nBrowser profiles present: "
                    + (", ".join(browsers) if browsers else "none")
                    + f"\nPlatform credential store: {builtin}"
                    + "\n\nThis is an inventory of installed software and profile "
                    "directories. No vault, keychain, or password database was opened."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.password_manager_check.inventory",
                data={
                    "check": "inventory",
                    "managers": managers,
                    "browsers": browsers,
                    "platform_builtin": builtin,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_password_manager":
                actions.append(
                    Action(
                        title="Set up a password manager",
                        description=(
                            "Pick one and put it in place before changing any passwords, "
                            "so each new password can be unique and you do not have to "
                            "remember them.\n\n"
                            "  1. Choose a manager. Bitwarden and KeePassXC are free and "
                            "open source; 1Password and Proton Pass are paid. Any of them "
                            "beats reuse.\n"
                            "  2. Set a long passphrase for it — several unrelated words, "
                            "not a short complex string. This is the one you memorise.\n"
                            "  3. Turn on two-factor authentication for the manager itself.\n"
                            "  4. Write the recovery kit or emergency code on paper and "
                            "store it somewhere physically safe. If you lose it, nobody "
                            "can recover the vault for you — that is the point.\n"
                            "  5. Add accounts as you change their passwords, starting "
                            "with the email address the other accounts reset through.\n\n"
                            "Never type your master password into this tool, or into "
                            "anything that asks for it outside the manager itself."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check},
                    )
                )

            elif check == "browser_stored_passwords":
                browsers = finding.data.get("browsers", [])
                actions.append(
                    Action(
                        title="Move passwords out of browser storage",
                        description=(
                            "Browsers holding passwords here: "
                            + ", ".join(browsers)
                            + "\n\n"
                            "  1. Set up a password manager first (see the other action).\n"
                            "  2. Export from the browser's password settings, import into "
                            "the manager, then delete the export file — it is plain text, "
                            "and it is the most dangerous file on your disk while it exists.\n"
                            "  3. Turn off the browser's offer to save passwords.\n"
                            "  4. Clear the browser's saved passwords once you have "
                            "confirmed they are in the manager.\n\n"
                            "If you are doing this because of a compromise, change the "
                            "passwords as you move them rather than importing the old ones."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"check": check, "browsers": browsers},
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- detection ---------------------------------------------------------

    def _app_dirs(self) -> list[str]:
        return self.app_dirs if self.app_dirs is not None else _DARWIN_APP_DIRS

    def _find_darwin_managers(self) -> list[str]:
        """Match .app bundle names in the application directories.

        Only the top level of each directory is listed: application bundles live
        there, and descending into them would mean walking the whole of
        /Applications for no gain.
        """
        installed: set[str] = set()
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
                for manager in _MANAGERS:
                    if any(bundle.startswith(a.lower()) for a in manager["app"]):
                        installed.add(manager["name"])
                        # First match wins. _MANAGERS lists the more specific
                        # name first (KeePassXC before KeePass) so a prefix match
                        # does not report both for a single application.
                        break
        return sorted(installed)

    def _find_windows_managers(self) -> list[str]:
        """Match installed-program display names in the uninstall registry keys."""
        installed: set[str] = set()
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
                # REG_SZ values are tab/space separated: name, type, then value.
                parts = line.split("REG_SZ")
                if len(parts) < 2:
                    continue
                display = parts[1].strip().lower()
                for manager in _MANAGERS:
                    if any(display.startswith(w.lower()) for w in manager["windows"]):
                        installed.add(manager["name"])
                        break
        return sorted(installed)

    def _find_browser_profiles(self, profile: SystemProfile) -> list[str]:
        if self.browser_profiles is not None:
            table = self.browser_profiles
        elif profile.platform == Platform.DARWIN:
            table = _DARWIN_BROWSER_PROFILES
        else:
            table = _WIN_BROWSER_PROFILES

        present = []
        for browser, raw_path in table.items():
            if is_dir_nofollow(Path(raw_path).expanduser()):
                present.append(browser)
        return sorted(present)
