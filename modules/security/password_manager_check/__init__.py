"""Report whether this device has a password manager, and where the browser
is keeping passwords instead.

After a compromise the single highest-value change someone can make is to stop
reusing passwords, and that only works if there is somewhere to keep unique
ones. This module answers two narrow, checkable questions:

1. Is a password manager installed on this device?
2. Is a browser storing passwords in its own database?

Both are answered from the presence of files and applications. The module never
opens a password database, never reads a credential, and never asks for a
master password — a browser's ``Login Data`` file is reported by path,
modification date, and size only. It also cannot see a manager used purely
through a website, so "not detected" means "not visible from here", and every
finding says so.
"""

from datetime import datetime
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

# Matched case-insensitively against application-bundle and installed-software
# names. Substrings, because installers append versions and vendor suffixes.
KNOWN_MANAGERS = {
    "1password": "1Password",
    "bitwarden": "Bitwarden",
    "dashlane": "Dashlane",
    "enpass": "Enpass",
    "keepassxc": "KeePassXC",
    "keepassium": "KeePassium",
    "keepass": "KeePass",
    "keeper password": "Keeper",
    "lastpass": "LastPass",
    "nordpass": "NordPass",
    "proton pass": "Proton Pass",
    "roboform": "RoboForm",
    "strongbox": "Strongbox",
    "passwords.app": "Apple Passwords",
}

# Browser-extension identifiers for the managers most people install as an
# extension only. Chromium keeps one directory per extension id.
KNOWN_MANAGER_EXTENSION_IDS = {
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa": "1Password",
    "nngceckbapebfimnlniiiahkandclblb": "Bitwarden",
    "fdjamakpfbbddfjaooikfcpapjohcfmg": "Dashlane",
    "hdokiejnpimakedhajhdlcegeplioahd": "LastPass",
    "bfogiafebfohielmmehodmfbbebbbpei": "Keeper",
    "fooolghllnmhmmndgjiamiiodkpenpbb": "NordPass",
    "ghmbeldphafepmbegfdlkpapadhbakde": "Proton Pass",
    "pnlccmojcmeohlpggmfnbbiapkmbliob": "RoboForm",
    "kmcfomidfpdkfieipokbalgegidffkal": "Enpass",
}

_DETECTION_CAVEAT = (
    "This check can only see software installed on this device. A password "
    "manager used entirely through a website, or one installed on a phone, "
    "will not appear here."
)


class Module(ModuleBase):
    name = "password_manager_check"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "5s"

    def __init__(self) -> None:
        self._sensitivity = "normal"

    def configure(self, config: dict[str, Any]) -> None:
        """Accept ``sensitivity`` from a profile's ``module_config``.

        At ``elevated`` sensitivity — the setting the post-compromise profile
        uses — a browser password database is a warning even when a real
        password manager is also installed, because the browser copy is the one
        an attacker with code execution can decrypt without a master password.
        """
        sensitivity = config.get("sensitivity")
        if isinstance(sensitivity, str) and sensitivity in {"normal", "elevated"}:
            self._sensitivity = sensitivity

    def check(self, profile: SystemProfile) -> CheckResult:
        managers = self._detect_managers(profile)
        stores = self._detect_browser_password_stores(profile)

        findings: list[Finding] = []
        if managers:
            findings.append(self._managers_finding(managers))
        else:
            findings.append(self._no_manager_finding())
        if stores:
            findings.append(self._browser_store_finding(stores, bool(managers)))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only. Nothing here moves or deletes a password."""
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "no_password_manager":
                actions.append(self._setup_action())
            elif check == "browser_password_store":
                actions.append(self._migrate_action(finding))
            elif check == "password_manager_detected":
                actions.append(self._review_action(finding))
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- detection ----------------

    def _detect_managers(self, profile: SystemProfile) -> list[dict]:
        """Return one record per distinct password manager found on the device."""
        found: dict[str, dict] = {}

        for root in self._application_roots(profile.platform):
            for entry in _list_dir(root):
                product = _match_manager(entry.name)
                if product and product not in found:
                    found[product] = {
                        "product": product,
                        "source": "installed application",
                        "evidence": _display_path(entry),
                    }

        for name in profile.installed_software:
            product = _match_manager(name)
            if product and product not in found:
                found[product] = {
                    "product": product,
                    "source": "installed software inventory",
                    "evidence": name,
                }

        for browser, extensions_dir in self._extension_roots(profile.platform):
            for entry in _list_dir(extensions_dir):
                product = KNOWN_MANAGER_EXTENSION_IDS.get(entry.name.lower())
                if product and product not in found:
                    found[product] = {
                        "product": product,
                        "source": f"{browser} extension",
                        "evidence": entry.name,
                    }

        return sorted(found.values(), key=lambda record: record["product"])

    def _detect_browser_password_stores(self, profile: SystemProfile) -> list[dict]:
        """Locate browser password databases without opening any of them."""
        stores = []
        for browser, path in self._browser_password_store_paths(profile.platform):
            try:
                stat = path.stat()
            except OSError:
                continue
            stores.append(
                {
                    "browser": browser,
                    "path": _display_path(path),
                    "size_bytes": stat.st_size,
                    "modified": _format_date(stat.st_mtime),
                }
            )
        return stores

    # ---------------- filesystem layout ----------------
    #
    # These three helpers are the module's only knowledge of where things live,
    # so a test can point them at a fixture tree instead of a real home
    # directory.

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

    def _chromium_user_data_roots(self, platform: Platform) -> list[tuple[str, Path]]:
        home = Path.home()
        if platform == Platform.DARWIN:
            support = home / "Library" / "Application Support"
            return [
                ("Chrome", support / "Google" / "Chrome"),
                ("Edge", support / "Microsoft Edge"),
                ("Brave", support / "BraveSoftware" / "Brave-Browser"),
            ]
        if platform == Platform.WIN32:
            local = home / "AppData" / "Local"
            return [
                ("Chrome", local / "Google" / "Chrome" / "User Data"),
                ("Edge", local / "Microsoft" / "Edge" / "User Data"),
                ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
            ]
        return []

    def _firefox_profile_roots(self, platform: Platform) -> list[tuple[str, Path]]:
        home = Path.home()
        if platform == Platform.DARWIN:
            return [
                ("Firefox", home / "Library" / "Application Support" / "Firefox" / "Profiles")
            ]
        if platform == Platform.WIN32:
            return [
                ("Firefox", home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles")
            ]
        return []

    def _extension_roots(self, platform: Platform) -> list[tuple[str, Path]]:
        roots = []
        for browser, user_data in self._chromium_user_data_roots(platform):
            for profile_dir in _chromium_profile_dirs(user_data):
                roots.append((browser, profile_dir / "Extensions"))
        return roots

    def _browser_password_store_paths(self, platform: Platform) -> list[tuple[str, Path]]:
        paths = []
        for browser, user_data in self._chromium_user_data_roots(platform):
            for profile_dir in _chromium_profile_dirs(user_data):
                paths.append((browser, profile_dir / "Login Data"))
        for browser, profiles_root in self._firefox_profile_roots(platform):
            for profile_dir in sorted(_list_dir(profiles_root)):
                if profile_dir.is_dir():
                    paths.append((browser, profile_dir / "logins.json"))
        return paths

    # ---------------- findings ----------------

    def _managers_finding(self, managers: list[dict]) -> Finding:
        listing = "\n".join(
            f"  • {record['product']} ({record['source']})" for record in managers
        )
        return Finding(
            title=f"Password manager detected: {managers[0]['product']}"
            if len(managers) == 1
            else f"{len(managers)} password managers detected",
            description=(
                "This device has password-manager software installed:\n"
                f"{listing}\n\n"
                "Detecting the software says nothing about whether it is actually "
                "being used, or whether the passwords inside it are unique. Use the "
                "manager's own security or watchtower report to check for reused and "
                "weak passwords.\n\n"
                f"{_DETECTION_CAVEAT}"
            ),
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "password_manager_detected",
                "managers": managers,
                "count": len(managers),
                "confidence": "high",
            },
        )

    def _no_manager_finding(self) -> Finding:
        return Finding(
            title="No password manager found on this device",
            description=(
                "None of the password managers this check knows about are installed "
                "here. Without one, unique passwords for every account are not "
                "realistic, and a single reused password turns one breach into many.\n\n"
                f"{_DETECTION_CAVEAT} If you already use one on your phone or through "
                "a website, treat this as a prompt to install it here too, so the "
                "device you sign in from is not the weak link."
            ),
            severity=Severity.WARNING,
            category=self.category,
            data={
                "check": "no_password_manager",
                "searched_for": sorted(set(KNOWN_MANAGERS.values())),
                "confidence": "medium",
            },
        )

    def _browser_store_finding(self, stores: list[dict], manager_present: bool) -> Finding:
        listing = "\n".join(
            f"  • {store['browser']}: {store['path']} "
            f"(last changed {store['modified']})"
            for store in stores
        )
        browsers = sorted({store["browser"] for store in stores})
        severity = Severity.WARNING
        if manager_present and self._sensitivity != "elevated":
            severity = Severity.INFO
        return Finding(
            title=f"Browser-stored passwords found in {', '.join(browsers)}",
            description=(
                "These browsers keep their own password database on this device:\n"
                f"{listing}\n\n"
                "The toolkit did not open any of them — only their file details were "
                "read. That matters because anything else running as your user "
                "account can open them, and on a device that may have been "
                "compromised those passwords should be treated as exposed.\n\n"
                "Move them into a password manager, change the ones that matter, and "
                "then turn off the browser's own password saving."
            ),
            severity=severity,
            category=self.category,
            data={
                "check": "browser_password_store",
                "stores": stores,
                "browsers": browsers,
                "manager_present": manager_present,
                "sensitivity": self._sensitivity,
                "confidence": "high",
            },
        )

    # ---------------- guidance ----------------

    def _setup_action(self) -> Action:
        return Action(
            title="Set up a password manager on this device",
            description=(
                "Pick one manager and use it for everything — mixing three of them is "
                "how people end up back at reused passwords.\n\n"
                "1. Choose a manager that runs on every device you use, and install "
                "it here and on your phone.\n"
                "2. Set a long passphrase you have never used anywhere else. Write it "
                "on paper and keep the paper somewhere physically safe.\n"
                "3. Save the manager's recovery kit or emergency sheet on paper too. "
                "If you lose it, nobody can let you back in.\n"
                "4. Add accounts as you sign into them rather than trying to import "
                "everything in one sitting. Start with email, then banking, then "
                "anything holding a payment card.\n\n"
                "Do not type the master passphrase into this toolkit, or into any "
                "page that arrives by link. Open the manager yourself."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _migrate_action(self, finding: Finding) -> Action:
        browsers = finding.data.get("browsers", [])
        listed = ", ".join(browsers) if browsers else "your browser"
        return Action(
            title=f"Move saved passwords out of {listed}",
            description=(
                f"For each of {listed}:\n"
                "1. Export or copy the saved passwords into your password manager. "
                "Every manager has an import step for exactly this.\n"
                "2. Delete the export file afterwards — it is a plain-text list of "
                "your passwords, and it will otherwise sit in Downloads forever.\n"
                "3. Turn off 'offer to save passwords' in the browser's settings so "
                "the database does not refill.\n"
                "4. Clear the browser's existing saved passwords once the import is "
                "verified.\n\n"
                "If this device may have been compromised, importing is not enough on "
                "its own: change the passwords for email, banking, and anything with a "
                "payment card, because the browser copies should be assumed read."
            ),
            risk_level=RiskLevel.MODERATE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _review_action(self, finding: Finding) -> Action:
        products = [record["product"] for record in finding.data.get("managers", [])]
        listed = ", ".join(products) if products else "your password manager"
        return Action(
            title=f"Run the security report in {listed}",
            description=(
                f"{listed} is installed, which is the hard part. The remaining work is "
                "using it:\n"
                "1. Open its security, watchtower, or password-health report.\n"
                "2. Fix reused passwords first, then weak ones, then anything the "
                "report flags as exposed in a known breach.\n"
                "3. Confirm the vault itself has two-factor authentication turned on.\n"
                "4. Check that you still have the recovery kit or emergency sheet, on "
                "paper, somewhere you can reach without this device."
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )


# ---------------- helpers ----------------


def _match_manager(name: str) -> str | None:
    lowered = name.lower()
    for needle, product in KNOWN_MANAGERS.items():
        if needle in lowered:
            return product
    return None


def _list_dir(path: Path) -> list[Path]:
    """Non-recursive listing that treats an unreadable directory as empty."""
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _chromium_profile_dirs(user_data: Path) -> list[Path]:
    """Chromium keeps one directory per browser profile: Default, Profile 1, …"""
    return sorted(
        entry
        for entry in _list_dir(user_data)
        if entry.is_dir()
        and (entry.name == "Default" or entry.name.startswith("Profile "))
    )


def _display_path(path: Path) -> str:
    """Render a path with the home directory replaced by ``~``.

    Home directories contain the account name, which does not belong in an
    exported rescue report.
    """
    try:
        return "~/" + str(path.relative_to(Path.home())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _format_date(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "unknown"
