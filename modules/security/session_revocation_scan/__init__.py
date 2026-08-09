"""Find the things on this device that stay signed in after a password change.

Changing a password is the step everybody knows about, and on its own it does
much less than people expect. A browser that is already signed in keeps its
session cookie. An API token in a dotfile keeps working. A cloud CLI stays
authenticated for weeks. All of those have to be revoked deliberately, from the
provider's side, and they are easy to forget because nothing on the device
announces them.

This module lists them. It records that a file exists, when it last changed,
how large it is, and who can read it — and stops there. It never opens a cookie
database, never parses a token, and never sends anything anywhere. A finding
here is not evidence of compromise; it is a work list for the revocation step
of a recovery.
"""

import stat as stat_module
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

# Files that hold a long-lived credential, keyed by their path relative to the
# home directory. The note explains what has to be revoked, because "delete the
# file" is the wrong instruction — the token stays valid on the server.
CREDENTIAL_ARTIFACTS: dict[str, tuple[str, str]] = {
    ".aws/credentials": (
        "AWS",
        "Deactivate and delete the access key in IAM; deleting this file alone "
        "leaves the key working.",
    ),
    ".config/gcloud/credentials.db": (
        "Google Cloud",
        "Run `gcloud auth revoke --all`, then re-authenticate.",
    ),
    ".azure/msal_token_cache.json": (
        "Azure",
        "Run `az logout`, then revoke sessions in Entra ID.",
    ),
    ".kube/config": (
        "Kubernetes",
        "Rotate the cluster credentials this file embeds; they are usually "
        "long-lived.",
    ),
    ".docker/config.json": (
        "Container registries",
        "Run `docker logout` for each registry and rotate the registry tokens.",
    ),
    ".config/gh/hosts.yml": (
        "GitHub CLI",
        "Revoke the token under GitHub Settings → Developer settings, then "
        "re-run `gh auth login`.",
    ),
    ".git-credentials": (
        "Git over HTTPS",
        "This file stores credentials in plain text. Revoke the tokens it "
        "covers and switch to a credential helper.",
    ),
    ".netrc": (
        "Generic (.netrc)",
        "Plain-text credentials for whichever hosts it lists. Rotate each one.",
    ),
    "_netrc": (
        "Generic (_netrc)",
        "Plain-text credentials for whichever hosts it lists. Rotate each one.",
    ),
    ".npmrc": (
        "npm registry",
        "Revoke the npm access token at npmjs.com, then `npm login` again.",
    ),
    ".pypirc": (
        "PyPI",
        "Revoke the API token in your PyPI account settings.",
    ),
    ".cargo/credentials.toml": (
        "crates.io",
        "Revoke the token in your crates.io account settings.",
    ),
    ".gem/credentials": (
        "RubyGems",
        "Reset the API key at rubygems.org.",
    ),
    ".terraform.d/credentials.tfrc.json": (
        "Terraform Cloud",
        "Revoke the API token in Terraform Cloud user settings.",
    ),
}

_SCOPE_CAVEAT = (
    "The toolkit did not open any of these files — only their name, size, "
    "modification date, and permissions were read."
)


class Module(ModuleBase):
    name = "session_revocation_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 40
    depends_on = []
    estimated_duration = "5s"

    def __init__(self) -> None:
        self._sensitivity = "normal"

    def configure(self, config: dict[str, Any]) -> None:
        """Accept ``sensitivity`` from a profile's ``module_config``.

        At ``elevated`` sensitivity — used by the post-compromise profile — an
        existing browser session is a warning rather than an observation,
        because a session that predates the compromise may belong to somebody
        else by now.
        """
        sensitivity = config.get("sensitivity")
        if isinstance(sensitivity, str) and sensitivity in {"normal", "elevated"}:
            self._sensitivity = sensitivity

    def check(self, profile: SystemProfile) -> CheckResult:
        sessions = self._detect_browser_sessions(profile)
        credentials = self._detect_credential_artifacts(profile.platform)
        exposed = [record for record in credentials if record["world_readable"]]

        findings: list[Finding] = []
        if sessions:
            findings.append(self._browser_session_finding(sessions))
        if credentials:
            findings.append(self._credential_finding(credentials))
        if exposed:
            findings.append(self._permissions_finding(exposed))
        findings.append(self._provider_side_finding())
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only. Revocation happens on the provider's side, not here."""
        actions: list[Action] = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "browser_sessions":
                actions.append(self._sign_out_action(finding))
            elif check == "credential_artifacts":
                actions.append(self._rotate_tokens_action(finding))
            elif check == "credential_permissions":
                actions.append(self._tighten_permissions_action(finding))
            elif check == "provider_side_sessions":
                actions.append(self._provider_review_action())
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- detection ----------------

    def _detect_browser_sessions(self, profile: SystemProfile) -> list[dict]:
        sessions = []
        for browser, label, path in self._browser_session_paths(profile.platform):
            stat = _stat(path)
            if stat is None:
                continue
            sessions.append(
                {
                    "browser": browser,
                    "profile": label,
                    "path": _display_path(path),
                    "size_bytes": stat.st_size,
                    "modified": _format_date(stat.st_mtime),
                }
            )
        return sessions

    def _detect_credential_artifacts(self, platform: Platform) -> list[dict]:
        home = Path.home()
        # Windows does not express access control in the POSIX mode bits, which
        # Python reports as a constant there. Claiming a file is world-readable
        # from that value would be a fabricated finding, so permissions are only
        # judged where the bits mean something.
        modes_meaningful = platform != Platform.WIN32
        records = []
        for relative, (service, revocation) in CREDENTIAL_ARTIFACTS.items():
            path = home / relative
            stat = _stat(path)
            if stat is None:
                continue
            records.append(
                {
                    "service": service,
                    "path": "~/" + relative,
                    "size_bytes": stat.st_size,
                    "modified": _format_date(stat.st_mtime),
                    "revocation": revocation,
                    "world_readable": (
                        modes_meaningful and _is_group_or_world_readable(stat.st_mode)
                    ),
                    "mode": _format_mode(stat.st_mode) if modes_meaningful else "n/a",
                }
            )
        return sorted(records, key=lambda record: record["service"])

    # ---------------- filesystem layout ----------------

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
        if platform == Platform.LINUX:
            config = home / ".config"
            return [
                ("Chrome", config / "google-chrome"),
                ("Chromium", config / "chromium"),
                ("Brave", config / "BraveSoftware" / "Brave-Browser"),
            ]
        return []

    def _firefox_profile_roots(self, platform: Platform) -> list[Path]:
        home = Path.home()
        if platform == Platform.DARWIN:
            return [home / "Library" / "Application Support" / "Firefox" / "Profiles"]
        if platform == Platform.WIN32:
            return [home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"]
        if platform == Platform.LINUX:
            return [home / ".mozilla" / "firefox"]
        return []

    def _safari_cookie_paths(self, platform: Platform) -> list[Path]:
        if platform != Platform.DARWIN:
            return []
        home = Path.home()
        return [
            home / "Library" / "Cookies" / "Cookies.binarycookies",
            home
            / "Library"
            / "Containers"
            / "com.apple.Safari"
            / "Data"
            / "Library"
            / "Cookies"
            / "Cookies.binarycookies",
        ]

    def _browser_session_paths(self, platform: Platform) -> list[tuple[str, str, Path]]:
        """Return (browser, profile label, cookie store path) triples to stat."""
        paths: list[tuple[str, str, Path]] = []
        for browser, user_data in self._chromium_user_data_roots(platform):
            for profile_dir in _chromium_profile_dirs(user_data):
                # Chromium moved the cookie store under Network/ in 2020; older
                # profiles still have it at the top level.
                paths.append((browser, profile_dir.name, profile_dir / "Network" / "Cookies"))
                paths.append((browser, profile_dir.name, profile_dir / "Cookies"))
        for profiles_root in self._firefox_profile_roots(platform):
            for profile_dir in sorted(_list_dir(profiles_root)):
                if profile_dir.is_dir():
                    paths.append(("Firefox", profile_dir.name, profile_dir / "cookies.sqlite"))
        for path in self._safari_cookie_paths(platform):
            paths.append(("Safari", "Default", path))
        return paths

    # ---------------- findings ----------------

    def _browser_session_finding(self, sessions: list[dict]) -> Finding:
        listing = "\n".join(
            f"  • {record['browser']} ({record['profile']}) — last changed "
            f"{record['modified']}"
            for record in sessions
        )
        browsers = sorted({record["browser"] for record in sessions})
        severity = (
            Severity.WARNING if self._sensitivity == "elevated" else Severity.INFO
        )
        return Finding(
            title=f"{len(sessions)} browser session store(s) on this device",
            description=(
                "These browsers hold session cookies, which keep accounts signed in "
                "independently of the password:\n"
                f"{listing}\n\n"
                "Changing a password does not always end these sessions. Most "
                "providers have a 'sign out of all devices' control that does, and it "
                "has to be used deliberately.\n\n"
                f"{_SCOPE_CAVEAT} Their presence is completely normal — this is a list "
                "of places to sign out from, not a list of problems."
            ),
            severity=severity,
            category=self.category,
            data={
                "check": "browser_sessions",
                "sessions": sessions,
                "browsers": browsers,
                "count": len(sessions),
                "sensitivity": self._sensitivity,
                "confidence": "high",
            },
        )

    def _credential_finding(self, credentials: list[dict]) -> Finding:
        listing = "\n".join(
            f"  • {record['service']}: {record['path']} "
            f"(last changed {record['modified']})\n      {record['revocation']}"
            for record in credentials
        )
        services = sorted({record["service"] for record in credentials})
        return Finding(
            title=f"{len(credentials)} stored credential file(s) need revoking",
            description=(
                "These files hold access tokens or keys that keep working after an "
                "account password changes:\n"
                f"{listing}\n\n"
                "Each one has to be revoked at the service, not just deleted here — a "
                "deleted file leaves a live token on the provider's side, and a copy "
                "taken from this device would still work.\n\n"
                f"{_SCOPE_CAVEAT}"
            ),
            severity=Severity.WARNING,
            category=self.category,
            data={
                "check": "credential_artifacts",
                "credentials": credentials,
                "services": services,
                "count": len(credentials),
                "confidence": "high",
            },
        )

    def _permissions_finding(self, exposed: list[dict]) -> Finding:
        listing = "\n".join(
            f"  • {record['path']} (mode {record['mode']})" for record in exposed
        )
        return Finding(
            title=f"{len(exposed)} credential file(s) readable by other accounts",
            description=(
                "These credential files can be read by users or groups other than "
                "you:\n"
                f"{listing}\n\n"
                "On a shared machine that means anybody with an account can copy the "
                "tokens. Tightening the permissions is worth doing, but it does not "
                "undo any copying that already happened — revoke the tokens as well."
            ),
            severity=Severity.WARNING,
            category=self.category,
            data={
                "check": "credential_permissions",
                "credentials": exposed,
                "count": len(exposed),
                "confidence": "high",
            },
        )

    def _provider_side_finding(self) -> Finding:
        return Finding(
            title="Account sessions can only be reviewed at each provider",
            description=(
                "Sessions on other devices, connected third-party apps, app "
                "passwords, and OAuth grants live on the provider's servers. Nothing "
                "on this computer can list them, and this toolkit deliberately does "
                "not sign in to your accounts to try.\n\n"
                "This finding is a reminder that the revocation work is only half done "
                "when the local list above is cleared."
            ),
            severity=Severity.INFO,
            category=self.category,
            data={"check": "provider_side_sessions", "confidence": "high"},
        )

    # ---------------- guidance ----------------

    def _sign_out_action(self, finding: Finding) -> Action:
        browsers = finding.data.get("browsers", [])
        listed = ", ".join(browsers) if browsers else "your browser"
        return Action(
            title="Sign out everywhere, in the right order",
            description=(
                "Order matters. Signing out of all devices before changing the "
                "password just lets whoever has the password sign back in.\n\n"
                "For each important account:\n"
                "1. Change the password first.\n"
                "2. Then use the provider's 'sign out of all devices' or 'log out "
                "other sessions' control.\n"
                "3. Then check the connected-apps or third-party-access list and "
                "remove anything you do not recognise.\n"
                "4. Sign back in on the devices you actually use.\n\n"
                f"Session cookies were found in {listed}. Clearing that browser's "
                "cookies signs this device out, which is worth doing at the end, but "
                "it does nothing about sessions on any other device."
            ),
            risk_level=RiskLevel.MODERATE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _rotate_tokens_action(self, finding: Finding) -> Action:
        credentials = finding.data.get("credentials", [])
        steps = "\n".join(
            f"{index}. {record['service']} ({record['path']}) — {record['revocation']}"
            for index, record in enumerate(credentials, start=1)
        )
        return Action(
            title=f"Revoke and re-issue {len(credentials)} stored credential(s)",
            description=(
                "Work through these at the service, not on disk:\n\n"
                f"{steps}\n\n"
                "Do not start by deleting the files. Revoke first, confirm the old "
                "credential is dead, then re-authenticate — otherwise you lose the "
                "record of what needs revoking and the token stays live.\n\n"
                "If a service shows access logs, look at them while you are there: a "
                "token used from somewhere you have never been is the clearest signal "
                "you will get."
            ),
            risk_level=RiskLevel.MODERATE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _tighten_permissions_action(self, finding: Finding) -> Action:
        credentials = finding.data.get("credentials", [])
        commands = "\n".join(f"  chmod 600 {record['path']}" for record in credentials)
        return Action(
            title="Restrict credential files to your account only",
            description=(
                "After revoking and re-issuing the tokens, restrict the files so the "
                "replacements are not exposed the same way:\n\n"
                f"{commands}\n\n"
                "Run these yourself and read them before you do — the toolkit does not "
                "change file permissions for you."
            ),
            risk_level=RiskLevel.MODERATE,
            kind=ActionKind.GUIDANCE,
            success=True,
        )

    def _provider_review_action(self) -> Action:
        return Action(
            title="Review sessions and connected apps at each provider",
            description=(
                "Go account by account, most important first — email, then password "
                "manager, then banking, then cloud and social accounts. In each "
                "provider's security settings, look for:\n"
                "- active sessions or 'where you're signed in';\n"
                "- connected apps, third-party access, or OAuth grants;\n"
                "- app passwords and API tokens;\n"
                "- forwarding rules, filters, and recovery addresses, which are how "
                "access gets kept after a password change;\n"
                "- registered second-factor devices.\n\n"
                "Remove anything you do not recognise, and write down what you "
                "removed. Reach these pages by typing the provider's address "
                "yourself, never through a link in a message about the compromise."
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


def _chromium_profile_dirs(user_data: Path) -> list[Path]:
    """Chromium keeps one directory per browser profile: Default, Profile 1, …"""
    return sorted(
        entry
        for entry in _list_dir(user_data)
        if entry.is_dir()
        and (entry.name == "Default" or entry.name.startswith("Profile "))
    )


def _stat(path: Path):
    try:
        return path.stat()
    except OSError:
        return None


def _is_group_or_world_readable(mode: int) -> bool:
    return bool(mode & (stat_module.S_IRGRP | stat_module.S_IROTH))


def _format_mode(mode: int) -> str:
    return oct(stat_module.S_IMODE(mode))[2:].rjust(3, "0")


def _display_path(path: Path) -> str:
    """Render a path with the home directory replaced by ``~``."""
    try:
        return "~/" + str(path.relative_to(Path.home())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _format_date(timestamp: float) -> str:
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "unknown"
