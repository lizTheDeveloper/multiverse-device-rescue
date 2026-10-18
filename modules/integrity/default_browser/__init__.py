import subprocess
import os

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
    name = "default_browser"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    # Well-known macOS browsers
    KNOWN_BROWSERS = {
        "com.apple.Safari": "Safari",
        "com.google.Chrome": "Google Chrome",
        "org.mozilla.firefox": "Firefox",
        "com.microsoft.edgemac": "Microsoft Edge",
        "com.brave.Browser": "Brave",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get default HTTP handler
        http_handler = self._get_default_handler("http")
        https_handler = self._get_default_handler("https")
        mailto_handler = self._get_default_handler("mailto")

        # Report default browser (use https as primary, fall back to http)
        browser_id = https_handler or http_handler
        browser_name = self._get_app_name(browser_id) if browser_id else "Unknown"

        known_id = self._known_id(browser_id) if browser_id else None
        if known_id:
            browser_name = self.KNOWN_BROWSERS[known_id]
        if browser_id:
            browser_display = self.KNOWN_BROWSERS.get(known_id, browser_name)
            findings.append(
                Finding(
                    title="Your default web browser",
                    description=f"Default browser: {browser_display} ({browser_id})",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "default_browser_info",
                        "browser_id": browser_id,
                        "browser_name": browser_display,
                    },
                )
            )

            # Check if browser is a known one
            if known_id:
                findings.append(
                    Finding(
                        title="Your default web browser is a standard app",
                        description=f"Using {self.KNOWN_BROWSERS[known_id]}, a well-known browser.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "known_browser",
                            "browser_id": browser_id,
                        },
                    )
                )
            else:
                # Unknown browser - check if app exists
                if not self._app_exists(browser_id):
                    findings.append(
                        Finding(
                            title=f"Your default browser '{browser_id}' might be missing",
                            description=(
                                f"Your computer is set to open web links in '{browser_id}', "
                                "but we can't find that app installed. This usually means "
                                "the app was removed or moved, so clicking links might "
                                "not work or could open the wrong program.\n\n"
                                "What to do: Open System Settings > Desktop & Dock > "
                                "Default web browser and choose a browser you actually "
                                "have, like Safari or Chrome."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "browser_not_installed",
                                "browser_id": browser_id,
                            },
                        )
                    )

        # Report default email client
        if mailto_handler:
            email_name = self._get_app_name(mailto_handler)
            email_display = self.KNOWN_BROWSERS.get(mailto_handler, email_name)
            findings.append(
                Finding(
                    title="Your default email app",
                    description=f"Default email client: {email_display} ({mailto_handler})",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "default_email_info",
                        "email_id": mailto_handler,
                        "email_name": email_display,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "browser_not_installed":
                browser_id = finding.data.get("browser_id")
                actions.append(
                    Action(
                        title=f"Install or reconfigure default browser",
                        description=(
                            f"The default browser is set to '{browser_id}' which may not be installed.\n"
                            "To change the default browser:\n"
                            "1. Open System Preferences > General > Default web browser\n"
                            "2. Select a different browser from the dropdown\n"
                            "Or install the missing browser application."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_default_handler(self, scheme: str) -> str:
        """Get the default handler for a URL scheme (http, https, mailto).
        Returns the bundle identifier or empty string if not found."""
        try:
            # Try reading from LaunchServices defaults
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.LaunchServices/com.apple.launchservices.secure",
                    "LSHandlers",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                handler = self._parse_lshandlers(result.stdout, scheme)
                if handler:
                    return handler
        except (OSError, subprocess.SubprocessError):
            pass

        # Fallback: try using duti if available
        try:
            result = subprocess.run(
                ["duti", "-x", scheme],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass

        return ""

    @staticmethod
    def _parse_lshandlers(text: str, scheme: str) -> str:
        """Bundle id handling ``scheme`` in `defaults read ... LSHandlers` output.

        Each handler is one ``{ ... }`` entry. macOS writes the keys
        alphabetically, so LSHandlerRoleAll comes *before* LSHandlerURLScheme,
        and a nested LSHandlerPreferredVersions dict has its own
        ``LSHandlerRoleAll = "-"``. Reading line by line and taking the next
        RoleAll after the scheme picked up the following entry's "-" and
        reported the default browser as a missing app called '-'.
        """
        depth = 0
        entry: dict[str, str] = {}
        for raw in text.splitlines():
            line = raw.strip()
            if depth == 1 and "=" in line:
                key, value = line.split("=", 1)
                entry[key.strip()] = value.strip().rstrip(";").strip().strip('"')
            opens, closes = line.count("{"), line.count("}")
            if opens and depth == 0:
                entry = {}
            depth += opens - closes
            if closes and depth == 0:
                if entry.get("LSHandlerURLScheme", "").lower() == scheme:
                    role = entry.get("LSHandlerRoleAll", "")
                    if role and role != "-":
                        return role
                entry = {}
        return ""

    def _get_app_name(self, bundle_id: str) -> str:
        """Get human-readable app name from bundle identifier."""
        if not bundle_id:
            return "Unknown"

        # Known bundle IDs
        known = {
            "com.apple.Safari": "Safari",
            "com.google.Chrome": "Google Chrome",
            "org.mozilla.firefox": "Firefox",
            "com.microsoft.edgemac": "Microsoft Edge",
            "com.brave.Browser": "Brave",
            "com.apple.mail": "Mail",
            "com.google.Chrome.canary": "Google Chrome Canary",
        }
        if bundle_id in known:
            return known[bundle_id]

        # Try to extract name from bundle ID
        parts = bundle_id.split(".")
        if parts:
            return parts[-1].replace("-", " ").title()

        return bundle_id

    def _known_id(self, bundle_id: str) -> str | None:
        """The KNOWN_BROWSERS key matching ``bundle_id``, ignoring case."""
        lowered = bundle_id.lower()
        for known in self.KNOWN_BROWSERS:
            if known.lower() == lowered:
                return known
        return None

    def _app_exists(self, bundle_id: str) -> bool:
        """Check if an app with the given bundle ID exists on the system."""
        try:
            result = subprocess.run(
                # "c": LaunchServices stores ids lowercased (com.google.chrome)
                # while the app's own id is com.google.Chrome.
                ["mdfind", f'kMDItemCFBundleIdentifier == "{bundle_id}"c'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False
