import json
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
    name = "browser_hijack_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "2s"

    emits_codes = [
        "security.browser_hijack_check.safari_homepage_suspicious",
        "security.browser_hijack_check.safari_search_engine_suspicious",
        "security.browser_hijack_check.chrome_managed_by_policy",
        "security.browser_hijack_check.chrome_homepage_suspicious",
        "security.browser_hijack_check.chrome_search_engine_suspicious",
        "security.browser_hijack_check.firefox_homepage_suspicious",
        "security.browser_hijack_check.firefox_search_engine_suspicious",
        "security.browser_hijack_check.all_browsers_clean",
    ]

    # Known legitimate search engines and homepages
    LEGITIMATE_SEARCH_ENGINES = {
        "com.google.Chrome.safe_browsing",
        "com.google.Chrome",
        "google",
        "Google",
        "bing",
        "Bing",
        "duckduckgo",
        "DuckDuckGo",
        "yahoo",
        "Yahoo",
    }

    LEGITIMATE_HOMEPAGES = {
        "about:blank",
        "about:home",
        "about:newtab",
        "https://www.google.com",
        "https://www.bing.com",
        "https://www.duckduckgo.com",
        "https://www.yahoo.com",
        "https://www.apple.com",
        "https://apple.com",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Safari
        safari_findings = self._check_safari()
        findings.extend(safari_findings)

        # Check Chrome
        chrome_findings = self._check_chrome()
        findings.extend(chrome_findings)

        # Check Firefox
        firefox_findings = self._check_firefox()
        findings.extend(firefox_findings)

        # If no findings, report all good
        if not findings:
            findings.append(
                Finding(
                    title="Browser hijacking check passed",
                    description=(
                        "All detected browsers have standard homepages and search engines configured. "
                        "No signs of browser hijacking detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.browser_hijack_check.all_browsers_clean",
                    data={"check": "all_browsers_clean"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "safari_homepage_suspicious":
                homepage = finding.data.get("homepage", "unknown")
                actions.append(
                    Action(
                        title="Reset Safari homepage",
                        description=(
                            f"Current homepage: {homepage}\n"
                            "To reset Safari homepage:\n"
                            "1. Open Safari\n"
                            "2. Go to Safari > Settings > General\n"
                            "3. Set 'Homepage' to 'about:blank' or a trusted site (e.g., google.com)\n"
                            "4. Click OK"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "safari_search_engine_suspicious":
                engine = finding.data.get("engine", "unknown")
                actions.append(
                    Action(
                        title="Reset Safari search engine",
                        description=(
                            f"Current search engine: {engine}\n"
                            "To reset Safari search engine:\n"
                            "1. Open Safari\n"
                            "2. Go to Safari > Settings > Search\n"
                            "3. Select a legitimate search engine (Google, Bing, DuckDuckGo, Yahoo)\n"
                            "4. Click OK"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "chrome_homepage_suspicious":
                homepage = finding.data.get("homepage", "unknown")
                actions.append(
                    Action(
                        title="Reset Chrome homepage",
                        description=(
                            f"Current homepage: {homepage}\n"
                            "To reset Chrome homepage:\n"
                            "1. Open Chrome\n"
                            "2. Go to Chrome > Settings > On startup\n"
                            "3. Select 'Open the New Tab page' or a trusted URL\n"
                            "4. If needed, uninstall suspicious extensions in Settings > Extensions"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "chrome_search_engine_suspicious":
                engine = finding.data.get("engine", "unknown")
                actions.append(
                    Action(
                        title="Reset Chrome search engine",
                        description=(
                            f"Current search engine: {engine}\n"
                            "To reset Chrome search engine:\n"
                            "1. Open Chrome\n"
                            "2. Go to Chrome > Settings > Search engine\n"
                            "3. Select Google or another legitimate search engine from the list\n"
                            "4. If necessary, uninstall suspicious extensions in Settings > Extensions"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "chrome_managed_by_policy":
                actions.append(
                    Action(
                        title="Review Chrome enterprise policy",
                        description=(
                            "Chrome is managed by enterprise policy. Verify that the policies "
                            "are from your organization and that you trust them. "
                            "Check Chrome > Settings > About Chrome to see policy details."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "firefox_homepage_suspicious":
                homepage = finding.data.get("homepage", "unknown")
                actions.append(
                    Action(
                        title="Reset Firefox homepage",
                        description=(
                            f"Current homepage: {homepage}\n"
                            "To reset Firefox homepage:\n"
                            "1. Open Firefox\n"
                            "2. Go to Firefox > Settings > Home\n"
                            "3. Set 'Homepage and new windows' to a trusted page (Google, Bing, etc.)\n"
                            "4. If needed, uninstall suspicious add-ons in Settings > Extensions & Themes"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "firefox_search_engine_suspicious":
                engine = finding.data.get("engine", "unknown")
                actions.append(
                    Action(
                        title="Reset Firefox search engine",
                        description=(
                            f"Current search engine: {engine}\n"
                            "To reset Firefox search engine:\n"
                            "1. Open Firefox\n"
                            "2. Go to Firefox > Settings > Search\n"
                            "3. Select a legitimate search engine from the dropdown\n"
                            "4. Remove any suspicious search engines from the list"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_safari(self) -> list[Finding]:
        """Check Safari homepage and search engine settings."""
        findings = []

        # Check homepage
        homepage = self._get_safari_homepage()
        if homepage:
            is_suspicious = not self._is_legitimate_homepage(homepage)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Safari homepage appears suspicious",
                        description=(
                            f"Safari homepage is set to: {homepage}\n"
                            "This does not match a known legitimate homepage. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.safari_homepage_suspicious",
                        data={"check": "safari_homepage_suspicious", "homepage": homepage},
                    )
                )

        # Check search engine
        search_engine = self._get_safari_search_engine()
        if search_engine:
            is_suspicious = not self._is_legitimate_search_engine(search_engine)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Safari search engine appears suspicious",
                        description=(
                            f"Safari search engine is set to: {search_engine}\n"
                            "This does not match a known legitimate search engine. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.safari_search_engine_suspicious",
                        data={"check": "safari_search_engine_suspicious", "engine": search_engine},
                    )
                )

        return findings

    def _check_chrome(self) -> list[Finding]:
        """Check Chrome homepage, search engine, and policy settings."""
        findings = []

        # Check if Chrome is managed by policy
        is_managed = self._is_chrome_managed()
        if is_managed:
            findings.append(
                Finding(
                    title="Chrome is managed by enterprise policy",
                    description=(
                        "Chrome is managed by enterprise policy settings. "
                        "Verify that these policies are from your organization and trusted. "
                        "Malware can sometimes use policy settings to hijack browser behavior."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.browser_hijack_check.chrome_managed_by_policy",
                    data={"check": "chrome_managed_by_policy"},
                )
            )

        # Check homepage
        homepage = self._get_chrome_homepage()
        if homepage:
            is_suspicious = not self._is_legitimate_homepage(homepage)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Chrome homepage appears suspicious",
                        description=(
                            f"Chrome homepage is set to: {homepage}\n"
                            "This does not match a known legitimate homepage. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.chrome_homepage_suspicious",
                        data={"check": "chrome_homepage_suspicious", "homepage": homepage},
                    )
                )

        # Check default search provider
        search_engine = self._get_chrome_search_engine()
        if search_engine:
            is_suspicious = not self._is_legitimate_search_engine(search_engine)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Chrome search engine appears suspicious",
                        description=(
                            f"Chrome search engine is set to: {search_engine}\n"
                            "This does not match a known legitimate search engine. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.chrome_search_engine_suspicious",
                        data={"check": "chrome_search_engine_suspicious", "engine": search_engine},
                    )
                )

        return findings

    def _check_firefox(self) -> list[Finding]:
        """Check Firefox homepage and search engine settings."""
        findings = []

        # Check homepage
        homepage = self._get_firefox_homepage()
        if homepage:
            is_suspicious = not self._is_legitimate_homepage(homepage)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Firefox homepage appears suspicious",
                        description=(
                            f"Firefox homepage is set to: {homepage}\n"
                            "This does not match a known legitimate homepage. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.firefox_homepage_suspicious",
                        data={"check": "firefox_homepage_suspicious", "homepage": homepage},
                    )
                )

        # Check search engine
        search_engine = self._get_firefox_search_engine()
        if search_engine:
            is_suspicious = not self._is_legitimate_search_engine(search_engine)
            if is_suspicious:
                findings.append(
                    Finding(
                        title="Firefox search engine appears suspicious",
                        description=(
                            f"Firefox search engine is set to: {search_engine}\n"
                            "This does not match a known legitimate search engine. "
                            "This could indicate browser hijacking or malware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.browser_hijack_check.firefox_search_engine_suspicious",
                        data={"check": "firefox_search_engine_suspicious", "engine": search_engine},
                    )
                )

        return findings

    def _get_safari_homepage(self) -> str | None:
        """Get Safari homepage from defaults."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.Safari", "HomePage"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return None
        except (OSError, subprocess.CalledProcessError):
            return None

    def _get_safari_search_engine(self) -> str | None:
        """Get Safari search engine from defaults."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.Safari", "SearchProviderIdentifier"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            return None
        except (OSError, subprocess.CalledProcessError):
            return None

    def _get_chrome_homepage(self) -> str | None:
        """Get Chrome homepage from Preferences JSON."""
        try:
            prefs_path = (
                Path.home()
                / "Library/Application Support/Google/Chrome/Default/Preferences"
            )
            if not prefs_path.exists():
                return None

            with open(prefs_path, "r") as f:
                prefs = json.load(f)

            homepage = prefs.get("homepage")
            return homepage if homepage else None
        except (OSError, json.JSONDecodeError, IOError):
            return None

    def _get_chrome_search_engine(self) -> str | None:
        """Get Chrome default search provider from Preferences JSON."""
        try:
            prefs_path = (
                Path.home()
                / "Library/Application Support/Google/Chrome/Default/Preferences"
            )
            if not prefs_path.exists():
                return None

            with open(prefs_path, "r") as f:
                prefs = json.load(f)

            # Chrome stores search engine info in extensions.settings
            search_engines = prefs.get("extensions", {}).get("settings", {})
            # Look for the default search provider extension
            for ext_id, settings in search_engines.items():
                if settings.get("manifest", {}).get("name"):
                    name = settings.get("manifest", {}).get("name")
                    # Check if this is the default search provider
                    if any(
                        keyword in name.lower()
                        for keyword in ["google", "bing", "duckduckgo", "yahoo"]
                    ):
                        return name

            # Fallback: check for default_search_provider_data
            default_search = prefs.get("default_search_provider_data", {})
            if default_search:
                template_url = default_search.get("template_url", "")
                return template_url if template_url else None

            return None
        except (OSError, json.JSONDecodeError, IOError):
            return None

    def _is_chrome_managed(self) -> bool:
        """Check if Chrome is managed by enterprise policy."""
        try:
            prefs_path = (
                Path.home()
                / "Library/Application Support/Google/Chrome/Default/Preferences"
            )
            if not prefs_path.exists():
                return False

            with open(prefs_path, "r") as f:
                prefs = json.load(f)

            # Check for managed policies
            managed_policies = prefs.get("managed_configuration_hash", "")
            if managed_policies:
                return True

            # Check for policies key
            if "policy" in prefs:
                return True

            return False
        except (OSError, json.JSONDecodeError, IOError):
            return False

    def _get_firefox_homepage(self) -> str | None:
        """Get Firefox homepage from prefs.js."""
        try:
            firefox_profiles_dir = (
                Path.home() / "Library/Application Support/Firefox/Profiles"
            )
            if not firefox_profiles_dir.exists():
                return None

            # Find the first profile directory
            profile_dir = None
            for item in firefox_profiles_dir.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    profile_dir = item
                    break

            if not profile_dir:
                return None

            prefs_file = profile_dir / "prefs.js"
            if not prefs_file.exists():
                return None

            with open(prefs_file, "r") as f:
                for line in f:
                    if 'user_pref("browser.startup.homepage"' in line:
                        # Parse the preference line: user_pref("key", "value");
                        # Extract value between quotes
                        parts = line.split('"')
                        if len(parts) >= 4:
                            return parts[3]

            return None
        except (OSError, IOError):
            return None

    def _get_firefox_search_engine(self) -> str | None:
        """Get Firefox default search engine from prefs.js."""
        try:
            firefox_profiles_dir = (
                Path.home() / "Library/Application Support/Firefox/Profiles"
            )
            if not firefox_profiles_dir.exists():
                return None

            # Find the first profile directory
            profile_dir = None
            for item in firefox_profiles_dir.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    profile_dir = item
                    break

            if not profile_dir:
                return None

            prefs_file = profile_dir / "prefs.js"
            if not prefs_file.exists():
                return None

            with open(prefs_file, "r") as f:
                for line in f:
                    if 'user_pref("browser.search.defaultenginename"' in line:
                        # Parse the preference line: user_pref("key", "value");
                        # Extract value between quotes
                        parts = line.split('"')
                        if len(parts) >= 4:
                            return parts[3]

            return None
        except (OSError, IOError):
            return None

    def _is_legitimate_homepage(self, homepage: str) -> bool:
        """Check if homepage is in the legitimate list."""
        if not homepage:
            return True

        # Check exact matches
        if homepage in self.LEGITIMATE_HOMEPAGES:
            return True

        # Check if it contains a legitimate domain
        hostname_lower = homepage.lower()
        legitimate_domains = {
            "google",
            "bing",
            "duckduckgo",
            "yahoo",
            "apple",
            "about:",
        }

        for domain in legitimate_domains:
            if domain in hostname_lower:
                return True

        return False

    def _is_legitimate_search_engine(self, engine: str) -> bool:
        """Check if search engine is in the legitimate list."""
        if not engine:
            return True

        # Check exact matches
        if engine in self.LEGITIMATE_SEARCH_ENGINES:
            return True

        # Check if it contains a legitimate search engine name
        engine_lower = engine.lower()
        for search_engine in self.LEGITIMATE_SEARCH_ENGINES:
            if search_engine.lower() in engine_lower:
                return True

        return False
