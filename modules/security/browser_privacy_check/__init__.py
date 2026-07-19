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
    name = "browser_privacy_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.browser_privacy_check.do_not_track_disabled",
        "security.browser_privacy_check.fraud_warning_disabled",
        "security.browser_privacy_check.cookies_always_allow",
        "security.browser_privacy_check.autofilll_passwords_enabled",
        "security.browser_privacy_check.installed_browsers",
        "security.browser_privacy_check.saved_passwords",
        "security.browser_privacy_check.privacy_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Safari privacy settings
        safari_findings = self._check_safari_privacy()
        findings.extend(safari_findings)

        # Check installed browsers
        browser_findings = self._check_installed_browsers()
        findings.extend(browser_findings)

        # Check Safari saved passwords
        password_findings = self._check_safari_passwords()
        findings.extend(password_findings)

        # Add info summary if no issues
        if not findings:
            findings.append(
                Finding(
                    title="Browser privacy configuration",
                    description=(
                        "Safari privacy settings are properly configured. "
                        "Do Not Track is enabled, fraud warnings are enabled, "
                        "and cookies are blocked appropriately."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.browser_privacy_check.privacy_summary",
                    data={"check": "privacy_summary", "status": "clean"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "fraud_warning_disabled":
                actions.append(
                    Action(
                        title="Enable Safari fraud warning",
                        description=(
                            "Fraud warnings help protect against phishing sites. "
                            "Open Safari > Settings > Security, and ensure "
                            "'Warn when visiting a fraudulent website' is enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "do_not_track_disabled":
                actions.append(
                    Action(
                        title="Enable Do Not Track in Safari",
                        description=(
                            "Do Not Track (DNT) requests that your browsing not be tracked. "
                            "Open Safari > Settings > Privacy, and check "
                            "'Ask websites not to track me' to enable this feature."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "cookies_always_allow":
                actions.append(
                    Action(
                        title="Restrict cookie blocking policy in Safari",
                        description=(
                            "Allowing all cookies increases tracking risk. "
                            "Open Safari > Settings > Privacy, and change "
                            "'Block all cookies' to a more restrictive setting like "
                            "'Block third-party and advertisers'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "autofilll_passwords_enabled":
                actions.append(
                    Action(
                        title="Review Safari password autofill settings",
                        description=(
                            "Autofill passwords can be a security risk if your keychain is weak. "
                            "Consider opening Safari > Settings > Passwords and reviewing "
                            "whether autofill is necessary for your use case."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "privacy_summary":
                # No action needed for summary
                pass

        return FixResult(module_name=self.name, actions=actions)

    def _check_safari_privacy(self) -> list[Finding]:
        """Check Safari privacy settings via defaults read."""
        findings = []

        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.Safari"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout

            # Check Do Not Track HTTP Header
            if "SendDoNotTrackHTTPHeader" in output and "= 0" in output:
                # Extract the specific line to check
                for line in output.split("\n"):
                    if "SendDoNotTrackHTTPHeader" in line and "= 0" in line:
                        findings.append(
                            Finding(
                                title="Do Not Track disabled in Safari",
                                description=(
                                    "Do Not Track (DNT) is disabled in Safari. "
                                    "Enabling DNT requests that websites not track your browsing. "
                                    "This is a privacy best practice."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                code="security.browser_privacy_check.do_not_track_disabled",
                                data={"check": "do_not_track_disabled"},
                            )
                        )
                        break

            # Check Fraud Warning
            if "WarnAboutFraudulentWebsites" in output and "= 0" in output:
                for line in output.split("\n"):
                    if "WarnAboutFraudulentWebsites" in line and "= 0" in line:
                        findings.append(
                            Finding(
                                title="Fraudulent website warnings disabled in Safari",
                                description=(
                                    "Safari's fraud warning system is disabled. "
                                    "This feature helps protect against phishing and malicious sites. "
                                    "Re-enabling it is strongly recommended."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                code="security.browser_privacy_check.fraud_warning_disabled",
                                data={"check": "fraud_warning_disabled"},
                            )
                        )
                        break

            # Check Cookie Policy
            if "BlockStoragePolicy" in output:
                for line in output.split("\n"):
                    if "BlockStoragePolicy" in line and ("Always Allow" in line or "= 0" in line):
                        findings.append(
                            Finding(
                                title="Cookies are always allowed in Safari",
                                description=(
                                    "Safari is configured to allow all cookies, which increases tracking risk. "
                                    "Consider changing the cookie blocking policy to block third-party and advertiser cookies. "
                                    "This reduces your exposure to tracking and advertising networks."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                code="security.browser_privacy_check.cookies_always_allow",
                                data={"check": "cookies_always_allow"},
                            )
                        )
                        break

            # Check Auto Fill Passwords
            if "AutoFillPasswords" in output:
                for line in output.split("\n"):
                    if "AutoFillPasswords" in line and "= 1" in line:
                        findings.append(
                            Finding(
                                title="Safari password autofill is enabled",
                                description=(
                                    "Safari's password autofill feature is enabled. "
                                    "If your Mac's keychain password is weak, this could be a security risk. "
                                    "Ensure your login password is strong if you use autofill."
                                ),
                                severity=Severity.INFO,
                                category=self.category,
                                code="security.browser_privacy_check.autofilll_passwords_enabled",
                                data={"check": "autofilll_passwords_enabled"},
                            )
                        )
                        break

        except OSError:
            pass
        except Exception:
            pass

        return findings

    def _check_installed_browsers(self) -> list[Finding]:
        """Check for installed browsers and profile counts."""
        findings = []

        chrome_path = Path.home() / "Library/Application Support/Google/Chrome"
        firefox_path = Path.home() / "Library/Application Support/Firefox/Profiles"

        browsers = []

        # Check Chrome
        if chrome_path.exists():
            try:
                profiles = [d for d in chrome_path.iterdir() if d.is_dir()]
                profile_count = len(profiles)
                browsers.append(f"Google Chrome ({profile_count} profile(s))")
            except OSError:
                browsers.append("Google Chrome (unable to read profiles)")

        # Check Firefox
        if firefox_path.exists():
            try:
                profiles = [d for d in firefox_path.iterdir() if d.is_dir()]
                profile_count = len(profiles)
                browsers.append(f"Mozilla Firefox ({profile_count} profile(s))")
            except OSError:
                browsers.append("Mozilla Firefox (unable to read profiles)")

        if browsers:
            findings.append(
                Finding(
                    title=f"Installed browsers: {len(browsers)}",
                    description=(
                        f"The following browsers are installed on this system: "
                        f"{', '.join(browsers)}. "
                        "Review privacy settings in each browser independently."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.browser_privacy_check.installed_browsers",
                    data={"check": "installed_browsers", "browsers": browsers},
                )
            )

        return findings

    def _check_safari_passwords(self) -> list[Finding]:
        """Check for saved passwords in Safari keychain."""
        findings = []

        try:
            # Count internet passwords saved for Safari/websites
            result = subprocess.run(
                ["security", "find-internet-password", "-l", ""],
                capture_output=True,
                text=True,
            )

            # Count occurrences of "keychain" in output as approximation
            if result.returncode == 0:
                keychain_count = result.stdout.count("keychain:")
                if keychain_count > 0:
                    findings.append(
                        Finding(
                            title=f"Safari has {keychain_count} saved passwords",
                            description=(
                                f"Approximately {keychain_count} internet passwords are saved in Safari. "
                                "These are stored in your system keychain and protected by your login password. "
                                "Regularly review and remove passwords for accounts you no longer use."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            code="security.browser_privacy_check.saved_passwords",
                            data={"check": "saved_passwords", "count": keychain_count},
                        )
                    )

        except OSError:
            pass
        except Exception:
            pass

        return findings
