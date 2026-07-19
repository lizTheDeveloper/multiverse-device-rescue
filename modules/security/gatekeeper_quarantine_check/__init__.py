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
    name = "gatekeeper_quarantine_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 56
    depends_on = []
    estimated_duration = "8s"

    emits_codes = [
        "security.gatekeeper_quarantine_check.gatekeeper_disabled",
        "security.gatekeeper_quarantine_check.gatekeeper_enabled",
        "security.gatekeeper_quarantine_check.sip_disabled",
        "security.gatekeeper_quarantine_check.sip_enabled",
        "security.gatekeeper_quarantine_check.quarantine_removed",
        "security.gatekeeper_quarantine_check.gatekeeper_assessment_failed",
        "security.gatekeeper_quarantine_check.gatekeeper_working",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Gatekeeper status
        gatekeeper_enabled = self._check_gatekeeper_status()
        if gatekeeper_enabled is False:
            findings.append(
                Finding(
                    title="Gatekeeper is disabled",
                    description=(
                        "Gatekeeper is completely disabled, removing the first line of "
                        "defense against malware. This allows any unsigned or untrusted "
                        "applications to run without verification. CRITICAL: Re-enable "
                        "Gatekeeper immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.gatekeeper_disabled",
                    data={"check": "gatekeeper_disabled"},
                )
            )
        elif gatekeeper_enabled is True:
            findings.append(
                Finding(
                    title="Gatekeeper is enabled",
                    description="Gatekeeper is enabled and will verify code signatures on applications.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.gatekeeper_enabled",
                    data={"check": "gatekeeper_enabled"},
                )
            )

        # Check SIP status
        sip_enabled = self._check_sip_status()
        if sip_enabled is False:
            findings.append(
                Finding(
                    title="System Integrity Protection (SIP) is disabled",
                    description=(
                        "SIP is disabled, which means system files and processes are not "
                        "protected from modification by unauthorized parties. This is a "
                        "CRITICAL security issue. Re-enable SIP immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.sip_disabled",
                    data={"check": "sip_disabled"},
                )
            )
        elif sip_enabled is True:
            findings.append(
                Finding(
                    title="System Integrity Protection (SIP) is enabled",
                    description="SIP is enabled and protecting critical system files.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.sip_enabled",
                    data={"check": "sip_enabled"},
                )
            )

        # Check for apps with quarantine flags removed
        apps_without_quarantine = self._check_quarantine_flags()
        if apps_without_quarantine:
            findings.append(
                Finding(
                    title=f"Quarantine flag removed from {len(apps_without_quarantine)} app(s)",
                    description=(
                        f"The following {len(apps_without_quarantine)} app(s) have had their "
                        f"quarantine flag manually removed, potentially bypassing Gatekeeper "
                        f"assessment: {', '.join(sorted(apps_without_quarantine))}. "
                        "This could indicate either intentional security circumvention or "
                        "evidence of compromise."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.quarantine_removed",
                    data={"check": "quarantine_removed", "apps": apps_without_quarantine},
                )
            )

        # Test Gatekeeper assessment on a common app
        gatekeeper_works = self._test_gatekeeper_assessment()
        if gatekeeper_works is False:
            findings.append(
                Finding(
                    title="Gatekeeper assessment failed or unavailable",
                    description=(
                        "Gatekeeper assessment test on a known system app returned an error "
                        "or unexpected result. This may indicate Gatekeeper is not functioning "
                        "properly."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.gatekeeper_assessment_failed",
                    data={"check": "gatekeeper_assessment_failed"},
                )
            )
        elif gatekeeper_works is True:
            findings.append(
                Finding(
                    title="Gatekeeper assessment working",
                    description="Gatekeeper assessment verification completed successfully.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.gatekeeper_quarantine_check.gatekeeper_working",
                    data={"check": "gatekeeper_working"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational guidance on how to re-enable Gatekeeper and SIP.
        Does not actually modify the system.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "gatekeeper_disabled":
                actions.append(
                    Action(
                        title="Re-enable Gatekeeper",
                        description=(
                            "Run: sudo spctl --master-enable\n"
                            "This will re-enable Gatekeeper's code signature verification. "
                            "If you have specific unsigned apps you need to run, allow them "
                            "individually instead of disabling Gatekeeper globally with: "
                            "sudo spctl --add --label 'Approved App' /path/to/app"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "sip_disabled":
                actions.append(
                    Action(
                        title="Re-enable System Integrity Protection (SIP)",
                        description=(
                            "1. Reboot your Mac into Recovery Mode: Hold Cmd+R during startup\n"
                            "2. Open Terminal from Utilities menu\n"
                            "3. Run: csrutil enable\n"
                            "4. Reboot normally\n"
                            "SIP protects critical system files from unauthorized modification. "
                            "If you disabled it for development, consider using less restrictive "
                            "alternatives."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "quarantine_removed":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Review and restore quarantine flags on suspicious apps",
                        description=(
                            f"The following apps have quarantine flags removed: {app_list}\n"
                            "Restore quarantine flags with: xattr -d com.apple.quarantine /path/to/app\n"
                            "Then verify Gatekeeper assessment with: spctl -a -t execute -vvv /path/to/app\n"
                            "Review each app and determine if the quarantine flag removal was "
                            "legitimate or indicates a security issue."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "gatekeeper_assessment_failed":
                actions.append(
                    Action(
                        title="Verify Gatekeeper functionality",
                        description=(
                            "Run: spctl -a -t execute -vvv /Applications/Safari.app\n"
                            "This tests Gatekeeper's ability to assess app signatures. "
                            "If the test fails, Gatekeeper may not be functioning properly. "
                            "Try: sudo spctl --reset-default\n"
                            "This resets Gatekeeper to default settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_gatekeeper_status(self) -> bool | None:
        """
        Check Gatekeeper status by running: spctl --status
        Returns: True if enabled (assessments enabled), False if disabled, None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/sbin/spctl", "--status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.lower()
            return "enabled" in output
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _check_sip_status(self) -> bool | None:
        """
        Check SIP status by running: csrutil status
        Returns: True if enabled, False if disabled, None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/bin/csrutil", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.lower()
            return "enabled" in output
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _check_quarantine_flags(self) -> list[str]:
        """
        Check for apps in /Applications that have the quarantine flag removed.
        Returns a list of app bundle names (e.g., 'Safari.app') that are missing quarantine.
        """
        apps_without_quarantine = []
        apps_dir = Path("/Applications")

        if not apps_dir.exists():
            return []

        try:
            # Check common system and third-party apps
            check_apps = [
                "Safari.app",
                "Firefox.app",
                "Google Chrome.app",
                "Visual Studio Code.app",
                "Spotify.app",
                "Discord.app",
                "Slack.app",
                "Telegram.app",
                "VLC.app",
            ]

            for app_name in check_apps:
                app_path = apps_dir / app_name
                if not app_path.exists():
                    continue

                # Check if quarantine xattr exists
                try:
                    result = subprocess.run(
                        ["/usr/bin/xattr", "-p", "com.apple.quarantine", str(app_path)],
                        capture_output=True,
                        text=True,
                        timeout=3,
                    )
                    # If xattr returns 0, quarantine flag exists; if 1, it doesn't
                    if result.returncode != 0:
                        # Quarantine flag doesn't exist
                        apps_without_quarantine.append(app_name)
                except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
                    # Unable to check, skip
                    pass

        except Exception:
            pass

        return apps_without_quarantine

    def _test_gatekeeper_assessment(self) -> bool | None:
        """
        Test Gatekeeper by running an assessment on Safari.
        Returns: True if assessment succeeded, False if failed, None if unable to test
        """
        try:
            result = subprocess.run(
                ["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose", "/Applications/Safari.app"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Assessment succeeds if returncode is 0 or output contains accepted/valid indicators
            if result.returncode == 0:
                return True
            output = result.stdout.lower() + result.stderr.lower()
            # Check for indicators of successful assessment
            if "accepted" in output or "valid" in output:
                return True
            # Any output from spctl means it's working, even if the result is "rejected"
            if "rejected" in output or "invalid" in output:
                return True
            return False
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None
