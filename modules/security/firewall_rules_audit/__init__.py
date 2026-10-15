import subprocess
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
    name = "firewall_rules_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.firewall_rules_audit.alf_disabled",
        "security.firewall_rules_audit.stealth_disabled",
        "security.firewall_rules_audit.too_many_apps",
        "security.firewall_rules_audit.allow_signed_enabled",
        "security.firewall_rules_audit.firewall_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check ALF (Application Layer Firewall) status
        alf_enabled = self._get_alf_status()
        stealth_enabled = self._get_stealth_mode()
        allowed_apps = self._get_allowed_apps()
        block_all = self._get_block_all_incoming()
        allow_signed = self._get_allow_signed_software()

        # Flag CRITICAL if firewall is completely off
        if not alf_enabled:
            findings.append(
                Finding(
                    title="Your Mac's firewall is turned off",
                    description=(
                        "Your Mac's built-in firewall is currently off. This means your "
                        "computer is not blocking unwanted connections from other devices "
                        "on your network. "
                        "This is a significant gap in your security, though it does not "
                        "mean someone is currently spying on you.\n\n"
                        "What to do: Open System Settings, go to Network, then click Firewall. "
                        "Turn it on. This is a safe and important step."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.firewall_rules_audit.alf_disabled",
                    data={"check": "alf_disabled"},
                )
            )

        # Flag WARNING if stealth mode is disabled
        if alf_enabled and not stealth_enabled:
            findings.append(
                Finding(
                    title="Your Mac responds to network pings",
                    description=(
                        "Your firewall is on, but 'stealth mode' is off. This means your "
                        "Mac answers when other devices on your network check if it is "
                        "there. "
                        "This is usually a minor issue, but it makes your computer easier "
                        "to find on the network.\n\n"
                        "What to do: Open System Settings > Network > Firewall > Firewall "
                        "Options. Check the box for 'Enable Stealth Mode'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.firewall_rules_audit.stealth_disabled",
                    data={"check": "stealth_disabled"},
                )
            )

        # Flag WARNING if >30 apps are allowed through
        app_count = len(allowed_apps)
        if app_count > 30:
            findings.append(
                Finding(
                    title=f"Many apps are allowed through your firewall ({app_count})",
                    description=(
                        f"Your firewall has exceptions for {app_count} different apps. "
                        "Having many exceptions can weaken your protection because each "
                        "app is allowed to receive connections without you checking every "
                        "time.\n\n"
                        f"Here are a few of the allowed apps: {', '.join(sorted(allowed_apps)[:10])}...\n\n"
                        "What to do: Open System Settings > Network > Firewall > Firewall "
                        "Options. Review the list and remove apps you don't use or don't "
                        "need to connect to the internet."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.firewall_rules_audit.too_many_apps",
                    data={"check": "too_many_apps", "count": app_count, "apps": allowed_apps},
                )
            )

        # Flag WARNING if "automatically allow signed software" is on
        if allow_signed:
            findings.append(
                Finding(
                    title="Firewall automatically allows signed apps",
                    description=(
                        "Your firewall is set to automatically allow any app that has "
                        "a valid digital signature. This is a very permissive setting "
                        "that bypasses your manual review for many apps.\n\n"
                        "What to do: Open System Settings > Network > Firewall > Firewall "
                        "Options. Uncheck 'Automatically allow signed software to receive "
                        "incoming connections'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.firewall_rules_audit.allow_signed_enabled",
                    data={"check": "allow_signed_enabled"},
                )
            )

        # Flag INFO with firewall configuration summary
        config_items = []
        config_items.append(f"ALF Status: {'Enabled' if alf_enabled else 'Disabled'}")
        config_items.append(f"Stealth Mode: {'Enabled' if stealth_enabled else 'Disabled'}")
        config_items.append(f"Block All Incoming: {'Yes' if block_all else 'No'}")
        config_items.append(f"Allow Signed Software: {'Yes' if allow_signed else 'No'}")
        config_items.append(f"Allowed Applications: {app_count}")

        findings.append(
            Finding(
                title="Your firewall settings",
                description="\n".join(config_items),
                severity=Severity.INFO,
                category=self.category,
                code="security.firewall_rules_audit.firewall_summary",
                data={
                    "check": "firewall_summary",
                    "alf_enabled": alf_enabled,
                    "stealth_enabled": stealth_enabled,
                    "block_all": block_all,
                    "allow_signed": allow_signed,
                    "allowed_apps_count": app_count,
                    "allowed_apps": allowed_apps,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "alf_disabled":
                actions.append(
                    Action(
                        title="Enable Application Layer Firewall",
                        description=(
                            "To enable the firewall, open System Settings > Network > Firewall "
                            "and click the 'Turn On Firewall' button. The firewall will then protect "
                            "your system from unwanted network connections."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "stealth_disabled":
                actions.append(
                    Action(
                        title="Enable Stealth Mode",
                        description=(
                            "To enable stealth mode, open System Settings > Network > Firewall > "
                            "Firewall Options and check the 'Enable Stealth Mode' option. "
                            "This prevents your Mac from responding to ping requests."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "too_many_apps":
                app_list = ", ".join(sorted(finding.data.get("apps", [])[:10]))
                actions.append(
                    Action(
                        title="Review and reduce firewall exceptions",
                        description=(
                            f"Too many apps ({finding.data.get('count')}) are allowed through the firewall. "
                            f"Sample apps: {app_list}.\n"
                            "Open System Settings > Network > Firewall Options and review the list of "
                            "apps allowed through the firewall. Remove access for apps that don't need "
                            "network connectivity."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "allow_signed_enabled":
                actions.append(
                    Action(
                        title="Disable automatic allow for signed software",
                        description=(
                            "To disable automatic allow for signed software, open System Settings > "
                            "Network > Firewall > Firewall Options and uncheck the 'Automatically allow "
                            "signed software to receive incoming connections' option. This ensures you "
                            "review each app's network access explicitly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_alf_status(self) -> bool:
        """Check if ALF is enabled via defaults read."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            return result.stdout.strip() == "1"
        except Exception:
            return False

    def _get_stealth_mode(self) -> bool:
        """Check if stealth mode is enabled via defaults read."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "stealthenabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            return result.stdout.strip() == "1"
        except Exception:
            return False

    def _get_allowed_apps(self) -> list[str]:
        """List applications allowed through firewall via socketfilterfw."""
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            apps = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("Automatically allow"):
                    continue
                # Filter out lines that are not app names (e.g., status lines)
                if "(" in line and ")" in line:
                    # Extract app name before the status
                    app_name = line.split("(")[0].strip()
                    if app_name:
                        apps.append(app_name)
            return apps
        except Exception:
            return []

    def _get_block_all_incoming(self) -> bool:
        """Check if 'Block all incoming connections' is on."""
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            return "1" in result.stdout or "enabled" in result.stdout.lower()
        except Exception:
            return False

    def _get_allow_signed_software(self) -> bool:
        """Check if 'Automatically allow signed software' is on."""
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getallowsigned"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            return "1" in result.stdout or "enabled" in result.stdout.lower()
        except Exception:
            return False
