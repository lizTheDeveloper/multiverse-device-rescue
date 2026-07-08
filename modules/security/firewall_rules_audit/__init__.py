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
                    title="Application Layer Firewall is disabled",
                    description=(
                        "The macOS Application Layer Firewall (ALF) is not enabled. "
                        "The firewall provides basic protection against unwanted network access. "
                        "Enable it in System Settings > Network > Firewall."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "alf_disabled"},
                )
            )

        # Flag WARNING if stealth mode is disabled
        if alf_enabled and not stealth_enabled:
            findings.append(
                Finding(
                    title="Stealth mode is disabled",
                    description=(
                        "Stealth mode is disabled. Your Mac will respond to ping requests, "
                        "revealing its presence on the network. Enable stealth mode in "
                        "System Settings > Network > Firewall > Firewall Options."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "stealth_disabled"},
                )
            )

        # Flag WARNING if >30 apps are allowed through
        app_count = len(allowed_apps)
        if app_count > 30:
            findings.append(
                Finding(
                    title=f"Too many apps allowed through firewall ({app_count})",
                    description=(
                        f"{app_count} applications are allowed through the firewall. "
                        "Excessive exceptions weaken the firewall's protection. "
                        "Review and remove access for apps that don't need network access. "
                        f"Allowed apps: {', '.join(sorted(allowed_apps)[:10])}..."
                        if len(allowed_apps) > 10 else f"Allowed apps: {', '.join(sorted(allowed_apps))}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "too_many_apps", "count": app_count, "apps": allowed_apps},
                )
            )

        # Flag WARNING if "automatically allow signed software" is on
        if allow_signed:
            findings.append(
                Finding(
                    title="Automatically allow signed software is enabled",
                    description=(
                        "The firewall is set to automatically allow signed software. "
                        "This is overly permissive and allows any validly signed app through "
                        "without user review. Disable this in System Settings > Network > "
                        "Firewall > Firewall Options."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                title="Firewall configuration summary",
                description="\n".join(config_items),
                severity=Severity.INFO,
                category=self.category,
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
