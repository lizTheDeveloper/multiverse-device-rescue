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
from rescue.macos_firewall import (
    parse_allow_signed,
    parse_block_all,
    parse_global_state,
    parse_listapps,
    parse_stealth_mode,
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
        "security.firewall_rules_audit.alf_unknown",
        "security.firewall_rules_audit.stealth_unknown",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Each setting reads as True (on), False (off) or None (couldn't tell).
        # macOS 15+ no longer keeps the state in com.apple.alf.plist (on macOS
        # 26 the file doesn't exist), so reading that plist turned every Mac
        # into "Your Mac's firewall is turned off". socketfilterfw is the
        # source of truth, and an unreadable answer is "couldn't check".
        alf_enabled = self._get_alf_status()
        stealth_enabled = self._get_stealth_mode()
        allowed_apps = self._get_allowed_apps()
        block_all = self._get_block_all_incoming()
        allow_signed = self._get_allow_signed_software()

        if alf_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether your Mac's firewall is on",
                    description=(
                        "Reclaim City couldn't read your Mac's firewall setting, so it "
                        "doesn't know whether the firewall is on or off. This is not a "
                        "sign that anything is wrong.\n\n"
                        "To see for yourself: open System Settings, click Network, then "
                        "look at Firewall."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.firewall_rules_audit.alf_unknown",
                    data={"check": "alf_unknown", "alf_enabled": None},
                )
            )
        elif alf_enabled is False:
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

        # Stealth mode only matters while the firewall is on.
        if alf_enabled is True and stealth_enabled is False:
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
        elif alf_enabled is True and stealth_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check your firewall's stealth mode",
                    description=(
                        "Your firewall is on, but Reclaim City couldn't read whether "
                        "'stealth mode' is on. This is not a sign that anything is wrong."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.firewall_rules_audit.stealth_unknown",
                    data={"check": "stealth_unknown", "stealth_enabled": None},
                )
            )

        # Flag WARNING if >30 apps are allowed through
        app_count = len(allowed_apps) if allowed_apps is not None else None
        allowed_apps = allowed_apps or []
        if app_count is not None and app_count > 30:
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
        if allow_signed is True:
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
        def _say(value, on="On", off="Off"):
            return "Couldn't check" if value is None else (on if value else off)

        config_items = [
            f"Firewall: {_say(alf_enabled)}",
            f"Stealth Mode: {_say(stealth_enabled)}",
            f"Block All Incoming: {_say(block_all, 'Yes', 'No')}",
            f"Allow Signed Software: {_say(allow_signed, 'Yes', 'No')}",
            "Allowed Applications: "
            + ("Couldn't check" if app_count is None else str(app_count)),
        ]

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

    # Each command is written out in full (not built from a flag) so
    # docs/commands.md and `rescue scan --trace` list exactly what runs.
    @staticmethod
    def _stdout(call) -> str | None:
        """stdout of ``call()`` (a subprocess.run), or None if it couldn't run."""
        try:
            result = call()
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    def _get_alf_status(self) -> bool | None:
        """Is the Application Firewall on? None if it couldn't be read."""
        return parse_global_state(self._stdout(lambda: subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True, text=True, timeout=15)))

    def _get_stealth_mode(self) -> bool | None:
        """Is stealth mode on? None if it couldn't be read."""
        return parse_stealth_mode(self._stdout(lambda: subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
            capture_output=True, text=True, timeout=15)))

    def _get_allowed_apps(self) -> list[str] | None:
        """Apps allowed through the firewall; None if the list couldn't be read."""
        return parse_listapps(self._stdout(lambda: subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"],
            capture_output=True, text=True, timeout=15)))

    def _get_block_all_incoming(self) -> bool | None:
        """Is 'Block all incoming connections' on? None if it couldn't be read."""
        return parse_block_all(self._stdout(lambda: subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
            capture_output=True, text=True, timeout=15)))

    def _get_allow_signed_software(self) -> bool | None:
        """Is 'Automatically allow signed software' on? None if unreadable."""
        return parse_allow_signed(self._stdout(lambda: subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getallowsigned"],
            capture_output=True, text=True, timeout=15)))
