import re
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
    name = "keylogger_indicators"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.keylogger_indicators.input_monitoring_access",
        "security.keylogger_indicators.known_keyloggers",
        "security.keylogger_indicators.suspicious_input_monitoring",
        "security.keylogger_indicators.cgeventtap_usage",
    ]

    # Known keylogger process names to flag as CRITICAL
    KNOWN_KEYLOGGERS = {
        "aobo",
        "kidlogger",
        "spyrix",
        "cocospy",
        "mspy",
        "flexispy",
        "hoverwatch",
        "refog",
        "elite_keylogger",
        "perfect_keylogger",
        "ardamax",
    }

    # Well-known apps that legitimately need Input Monitoring
    WELL_KNOWN_INPUT_MONITORING_APPS = {
        "com.apple.Finder",
        "com.apple.systempreferences",
        "com.apple.Systempreferences",
        "com.apple.systemsettings",
        "com.apple.dt.Xcode",
        "com.apple.Terminal",
        "com.googlecode.iterm2",
        "com.sublimetext.3",
        "com.microsoft.VSCode",
        "org.gnu.emacs",
        "org.alacritty",
        "io.wezfurlong.wezterm",
        "com.apple.Automator",
        "com.apple.Script Editor",
        "org.hammerspoon.Hammerspoon",
    }

    # Well-known vendors whose apps legitimately ask for Input Monitoring
    # (game controllers, gaming keyboards/mice, remappers, password managers).
    # These are reported as informational, not as suspicious.
    WELL_KNOWN_VENDOR_PREFIXES = (
        "com.valvesoftware.",  # Steam (controller / Steam Input)
        "com.logitech.",
        "com.logi.",
        "com.razer.",
        "com.corsair.",
        "com.steelseries.",
        "com.elgato.",
        "org.pqrs.",  # Karabiner-Elements
        "com.hegenberg.",  # BetterTouchTool
        "com.1password.",
        "com.agilebits.",
        "com.microsoft.",
        "com.google.",
    )

    def _is_well_known(self, app: str) -> bool:
        return (
            app in self.WELL_KNOWN_INPUT_MONITORING_APPS
            or app.startswith("com.apple.")
            or app.startswith(self.WELL_KNOWN_VENDOR_PREFIXES)
        )

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check 1: Query TCC database for Input Monitoring permissions
        input_monitoring_apps = self._get_input_monitoring_apps()

        if input_monitoring_apps:
            findings.append(
                Finding(
                    title=f"Keyboard access: {len(input_monitoring_apps)} app(s)",
                    description=(
                        f"{len(input_monitoring_apps)} app(s) have been granted Input Monitoring "
                        f"access: {', '.join(sorted(input_monitoring_apps))}. "
                        "Input Monitoring allows apps to capture keyboard and mouse input. "
                        "Review to ensure only trusted apps have this access."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.keylogger_indicators.input_monitoring_access",
                    data={"check": "input_monitoring_access", "apps": sorted(input_monitoring_apps)},
                )
            )

        # Check 2: Flag known keyloggers as CRITICAL
        known_keyloggers_found = []
        for app in input_monitoring_apps:
            for keylogger in self.KNOWN_KEYLOGGERS:
                if keylogger.lower() in app.lower():
                    known_keyloggers_found.append(app)
                    break

        if known_keyloggers_found:
            findings.append(
                Finding(
                    title=f"Known keylogger app found: {', '.join(known_keyloggers_found)}",
                    description=(
                        f"We found {len(known_keyloggers_found)} app(s) with keyboard "
                        f"access that match known spyware: {', '.join(known_keyloggers_found)}. "
                        "These apps can secretly record everything you type, including "
                        "passwords and private messages. This is a serious sign that "
                        "someone may be spying on you.\n\n"
                        "If you think a partner, ex, or family member set this up to "
                        "monitor you, removing it can alert them. Talk to an advocate "
                        "first (US National Domestic Violence Hotline: 1-800-799-7233, "
                        "or text START to 88788).\n\n"
                        "What to do: If you are safe to proceed, go to System Settings "
                        "> Privacy & Security > Input Monitoring and turn off access "
                        "for these apps. Then, move the app folders to a safe location "
                        "to keep as evidence."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.keylogger_indicators.known_keyloggers",
                    data={"check": "known_keyloggers", "apps": known_keyloggers_found},
                )
            )

        # Check 3: Flag suspicious apps with Input Monitoring access
        suspicious_apps = []
        claimed_known_apps = []
        for app in input_monitoring_apps:
            if not self._is_well_known(app):
                suspicious_apps.append(app)
            else:
                claimed_known_apps.append(app)

        # A bundle ID is just a string any app can choose, so a familiar-looking
        # ID is never proof of who made the app. Keep these visible (info), never drop.
        if claimed_known_apps:
            findings.append(
                Finding(
                    title=(
                        f"Keyboard access: {len(claimed_known_apps)} app(s) with familiar names"
                    ),
                    description=(
                        f"These app(s) have Input Monitoring access and use the name of a "
                        f"familiar company or app: {', '.join(sorted(claimed_known_apps))}. "
                        "This tool has not verified who actually made them, because an app can "
                        "pick any name. If you don't remember installing one, turn its access "
                        "off in System Settings > Privacy & Security > Input Monitoring."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={
                        "check": "claimed_vendor_input_monitoring",
                        "apps": sorted(claimed_known_apps),
                    },
                )
            )

        if suspicious_apps:
            findings.append(
                Finding(
                    title=(
                        f"Unrecognized apps have keyboard access: {', '.join(sorted(suspicious_apps))}"
                    ),
                    description=(
                        f"{len(suspicious_apps)} app(s) have permission to see your keyboard "
                        f"input, but we don't recognize them: {', '.join(sorted(suspicious_apps))}. "
                        "Many normal tools (like keyboard remappers or game launchers) "
                        "ask for this, so it is not automatically a sign of spying. However, "
                        "if you do not remember installing one, it is worth checking.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Go to System Settings > Privacy & Security > Input "
                        "Monitoring. Turn off access for any app you don't recognize "
                        "or didn't install yourself."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={"check": "suspicious_input_monitoring", "apps": suspicious_apps},
                )
            )

        # Check 4: Check for CGEventTap usage
        cgeventtap_processes = self._check_cgeventtap_usage()
        if cgeventtap_processes:
            findings.append(
                Finding(
                    title=(
                        f"Apps are actively capturing your keystrokes: {', '.join(sorted(cgeventtap_processes))}"
                    ),
                    description=(
                        f"{len(cgeventtap_processes)} running process(es) are currently "
                        f"using a system tool to capture your keyboard and mouse: {', '.join(sorted(cgeventtap_processes))}. "
                        "This means these programs are actively listening to your input "
                        "right now. While some legitimate tools do this, it is a common "
                        "method for spyware to steal passwords.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Check if you recognize these names. If not, go to "
                        "System Settings > Privacy & Security > Input Monitoring and "
                        "turn off access for the corresponding apps to stop the capture."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.cgeventtap_usage",
                    data={"check": "cgeventtap_usage", "processes": sorted(cgeventtap_processes)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "input_monitoring_access":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Review and manage Input Monitoring access",
                        description=(
                            f"Apps with Input Monitoring access: {app_list}.\n"
                            "To manage Input Monitoring permissions, open System Settings > "
                            "Privacy & Security > Input Monitoring. Review each app and "
                            "toggle off access for apps you don't trust or don't need."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "known_keyloggers":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Remove known keyloggers immediately",
                        description=(
                            f"Known keylogger application(s) found: {app_list}.\n"
                            "IMMEDIATE ACTION REQUIRED:\n"
                            "1. Disconnect from the internet to prevent data exfiltration\n"
                            "2. Boot into Safe Mode or Safe Boot\n"
                            "3. Use Malwarebytes, CleanMyMac, or similar anti-malware to remove\n"
                            "4. Revoke all permissions in System Settings > Privacy & Security\n"
                            "5. Change all passwords from a clean device\n"
                            "6. Consider professional help if the malware persists\n\n"
                            "These applications steal passwords, credit cards, and private messages."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "suspicious_input_monitoring":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Revoke Input Monitoring access from suspicious apps",
                        description=(
                            f"Suspicious apps with Input Monitoring access: {app_list}.\n"
                            "To revoke access, open System Settings > Privacy & Security > "
                            "Input Monitoring and remove these apps from the list. If you "
                            "installed any of these apps, consider uninstalling them using "
                            "System Settings > General > Software > AppName > Remove, or "
                            "by dragging the app to Trash."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "cgeventtap_usage":
                processes = finding.data.get("processes", [])
                processes_list = ", ".join(processes)
                actions.append(
                    Action(
                        title="Investigate CGEventTap usage",
                        description=(
                            f"Processes using CGEventTap: {processes_list}.\n"
                            "CGEventTap allows capturing keyboard and mouse events. To investigate:\n"
                            "1. Research these processes to understand their legitimate purpose\n"
                            "2. Use Activity Monitor to examine process details\n"
                            "3. Check System Settings > Privacy & Security for Input Monitoring access\n"
                            "4. Uninstall or disable applications using CGEventTap if not trusted\n"
                            "5. Consider running anti-malware scans if usage is suspicious"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_input_monitoring_apps(self) -> list[str]:
        """Query TCC database for apps with Input Monitoring access.

        Returns list of app bundle identifiers with Input Monitoring access.
        Returns [] on any failure (permission denied, file not found, etc).
        """
        try:
            system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
            user_db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

            apps = []
            seen = set()

            # Query system database
            for db_path in [system_db, user_db]:
                try:
                    result = subprocess.run(
                        [
                            "sqlite3",
                            db_path,
                            "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        for line in result.stdout.strip().split("\n"):
                            if line and line not in seen:
                                apps.append(line)
                                seen.add(line)
                except Exception:
                    pass

            return apps
        except Exception:
            return []

    def _check_cgeventtap_usage(self) -> list[str]:
        """Check for CGEventTap usage in system logs.

        Returns list of processes using CGEventTap.
        Returns [] on any failure.
        """
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--last",
                    "1h",
                    "--predicate",
                    "eventMessage CONTAINS 'CGEventTap'",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            return _cgeventtap_processes(result.stdout)
        except Exception:
            return []


# `log show --style compact` lines look like
#   2026-10-15 04:10:01.123 Df loginwindow[123:456] message ...
# after a "Timestamp  Ty  Process[PID:TID]" header. The process name sits
# between the type column and "[pid", and may contain spaces.
_COMPACT_LOG_LINE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\S+\s+\S+\s+(.+?)\[\d+")


def _cgeventtap_processes(output: str) -> list[str]:
    """Process names from compact log lines; headers and noise are skipped."""
    names = set()
    for line in (output or "").splitlines():
        m = _COMPACT_LOG_LINE.match(line.strip())
        if m:
            names.add(m.group(1).strip())
    return sorted(names)
