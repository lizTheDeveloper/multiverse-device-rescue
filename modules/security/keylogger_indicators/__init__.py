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
        "security.keylogger_indicators.keyboard_hooks",
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

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check 1: Query TCC database for Input Monitoring permissions
        input_monitoring_apps = self._get_input_monitoring_apps()

        if input_monitoring_apps:
            findings.append(
                Finding(
                    title=f"Input Monitoring access: {len(input_monitoring_apps)} app(s)",
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
                    title=f"CRITICAL: Known keylogger(s) detected: {len(known_keyloggers_found)}",
                    description=(
                        f"One or more known keylogger applications have Input Monitoring access: "
                        f"{', '.join(known_keyloggers_found)}. "
                        "These are malicious applications that steal passwords, credit cards, and "
                        "private messages. Immediately remove these apps and revoke their permissions."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.keylogger_indicators.known_keyloggers",
                    data={"check": "known_keyloggers", "apps": known_keyloggers_found},
                )
            )

        # Check 3: Flag suspicious apps with Input Monitoring access
        suspicious_apps = []
        for app in input_monitoring_apps:
            if app not in self.WELL_KNOWN_INPUT_MONITORING_APPS and not app.startswith("com.apple."):
                suspicious_apps.append(app)

        if suspicious_apps:
            findings.append(
                Finding(
                    title=f"Suspicious Input Monitoring access: {len(suspicious_apps)} app(s)",
                    description=(
                        f"{len(suspicious_apps)} unknown or suspicious app(s) have Input Monitoring "
                        f"access: {', '.join(sorted(suspicious_apps))}. "
                        "These apps may not be trusted applications. Input Monitoring is often abused "
                        "by spyware to capture sensitive information. Investigate and revoke access "
                        "for apps you don't recognize or trust."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.suspicious_input_monitoring",
                    data={"check": "suspicious_input_monitoring", "apps": suspicious_apps},
                )
            )

        # Check 4: Check for keyboard event hooks via ioreg
        keyboard_hooks = self._check_keyboard_hooks()
        if keyboard_hooks:
            findings.append(
                Finding(
                    title=f"Keyboard event hooks detected: {len(keyboard_hooks)} instance(s)",
                    description=(
                        f"Detected {len(keyboard_hooks)} keyboard event hook(s) in the system. "
                        "These could indicate keylogging activity. Hooks detected: "
                        f"{', '.join(keyboard_hooks)}. "
                        "Investigate the source and purpose of these hooks."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.keylogger_indicators.keyboard_hooks",
                    data={"check": "keyboard_hooks", "hooks": keyboard_hooks},
                )
            )

        # Check 5: Check for CGEventTap usage
        cgeventtap_processes = self._check_cgeventtap_usage()
        if cgeventtap_processes:
            findings.append(
                Finding(
                    title=f"CGEventTap usage detected: {len(cgeventtap_processes)} process(es)",
                    description=(
                        f"Detected {len(cgeventtap_processes)} process(es) using CGEventTap for "
                        "programmatic keyboard/mouse capture: "
                        f"{', '.join(sorted(cgeventtap_processes))}. "
                        "CGEventTap allows capturing system input events. Investigate processes "
                        "using this API to ensure they are legitimate."
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
            elif check == "keyboard_hooks":
                hooks = finding.data.get("hooks", [])
                hooks_list = ", ".join(hooks)
                actions.append(
                    Action(
                        title="Investigate keyboard event hooks",
                        description=(
                            f"Keyboard event hooks detected: {hooks_list}.\n"
                            "These hooks may indicate keylogging activity. To investigate:\n"
                            "1. Use Activity Monitor to identify which processes are using hooks\n"
                            "2. Search for the hook names online to understand their purpose\n"
                            "3. Uninstall suspicious applications\n"
                            "4. Run anti-malware scans if hooks are not from trusted apps\n"
                            "5. Consider expert help if hooks persist after cleanup"
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

    def _check_keyboard_hooks(self) -> list[str]:
        """Check for keyboard event hooks via ioreg.

        Returns list of detected keyboard hooks.
        Returns [] on any failure.
        """
        try:
            result = subprocess.run(
                ["ioreg", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            hooks = []
            for line in result.stdout.split("\n"):
                if "HIDKeyboard" in line or "KeyboardEventTap" in line:
                    hooks.append(line.strip())

            return hooks[:10] if hooks else []  # Limit to first 10 to avoid noise
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

            processes = set()
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    # Extract process name from log line (first field or whole line if short)
                    parts = line.split()
                    if parts:
                        processes.add(parts[0])

            return list(processes)
        except Exception:
            return []
