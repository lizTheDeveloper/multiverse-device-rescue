import plistlib
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
    name = "scheduled_tasks_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan user-level agents
        user_agents = self._scan_launch_agents(
            Path.home() / "Library/LaunchAgents", "user"
        )
        findings.extend(user_agents)

        # Scan system-level agents
        system_agents = self._scan_launch_agents(
            Path("/Library/LaunchAgents"), "system"
        )
        findings.extend(system_agents)

        # Scan system daemons
        daemons = self._scan_launch_agents(Path("/Library/LaunchDaemons"), "daemon")
        findings.extend(daemons)

        # Check for excessive user-level agents
        user_agent_count = len(user_agents)
        if user_agent_count > 20:
            findings.append(
                Finding(
                    title=f"Excessive user launch agents ({user_agent_count})",
                    description=(
                        f"Found {user_agent_count} user-level launch agents. "
                        "More than 20 agents can slow down system boot time. "
                        "Review and remove unnecessary or unused agents."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "excessive_user_agents",
                        "count": user_agent_count,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "suspicious_launch_agent":
                label = finding.data.get("label", "")
                reason = finding.data.get("reason", "")
                actions.append(
                    Action(
                        title=f"Review suspicious launch agent: {label}",
                        description=(
                            f"Suspicious launch agent detected: {label}\n"
                            f"Reason: {reason}\n\n"
                            "To review and remove this agent:\n"
                            "1. Open Finder > Library/LaunchAgents (or /Library/LaunchAgents)\n"
                            "2. Find the plist file matching this label\n"
                            "3. Review its contents in a text editor\n"
                            "4. Delete if confirmed as malicious\n\n"
                            "Or from terminal:\n"
                            f"  launchctl unload ~/Library/LaunchAgents/{label}.plist\n"
                            f"  rm ~/Library/LaunchAgents/{label}.plist"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "disabled_launch_agent":
                label = finding.data.get("label", "")
                actions.append(
                    Action(
                        title=f"Review disabled launch agent clutter: {label}",
                        description=(
                            f"Disabled launch agent still present: {label}\n\n"
                            "This agent is disabled but the plist file is still on disk. "
                            "To clean up:\n"
                            "1. Find the plist file in Finder or terminal\n"
                            "2. Delete the plist if you no longer need it\n"
                            "3. This will free a tiny amount of disk space and reduce clutter"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "excessive_user_agents":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Review and reduce excessive user launch agents ({count})",
                        description=(
                            f"Found {count} user-level launch agents. "
                            "More than 20 agents can slow down system boot.\n\n"
                            "To review:\n"
                            "1. Open: ~/Library/LaunchAgents in Finder\n"
                            "2. Review each plist file\n"
                            "3. Delete ones from apps you've uninstalled\n"
                            "4. Disable ones you don't need by removing or editing them\n\n"
                            "Or from terminal:\n"
                            "  ls -la ~/Library/LaunchAgents"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "launch_agent_info":
                label = finding.data.get("label", "")
                location = finding.data.get("location", "")
                actions.append(
                    Action(
                        title=f"Launch agent: {label}",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_launch_agents(self, directory: Path, agent_type: str) -> list[Finding]:
        """Scan a directory for launch agents/daemons and parse plists."""
        findings = []

        if not directory.exists():
            return findings

        try:
            plist_files = list(directory.glob("*.plist"))
        except Exception:
            return findings

        for plist_path in plist_files:
            try:
                with open(plist_path, "rb") as f:
                    plist_data = plistlib.load(f)

                label = plist_data.get("Label", plist_path.stem)
                program = plist_data.get("Program", "")
                program_args = plist_data.get("ProgramArguments", [])
                disabled = plist_data.get("Disabled", False)

                # Build command string for display
                if program:
                    command = program
                elif program_args:
                    command = " ".join(str(arg) for arg in program_args[:2])
                else:
                    command = "(no program specified)"

                # Check for suspicious indicators
                is_suspicious, reason = self._check_suspicious(
                    label, program, program_args, plist_data
                )

                if disabled:
                    findings.append(
                        Finding(
                            title=f"Disabled launch {agent_type}: {label}",
                            description=(
                                f"Launch {agent_type} is disabled but still on disk: {label}\n"
                                f"Location: {plist_path}\n"
                                "This is clutter—consider deleting it."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "disabled_launch_agent",
                                "label": label,
                                "location": str(plist_path),
                                "type": agent_type,
                            },
                        )
                    )
                elif is_suspicious:
                    findings.append(
                        Finding(
                            title=f"Suspicious launch {agent_type}: {label}",
                            description=(
                                f"Suspicious launch {agent_type} detected: {label}\n"
                                f"Command: {command}\n"
                                f"Location: {plist_path}\n"
                                f"Reason: {reason}\n\n"
                                f"This {agent_type} exhibits suspicious characteristics. "
                                "Review and delete if confirmed as malicious."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "suspicious_launch_agent",
                                "label": label,
                                "reason": reason,
                                "location": str(plist_path),
                                "type": agent_type,
                                "command": command,
                            },
                        )
                    )
                else:
                    # Log legitimate agents as INFO
                    findings.append(
                        Finding(
                            title=f"Launch {agent_type}: {label}",
                            description=(
                                f"Launch {agent_type} found: {label}\n"
                                f"Command: {command}\n"
                                f"Location: {plist_path}\n"
                                "Verify this is from a trusted source."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "launch_agent_info",
                                "label": label,
                                "location": str(plist_path),
                                "type": agent_type,
                                "command": command,
                            },
                        )
                    )

            except Exception:
                # Skip files that can't be parsed
                pass

        return findings

    def _check_suspicious(
        self, label: str, program: str, program_args: list, plist_data: dict
    ) -> tuple[bool, str]:
        """Check if a launch agent/daemon exhibits suspicious characteristics."""
        reasons = []

        # Check for suspicious paths (temp, downloads, user-writable locations)
        suspicious_paths = ["/tmp", "/var/tmp", "Downloads", "Temp"]
        check_paths = [program] + program_args if isinstance(program_args, list) else []

        for path in check_paths:
            if isinstance(path, str):
                if any(sp in path for sp in suspicious_paths):
                    reasons.append(f"runs from suspicious path: {path}")
                    break

        # Check for obfuscated labels (very short, all numbers, unusual chars)
        if len(label) < 5 and label.replace("_", "").replace("-", "").isdigit():
            reasons.append("label is obfuscated (numeric/very short)")

        # Check if it's a known Apple/legitimate agent
        apple_prefixes = [
            "com.apple",
            "com.google",
            "org.nodejs",
            "com.docker",
            "com.spotify",
            "com.slack",
        ]
        is_known = any(label.startswith(p) for p in apple_prefixes)

        # If not from known publisher and has suspicious path, flag it
        if not is_known and reasons:
            return True, " | ".join(reasons)

        # Check for run-in-background with suspicious program
        if plist_data.get("RunAtLoad") and not is_known and program:
            if program.endswith((".sh", ".py")) and not any(
                p in program for p in ["/usr/local/bin", "/opt", "/Applications"]
            ):
                reasons.append("unknown publisher with auto-run enabled")
                return True, " | ".join(reasons)

        return False, ""
