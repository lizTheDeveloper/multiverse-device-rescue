import plistlib
import re
from pathlib import Path
from shlex import quote

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

    emits_codes = [
        "security.scheduled_tasks_audit.suspicious_launch_agent",
        "security.scheduled_tasks_audit.disabled_launch_agent",
        "security.scheduled_tasks_audit.launch_agent_info",
        "security.scheduled_tasks_audit.excessive_user_agents",
    ]

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
                    title=f"{user_agent_count} background items set up for your user",
                    description=(
                        f"Found {user_agent_count} user-level launch agents. "
                        "Apps, updaters and developer tools (such as Homebrew services) "
                        "each add one, so a high number is common and not a problem by "
                        "itself. Many at once can slightly slow login, and you may "
                        "want to remove ones left behind by apps you uninstalled. "
                        "Anything that looks wrong is reported separately."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.scheduled_tasks_audit.excessive_user_agents",
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
                            f"  launchctl unload ~/Library/LaunchAgents/{quote(str(label) + '.plist')}\n"
                            f"  rm ~/Library/LaunchAgents/{quote(str(label) + '.plist')}"
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
                            "This is common and usually harmless; many at once can "
                            "slightly slow login.\n\n"
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

    # "agent_type" is the scan location. Use a readable noun in titles so a
    # user agent reads "launch agent (yours)" rather than "launch user".
    _TYPE_NOUNS = {
        "user": "agent (yours)",
        "system": "agent (all users)",
        "daemon": "daemon (system-wide)",
    }

    def _scan_launch_agents(self, directory: Path, agent_type: str) -> list[Finding]:
        """Scan a directory for launch agents/daemons and parse plists."""
        findings = []
        noun = self._TYPE_NOUNS.get(agent_type, agent_type)

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

                if not isinstance(plist_data, dict):
                    raise ValueError("plist root is not a dictionary")
                # Values come from a file anyone can write: never assume types.
                label = plist_data.get("Label", plist_path.stem)
                label = label if isinstance(label, str) and label else plist_path.stem
                program = plist_data.get("Program", "")
                raw_args = plist_data.get("ProgramArguments", [])
                if isinstance(program, (list, tuple)):
                    program = " ".join(str(a) for a in program)
                elif not isinstance(program, str):
                    program = str(program) if program else ""
                if isinstance(raw_args, str):
                    program_args = [raw_args]
                elif isinstance(raw_args, (list, tuple)):
                    program_args = [str(a) for a in raw_args]
                else:
                    program_args = []
                disabled = plist_data.get("Disabled", False) is True

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
                            title=f"Turned-off background item: {label}",
                            description=(
                                f"Launch {noun} is disabled but still on disk: {label}\n"
                                f"Location: {plist_path}\n"
                                "This is clutter—consider deleting it."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            code="security.scheduled_tasks_audit.disabled_launch_agent",
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
                            title=f"Check this startup item: {label}",
                            description=(
                                f"We found a startup item named {label} that runs automatically. "
                                f"It looks unusual because: {reason}.\n\n"
                                f"Details: {command} (Location: {plist_path})\n\n"
                                "This is not proof of a hack, but it is worth checking. "
                                "If you do not recognize this name, it may be leftover "
                                "clutter or a tool you forgot about.\n\n"
                                "What to do: Open Finder, press Command+Shift+G, and "
                                "paste the location path above. If you do not recognize "
                                "the file, move it to a new folder on your Desktop to "
                                "disable it safely. Do not delete it yet."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.scheduled_tasks_audit.suspicious_launch_agent",
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
                            title=f"Background item: {label}",
                            description=(
                                f"Launch {noun} found: {label}\n"
                                f"Command: {command}\n"
                                f"Location: {plist_path}\n"
                                "Verify this is from a trusted source."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            code="security.scheduled_tasks_audit.launch_agent_info",
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
                # A file we cannot read is still something that sits in a launch
                # folder, so list it rather than hiding it from the report.
                findings.append(
                    Finding(
                        title=f"Background item file unreadable: {plist_path.name}",
                        description=(
                            f"This tool could not read {plist_path}. It may be damaged or "
                            "in an unusual format. If you do not recognize it, "
                            "check where it came from."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.scheduled_tasks_audit.launch_agent_info",
                        data={
                            "check": "launch_agent_info",
                            "label": plist_path.stem,
                            "location": str(plist_path),
                            "type": agent_type,
                            "command": "(unreadable)",
                        },
                    )
                )

        return findings

    def _check_suspicious(
        self, label: str, program: str, program_args: list, plist_data: dict
    ) -> tuple[bool, str]:
        """Check if a launch agent/daemon exhibits suspicious characteristics."""
        reasons = []

        # World-writable or throwaway locations. These are writable by any
        # program, so whatever appears there runs as the user, even if the file
        # is missing now. This is judged on the path alone: a label such as
        # com.apple.* or com.google.* is just text anyone can choose.
        check_paths = ([program] if isinstance(program, str) and program else []) + (
            [a for a in program_args if isinstance(a, str)]
            if isinstance(program_args, (list, tuple))
            else []
        )
        writable_re = re.compile(
            r"(?:^|[\s\"'=;|&(:])(?:(?:/private)?/(?:var/)?tmp(?=[/\s\"';|&)]|$)|/Users/Shared/)"
        )

        for path in check_paths:
            path = path.strip().strip("\"'")
            if writable_re.search(path):
                reasons.append(
                    f"runs from {path}, a folder any program on this Mac can write "
                    "to (whatever is placed there runs automatically as you)"
                )
                break
            if "Downloads" in path.split("/") or "Temp" in path.split("/"):
                reasons.append(f"runs from a downloads/temporary folder: {path}")
                break

        # Writable-location reasons always flag, whatever the label says.
        if any("any program on this Mac can write" in r for r in reasons):
            return True, " | ".join(reasons)

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
