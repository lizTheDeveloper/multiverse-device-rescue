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
    name = "launch_agent_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.launch_agent_audit.too_many_agents",
        "security.launch_agent_audit.agent_info",
        "security.launch_agent_audit.suspicious_path",
        "security.launch_agent_audit.missing_program",
        "security.launch_agent_audit.obfuscated_name",
    ]

    WORLD_WRITABLE_PREFIXES = (
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/Users/Shared/",
        "/dev/shm/",
    )

    # Hidden folders that developer tools (version managers, virtualenvs,
    # package managers) use for their own programs. These are ordinary.
    DEVELOPER_TOOL_DIRS = {
        ".nvm", ".venv", "venv", ".pyenv", ".asdf", ".volta", ".bun", ".local",
        ".cargo", ".rustup", ".rbenv", ".rvm", ".fnm", ".npm", ".npm-global",
        ".deno", ".sdkman", ".pnpm", ".nodenv", ".goenv", ".gem", ".conda",
        ".virtualenvs", ".pipx", ".uv", ".mise", ".config", "virtualenv",
    }

    # Standard system locations where short program names (sh, ls) are normal.
    SYSTEM_BIN_DIRS = (
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
        "/opt/homebrew/bin/", "/opt/homebrew/opt/",
    )

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan both user and system LaunchAgents directories
        user_agents = self._scan_launch_agents_dir(
            Path.home() / "Library" / "LaunchAgents"
        )
        system_agents = self._scan_launch_agents_dir(
            Path("/Library/LaunchAgents")
        )

        all_agents = user_agents + system_agents

        # Many user launch agents is normal on a developer machine (every
        # Homebrew service, updater and background tool adds one), so this is
        # only a heads-up, not a warning.
        if len(user_agents) > 20:
            findings.append(
                Finding(
                    title=f"{len(user_agents)} background items start automatically for your user",
                    description=(
                        f"Found {len(user_agents)} launch agents in ~/Library/LaunchAgents. "
                        "Apps, updaters and developer tools (such as Homebrew services) "
                        "each add one, so a high number is common on a Mac with lots of "
                        "software. This is not a sign of a problem by itself; any "
                        "individual item that looks wrong is reported separately."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.launch_agent_audit.too_many_agents",
                    data={"check": "too_many_agents", "count": len(user_agents)},
                )
            )

        # Process each agent
        for label, program_path, arguments in all_agents:
            # Flag INFO for each found agent
            findings.append(
                Finding(
                    title=f"Launch agent found: {label}",
                    description=f"Program path: {program_path}",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.launch_agent_audit.agent_info",
                    data={
                        "check": "agent_info",
                        "label": label,
                        "program": program_path,
                    },
                )
            )

            # Check for suspicious characteristics
            suspicious_findings = self._check_suspicious_agent(label, program_path, arguments)
            findings.extend(suspicious_findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "too_many_agents":
                actions.append(
                    Action(
                        title="Review user launch agents for adware",
                        description=(
                            "To review and remove suspicious user launch agents:\n"
                            "1. Open ~/Library/LaunchAgents/\n"
                            "2. Check each .plist file for suspicious names or vendors\n"
                            "3. Remove suspicious files and restart\n"
                            "4. Use Activity Monitor to identify unknown processes"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "suspicious_path":
                agent_label = finding.data.get("label", "unknown")
                program_path = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Investigate suspicious agent: {agent_label}",
                        description=(
                            f"The launch agent '{agent_label}' points to a suspicious "
                            f"location: {program_path}\n\n"
                            "To remove this agent:\n"
                            f"1. launchctl unload ~/Library/LaunchAgents/{agent_label}.plist\n"
                            f"2. rm ~/Library/LaunchAgents/{agent_label}.plist\n"
                            "3. Restart your Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "missing_program":
                agent_label = finding.data.get("label", "unknown")
                program_path = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Investigate broken agent: {agent_label}",
                        description=(
                            f"The launch agent '{agent_label}' references a program "
                            f"that does not exist: {program_path}\n\n"
                            "This is usually left over from an uninstalled app. "
                            "If you do not recognize it, to remove this agent:\n"
                            f"1. launchctl unload ~/Library/LaunchAgents/{agent_label}.plist\n"
                            f"2. rm ~/Library/LaunchAgents/{agent_label}.plist\n"
                            "3. Restart your Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "obfuscated_name":
                agent_label = finding.data.get("label", "unknown")
                program_path = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Investigate obfuscated agent: {agent_label}",
                        description=(
                            f"The launch agent '{agent_label}' has an obfuscated name "
                            f"and points to: {program_path}\n\n"
                            "Obfuscated names are common in malware. To investigate:\n"
                            "1. Check the program path with: file <path>\n"
                            "2. Check with: codesign -v <path>\n"
                            "3. If suspicious, remove as above"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_launch_agents_dir(
        self, directory: Path
    ) -> list[tuple[str, str, list[str]]]:
        """Scan a LaunchAgents directory; return (label, program, arguments) tuples."""
        agents = []

        if not directory.exists():
            return agents

        try:
            plist_paths = sorted(directory.glob("*.plist"))
        except Exception:
            return agents

        for plist_path in plist_paths:
            label, program, arguments = self._extract_from_plist(str(plist_path))
            if label and program:
                agents.append((label, program, arguments))

        return agents

    @staticmethod
    def _extract_from_plist(
        plist_path: str,
    ) -> tuple[str | None, str | None, list[str]]:
        """Read Label and the program (Program, else ProgramArguments[0]) with plistlib."""
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return None, None, []
        if not isinstance(data, dict):
            return None, None, []

        label = data.get("Label")
        if not isinstance(label, str) or not label:
            return None, None, []

        args = data.get("ProgramArguments")
        arguments = [str(a) for a in args] if isinstance(args, list) else []
        program = data.get("Program")
        if not isinstance(program, str) or not program:
            program = arguments[0] if arguments else None
        if not program:
            return None, None, []
        return label, program.strip().strip("\"'"), arguments

    def _check_suspicious_agent(
        self, label: str, program_path: str, arguments: list[str] | None = None
    ) -> list[Finding]:
        """Check if an agent has suspicious characteristics."""
        findings = []
        arguments = arguments or []

        writable = next(
            (
                str(c).strip().strip("\"'")
                for c in [program_path, *arguments]
                if str(c).strip().strip("\"'").startswith(self.WORLD_WRITABLE_PREFIXES)
            ),
            None,
        )
        parts = [p for p in program_path.split("/") if p]
        unusual_hidden = (
            not any(
                p in self.DEVELOPER_TOOL_DIRS
                or p.lower().startswith((".venv", "venv"))
                or p.lower().endswith("venv")
                for p in parts
            )
            and any(p.startswith(".") and p not in (".", "..") for p in parts)
        )

        if writable:
            findings.append(
                Finding(
                    title=f"Launch agent runs from a world-writable folder: {label}",
                    description=(
                        f"The launch agent '{label}' runs {writable}, which is in a "
                        "folder (such as /tmp) that any program on this Mac can write "
                        "to. Whatever is placed there will run automatically as you, "
                        "even if the file does not exist right now."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.launch_agent_audit.suspicious_path",
                    data={
                        "check": "suspicious_path",
                        "label": label,
                        "program": program_path,
                    },
                )
            )
        elif unusual_hidden:
            findings.append(
                Finding(
                    title=f"Launch agent runs from a hidden folder: {label}",
                    description=(
                        f"The launch agent '{label}' runs a program inside a hidden "
                        f"folder: {program_path}\n"
                        "Some apps do this legitimately, but check that you recognize it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.launch_agent_audit.suspicious_path",
                    data={
                        "check": "suspicious_path",
                        "label": label,
                        "program": program_path,
                    },
                )
            )

        # Very short program names can be a sign of obfuscation, but not for
        # standard system tools such as /bin/sh.
        program_name = Path(program_path).name
        if (
            len(program_name) <= 2
            and not program_name.startswith(".")
            and not program_path.startswith(self.SYSTEM_BIN_DIRS)
        ):
            findings.append(
                Finding(
                    title=f"Launch agent with obfuscated name: {label}",
                    description=(
                        f"The launch agent '{label}' points to a program with a "
                        f"very short name: {program_name}\n"
                        "Very short, meaningless names are sometimes used to hide "
                        "unwanted software. Check that you recognize it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.launch_agent_audit.obfuscated_name",
                    data={
                        "check": "obfuscated_name",
                        "label": label,
                        "program": program_path,
                    },
                )
            )

        # Missing program (only for absolute paths; bare names are looked up
        # on PATH by launchd).
        try:
            program_path_obj = Path(program_path).expanduser()
            if program_path_obj.is_absolute() and not program_path_obj.exists():
                findings.append(
                    Finding(
                        title=f"Launch agent program does not exist: {label}",
                        description=(
                            f"The launch agent '{label}' points to a program that "
                            f"cannot be found: {program_path}\n"
                            "This is usually left over from an app that was uninstalled. "
                            "If you do not recognize the name, it is worth a closer look."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.launch_agent_audit.missing_program",
                        data={
                            "check": "missing_program",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )
        except Exception:
            pass

        return findings
