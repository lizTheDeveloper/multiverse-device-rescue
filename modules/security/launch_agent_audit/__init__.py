import os
import plistlib
import posixpath
import re
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

    # SIP-protected locations where short program names (sh, ls) are normal.
    # /usr/local and /opt/homebrew are writable by non-root users, so they are
    # deliberately not here.
    SYSTEM_BIN_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")

    _WRITABLE_RE = re.compile(
        r"(?:^|[\s\"'=;|&(:])(?:(?:/private)?/(?:var/)?tmp(?=[/\s\"';|&)]|$)"
        r"|/Users/Shared/|/dev/shm/)"
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
                    description=(
                        f"Program path: {program_path}"
                        if program_path
                        else "This tool could not read a program from this launch agent file "
                        "(it may be damaged or in an unusual format). If you do not "
                        "recognize it, check where it came from."
                    ),
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
            if program_path:
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
            agents.append((label, program, arguments))

        return agents

    @staticmethod
    def _extract_from_plist(
        plist_path: str,
    ) -> tuple[str, str, list[str]]:
        """Read Label and the program (Program, else ProgramArguments[0]) with plistlib.

        Never drops an agent: unreadable files or unexpected value types come
        back with an empty program so the caller can still list them.
        """
        stem = Path(plist_path).stem
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return stem, "", []
        if not isinstance(data, dict):
            return stem, "", []

        label = data.get("Label")
        if not isinstance(label, str) or not label:
            label = stem

        args = data.get("ProgramArguments")
        if isinstance(args, str):
            args = [args]
        arguments = [str(a) for a in args] if isinstance(args, (list, tuple)) else []
        program = data.get("Program")
        if isinstance(program, (list, tuple)):
            program = " ".join(str(a) for a in program)
        elif program and not isinstance(program, str):
            program = str(program)
        if not program:
            program = arguments[0] if arguments else ""
        return label, program.strip().strip("\"'"), arguments

    @staticmethod
    def _path_forms(candidate: str) -> list[str]:
        """Absolute normalized and symlink-resolved forms of a path-looking string."""
        c = str(candidate).strip().strip("\"'")
        if not (c.startswith("/") or c.startswith("~")):
            return []
        try:
            expanded = posixpath.normpath(os.path.expanduser(c))
            forms = [expanded]
            real = os.path.realpath(expanded)
            if real != expanded:
                forms.append(real)
            return forms
        except Exception:
            return [c]

    def _writable_location(self, program_path: str, arguments: list[str]) -> str | None:
        """First program/argument in a world-writable place (raw text, normalized or resolved)."""
        for candidate in [program_path, *arguments]:
            text = str(candidate).strip().strip("\"'")
            if self._WRITABLE_RE.search(text):
                return text
            for form in self._path_forms(text):
                if (form + "/").startswith(self.WORLD_WRITABLE_PREFIXES):
                    return text
        return None

    def _hidden_kind(self, program_path: str, arguments: list[str]) -> str | None:
        """None, "developer" or "unusual" for hidden folders in program paths.

        "developer" only when every hidden folder is an exact developer-tool
        folder name. It is informational and never a reason to drop the item.
        """
        hidden: list[str] = []
        excused: list[str] = []
        for candidate in [program_path, *arguments]:
            for form in self._path_forms(candidate):
                parts = [p for p in form.split("/") if p]
                found = [p for p in parts if p.startswith(".") and p not in (".", "..")]
                # A virtualenv's own interpreter runs only what it is given; any
                # script path in the arguments is checked on its own.
                if (
                    found
                    and parts[-1].lower().startswith("python")
                    and any(
                        p.lower() in ("venv", "virtualenv") or p.lower().startswith(".venv")
                        for p in parts[:-2]
                    )
                ):
                    excused.extend(found)
                else:
                    hidden.extend(found)
        if not hidden and not excused:
            return None
        if all(p in self.DEVELOPER_TOOL_DIRS or p.lower().startswith(".venv") for p in hidden):
            return "developer"
        return "unusual"

    def _in_system_bin_dir(self, program_path: str) -> bool:
        """True if every resolved form of the program path is in a SIP bin directory."""
        forms = self._path_forms(program_path)
        return bool(forms) and all(f.startswith(self.SYSTEM_BIN_DIRS) for f in forms)

    def _check_suspicious_agent(
        self, label: str, program_path: str, arguments: list[str] | None = None
    ) -> list[Finding]:
        """Check if an agent has suspicious characteristics."""
        findings = []
        arguments = arguments or []

        writable = self._writable_location(program_path, arguments)
        hidden_kind = None if writable else self._hidden_kind(program_path, arguments)

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
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.launch_agent_audit.suspicious_path",
                    data={
                        "check": "suspicious_path",
                        "label": label,
                        "program": program_path,
                    },
                )
            )
        elif hidden_kind == "developer":
            # Ordinary for developer tools, but a hidden folder is also a place
            # to hide, so keep it listed (info) instead of dropping it.
            findings.append(
                Finding(
                    title=f"Background program from a developer tool folder: {label}",
                    description=(
                        f"The launch agent '{label}' runs a program from a folder used by "
                        f"developer tools: {program_path}\n"
                        "This is normal if you use that tool. Anyone can create a folder "
                        "with that name, so check that you recognize it."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.launch_agent_audit.suspicious_path",
                    data={
                        "check": "developer_tool_path",
                        "label": label,
                        "program": program_path,
                    },
                )
            )
        elif hidden_kind == "unusual":
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
            and not self._in_system_bin_dir(program_path)
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
