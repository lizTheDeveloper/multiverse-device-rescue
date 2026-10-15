import os
import plistlib
import posixpath
import re
from pathlib import Path
from shlex import quote

from rescue import known_items
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


def _tag_plists(findings: list, starts: list) -> None:
    """Record the plist each finding came from as data["plist"].

    The app uses it to offer "Fix it for me" on exactly that file, rather than
    guessing a file from the label (which any plist can choose).
    """
    bounds = starts + [(len(findings), None)]
    for (start, plist), (end, _) in zip(bounds, bounds[1:]):
        if not plist:
            continue
        for finding in findings[start:end]:
            finding.data.setdefault("plist", plist)


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
        # plist -> (label, program, arguments), for "marked as mine".
        tasks: dict[str, tuple] = {}
        starts: list[tuple[int, str | None]] = []
        for item in all_agents:
            label, program_path, arguments = item[:3]
            starts.append((len(findings), item[3] if len(item) > 3 else None))
            if starts[-1][1]:
                tasks[starts[-1][1]] = (label, program_path, arguments)
            # Flag INFO for each found agent
            findings.append(
                Finding(
                    title=f"Background item: {label}",
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

        _tag_plists(findings, starts)
        # Items the person marked as theirs are downgraded and labelled, never
        # hidden; a changed program, plist or arguments no longer matches.
        for f in findings:
            task = tasks.get(f.data.get("plist"))
            if task:
                f.data["arguments_sha256"] = known_items.arguments_sha256(task[2])

        def identify(f):
            task = tasks.get(f.data.get("plist"))
            if not task:
                return None
            return known_items.background_task_identity(task[0], task[1], f.data["plist"], task[2])

        known_items.apply_marks(findings, known_items.BACKGROUND_TASK, identify)
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
                            f"1. launchctl unload ~/Library/LaunchAgents/{quote(str(agent_label) + '.plist')}\n"
                            f"2. rm ~/Library/LaunchAgents/{quote(str(agent_label) + '.plist')}\n"
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
                            f"1. launchctl unload ~/Library/LaunchAgents/{quote(str(agent_label) + '.plist')}\n"
                            f"2. rm ~/Library/LaunchAgents/{quote(str(agent_label) + '.plist')}\n"
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
    ) -> list[tuple[str, str, list[str], str]]:
        """Scan a LaunchAgents directory; return (label, program, arguments, plist path) tuples."""
        agents = []

        if not directory.exists():
            return agents

        try:
            plist_paths = sorted(directory.glob("*.plist"))
        except Exception:
            return agents

        for plist_path in plist_paths:
            label, program, arguments = self._extract_from_plist(str(plist_path))
            agents.append((label, program, arguments, str(plist_path)))

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
            # On Windows realpath() turns "/x" into "C:\\x"; that is not a form of
            # the POSIX path, so only keep results that are still POSIX paths.
            if real != expanded and real.startswith("/"):
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
                    # Only the virtualenv's own folders are excused; any other hidden
                    # folder on the way to it (~/.evil/venv/bin/python) still counts.
                    for p in found:
                        if p in self.DEVELOPER_TOOL_DIRS or p.lower().startswith(".venv"):
                            excused.append(p)
                        else:
                            hidden.append(p)
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
                    title=f"Background task '{label}' runs from a folder anyone can change",
                    description=(
                        f"A background task named '{label}' is set to run a program from "
                        f"{writable}. This location is a shared folder where any program on "
                        "your Mac can save or replace files. If someone or something "
                        "puts a malicious file there, it will run automatically with "
                        "your permissions, even if the file isn't there right now.\n\n"
                        "This is a serious security risk because it allows hidden software "
                        "to take control of your Mac.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings > General > Login Items & Extensions. "
                        f"If it's safe for you, turn off '{label}' under Allow in the "
                        "Background."
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
                    title=f"Background item from a developer tool folder: {label}",
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
                    title=f"Background task '{label}' runs from a hidden folder",
                    description=(
                        f"The background task '{label}' runs a program from {program_path}, "
                        "which is inside a hidden folder. Hidden folders are often used "
                        "by developers, but they can also be used to hide unwanted software.\n\n"
                        "This is not automatically dangerous, but you should verify that "
                        "you installed this app.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings > General > Login Items & Extensions. "
                        f"Check if you recognize the app associated with '{label}'. If "
                        "you don't recognize it, turn it off under Allow in the Background."
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
                    title=f"Background task '{label}' has a confusingly short name",
                    description=(
                        f"The background task '{label}' points to a file named '{program_name}'. "
                        "Legitimate apps usually have clear, descriptive names. Very "
                        "short or random names are sometimes used by unwanted software "
                        "to hide in plain sight.\n\n"
                        "This might be a false alarm, but it is worth checking to be "
                        "sure.\n\n"
                        "What to do: Open System Settings > General > Login Items & Extensions. "
                        f"Find the entry for '{label}' and check if you recognize the "
                        "app it belongs to. If you don't, turn it off under Allow in the "
                        "Background."
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
            # launchd paths are POSIX; "/x" is not absolute to Windows' pathlib.
            is_abs = program_path_obj.is_absolute() or program_path.startswith("/")
            if is_abs and not program_path_obj.exists():
                findings.append(
                    Finding(
                        title=f"Background task '{label}' points to a missing file",
                        description=(
                            f"A background task named '{label}' is set to run a program "
                            f"at {program_path}, but that file does not exist on your "
                            "Mac.\n\n"
                            "This is usually harmless leftover clutter from an app you "
                            "uninstalled.\n\n"
                            "What to do: Open System Settings > General > Login Items "
                            f"& Extensions and turn off '{label}' under Allow in the "
                            "Background, or leave it; it can't run without its program."
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
