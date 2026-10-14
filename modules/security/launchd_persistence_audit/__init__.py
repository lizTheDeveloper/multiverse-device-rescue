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
    name = "launchd_persistence_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.launchd_persistence_audit.known_malware",
        "security.launchd_persistence_audit.suspicious_path",
        "security.launchd_persistence_audit.keepalive_runatload",
        "security.launchd_persistence_audit.non_apple_info",
    ]

    # Known malware label prefixes
    KNOWN_MALWARE_LABELS = [
        "com.pcv",
        "com.vsearch",
        "com.crossrider",
        "com.genio",
        "com.operatorMac",
        "com.spi",
    ]

    # Locations any local user or program can write to. Whatever lands here
    # runs with the user's (or root's) privileges the next time launchd starts
    # the item, so a launchd item pointing here is a real risk.
    WORLD_WRITABLE_PREFIXES = (
        "/tmp/",
        "/private/tmp/",
        "/var/tmp/",
        "/private/var/tmp/",
        "/Users/Shared/",
        "/dev/shm/",
    )

    # Hidden/versioned folders in a home directory that developer tools use
    # for their own binaries. These are ordinary on a developer machine.
    DEVELOPER_TOOL_DIRS = {
        ".nvm", ".venv", "venv", ".pyenv", ".asdf", ".volta", ".bun", ".local",
        ".cargo", ".rustup", ".rbenv", ".rvm", ".fnm", ".npm", ".npm-global",
        ".deno", ".sdkman", ".pnpm", ".nodenv", ".goenv", ".gem", ".conda",
        ".virtualenvs", ".pipx", ".uv", ".mise", ".config", "virtualenv",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan all three directories
        user_agents = self._scan_launchd_dir(Path.home() / "Library" / "LaunchAgents")
        system_agents = self._scan_launchd_dir(Path("/Library/LaunchAgents"))
        system_daemons = self._scan_launchd_dir(Path("/Library/LaunchDaemons"))

        all_items = user_agents + system_agents + system_daemons

        for label, program_path, keep_alive, run_at_load, arguments in all_items:
            # Check for known malware labels
            if self._is_known_malware(label):
                findings.append(
                    Finding(
                        title=f"Known malware persistence: {label}",
                        description=(
                            f"The launchd item '{label}' is from a known malware family. "
                            f"This is a critical indicator of compromise. "
                            f"Program: {program_path}"
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.launchd_persistence_audit.known_malware",
                        data={
                            "check": "known_malware",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )
                continue

            # World-writable locations (real risk) and unusual hidden folders
            writable = self._world_writable_path(program_path, arguments)
            if writable:
                findings.append(
                    Finding(
                        title=f"Launchd item runs from a world-writable location: {label}",
                        description=(
                            f"The launchd item '{label}' runs {writable}, which is in a "
                            "folder that any program on this Mac can write to "
                            "(such as /tmp). Anything placed there will be run "
                            "automatically as you, even if the file does not exist "
                            "right now. Legitimate software installs itself in "
                            "/Applications or /opt/homebrew, not /tmp. "
                            f"Program: {program_path}"
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.launchd_persistence_audit.suspicious_path",
                        data={
                            "check": "suspicious_path",
                            "label": label,
                            "program": program_path,
                            "location": writable,
                            "program_exists": Path(writable).exists(),
                        },
                    )
                )
                continue

            if self._has_unusual_hidden_path(program_path):
                findings.append(
                    Finding(
                        title=f"Launchd item runs from a hidden folder: {label}",
                        description=(
                            f"The launchd item '{label}' runs a program inside a hidden "
                            f"folder: {program_path}\n"
                            "Some apps do this legitimately, but hidden folders are also "
                            "a place where unwanted software hides. Check that you "
                            "recognize this program."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.launchd_persistence_audit.suspicious_path",
                        data={
                            "check": "suspicious_path",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )
                continue

            # KeepAlive + RunAtLoad is how every background service works, so it
            # is only worth a warning when the program is also missing.
            if (
                not self._is_apple(label)
                and keep_alive
                and run_at_load
                and not self._program_exists(program_path)
            ):
                findings.append(
                    Finding(
                        title=f"Background service points to a missing program: {label}",
                        description=(
                            f"The launchd item '{label}' is set to start at login and "
                            "restart itself, but its program cannot be found: "
                            f"{program_path}\n"
                            "This is usually left over from an app that was removed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.launchd_persistence_audit.keepalive_runatload",
                        data={
                            "check": "keepalive_runatload",
                            "label": label,
                            "program": program_path,
                            "program_exists": False,
                        },
                    )
                )

            # Flag INFO for all non-Apple items
            if not self._is_apple(label):
                findings.append(
                    Finding(
                        title=f"Non-Apple launchd item: {label}",
                        description=(
                            f"Found non-Apple launchd item: {label}\n"
                            f"Program: {program_path}\n"
                            f"KeepAlive: {keep_alive}, RunAtLoad: {run_at_load}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.launchd_persistence_audit.non_apple_info",
                        data={
                            "check": "non_apple_info",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        seen_labels = set()

        for finding in findings.findings:
            check = finding.data.get("check")
            label = finding.data.get("label", "unknown")

            # Avoid duplicate actions for the same label
            if label in seen_labels:
                continue
            seen_labels.add(label)

            if check == "known_malware":
                program = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Remove known malware persistence: {label}",
                        description=(
                            f"The launchd item '{label}' is from a known malware family.\n\n"
                            f"To remove this malware persistence:\n"
                            "1. Identify the plist location (likely in ~/Library/LaunchAgents/, "
                            "/Library/LaunchAgents/, or /Library/LaunchDaemons/)\n"
                            f"2. Run: launchctl unload <path>/{label}.plist\n"
                            f"3. Run: rm <path>/{label}.plist\n"
                            f"4. Remove the executable: rm {program}\n"
                            "5. Restart your Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "suspicious_path":
                program = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Remove suspicious launchd persistence: {label}",
                        description=(
                            f"The launchd item '{label}' executes from a suspicious location: {program}\n\n"
                            f"To remove this persistence:\n"
                            "1. Identify the plist location (likely in ~/Library/LaunchAgents/, "
                            "/Library/LaunchAgents/, or /Library/LaunchDaemons/)\n"
                            f"2. Run: launchctl unload <path>/{label}.plist\n"
                            f"3. Run: rm <path>/{label}.plist\n"
                            f"4. Remove the executable: rm {program}\n"
                            "5. Restart your Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "keepalive_runatload":
                program = finding.data.get("program", "unknown")
                actions.append(
                    Action(
                        title=f"Review background service with missing program: {label}",
                        description=(
                            f"The launchd item '{label}' starts at login and restarts "
                            f"itself, but its program was not found.\n\n"
                            f"Review to ensure this is leftover from an app you removed. Program: {program}\n"
                            f"If suspicious:\n"
                            "1. Identify the plist location\n"
                            f"2. Run: launchctl unload <path>/{label}.plist\n"
                            f"3. Run: rm <path>/{label}.plist\n"
                            "4. Remove the executable if needed\n"
                            "5. Restart your Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_launchd_dir(
        self, directory: Path
    ) -> list[tuple[str, str, bool, bool, list[str]]]:
        """Return (label, program, keep_alive, run_at_load, arguments) per plist."""
        items = []

        if not directory.exists():
            return items

        try:
            plist_files = sorted(directory.glob("*.plist"))
        except Exception:
            return items

        for plist_path in plist_files:
            label, program, keep_alive, run_at_load, arguments = (
                self._extract_from_plist(str(plist_path))
            )
            if label and program:
                items.append((label, program, keep_alive, run_at_load, arguments))

        return items

    @staticmethod
    def _extract_from_plist(
        plist_path: str,
    ) -> tuple[str | None, str | None, bool, bool, list[str]]:
        """Read Label, program, KeepAlive and RunAtLoad straight from the plist."""
        empty = (None, None, False, False, [])
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return empty
        if not isinstance(data, dict):
            return empty

        label = data.get("Label")
        if not isinstance(label, str) or not label:
            return empty

        args = data.get("ProgramArguments")
        arguments = [str(a) for a in args] if isinstance(args, list) else []
        program = data.get("Program")
        if not isinstance(program, str) or not program:
            program = arguments[0] if arguments else None
        if not program:
            return empty
        program = program.strip().strip("\"'")

        return (
            label,
            program,
            bool(data.get("KeepAlive", False)),
            bool(data.get("RunAtLoad", False)),
            arguments,
        )

    def _world_writable_path(self, program_path: str, arguments: list[str]) -> str | None:
        """Return the first program/argument path in a world-writable location."""
        for candidate in [program_path, *arguments]:
            expanded = str(candidate).strip().strip("\"'")
            if expanded.startswith(self.WORLD_WRITABLE_PREFIXES):
                return expanded
        return None

    def _has_unusual_hidden_path(self, program_path: str) -> bool:
        """True for a hidden folder that is not a known developer tool folder."""
        parts = [p for p in program_path.split("/") if p]
        if any(p in self.DEVELOPER_TOOL_DIRS or self._is_venv_name(p) for p in parts):
            return False
        return any(p.startswith(".") and p not in (".", "..") for p in parts)

    @staticmethod
    def _is_venv_name(part: str) -> bool:
        """Virtualenv folders such as .venv, venv, .venv-hermes, project-venv."""
        p = part.lower()
        return p.startswith((".venv", "venv")) or p.endswith("venv")

    @staticmethod
    def _program_exists(program_path: str) -> bool:
        try:
            return Path(program_path).expanduser().exists()
        except Exception:
            return True

    def _is_known_malware(self, label: str) -> bool:
        """Check if label matches known malware family prefixes."""
        for malware_prefix in self.KNOWN_MALWARE_LABELS:
            if label.startswith(malware_prefix):
                return True
        return False

    def _is_apple(self, label: str) -> bool:
        """Check if label is from Apple."""
        return label.startswith("com.apple.")
