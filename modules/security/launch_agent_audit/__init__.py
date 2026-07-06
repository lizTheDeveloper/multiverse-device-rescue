import subprocess
from pathlib import Path
import re

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

        # Check if more than 20 user launch agents (unusual, possible adware)
        if len(user_agents) > 20:
            findings.append(
                Finding(
                    title=f"Unusual number of user launch agents ({len(user_agents)})",
                    description=(
                        f"Found {len(user_agents)} user-level LaunchAgents, which is "
                        "unusual and may indicate adware or malware persistence. "
                        "Typical systems have fewer than 20 user agents."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "too_many_agents"},
                )
            )

        # Process each agent
        for label, program_path in all_agents:
            # Flag INFO for each found agent
            findings.append(
                Finding(
                    title=f"Launch agent found: {label}",
                    description=f"Program path: {program_path}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "agent_info",
                        "label": label,
                        "program": program_path,
                    },
                )
            )

            # Check for suspicious characteristics
            suspicious_findings = self._check_suspicious_agent(label, program_path)
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
                            "This may indicate malware that deleted its executable. "
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

    def _scan_launch_agents_dir(self, directory: Path) -> list[tuple[str, str]]:
        """Scan a LaunchAgents directory and return list of (label, program) tuples."""
        agents = []

        if not directory.exists():
            return agents

        try:
            result = subprocess.run(
                ["find", str(directory), "-name", "*.plist", "-type", "f"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return agents

            plist_paths = [
                p.strip() for p in result.stdout.split("\n") if p.strip()
            ]

            for plist_path in plist_paths:
                label, program = self._extract_from_plist(plist_path)
                if label and program:
                    agents.append((label, program))

        except Exception as e:
            pass

        return agents

    def _extract_from_plist(self, plist_path: str) -> tuple[str | None, str | None]:
        """Extract Label and first ProgramArguments entry from a plist file."""
        try:
            # Extract just the plist name without .plist extension for use with defaults
            plist_file = Path(plist_path)
            plist_name = plist_file.stem

            # Try to read Label
            label_result = subprocess.run(
                ["defaults", "read", plist_path, "Label"],
                capture_output=True,
                text=True,
            )
            if label_result.returncode != 0:
                return None, None
            label = label_result.stdout.strip()

            # Try to read ProgramArguments (first element is the program)
            prog_result = subprocess.run(
                ["defaults", "read", plist_path, "ProgramArguments"],
                capture_output=True,
                text=True,
            )
            if prog_result.returncode != 0:
                return None, None

            # Parse the output - format is:
            # (
            #   /path/to/program,
            #   arg1,
            #   ...
            # )
            lines = prog_result.stdout.strip().split("\n")
            program = None
            for line in lines:
                line = line.strip()
                if line and line != "(" and line != ")":
                    # Remove trailing comma if present
                    program = line.rstrip(",")
                    break

            return label, program

        except Exception as e:
            return None, None

    def _check_suspicious_agent(
        self, label: str, program_path: str
    ) -> list[Finding]:
        """Check if an agent has suspicious characteristics."""
        findings = []

        # Check for programs in /tmp/, /var/tmp/, or hidden directories
        if program_path.startswith(("/tmp/", "/var/tmp/")):
            findings.append(
                Finding(
                    title=f"Launch agent in temporary directory: {label}",
                    description=(
                        f"The launch agent '{label}' points to a temporary directory: "
                        f"{program_path}\n"
                        "This is highly suspicious and indicates malware persistence."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "suspicious_path",
                        "label": label,
                        "program": program_path,
                    },
                )
            )
        elif "/./" in program_path or program_path.startswith("/") and "/." in program_path:
            # Hidden directory check - look for /. in path
            path_parts = program_path.split("/")
            for part in path_parts:
                if part.startswith("."):
                    findings.append(
                        Finding(
                            title=f"Launch agent in hidden directory: {label}",
                            description=(
                                f"The launch agent '{label}' points to a hidden directory: "
                                f"{program_path}\n"
                                "Hidden directories are often used for malware persistence."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "suspicious_path",
                                "label": label,
                                "program": program_path,
                            },
                        )
                    )
                    break

        # Check for obfuscated names (very short random-looking names)
        # Extract the program name from path
        program_name = Path(program_path).name
        # Check if it's very short (2 chars or less) or matches pattern of random names
        if len(program_name) <= 2 and not program_name.startswith("."):
            findings.append(
                Finding(
                    title=f"Launch agent with obfuscated name: {label}",
                    description=(
                        f"The launch agent '{label}' points to a program with a "
                        f"suspiciously short/obfuscated name: {program_name}\n"
                        "Obfuscated names are common in malware."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "obfuscated_name",
                        "label": label,
                        "program": program_path,
                    },
                )
            )

        # Check if program exists
        try:
            program_path_obj = Path(program_path).expanduser()
            if not program_path_obj.exists():
                findings.append(
                    Finding(
                        title=f"Launch agent program does not exist: {label}",
                        description=(
                            f"The launch agent '{label}' points to a program that "
                            f"does not exist: {program_path}\n"
                            "This may indicate malware that deleted its executable."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
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
