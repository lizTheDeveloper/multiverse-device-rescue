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
    name = "launchd_persistence_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    # Known malware label prefixes
    KNOWN_MALWARE_LABELS = [
        "com.pcv",
        "com.vsearch",
        "com.crossrider",
        "com.genio",
        "com.operatorMac",
        "com.spi",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan all three directories
        user_agents = self._scan_launchd_dir(Path.home() / "Library" / "LaunchAgents")
        system_agents = self._scan_launchd_dir(Path("/Library/LaunchAgents"))
        system_daemons = self._scan_launchd_dir(Path("/Library/LaunchDaemons"))

        all_items = user_agents + system_agents + system_daemons

        for label, program_path, keep_alive, run_at_load in all_items:
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
                        data={
                            "check": "known_malware",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )
                continue

            # Check for suspicious paths (tmp, hidden directories)
            if self._has_suspicious_path(program_path):
                findings.append(
                    Finding(
                        title=f"Launchd item in suspicious location: {label}",
                        description=(
                            f"The launchd item '{label}' executes from a suspicious location: "
                            f"{program_path}\n"
                            "This indicates malware persistence in a temporary or hidden directory."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "suspicious_path",
                            "label": label,
                            "program": program_path,
                        },
                    )
                )
                continue

            # Check for non-Apple KeepAlive + RunAtLoad combination
            if (
                not self._is_apple(label)
                and keep_alive
                and run_at_load
            ):
                findings.append(
                    Finding(
                        title=f"Non-Apple persistence flags: {label}",
                        description=(
                            f"The launchd item '{label}' has both KeepAlive=true and "
                            f"RunAtLoad=true from a non-Apple source. This persistence pattern "
                            f"is suspicious. Program: {program_path}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "keepalive_runatload",
                            "label": label,
                            "program": program_path,
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
                        title=f"Review suspicious persistence pattern: {label}",
                        description=(
                            f"The launchd item '{label}' has suspicious persistence flags "
                            f"(KeepAlive+RunAtLoad) from a non-Apple source.\n\n"
                            f"Review to ensure this is legitimate. Program: {program}\n"
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

    def _scan_launchd_dir(self, directory: Path) -> list[tuple[str, str, bool, bool]]:
        """Scan a launchd directory and return list of (label, program, keep_alive, run_at_load) tuples."""
        items = []

        if not directory.exists():
            return items

        try:
            # Use pathlib to find all plist files
            plist_files = list(directory.glob("*.plist"))

            for plist_path in plist_files:
                label, program, keep_alive, run_at_load = self._extract_from_plist(
                    str(plist_path)
                )
                if label and program:
                    items.append((label, program, keep_alive, run_at_load))

        except Exception:
            pass

        return items

    def _extract_from_plist(
        self, plist_path: str
    ) -> tuple[str | None, str | None, bool, bool]:
        """Extract Label, Program/ProgramArguments, KeepAlive, and RunAtLoad from plist.

        Returns: (label, program_path, keep_alive, run_at_load)
        """
        try:
            # Read Label
            label_result = subprocess.run(
                ["defaults", "read", plist_path, "Label"],
                capture_output=True,
                text=True,
            )
            if label_result.returncode != 0:
                return None, None, False, False
            label = label_result.stdout.strip()

            # Try to read Program first, then ProgramArguments
            program = None
            prog_result = subprocess.run(
                ["defaults", "read", plist_path, "Program"],
                capture_output=True,
                text=True,
            )
            if prog_result.returncode == 0:
                program = prog_result.stdout.strip()

            # If Program not found, try ProgramArguments
            if not program:
                prog_result = subprocess.run(
                    ["defaults", "read", plist_path, "ProgramArguments"],
                    capture_output=True,
                    text=True,
                )
                if prog_result.returncode == 0:
                    # Parse the output - first element is the program
                    lines = prog_result.stdout.strip().split("\n")
                    for line in lines:
                        line = line.strip()
                        if line and line != "(" and line != ")":
                            program = line.rstrip(",")
                            break

            if not program:
                return None, None, False, False

            # Read KeepAlive (defaults to false)
            keep_alive = False
            keep_alive_result = subprocess.run(
                ["defaults", "read", plist_path, "KeepAlive"],
                capture_output=True,
                text=True,
            )
            if keep_alive_result.returncode == 0:
                keep_alive_str = keep_alive_result.stdout.strip()
                keep_alive = keep_alive_str in ("1", "true", "True", "YES")

            # Read RunAtLoad (defaults to false)
            run_at_load = False
            run_at_load_result = subprocess.run(
                ["defaults", "read", plist_path, "RunAtLoad"],
                capture_output=True,
                text=True,
            )
            if run_at_load_result.returncode == 0:
                run_at_load_str = run_at_load_result.stdout.strip()
                run_at_load = run_at_load_str in ("1", "true", "True", "YES")

            return label, program, keep_alive, run_at_load

        except Exception:
            return None, None, False, False

    def _is_known_malware(self, label: str) -> bool:
        """Check if label matches known malware family prefixes."""
        for malware_prefix in self.KNOWN_MALWARE_LABELS:
            if label.startswith(malware_prefix):
                return True
        return False

    def _is_apple(self, label: str) -> bool:
        """Check if label is from Apple."""
        return label.startswith("com.apple.")

    def _has_suspicious_path(self, program_path: str) -> bool:
        """Check if program path is in a suspicious location."""
        # Check for /tmp, /var/tmp, or hidden directories
        if program_path.startswith(("/tmp/", "/var/tmp/")):
            return True

        # Check for hidden directories (starting with .)
        path_parts = program_path.split("/")
        for part in path_parts:
            if part.startswith(".") and part != ".":
                return True

        return False
