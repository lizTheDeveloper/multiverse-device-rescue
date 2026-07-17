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
    name = "time_machine_exclusions"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all exclusions from defaults
        all_exclusions = self._get_all_exclusions()

        # Critical directories to check
        critical_dirs = {
            "~/Documents": "Documents folder (critical data)",
            "~/Desktop": "Desktop folder",
        }

        # Important directories to check
        important_dirs = {
            "~/Pictures": "Pictures folder",
            "~/Photos Library": "Photos Library",
        }

        # Check critical directories
        for dir_path, dir_desc in critical_dirs.items():
            expanded_path = str(Path(dir_path).expanduser())
            is_excluded = self._is_directory_excluded(dir_path, all_exclusions)
            if is_excluded:
                findings.append(
                    Finding(
                        title=f"{dir_desc} is excluded from Time Machine",
                        description=f"{expanded_path} is excluded from backups. Important data may not be protected.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "critical_excluded",
                            "path": expanded_path,
                            "description": dir_desc,
                        },
                    )
                )

        # Check important directories
        for dir_path, dir_desc in important_dirs.items():
            is_excluded = self._is_directory_excluded(dir_path, all_exclusions)
            expanded_path = str(Path(dir_path).expanduser())
            if is_excluded:
                findings.append(
                    Finding(
                        title=f"{dir_desc} is excluded from Time Machine",
                        description=f"{expanded_path} is excluded from backups.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "important_excluded",
                            "path": expanded_path,
                            "description": dir_desc,
                        },
                    )
                )

        # Add INFO finding listing all exclusions
        if all_exclusions:
            exclusion_list = "\n".join(sorted(all_exclusions))
            findings.append(
                Finding(
                    title="Time Machine exclusions configured",
                    description=f"The following paths are excluded from Time Machine:\n{exclusion_list}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "exclusions_list",
                        "exclusions": sorted(all_exclusions),
                    },
                )
            )
        else:
            # No exclusions means all directories are backed up
            findings.append(
                Finding(
                    title="No Time Machine exclusions configured",
                    description="All directories are included in Time Machine backups.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_exclusions"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "critical_excluded":
                path = finding.data.get("path", "directory")
                actions.append(
                    Action(
                        title=f"Re-include '{path}' in Time Machine",
                        description=(
                            f"To remove '{path}' from Time Machine exclusions:\n"
                            "1. Open System Settings > General > Time Machine\n"
                            "2. Click 'Options...'\n"
                            "3. Find '{path}' in the exclusions list\n"
                            "4. Select it and click the '-' button to remove it\n"
                            "5. Close the preferences and Time Machine will begin backing up this folder"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "important_excluded":
                path = finding.data.get("path", "directory")
                actions.append(
                    Action(
                        title=f"Re-include '{path}' in Time Machine",
                        description=(
                            f"To remove '{path}' from Time Machine exclusions:\n"
                            "1. Open System Settings > General > Time Machine\n"
                            "2. Click 'Options...'\n"
                            "3. Find '{path}' in the exclusions list\n"
                            "4. Select it and click the '-' button to remove it\n"
                            "5. Close the preferences and Time Machine will begin backing up this folder"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_all_exclusions(self) -> list[str]:
        """Get all Time Machine exclusions via defaults read."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.TimeMachine",
                    "ExcludeByPath",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_exclusions_output(result.stdout)
            return []
        except (OSError, subprocess.SubprocessError):
            return []

    def _parse_exclusions_output(self, output: str) -> list[str]:
        """Parse defaults read output for exclusions list.

        The output format is like:
        (
            "/path/to/exclude1",
            "/path/to/exclude2"
        )
        """
        exclusions = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('"') and line.endswith('",'):
                # Remove quotes and trailing comma
                path = line[1:-2]
                exclusions.append(path)
            elif line.startswith('"') and line.endswith('"'):
                # Last item without comma
                path = line[1:-1]
                exclusions.append(path)
        return exclusions

    def _is_directory_excluded(self, dir_path: str, all_exclusions: list[str]) -> bool:
        """Check if a directory is excluded using tmutil isexcluded."""
        try:
            # Expand ~ to home directory
            expanded_path = str(Path(dir_path).expanduser())

            result = subprocess.run(
                ["tmutil", "isexcluded", expanded_path],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                # tmutil isexcluded returns 0 if excluded, 1 if not excluded
                # But the actual return code indicates exclusion status
                # When excluded: stdout contains "[Excluded]"
                return "[Excluded]" in output or result.returncode == 0 and "Excluded" in output

            # Fallback: check against the exclusions list
            return any(excl == expanded_path for excl in all_exclusions)
        except (OSError, subprocess.SubprocessError):
            # Fallback: check against the exclusions list
            return any(excl == str(Path(dir_path).expanduser()) for excl in all_exclusions)
