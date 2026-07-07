import json
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

DATA_FILE = Path(__file__).parent / "data" / "known_bloatware.json"


class Module(ModuleBase):
    name = "win_bloatware"
    category = "bloatware"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        installed_apps = self._get_installed_apps()
        known_bloatware = _load_known_bloatware()

        findings = []
        bloatware_found = []

        # Check each installed app against known bloatware
        for app_name, publisher in installed_apps:
            entry = _match_bloatware(app_name, publisher, known_bloatware)
            if entry is not None:
                bloatware_found.append(entry)
                findings.append(
                    Finding(
                        title=f"Bloatware detected: {entry['name']}",
                        description=(
                            f"Found pre-installed bloatware: {entry['name']}. {entry['description']} "
                            f"Estimated resource savings if removed: {entry['estimated_resource_savings']}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "app_name": app_name,
                            "bloatware_name": entry["name"],
                            "publisher": publisher,
                            "resource_savings": entry["estimated_resource_savings"],
                        },
                    )
                )

        # Add INFO finding with summary
        total_count = len(installed_apps)
        bloatware_count = len(bloatware_found)
        findings.append(
            Finding(
                title=f"Installed apps summary: {total_count} total, {bloatware_count} bloatware",
                description=(
                    f"Your system has {total_count} installed UWP/Store apps. "
                    f"Found {bloatware_count} bloatware apps. "
                    f"Removing bloatware can free up disk space and improve system responsiveness."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "total_apps": total_count,
                    "bloatware_count": bloatware_count,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if "bloatware_name" in finding.data:
                # Individual bloatware app removal instruction
                app_name = finding.data.get("app_name", "unknown")
                bloatware_name = finding.data.get("bloatware_name", "unknown")
                actions.append(
                    Action(
                        title=f"Remove bloatware: {bloatware_name}",
                        description=(
                            f"To remove '{app_name}' from your system:\n"
                            f"1. Open Settings (Win + I)\n"
                            f"2. Go to Apps > Apps & features\n"
                            f"3. Search for '{app_name}' in the list\n"
                            f"4. Click on it and select 'Uninstall'\n"
                            f"5. Follow the prompts to complete removal\n\n"
                            f"Alternatively, use PowerShell (as Administrator):\n"
                            f"Remove-AppxPackage -Package '{app_name}' -User $env:USERNAME"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "total_apps" in finding.data:
                # Summary action with general guidance
                total = finding.data.get("total_apps", 0)
                bloatware = finding.data.get("bloatware_count", 0)
                actions.append(
                    Action(
                        title=f"Review and remove bloatware ({bloatware} found)",
                        description=(
                            f"Your system has {total} installed Store apps, with {bloatware} identified as bloatware. "
                            f"Review the apps above and use the removal instructions to uninstall the ones you don't need. "
                            f"Removing bloatware can free up disk space and improve system performance, especially on older machines."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_installed_apps(self) -> list[tuple[str, str]]:
        """
        Get installed UWP/Store apps using PowerShell Get-AppxPackage.
        Returns list of (Name, Publisher) tuples.
        """
        apps = []

        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-AppxPackage | Select-Object Name, Publisher | ConvertTo-Csv -NoTypeInformation",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split("\n")
                # Skip header line
                for line in lines[1:]:
                    if line.strip():
                        # Parse CSV line: "Name","Publisher"
                        parts = _parse_csv_line(line)
                        if len(parts) >= 2:
                            name = parts[0].strip('"')
                            publisher = parts[1].strip('"')
                            apps.append((name, publisher))
        except (OSError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return apps


def _load_known_bloatware() -> list[dict]:
    """Load known bloatware list from JSON data file."""
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(
    app_name: str, publisher: str, known_bloatware: list[dict]
) -> dict | None:
    """Check if app matches any known bloatware entry."""
    app_name_lower = app_name.lower()
    publisher_lower = publisher.lower()

    for entry in known_bloatware:
        publisher_pattern = entry["publisher_pattern"].lower()
        app_pattern = entry.get("app_pattern", "").lower()

        # Match by both publisher AND app pattern
        if publisher_pattern in publisher_lower and app_pattern in app_name_lower:
            return entry

    return None


def _parse_csv_line(line: str) -> list[str]:
    """Simple CSV parser for quoted fields."""
    parts = []
    current = ""
    in_quotes = False

    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            parts.append(current)
            current = ""
            continue
        current += char

    if current:
        parts.append(current)

    return parts
