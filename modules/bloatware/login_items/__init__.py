import json
import os
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
    name = "login_items"
    category = "bloatware"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        login_items = self._get_login_items()
        known_bloatware = _load_known_bloatware()

        findings = []

        # Flag each login item as INFO
        for item in login_items:
            entry = _match_bloatware(item, known_bloatware)
            if entry is not None:
                # Matched bloatware - flag as WARNING
                findings.append(
                    Finding(
                        title=f"Login item: {entry['name']}",
                        description=entry["description"],
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"item_name": item, "bloatware_name": entry["name"]},
                    )
                )
            else:
                # Unmatched login item - flag as INFO
                findings.append(
                    Finding(
                        title=f"Login item: {item}",
                        description=f"A login item that launches at startup.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"item_name": item},
                    )
                )

        # Flag WARNING if too many login items
        if len(login_items) > 10:
            findings.append(
                Finding(
                    title=f"Too many login items ({len(login_items)})",
                    description="More than 10 login items can significantly slow down system boot time. Consider disabling items you don't actively use.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"count": len(login_items)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if "item_name" in finding.data:
                item_name = finding.data["item_name"]
                actions.append(
                    Action(
                        title=f"Remove login item: {item_name}",
                        description=(
                            f"To remove '{item_name}' from login items, open System Settings > "
                            f"General > Login Items and remove it from the 'Open at Login' list."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "count" in finding.data:
                # This is the "too many items" finding - provide general guidance
                actions.append(
                    Action(
                        title="Review and reduce login items",
                        description=(
                            "Open System Settings > General > Login Items and review your login items. "
                            "Remove any items you don't need to launch at startup, especially background helpers and auto-updaters."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_login_items(self) -> list[str]:
        """Get login items from System Events via osascript."""
        login_items = []

        # Get items from System Events (primary source)
        try:
            result = subprocess.run(
                [
                    "osascript",
                    "-e",
                    "tell application \"System Events\" to get the name of every login item",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Output is comma-space separated on a single line
                login_items = [item.strip() for item in result.stdout.strip().split(", ")]
        except (OSError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Also check for background items plist (secondary source)
        btm_path = os.path.expanduser(
            "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
        )
        if Path(btm_path).exists():
            # Binary plist exists - just note it exists
            # Don't try to deep-parse; it's an NSKeyedArchiver binary plist
            pass

        return login_items


def _load_known_bloatware() -> list[dict]:
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(item_name: str, known_bloatware: list[dict]) -> dict | None:
    item_lower = item_name.lower()
    for entry in known_bloatware:
        if entry["name_pattern"].lower() in item_lower:
            return entry
    return None
