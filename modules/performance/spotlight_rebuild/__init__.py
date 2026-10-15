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


class Module(ModuleBase):
    name = "spotlight_rebuild"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Spotlight indexing status
        indexing_stuck = False
        indexing_enabled = False
        status_output = ""

        try:
            result = subprocess.run(
                ["mdutil", "-s", "/"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status_output = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            status_output = ""

        # Parse mdutil output
        for line in status_output.split("\n"):
            if "Indexing enabled" in line:
                indexing_enabled = True
                # Spotlight is stuck if enabled but waiting (not actively indexing)
                if "waiting" in line.lower():
                    indexing_stuck = True

        # Check mds/mds_stores CPU usage
        high_cpu_mds = False
        mds_cpu_percent = 0

        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,pcpu,comm"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            ps_output = result.stdout.strip()

            # Look for mds or mds_stores processes
            for line in ps_output.split("\n"):
                if "mds" in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            cpu_percent = float(parts[1])
                            if cpu_percent > mds_cpu_percent:
                                mds_cpu_percent = cpu_percent
                            if cpu_percent > 50:
                                high_cpu_mds = True
                        except ValueError:
                            pass
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Check Spotlight index size
        spotlight_index_path = Path.home() / ".Spotlight-V100"
        index_size_bytes = 0
        index_accessible = False

        if spotlight_index_path.exists():
            try:
                index_accessible = True
                for root, dirs, files in os.walk(spotlight_index_path):
                    for file in files:
                        try:
                            index_size_bytes += os.path.getsize(
                                os.path.join(root, file)
                            )
                        except OSError:
                            pass
            except OSError:
                index_accessible = False

        # Determine warnings
        very_large_index = index_accessible and index_size_bytes > 5 * 1024**3

        # Create findings based on checks
        if indexing_stuck and indexing_enabled:
            findings.append(
                Finding(
                    title="Spotlight indexing appears to be stuck",
                    description=(
                        "Your Mac's Spotlight search is turned on, but the background "
                        "process that updates the search index seems to be paused or waiting. "
                        "It can make your Mac feel slower "
                        "or cause searches to fail.\n\n"
                        "What to do: To rebuild it, open System Settings > Siri & "
                        "Spotlight > Spotlight Privacy, add your Macintosh HD, then "
                        "remove it again. Spotlight starts a fresh index."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "indexing_stuck": True,
                        "indexing_enabled": True,
                        "issue_type": "stuck_indexing",
                    },
                )
            )

        if high_cpu_mds:
            findings.append(
                Finding(
                    title=(
                        f"Spotlight search is using a lot of computer power ({mds_cpu_percent:.1f}%)"
                    ),
                    description=(
                        "Spotlight, the tool that helps you find files, is currently "
                        f"using {mds_cpu_percent:.1f}% of your Mac's processing power. "
                        "This is normal when your Mac is first setting up a new index "
                        "or after a major update, but if it stays high, it can slow down "
                        "other apps.\n\n"
                        "What to do: If it stays high for a day, rebuild the index: open "
                        "System Settings > Siri & Spotlight > Spotlight Privacy, add your "
                        "Macintosh HD, then remove it again."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "high_cpu_mds": True,
                        "mds_cpu_percent": mds_cpu_percent,
                        "issue_type": "high_cpu_usage",
                    },
                )
            )

        if very_large_index:
            findings.append(
                Finding(
                    title=(
                        f"Spotlight search index is very large ({_fmt_bytes(index_size_bytes)})"
                    ),
                    description=(
                        f"Your Mac's Spotlight search index is {_fmt_bytes(index_size_bytes)}, "
                        "which is larger than the typical 5GB limit. This usually happens "
                        "if you have a lot of files or if the index has grown over time. "
                        "A very large index can sometimes "
                        "slow down your Mac.\n\n"
                        "What to do: To rebuild it, open System Settings > Siri & "
                        "Spotlight > Spotlight Privacy, add your Macintosh HD, then "
                        "remove it again. Spotlight starts a fresh index."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "very_large_index": True,
                        "index_size_bytes": index_size_bytes,
                        "issue_type": "large_index",
                    },
                )
            )

        # Always include an INFO finding with status
        if not findings:
            index_size_str = _fmt_bytes(index_size_bytes) if index_accessible else "unknown"
            findings.append(
                Finding(
                    title="Spotlight indexing status",
                    description=(
                        f"Indexing is {'enabled' if indexing_enabled else 'disabled'}. "
                        f"Index size: {index_size_str}. "
                        f"mds CPU: {mds_cpu_percent:.1f}%"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "indexing_enabled": indexing_enabled,
                        "indexing_stuck": False,
                        "index_size_bytes": index_size_bytes,
                        "index_accessible": index_accessible,
                        "mds_cpu_percent": mds_cpu_percent,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        # Check if any findings suggest index rebuild
        has_rebuild_issue = any(
            f.data.get("issue_type")
            in ("stuck_indexing", "high_cpu_usage", "large_index")
            for f in findings.findings
        )

        if has_rebuild_issue:
            actions.append(
                Action(
                    title="Rebuild Spotlight index",
                    description=(
                        "To rebuild the Spotlight index, run the following commands in Terminal:\n\n"
                        "  sudo mdutil -E -i on /\n"
                        "  sudo mdutil -i on /\n\n"
                        "Note: Rebuilding may take several hours depending on your disk size. "
                        "Your Mac may feel slow during this process. You can check progress with: "
                        "mdutil -s /"
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        else:
            # Informational - no rebuild needed
            findings_data = findings.findings[0].data if findings.findings else {}
            index_size_str = (
                _fmt_bytes(findings_data.get("index_size_bytes", 0))
                if findings_data.get("index_accessible")
                else "unknown"
            )
            actions.append(
                Action(
                    title="Spotlight status report",
                    description=(
                        f"Spotlight is {'enabled' if findings_data.get('indexing_enabled') else 'disabled'}. "
                        f"Index size: {index_size_str}. "
                        f"mds CPU: {findings_data.get('mds_cpu_percent', 0):.1f}%. "
                        "No rebuild needed at this time."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )

        return FixResult(module_name=self.name, actions=actions)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
