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
    name = "spotlight_repair"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 72
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Spotlight indexing status on boot volume
        indexing_enabled = False
        indexing_active = False
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

        # Parse mdutil output. Only "Indexing disabled" means off. macOS 26
        # answers "Index is read-only." for / and /System/Volumes/Data while
        # Spotlight search works; that, an empty answer, or anything else new
        # is "couldn't confirm", not "turned off".
        indexing_disabled = False
        for line in status_output.split("\n"):
            if "Indexing enabled" in line:
                indexing_enabled = True
                # Check if actively indexing
                if "waiting" not in line.lower():
                    indexing_active = True
            elif "Indexing disabled" in line or "Indexing and searching disabled" in line:
                indexing_disabled = True

        if not indexing_enabled and not indexing_disabled:
            findings.append(
                Finding(
                    title="Couldn't confirm Spotlight indexing on your main drive",
                    description=(
                        "Reclaim City couldn't tell from macOS whether Spotlight is "
                        "indexing your main drive"
                        + (f" (macOS said: \"{status_output.splitlines()[-1].strip()}\")"
                           if status_output.strip() else "")
                        + ". This is not a sign that anything is wrong. If searching "
                        "with Spotlight finds your files, it is working."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "indexing_enabled": None,
                        "issue_type": "indexing_unknown",
                        "status": status_output[:200],
                    },
                )
            )

        # Flag if Spotlight is disabled on boot volume
        if indexing_disabled and not indexing_enabled:
            findings.append(
                Finding(
                    title="Spotlight search is turned off on your main drive",
                    description=(
                        "Spotlight is the search tool on your Mac. Right now, it is turned "
                        "off for your main drive. This means you can't use the search "
                        "bar to find files, and some system features that rely on it won't "
                        "work.\n\n"
                        "What to do: Indexing has to be turned back on from Terminal; ask "
                        "a technical helper to run: sudo mdutil -i on /"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "indexing_enabled": False,
                        "issue_type": "disabled_indexing",
                    },
                )
            )

        # Check mds/mds_stores CPU usage
        high_cpu_mds = False
        mds_cpu_percent = 0.0

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

        # Flag if mds is consuming excessive CPU
        if high_cpu_mds:
            findings.append(
                Finding(
                    title=(
                        f"Spotlight search is using a lot of power ({mds_cpu_percent:.1f}% CPU)"
                    ),
                    description=(
                        "The background process that updates Spotlight search is using "
                        f"{mds_cpu_percent:.1f}% of your computer's power. This is likely "
                        "because Spotlight is trying to scan a lot of files at once. "
                        "It can make your Mac feel slow or hot.\n\n"
                        "What to do: Give it time to finish. If it stays high for a day, "
                        "rebuild the index: open System Settings > Siri & Spotlight > "
                        "Spotlight Privacy, add your Macintosh HD, then remove it again."
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

        # Flag if index is very large (>5GB)
        very_large_index = index_accessible and index_size_bytes > 5 * 1024**3

        if very_large_index:
            findings.append(
                Finding(
                    title=(
                        f"Spotlight search data is taking up a lot of space ({_fmt_bytes(index_size_bytes)})"
                    ),
                    description=(
                        "Spotlight keeps a list of your files to help you find them quickly. "
                        f"This list is currently {_fmt_bytes(index_size_bytes)}. That "
                        "is larger than usual and can slow down your Mac or drain your "
                        "battery.\n\n"
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

        # Check for excluded paths/volumes
        excluded_paths = self._get_excluded_paths()

        # If no warnings, include an INFO summary
        if not findings:
            index_size_str = _fmt_bytes(index_size_bytes) if index_accessible else "unknown"
            findings.append(
                Finding(
                    title="Spotlight indexing status",
                    description=(
                        f"Indexing is {'enabled' if indexing_enabled else 'disabled'}. "
                        f"Index size: {index_size_str}. "
                        f"mds CPU: {mds_cpu_percent:.1f}%. "
                        f"Excluded volumes: {len(excluded_paths)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "indexing_enabled": indexing_enabled,
                        "indexing_active": indexing_active,
                        "index_size_bytes": index_size_bytes,
                        "index_accessible": index_accessible,
                        "mds_cpu_percent": mds_cpu_percent,
                        "excluded_paths_count": len(excluded_paths),
                        "excluded_paths": excluded_paths,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        # Check if any findings suggest index repair
        has_repair_issue = any(
            f.data.get("issue_type")
            in ("disabled_indexing", "high_cpu_usage", "large_index")
            for f in findings.findings
        )

        if has_repair_issue:
            actions.append(
                Action(
                    title="Rebuild Spotlight index",
                    description=(
                        "To rebuild the Spotlight index, run the following command in Terminal:\n\n"
                        "  sudo mdutil -E /\n\n"
                        "This will erase and rebuild the Spotlight index. "
                        "Rebuilding may take several hours depending on your disk size. "
                        "Your Mac may feel slow during this process. "
                        "You can check progress with: mdutil -s /"
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
                    title="Spotlight repair status",
                    description=(
                        f"Spotlight is {'enabled' if findings_data.get('indexing_enabled') else 'disabled'}. "
                        f"Index size: {index_size_str}. "
                        f"mds CPU: {findings_data.get('mds_cpu_percent', 0):.1f}%. "
                        f"Excluded volumes: {findings_data.get('excluded_paths_count', 0)}. "
                        "No repair needed at this time."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _get_excluded_paths(self) -> list[str]:
        """Get list of paths/volumes excluded from Spotlight indexing."""
        excluded = []

        # Try to get excluded paths from defaults
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.Spotlight",
                    "orderedItems",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                # Parse output to extract paths
                for line in result.stdout.split("\n"):
                    if "Path =" in line:
                        # Extract path between quotes
                        parts = line.split('Path = "')
                        if len(parts) > 1:
                            path = parts[1].split('"')[0]
                            excluded.append(path)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return excluded


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
