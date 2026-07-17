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
    name = "spotlight_status"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Spotlight status using mdutil
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

        # Parse mdutil output to determine if indexing is enabled
        # Note: "Indexing enabled" vs "Indexing disabled" indicates the state
        # To detect if it's actively indexing, we check for absence of "(Spotlight is waiting)"
        indexing_enabled = False
        indexing_active = False

        for line in status_output.split("\n"):
            if "Indexing enabled" in line:
                indexing_enabled = True
                # If it says "Indexing enabled" but doesn't mention waiting, it's likely active
                if "waiting" not in line.lower():
                    indexing_active = True

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

        # Check for excluded paths/volumes
        excluded_paths = self._get_excluded_paths()

        # Create findings based on status
        if indexing_active:
            findings.append(
                Finding(
                    title="Spotlight indexing is currently active",
                    description=(
                        "Spotlight is currently indexing your disk. This can cause CPU and "
                        "disk I/O spikes. Wait for indexing to complete or disable it temporarily."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "indexing_active": True,
                        "indexing_enabled": indexing_enabled,
                    },
                )
            )
        else:
            # Info finding about current status
            index_size_str = _fmt_bytes(index_size_bytes) if index_accessible else "unknown"
            findings.append(
                Finding(
                    title="Spotlight indexing status",
                    description=(
                        f"Indexing is {'enabled' if indexing_enabled else 'disabled'}. "
                        f"Index size: {index_size_str}. "
                        f"Excluded paths: {len(excluded_paths)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "indexing_enabled": indexing_enabled,
                        "indexing_active": False,
                        "index_size_bytes": index_size_bytes,
                        "index_accessible": index_accessible,
                        "excluded_paths_count": len(excluded_paths),
                        "excluded_paths": excluded_paths,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("indexing_active"):
                actions.append(
                    Action(
                        title="Wait for Spotlight indexing to complete",
                        description=(
                            "Spotlight indexing is active. For the best performance, "
                            "allow indexing to complete. You can check status with: mdutil -s / "
                            "To rebuild the index manually, use: mdutil -E -i on / && mdutil -i on /"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                actions.append(
                    Action(
                        title="Spotlight status report",
                        description=(
                            f"Spotlight is {'enabled' if finding.data.get('indexing_enabled') else 'disabled'}. "
                            f"Index size: {_fmt_bytes(finding.data.get('index_size_bytes', 0))} "
                            f"({finding.data.get('excluded_paths_count', 0)} excluded paths). "
                            "No action required unless performance is affected."
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
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
