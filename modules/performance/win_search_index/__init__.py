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

HIGH_CPU_THRESHOLD = 25  # percent
MAX_INDEX_SIZE_GB = 5


class Module(ModuleBase):
    name = "win_search_index"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        service_status = self._get_service_status()
        cpu_usage = self._get_search_indexer_cpu()
        index_size_gb = self._get_index_size_gb()
        item_count = self._get_indexed_items_count()

        findings = []

        # Check if service is stopped
        if service_status == "Stopped":
            findings.append(
                Finding(
                    title="Windows Search service is stopped",
                    description=(
                        "The Windows Search service (WSearch) is not running. "
                        "Search functionality will not work. Restart the service via "
                        "Services.msc or PowerShell (Start-Service WSearch)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service_status": service_status},
                )
            )

        # Check CPU usage
        if cpu_usage is not None and cpu_usage > HIGH_CPU_THRESHOLD:
            findings.append(
                Finding(
                    title=f"SearchIndexer using high CPU ({cpu_usage:.1f}%)",
                    description=(
                        f"SearchIndexer.exe is consuming {cpu_usage:.1f}% CPU, "
                        "which suggests indexing is in progress or the index is corrupted. "
                        "Wait for indexing to complete or rebuild the index via "
                        "Settings > Privacy > Search > Advanced > Delete index and rebuild."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"cpu_percent": cpu_usage},
                )
            )

        # Check index size
        if index_size_gb is not None and index_size_gb > MAX_INDEX_SIZE_GB:
            findings.append(
                Finding(
                    title=f"Search index is bloated ({index_size_gb:.1f} GB)",
                    description=(
                        f"The Windows Search index has grown to {index_size_gb:.1f} GB, "
                        "which is larger than expected and may cause performance issues. "
                        "Consider rebuilding the index via "
                        "Settings > Privacy > Search > Advanced > Delete index and rebuild."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"index_size_gb": index_size_gb},
                )
            )

        # Report index health if no warnings
        if not findings:
            index_size_str = f"{index_size_gb:.1f}" if index_size_gb is not None else "unknown"
            cpu_str = f"{cpu_usage:.1f}" if cpu_usage is not None else "unknown"
            findings.append(
                Finding(
                    title="Windows Search index healthy",
                    description=(
                        f"Search service is {service_status or 'unknown'}. "
                        f"Index size: {index_size_str} GB, "
                        f"Items indexed: {item_count or 'unknown'}, "
                        f"SearchIndexer CPU: {cpu_str}%"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "service_status": service_status,
                        "index_size_gb": index_size_gb,
                        "item_count": item_count,
                        "cpu_percent": cpu_usage,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if "service is stopped" in finding.title.lower():
                actions.append(
                    Action(
                        title="Restart Windows Search service",
                        description=(
                            "Run in PowerShell (as Administrator): "
                            "Start-Service WSearch"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "high cpu" in finding.title.lower():
                actions.append(
                    Action(
                        title="Allow indexing to complete or rebuild index",
                        description=(
                            "Open Settings > Privacy > Search > Advanced > "
                            "Delete index and rebuild. Or wait for current indexing to complete "
                            "by monitoring SearchIndexer.exe in Task Manager."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "bloated" in finding.title.lower():
                actions.append(
                    Action(
                        title="Rebuild Search index",
                        description=(
                            "Open Settings > Privacy > Search > Advanced > "
                            "Delete index and rebuild to shrink the index and improve performance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_service_status(self) -> str | None:
        """Get Windows Search service status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-Service WSearch | Select-Object -ExpandProperty Status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status = result.stdout.strip()
            return status if status else None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _get_search_indexer_cpu(self) -> float | None:
        """Get SearchIndexer.exe CPU usage percentage."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "(Get-Process SearchIndexer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CPU)"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            cpu_str = result.stdout.strip()
            if cpu_str:
                return float(cpu_str)
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
            return None

    def _get_index_size_gb(self) -> float | None:
        """Get Windows Search index size in GB."""
        try:
            # Get the index location from registry
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows Search" -Name DataDirectory -ErrorAction SilentlyContinue).DataDirectory',
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            index_path = result.stdout.strip()
            if not index_path:
                return None

            # Get the folder size
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    f'(Get-ChildItem "{index_path}" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB',
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            size_str = result.stdout.strip()
            if size_str:
                return float(size_str)
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
            return None

    def _get_indexed_items_count(self) -> int | None:
        """Get number of items in the search index."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows Search\\CrawlScopeManager\\Windows\\SystemIndex" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ItemCount)',
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            count_str = result.stdout.strip()
            if count_str:
                return int(count_str)
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
            return None
