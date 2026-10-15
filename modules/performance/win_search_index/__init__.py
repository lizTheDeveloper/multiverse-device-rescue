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
                    title="Your computer's search engine is turned off",
                    description=(
                        "The background service that keeps your files searchable is currently "
                        "stopped. This means the Windows Search bar won't find your files "
                        "or apps.\n\n"
                        "What to do: Open the Start menu, type 'Services', and press Enter. "
                        "Find 'Windows Search' in the list, right-click it, and select "
                        "'Start'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "service_stopped", "service_status": service_status},
                )
            )

        # Check CPU usage
        if cpu_usage is not None and cpu_usage > HIGH_CPU_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Search tool is using a lot of computer power ({cpu_usage:.1f}%)",
                    description=(
                        f"The program that indexes your files is using {cpu_usage:.1f}% "
                        "of your computer's processing power. This usually happens when "
                        "it is first setting up or fixing a list of your files. It can "
                        "make your computer feel slow.\n\n"
                        "What to do: Wait for the activity to settle down. If it stays "
                        "high for a long time, rebuild it: Settings > Privacy & security > Searching Windows > Advanced "
                        "indexing options, then Advanced > Rebuild."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "high_cpu", "cpu_percent": cpu_usage},
                )
            )

        # Check index size
        if index_size_gb is not None and index_size_gb > MAX_INDEX_SIZE_GB:
            findings.append(
                Finding(
                    title=f"Your search list is very large ({index_size_gb:.1f} GB)",
                    description=(
                        "The file that helps Windows find your documents has grown to "
                        f"{index_size_gb:.1f} GB. This is larger than usual and might "
                        "be slowing down your computer.\n\n"
                        "What to do: Rebuild it: Settings > Privacy & security > Searching Windows > Advanced "
                        "indexing options, then Advanced > Rebuild."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "index_bloated", "index_size_gb": index_size_gb},
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
            if finding.data.get("check") == "service_stopped":
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
            elif finding.data.get("check") == "high_cpu":
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
            elif finding.data.get("check") == "index_bloated":
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
