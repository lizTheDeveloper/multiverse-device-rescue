from datetime import datetime, timedelta
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
    name = "temp_file_scanner"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan system caches
        system_caches = self._get_directory_size(Path("/Library/Caches"))
        user_caches = self._get_directory_size(Path.home() / "Library/Caches")
        total_caches = system_caches + user_caches

        # Scan system logs
        system_logs = self._get_directory_size(Path("/var/log"))
        user_logs = self._get_directory_size(Path.home() / "Library/Logs")
        old_logs_count = self._count_old_files(
            Path("/var/log"), days=30
        ) + self._count_old_files(Path.home() / "Library/Logs", days=30)
        total_logs = system_logs + user_logs

        # Scan temporary files
        tmp_files = self._get_directory_size(Path("/tmp"))
        var_folders = self._get_directory_size(Path("/var/folders"))
        total_temps = tmp_files + var_folders

        # Scan optional Xcode derived data
        xcode_derived = self._get_directory_size(
            Path.home() / "Library/Developer/Xcode/DerivedData"
        )

        # Scan optional Homebrew cache
        homebrew_cache = self._get_directory_size(
            Path.home() / "Library/Caches/Homebrew"
        )

        total_waste = total_caches + total_logs + total_temps + xcode_derived + homebrew_cache

        # Create findings if space is significant
        if total_caches > 100 * 1024 * 1024:  # > 100 MB
            findings.append(
                Finding(
                    title=f"System caches using {_fmt_bytes(total_caches)}",
                    description=(
                        f"System and user caches (/Library/Caches, ~/Library/Caches) "
                        f"are using {_fmt_bytes(total_caches)}. These can usually be safely removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "caches",
                        "size_bytes": total_caches,
                        "size_formatted": _fmt_bytes(total_caches),
                    },
                )
            )

        if total_logs > 100 * 1024 * 1024:  # > 100 MB
            findings.append(
                Finding(
                    title=f"System logs using {_fmt_bytes(total_logs)}",
                    description=(
                        f"System and user logs (/var/log, ~/Library/Logs) "
                        f"are using {_fmt_bytes(total_logs)}. "
                        f"Found {old_logs_count} log files older than 30 days."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "logs",
                        "size_bytes": total_logs,
                        "size_formatted": _fmt_bytes(total_logs),
                        "old_files_count": old_logs_count,
                    },
                )
            )

        if total_temps > 100 * 1024 * 1024:  # > 100 MB
            findings.append(
                Finding(
                    title=f"Temporary files using {_fmt_bytes(total_temps)}",
                    description=(
                        f"Temporary files (/tmp, /var/folders) "
                        f"are using {_fmt_bytes(total_temps)}. These can usually be safely removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "temps",
                        "size_bytes": total_temps,
                        "size_formatted": _fmt_bytes(total_temps),
                    },
                )
            )

        if xcode_derived > 0:
            findings.append(
                Finding(
                    title=f"Xcode derived data using {_fmt_bytes(xcode_derived)}",
                    description=(
                        f"Xcode derived data (~/Library/Developer/Xcode/DerivedData) "
                        f"is using {_fmt_bytes(xcode_derived)}. "
                        f"These can be safely removed and will be regenerated when needed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "xcode_derived",
                        "size_bytes": xcode_derived,
                        "size_formatted": _fmt_bytes(xcode_derived),
                    },
                )
            )

        if homebrew_cache > 0:
            findings.append(
                Finding(
                    title=f"Homebrew cache using {_fmt_bytes(homebrew_cache)}",
                    description=(
                        f"Homebrew cache (~/Library/Caches/Homebrew) "
                        f"is using {_fmt_bytes(homebrew_cache)}. "
                        f"These can be safely removed with 'brew cleanup'."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "homebrew_cache",
                        "size_bytes": homebrew_cache,
                        "size_formatted": _fmt_bytes(homebrew_cache),
                    },
                )
            )

        if total_waste > 0:
            findings.insert(
                0,
                Finding(
                    title=f"Found {_fmt_bytes(total_waste)} of reclaimable disk space",
                    description=(
                        f"Total space used by caches, logs, and temp files: {_fmt_bytes(total_waste)}. "
                        f"Removing these items may improve disk performance and free up space."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "total_waste",
                        "size_bytes": total_waste,
                        "size_formatted": _fmt_bytes(total_waste),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")

            if finding_type == "total_waste":
                actions.append(
                    Action(
                        title="Total reclaimable space report",
                        description=(
                            f"Total: {size_str}. Review individual findings below to "
                            f"understand what can be safely removed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "caches":
                actions.append(
                    Action(
                        title=f"System and user caches: {size_str}",
                        description=(
                            f"These caches ({size_str}) can typically be safely removed. "
                            f"They will be regenerated as needed. "
                            f"To clean: rm -rf /Library/Caches ~/Library/Caches"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "logs":
                old_count = finding.data.get("old_files_count", 0)
                actions.append(
                    Action(
                        title=f"System and user logs: {size_str}",
                        description=(
                            f"These logs ({size_str}) with {old_count} files older than 30 days "
                            f"can be safely archived or removed. "
                            f"Older logs are unlikely to be needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "temps":
                actions.append(
                    Action(
                        title=f"Temporary files: {size_str}",
                        description=(
                            f"Temporary files ({size_str}) can be safely removed. "
                            f"They are typically not needed after application restarts."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "xcode_derived":
                actions.append(
                    Action(
                        title=f"Xcode derived data: {size_str}",
                        description=(
                            f"Xcode derived data ({size_str}) can be safely removed. "
                            f"It will be regenerated the next time you build. "
                            f"To clean: rm -rf ~/Library/Developer/Xcode/DerivedData/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "homebrew_cache":
                actions.append(
                    Action(
                        title=f"Homebrew cache: {size_str}",
                        description=(
                            f"Homebrew cache ({size_str}) can be safely cleaned. "
                            f"Run 'brew cleanup' or 'brew cleanup -s' to remove."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of all files in directory, with error handling."""
        if not path.exists():
            return 0

        total_size = 0
        try:
            for item in path.rglob("*"):
                try:
                    if item.is_file(follow_symlinks=False):
                        total_size += item.stat().st_size
                except (OSError, PermissionError):
                    # Skip files we can't access
                    continue
        except (OSError, PermissionError):
            # Skip directories we can't traverse
            pass

        return total_size

    def _count_old_files(self, path: Path, days: int = 30) -> int:
        """Count files older than specified number of days."""
        if not path.exists():
            return 0

        cutoff = datetime.now() - timedelta(days=days)
        count = 0

        try:
            for item in path.rglob("*"):
                try:
                    if item.is_file(follow_symlinks=False):
                        mtime = datetime.fromtimestamp(item.stat().st_mtime)
                        if mtime < cutoff:
                            count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return count


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
