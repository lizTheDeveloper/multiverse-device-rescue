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

# Thresholds
OLD_FILES_DAYS = 90
LARGE_CACHE_SIZE = 500 * 1024 * 1024  # 500 MB
WARNING_THRESHOLD = 1024 * 1024 * 1024  # 1 GB


class Module(ModuleBase):
    name = "storage_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Scan each storage category
        downloads_old = self._scan_old_downloads(home / "Downloads")
        large_caches = self._scan_large_caches(home / "Library/Caches")
        trash_size = self._get_trash_size(home / ".Trash")
        dmg_files = self._scan_dmg_files(home / "Downloads")
        app_support = self._scan_app_support(home / "Library/Application Support")

        # Calculate total reclaimable space
        total_reclaimable = (
            downloads_old["size"]
            + large_caches["size"]
            + trash_size
            + dmg_files["size"]
            + app_support["size"]
        )

        # Create findings for each category with content
        if downloads_old["size"] > 0:
            findings.append(
                Finding(
                    title=f"Old files in Downloads: {_fmt_bytes(downloads_old['size'])}",
                    description=(
                        f"~/Downloads contains {downloads_old['count']} files older than {OLD_FILES_DAYS} days "
                        f"using {_fmt_bytes(downloads_old['size'])}. These are likely forgotten."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "old_downloads",
                        "size_bytes": downloads_old["size"],
                        "size_formatted": _fmt_bytes(downloads_old["size"]),
                        "file_count": downloads_old["count"],
                    },
                )
            )

        if large_caches["size"] > 0:
            findings.append(
                Finding(
                    title=f"Large cache directories: {_fmt_bytes(large_caches['size'])}",
                    description=(
                        f"Found {large_caches['count']} cache directories larger than {_fmt_bytes(LARGE_CACHE_SIZE)} "
                        f"using a total of {_fmt_bytes(large_caches['size'])}. "
                        f"Caches can be safely removed and will be regenerated."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "large_caches",
                        "size_bytes": large_caches["size"],
                        "size_formatted": _fmt_bytes(large_caches["size"]),
                        "directory_count": large_caches["count"],
                    },
                )
            )

        if trash_size > 0:
            findings.append(
                Finding(
                    title=f"Trash: {_fmt_bytes(trash_size)}",
                    description=(
                        f"Trash (~/.Trash) contains {_fmt_bytes(trash_size)} of deleted files. "
                        f"These can be permanently removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "trash",
                        "size_bytes": trash_size,
                        "size_formatted": _fmt_bytes(trash_size),
                    },
                )
            )

        if dmg_files["size"] > 0:
            findings.append(
                Finding(
                    title=f"Large .dmg installer files: {_fmt_bytes(dmg_files['size'])}",
                    description=(
                        f"Found {dmg_files['count']} .dmg installer files in ~/Downloads "
                        f"using {_fmt_bytes(dmg_files['size'])}. "
                        f"These are typically safe to delete after installation."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "dmg_files",
                        "size_bytes": dmg_files["size"],
                        "size_formatted": _fmt_bytes(dmg_files["size"]),
                        "file_count": dmg_files["count"],
                    },
                )
            )

        if app_support["size"] > 0:
            findings.append(
                Finding(
                    title=f"Unused application data: {_fmt_bytes(app_support['size'])}",
                    description=(
                        f"Found {app_support['count']} directories in ~/Library/Application Support "
                        f"for applications that may no longer be installed, using {_fmt_bytes(app_support['size'])}. "
                        f"Check if these apps are still in use."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "app_support",
                        "size_bytes": app_support["size"],
                        "size_formatted": _fmt_bytes(app_support["size"]),
                        "directory_count": app_support["count"],
                    },
                )
            )

        # Add overall warning if significant space is reclaimable
        if total_reclaimable >= WARNING_THRESHOLD:
            findings.insert(
                0,
                Finding(
                    title=f"High reclaimable storage: {_fmt_bytes(total_reclaimable)}",
                    description=(
                        f"Total reclaimable space across all categories: {_fmt_bytes(total_reclaimable)}. "
                        f"Review the findings below for specific cleanup opportunities."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "total_reclaimable",
                        "size_bytes": total_reclaimable,
                        "size_formatted": _fmt_bytes(total_reclaimable),
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")

            if finding_type == "total_reclaimable":
                actions.append(
                    Action(
                        title="Total reclaimable storage report",
                        description=(
                            f"Total: {size_str}. Review individual findings below to understand "
                            f"which categories have the most reclaimable space."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "old_downloads":
                file_count = finding.data.get("file_count", 0)
                actions.append(
                    Action(
                        title=f"Old files in Downloads: {size_str}",
                        description=(
                            f"{file_count} files in ~/Downloads older than {OLD_FILES_DAYS} days "
                            f"using {size_str}. You can safely delete these forgotten downloads. "
                            f"Review the files manually before deletion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "large_caches":
                dir_count = finding.data.get("directory_count", 0)
                actions.append(
                    Action(
                        title=f"Large cache directories: {size_str}",
                        description=(
                            f"{dir_count} cache directories using {size_str}. "
                            f"Cache files can be safely removed - they will be regenerated as needed. "
                            f"To clean: rm -rf ~/Library/Caches"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "trash":
                actions.append(
                    Action(
                        title=f"Trash: {size_str}",
                        description=(
                            f"Trash contains {size_str} of deleted files. "
                            f"Empty the Trash to permanently delete these files and free space. "
                            f"Use Finder > Empty Trash or: rm -rf ~/.Trash/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "dmg_files":
                file_count = finding.data.get("file_count", 0)
                actions.append(
                    Action(
                        title=f"Large .dmg installer files: {size_str}",
                        description=(
                            f"Found {file_count} .dmg installer files in ~/Downloads using {size_str}. "
                            f"These are typically used for installation and can be deleted after "
                            f"the application is installed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "app_support":
                dir_count = finding.data.get("directory_count", 0)
                actions.append(
                    Action(
                        title=f"Unused application data: {size_str}",
                        description=(
                            f"Found {dir_count} directories in ~/Library/Application Support "
                            f"for possibly uninstalled apps using {size_str}. "
                            f"Check if these applications are still installed before deleting."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_old_downloads(self, downloads_dir: Path) -> dict:
        """Scan Downloads for files older than OLD_FILES_DAYS days."""
        if not downloads_dir.exists():
            return {"size": 0, "count": 0}

        cutoff = datetime.now() - timedelta(days=OLD_FILES_DAYS)
        total_size = 0
        count = 0

        try:
            for item in downloads_dir.iterdir():
                try:
                    if item.is_file(follow_symlinks=False):
                        mtime = datetime.fromtimestamp(item.stat().st_mtime)
                        if mtime < cutoff:
                            total_size += item.stat().st_size
                            count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": count}

    def _scan_large_caches(self, caches_dir: Path) -> dict:
        """Scan for cache directories larger than LARGE_CACHE_SIZE."""
        if not caches_dir.exists():
            return {"size": 0, "count": 0}

        total_size = 0
        count = 0

        try:
            for item in caches_dir.iterdir():
                try:
                    if item.is_dir(follow_symlinks=False):
                        dir_size = self._get_directory_size(item)
                        if dir_size > LARGE_CACHE_SIZE:
                            total_size += dir_size
                            count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": count}

    def _get_trash_size(self, trash_dir: Path) -> int:
        """Get total size of Trash."""
        if not trash_dir.exists():
            return 0

        total_size = 0
        try:
            for item in trash_dir.iterdir():
                try:
                    if item.is_file(follow_symlinks=False):
                        total_size += item.stat().st_size
                    elif item.is_dir(follow_symlinks=False):
                        total_size += self._get_directory_size(item)
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return total_size

    def _scan_dmg_files(self, downloads_dir: Path) -> dict:
        """Scan Downloads for large .dmg files."""
        if not downloads_dir.exists():
            return {"size": 0, "count": 0}

        total_size = 0
        count = 0

        try:
            for item in downloads_dir.iterdir():
                try:
                    if item.is_file(follow_symlinks=False) and item.suffix.lower() == ".dmg":
                        total_size += item.stat().st_size
                        count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": count}

    def _scan_app_support(self, app_support_dir: Path) -> dict:
        """Scan Application Support for directories of uninstalled apps."""
        if not app_support_dir.exists():
            return {"size": 0, "count": 0}

        total_size = 0
        count = 0

        try:
            for item in app_support_dir.iterdir():
                try:
                    if item.is_dir(follow_symlinks=False):
                        # Simple heuristic: count directories (can't easily detect uninstalled apps)
                        dir_size = self._get_directory_size(item)
                        total_size += dir_size
                        count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": count}

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
                    continue
        except (OSError, PermissionError):
            pass

        return total_size


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
