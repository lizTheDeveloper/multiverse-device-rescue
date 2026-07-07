import subprocess
import os
from pathlib import Path
from datetime import datetime, timedelta

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
LARGE_FILE_SIZE = 1024 * 1024 * 1024  # 1 GB
OLD_FILES_DAYS = 90
OLD_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
CRITICAL_TOTAL_SIZE = 50 * 1024 * 1024 * 1024  # 50 GB

# File extensions for categorization
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".mov", ".avi", ".flv", ".m4v", ".wmv", ".webm"}
DISK_IMAGE_EXTENSIONS = {".dmg", ".iso", ".img"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz"}
VM_IMAGE_EXTENSIONS = {".vmdk", ".vdi", ".vhdx"}


class Module(ModuleBase):
    name = "large_files_finder"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Find all large files
        large_files = self._find_large_files(home)
        old_downloads = self._find_old_large_downloads(home / "Downloads")
        desktop_files = self._find_large_desktop_files(home / "Desktop")

        # Categorize files
        categorized = self._categorize_files(large_files)

        # Calculate total size
        total_size = sum(info["size"] for info in large_files)

        # Create findings

        # Top 10 largest files (INFO)
        if large_files:
            # Sort by size descending
            sorted_files = sorted(large_files, key=lambda x: x["size"], reverse=True)[:10]
            top_files_desc = "\n".join(
                [
                    f"  {_fmt_bytes(f['size']).rjust(10)} - {f['path']}"
                    for f in sorted_files
                ]
            )
            findings.append(
                Finding(
                    title=f"Top 10 largest files: {_fmt_bytes(total_size)}",
                    description=(
                        f"Found {len(large_files)} files larger than {_fmt_bytes(LARGE_FILE_SIZE)}:\n"
                        f"{top_files_desc}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "top_large_files",
                        "total_size_bytes": total_size,
                        "total_size_formatted": _fmt_bytes(total_size),
                        "file_count": len(large_files),
                        "files": sorted_files,
                    },
                )
            )

        # Categorized files (INFO)
        if categorized:
            category_lines = []
            for cat_name, files in categorized.items():
                cat_size = sum(f["size"] for f in files)
                category_lines.append(
                    f"  {cat_name}: {len(files)} files, {_fmt_bytes(cat_size)}"
                )
            findings.append(
                Finding(
                    title="Large files by category",
                    description=(
                        "Breakdown of large files by type:\n"
                        + "\n".join(category_lines)
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "categorized_files",
                        "categories": categorized,
                    },
                )
            )

        # Desktop files (INFO if any)
        if desktop_files:
            desktop_size = sum(f["size"] for f in desktop_files)
            findings.append(
                Finding(
                    title=f"Large files on Desktop: {_fmt_bytes(desktop_size)}",
                    description=(
                        f"Found {len(desktop_files)} large files on ~/Desktop using {_fmt_bytes(desktop_size)}. "
                        f"Consider organizing or moving these files."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "desktop_files",
                        "size_bytes": desktop_size,
                        "size_formatted": _fmt_bytes(desktop_size),
                        "file_count": len(desktop_files),
                        "files": desktop_files,
                    },
                )
            )

        # Old downloads >500MB (WARNING)
        if old_downloads:
            old_downloads_size = sum(f["size"] for f in old_downloads)
            findings.append(
                Finding(
                    title=f"Old large downloads: {_fmt_bytes(old_downloads_size)} (older than {OLD_FILES_DAYS} days)",
                    description=(
                        f"Found {len(old_downloads)} old files in ~/Downloads (>500MB, older than {OLD_FILES_DAYS} days) "
                        f"using {_fmt_bytes(old_downloads_size)}. "
                        f"These files may be safe to delete if you no longer need them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "old_downloads",
                        "size_bytes": old_downloads_size,
                        "size_formatted": _fmt_bytes(old_downloads_size),
                        "file_count": len(old_downloads),
                        "files": old_downloads,
                    },
                )
            )

        # Critical threshold warning (WARNING)
        if total_size >= CRITICAL_TOTAL_SIZE:
            findings.insert(
                0,
                Finding(
                    title=f"Critical: {_fmt_bytes(total_size)} in large files",
                    description=(
                        f"Total large files (>1GB) consume {_fmt_bytes(total_size)}, "
                        f"exceeding the {_fmt_bytes(CRITICAL_TOTAL_SIZE)} threshold. "
                        f"Review the findings below to identify candidates for deletion or relocation."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "critical_large_files",
                        "size_bytes": total_size,
                        "size_formatted": _fmt_bytes(total_size),
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "critical_large_files":
                actions.append(
                    Action(
                        title="Critical storage warning",
                        description=(
                            f"Large files consuming {finding.data.get('size_formatted', 'unknown')} detected. "
                            f"Review the detailed findings below to identify which files to delete or move. "
                            f"Consider external drives or cloud storage for archival."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "top_large_files":
                file_count = finding.data.get("file_count", 0)
                total_size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Review {file_count} large files ({total_size_str})",
                        description=(
                            f"Inspect the top 10 largest files listed above. "
                            f"Determine which are needed and which can be safely deleted. "
                            f"Use Finder to inspect file types and delete unnecessary ones."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "categorized_files":
                actions.append(
                    Action(
                        title="Review categorized large files",
                        description=(
                            f"Large files are broken down by type. "
                            f"Disk images (.dmg, .iso) and installers are typically safe to delete after use. "
                            f"Videos and archives may be needed - review before deletion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "desktop_files":
                size_str = finding.data.get("size_formatted", "unknown")
                file_count = finding.data.get("file_count", 0)
                actions.append(
                    Action(
                        title=f"Organize Desktop files ({file_count} files, {size_str})",
                        description=(
                            f"Large files on Desktop should typically be moved to appropriate folders. "
                            f"This keeps your Desktop clean and can improve performance. "
                            f"Consider moving media files to ~/Downloads or Documents folders."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "old_downloads":
                size_str = finding.data.get("size_formatted", "unknown")
                file_count = finding.data.get("file_count", 0)
                actions.append(
                    Action(
                        title=f"Purge old downloads ({file_count} files, {size_str})",
                        description=(
                            f"{file_count} files in ~/Downloads are older than {OLD_FILES_DAYS} days "
                            f"and larger than {_fmt_bytes(OLD_FILE_SIZE)} each. "
                            f"Review these files carefully before deletion - they are likely forgotten downloads."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _find_large_files(self, home: Path) -> list[dict]:
        """Find all files > 1GB using find command."""
        files = []

        try:
            # Use find to locate files > 1GB
            cmd = [
                "find",
                str(home),
                "-type", "f",
                "-size", "+1G",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            path = Path(line.strip())
                            if path.exists():
                                size = path.stat().st_size
                                files.append({
                                    "path": str(path),
                                    "size": size,
                                })
                        except (OSError, PermissionError):
                            continue
        except (subprocess.TimeoutExpired, Exception):
            pass

        return files

    def _find_old_large_downloads(self, downloads_dir: Path) -> list[dict]:
        """Find old files >500MB in Downloads that are older than 90 days."""
        if not downloads_dir.exists():
            return []

        files = []
        cutoff = datetime.now() - timedelta(days=OLD_FILES_DAYS)

        try:
            for item in downloads_dir.iterdir():
                try:
                    if item.is_file(follow_symlinks=False):
                        size = item.stat().st_size
                        mtime = datetime.fromtimestamp(item.stat().st_mtime)

                        if size > OLD_FILE_SIZE and mtime < cutoff:
                            files.append({
                                "path": str(item),
                                "size": size,
                            })
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return sorted(files, key=lambda x: x["size"], reverse=True)

    def _find_large_desktop_files(self, desktop_dir: Path) -> list[dict]:
        """Find large files on Desktop (>1GB)."""
        if not desktop_dir.exists():
            return []

        files = []

        try:
            for item in desktop_dir.iterdir():
                try:
                    if item.is_file(follow_symlinks=False):
                        size = item.stat().st_size
                        if size > LARGE_FILE_SIZE:
                            files.append({
                                "path": str(item),
                                "size": size,
                            })
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return sorted(files, key=lambda x: x["size"], reverse=True)

    def _categorize_files(self, files: list[dict]) -> dict[str, list]:
        """Categorize large files by type."""
        categories = {
            "Videos": [],
            "Disk Images": [],
            "Archives": [],
            "VM Images": [],
            "Other": [],
        }

        for file_info in files:
            path = Path(file_info["path"])
            suffix = path.suffix.lower()

            if suffix in VIDEO_EXTENSIONS:
                categories["Videos"].append(file_info)
            elif suffix in DISK_IMAGE_EXTENSIONS:
                categories["Disk Images"].append(file_info)
            elif suffix in ARCHIVE_EXTENSIONS:
                categories["Archives"].append(file_info)
            elif suffix in VM_IMAGE_EXTENSIONS:
                categories["VM Images"].append(file_info)
            else:
                categories["Other"].append(file_info)

        # Remove empty categories
        return {k: v for k, v in categories.items() if v}


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
