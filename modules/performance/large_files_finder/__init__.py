import os
import time
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
from rescue.command import run
from rescue.fsbounds import is_file_nofollow

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

# Searching a whole home folder for big files can take more than ten minutes
# on a developer Mac. It used to run as one `find` with a 60-second timeout,
# exactly the engine's limit for the whole check, so the check always timed
# out and reported nothing. Now the search has its own budget and runs one
# `find` per folder, each with its own limit, folders where big files usually
# are first. A stopped `find` loses what it printed (its output is buffered),
# so separate runs keep the results of every folder that finished, and the
# folders that didn't are named.
SEARCH_BUDGET_S = 30.0
# No one folder may use more than this, so a huge one can't starve the rest.
_PER_FOLDER_TIMEOUT_S = 10.0
# Searched first, in this order. Documents last: it is often the biggest tree.
_LIKELY_FOLDERS = ["Downloads", "Desktop", "Movies", "Music", "Pictures", "Documents"]
# Folder names skipped everywhere: package caches with many small files.
_SKIP_NAMES = ["node_modules"]


class Module(ModuleBase):
    name = "large_files_finder"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "30s"

    search_budget_s: float = SEARCH_BUDGET_S

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Find all large files
        self._search_incomplete = False
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
                    title=f"Your 10 biggest files: {_fmt_bytes(total_size)}",
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
                    title=f"Big files on your Desktop: {_fmt_bytes(desktop_size)}",
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
                    title=(
                        f"Old files in Downloads are taking up space ({_fmt_bytes(old_downloads_size)})"
                    ),
                    description=(
                        f"We found {len(old_downloads)} files in your Downloads folder "
                        f"that are over 500MB and older than {OLD_FILES_DAYS} days. Together, "
                        f"they use {_fmt_bytes(old_downloads_size)} of storage.\n\n"
                        "This is a common source of clutter. These files are likely things "
                        "you downloaded a while ago and forgot about.\n\n"
                        "What to do: Open your Downloads folder, look for the large files "
                        "listed, and move any you no longer need to a separate folder "
                        "or the Trash."
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
                    title=f"Large files are using a lot of space ({_fmt_bytes(total_size)})",
                    description=(
                        f"Files over 1GB on your computer are using {_fmt_bytes(total_size)} "
                        "of storage in total. This is higher than the usual limit of "
                        f"{_fmt_bytes(CRITICAL_TOTAL_SIZE)}.\n\n"
                        "This means your storage is getting full, which can slow down "
                        "your device.\n\n"
                        "What to do: Look at the other findings below to see which specific "
                        "files are the largest, and move the ones you don't need to an "
                        "external drive or the Trash."
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

        if self._search_incomplete:
            unfinished = self._unfinished_folders
            findings.append(
                Finding(
                    title="The search for big files didn't finish",
                    description=(
                        "Looking for files over "
                        f"{_fmt_bytes(LARGE_FILE_SIZE)} took too long in some places, so "
                        "the search there was stopped. Not searched to the end: "
                        + ", ".join(unfinished)
                        + ". Big files in those places may be missing from this list. "
                        "Nothing was changed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "search_incomplete",
                        "time_budget_s": self.search_budget_s,
                        "unfinished": unfinished,
                        "files_found": len(large_files),
                    },
                )
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
        """Find files > 1GB under ``home`` within the search budget.

        One ``find`` per likely folder, then one for the rest of the home
        folder (skipping those). Each run is limited to what is left of the
        budget and to a per-folder cap. ``_search_incomplete`` and
        ``_unfinished_folders`` record what was not searched to the end.
        """
        self._search_incomplete = False
        self._unfinished_folders: list[str] = []
        deadline = time.monotonic() + self.search_budget_s
        skip: list[str] = []
        for name in _SKIP_NAMES:
            skip += ["-name", name, "-o"]

        likely = [(f"~/{name}", home / name) for name in _LIKELY_FOLDERS]
        likely = [(label, path) for label, path in likely if path.is_dir()]
        rest_skip = list(skip)
        for _, folder in likely:
            rest_skip += ["-path", str(folder), "-o"]

        searches = [
            (label, path, ["find", str(path), "-xdev", "(", *skip[:-1], ")", "-prune",
                           "-o", "-type", "f", "-size", "+1G", "-print"])
            for label, path in likely
        ]
        searches.append(
            ("the rest of your home folder", home,
             ["find", str(home), "-xdev", "(", *rest_skip[:-1], ")", "-prune",
              "-o", "-type", "f", "-size", "+1G", "-print"])
        )

        paths: list[str] = []
        for label, root, cmd in searches:
            remaining = deadline - time.monotonic()
            if remaining < 0.5:
                self._unfinished_folders.append(label)
                continue
            result = run(cmd, timeout=min(remaining, _PER_FOLDER_TIMEOUT_S))
            output = result.stdout
            if _top_folder_unreadable(result.stderr, root):
                # Without Full Disk Access, macOS refuses the folder itself:
                # find prints nothing and exits 1. That is not "searched, empty".
                self._unfinished_folders.append(f"{label} (couldn't be opened)")
                continue
            if (
                result.timed_out
                or result.truncated
                or result.error
                or result.returncode is None
            ):
                self._unfinished_folders.append(label)
                # Anything printed before it was stopped is real, except a
                # last line that may have been cut off.
                if not output.endswith("\n"):
                    output = output.rsplit("\n", 1)[0] if "\n" in output else ""
            # find exits 1 when some folders could not be read (common in a
            # home folder); the paths it printed are still real.
            paths += [line for line in output.splitlines() if line.strip()]
        self._search_incomplete = bool(self._unfinished_folders)

        files = []
        seen = set()
        for line in paths:
            if line in seen:
                continue
            seen.add(line)
            try:
                path = Path(line.strip())
                if is_file_nofollow(path):
                    files.append({"path": str(path), "size": path.stat().st_size})
            except (OSError, PermissionError):
                continue
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
                    if is_file_nofollow(item):
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
                    if is_file_nofollow(item):
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


def _top_folder_unreadable(stderr: str, root: Path) -> bool:
    """True if find reported that it could not open ``root`` itself."""
    for line in (stderr or "").splitlines():
        line = line.strip()
        for problem in ("Operation not permitted", "Permission denied"):
            if line == f"find: {root}: {problem}":
                return True
    return False


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
