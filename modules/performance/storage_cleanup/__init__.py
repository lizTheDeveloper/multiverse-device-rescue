import os
import time
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
from rescue.fsbounds import is_dir_nofollow, is_file_nofollow

# Thresholds
OLD_FILES_DAYS = 90
LARGE_CACHE_SIZE = 500 * 1024 * 1024  # 500 MB
WARNING_THRESHOLD = 1024 * 1024 * 1024  # 1 GB
# Adding up every file in ~/Library/Application Support took 79 seconds on a
# real Mac (114 GB in 202 folders), past the engine's 60-second limit, so the
# whole check was reported as "couldn't run". Sizes are now measured within
# this budget; anything not finished is reported as "at least" and named.
SIZE_BUDGET_S = 30.0

_AREA_NAMES = {
    "large_caches": "the large temporary storage folders (~/Library/Caches)",
    "trash": "the Trash",
    "app_support": "~/Library/Application Support",
}


class Module(ModuleBase):
    name = "storage_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "15s"
    emits_codes = ["performance.storage_cleanup.total_reclaimable"]

    size_budget_s: float = SIZE_BUDGET_S

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()
        self._deadline = time.monotonic() + self.size_budget_s
        cut_short: list[str] = []

        def measured(area, fn, *args):
            self._ran_out = False
            value = fn(*args)
            if self._ran_out:
                cut_short.append(area)
            return value

        # Scan each storage category
        downloads_old = self._scan_old_downloads(home / "Downloads")
        large_caches = measured("large_caches", self._scan_large_caches, home / "Library/Caches")
        trash_size = measured("trash", self._get_trash_size, home / ".Trash")
        dmg_files = self._scan_dmg_files(home / "Downloads")
        app_support = measured(
            "app_support", self._scan_app_support, home / "Library/Application Support"
        )

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
                    title=(
                        f"Old files in your Downloads folder: {_fmt_bytes(downloads_old['size'])}"
                    ),
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
                    title=(
                        f"Large temporary storage folders: {_fmt_bytes(large_caches['size'])}"
                    ),
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
                    title=f"Trash folder size: {_fmt_bytes(trash_size)}",
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
                    title=f"Old installer files: {_fmt_bytes(dmg_files['size'])}",
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
                    title=f"Data from uninstalled apps: {_fmt_bytes(app_support['size'])}",
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
                    title=f"Your Mac has {_fmt_bytes(total_reclaimable)} of unused space",
                    description=(
                        f"Your Mac has {_fmt_bytes(total_reclaimable)} of space that is "
                        "currently taking up room but not actively being used. It simply "
                        "means you have files, caches, or old data that can be removed "
                        "to free up storage. Please look at the other findings in this "
                        "report to see exactly what is using that space.\n\n"
                        "What to do: Review the other findings below to identify specific "
                        "items you can safely remove. If you are unsure about a specific "
                        "file or folder, it is safer to leave it alone than to delete "
                        "it by mistake."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    # A stable code, so the finding keeps one identity while its
                    # size (and an "at least") in the title changes.
                    code="performance.storage_cleanup.total_reclaimable",
                    data={
                        "type": "total_reclaimable",
                        "size_bytes": total_reclaimable,
                        "size_formatted": _fmt_bytes(total_reclaimable),
                    },
                ),
            )

        if cut_short:
            for finding in findings:
                kind = finding.data.get("type")
                if kind in cut_short or kind == "total_reclaimable":
                    finding.data["incomplete"] = True
                    if kind == "total_reclaimable":
                        finding.title = finding.title.replace(" has ", " has at least ", 1)
                    else:
                        finding.title = finding.title.replace(": ", ": at least ", 1)
            areas = [_AREA_NAMES[a] for a in cut_short]
            findings.append(
                Finding(
                    title="Some folders were too big to measure fully",
                    description=(
                        "Adding up the size of "
                        + ", ".join(areas)
                        + " was stopped before it finished. The sizes shown for those folders are only the part that "
                        "was measured, so the real amount is larger. Nothing was changed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "measurement_incomplete",
                        "areas": cut_short,
                        "time_budget_s": self.size_budget_s,
                    },
                )
            )

        # Sizes that stopped early are only part of the real amount.
        return CheckResult(module_name=self.name, findings=findings, complete=not cut_short)

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
                    if is_file_nofollow(item):
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
                    if is_dir_nofollow(item):
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
                    if is_file_nofollow(item):
                        total_size += item.stat().st_size
                    elif is_dir_nofollow(item):
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
                    if is_file_nofollow(item) and item.suffix.lower() == ".dmg":
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
                    if is_dir_nofollow(item):
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
        """Total size of the regular files under ``path``, without following links.

        Stops at the check's deadline (set in check()), sets ``_ran_out``, and
        returns what it had added up so far.
        """
        if not is_dir_nofollow(path):
            return 0

        deadline = getattr(self, "_deadline", None)
        total_size = 0
        stack = [str(path)]
        seen = 0
        while stack:
            if deadline is not None and time.monotonic() >= deadline:
                self._ran_out = True
                return total_size
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        seen += 1
                        if (
                            deadline is not None
                            and seen % 500 == 0
                            and time.monotonic() >= deadline
                        ):
                            self._ran_out = True
                            return total_size
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                total_size += entry.stat(follow_symlinks=False).st_size
                        except OSError:
                            continue
            except OSError:
                continue

        return total_size


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
