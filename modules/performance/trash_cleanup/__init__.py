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
TRASH_SIZE_WARNING = 5 * 1024 * 1024 * 1024  # 5 GB
TRASH_ITEM_COUNT_WARNING = 1000


class Module(ModuleBase):
    name = "trash_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Scan local Trash
        local_trash_data = self._scan_trash(home / ".Trash")
        total_size = local_trash_data["size"]
        total_items = local_trash_data["count"]

        # Scan external drive Trash
        external_trash_data = self._scan_external_trash()
        total_size += external_trash_data["size"]
        total_items += external_trash_data["count"]

        # Create findings
        if total_size > 0 or total_items > 0:
            # Info finding for current status
            findings.append(
                Finding(
                    title=f"Trash: {_fmt_bytes(total_size)} ({total_items} items)",
                    description=(
                        f"Total Trash across all volumes: {_fmt_bytes(total_size)} "
                        f"containing {total_items} items."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "trash_status",
                        "size_bytes": total_size,
                        "size_formatted": _fmt_bytes(total_size),
                        "item_count": total_items,
                    },
                )
            )

        # Warn if Trash exceeds 5GB
        if total_size >= TRASH_SIZE_WARNING:
            findings.insert(
                0,
                Finding(
                    title=f"Large Trash: {_fmt_bytes(total_size)}",
                    description=(
                        f"Trash is consuming {_fmt_bytes(total_size)}, "
                        f"which exceeds the 5GB threshold. "
                        f"Consider emptying Trash to free disk space."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "large_trash",
                        "size_bytes": total_size,
                        "size_formatted": _fmt_bytes(total_size),
                    },
                ),
            )

        # Warn if Trash has too many items
        if total_items >= TRASH_ITEM_COUNT_WARNING:
            findings.insert(
                0 if total_size < TRASH_SIZE_WARNING else 1,
                Finding(
                    title=f"Too many items in Trash: {total_items}",
                    description=(
                        f"Trash contains {total_items} items, "
                        f"which exceeds the 1000 item threshold. "
                        f"This can cause the Trash UI to become sluggish. "
                        f"Consider emptying Trash."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "too_many_trash_items",
                        "item_count": total_items,
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "trash_status":
                size_str = finding.data.get("size_formatted", "unknown")
                item_count = finding.data.get("item_count", 0)
                actions.append(
                    Action(
                        title=f"Trash status: {size_str} ({item_count} items)",
                        description=(
                            f"Current Trash contents: {size_str} with {item_count} items. "
                            f"To empty Trash via Finder, select Finder > Empty Trash. "
                            f"Alternatively, use: rm -rf ~/.Trash/* && rm -rf /Volumes/*/.Trashes/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "large_trash":
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Large Trash detected: {size_str}",
                        description=(
                            f"Trash is consuming {size_str} of disk space. "
                            f"Empty Trash to reclaim this space. "
                            f"Open Finder and select Empty Trash from the menu bar, "
                            f"or run: rm -rf ~/.Trash/* && rm -rf /Volumes/*/.Trashes/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "too_many_trash_items":
                item_count = finding.data.get("item_count", 0)
                actions.append(
                    Action(
                        title=f"Too many Trash items: {item_count}",
                        description=(
                            f"Trash contains {item_count} items, making the UI sluggish. "
                            f"Empty the Trash to improve system responsiveness. "
                            f"Use Finder > Empty Trash or run: rm -rf ~/.Trash/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_trash(self, trash_dir: Path) -> dict:
        """Scan local Trash directory for size and item count."""
        if not trash_dir.exists():
            return {"size": 0, "count": 0}

        total_size = 0
        item_count = 0

        try:
            for item in trash_dir.rglob("*"):
                try:
                    if item.is_file(follow_symlinks=False):
                        total_size += item.stat().st_size
                        item_count += 1
                    elif item.is_dir(follow_symlinks=False):
                        item_count += 1
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": item_count}

    def _scan_external_trash(self) -> dict:
        """Scan external drive Trash directories (/Volumes/*/.Trashes/)."""
        total_size = 0
        total_count = 0

        try:
            volumes = Path("/Volumes")
            if not volumes.exists():
                return {"size": 0, "count": 0}

            for volume in volumes.iterdir():
                try:
                    if not volume.is_symlink() and volume.is_dir():
                        trashes_dir = volume / ".Trashes"
                        if trashes_dir.exists():
                            for trash_item in trashes_dir.rglob("*"):
                                try:
                                    if trash_item.is_file(follow_symlinks=False):
                                        total_size += trash_item.stat().st_size
                                        total_count += 1
                                    elif trash_item.is_dir(follow_symlinks=False):
                                        # Don't double-count directories in the count
                                        pass
                                except (OSError, PermissionError):
                                    continue
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return {"size": total_size, "count": total_count}

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of all files in directory."""
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
