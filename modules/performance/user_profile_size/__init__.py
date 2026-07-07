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

# Thresholds
USER_DIR_WARNING_THRESHOLD = 50 * 1024**3  # 50 GB
LIBRARY_WARNING_THRESHOLD = 10 * 1024**3  # 10 GB

# System directories to skip
SKIP_DIRS = {"Shared", "Guest"}

# Subdirectories to analyze for current user
SUBDIRS_TO_CHECK = {
    "Desktop",
    "Documents",
    "Downloads",
    "Movies",
    "Music",
    "Pictures",
    "Library",
}


class Module(ModuleBase):
    name = "user_profile_size"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all user directories
        users_dir = Path("/Users")
        user_dirs = self._get_user_directories(users_dir)

        if not user_dirs:
            return CheckResult(module_name=self.name, findings=[])

        # Check each user directory
        large_users = []
        all_users_sizes = []

        for user_dir in user_dirs:
            try:
                size_bytes = self._get_directory_size(user_dir)
                user_name = user_dir.name
                all_users_sizes.append((user_name, size_bytes))

                if size_bytes > USER_DIR_WARNING_THRESHOLD:
                    large_users.append((user_name, size_bytes))
            except Exception:
                # Skip directories we can't access
                continue

        # Check Library directory bloat for current user
        current_user = Path.home()
        library_path = current_user / "Library"
        library_size = 0
        library_bloat = False

        try:
            library_size = self._get_directory_size(library_path)
            if library_size > LIBRARY_WARNING_THRESHOLD:
                library_bloat = True
        except Exception:
            pass

        # Create findings for large user directories
        for user_name, size_bytes in large_users:
            findings.append(
                Finding(
                    title=f"User '{user_name}' profile is {_fmt_bytes(size_bytes)} (>{_fmt_bytes(USER_DIR_WARNING_THRESHOLD)})",
                    description=(
                        f"/Users/{user_name} is using {_fmt_bytes(size_bytes)}. "
                        f"This is unusually large and may indicate accumulated cache or old data. "
                        f"Consider reviewing the user's Downloads, Documents, and Library directories."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "large_user_dir",
                        "user_name": user_name,
                        "size_bytes": size_bytes,
                        "size_formatted": _fmt_bytes(size_bytes),
                    },
                )
            )

        # Create finding for Library bloat
        if library_bloat:
            findings.append(
                Finding(
                    title=f"Library directory is {_fmt_bytes(library_size)} (>{_fmt_bytes(LIBRARY_WARNING_THRESHOLD)})",
                    description=(
                        f"~/.Library is using {_fmt_bytes(library_size)}, which is unusually large. "
                        f"This often contains application caches, saved state, and other hidden data. "
                        f"Consider reviewing: ~/Library/Caches, ~/Library/Application Support, "
                        f"~/Library/Saved Application State"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "library_bloat",
                        "size_bytes": library_size,
                        "size_formatted": _fmt_bytes(library_size),
                    },
                )
            )

        # Create INFO finding with all user directories
        if all_users_sizes:
            user_details = "\n".join(
                [f"  {name}: {_fmt_bytes(size)}" for name, size in sorted(all_users_sizes, key=lambda x: x[1], reverse=True)]
            )
            findings.append(
                Finding(
                    title=f"User directory sizes ({len(all_users_sizes)} users found)",
                    description=(
                        f"Found {len(all_users_sizes)} user directories:\n{user_details}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "user_summary",
                        "user_count": len(all_users_sizes),
                        "users": all_users_sizes,
                    },
                )
            )

        # Create breakdown for current user's subdirectories
        current_user_name = os.getenv("USER", "unknown")
        subdir_sizes = self._get_current_user_breakdown(current_user)

        if subdir_sizes:
            subdir_details = "\n".join(
                [
                    f"  {name}: {_fmt_bytes(size)}"
                    for name, size in sorted(subdir_sizes.items(), key=lambda x: x[1], reverse=True)
                ]
            )
            findings.append(
                Finding(
                    title=f"Current user '{current_user_name}' subdirectory breakdown",
                    description=(
                        f"Directory sizes for {current_user_name}:\n{subdir_details}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "subdir_breakdown",
                        "user_name": current_user_name,
                        "subdirs": subdir_sizes,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational cleanup suggestions for profile bloat."""
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "large_user_dir":
                user_name = finding.data.get("user_name", "unknown")
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Review {user_name}'s profile ({size_str})",
                        description=(
                            f"User {user_name}'s profile (/Users/{user_name}) is {size_str}. "
                            f"Check the following directories for cleanup opportunities:\n"
                            f"  - ~/Downloads (old installers, archived files)\n"
                            f"  - ~/Library/Caches (safe to remove, will be regenerated)\n"
                            f"  - ~/Library/Application Support (app-specific data)\n"
                            f"  - ~/Library/Logs (old logs can be archived)\n"
                            f"  - ~/Movies, ~/Music (old media files)\n"
                            f"Consider running: du -sh ~/[Desktop,Documents,Downloads,Movies,Music,Library]"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "library_bloat":
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Review Library directory ({size_str})",
                        description=(
                            f"The Library directory is {size_str}, which is unusually large. "
                            f"Use these commands to identify the largest subdirectories:\n"
                            f"  du -sh ~/Library/*\n"
                            f"  du -sh ~/Library/Caches/*\n"
                            f"  du -sh ~/Library/Application\\ Support/*\n"
                            f"Then consider removing old caches or application support data. "
                            f"Always backup before removing files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "user_summary":
                actions.append(
                    Action(
                        title="User directory size report",
                        description=(
                            "This is informational. The report shows all user directories found on the system. "
                            "Individual users with directories over 50GB are flagged above. "
                            f"Total users found: {finding.data.get('user_count', 0)}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "subdir_breakdown":
                actions.append(
                    Action(
                        title="Current user subdirectory breakdown",
                        description=(
                            "This shows how space is distributed across the current user's major directories. "
                            "Focus cleanup efforts on the largest directories (typically Downloads, Library, Documents)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_directories(self, users_dir: Path) -> list[Path]:
        """Get all user home directories, excluding system directories."""
        user_dirs = []
        try:
            for item in users_dir.iterdir():
                if not item.is_dir(follow_symlinks=False):
                    continue
                if item.name in SKIP_DIRS:
                    continue
                if item.name.startswith("."):
                    continue
                user_dirs.append(item)
        except (OSError, PermissionError):
            pass
        return sorted(user_dirs)

    def _get_directory_size(self, path: Path) -> int:
        """Get directory size in bytes using du -sk (top-level only)."""
        if not path.exists():
            return 0

        try:
            result = subprocess.run(
                ["du", "-sk", str(path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # du outputs size in 1024-byte blocks
                size_blocks = int(result.stdout.split()[0])
                return size_blocks * 1024
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass

        return 0

    def _get_current_user_breakdown(self, current_user: Path) -> dict[str, int]:
        """Get size breakdown of current user's major subdirectories."""
        breakdown = {}

        for subdir in SUBDIRS_TO_CHECK:
            subdir_path = current_user / subdir
            if subdir_path.exists():
                try:
                    size = self._get_directory_size(subdir_path)
                    if size > 0:
                        breakdown[subdir] = size
                except Exception:
                    continue

        return breakdown


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
