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

FONT_COUNT_WARNING_THRESHOLD = 500


class Module(ModuleBase):
    name = "font_cache"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Count installed fonts
        font_count = self._count_installed_fonts()
        if font_count > FONT_COUNT_WARNING_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Found {font_count} installed fonts (excessive)",
                    description=(
                        f"The system has {font_count} installed fonts. "
                        f"Excessive fonts ({FONT_COUNT_WARNING_THRESHOLD}+) can slow down "
                        f"font rendering and cause display issues. "
                        f"Consider removing unused fonts to improve performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"font_count": font_count},
                )
            )

        # Check font cache size and location
        cache_location, cache_size = self._find_font_cache()
        if cache_location:
            findings.append(
                Finding(
                    title=f"Font cache location: {cache_location}",
                    description=(
                        f"Font cache located at: {cache_location}\n"
                        f"Cache size: {_fmt_bytes(cache_size)}\n"
                        f"If the font cache is corrupted, it can cause app crashes "
                        f"and slow rendering. The cache is automatically rebuilt "
                        f"if removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "cache_location": cache_location,
                        "cache_size_bytes": cache_size,
                        "cache_size_formatted": _fmt_bytes(cache_size),
                    },
                )
            )

        # Check if atsutil server is running
        atsutil_running = self._is_atsutil_running()
        findings.append(
            Finding(
                title=f"Font server (atsutil) is {'running' if atsutil_running else 'not running'}",
                description=(
                    f"The Apple Type Services (atsutil) server is responsible for "
                    f"font caching and management. "
                    f"Current status: {'running' if atsutil_running else 'not running'}. "
                    f"If you experience font rendering issues, you can reset the font cache."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"atsutil_running": atsutil_running},
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("font_count"):
                actions.append(
                    Action(
                        title="Font count is excessive",
                        description=(
                            f"Found {finding.data.get('font_count')} fonts. "
                            f"To manage fonts on macOS, use Font Book (Applications > Font Book) "
                            f"to disable or remove unused fonts. This can improve rendering speed "
                            f"and prevent display issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("cache_location"):
                actions.append(
                    Action(
                        title="Font cache reset (informational)",
                        description=(
                            f"If you experience font rendering issues or app crashes related to fonts:\n"
                            f"1. Quit all applications\n"
                            f"2. Run: sudo atsutil databases -remove\n"
                            f"3. Restart your Mac\n"
                            f"\n"
                            f"This will remove the font cache at {finding.data.get('cache_location')} "
                            f"and force macOS to rebuild it. Do not run this command unless you "
                            f"experience font-related issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "Font server" in finding.title:
                if finding.data.get("atsutil_running"):
                    actions.append(
                        Action(
                            title="Font server is running normally",
                            description=(
                                "The atsutil server is running and font caching is active. "
                                "No action needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Font server is not running",
                            description=(
                                "The atsutil server is not currently running. "
                                "It should start automatically. If you experience font issues, "
                                "try restarting your Mac."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _count_installed_fonts(self) -> int:
        """Count all installed fonts in system and user font directories."""
        font_paths = [
            Path("/Library/Fonts"),
            Path("/System/Library/Fonts"),
            Path.home() / "Library/Fonts",
        ]

        total_fonts = 0
        for font_path in font_paths:
            if font_path.exists():
                try:
                    # Count font files (common extensions)
                    font_extensions = {".ttf", ".otf", ".dfont", ".ttc"}
                    fonts = [
                        f for f in font_path.rglob("*")
                        if f.is_file() and f.suffix.lower() in font_extensions
                    ]
                    total_fonts += len(fonts)
                except (OSError, PermissionError):
                    pass

        return total_fonts

    def _find_font_cache(self) -> tuple[str | None, int]:
        """Find font cache location in /var/folders and return (path, size)."""
        try:
            var_folders = Path("/var/folders")
            if not var_folders.exists():
                return None, 0

            # Search for com.apple.FontRegistry in /var/folders
            cache_locations = []
            for item in var_folders.rglob("*"):
                if "com.apple.FontRegistry" in str(item):
                    cache_locations.append(item)

            if cache_locations:
                # Return the largest cache directory
                largest = max(cache_locations, key=lambda p: self._get_directory_size(p))
                size = self._get_directory_size(largest)
                return str(largest), size
        except (OSError, PermissionError):
            pass

        return None, 0

    def _is_atsutil_running(self) -> bool:
        """Check if the atsutil (font server) process is running."""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "atsutil"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of all files in directory."""
        if not path.exists():
            return 0

        total_size = 0
        try:
            if path.is_file():
                return path.stat().st_size
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
