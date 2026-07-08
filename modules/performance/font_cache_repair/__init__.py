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
FONT_CACHE_SIZE_WARNING = 500 * 1024 * 1024  # 500 MB
FONT_COUNT_WARNING = 1000


class Module(ModuleBase):
    name = "font_cache_repair"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check font cache size in /private/var/folders
        var_folders_cache_size = self._get_var_folders_cache_size()

        # Check system font cache
        system_cache_size = self._get_system_cache_size()

        # Count installed fonts
        font_count = self._count_installed_fonts()

        # Check font server status
        font_server_responsive = self._is_font_server_responsive()

        # Check for font database issues
        has_database_issues = self._has_database_issues()

        # Calculate total font cache size
        total_cache_size = var_folders_cache_size + system_cache_size

        # Add findings
        if total_cache_size > FONT_CACHE_SIZE_WARNING:
            findings.append(
                Finding(
                    title=f"Font cache is bloated: {_fmt_bytes(total_cache_size)}",
                    description=(
                        f"The font cache exceeds 500 MB ({_fmt_bytes(total_cache_size)}). "
                        f"A bloated font cache can cause slowdowns, app crashes, and rendering glitches. "
                        f"This often indicates cache corruption on older Macs."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "bloated_cache",
                        "cache_size_bytes": total_cache_size,
                        "cache_size_formatted": _fmt_bytes(total_cache_size),
                    },
                )
            )

        if not font_server_responsive:
            findings.append(
                Finding(
                    title="Font server is not responding",
                    description=(
                        "The atsutil font server is not responding to ping requests. "
                        "This indicates the font server may be in an unstable state and could cause "
                        "font rendering issues and application crashes."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "font_server_unresponsive",
                    },
                )
            )

        if font_count > FONT_COUNT_WARNING:
            findings.append(
                Finding(
                    title=f"Excessive fonts installed: {font_count}",
                    description=(
                        f"The system has {font_count} installed fonts, exceeding the {FONT_COUNT_WARNING} threshold. "
                        f"Excessive fonts slow down system performance, increase boot time, and can cause rendering issues. "
                        f"Consider disabling or removing unused fonts."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "excessive_fonts",
                        "font_count": font_count,
                    },
                )
            )

        if has_database_issues:
            findings.append(
                Finding(
                    title="Font database may have integrity issues",
                    description=(
                        "Font database validation detected potential issues. "
                        "This can cause fonts to not load correctly and lead to rendering glitches. "
                        "The font cache may need to be rebuilt."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "database_issues",
                    },
                )
            )

        # Add informational findings
        findings.append(
            Finding(
                title=f"Font cache size: {_fmt_bytes(total_cache_size)}",
                description=(
                    f"Font cache status:\n"
                    f"  /var/folders cache: {_fmt_bytes(var_folders_cache_size)}\n"
                    f"  System cache: {_fmt_bytes(system_cache_size)}\n"
                    f"  Total: {_fmt_bytes(total_cache_size)}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "type": "cache_info",
                    "var_folders_size": var_folders_cache_size,
                    "system_cache_size": system_cache_size,
                    "total_size": total_cache_size,
                },
            )
        )

        findings.append(
            Finding(
                title=f"Installed fonts: {font_count}",
                description=(
                    f"System has {font_count} installed fonts across system and user directories. "
                    f"(Warning threshold: {FONT_COUNT_WARNING}+)"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "type": "font_count",
                    "font_count": font_count,
                },
            )
        )

        findings.append(
            Finding(
                title=f"Font server status: {'responsive' if font_server_responsive else 'unresponsive'}",
                description=(
                    f"The atsutil font server is {'responding normally' if font_server_responsive else 'not responding'}. "
                    f"A responsive font server is needed for proper font management and rendering."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "type": "font_server_status",
                    "responsive": font_server_responsive,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "bloated_cache":
                size_str = finding.data.get("cache_size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Font cache is bloated: {size_str}",
                        description=(
                            f"Font cache exceeds 500 MB and should be rebuilt. "
                            f"To clear the font cache and reset the font server:\n"
                            f"  1. Quit all applications\n"
                            f"  2. Run: sudo atsutil databases -removeUser\n"
                            f"  3. Run: sudo atsutil server -shutdown\n"
                            f"  4. Run: sudo atsutil server -ping\n"
                            f"  5. Restart your Mac\n"
                            f"\n"
                            f"This removes corrupted cache and forces macOS to rebuild it cleanly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "font_server_unresponsive":
                actions.append(
                    Action(
                        title="Font server is not responding",
                        description=(
                            f"The atsutil font server is unresponsive. To restart it:\n"
                            f"  1. Quit all applications\n"
                            f"  2. Run: sudo atsutil server -shutdown\n"
                            f"  3. Run: sudo atsutil server -ping\n"
                            f"  4. Restart your Mac if the server does not start\n"
                            f"\n"
                            f"If the server continues to be unresponsive, also run:\n"
                            f"  sudo atsutil databases -removeUser"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "excessive_fonts":
                font_count = finding.data.get("font_count", 0)
                actions.append(
                    Action(
                        title=f"Excessive fonts installed: {font_count}",
                        description=(
                            f"The system has {font_count} fonts installed ({FONT_COUNT_WARNING}+ is excessive). "
                            f"To manage fonts:\n"
                            f"  1. Open Font Book (Applications > Font Book)\n"
                            f"  2. Review installed fonts\n"
                            f"  3. Disable or remove unused fonts\n"
                            f"\n"
                            f"This will improve font rendering speed and reduce memory usage."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "database_issues":
                actions.append(
                    Action(
                        title="Font database has integrity issues",
                        description=(
                            f"Font database validation detected issues. Rebuild the database:\n"
                            f"  1. Quit all applications\n"
                            f"  2. Run: sudo atsutil databases -remove\n"
                            f"  3. Run: sudo atsutil server -shutdown\n"
                            f"  4. Run: sudo atsutil server -ping\n"
                            f"  5. Restart your Mac\n"
                            f"\n"
                            f"This rebuilds the entire font database from scratch."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_var_folders_cache_size(self) -> int:
        """Get font cache size in /private/var/folders for com.apple.ATS directories."""
        total_size = 0
        try:
            result = subprocess.run(
                ["find", "/private/var/folders", "-name", "com.apple.ATS", "-type", "d"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            path = Path(line.strip())
                            if path.exists():
                                total_size += self._get_directory_size(path)
                        except (OSError, PermissionError):
                            continue
        except (subprocess.TimeoutExpired, Exception):
            pass

        return total_size

    def _get_system_cache_size(self) -> int:
        """Get system font cache size at /System/Library/Caches/com.apple.ATS/."""
        try:
            system_cache = Path("/System/Library/Caches/com.apple.ATS")
            if system_cache.exists():
                return self._get_directory_size(system_cache)
        except (OSError, PermissionError):
            pass

        return 0

    def _count_installed_fonts(self) -> int:
        """Count installed fonts using system_profiler SPFontsDataType."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPFontsDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Count lines with "Full Name:" which indicates a font entry
                font_count = result.stdout.count("Full Name:")
                return font_count
        except (subprocess.TimeoutExpired, Exception):
            pass

        return 0

    def _is_font_server_responsive(self) -> bool:
        """Check if font server (atsutil) is responsive via atsutil server -ping."""
        try:
            result = subprocess.run(
                ["atsutil", "server", "-ping"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False

    def _has_database_issues(self) -> bool:
        """Check for font database issues via atsutil databases -list."""
        try:
            result = subprocess.run(
                ["atsutil", "databases", "-list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                # Check for error or issue indicators in output
                issue_indicators = ["error", "invalid", "corrupt", "failed"]
                return any(indicator in output for indicator in issue_indicators)
        except (subprocess.TimeoutExpired, Exception):
            pass

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
