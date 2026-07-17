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
SINGLE_BROWSER_WARNING = 2 * 1024 * 1024 * 1024  # 2 GB
TOTAL_CACHE_WARNING = 5 * 1024 * 1024 * 1024  # 5 GB


class Module(ModuleBase):
    name = "browser_cache_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()
        caches_dir = home / "Library/Caches"

        # Check each browser's cache
        browser_caches = {
            "Safari": caches_dir / "com.apple.Safari",
            "Chrome": caches_dir / "Google/Chrome",
            "Firefox": caches_dir / "Firefox/Profiles",
            "Edge": caches_dir / "Microsoft Edge",
        }

        cache_sizes = {}
        total_cache_size = 0

        for browser_name, cache_path in browser_caches.items():
            size = self._get_directory_size(cache_path)
            cache_sizes[browser_name] = size
            total_cache_size += size

        # Create findings for each browser with non-zero cache
        for browser_name, size in cache_sizes.items():
            if size > 0:
                findings.append(
                    Finding(
                        title=f"{browser_name} cache: {_fmt_bytes(size)}",
                        description=(
                            f"{browser_name} cache is using {_fmt_bytes(size)}. "
                            f"Browser caches can be safely cleared and will be regenerated as needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "type": "browser_cache",
                            "browser": browser_name,
                            "size_bytes": size,
                            "size_formatted": _fmt_bytes(size),
                        },
                    )
                )

                # Flag WARNING if individual browser cache exceeds 2GB
                if size > SINGLE_BROWSER_WARNING:
                    findings.insert(
                        0,
                        Finding(
                            title=f"Large {browser_name} cache: {_fmt_bytes(size)}",
                            description=(
                                f"{browser_name} cache is using {_fmt_bytes(size)}, which exceeds 2GB. "
                                f"Consider clearing this cache to free up significant disk space."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "type": "large_browser_cache",
                                "browser": browser_name,
                                "size_bytes": size,
                                "size_formatted": _fmt_bytes(size),
                            },
                        ),
                    )

        # Flag WARNING if total cache exceeds 5GB
        if total_cache_size > TOTAL_CACHE_WARNING:
            findings.insert(
                0,
                Finding(
                    title=f"High total browser cache: {_fmt_bytes(total_cache_size)}",
                    description=(
                        f"Total browser cache across all browsers is {_fmt_bytes(total_cache_size)}, "
                        f"which exceeds 5GB. Clearing browser caches can significantly free up disk space."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "total_browser_cache",
                        "size_bytes": total_cache_size,
                        "size_formatted": _fmt_bytes(total_cache_size),
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")
            browser = finding.data.get("browser", "unknown")

            if finding_type == "total_browser_cache":
                actions.append(
                    Action(
                        title="High total browser cache report",
                        description=(
                            f"Total browser cache: {size_str}. "
                            f"Clear browser caches through each browser's settings or use: "
                            f"rm -rf ~/Library/Caches/com.apple.Safari, "
                            f"rm -rf ~/Library/Caches/Google/Chrome, "
                            f"rm -rf ~/Library/Caches/Firefox/Profiles, "
                            f"rm -rf ~/Library/Caches/Microsoft\\ Edge"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "large_browser_cache":
                actions.append(
                    Action(
                        title=f"Large {browser} cache: {size_str}",
                        description=(
                            f"{browser} cache is using {size_str}. "
                            f"To clear {browser} cache: "
                            f"1. Open {browser} settings/preferences "
                            f"2. Find 'Clear browsing data' or 'Privacy' section "
                            f"3. Select 'Cached images and files' and choose time range 'All time' "
                            f"4. Click Clear. "
                            f"Or use rm -rf ~/Library/Caches/com.apple.Safari (Safari), "
                            f"~/Library/Caches/Google/Chrome (Chrome), "
                            f"~/Library/Caches/Firefox/Profiles (Firefox), "
                            f"~/Library/Caches/Microsoft\\ Edge (Edge)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "browser_cache":
                actions.append(
                    Action(
                        title=f"{browser} cache: {size_str}",
                        description=(
                            f"{browser} cache is using {size_str}. "
                            f"To clear: Open {browser} settings, find 'Clear browsing data', "
                            f"select 'Cached images and files', choose 'All time', and click Clear."
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
