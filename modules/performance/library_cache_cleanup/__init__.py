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
TOTAL_CACHE_WARNING = 10 * 1024 * 1024 * 1024  # 10 GB
SINGLE_CACHE_WARNING = 3 * 1024 * 1024 * 1024  # 3 GB

# Known cache-heavy apps
KNOWN_CACHE_APPS = {
    "Slack": ["slack.com.slack", "Slack"],
    "Spotify": ["com.spotify.client", "Spotify"],
    "Microsoft Teams": ["com.microsoft.teams", "Microsoft Teams", "MicrosoftTeams"],
    "Discord": ["com.hnc.Discord", "Discord"],
    "Zoom": ["us.zoom.videomeetings", "zoom.us", "Zoom"],
    "Dropbox": ["com.getdropbox.dropbox", "Dropbox"],
    "Google Drive": ["com.google.drive", "Google Drive", "GoogleDriveFS"],
}


class Module(ModuleBase):
    name = "library_cache_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()
        caches_dir = home / "Library" / "Caches"

        if not caches_dir.exists():
            return CheckResult(module_name=self.name, findings=findings)

        # Scan all cache directories and get sizes
        cache_sizes = self._scan_caches(caches_dir)
        total_size = sum(cache_sizes.values())

        # Identify known app caches
        known_apps_info = self._identify_known_apps(cache_sizes)

        # Get top 10 largest directories
        top_caches = sorted(cache_sizes.items(), key=lambda x: x[1], reverse=True)[:10]

        # Check for warnings
        has_total_warning = total_size >= TOTAL_CACHE_WARNING
        has_single_warning = any(size >= SINGLE_CACHE_WARNING for size in cache_sizes.values())

        # Add findings
        if has_total_warning:
            findings.append(
                Finding(
                    title=f"High total cache size: {_fmt_bytes(total_size)}",
                    description=(
                        f"~/Library/Caches contains {_fmt_bytes(total_size)}, exceeding the 10GB threshold. "
                        f"This may impact disk space and system performance. Review the cache directories below."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "total_cache_size",
                        "size_bytes": total_size,
                        "size_formatted": _fmt_bytes(total_size),
                    },
                )
            )

        if has_single_warning:
            for app_name, size in cache_sizes.items():
                if size >= SINGLE_CACHE_WARNING:
                    findings.append(
                        Finding(
                            title=f"Large cache directory: {app_name} ({_fmt_bytes(size)})",
                            description=(
                                f"The cache for {app_name} is {_fmt_bytes(size)}, exceeding the 3GB threshold. "
                                f"This cache can be safely removed and will be regenerated when the app runs."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "type": "large_single_cache",
                                "app_name": app_name,
                                "size_bytes": size,
                                "size_formatted": _fmt_bytes(size),
                            },
                        )
                    )

        if known_apps_info:
            findings.append(
                Finding(
                    title=f"Known cache-heavy apps detected: {len(known_apps_info)} apps",
                    description=(
                        f"Detected caches for {len(known_apps_info)} known cache-heavy applications: "
                        f"{', '.join(known_apps_info.keys())}. "
                        f"These apps are known to accumulate large caches. "
                        f"Total size: {_fmt_bytes(sum(known_apps_info.values()))}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "known_apps",
                        "apps": known_apps_info,
                        "total_size": sum(known_apps_info.values()),
                        "total_formatted": _fmt_bytes(sum(known_apps_info.values())),
                    },
                )
            )

        if top_caches:
            findings.append(
                Finding(
                    title=f"Top 10 cache directories: {_fmt_bytes(sum(size for _, size in top_caches))}",
                    description=(
                        f"Largest cache directories:\n" +
                        "\n".join(
                            f"  {i+1}. {name}: {_fmt_bytes(size)}"
                            for i, (name, size) in enumerate(top_caches)
                        )
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "top_caches",
                        "caches": {name: size for name, size in top_caches},
                        "total_size": sum(size for _, size in top_caches),
                        "total_formatted": _fmt_bytes(sum(size for _, size in top_caches)),
                    },
                )
            )

        if total_size > 0:
            findings.append(
                Finding(
                    title=f"Total cache size: {_fmt_bytes(total_size)}",
                    description=(
                        f"~/Library/Caches currently uses {_fmt_bytes(total_size)} across "
                        f"{len(cache_sizes)} directories. Cache files are safe to delete and will "
                        f"be regenerated as needed by applications."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "total_cache_info",
                        "size_bytes": total_size,
                        "size_formatted": _fmt_bytes(total_size),
                        "directory_count": len(cache_sizes),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "total_cache_size":
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"High cache size: {size_str}",
                        description=(
                            f"Total cache exceeds 10GB. To safely clear all caches:\n"
                            f"  rm -rf ~/Library/Caches/*\n"
                            f"All applications will regenerate their caches as needed on next launch. "
                            f"Note: Some apps may need to be restarted after cache clearing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "large_single_cache":
                app_name = finding.data.get("app_name", "unknown")
                size_str = finding.data.get("size_formatted", "unknown")
                actions.append(
                    Action(
                        title=f"Large cache for {app_name}: {size_str}",
                        description=(
                            f"The {app_name} cache uses {size_str}. This is safe to remove. "
                            f"Restart {app_name} after deletion to regenerate the cache. "
                            f"To remove: rm -rf ~/Library/Caches/*{app_name}*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "known_apps":
                apps = finding.data.get("apps", {})
                total_str = finding.data.get("total_formatted", "unknown")
                app_list = ", ".join(apps.keys())
                actions.append(
                    Action(
                        title=f"Known cache-heavy apps caches: {total_str}",
                        description=(
                            f"Detected caches for: {app_list}. "
                            f"These caches are safe to delete individually by removing their directories in ~/Library/Caches. "
                            f"Applications will regenerate caches when restarted."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "top_caches":
                size_str = finding.data.get("total_formatted", "unknown")
                caches = finding.data.get("caches", {})
                cache_list = "\n".join(
                    f"  - {name}: {_fmt_bytes(size)}"
                    for name, size in caches.items()
                )
                actions.append(
                    Action(
                        title=f"Top cache directories: {size_str}",
                        description=(
                            f"Largest cache directories (safe to remove):\n{cache_list}\n"
                            f"You can selectively remove individual caches from ~/Library/Caches/ "
                            f"or clear all with: rm -rf ~/Library/Caches/*"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "total_cache_info":
                size_str = finding.data.get("size_formatted", "unknown")
                dir_count = finding.data.get("directory_count", 0)
                actions.append(
                    Action(
                        title=f"Cache overview: {size_str} in {dir_count} directories",
                        description=(
                            f"Cache files are generally safe to delete. To manage caches:\n"
                            f"  1. Individual app: rm -rf ~/Library/Caches/[app-name]\n"
                            f"  2. All caches: rm -rf ~/Library/Caches/*\n"
                            f"Note: Some cached data helps apps start faster. Delete selectively."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_caches(self, caches_dir: Path) -> dict[str, int]:
        """Scan cache directories and return dict of {dir_name: size_bytes}."""
        cache_sizes = {}

        try:
            for item in caches_dir.iterdir():
                try:
                    if item.is_dir(follow_symlinks=False):
                        dir_size = self._get_directory_size(item)
                        if dir_size > 0:
                            cache_sizes[item.name] = dir_size
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return cache_sizes

    def _identify_known_apps(self, cache_sizes: dict[str, int]) -> dict[str, int]:
        """Identify known cache-heavy apps in the cache_sizes dict."""
        known_apps_info = {}

        for app_display_name, cache_identifiers in KNOWN_CACHE_APPS.items():
            total_for_app = 0
            for cache_dir_name in cache_sizes:
                for identifier in cache_identifiers:
                    if identifier.lower() in cache_dir_name.lower():
                        total_for_app += cache_sizes[cache_dir_name]
                        break

            if total_for_app > 0:
                known_apps_info[app_display_name] = total_for_app

        return known_apps_info

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
