import subprocess
from pathlib import Path
from collections import defaultdict

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
FONT_FOLDER_SIZE_WARNING_THRESHOLD = 1024 * 1024 * 1024  # 1GB


class Module(ModuleBase):
    name = "font_issues"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Count installed fonts and check for issues
        font_count, fonts_by_location = self._count_installed_fonts()

        # Check total font count
        if font_count > FONT_COUNT_WARNING_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Found {font_count} installed fonts (excessive)",
                    description=(
                        f"The system has {font_count} installed fonts. "
                        f"Excessive fonts ({FONT_COUNT_WARNING_THRESHOLD}+) can cause "
                        f"app crashes, slow boot times, and rendering glitches on older Macs. "
                        f"Consider removing unused fonts to improve performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"font_count": font_count, "check": "excessive_font_count"},
                )
            )

        # Check folder sizes
        folder_sizes = self._get_folder_sizes(fonts_by_location)
        user_fonts_path = Path.home() / "Library/Fonts"
        user_fonts_size = folder_sizes.get(str(user_fonts_path), 0)

        if user_fonts_size > FONT_FOLDER_SIZE_WARNING_THRESHOLD:
            findings.append(
                Finding(
                    title=f"User fonts folder is large ({_fmt_bytes(user_fonts_size)})",
                    description=(
                        f"~/Library/Fonts is {_fmt_bytes(user_fonts_size)}, which is unusually large (> 1GB). "
                        f"This likely indicates font packs or collections have been installed. "
                        f"Large font collections can slow down system boot and font rendering. "
                        f"Review installed fonts and remove unused ones."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"size_bytes": user_fonts_size, "check": "large_user_fonts"},
                )
            )

        # Check for duplicate fonts
        duplicates = self._find_duplicate_fonts(fonts_by_location)
        if duplicates:
            dup_list = ", ".join(sorted(duplicates.keys()))
            findings.append(
                Finding(
                    title=f"Found {len(duplicates)} duplicate font names",
                    description=(
                        f"The following font names appear in multiple locations: {dup_list}. "
                        f"Duplicate fonts can cause rendering inconsistencies and slow down font loading. "
                        f"Use Font Book to identify and remove duplicates."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"duplicates": duplicates, "check": "duplicate_fonts"},
                )
            )

        # Add informational findings about font counts per location
        for location, count in fonts_by_location.items():
            size = folder_sizes.get(location, 0)
            findings.append(
                Finding(
                    title=f"Font count at {location}: {count} fonts",
                    description=(
                        f"Location: {location}\n"
                        f"Font count: {count}\n"
                        f"Folder size: {_fmt_bytes(size)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "location": location,
                        "count": count,
                        "size_bytes": size,
                        "check": "font_location_info",
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "excessive_font_count":
                actions.append(
                    Action(
                        title="Found excessive number of fonts",
                        description=(
                            f"Found {finding.data.get('font_count')} fonts. "
                            f"To manage fonts on macOS: "
                            f"1. Open Font Book (Applications > Font Book). "
                            f"2. Sort fonts by 'Enabled' status to see which are active. "
                            f"3. Identify and disable unused fonts (don't delete system fonts). "
                            f"4. For fonts you no longer need, use Font Book's 'Remove Family' option. "
                            f"Removing unused fonts will improve rendering speed and prevent display issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "large_user_fonts":
                actions.append(
                    Action(
                        title="User fonts folder is unusually large",
                        description=(
                            f"~/Library/Fonts is {_fmt_bytes(finding.data.get('size_bytes'))} (> 1GB). "
                            f"This is unusual and likely contains font packs or collections. "
                            f"Recommendations: "
                            f"1. Open Font Book and review your installed fonts. "
                            f"2. Disable any font families you don't use regularly. "
                            f"3. Consider removing font packages from third-party applications. "
                            f"4. Do NOT delete fonts that came with your Mac. "
                            f"Reducing the font library will improve boot times and responsiveness."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "duplicate_fonts":
                duplicates = finding.data.get("duplicates", {})
                dup_desc = "\n".join(
                    f"  - {name}: {', '.join(locations)}"
                    for name, locations in sorted(duplicates.items())
                )
                actions.append(
                    Action(
                        title="Found duplicate fonts in multiple locations",
                        description=(
                            f"The following fonts appear in multiple locations:\n{dup_desc}\n\n"
                            f"To resolve duplicates: "
                            f"1. Open Font Book. "
                            f"2. For each duplicate, select one and use 'File > Remove Family' "
                            f"(after confirming it's not the system version). "
                            f"3. Keep only one copy of each font. "
                            f"Font duplicates can cause rendering issues and slow font loading."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "font_location_info":
                actions.append(
                    Action(
                        title=f"Font location: {finding.data.get('location')}",
                        description=(
                            f"Location: {finding.data.get('location')}\n"
                            f"Fonts: {finding.data.get('count')}\n"
                            f"Size: {_fmt_bytes(finding.data.get('size_bytes'))}\n"
                            f"This is informational. No action required."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _count_installed_fonts(self) -> tuple[int, dict[str, int]]:
        """
        Count all installed fonts using find command.
        Returns (total_count, {location: count})
        """
        font_locations = [
            Path.home() / "Library/Fonts",
            Path("/Library/Fonts"),
            Path("/System/Library/Fonts"),
        ]

        total_count = 0
        fonts_by_location = {}

        for location in font_locations:
            if not location.exists():
                continue

            try:
                # Use subprocess with find command to count font files
                # Extensions: .ttf, .otf, .ttc, .dfont
                result = subprocess.run(
                    [
                        "find",
                        str(location),
                        "-type",
                        "f",
                        "(",
                        "-name",
                        "*.ttf",
                        "-o",
                        "-name",
                        "*.otf",
                        "-o",
                        "-name",
                        "*.ttc",
                        "-o",
                        "-name",
                        "*.dfont",
                        ")",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    # Count lines in output (each line is a file)
                    lines = [line for line in result.stdout.strip().split("\n") if line]
                    count = len(lines)
                    fonts_by_location[str(location)] = count
                    total_count += count
            except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
                # If subprocess fails, try fallback with Path.rglob
                try:
                    font_extensions = {".ttf", ".otf", ".dfont", ".ttc"}
                    fonts = [
                        f for f in location.rglob("*")
                        if f.is_file() and f.suffix.lower() in font_extensions
                    ]
                    count = len(fonts)
                    fonts_by_location[str(location)] = count
                    total_count += count
                except (OSError, PermissionError):
                    fonts_by_location[str(location)] = 0

        return total_count, fonts_by_location

    def _get_folder_sizes(self, locations: dict[str, int]) -> dict[str, int]:
        """Get the total size of each font folder."""
        sizes = {}
        for location_str in locations.keys():
            location = Path(location_str)
            sizes[location_str] = self._get_directory_size(location)
        return sizes

    def _find_duplicate_fonts(self, fonts_by_location: dict[str, int]) -> dict[str, list[str]]:
        """
        Find duplicate fonts by name collision.
        Returns {font_name: [location1, location2, ...]}
        """
        font_names = defaultdict(list)

        for location_str in fonts_by_location.keys():
            location = Path(location_str)
            if not location.exists():
                continue

            try:
                # Get all font files in this location
                font_extensions = {".ttf", ".otf", ".dfont", ".ttc"}
                fonts = [
                    f.name for f in location.rglob("*")
                    if f.is_file() and f.suffix.lower() in font_extensions
                ]
                for font_name in fonts:
                    font_names[font_name].append(location_str)
            except (OSError, PermissionError):
                continue

        # Return only duplicates (fonts that appear in multiple locations)
        duplicates = {
            name: locations
            for name, locations in font_names.items()
            if len(locations) > 1
        }
        return duplicates

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
