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


class Module(ModuleBase):
    name = "photos_library_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Photos library exists
        library_path = Path.home() / "Pictures" / "Photos Library.photoslibrary"
        library_exists = library_path.exists() and library_path.is_dir()

        if not library_exists:
            findings.append(
                Finding(
                    title="Photos library not found",
                    description="Photos library not found at ~/Pictures/Photos Library.photoslibrary. "
                    "The library may have been moved or deleted.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "library_exists", "exists": False},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Library exists - get size
        library_size_bytes = self._get_dir_size(library_path)
        library_size_gb = library_size_bytes / (1024**3)

        findings.append(
            Finding(
                title=f"Photos library size: {library_size_gb:.2f} GB",
                description=f"Photos library at ~/Pictures/Photos Library.photoslibrary is {library_size_gb:.2f} GB.",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "library_size", "size_bytes": library_size_bytes, "size_gb": library_size_gb},
            )
        )

        # Check iCloud Photos status
        icloud_photos_enabled = self._is_icloud_photos_enabled()
        findings.append(
            Finding(
                title=f"iCloud Photos: {'Enabled' if icloud_photos_enabled else 'Disabled'}",
                description=f"iCloud Photo Library is currently {'enabled' if icloud_photos_enabled else 'disabled'}.",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "icloud_photos", "enabled": icloud_photos_enabled},
            )
        )

        # Check storage optimization setting
        optimize_storage_enabled = self._is_optimize_storage_enabled()
        download_originals_enabled = self._is_download_originals_enabled()

        storage_setting = "Unknown"
        if optimize_storage_enabled:
            storage_setting = "Optimize Storage"
        elif download_originals_enabled:
            storage_setting = "Download Originals"
        else:
            storage_setting = "Unknown"

        findings.append(
            Finding(
                title=f"Photos storage optimization: {storage_setting}",
                description=f"Photos app storage setting is: {storage_setting}.",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "storage_optimization",
                    "optimize_storage": optimize_storage_enabled,
                    "download_originals": download_originals_enabled,
                    "setting": storage_setting,
                },
            )
        )

        # Flag warning if library is very large and optimize storage is NOT enabled
        if library_size_gb > 100 and not optimize_storage_enabled and icloud_photos_enabled:
            findings.append(
                Finding(
                    title="Large Photos library with Optimize Storage disabled",
                    description=(
                        f"Photos library is {library_size_gb:.2f} GB and Optimize Storage is not enabled. "
                        "This means full-resolution images are stored locally, which may consume significant disk space. "
                        "Consider enabling Optimize Storage to save disk space while keeping iCloud Photos enabled."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "large_library_no_optimization",
                        "size_gb": library_size_gb,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "library_exists":
                if not finding.data.get("exists"):
                    actions.append(
                        Action(
                            title="Photos library missing",
                            description=(
                                "The Photos library was not found at ~/Pictures/Photos Library.photoslibrary. "
                                "If you recently moved or deleted the library, you can restore it from Time Machine. "
                                "To check Time Machine, open System Preferences > Time Machine and click 'Browse Other Backup Disks'. "
                                "If the library is on an external drive, connect the drive and the Photos app may find it automatically."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "library_size":
                size_gb = finding.data.get("size_gb", 0)
                actions.append(
                    Action(
                        title="Photos library size information",
                        description=(
                            f"Your Photos library is {size_gb:.2f} GB. "
                            "Monitor this size periodically as it grows with new photos. "
                            "Ensure you have adequate free disk space (at least 10-20% free is recommended)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "icloud_photos":
                enabled = finding.data.get("enabled", False)
                if enabled:
                    actions.append(
                        Action(
                            title="iCloud Photos is enabled",
                            description=(
                                "iCloud Photo Library is enabled. Photos are synced to iCloud and accessible on all your devices. "
                                "To disable iCloud Photos, open Photos app > Settings (cmd+,) > iCloud > uncheck 'iCloud Photos'."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="iCloud Photos is disabled",
                            description=(
                                "iCloud Photo Library is not enabled. To enable it, open Photos app > Settings (cmd+,) > iCloud > "
                                "check 'iCloud Photos'. This will sync your photos to iCloud and make them accessible on all your devices."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "storage_optimization":
                setting = finding.data.get("setting", "Unknown")
                optimize = finding.data.get("optimize_storage", False)
                download = finding.data.get("download_originals", False)

                if optimize:
                    actions.append(
                        Action(
                            title="Optimize Storage is enabled",
                            description=(
                                "Optimize Storage is enabled. Full-resolution photos are stored in iCloud, "
                                "and your Mac stores optimized, lower-resolution versions locally to save disk space. "
                                "Original files are downloaded when needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif download:
                    actions.append(
                        Action(
                            title="Download Originals is enabled",
                            description=(
                                "Download Originals is enabled. Full-resolution photos are downloaded and stored on your Mac. "
                                "This provides the fastest access to photos but requires more disk space."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Photos storage setting unknown",
                            description=(
                                "Could not determine the Photos storage setting. "
                                "Open Photos app > Settings (cmd+,) > iCloud to verify your storage preference."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "large_library_no_optimization":
                size_gb = finding.data.get("size_gb", 0)
                actions.append(
                    Action(
                        title="Large Photos library without optimization",
                        description=(
                            f"Your Photos library is {size_gb:.2f} GB and Optimize Storage is disabled. "
                            "To enable Optimize Storage and save disk space: "
                            "1. Open Photos app > Settings (cmd+,) > iCloud "
                            "2. Select 'Optimize Mac Storage' instead of 'Download Originals' "
                            "3. Photos will replace full-resolution images with optimized versions, freeing up disk space. "
                            "Original files remain safely in iCloud."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_icloud_photos_enabled(self) -> bool:
        """Check if iCloud Photos is enabled via defaults."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.photolibraryd", "PQLCloudEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _is_optimize_storage_enabled(self) -> bool:
        """Check if Optimize Storage is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.photolibraryd", "CloudPhotoLibraryOptimizeStorageEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _is_download_originals_enabled(self) -> bool:
        """Check if Download Originals is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.photolibraryd", "CloudPhotoLibraryDownloadOriginalEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_dir_size(self, path: Path) -> int:
        """Recursively calculate directory size in bytes."""
        total = 0
        try:
            for entry in path.rglob("*"):
                if entry.is_file(follow_symlinks=False):
                    try:
                        total += entry.stat().st_size
                    except (OSError, ValueError):
                        pass
        except Exception:
            pass

        return total
