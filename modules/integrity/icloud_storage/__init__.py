import json
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
    name = "icloud_storage"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get iCloud storage quota and usage
        quota_bytes, usage_bytes = self._get_icloud_storage_info()

        if quota_bytes is not None and usage_bytes is not None:
            usage_percent = (usage_bytes / quota_bytes * 100) if quota_bytes > 0 else 0
            quota_gb = quota_bytes / (1024**3)
            usage_gb = usage_bytes / (1024**3)
            available_gb = (quota_bytes - usage_bytes) / (1024**3)

            findings.append(
                Finding(
                    title=f"iCloud storage: {usage_gb:.2f} GB / {quota_gb:.2f} GB used ({usage_percent:.1f}%)",
                    description=(
                        f"iCloud storage usage: {usage_gb:.2f} GB out of {quota_gb:.2f} GB quota. "
                        f"Available: {available_gb:.2f} GB."
                    ),
                    severity=Severity.WARNING if usage_percent > 90 else Severity.INFO,
                    category=self.category,
                    data={
                        "check": "icloud_storage",
                        "quota_bytes": quota_bytes,
                        "usage_bytes": usage_bytes,
                        "usage_percent": usage_percent,
                        "quota_gb": quota_gb,
                        "usage_gb": usage_gb,
                        "available_gb": available_gb,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    title="Could not determine iCloud storage usage",
                    description="Unable to read iCloud storage information from system settings.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "icloud_storage", "available": False},
                )
            )

        # Check iCloud Drive enabled status and cache size
        icloud_drive_enabled = self._is_icloud_drive_enabled()
        cache_size_bytes = self._get_icloud_cache_size()

        if icloud_drive_enabled:
            findings.append(
                Finding(
                    title="iCloud Drive is enabled",
                    description="iCloud Drive is currently enabled on this device.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "icloud_drive_enabled", "enabled": True},
                )
            )

            if cache_size_bytes > 0:
                cache_size_gb = cache_size_bytes / (1024**3)
                findings.append(
                    Finding(
                        title=f"Local iCloud cache: {cache_size_gb:.2f} GB",
                        description=(
                            f"Total size of ~/Library/Mobile Documents/ (iCloud local cache): {cache_size_gb:.2f} GB. "
                            "This is a local cache of your iCloud files."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "cache_size",
                            "size_bytes": cache_size_bytes,
                            "size_gb": cache_size_gb,
                        },
                    )
                )
        else:
            findings.append(
                Finding(
                    title="iCloud Drive is disabled",
                    description="iCloud Drive is not currently enabled on this device.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "icloud_drive_enabled", "enabled": False},
                )
            )

        # Check Desktop & Documents sync status
        desktop_docs_sync_enabled = self._is_desktop_documents_sync_enabled()

        if desktop_docs_sync_enabled:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is enabled",
                    description="iCloud Desktop & Documents sync is currently enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "desktop_docs_sync", "enabled": True},
                )
            )

            # Check local Desktop and Documents folder sizes
            desktop_docs_size = self._get_desktop_documents_size()
            if desktop_docs_size > 0:
                size_gb = desktop_docs_size / (1024**3)
                severity = Severity.WARNING if size_gb > 5 else Severity.INFO
                findings.append(
                    Finding(
                        title=f"Desktop & Documents local size: {size_gb:.2f} GB",
                        description=(
                            f"Your local Desktop and Documents folders total {size_gb:.2f} GB. "
                            "With Desktop & Documents sync enabled, these files consume iCloud quota. "
                            "Ensure you have enough iCloud storage to accommodate this."
                        ),
                        severity=severity,
                        category=self.category,
                        data={
                            "check": "desktop_docs_size",
                            "size_bytes": desktop_docs_size,
                            "size_gb": size_gb,
                        },
                    )
                )
        else:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is disabled",
                    description="iCloud Desktop & Documents sync is not currently enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "desktop_docs_sync", "enabled": False},
                )
            )

        # Check for large files in iCloud Drive
        large_files = self._find_large_files_in_icloud()
        if large_files:
            findings.append(
                Finding(
                    title=f"Found {len(large_files)} large file(s) in iCloud Drive",
                    description=(
                        f"Found {len(large_files)} files larger than 100 MB in iCloud Drive. "
                        "Large files consume significant quota. Consider reviewing and removing files you no longer need."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "large_files",
                        "count": len(large_files),
                        "files": large_files,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "icloud_storage":
                if not finding.data.get("available", True):
                    actions.append(
                        Action(
                            title="iCloud storage info unavailable",
                            description=(
                                "Could not read iCloud storage information. "
                                "Ensure iCloud is signed in via System Settings > [Your Name] > iCloud."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    usage_percent = finding.data.get("usage_percent", 0)
                    usage_gb = finding.data.get("usage_gb", 0)
                    available_gb = finding.data.get("available_gb", 0)

                    if usage_percent > 90:
                        actions.append(
                            Action(
                                title="iCloud storage is nearly full",
                                description=(
                                    f"Your iCloud storage is {usage_percent:.1f}% full ({usage_gb:.2f} GB used, "
                                    f"{available_gb:.2f} GB available). Consider: (1) Deleting files from iCloud Drive, "
                                    "(2) Disabling Desktop & Documents sync if not needed, "
                                    "(3) Deleting old photos from Photos app, "
                                    "(4) Upgrading your iCloud storage plan. "
                                    "Visit iCloud.com to manage your storage."
                                ),
                                risk_level=RiskLevel.SAFE,
                                success=True,
                            )
                        )
                    else:
                        actions.append(
                            Action(
                                title="iCloud storage status",
                                description=(
                                    f"Your iCloud storage is {usage_percent:.1f}% full ({usage_gb:.2f} GB used). "
                                    f"You have {available_gb:.2f} GB available."
                                ),
                                risk_level=RiskLevel.SAFE,
                                success=True,
                            )
                        )

            elif check == "icloud_drive_enabled":
                if finding.data.get("enabled"):
                    actions.append(
                        Action(
                            title="iCloud Drive is enabled",
                            description=(
                                "iCloud Drive is enabled. Your documents are synced to iCloud. "
                                "To disable, go to System Settings > [Your Name] > iCloud > iCloud Drive and toggle off."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="iCloud Drive is disabled",
                            description=(
                                "iCloud Drive is disabled. To enable, go to System Settings > [Your Name] > iCloud > "
                                "iCloud Drive and toggle on."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "cache_size":
                size_gb = finding.data.get("size_gb", 0)
                actions.append(
                    Action(
                        title="iCloud local cache status",
                        description=(
                            f"Your local iCloud cache is {size_gb:.2f} GB. "
                            "This is a local copy of your iCloud files. macOS manages this space automatically."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "desktop_docs_sync":
                if finding.data.get("enabled"):
                    actions.append(
                        Action(
                            title="Desktop & Documents sync is enabled",
                            description=(
                                "Desktop & Documents sync is enabled. Your Desktop and Documents folders are backed up to iCloud. "
                                "Ensure you have sufficient iCloud quota. To disable, go to System Settings > [Your Name] > iCloud > "
                                "iCloud Drive > Options and uncheck 'Desktop & Documents Folders'."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Desktop & Documents sync is disabled",
                            description=(
                                "Desktop & Documents sync is disabled. Your Desktop and Documents are not synced to iCloud. "
                                "To enable, go to System Settings > [Your Name] > iCloud > iCloud Drive > Options and check "
                                "'Desktop & Documents Folders'."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "desktop_docs_size":
                size_gb = finding.data.get("size_gb", 0)
                actions.append(
                    Action(
                        title="Desktop & Documents folder size",
                        description=(
                            f"Your Desktop and Documents folders total {size_gb:.2f} GB. "
                            "With Desktop & Documents sync enabled, this entire size consumes your iCloud quota. "
                            "Consider moving large files elsewhere or disabling sync if you don't need it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "large_files":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Large files detected in iCloud",
                        description=(
                            f"Found {count} files larger than 100 MB in iCloud Drive. "
                            "Large files consume significant storage quota. "
                            "Review and consider deleting files you no longer need. "
                            "Access iCloud.com or the Finder to manage your iCloud files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_icloud_storage_info(self) -> tuple[int | None, int | None]:
        """Get iCloud storage quota and usage in bytes.

        Returns (quota_bytes, usage_bytes) or (None, None) if unavailable.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.iCloud.plist", "MobileMeAccounts"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None, None

            # Try to extract StorageUsageInfo from the plist output
            lines = result.stdout.splitlines()
            quota_bytes = None
            usage_bytes = None

            for i, line in enumerate(lines):
                if "StorageUsageTotal" in line:
                    # Extract numeric value
                    try:
                        parts = line.split("=")
                        if len(parts) > 1:
                            value_str = parts[1].strip().rstrip(";")
                            usage_bytes = int(value_str)
                    except (ValueError, IndexError):
                        pass
                elif "StorageQuota" in line:
                    try:
                        parts = line.split("=")
                        if len(parts) > 1:
                            value_str = parts[1].strip().rstrip(";")
                            quota_bytes = int(value_str)
                    except (ValueError, IndexError):
                        pass

            return quota_bytes, usage_bytes
        except (OSError, subprocess.SubprocessError):
            return None, None

    def _is_icloud_drive_enabled(self) -> bool:
        """Check if iCloud Drive is enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.iCloud.plist",
                    "iCloudDriveEnabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _is_desktop_documents_sync_enabled(self) -> bool:
        """Check if Desktop & Documents sync is enabled."""
        try:
            # Check the Finder preferences for Desktop & Documents sync
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.iCloud.plist",
                    "DesktopAndDocumentsManagedByiCloud",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_icloud_cache_size(self) -> int:
        """Get the size of ~/Library/Mobile Documents/ directory in bytes."""
        try:
            cache_path = Path.home() / "Library" / "Mobile Documents"
            if cache_path.exists() and cache_path.is_dir():
                return self._get_dir_size(cache_path)
        except Exception:
            pass

        return 0

    def _get_desktop_documents_size(self) -> int:
        """Get the combined size of Desktop and Documents folders in bytes."""
        total = 0
        try:
            home = Path.home()
            for folder in ["Desktop", "Documents"]:
                folder_path = home / folder
                if folder_path.exists() and folder_path.is_dir():
                    total += self._get_dir_size(folder_path)
        except Exception:
            pass

        return total

    def _find_large_files_in_icloud(self, size_threshold: int = 100 * 1024 * 1024) -> list[str]:
        """Find files larger than size_threshold in iCloud Drive.

        Args:
            size_threshold: Minimum file size in bytes (default 100 MB)

        Returns:
            List of file paths larger than threshold
        """
        large_files = []
        try:
            icloud_path = Path.home() / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
            if icloud_path.exists() and icloud_path.is_dir():
                for entry in icloud_path.rglob("*"):
                    if entry.is_file(follow_symlinks=False):
                        try:
                            if entry.stat().st_size > size_threshold:
                                # Store just the relative path for readability
                                rel_path = entry.relative_to(icloud_path)
                                large_files.append(str(rel_path))
                        except (OSError, ValueError):
                            pass
        except Exception:
            pass

        return large_files

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
