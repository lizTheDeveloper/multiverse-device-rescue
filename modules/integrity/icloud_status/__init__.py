import re
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
    name = "icloud_status"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check iCloud account status
        account_info = self._get_icloud_account_info()
        if account_info is None:
            findings.append(
                Finding(
                    title="iCloud is not signed in",
                    description="No iCloud account is currently signed in on this device.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "icloud_account", "signed_in": False},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # iCloud is signed in
        findings.append(
            Finding(
                title=f"iCloud account signed in: {account_info}",
                description=f"iCloud account '{account_info}' is currently signed in.",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "icloud_account", "signed_in": True, "account": account_info},
            )
        )

        # Check Desktop & Documents sync status
        sync_enabled = self._is_desktop_documents_sync_enabled()
        if sync_enabled:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is enabled",
                    description="iCloud Desktop & Documents sync is currently enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "sync_enabled", "sync_enabled": True},
                )
            )

            # Check for .icloud placeholder files which indicate incomplete sync
            icloud_files = self._count_icloud_placeholder_files()
            if icloud_files > 0:
                findings.append(
                    Finding(
                        title=f"Found {icloud_files} .icloud placeholder files",
                        description=(
                            f"Desktop & Documents sync is enabled but found {icloud_files} .icloud files "
                            "(incomplete downloads). This typically means files are still syncing to the local drive."
                        ),
                        severity=Severity.WARNING if icloud_files > 20 else Severity.INFO,
                        category=self.category,
                        data={"check": "icloud_files", "count": icloud_files},
                    )
                )
        else:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is disabled",
                    description="iCloud Desktop & Documents sync is not currently enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "sync_enabled", "sync_enabled": False},
                )
            )

        # Check iCloud Drive cache size
        cache_size_bytes = self._get_icloud_cache_size()
        if cache_size_bytes > 0:
            cache_size_gb = cache_size_bytes / (1024**3)
            findings.append(
                Finding(
                    title=f"Local iCloud cache: {cache_size_gb:.2f} GB",
                    description=f"Total size of ~/Library/Mobile Documents/ (iCloud local cache): {cache_size_gb:.2f} GB.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "cache_size", "size_bytes": cache_size_bytes, "size_gb": cache_size_gb},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "icloud_account":
                if finding.data.get("signed_in"):
                    account = finding.data.get("account", "unknown")
                    actions.append(
                        Action(
                            title="iCloud account status",
                            description=f"iCloud account '{account}' is signed in. Verify this is the correct account.",
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="No iCloud account signed in",
                            description=(
                                "To sign in to iCloud, open System Settings > [Your Name] > iCloud "
                                "(or System Settings > Apple Account > iCloud on newer macOS versions). "
                                "Then sign in with your Apple ID."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "sync_enabled":
                if finding.data.get("sync_enabled"):
                    actions.append(
                        Action(
                            title="Desktop & Documents sync is enabled",
                            description=(
                                "Files from your Desktop and Documents folders are being synced to iCloud. "
                                "To disable this, open System Settings > [Your Name] > iCloud > iCloud Drive > "
                                "Options, and uncheck 'Desktop & Documents Folders'."
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
                                "Desktop & Documents sync is not enabled. To enable it, open System Settings > "
                                "[Your Name] > iCloud > iCloud Drive > Options, and check 'Desktop & Documents Folders'. "
                                "This will sync your Desktop and Documents folders to iCloud."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "icloud_files":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="iCloud sync in progress",
                        description=(
                            f"Found {count} .icloud placeholder files. This indicates that files are still being synced "
                            "to your local drive. This is normal behavior during initial sync or when adding new files. "
                            "Allow some time for the sync to complete. If .icloud files persist for days, "
                            "check your internet connection and iCloud Drive status."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "cache_size":
                size_gb = finding.data.get("size_gb", 0)
                actions.append(
                    Action(
                        title="iCloud local cache size",
                        description=(
                            f"Your local iCloud cache (~~/Library/Mobile Documents/) is {size_gb:.2f} GB. "
                            "This is normal and expected. These files are cached copies of iCloud-synced documents. "
                            "They will be removed if iCloud cache space is needed for other data."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_icloud_account_info(self) -> str | None:
        """Get iCloud account information from defaults."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.iCloud.plist", "MobileMeAccounts"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None

            # Parse plist output for MobileMeAccountDisplay
            for line in result.stdout.splitlines():
                if "MobileMeAccountDisplay" in line:
                    # Extract the email from something like:
                    # MobileMeAccountDisplay = "alice@icloud.com";
                    match = re.search(r'MobileMeAccountDisplay\s*=\s*"([^"]+)"', line)
                    if match:
                        return match.group(1)
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_desktop_documents_sync_enabled(self) -> bool:
        """Check if Desktop & Documents sync is enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.iCloud.plist",
                    "Enabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False

            # Check for various iCloud Drive sync keys
            # Try alternate key names
            try:
                result2 = subprocess.run(
                    [
                        "defaults",
                        "read",
                        "~/Library/Preferences/com.apple.iCloud.plist",
                        "ForceSyncEnabled",
                    ],
                    capture_output=True,
                    text=True,
                    shell=False,
                )
            except Exception:
                pass

            # Most reliable: check if the iCloudDriveEnabled key is set
            try:
                result3 = subprocess.run(
                    [
                        "defaults",
                        "read",
                        "com.apple.iCloud.plist",
                        "iCloudDrive",
                    ],
                    capture_output=True,
                    text=True,
                )
                if result3.returncode == 0:
                    value = result3.stdout.strip()
                    return value == "1"
            except Exception:
                pass

            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _count_icloud_placeholder_files(self) -> int:
        """Count .icloud placeholder files in Desktop and Documents."""
        count = 0
        try:
            home = Path.home()
            # Check both Desktop and Documents
            for folder in ["Desktop", "Documents"]:
                folder_path = home / folder
                if folder_path.exists() and folder_path.is_dir():
                    # Find all .icloud files
                    count += len(list(folder_path.glob("**/*.icloud")))
        except Exception:
            pass

        return count

    def _get_icloud_cache_size(self) -> int:
        """Get the size of ~/Library/Mobile Documents/ directory."""
        try:
            cache_path = Path.home() / "Library" / "Mobile Documents"
            if cache_path.exists() and cache_path.is_dir():
                return self._get_dir_size(cache_path)
        except Exception:
            pass

        return 0

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
