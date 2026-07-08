import os
import plistlib
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
    name = "icloud_storage_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check iCloud account status
        account_info = self._check_icloud_account()
        if account_info["signed_in"]:
            findings.append(
                Finding(
                    title="iCloud account signed in",
                    description=(
                        f"iCloud account '{account_info.get('account_email', 'Unknown')}' is signed in and active."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "account_status", "signed_in": True},
                )
            )
        else:
            findings.append(
                Finding(
                    title="iCloud account not signed in",
                    description=(
                        "iCloud account appears to be not signed in. This will prevent "
                        "iCloud backup, photo sync, and document cloud storage from working. "
                        "Sign in to your iCloud account in System Settings to restore these features."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "account_status", "signed_in": False},
                )
            )

        # Check iCloud Drive status
        drive_info = self._check_icloud_drive()
        if drive_info["enabled"]:
            findings.append(
                Finding(
                    title="iCloud Drive is enabled",
                    description="iCloud Drive is enabled and syncing.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "drive_status", "enabled": True},
                )
            )

            # Check for sync issues
            if drive_info.get("has_errors"):
                findings.append(
                    Finding(
                        title="iCloud Drive sync errors detected",
                        description=(
                            "iCloud Drive has encountered sync errors. This may prevent "
                            "files from being properly backed up to the cloud. Check "
                            "System Settings > [Your Name] > iCloud > iCloud Drive for details."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "drive_errors", "has_errors": True},
                    )
                )

            # Check for stuck uploads
            if drive_info.get("pending_items", 0) > 0:
                findings.append(
                    Finding(
                        title=f"iCloud Drive has {drive_info['pending_items']} items pending upload",
                        description=(
                            f"{drive_info['pending_items']} items are waiting to upload to iCloud Drive. "
                            "This is normal for recent changes, but if this persists, check your network "
                            "connection or restart Finder."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "pending_uploads",
                            "pending_items": drive_info["pending_items"],
                        },
                    )
                )
        else:
            findings.append(
                Finding(
                    title="iCloud Drive is disabled",
                    description="iCloud Drive is not enabled. Enable it in System Settings to sync files across devices.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "drive_status", "enabled": False},
                )
            )

        # Check Desktop & Documents sync
        docs_sync = self._check_desktop_docs_sync()
        if docs_sync["enabled"]:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is enabled",
                    description="Desktop and Documents folders are being synced to iCloud.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "docs_sync_status", "enabled": True},
                )
            )
        else:
            findings.append(
                Finding(
                    title="Desktop & Documents sync is disabled",
                    description="Desktop and Documents sync is not enabled. Enable it in System Settings > [Your Name] > iCloud to back up these folders.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "docs_sync_status", "enabled": False},
                )
            )

        # Check iCloud Photos status
        photos_info = self._check_icloud_photos()
        if photos_info["enabled"]:
            findings.append(
                Finding(
                    title="iCloud Photos is enabled",
                    description="iCloud Photos Library is enabled and syncing.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "photos_status", "enabled": True},
                )
            )
        else:
            findings.append(
                Finding(
                    title="iCloud Photos is disabled",
                    description="iCloud Photos Library is not enabled. Enable it to back up photos and videos.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "photos_status", "enabled": False},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "account_status":
                if not finding.data.get("signed_in"):
                    actions.append(
                        Action(
                            title="Sign in to iCloud account",
                            description=(
                                "Open System Settings > [Your Name] (at the top of the sidebar) and verify "
                                "that you are signed in with your Apple ID. If not, click 'Sign In' and enter "
                                "your Apple ID credentials. You may need to complete two-factor authentication."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "drive_errors":
                actions.append(
                    Action(
                        title="Resolve iCloud Drive sync errors",
                        description=(
                            "To resolve sync errors: (1) Open System Settings > [Your Name] > iCloud > iCloud Drive; "
                            "(2) Check the status and any error messages; (3) Verify you have sufficient iCloud storage; "
                            "(4) Check your internet connection; (5) If errors persist, sign out and back in to iCloud "
                            "in System Settings; (6) If a specific file is stuck, try renaming or moving it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_uploads":
                actions.append(
                    Action(
                        title="Wait for iCloud Drive uploads to complete",
                        description=(
                            "Pending uploads are normal for recently changed files. Leave your Mac connected to the "
                            "internet and plugged in if possible. If uploads are stuck: (1) Check your network connection; "
                            "(2) Verify you have sufficient iCloud storage; (3) Restart Finder (cmd+option+esc, select Finder, click Relaunch); "
                            "(4) If that doesn't work, restart your Mac."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_icloud_account(self) -> dict:
        """Check if iCloud account is signed in."""
        result = {"signed_in": False, "account_email": None}

        try:
            home = os.path.expanduser("~")
            plist_path = os.path.join(
                home, "Library/Preferences/MobileMeAccounts.plist"
            )

            if not os.path.exists(plist_path):
                return result

            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            # Check if there are any accounts
            if isinstance(plist_data, dict):
                accounts = plist_data.get("Accounts", [])
                if isinstance(accounts, list) and len(accounts) > 0:
                    first_account = accounts[0]
                    if isinstance(first_account, dict):
                        email = first_account.get("AccountID")
                        if email:
                            result["signed_in"] = True
                            result["account_email"] = email
        except (OSError, Exception):
            pass

        return result

    def _check_icloud_drive(self) -> dict:
        """Check iCloud Drive status using brctl."""
        result = {"enabled": False, "has_errors": False, "pending_items": 0}

        # Try brctl status
        brctl_output = self._run_brctl_status()
        if brctl_output:
            # Check if drive appears to be active (brctl status shows sync status)
            if "Connected" in brctl_output or "Online" in brctl_output:
                result["enabled"] = True

            # Look for error indicators
            if "Error" in brctl_output or "error" in brctl_output:
                result["has_errors"] = True

            # Count pending items (rough heuristic)
            pending_match = re.search(
                r"Pending[\s:]+(\d+)", brctl_output, re.IGNORECASE
            )
            if pending_match:
                result["pending_items"] = int(pending_match.group(1))

        # Check CloudDocs logs for recent errors
        try:
            home = os.path.expanduser("~")
            logs_dir = os.path.join(home, "Library/Logs/CloudDocs")
            if os.path.isdir(logs_dir):
                # Check if there are recent error logs
                for log_file in os.listdir(logs_dir):
                    if "error" in log_file.lower():
                        result["has_errors"] = True
                        break
        except (OSError, Exception):
            pass

        return result

    def _check_desktop_docs_sync(self) -> dict:
        """Check Desktop & Documents sync status."""
        result = {"enabled": False}

        try:
            home = os.path.expanduser("~")
            plist_path = os.path.join(
                home, "Library/Preferences/com.apple.bird.plist"
            )

            if not os.path.exists(plist_path):
                return result

            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            # Check for Desktop & Documents sync enabled flag
            # The key varies; check common ones
            if isinstance(plist_data, dict):
                # Common key names for Desktop & Documents sync
                if plist_data.get("Enabled") == 1 or plist_data.get(
                    "DesktopDocumentsSyncEnabled"
                ):
                    result["enabled"] = True
                elif "Desktop" in str(plist_data) and "Enabled" in str(plist_data):
                    result["enabled"] = True
        except (OSError, Exception):
            pass

        return result

    def _check_icloud_photos(self) -> dict:
        """Check iCloud Photos status."""
        result = {"enabled": False}

        try:
            home = os.path.expanduser("~")
            plist_path = os.path.join(
                home, "Library/Preferences/com.apple.cloudphotosd.plist"
            )

            if not os.path.exists(plist_path):
                return result

            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            # Check for iCloud Photos enabled flag
            if isinstance(plist_data, dict):
                # Common keys for iCloud Photos
                if plist_data.get("PhotosEnabled") == 1:
                    result["enabled"] = True
                elif plist_data.get("Enabled") == 1:
                    result["enabled"] = True
        except (OSError, Exception):
            pass

        return result

    def _run_brctl_status(self) -> str:
        """Run brctl status and return output."""
        try:
            result = subprocess.run(
                ["brctl", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return ""
