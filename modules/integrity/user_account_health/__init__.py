import os
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
    name = "user_account_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all user accounts
        dscl_users = self._get_dscl_users()
        if not dscl_users:
            findings.append(
                Finding(
                    title="Could not check your user accounts",
                    description=(
                        "We couldn't read the list of people who have accounts on this Mac. "
                        "Because we couldn't look, we can't confirm everything "
                        "is normal.\n\n"
                        "What to do: Restart your Mac and run the checkup again."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "dscl_read_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for duplicate UIDs
        uid_duplicates = self._find_duplicate_uids(dscl_users)
        for uid, accounts in uid_duplicates.items():
            findings.append(
                Finding(
                    title=f"Two accounts share the same ID number ({uid})",
                    description=(
                        f"Accounts {', '.join(accounts)} are using the same unique ID "
                        f"number ({uid}). "
                        "This is a technical error that can confuse the Mac about who "
                        "owns which files.\n\n"
                        "What to do: Contact Apple Support to fix the ID numbers. Do not "
                        "try to edit this manually."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "duplicate_uid", "uid": uid, "accounts": accounts},
                )
            )

        # Check current user's account
        current_user = os.environ.get("USER", "")
        if current_user:
            current_user_checks = self._check_current_user(current_user, dscl_users)
            findings.extend(current_user_checks)

        # Check for orphaned home directories
        orphaned_dirs = self._find_orphaned_home_dirs(dscl_users)
        for orphaned_path in orphaned_dirs:
            findings.append(
                Finding(
                    title=f"Leftover folder for a deleted user: {orphaned_path}",
                    description=(
                        f"The folder {orphaned_path} exists, but there is no matching "
                        "user account on your Mac. "
                        "This is usually just a leftover from an account that was removed "
                        "in the past. "
                        "\n\n"
                        "What to do: If you recognize the name and know that person no "
                        "longer uses this Mac, you can safely delete the folder. Otherwise, "
                        "leave it alone."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "orphaned_home_dir", "path": orphaned_path},
                )
            )

        # Report accounts and groups (INFO level)
        if dscl_users:
            user_list = ", ".join(sorted(dscl_users.keys()))
            findings.append(
                Finding(
                    title="User accounts found",
                    description=(
                        f"System has {len(dscl_users)} user account(s): {user_list}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "user_accounts", "users": list(dscl_users.keys())},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "dscl_read_failed":
                actions.append(
                    Action(
                        title="Directory service read failed",
                        description=(
                            "The system's directory service (dscl) could not be queried. "
                            "Try restarting the system or running 'dscacheutil -q user' to test connectivity. "
                            "If the problem persists, you may need to repair the directory service or restore from backup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "duplicate_uid":
                uid = finding.data.get("uid")
                accounts = finding.data.get("accounts", [])
                actions.append(
                    Action(
                        title=f"Resolve duplicate UID {uid}",
                        description=(
                            f"UID {uid} is shared by accounts: {', '.join(accounts)}. "
                            "Use 'dscl . -read /Users/<account> UniqueID' to verify UIDs, then "
                            "contact Apple Support to reassign conflicting UIDs. Do not manually edit dscl. "
                            "Duplicate UIDs can cause file permission issues across the system."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "home_dir_missing":
                username = finding.data.get("username")
                expected_path = finding.data.get("expected_path")
                actions.append(
                    Action(
                        title=f"Home directory missing for user {username}",
                        description=(
                            f"User {username} has a dscl record but home directory {expected_path} does not exist. "
                            "This prevents the user from logging in or accessing their files. "
                            "Recreate the home directory with 'createhomedir -c' (requires root), "
                            "or recreate the user account via System Settings > Users & Groups and restore files from backup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "home_dir_mismatch":
                username = finding.data.get("username")
                dscl_path = finding.data.get("dscl_path")
                actual_path = finding.data.get("actual_path")
                actions.append(
                    Action(
                        title=f"Home directory path mismatch for user {username}",
                        description=(
                            f"User {username} dscl record points to {dscl_path} but home is actually at {actual_path}. "
                            "This can cause login and file access issues. "
                            "Update dscl with: dscl . -change /Users/{username} NFSHomeDirectory {dscl_path} {actual_path}, "
                            "or use System Settings > Advanced Options to correct the home directory path."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "shell_invalid":
                username = finding.data.get("username")
                shell = finding.data.get("shell")
                actions.append(
                    Action(
                        title=f"Invalid login shell for user {username}",
                        description=(
                            f"User {username} has shell {shell} which does not exist. "
                            "Reset the shell to /bin/zsh with: "
                            "dscl . -change /Users/{username} UserShell {shell} /bin/zsh"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "preferences_unreadable":
                username = finding.data.get("username")
                actions.append(
                    Action(
                        title=f"User preferences corrupted for {username}",
                        description=(
                            f"User {username}'s preference files are corrupted or unreadable. "
                            "Preferences can be reset by deleting ~/Library/Preferences and logging out. "
                            "First backup: cp -r ~/Library/Preferences ~/Library/Preferences.backup, "
                            "then: rm -rf ~/Library/Preferences"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "orphaned_home_dir":
                path = finding.data.get("path")
                actions.append(
                    Action(
                        title=f"Remove orphaned home directory",
                        description=(
                            f"Directory {path} is not owned by any user account. "
                            "Safe to delete if the user has been removed. "
                            "Delete with: rm -rf {path}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "user_accounts":
                actions.append(
                    Action(
                        title="User accounts status",
                        description=(
                            "User accounts are properly configured. "
                            "No critical issues detected."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_dscl_users(self) -> dict[str, int]:
        """Get list of user accounts and UIDs from dscl. Filter out system accounts (UID < 500)."""
        users = {}
        try:
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users", "UniqueID"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        username = parts[0]
                        try:
                            uid = int(parts[-1])
                            # Filter out system accounts (UID < 500)
                            if uid >= 500:
                                users[username] = uid
                        except (ValueError, IndexError):
                            pass
        except (OSError, subprocess.SubprocessError):
            pass
        return users

    def _find_duplicate_uids(self, users: dict[str, int]) -> dict[int, list[str]]:
        """Find duplicate UIDs across users."""
        uid_map = {}
        for username, uid in users.items():
            if uid not in uid_map:
                uid_map[uid] = []
            uid_map[uid].append(username)

        # Return only duplicates
        return {uid: accounts for uid, accounts in uid_map.items() if len(accounts) > 1}

    def _check_current_user(self, username: str, dscl_users: dict[str, int]) -> list[Finding]:
        """Check current user's account integrity."""
        findings = []

        # Check if user exists in dscl
        if username not in dscl_users:
            findings.append(
                Finding(
                    title=f"Your account ({username}) is missing from the system list",
                    description=(
                        f"You are logged in as {username}, but the system's internal list "
                        "of users doesn't show this account. "
                        "This is a serious technical error that might prevent you from "
                        "logging in next time. "
                        "\n\n"
                        "What to do: Do not log out or restart until you have saved your "
                        "work. Contact Apple Support immediately to repair your account "
                        "record."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "user_not_in_dscl", "username": username},
                )
            )
            return findings

        # Get home directory from dscl
        dscl_home = self._get_dscl_home_dir(username)
        if not dscl_home:
            findings.append(
                Finding(
                    title=f"Could not check the home folder for {username}",
                    description=(
                        "We couldn't read the location of the home folder for the account "
                        f"{username}. "
                        "This might mean the account record is damaged. "
                        "\n\n"
                        "What to do: If this is your account, contact Apple Support. If "
                        "it is an old account you don't use, you can ignore this or delete "
                        "the account."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "dscl_home_read_failed", "username": username},
                )
            )
            return findings

        # Check if home directory exists
        if not os.path.exists(dscl_home):
            findings.append(
                Finding(
                    title=f"Home folder missing for {username}",
                    description=(
                        f"The system says the home folder for {username} should be at "
                        f"{dscl_home}, but that folder doesn't exist. "
                        "This means that user cannot log in or access their files. "
                        "\n\n"
                        "What to do: If this is your account, contact Apple Support to "
                        "restore the folder. If it is an old account, you can delete the "
                        "account to clean up the error."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "home_dir_missing",
                        "username": username,
                        "expected_path": dscl_home,
                    },
                )
            )

        # Check if actual home directory matches dscl record
        actual_home = os.path.expanduser("~" + username)
        if actual_home != dscl_home:
            findings.append(
                Finding(
                    title=f"Home folder path mismatch for {username}",
                    description=(
                        f"The system record points to {dscl_home}, but the actual folder "
                        f"is at {actual_home}. "
                        "This mismatch can cause file access problems. "
                        "\n\n"
                        "What to do: Contact Apple Support to correct the path in the "
                        "system settings. Do not move folders manually."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "home_dir_mismatch",
                        "username": username,
                        "dscl_path": dscl_home,
                        "actual_path": actual_home,
                    },
                )
            )

        # Check login shell
        shell = self._get_dscl_shell(username)
        if shell and not os.path.exists(shell):
            findings.append(
                Finding(
                    title=f"Invalid login shell for {username}",
                    description=(
                        f"The account {username} is set to use a command-line tool ({shell}) "
                        "that doesn't exist on this Mac. "
                        "This can prevent the user from logging in properly. "
                        "\n\n"
                        "What to do: Contact Apple Support to reset the login shell to "
                        "the standard default. Do not try to fix this manually."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "shell_invalid", "username": username, "shell": shell},
                )
            )

        # Check if preferences are readable
        if dscl_home and os.path.exists(dscl_home):
            prefs_file = os.path.join(
                dscl_home, "Library/Preferences/.GlobalPreferences.plist"
            )
            if os.path.exists(prefs_file):
                try:
                    result = subprocess.run(
                        ["defaults", "read", prefs_file],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        findings.append(
                            Finding(
                                title=f"Corrupted settings file for {username}",
                                description=(
                                    f"The settings file {prefs_file} for {username} is "
                                    "damaged or unreadable. "
                                    "This might cause apps to crash or reset their preferences.\n\n"
                                    "What to do: If this is your account, back up your "
                                    "data and contact Apple Support. If it is an old account, "
                                    "you can ignore this."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check": "preferences_unreadable",
                                    "username": username,
                                },
                            )
                        )
                except (OSError, subprocess.SubprocessError):
                    pass

        return findings

    def _get_dscl_home_dir(self, username: str) -> str | None:
        """Get home directory from dscl record."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", f"/Users/{username}", "NFSHomeDirectory"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Output format: "NFSHomeDirectory: /Users/username"
                for line in result.stdout.strip().split("\n"):
                    if "NFSHomeDirectory" in line:
                        parts = line.split(": ", 1)
                        if len(parts) == 2:
                            return parts[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _get_dscl_shell(self, username: str) -> str | None:
        """Get login shell from dscl record."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", f"/Users/{username}", "UserShell"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Output format: "UserShell: /bin/bash"
                for line in result.stdout.strip().split("\n"):
                    if "UserShell" in line:
                        parts = line.split(": ", 1)
                        if len(parts) == 2:
                            return parts[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _find_orphaned_home_dirs(self, dscl_users: dict[str, int]) -> list[str]:
        """Find directories in /Users without matching user accounts."""
        orphaned = []
        users_dir = Path("/Users")

        if not users_dir.exists():
            return orphaned

        for item in users_dir.iterdir():
            if not item.is_dir():
                continue

            dirname = item.name
            # Skip system directories
            if dirname.startswith("."):
                continue
            if dirname in ("Guest", "Shared"):
                continue

            # Check if this directory corresponds to any user account
            if dirname not in dscl_users:
                orphaned.append(str(item))

        return orphaned
