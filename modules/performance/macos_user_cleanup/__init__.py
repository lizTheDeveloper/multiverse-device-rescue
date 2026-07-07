import os
import subprocess
from datetime import datetime, timedelta
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
UNUSED_ACCOUNT_DIR_WARNING_THRESHOLD = 10 * 1024**3  # 10 GB
LAST_LOGIN_THRESHOLD_DAYS = 365  # 1 year

# System directories to skip
SKIP_USERS = {
    "root",
    "daemon",
    "nobody",
    "_www",
    "_calendar",
    "_dovecot",
    "_ftp",
    "_lp",
    "_mysql",
    "_postgres",
    "_sshd",
    "_uucp",
    "Guest",
    "Shared",
}


class Module(ModuleBase):
    name = "macos_user_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of all users
        users_info = self._get_user_accounts()
        if not users_info:
            return CheckResult(module_name=self.name, findings=[])

        # Analyze each user
        old_unused_accounts = []
        all_user_details = []

        for username, uid, home_dir in users_info:
            # Check home directory size
            size_bytes = self._get_directory_size(Path(home_dir))

            # Check last login date
            last_login_date = self._get_last_login(username)
            last_login_str = last_login_date.strftime("%Y-%m-%d") if last_login_date else "Unknown"
            days_since_login = (datetime.now() - last_login_date).days if last_login_date else None

            all_user_details.append({
                "username": username,
                "uid": uid,
                "home": home_dir,
                "size_bytes": size_bytes,
                "last_login": last_login_str,
                "days_since_login": days_since_login,
            })

            # Flag if account hasn't been logged into in over 1 year AND has significant data
            if last_login_date and days_since_login and days_since_login > LAST_LOGIN_THRESHOLD_DAYS:
                old_unused_accounts.append({
                    "username": username,
                    "home": home_dir,
                    "size_bytes": size_bytes,
                    "last_login": last_login_str,
                    "days_since_login": days_since_login,
                })

            # Flag if unused account directory exceeds 10GB (regardless of last login)
            if size_bytes > UNUSED_ACCOUNT_DIR_WARNING_THRESHOLD:
                findings.append(
                    Finding(
                        title=f"User '{username}' home directory is {_fmt_bytes(size_bytes)} (>{_fmt_bytes(UNUSED_ACCOUNT_DIR_WARNING_THRESHOLD)})",
                        description=(
                            f"/Users/{username} is using {_fmt_bytes(size_bytes)}, which is consuming significant disk space. "
                            f"Last login: {last_login_str}. "
                            f"Consider archiving or removing this account's data if it is no longer in use."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "large_unused_account",
                            "username": username,
                            "home": home_dir,
                            "size_bytes": size_bytes,
                            "size_formatted": _fmt_bytes(size_bytes),
                            "last_login": last_login_str,
                            "days_since_login": days_since_login,
                        },
                    )
                )

        # Flag old unused accounts (not logged in for 1+ year)
        for account in old_unused_accounts:
            findings.append(
                Finding(
                    title=f"User '{account['username']}' has not logged in for {account['days_since_login']} days",
                    description=(
                        f"/Users/{account['username']} has not been logged into since {account['last_login']} ({account['days_since_login']} days). "
                        f"Home directory is {_fmt_bytes(account['size_bytes'])}. "
                        f"This account may be safe to archive or remove if the user has permanently moved out or is no longer active."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "old_unused_account",
                        "username": account['username'],
                        "home": account['home'],
                        "size_bytes": account['size_bytes'],
                        "size_formatted": _fmt_bytes(account['size_bytes']),
                        "last_login": account['last_login'],
                        "days_since_login": account['days_since_login'],
                    },
                )
            )

        # Create INFO finding with all user accounts
        if all_user_details:
            user_details = "\n".join(
                [
                    f"  {d['username']} (UID {d['uid']}): {_fmt_bytes(d['size_bytes'])} - Last login: {d['last_login']}"
                    for d in sorted(all_user_details, key=lambda x: x['size_bytes'], reverse=True)
                ]
            )
            findings.append(
                Finding(
                    title=f"User accounts summary ({len(all_user_details)} users found)",
                    description=(
                        f"Found {len(all_user_details)} user accounts on the system:\n{user_details}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "user_summary",
                        "user_count": len(all_user_details),
                        "users": all_user_details,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational cleanup suggestions for old/unused accounts."""
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "large_unused_account":
                username = finding.data.get("username", "unknown")
                size_str = finding.data.get("size_formatted", "unknown")
                last_login = finding.data.get("last_login", "unknown")
                actions.append(
                    Action(
                        title=f"Review account '{username}' ({size_str})",
                        description=(
                            f"User account {username} has {size_str} of data (last login: {last_login}). "
                            f"Consider the following options:\n"
                            f"  1. Archive the account: ditto /Users/{username} /Volumes/ExternalDrive/{username}_backup\n"
                            f"  2. Remove the account: System Settings → General → Users & Groups → (unlock) → select user → delete account\n"
                            f"  3. Transfer data: Move important files from /Users/{username} to a shared location first\n\n"
                            f"Always backup important data before removing accounts."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "old_unused_account":
                username = finding.data.get("username", "unknown")
                size_str = finding.data.get("size_formatted", "unknown")
                days_since = finding.data.get("days_since_login", 0)
                last_login = finding.data.get("last_login", "unknown")
                actions.append(
                    Action(
                        title=f"Review inactive account '{username}' (no login for {days_since} days)",
                        description=(
                            f"User account {username} has not been logged into since {last_login} ({days_since} days ago) "
                            f"and uses {size_str} of disk space. "
                            f"This is likely an account that can be safely archived or removed if:\n"
                            f"  - The user has permanently moved out or is no longer active\n"
                            f"  - All important data has been transferred to shared locations\n"
                            f"  - A backup has been made\n\n"
                            f"To check if there is important data:\n"
                            f"  ls -la /Users/{username}\n"
                            f"  du -sh /Users/{username}/*\n\n"
                            f"To archive: ditto /Users/{username} /Volumes/ExternalDrive/{username}_backup\n"
                            f"To remove: System Settings → General → Users & Groups → (unlock) → select user → delete account"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "user_summary":
                actions.append(
                    Action(
                        title="User accounts summary",
                        description=(
                            "This is an informational report of all user accounts on the system. "
                            f"Total users found: {finding.data.get('user_count', 0)}. "
                            "Individual accounts with high disk usage or that haven't been logged into in over 1 year "
                            "are flagged above."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_accounts(self) -> list[tuple[str, int, str]]:
        """
        Get list of real user accounts (UID >= 500) excluding system accounts.
        Returns list of (username, uid, home_dir) tuples.
        """
        users = []
        try:
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users", "UniqueID"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        username = parts[0]
                        try:
                            uid = int(parts[1])
                            # Filter: real users (UID >= 500) and skip known system accounts
                            if uid >= 500 and username not in SKIP_USERS:
                                home_dir = self._get_user_home_dir(username)
                                if home_dir:
                                    users.append((username, uid, home_dir))
                        except (ValueError, IndexError):
                            continue
        except (OSError, subprocess.TimeoutExpired):
            pass

        return users

    def _get_user_home_dir(self, username: str) -> str | None:
        """Get home directory for a user."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", f"/Users/{username}", "NFSHomeDirectory"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Output format: "NFSHomeDirectory: /Users/username"
                for line in result.stdout.strip().split("\n"):
                    if line.startswith("NFSHomeDirectory:"):
                        return line.split(":", 1)[1].strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    def _get_last_login(self, username: str) -> datetime | None:
        """
        Get last login date for a user using the 'last' command.
        Returns datetime object or None if unable to determine.
        """
        # Fallback: use 'last' command - it shows login history
        try:
            result = subprocess.run(
                ["last", "-t", "yyyymmddHHmmss", username],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if lines:
                    # First line is the most recent login
                    first_line = lines[0]
                    # Format: "username  ttys001  Dec 20 2024 09:15 - 09:45  (00:30)"
                    # or: "username  ttys001  Dec  5 10:30   still logged in"
                    # or: "root     console                      Dec 15 08:00 - 08:05  (00:05)"
                    # Try to parse the date from the line
                    try:
                        # Extract the date part - it's after the terminal/IP
                        parts = first_line.split()
                        # Find the month (Jan, Feb, Mar, etc.)
                        months = {
                            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
                        }
                        month_idx = None
                        for i, part in enumerate(parts):
                            if part in months:
                                month_idx = i
                                break

                        if month_idx is not None and month_idx + 1 < len(parts):
                            month = months[parts[month_idx]]
                            try:
                                day = int(parts[month_idx + 1])

                                # Check if the next part is a year (4 digits) or time (HH:MM)
                                year_or_time = parts[month_idx + 2] if month_idx + 2 < len(parts) else ""

                                if year_or_time and len(year_or_time) == 4 and year_or_time.isdigit():
                                    # Year is provided
                                    year = int(year_or_time)
                                    time_str = parts[month_idx + 3] if month_idx + 3 < len(parts) else "00:00"
                                else:
                                    # No year provided - assume current or previous year
                                    time_str = year_or_time
                                    now = datetime.now()
                                    year = now.year

                                # Parse time
                                hour, minute = 0, 0
                                if time_str and ":" in time_str:
                                    hour, minute = map(int, time_str.split(":"))

                                login_date = datetime(year, month, day, hour, minute)

                                # If this is in the future, use previous year
                                now = datetime.now()
                                if login_date > now:
                                    login_date = datetime(year - 1, month, day, hour, minute)

                                return login_date
                            except (ValueError, IndexError):
                                pass
                    except Exception:
                        pass
        except (OSError, subprocess.TimeoutExpired):
            pass

        return None

    def _get_directory_size(self, path: Path) -> int:
        """Get directory size in bytes using du -sk."""
        try:
            result = subprocess.run(
                ["du", "-sk", str(path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # du outputs size in 1024-byte blocks
                size_blocks = int(result.stdout.split()[0])
                return size_blocks * 1024
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass

        return 0


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
