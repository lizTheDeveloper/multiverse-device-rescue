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
    name = "mail_config"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Mail.app data directory size
        mail_dir_size = self._get_mail_directory_size()
        if mail_dir_size > 0:
            mail_dir_gb = mail_dir_size / (1024**3)
            if mail_dir_gb > 10:
                findings.append(
                    Finding(
                        title=f"Mail data directory is large: {mail_dir_gb:.2f} GB",
                        description=(
                            f"~/Library/Mail/ is {mail_dir_gb:.2f} GB. Large mail directories can slow down "
                            "Mail.app and system performance. Consider archiving or deleting old emails."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "mail_size", "size_bytes": mail_dir_size, "size_gb": mail_dir_gb},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Mail data directory size: {mail_dir_gb:.2f} GB",
                        description=f"~/Library/Mail/ is {mail_dir_gb:.2f} GB.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "mail_size", "size_bytes": mail_dir_size, "size_gb": mail_dir_gb},
                    )
                )

        # Check Mail accounts
        accounts_info = self._get_mail_accounts()
        if accounts_info is None:
            findings.append(
                Finding(
                    title="Could not determine Mail accounts",
                    description="Unable to read Mail account configuration from defaults.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "mail_accounts", "count": 0, "pop_count": 0, "disabled_count": 0},
                )
            )
        else:
            total_accounts, pop_accounts, disabled_accounts = accounts_info

            # Report total accounts
            findings.append(
                Finding(
                    title=f"Mail accounts configured: {total_accounts}",
                    description=f"Total mail accounts configured: {total_accounts}.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "mail_accounts",
                        "count": total_accounts,
                        "pop_count": pop_accounts,
                        "disabled_count": disabled_accounts,
                    },
                )
            )

            # Warn about disabled accounts
            if disabled_accounts > 0:
                findings.append(
                    Finding(
                        title=f"Disabled mail accounts detected: {disabled_accounts}",
                        description=(
                            f"Found {disabled_accounts} disabled mail account(s). "
                            "Disabled accounts may not sync emails. Check Mail settings to re-enable if needed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "disabled_accounts", "count": disabled_accounts},
                    )
                )

            # Warn about POP accounts
            if pop_accounts > 0:
                findings.append(
                    Finding(
                        title=f"POP mail account(s) detected: {pop_accounts}",
                        description=(
                            f"Found {pop_accounts} POP account(s). POP has limitations and synchronization issues. "
                            "Consider switching to IMAP for better reliability."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "pop_accounts", "count": pop_accounts},
                    )
                )

        # Check if Mail checks for new messages automatically
        check_frequency = self._get_mail_check_frequency()
        if check_frequency is not None:
            findings.append(
                Finding(
                    title=f"Mail check frequency: {check_frequency}",
                    description=f"Mail is set to check for new messages {check_frequency}.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "check_frequency", "frequency": check_frequency},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "mail_size":
                size_gb = finding.data.get("size_gb", 0)
                if size_gb > 10:
                    actions.append(
                        Action(
                            title="Mail data directory is large",
                            description=(
                                f"Your Mail data directory (~~/Library/Mail/) is {size_gb:.2f} GB. "
                                "This is typically caused by not archiving or deleting old emails. "
                                "To improve performance: open Mail > Archive old emails, or delete large mailbox folders. "
                                "You can also use Mail > Preferences > Accounts to delete unnecessary accounts."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Mail data directory size normal",
                            description=f"Your Mail data directory is {size_gb:.2f} GB, which is reasonable.",
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "mail_accounts":
                count = finding.data.get("count", 0)
                pop_count = finding.data.get("pop_count", 0)
                disabled_count = finding.data.get("disabled_count", 0)
                actions.append(
                    Action(
                        title="Mail account configuration",
                        description=(
                            f"Found {count} mail account(s) configured. "
                            f"({pop_count} POP, {disabled_count} disabled). "
                            "Open Mail > Preferences > Accounts to view and manage accounts."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disabled_accounts":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Disabled mail accounts",
                        description=(
                            f"You have {count} disabled mail account(s). "
                            "To re-enable: Open Mail > Preferences > Accounts, select each disabled account, "
                            "and check 'Enable this account'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pop_accounts":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="POP account(s) detected",
                        description=(
                            f"You have {count} POP account(s). POP is older and has synchronization limitations. "
                            "To switch to IMAP: Open Mail > Preferences > Accounts, select the account, "
                            "change Account Type to IMAP. Contact your email provider for IMAP settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "check_frequency":
                frequency = finding.data.get("frequency", "unknown")
                actions.append(
                    Action(
                        title="Mail check frequency",
                        description=(
                            f"Mail is checking for new messages {frequency}. "
                            "To adjust: Open Mail > Preferences > General > Check for new messages."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_mail_directory_size(self) -> int:
        """Get the size of ~/Library/Mail/ directory."""
        try:
            mail_path = Path.home() / "Library" / "Mail"
            if mail_path.exists() and mail_path.is_dir():
                return self._get_dir_size(mail_path)
        except Exception:
            pass

        return 0

    def _get_mail_accounts(self) -> tuple[int, int, int] | None:
        """Get mail account information: (total, pop_count, disabled_count)."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.mail", "MailAccounts"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None

            # Parse the defaults output to count accounts
            lines = result.stdout.splitlines()
            total_accounts = 0
            pop_accounts = 0
            disabled_accounts = 0

            # Count account entries (look for patterns in the plist output)
            # Each account has an AccountID entry
            for line in lines:
                if "AccountID" in line:
                    total_accounts += 1

            # Count POP accounts (look for authentication methods)
            for line in lines:
                if "POP" in line or "POPAuthentication" in line:
                    pop_accounts += 1

            # Count disabled accounts (look for Enabled = 0)
            for line in lines:
                if "Enabled" in line and "= 0" in line:
                    disabled_accounts += 1

            # If we found at least one account, return the counts
            if total_accounts > 0:
                return (total_accounts, pop_accounts, disabled_accounts)

            return None

        except (OSError, subprocess.SubprocessError):
            return None

    def _get_mail_check_frequency(self) -> str | None:
        """Get Mail check frequency setting."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.mail", "AutoFetchingEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                enabled = result.stdout.strip()
                if enabled == "1":
                    # Try to get the actual interval
                    try:
                        interval_result = subprocess.run(
                            ["defaults", "read", "com.apple.mail", "PollInterval"],
                            capture_output=True,
                            text=True,
                        )
                        if interval_result.returncode == 0:
                            interval = interval_result.stdout.strip()
                            if interval == "60":
                                return "every minute"
                            elif interval == "300":
                                return "every 5 minutes"
                            elif interval == "600":
                                return "every 10 minutes"
                            else:
                                return f"every {interval} seconds"
                    except Exception:
                        pass
                    return "automatically"
                else:
                    return "manually (push is disabled)"
            return None

        except (OSError, subprocess.SubprocessError):
            return None

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
