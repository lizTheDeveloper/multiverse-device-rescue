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
MAIL_DATA_WARNING = 10 * 1024 * 1024 * 1024  # 10 GB
MAIL_ATTACHMENTS_WARNING = 2 * 1024 * 1024 * 1024  # 2 GB


class Module(ModuleBase):
    name = "mail_attachment_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Check Mail data size
        mail_data_dir = home / "Library/Mail"
        mail_data_size = self._get_directory_size(mail_data_dir)

        # Check Mail attachment downloads
        mail_downloads_dir = (
            home / "Library/Containers/com.apple.mail/Data/Library/Mail Downloads"
        )
        mail_downloads_size = self._get_directory_size(mail_downloads_dir)

        # Add info finding for Mail data size
        if mail_data_size > 0:
            findings.append(
                Finding(
                    title=f"Mail data: {_fmt_bytes(mail_data_size)}",
                    description=(
                        f"~/Library/Mail contains {_fmt_bytes(mail_data_size)} of email data. "
                        f"Mail downloads and caches every attachment which can grow significantly "
                        f"on older Macs with many archived emails."
                    ),
                    severity=(
                        Severity.WARNING
                        if mail_data_size >= MAIL_DATA_WARNING
                        else Severity.INFO
                    ),
                    category=self.category,
                    data={
                        "type": "mail_data",
                        "size_bytes": mail_data_size,
                        "size_formatted": _fmt_bytes(mail_data_size),
                    },
                )
            )

        # Add finding for Mail attachment downloads
        if mail_downloads_size > 0:
            findings.append(
                Finding(
                    title=f"Mail attachment cache: {_fmt_bytes(mail_downloads_size)}",
                    description=(
                        f"~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads "
                        f"contains {_fmt_bytes(mail_downloads_size)} of cached attachments. "
                        f"Mail re-downloads attachments as needed, so this cache can be safely managed."
                    ),
                    severity=(
                        Severity.WARNING
                        if mail_downloads_size >= MAIL_ATTACHMENTS_WARNING
                        else Severity.INFO
                    ),
                    category=self.category,
                    data={
                        "type": "mail_attachments",
                        "size_bytes": mail_downloads_size,
                        "size_formatted": _fmt_bytes(mail_downloads_size),
                    },
                )
            )

        # If both are zero, report that Mail data is not significant
        if mail_data_size == 0 and mail_downloads_size == 0:
            findings.append(
                Finding(
                    title="Mail storage minimal",
                    description="Mail data and attachment cache are not taking up significant space.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"type": "mail_minimal", "size_bytes": 0},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")

            if finding_type == "mail_data":
                actions.append(
                    Action(
                        title=f"Mail data: {size_str}",
                        description=(
                            f"Mail data at ~/Library/Mail is using {size_str}. "
                            f"To manage this storage:\n"
                            f"1. Archive old emails in Mail to a separate folder\n"
                            f"2. Delete emails with large attachments\n"
                            f"3. In Mail, go to Mailbox > Delete Deleted Items to permanently delete\n"
                            f"4. Consider reducing email retention or moving archives to external storage"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "mail_attachments":
                actions.append(
                    Action(
                        title=f"Mail attachment cache: {size_str}",
                        description=(
                            f"Mail attachment cache at ~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads "
                            f"is using {size_str}. This cache is safe to manage:\n"
                            f"1. Close Mail before cleaning\n"
                            f"2. To remove the cache: rm -rf ~/Library/Containers/com.apple.mail/Data/Library/Mail\\ Downloads/*\n"
                            f"3. Restart Mail - it will re-cache attachments as needed\n"
                            f"Note: Only remove this cache, not the parent directories"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "mail_minimal":
                actions.append(
                    Action(
                        title="Mail storage is minimal",
                        description=(
                            "Mail storage is not taking up significant disk space. "
                            "No action needed at this time."
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
