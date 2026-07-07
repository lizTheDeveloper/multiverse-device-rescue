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
    name = "scheduled_tasks_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check current user's crontab
        user_crontab = self._get_user_crontab()
        if user_crontab:
            findings.extend(self._check_crontab(user_crontab, "current user"))
        else:
            findings.append(
                Finding(
                    title="No user crontab found",
                    description="The current user does not have a crontab configured.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_crontab"},
                )
            )

        # Check at jobs
        at_jobs = self._get_at_jobs()
        if at_jobs:
            findings.extend(self._check_at_jobs(at_jobs))
        else:
            findings.append(
                Finding(
                    title="No at jobs found",
                    description="No at jobs are currently scheduled.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_at_jobs"},
                )
            )

        # Try to scan /var/at/tabs/ for other user crontabs
        var_at_tabs_findings = self._scan_var_at_tabs()
        findings.extend(var_at_tabs_findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "remote_content_in_crontab":
                crontab_line = finding.data.get("line", "")
                user_context = finding.data.get("user", "current user")
                actions.append(
                    Action(
                        title=f"Review suspicious crontab entry ({user_context})",
                        description=(
                            f"The following crontab entry downloads or executes remote content:\n"
                            f"  {crontab_line}\n\n"
                            "This can be used for malware persistence. To review and remove:\n"
                            "1. Run: crontab -e\n"
                            "2. Review the entry and remove if suspicious\n"
                            "3. Save and exit"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "root_crontab_entry":
                crontab_line = finding.data.get("line", "")
                actions.append(
                    Action(
                        title="Review root crontab entry",
                        description=(
                            f"A scheduled task runs with root privileges:\n"
                            f"  {crontab_line}\n\n"
                            "Root crontabs are high-value targets for malware. To review:\n"
                            "1. Run: sudo crontab -l\n"
                            "2. Verify each entry is legitimate\n"
                            "3. Remove suspicious entries with: sudo crontab -e"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "crontab_info":
                crontab_line = finding.data.get("line", "")
                actions.append(
                    Action(
                        title="Legitimate crontab entry found",
                        description=(
                            f"Scheduled task found:\n"
                            f"  {crontab_line}\n\n"
                            "Verify this task is expected and legitimate."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "at_job_info":
                at_job = finding.data.get("job", "")
                actions.append(
                    Action(
                        title="At job found",
                        description=(
                            f"Scheduled at job found:\n"
                            f"  {at_job}\n\n"
                            "Verify this job is expected. To view details:\n"
                            "  at -c <job_id>"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check in ["no_crontab", "no_at_jobs"]:
                # These are clean findings, just informational
                actions.append(
                    Action(
                        title=finding.title,
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_crontab(self) -> list[str]:
        """Get the current user's crontab entries."""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Filter out comments and empty lines
                lines = [
                    line.strip()
                    for line in result.stdout.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
                return lines
            return []
        except Exception:
            return []

    def _get_at_jobs(self) -> list[str]:
        """Get list of at jobs."""
        try:
            result = subprocess.run(
                ["atq"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Filter out empty lines
                lines = [
                    line.strip()
                    for line in result.stdout.split("\n")
                    if line.strip()
                ]
                return lines
            return []
        except Exception:
            return []

    def _check_crontab(
        self, crontab_lines: list[str], user_context: str
    ) -> list[Finding]:
        """Check crontab entries for suspicious patterns."""
        findings = []

        for line in crontab_lines:
            # Check for remote content download/execution
            if any(
                cmd in line for cmd in ["curl", "wget"]
            ) and any(
                pattern in line
                for pattern in ["|", "$(", "`", "&&", ";"]
            ):
                findings.append(
                    Finding(
                        title=f"Crontab downloads/executes remote content ({user_context})",
                        description=(
                            f"Found crontab entry that downloads or executes remote content:\n"
                            f"  {line}\n\n"
                            "This is a common malware persistence mechanism and should be reviewed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "remote_content_in_crontab",
                            "line": line,
                            "user": user_context,
                        },
                    )
                )
            else:
                # Log all crontab entries as INFO
                findings.append(
                    Finding(
                        title=f"Crontab entry found ({user_context})",
                        description=f"Scheduled task: {line}",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "crontab_info",
                            "line": line,
                            "user": user_context,
                        },
                    )
                )

        return findings

    def _check_at_jobs(self, at_job_lines: list[str]) -> list[Finding]:
        """Check at jobs for suspicious patterns."""
        findings = []

        for line in at_job_lines:
            # at jobs are less commonly malicious, but log them
            findings.append(
                Finding(
                    title="At job found",
                    description=f"Scheduled at job: {line}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "at_job_info",
                        "job": line,
                    },
                )
            )

        return findings

    def _scan_var_at_tabs(self) -> list[Finding]:
        """Scan /var/at/tabs/ for other user crontabs (if accessible)."""
        findings = []
        var_at_path = Path("/var/at/tabs")

        if not var_at_path.exists():
            return findings

        try:
            # Try to list the directory
            entries = list(var_at_path.iterdir())
            for entry in entries:
                if entry.is_file():
                    username = entry.name
                    # Try to read the crontab file
                    try:
                        with open(entry, "r") as f:
                            content = f.read()
                            # Extract non-comment lines
                            lines = [
                                line.strip()
                                for line in content.split("\n")
                                if line.strip()
                                and not line.strip().startswith("#")
                            ]
                            findings.extend(
                                self._check_crontab(lines, f"user '{username}'")
                            )
                    except PermissionError:
                        # Skip if we don't have permission
                        pass
        except Exception:
            pass

        return findings
