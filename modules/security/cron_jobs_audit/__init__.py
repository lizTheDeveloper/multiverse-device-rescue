import subprocess
import re
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
    name = "cron_jobs_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.cron_jobs_audit.cron_entries_found",
        "security.cron_jobs_audit.rce_in_cron",
        "security.cron_jobs_audit.suspicious_path",
        "security.cron_jobs_audit.every_minute",
        "security.cron_jobs_audit.obfuscated_command",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Collect all cron entries from various sources
        cron_entries = []

        # 1. User crontab
        user_crontab = self._get_user_crontab()
        if user_crontab:
            cron_entries.extend(user_crontab)

        # 2. System crontabs
        system_crontabs = self._get_system_crontabs()
        if system_crontabs:
            cron_entries.extend(system_crontabs)

        # 3. Periodic scripts
        periodic_scripts = self._get_periodic_scripts()
        if periodic_scripts:
            cron_entries.extend(periodic_scripts)

        # 4. At jobs
        at_jobs = self._get_at_jobs()
        if at_jobs:
            cron_entries.extend(at_jobs)

        # If we found any cron entries, log them as INFO
        if cron_entries:
            findings.append(
                Finding(
                    title=f"User and system cron jobs found: {len(cron_entries)} entries",
                    description=(
                        f"Found {len(cron_entries)} total cron job entries from user crontab, "
                        "system crontabs, periodic scripts, and at jobs. "
                        "Review these entries to ensure they are legitimate."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.cron_jobs_audit.cron_entries_found",
                    data={"check": "cron_entries_found", "count": len(cron_entries), "entries": cron_entries},
                )
            )

        # Analyze cron entries for suspicious patterns
        suspicious_findings = self._analyze_cron_entries(cron_entries)
        findings.extend(suspicious_findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "cron_entries_found":
                actions.append(
                    Action(
                        title="Review user and system cron jobs",
                        description=(
                            "Review all cron job entries found on the system. "
                            "To view and edit user crontab: crontab -e\n"
                            "To view system crontabs: cat /etc/crontab and ls /etc/cron.d/\n"
                            "Remove any cron jobs you don't recognize or trust."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "rce_in_cron":
                entries = finding.data.get("entries", [])
                entry_list = "\n".join(entries)
                actions.append(
                    Action(
                        title="Remove remote code execution patterns from cron jobs",
                        description=(
                            f"The following cron jobs have suspicious remote code execution patterns "
                            f"(curl/wget piped to sh/bash):\n{entry_list}\n\n"
                            "These should be immediately removed from your system as they indicate "
                            "an attacker is maintaining remote access to your machine. "
                            "Run 'crontab -e' to remove the entries."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "suspicious_path":
                entries = finding.data.get("entries", [])
                entry_list = "\n".join(entries)
                actions.append(
                    Action(
                        title="Remove cron jobs executing from suspicious paths",
                        description=(
                            f"The following cron jobs execute from temporary or suspicious paths:\n{entry_list}\n\n"
                            "These should be reviewed and likely removed. Run 'crontab -e' or edit "
                            "/etc/crontab and /etc/cron.d/* to remove them."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "every_minute":
                entries = finding.data.get("entries", [])
                entry_list = "\n".join(entries)
                actions.append(
                    Action(
                        title="Review cron jobs running every minute",
                        description=(
                            f"The following cron jobs run every minute (* * * * * pattern), which could indicate "
                            f"beaconing behavior:\n{entry_list}\n\n"
                            "Review these entries carefully. If they are not legitimate, remove them via "
                            "'crontab -e' or by editing /etc/crontab and /etc/cron.d/*."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "obfuscated_command":
                entries = finding.data.get("entries", [])
                entry_list = "\n".join(entries)
                actions.append(
                    Action(
                        title="Review cron jobs with obfuscated commands",
                        description=(
                            f"The following cron jobs use obfuscation techniques (base64, eval, etc.):\n{entry_list}\n\n"
                            "These should be reviewed carefully as they may hide malicious activity. "
                            "Remove any suspicious entries via 'crontab -e' or by editing "
                            "/etc/crontab and /etc/cron.d/*."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_crontab(self) -> list[str]:
        """Get user crontab entries."""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []

            entries = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
            return entries
        except OSError:
            return []
        except Exception:
            return []

    def _get_system_crontabs(self) -> list[str]:
        """Get system crontab entries from /etc/crontab and /etc/cron.d/."""
        entries = []

        # Check /etc/crontab
        try:
            result = subprocess.run(
                ["cat", "/etc/crontab"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(line)
        except OSError:
            pass
        except Exception:
            pass

        # Check /etc/cron.d/
        try:
            result = subprocess.run(
                ["ls", "-1", "/etc/cron.d/"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for filename in result.stdout.strip().split("\n"):
                    filename = filename.strip()
                    if filename:
                        try:
                            cat_result = subprocess.run(
                                ["cat", f"/etc/cron.d/{filename}"],
                                capture_output=True,
                                text=True,
                            )
                            if cat_result.returncode == 0:
                                for line in cat_result.stdout.strip().split("\n"):
                                    line = line.strip()
                                    if line and not line.startswith("#"):
                                        entries.append(line)
                        except OSError:
                            pass
                        except Exception:
                            pass
        except OSError:
            pass
        except Exception:
            pass

        return entries

    def _get_periodic_scripts(self) -> list[str]:
        """Get periodic scripts from /etc/periodic/daily/, weekly/, monthly/."""
        entries = []

        for period in ["daily", "weekly", "monthly"]:
            try:
                result = subprocess.run(
                    ["ls", "-1", f"/etc/periodic/{period}/"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    for script in result.stdout.strip().split("\n"):
                        script = script.strip()
                        if script:
                            entries.append(f"periodic/{period}: {script}")
            except OSError:
                pass
            except Exception:
                pass

        return entries

    def _get_at_jobs(self) -> list[str]:
        """Get at jobs via atq command."""
        try:
            result = subprocess.run(
                ["atq"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                entries = []
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line:
                        entries.append(f"at: {line}")
                return entries
            return []
        except OSError:
            return []
        except Exception:
            return []

    def _analyze_cron_entries(self, entries: list[str]) -> list[Finding]:
        """Analyze cron entries for suspicious patterns."""
        findings = []

        rce_entries = []
        suspicious_path_entries = []
        every_minute_entries = []
        obfuscated_entries = []

        for entry in entries:
            # Check for RCE patterns: curl/wget piped to sh/bash
            if self._has_rce_pattern(entry):
                rce_entries.append(entry)

            # Check for suspicious paths
            if self._has_suspicious_path(entry):
                suspicious_path_entries.append(entry)

            # Check for every minute pattern (* * * * *)
            if self._is_every_minute(entry):
                every_minute_entries.append(entry)

            # Check for obfuscation (base64, eval)
            if self._has_obfuscation(entry):
                obfuscated_entries.append(entry)

        # Create findings for suspicious patterns
        if rce_entries:
            findings.append(
                Finding(
                    title=f"Critical: Cron jobs with RCE patterns detected: {len(rce_entries)}",
                    description=(
                        f"Found {len(rce_entries)} cron job(s) with remote code execution patterns "
                        "(curl/wget piped to sh/bash). These are likely malicious and should be removed immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.cron_jobs_audit.rce_in_cron",
                    data={"check": "rce_in_cron", "count": len(rce_entries), "entries": rce_entries},
                )
            )

        if suspicious_path_entries:
            findings.append(
                Finding(
                    title=f"Critical: Cron jobs executing from suspicious paths: {len(suspicious_path_entries)}",
                    description=(
                        f"Found {len(suspicious_path_entries)} cron job(s) executing from /tmp, /var/tmp, "
                        "or other suspicious locations. These are likely malicious."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.cron_jobs_audit.suspicious_path",
                    data={"check": "suspicious_path", "count": len(suspicious_path_entries), "entries": suspicious_path_entries},
                )
            )

        if every_minute_entries:
            findings.append(
                Finding(
                    title=f"Warning: Cron jobs running every minute: {len(every_minute_entries)}",
                    description=(
                        f"Found {len(every_minute_entries)} cron job(s) with (* * * * *) schedule, "
                        "which could indicate beaconing behavior. Review these carefully."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.cron_jobs_audit.every_minute",
                    data={"check": "every_minute", "count": len(every_minute_entries), "entries": every_minute_entries},
                )
            )

        if obfuscated_entries:
            findings.append(
                Finding(
                    title=f"Warning: Cron jobs with obfuscated commands: {len(obfuscated_entries)}",
                    description=(
                        f"Found {len(obfuscated_entries)} cron job(s) using obfuscation techniques "
                        "(base64 encoding, eval statements, etc.). These should be reviewed carefully."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.cron_jobs_audit.obfuscated_command",
                    data={"check": "obfuscated_command", "count": len(obfuscated_entries), "entries": obfuscated_entries},
                )
            )

        return findings

    def _has_rce_pattern(self, entry: str) -> bool:
        """Check if entry has RCE pattern: curl/wget piped to sh/bash."""
        # Pattern: (curl|wget) ... | (sh|bash)
        rce_pattern = r'(curl|wget).*\|\s*(sh|bash|zsh)'
        return bool(re.search(rce_pattern, entry, re.IGNORECASE))

    def _has_suspicious_path(self, entry: str) -> bool:
        """Check if entry executes from /tmp, /var/tmp, or starts with a dot."""
        # Check for /tmp or /var/tmp in the command
        if "/tmp/" in entry or "/var/tmp/" in entry:
            return True

        # Check for hidden directories (paths starting with .)
        if re.search(r'\s+/\.\w+', entry):
            return True

        return False

    def _is_every_minute(self, entry: str) -> bool:
        """Check if cron entry runs every minute (* * * * *)."""
        # Look for the cron schedule at the beginning of the entry
        # Format: min hour day month dow command
        # Every minute: * * * * *
        if re.search(r'^\*\s+\*\s+\*\s+\*\s+\*', entry):
            return True

        return False

    def _has_obfuscation(self, entry: str) -> bool:
        """Check if entry has obfuscation: base64, eval, etc."""
        obfuscation_patterns = [
            r'\bbase64\b',
            r'\beval\b',
            r'\bdecode\b',
            r'\buuencode\b',
        ]

        for pattern in obfuscation_patterns:
            if re.search(pattern, entry, re.IGNORECASE):
                return True

        return False
