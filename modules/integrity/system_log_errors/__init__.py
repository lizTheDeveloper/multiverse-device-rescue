import subprocess
from collections import defaultdict, Counter
import re

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
ERROR_COUNT_THRESHOLD = 50  # Flag if >50 errors in 1 hour
KNOWN_BAD_PATTERNS = [
    r"kernel",
    r"com\.apple\.xpc.*connection",
    r"crashd",
]


class Module(ModuleBase):
    name = "system_log_errors"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            # Get recent errors from system log
            log_output = self._get_recent_errors()
        except Exception as e:
            # If we can't get logs, just return no findings
            return CheckResult(module_name=self.name, findings=findings)

        if not log_output.strip():
            # No errors found - healthy system
            findings.append(
                Finding(
                    title="No recent errors in system log",
                    description=(
                        "The system log shows no errors in the last hour. "
                        "The system appears to be healthy."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"error_count": 0},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Parse error lines
        error_lines = [line.strip() for line in log_output.strip().split("\n") if line.strip()]
        error_count = len(error_lines)

        # Extract error sources/subsystems
        error_sources = defaultdict(int)
        known_bad_errors = []

        for line in error_lines:
            # Extract the process/subsystem name (first token typically)
            # Format is typically: ProcessName[PID]: ERROR: message
            # Extract just the process name part
            parts = line.split()
            if parts:
                source_raw = parts[0]
                # Remove the PID and colon if present: "Chrome[100]:" -> "Chrome"
                source = re.sub(r'\[\d+\]:?', '', source_raw)
                if source:
                    error_sources[source] += 1

            # Check for known-bad patterns
            for pattern in KNOWN_BAD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    known_bad_errors.append(line[:100])  # Truncate long lines

        # Count unique error sources
        unique_sources = len(error_sources)
        top_sources = dict(
            sorted(error_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        )

        # Flag WARNING if >50 errors
        if error_count > ERROR_COUNT_THRESHOLD:
            findings.append(
                Finding(
                    title=f"High error volume: {error_count} errors in 1 hour",
                    description=(
                        f"The system log contains {error_count} errors in the last hour. "
                        f"This suggests something is spamming errors and may indicate "
                        f"system instability or a malfunctioning service. "
                        f"Top error sources: {', '.join(top_sources.keys())}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "error_count": error_count,
                        "unique_sources": unique_sources,
                        "top_sources": top_sources,
                    },
                )
            )

        # Flag WARNING for known-bad errors
        if known_bad_errors:
            findings.append(
                Finding(
                    title=f"Known-issue errors detected: {len(known_bad_errors)} occurrence(s)",
                    description=(
                        f"Detected {len(known_bad_errors)} error(s) from known-problematic systems. "
                        f"This may indicate kernel issues, XPC communication failures, or crashes. "
                        f"Sample errors: {known_bad_errors[0] if known_bad_errors else 'None'}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "known_bad_count": len(known_bad_errors),
                        "sample_errors": known_bad_errors[:3],
                    },
                )
            )

        # Flag INFO with summary
        if not findings:  # Only add summary if no warnings yet
            findings.append(
                Finding(
                    title=f"System log summary: {error_count} errors in 1 hour",
                    description=(
                        f"The system log contains {error_count} error(s) across "
                        f"{unique_sources} different source(s) in the last hour. "
                        f"Top sources: {', '.join(top_sources.keys()) if top_sources else 'None'}. "
                        f"Error frequency appears normal."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "error_count": error_count,
                        "unique_sources": unique_sources,
                        "top_sources": top_sources,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("error_count", 0) > ERROR_COUNT_THRESHOLD:
                # High error volume action
                actions.append(
                    Action(
                        title="Investigate high error volume in system log",
                        description=(
                            f"The system log shows {finding.data['error_count']} errors "
                            f"from {finding.data['unique_sources']} unique sources. "
                            f"Review the error sources and consider: "
                            f"(1) identifying which service/process is generating errors, "
                            f"(2) checking if recently installed software is causing issues, "
                            f"(3) verifying macOS and application updates are current, "
                            f"(4) running Disk Utility First Aid, or "
                            f"(5) reviewing the full log with: log show --last 1h"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("known_bad_count", 0) > 0:
                # Known-bad error action
                actions.append(
                    Action(
                        title="Address known-issue errors",
                        description=(
                            f"Detected {finding.data['known_bad_count']} error(s) "
                            f"from known-problematic systems (kernel, XPC, crashes). "
                            f"Consider: (1) checking Apple Support for system issues, "
                            f"(2) reviewing syslog for context, "
                            f"(3) restarting the system, "
                            f"(4) checking for kernel extensions issues, or "
                            f"(5) verifying hardware with Apple Diagnostics."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                # Healthy system or normal errors
                error_count = finding.data.get("error_count", 0)
                actions.append(
                    Action(
                        title="Monitor system logs",
                        description=(
                            f"The system log shows {error_count} error(s) in the last hour. "
                            f"This is within normal range. Continue monitoring system performance "
                            f"and note any recurring issues. If you observe specific problems "
                            f"(freezes, crashes, slow performance), check the logs again "
                            f"with: log show --last 1h --predicate 'messageType == error'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_recent_errors(self) -> str:
        """Fetch recent error messages from system log.

        Uses 'log show' command to get errors from the last hour.
        Can be mocked in tests.
        """
        cmd = [
            "log",
            "show",
            "--last",
            "1h",
            "--predicate",
            "messageType == error",
            "--style",
            "compact",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            # If command fails, return empty string
            return ""
        return result.stdout
