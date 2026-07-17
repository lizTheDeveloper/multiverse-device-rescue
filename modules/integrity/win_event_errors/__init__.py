import subprocess
from collections import defaultdict
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
ERROR_COUNT_THRESHOLD = 20  # Flag WARNING if >20 errors in System log
KNOWN_BAD_SOURCES = [
    r"Disk",
    r"WHEA",
    r"BugCheck",
]


class Module(ModuleBase):
    name = "win_event_errors"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            # Get recent errors from System log
            system_errors = self._get_system_log_errors()
            system_error_lines = [
                line.strip() for line in system_errors.strip().split("\n") if line.strip()
            ]
        except Exception:
            system_error_lines = []

        try:
            # Get recent errors from Application log
            app_errors = self._get_application_log_errors()
            app_error_lines = [
                line.strip() for line in app_errors.strip().split("\n") if line.strip()
            ]
        except Exception:
            app_error_lines = []

        system_error_count = len(system_error_lines)
        app_error_count = len(app_error_lines)
        total_errors = system_error_count + app_error_count

        # If no errors found in either log
        if not system_error_lines and not app_error_lines:
            findings.append(
                Finding(
                    title="No recent errors in Event Logs",
                    description=(
                        "The Windows Event Logs (System and Application) show no recent errors. "
                        "The system appears to be healthy."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"system_error_count": 0, "app_error_count": 0},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Extract error sources from both logs
        error_sources = defaultdict(int)
        known_bad_errors = []

        for error_line in system_error_lines + app_error_lines:
            # Extract the source/provider (typically first field in Event Log output)
            # Format from PowerShell is usually: Provider | TimeCreated | Level | Message
            # We extract the provider name
            parts = error_line.split("|")
            if parts:
                source = parts[0].strip()
                if source:
                    error_sources[source] += 1

            # Check for known-bad patterns
            for pattern in KNOWN_BAD_SOURCES:
                if re.search(pattern, error_line, re.IGNORECASE):
                    known_bad_errors.append(error_line[:100])  # Truncate long lines

        # Count unique error sources
        unique_sources = len(error_sources)
        top_sources = dict(
            sorted(error_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        )

        # Flag WARNING if >20 errors in System log
        if system_error_count > ERROR_COUNT_THRESHOLD:
            findings.append(
                Finding(
                    title=f"High error volume in System log: {system_error_count} errors",
                    description=(
                        f"The System Event Log contains {system_error_count} recent errors. "
                        f"This suggests something is spamming errors and may indicate "
                        f"system instability or a malfunctioning service. "
                        f"Top error sources: {', '.join(top_sources.keys())}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "system_error_count": system_error_count,
                        "app_error_count": app_error_count,
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
                        f"Detected {len(known_bad_errors)} error(s) from known-problematic sources "
                        f"(Disk, WHEA, BugCheck). This may indicate hardware issues, driver problems, "
                        f"or system crashes. Sample error: {known_bad_errors[0] if known_bad_errors else 'None'}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "known_bad_count": len(known_bad_errors),
                        "sample_errors": known_bad_errors[:3],
                    },
                )
            )

        # Flag INFO with summary if no warnings yet
        if not findings:
            findings.append(
                Finding(
                    title=f"Event Log summary: {total_errors} recent errors",
                    description=(
                        f"The Windows Event Logs contain {system_error_count} System errors "
                        f"and {app_error_count} Application errors across {unique_sources} different sources. "
                        f"Top sources: {', '.join(top_sources.keys()) if top_sources else 'None'}. "
                        f"Error frequency appears normal."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "system_error_count": system_error_count,
                        "app_error_count": app_error_count,
                        "unique_sources": unique_sources,
                        "top_sources": top_sources,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("system_error_count", 0) > ERROR_COUNT_THRESHOLD:
                # High error volume action
                actions.append(
                    Action(
                        title="Investigate high error volume in System Event Log",
                        description=(
                            f"The System Event Log shows {finding.data['system_error_count']} recent errors "
                            f"from {finding.data['unique_sources']} unique sources. "
                            f"Review the error sources and consider: "
                            f"(1) identifying which driver or service is generating errors, "
                            f"(2) checking if recently installed software is causing issues, "
                            f"(3) verifying Windows and driver updates are current, "
                            f"(4) running Windows built-in hardware diagnostics, or "
                            f"(5) reviewing the full Event Log with Event Viewer (eventvwr.msc)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("known_bad_count", 0) > 0:
                # Known-bad error action
                actions.append(
                    Action(
                        title="Address known-issue errors from hardware/system sources",
                        description=(
                            f"Detected {finding.data['known_bad_count']} error(s) "
                            f"from known-problematic sources (Disk, WHEA, BugCheck). "
                            f"Consider: (1) running Check Disk utility (chkdsk), "
                            f"(2) updating storage drivers, "
                            f"(3) checking Windows Event Viewer for detailed error context, "
                            f"(4) running Windows hardware diagnostics, or "
                            f"(5) investigating if recent hardware changes were made."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                # Normal errors - informational action
                total_errors = (
                    finding.data.get("system_error_count", 0) +
                    finding.data.get("app_error_count", 0)
                )
                actions.append(
                    Action(
                        title="Monitor Event Logs",
                        description=(
                            f"The Windows Event Logs show {total_errors} recent error(s) in normal ranges. "
                            f"Continue monitoring system performance and note any recurring issues. "
                            f"If you observe specific problems (crashes, slowdowns, freezes), "
                            f"check Event Viewer (eventvwr.msc) for more context."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_system_log_errors(self) -> str:
        """Fetch recent error messages from System Event Log.

        Uses PowerShell Get-WinEvent to retrieve errors from the last 50 entries.
        Can be mocked in tests.
        """
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 50 | ForEach-Object { $_.ProviderName + ' | ' + $_.TimeCreated + ' | ' + $_.Message }",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return ""
            return result.stdout
        except Exception:
            return ""

    def _get_application_log_errors(self) -> str:
        """Fetch recent error messages from Application Event Log.

        Uses PowerShell Get-WinEvent to retrieve errors from the last 50 entries.
        Can be mocked in tests.
        """
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 50 | ForEach-Object { $_.ProviderName + ' | ' + $_.TimeCreated + ' | ' + $_.Message }",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return ""
            return result.stdout
        except Exception:
            return ""
