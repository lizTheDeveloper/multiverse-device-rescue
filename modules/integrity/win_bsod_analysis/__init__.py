import subprocess
from datetime import datetime, timedelta, timezone
from typing import Optional

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
    name = "win_bsod_analysis"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    # Common Windows stop codes and their meanings
    STOP_CODES = {
        "0x0000007E": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "0x0000007F": "UNEXPECTED_KERNEL_MODE_TRAP",
        "0x0000008E": "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        "0x0000009F": "DRIVER_POWER_STATE_FAILURE",
        "0x000000A": "IRQL_NOT_LESS_OR_EQUAL",
        "0x00000024": "NTFS_FILE_SYSTEM",
        "0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA",
        "0x0000007C": "BUGCODE_USB_DRIVER",
        "0x00000D1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "0x00000109": "CRITICAL_STRUCTURE_CORRUPTION",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get BSOD events from System log
        bsod_events = self._get_bsod_events()

        if not bsod_events:
            findings.append(
                Finding(
                    title="No BSOD events detected",
                    description=(
                        "No recent Blue Screen of Death events were found in the System event log. "
                        "Your system appears to be stable."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_bsod_events"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        event_count = len(bsod_events)
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Filter events by time
        recent_24h = [e for e in bsod_events if e["timestamp"] >= last_24h]
        recent_7d = [e for e in bsod_events if e["timestamp"] >= last_7d]

        # Extract stop codes and build event summary
        stop_codes = {}
        event_summary = []
        for event in bsod_events:
            code = event.get("stop_code", "UNKNOWN")
            if code not in stop_codes:
                stop_codes[code] = 0
            stop_codes[code] += 1
            event_summary.append(
                f"{event['timestamp'].strftime('%Y-%m-%d %H:%M')}: {code} - {self.STOP_CODES.get(code, 'Unknown error')}"
            )

        # Check for minidump files
        minidump_exists = self._check_minidump_files()

        # CRITICAL: BSOD in last 24 hours
        if recent_24h:
            findings.append(
                Finding(
                    title=f"BSOD occurred in last 24 hours",
                    description=(
                        f"Found {len(recent_24h)} crash event(s) in the last 24 hours. "
                        f"Stop code: {recent_24h[0].get('stop_code', 'UNKNOWN')}. "
                        "Your system is currently unstable. Immediate action is recommended."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "recent_bsod_24h",
                        "event_count": len(recent_24h),
                        "stop_code": recent_24h[0].get("stop_code", "UNKNOWN"),
                        "timestamp": recent_24h[0]["timestamp"].isoformat(),
                    },
                )
            )

        # WARNING: Multiple BSODs in last 7 days
        elif recent_7d and len(recent_7d) > 1:
            findings.append(
                Finding(
                    title=f"Multiple BSODs detected in last 7 days",
                    description=(
                        f"Found {len(recent_7d)} crash event(s) in the last 7 days. "
                        "This indicates a recurring issue that requires investigation. "
                        f"Stop codes involved: {', '.join(set(e.get('stop_code', 'UNKNOWN') for e in recent_7d))}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "recurring_bsod_7d",
                        "event_count": len(recent_7d),
                        "stop_codes": list(set(e.get("stop_code") for e in recent_7d)),
                    },
                )
            )

        # INFO: BSOD history with details
        findings.append(
            Finding(
                title=f"BSOD history ({event_count} events)",
                description=(
                    f"Found {event_count} Blue Screen of Death event(s) in event log. "
                    f"Stop codes: {', '.join(f'{code} ({self.STOP_CODES.get(code, 'Unknown')})' for code in stop_codes.keys())}. "
                    f"Minidump files: {'present' if minidump_exists else 'not found'}. "
                    "Review the event log for patterns and driver/hardware issues."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "bsod_history",
                    "total_events": event_count,
                    "stop_codes": stop_codes,
                    "minidump_exists": minidump_exists,
                    "events": event_summary[:5],  # Include first 5 events in summary
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "recent_bsod_24h":
                stop_code = finding.data.get("stop_code", "UNKNOWN")
                description = self.STOP_CODES.get(stop_code, "An unidentified system error")
                actions.append(
                    Action(
                        title=f"BSOD in last 24 hours: {stop_code}",
                        description=(
                            f"Stop code {stop_code} ({description}) indicates a critical system error. "
                            "Recommendations: "
                            "(1) Update all device drivers, especially chipset, GPU, and storage drivers. "
                            "(2) Check Windows Update for system patches. "
                            "(3) Run System File Checker: sfc /scannow (in Command Prompt as Admin). "
                            "(4) If the issue persists, restore from a known good backup or perform a clean Windows installation. "
                            "(5) Consider hardware diagnostics if errors continue after driver/OS updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "recurring_bsod_7d":
                stop_codes = finding.data.get("stop_codes", [])
                code_str = ", ".join(str(c) for c in stop_codes)
                descriptions = [
                    self.STOP_CODES.get(c, "Unknown error") for c in stop_codes
                ]
                actions.append(
                    Action(
                        title=f"Recurring BSODs detected: {code_str}",
                        description=(
                            f"Multiple crash events ({code_str}) in last 7 days indicate a systemic problem. "
                            "These errors likely relate to: "
                            "- Faulty or incompatible drivers (GPU, chipset, storage, network). "
                            "- Hardware issues (RAM, hard drive, SSD, power supply). "
                            "- Corrupted system files or recent updates. "
                            "Recommendations: "
                            "(1) Update or rollback recently installed drivers. "
                            "(2) Run Windows Memory Diagnostics (mdsched.exe) to test RAM. "
                            "(3) Run chkdsk C: /F (reboot required) to check disk integrity. "
                            "(4) Check Device Manager for unknown or warning devices. "
                            "(5) Consider testing with hardware diagnostics from your system manufacturer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bsod_history":
                stop_codes = finding.data.get("stop_codes", {})
                minidump_exists = finding.data.get("minidump_exists", False)
                actions.append(
                    Action(
                        title=f"BSOD history recorded",
                        description=(
                            "Your system has experienced Blue Screen of Death events. "
                            "Minidump files are "
                            f"{'available' if minidump_exists else 'not available'} for detailed analysis. "
                            "Next steps: "
                            "(1) Check Event Viewer (eventvwr.msc) under Windows Logs > System "
                            "to examine individual BugCheck events (ID 1001). "
                            "(2) Look for patterns in when crashes occur (specific time, after updates, during activities). "
                            "(3) Review driver update history and system changes before first crash. "
                            "(4) For detailed analysis, use Windows Debugger or contact Microsoft Support with minidump files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_bsod_events":
                actions.append(
                    Action(
                        title="System stable - no BSOD events",
                        description=(
                            "No Blue Screen of Death events detected. "
                            "Your system is running stably. "
                            "Continue regular maintenance: keep drivers updated, monitor system health, "
                            "and maintain regular backups."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_bsod_events(self) -> Optional[list]:
        """Get BSOD events from Windows System event log."""
        events = []

        try:
            # Query for BugCheck events (ID 1001) which contain BSOD information
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; ID=1001} "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, @{Name='StopCode'; Expression={$_.Message | Select-String -Pattern '0x[0-9A-F]{8}' | "
                "ForEach-Object {$_.Matches.Value}}} | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                events = _parse_bsod_events(result.stdout)

            # Fallback: check WER (Windows Error Reporting) events
            if not events:
                ps_cmd_wer = (
                    "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} "
                    "-MaxEvents 10 -ErrorAction SilentlyContinue | "
                    "Select-Object TimeCreated, @{Name='StopCode'; Expression={$_.Message | Select-String -Pattern '0x[0-9A-F]{8}' | "
                    "ForEach-Object {$_.Matches.Value}}} | ConvertTo-Json"
                )
                result_wer = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd_wer],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result_wer.returncode == 0 and result_wer.stdout.strip():
                    events = _parse_bsod_events(result_wer.stdout)

        except (OSError, subprocess.SubprocessError, TimeoutError):
            pass

        return events if events else None

    def _check_minidump_files(self) -> bool:
        """Check if minidump files exist in the Windows minidump directory."""
        try:
            ps_cmd = "Test-Path 'C:\\Windows\\Minidump\\*.dmp'"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and "True" in result.stdout
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False


def _parse_bsod_events(json_output: str) -> list:
    """Parse PowerShell JSON output from Get-WinEvent for BSOD events."""
    import json

    events = []
    if not json_output.strip():
        return events

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for item in data:
            if item is None or not isinstance(item, dict):
                continue

            time_created = item.get("TimeCreated")
            stop_code = item.get("StopCode")

            if time_created and stop_code:
                try:
                    # Parse ISO format timestamp
                    timestamp = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
                    events.append(
                        {
                            "timestamp": timestamp,
                            "stop_code": stop_code if isinstance(stop_code, str) else str(
                                stop_code[0]
                            ) if isinstance(stop_code, list) else "UNKNOWN",
                        }
                    )
                except (ValueError, IndexError, AttributeError):
                    continue

    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        pass

    # Sort by timestamp, most recent first
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    return events
