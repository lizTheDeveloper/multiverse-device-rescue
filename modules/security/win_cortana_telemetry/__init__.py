import subprocess

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
    name = "win_cortana_telemetry"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check telemetry level
        telemetry_level = self._query_reg_value(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
        )

        # Check if Cortana is enabled
        cortana_enabled = self._query_reg_value(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
            "AllowCortana",
        )

        # Check advertising ID
        advertising_id = self._query_reg_value(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
        )

        # Check activity history
        activity_feed = self._query_reg_value(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
            "EnableActivityFeed",
        )

        # Check location services
        location_services = self._query_reg_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            "Value",
        )

        # Telemetry level check: 3 (Full) and 2 (Enhanced) send detailed usage data
        if telemetry_level in ("2", "3"):
            level_name = "Enhanced" if telemetry_level == "2" else "Full"
            findings.append(
                Finding(
                    title=f"Telemetry level set to {level_name}",
                    description=(
                        f"Windows telemetry is set to {level_name} level, "
                        "which sends detailed usage data to Microsoft. This may impact "
                        "privacy and consume system resources. Consider reducing to Basic "
                        "or Minimal level for privacy-conscious systems."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "telemetry_level", "value": telemetry_level},
                )
            )

        # Cortana enabled check (value 1 = enabled, 0 = disabled)
        if cortana_enabled == "1":
            findings.append(
                Finding(
                    title="Cortana is enabled",
                    description=(
                        "Cortana is enabled and may collect voice, search, and activity "
                        "data. Disable it in Settings > Privacy & Security > Voice "
                        "activation if privacy is a concern."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "cortana_enabled", "value": cortana_enabled},
                )
            )

        # Advertising ID check (value 1 = enabled, 0 = disabled)
        if advertising_id == "1":
            findings.append(
                Finding(
                    title="Advertising ID is enabled",
                    description=(
                        "Windows Advertising ID is enabled, allowing apps to track "
                        "advertising preferences and behavior. Disable it in Settings > "
                        "Privacy & Security > General > Advertising ID for better privacy."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "advertising_id", "value": advertising_id},
                )
            )

        # Activity history check (value 1 = enabled, 0 = disabled)
        if activity_feed == "1":
            findings.append(
                Finding(
                    title="Activity History is enabled",
                    description=(
                        "Windows Activity History is enabled, tracking your recent "
                        "activities. Disable it in Settings > Privacy & Security > "
                        "Activity History to reduce tracking."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "activity_feed", "value": activity_feed},
                )
            )

        # Location services check (value 'Allow' = enabled)
        if location_services and location_services.lower() == "allow":
            findings.append(
                Finding(
                    title="Location services are enabled",
                    description=(
                        "Windows Location services are enabled. Review which apps have "
                        "access to your location in Settings > Privacy & Security > "
                        "Location to control tracking."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "location_services", "value": location_services},
                )
            )

        # If no privacy concerns, add summary INFO
        if not findings:
            findings.append(
                Finding(
                    title="Windows privacy and telemetry settings are optimized",
                    description=(
                        "Telemetry is at Basic/Minimal level, Cortana is disabled, "
                        "Advertising ID is disabled, Activity History is disabled, and "
                        "Location services are disabled. Privacy configuration is good."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"privacy_status": "optimized"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "telemetry_level":
                actions.append(
                    Action(
                        title="Reduce telemetry level to Basic or Minimal",
                        description=(
                            "To reduce telemetry: Open Settings > Privacy & Security > "
                            "Diagnostics & device options > Change diagnostic data > "
                            "Select 'Required diagnostic data (minimal)' or 'Optional "
                            "diagnostic data (basic)'. Minimal is recommended for "
                            "privacy-conscious users."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "cortana_enabled":
                actions.append(
                    Action(
                        title="Disable Cortana",
                        description=(
                            "To disable Cortana: Open Settings > Privacy & Security > "
                            "Voice activation > Toggle off 'Voice activation' and "
                            "'Wake word activation' if desired."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "advertising_id":
                actions.append(
                    Action(
                        title="Disable Advertising ID",
                        description=(
                            "To disable Advertising ID: Open Settings > Privacy & "
                            "Security > General > Toggle off 'Advertising ID' "
                            "(Show me personalized ads)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "activity_feed":
                actions.append(
                    Action(
                        title="Disable Activity History",
                        description=(
                            "To disable Activity History: Open Settings > Privacy & "
                            "Security > Activity History > Uncheck "
                            "'Store my activity history on this device'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "location_services":
                actions.append(
                    Action(
                        title="Disable or limit Location services",
                        description=(
                            "To disable Location services: Open Settings > Privacy & "
                            "Security > Location > Toggle off 'Location'. Alternatively, "
                            "keep it enabled but disable it per-app for apps that don't "
                            "need location access."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _query_reg_value(self, reg_path: str, value_name: str) -> str | None:
        """Query a registry value and return its data, or None if not found."""
        try:
            result = subprocess.run(
                ["reg", "query", reg_path, "/v", value_name],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Parse output like:
            # HKEY_LOCAL_MACHINE\SOFTWARE\...
            #     ValueName    REG_DWORD    0x1
            return _parse_reg_value(result.stdout, value_name)
        except (OSError, subprocess.SubprocessError):
            return None


def _parse_reg_value(output: str, value_name: str) -> str | None:
    """Parse reg query output to extract the value.

    Example output:
        HKEY_LOCAL_MACHINE\SOFTWARE\...
            ValueName    REG_DWORD    0x1

    Returns the last whitespace-separated token on the line containing value_name,
    or for REG_SZ values, the string value.
    """
    for line in output.splitlines():
        if value_name in line:
            parts = line.split()
            if len(parts) >= 3:
                # The value is the last part
                value_str = parts[-1]
                # Try to convert hex to decimal for REG_DWORD values
                if value_str.startswith("0x"):
                    try:
                        return str(int(value_str, 16))
                    except ValueError:
                        return None
                # For REG_SZ values, return as-is
                return value_str
    return None
