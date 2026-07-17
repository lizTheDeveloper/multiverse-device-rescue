import json
import subprocess
from datetime import datetime

from rescue.models import (
    Action,
    ActionKind,
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
    name = "win_antivirus_status"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Query antivirus products from Security Center 2
        av_products = self._get_antivirus_products()
        defender_status = self._get_defender_status()

        # Check if any AV products are registered
        if not av_products:
            findings.append(
                Finding(
                    title="No antivirus product is registered",
                    description=(
                        "Windows Security Center detected no registered antivirus products. "
                        "The system has no real-time malware protection."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "no_av_product"},
                )
            )
        else:
            # Check for real-time protection in all AV products
            has_realtime_protection = any(
                av.get("real_time_enabled", False) for av in av_products
            )

            if not has_realtime_protection:
                findings.append(
                    Finding(
                        title="Real-time protection is disabled on all registered antivirus products",
                        description=(
                            "No antivirus product has real-time protection enabled. "
                            "New threats will not be detected as files are accessed."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "realtime_protection_disabled"},
                    )
                )

            # Check for stale definitions
            oldest_definition_age = None
            for av in av_products:
                if av.get("definition_age_days") is not None:
                    if oldest_definition_age is None:
                        oldest_definition_age = av["definition_age_days"]
                    else:
                        oldest_definition_age = max(
                            oldest_definition_age, av["definition_age_days"]
                        )

            if oldest_definition_age is not None and oldest_definition_age > 7:
                findings.append(
                    Finding(
                        title=(
                            f"Antivirus definitions are {int(oldest_definition_age)} days old"
                        ),
                        description=(
                            "At least one antivirus product has outdated definitions, "
                            "reducing detection of newer threats."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "stale_definitions"},
                    )
                )

            # Check for multiple AV products (potential conflicts)
            if len(av_products) > 1:
                findings.append(
                    Finding(
                        title=f"{len(av_products)} antivirus products are registered",
                        description=(
                            "Multiple antivirus products can conflict with each other, "
                            "causing performance issues and reduced protection."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "multiple_av_products", "count": len(av_products)},
                    )
                )

            # Report all registered AV products
            product_list = ", ".join(av["name"] for av in av_products)
            findings.append(
                Finding(
                    title=f"Registered antivirus products: {product_list}",
                    description=(
                        "The following antivirus products are registered in Windows Security Center: "
                        + ", ".join(
                            f"{av['name']} (enabled: {av['enabled']}, "
                            f"real-time: {av['real_time_enabled']}, "
                            f"definitions: {av.get('definition_age_days', 'unknown')} days old)"
                            for av in av_products
                        )
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "registered_products", "products": av_products},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "realtime_protection_disabled":
                title = "Enable real-time protection in Windows Defender"
                ps_command = "Set-MpPreference -DisableRealtimeMonitoring $false"
                description = (
                    "Runs PowerShell command to enable real-time protection in Windows Defender. "
                    "Note: You may need to manually enable real-time protection for non-Microsoft "
                    "antivirus products through their respective settings."
                )
            elif check == "stale_definitions":
                title = "Update antivirus definitions"
                ps_command = "Update-MpSignature"
                description = (
                    "Runs PowerShell command to update Windows Defender definitions. "
                    "Non-Microsoft antivirus products should update automatically or through "
                    "their own update mechanisms."
                )
            elif check == "no_av_product":
                title = "No action: install an antivirus product"
                description = (
                    "No registered antivirus product detected. Please install and enable a "
                    "reputable antivirus solution (Windows Defender is built-in and enabled by default)."
                )
                actions.append(
                    Action(
                        title=title,
                        description=description,
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual installation of antivirus product required",
                    )
                )
                continue
            else:
                continue

            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_command],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip()
                    or "PowerShell command failed (may require Administrator privileges)"
                )
            except OSError as e:
                success = False
                error = str(e)

            actions.append(
                Action(
                title=title,
                description=description,
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=success,
                    error=error,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _get_antivirus_products(self) -> list[dict]:
        """Query Windows Security Center 2 for registered antivirus products."""
        try:
            ps_command = (
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
                "Select-Object displayName, productState, pathToSignedReportingExe | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            if not data:
                return []

            # Normalize to list
            products = data if isinstance(data, list) else [data]

            av_list = []
            for product in products:
                av_info = {
                    "name": product.get("displayName", "Unknown"),
                    "enabled": self._is_product_enabled(product.get("productState", 0)),
                    "real_time_enabled": self._is_realtime_protection_enabled(
                        product.get("productState", 0)
                    ),
                    "definition_age_days": None,
                }
                av_list.append(av_info)

            return av_list
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
            return []

    def _get_defender_status(self) -> dict | None:
        """Query Windows Defender specific status including definition age."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0 or not result.stdout.strip():
                return None

            return json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return None

    @staticmethod
    def _is_product_enabled(product_state: int) -> bool:
        """Decode productState bitmask to check if product is enabled.

        Bit 4 (value 16) indicates enabled/disabled state.
        """
        # Bit 4 set = disabled, Bit 4 clear = enabled
        return (product_state & 0x10) == 0

    @staticmethod
    def _is_realtime_protection_enabled(product_state: int) -> bool:
        """Decode productState bitmask to check if real-time protection is enabled.

        Bit 8 (value 256) indicates real-time protection status.
        """
        # Bit 8 set = real-time protection enabled
        return (product_state & 0x100) != 0
