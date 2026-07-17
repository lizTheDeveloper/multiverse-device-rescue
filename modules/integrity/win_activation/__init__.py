import json
import subprocess
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
    name = "win_activation"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get activation info from WMI
        activation_info = self._get_activation_info()

        if not activation_info:
            findings.append(
                Finding(
                    title="Unable to determine Windows activation status",
                    description=(
                        "Failed to retrieve Windows activation information. "
                        "This may require administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "unable_to_check"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        license_status = activation_info.get("license_status")
        license_status_text = _get_license_status_text(license_status)
        product_name = activation_info.get("product_name", "Windows")

        # Check activation status
        if license_status == 1:
            # Licensed - all good
            findings.append(
                Finding(
                    title=f"{product_name} is activated",
                    description=(
                        f"Windows is properly activated with status: {license_status_text}. "
                        "Your system is properly licensed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "activated",
                        "license_status": license_status,
                        "status_text": license_status_text,
                        "product_name": product_name,
                    },
                )
            )
        elif license_status in (2, 3, 4):
            # In grace period (OOBGrace, OOTGrace, NonGenuineGrace)
            findings.append(
                Finding(
                    title=f"{product_name} is in grace period",
                    description=(
                        f"Windows is in grace period with status: {license_status_text}. "
                        "Activation will be required within 30 days."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "grace_period",
                        "license_status": license_status,
                        "status_text": license_status_text,
                        "product_name": product_name,
                    },
                )
            )
        elif license_status == 0:
            # Unlicensed
            findings.append(
                Finding(
                    title=f"{product_name} is not activated",
                    description=(
                        "Windows is not activated. This is a critical issue. "
                        "Your system is not properly licensed and may have limited functionality."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "not_activated",
                        "license_status": license_status,
                        "status_text": license_status_text,
                        "product_name": product_name,
                    },
                )
            )
        elif license_status == 5:
            # Notification
            findings.append(
                Finding(
                    title=f"{product_name} activation notification",
                    description=(
                        f"Windows is showing activation notification: {license_status_text}. "
                        "Activation may be pending."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "notification",
                        "license_status": license_status,
                        "status_text": license_status_text,
                        "product_name": product_name,
                    },
                )
            )
        else:
            # Unknown status
            findings.append(
                Finding(
                    title=f"{product_name} has unknown activation status",
                    description=(
                        f"Windows activation status is unknown: {license_status}. "
                        "Please check activation manually."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "unknown_status",
                        "license_status": license_status,
                        "product_name": product_name,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")
            product_name = finding.data.get("product_name", "Windows")
            status_text = finding.data.get("status_text", "Unknown")

            if check == "activated":
                actions.append(
                    Action(
                        title=f"{product_name} is properly activated",
                        description=(
                            "Your Windows system is properly activated and licensed. "
                            "No action required."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "grace_period":
                actions.append(
                    Action(
                        title=f"Activate {product_name}",
                        description=(
                            f"Windows is in grace period ({status_text}). "
                            "You have approximately 30 days to activate. "
                            "Go to Settings > System > Activation and activate using your product key or Microsoft account."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "not_activated":
                actions.append(
                    Action(
                        title=f"Activate {product_name} immediately",
                        description=(
                            "Windows is not activated. This is critical. "
                            "Go to Settings > System > Activation and activate using a valid product key or your Microsoft account. "
                            "Contact your system administrator or Microsoft support if you need assistance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "notification":
                actions.append(
                    Action(
                        title=f"{product_name} activation in progress",
                        description=(
                            f"Windows is showing activation notification ({status_text}). "
                            "Your activation may be processing. "
                            "If activation does not complete within 24 hours, "
                            "go to Settings > System > Activation to complete the process."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unable_to_check":
                actions.append(
                    Action(
                        title="Unable to verify activation status",
                        description=(
                            "This check requires administrator privileges. "
                            "Run this diagnostic as Administrator to check Windows activation status, "
                            "or manually check Settings > System > Activation."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            else:  # unknown_status
                actions.append(
                    Action(
                        title=f"Verify {product_name} activation manually",
                        description=(
                            "The activation status could not be determined. "
                            "Please go to Settings > System > Activation to verify your activation status manually."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_activation_info(self) -> Optional[dict]:
        """Get Windows activation information from WMI."""
        try:
            # PowerShell command to get activation info
            ps_cmd = (
                "Get-CimInstance SoftwareLicensingProduct | "
                "Where-Object {$_.PartialProductKey} | "
                "Select-Object Name, LicenseStatus | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_activation_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_activation_info(json_output: str) -> Optional[dict]:
    """Parse PowerShell JSON output from Get-CimInstance SoftwareLicensingProduct."""
    if not json_output.strip():
        return None

    try:
        data = json.loads(json_output)
        # Handle both single object and array
        if isinstance(data, list):
            if not data:
                return None
            data = data[0]

        # Extract activation info
        info = {
            "product_name": data.get("Name", "Windows"),
            "license_status": data.get("LicenseStatus"),
        }

        return info if info.get("license_status") is not None else None
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _get_license_status_text(status_code: int) -> str:
    """Convert license status code to human-readable text."""
    status_map = {
        0: "Unlicensed",
        1: "Licensed",
        2: "Out of Box Grace Period",
        3: "Out of Tolerance Grace Period",
        4: "Non-Genuine Grace Period",
        5: "Notification",
    }
    return status_map.get(status_code, f"Unknown ({status_code})")
