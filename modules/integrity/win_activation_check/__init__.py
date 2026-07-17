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
    name = "win_activation_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get activation status
        activation_info = self._get_activation_status()
        if not activation_info:
            findings.append(
                Finding(
                    title="Could not retrieve Windows activation status",
                    description=(
                        "Failed to run slmgr.vbs. Activation status cannot be assessed. "
                        "Ensure you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "activation_check_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check activation status
        is_activated = activation_info.get("is_activated", False)
        in_grace_period = activation_info.get("in_grace_period", False)
        license_type = activation_info.get("license_type", "Unknown")
        license_status = activation_info.get("license_status", "Unknown")
        is_digital = activation_info.get("is_digital", False)

        # Warning: In grace period (check this first since it takes precedence)
        if in_grace_period:
            findings.append(
                Finding(
                    title="Windows is in grace period",
                    description=(
                        f"Windows is in the initial grace period. "
                        f"The grace period will expire soon and Windows will need to be activated. "
                        f"License type: {license_type}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "grace_period",
                        "license_type": license_type,
                    },
                )
            )
        # Critical: Not activated
        elif not is_activated:
            findings.append(
                Finding(
                    title="Windows is not activated",
                    description=(
                        f"Windows activation status: {license_status}. "
                        "This may result in a watermark on your screen and restrictions on "
                        "Windows features. Activation is required for full functionality."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "not_activated",
                        "license_status": license_status,
                        "license_type": license_type,
                    },
                )
            )
        else:
            # Info: Activated
            license_info = (
                f"License type: {license_type}. "
                f"License status: {license_status}. "
            )
            if is_digital:
                license_info += "Digital license."
            else:
                license_info += "Product key based."

            findings.append(
                Finding(
                    title="Windows is activated",
                    description=(
                        f"Windows activation is valid. {license_info} "
                        "Your system is properly licensed and activated."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "activated",
                        "license_type": license_type,
                        "license_status": license_status,
                        "is_digital": is_digital,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "not_activated":
                license_type = finding.data.get("license_type", "Unknown")
                actions.append(
                    Action(
                        title="Windows is not activated",
                        description=(
                            f"Your Windows installation is not activated. License type: {license_type}. "
                            "To activate Windows: "
                            "(1) Open Settings > System > Activation. "
                            "(2) Click 'Activate' to activate Windows using a product key "
                            "or your Microsoft account. "
                            "(3) If you have a digital license linked to your account, sign in with that account. "
                            "(4) If you have a new product key, enter it in the Settings interface. "
                            "(5) If you need help, visit https://support.microsoft.com/en-us/windows/activation"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "grace_period":
                license_type = finding.data.get("license_type", "Unknown")
                actions.append(
                    Action(
                        title="Windows is in grace period",
                        description=(
                            f"Your Windows is in the grace period and needs to be activated soon. "
                            f"License type: {license_type}. "
                            "To activate Windows before the grace period expires: "
                            "(1) Open Settings > System > Activation. "
                            "(2) Click 'Activate' to activate Windows using a product key "
                            "or your Microsoft account. "
                            "(3) Complete the activation process. "
                            "Activating during the grace period ensures uninterrupted access to all features."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "activation_check_failed":
                actions.append(
                    Action(
                        title="Unable to check Windows activation status",
                        description=(
                            "The slmgr.vbs command failed. "
                            "Ensure you have Administrator privileges and try running the diagnostic again. "
                            "To manually check activation status, run the following in Command Prompt (as Administrator): "
                            "cscript C:\\Windows\\System32\\slmgr.vbs /xpr"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "activated":
                actions.append(
                    Action(
                        title="Windows is properly activated",
                        description=(
                            "Your Windows installation is properly activated and licensed. "
                            "Continue to maintain your activation by keeping your system up to date "
                            "and protecting your digital license or product key."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_activation_status(self) -> Optional[dict]:
        """Get Windows activation status via slmgr.vbs commands."""
        try:
            # Get expiration status
            xpr_output = self._run_slmgr_command("/xpr")
            if not xpr_output:
                return None

            # Get detailed license info
            dli_output = self._run_slmgr_command("/dli")
            if not dli_output:
                return None

            return _parse_activation_info(xpr_output, dli_output)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _run_slmgr_command(self, flag: str) -> Optional[str]:
        """Run a slmgr.vbs command and return output."""
        try:
            cmd = ["cscript", "//Nologo", "C:\\Windows\\System32\\slmgr.vbs", flag]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None
            return result.stdout
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_activation_info(xpr_output: str, dli_output: str) -> dict:
    """Parse slmgr.vbs output to determine activation status."""
    info = {
        "is_activated": False,
        "in_grace_period": False,
        "license_type": "Unknown",
        "license_status": "Unknown",
        "is_digital": False,
    }

    xpr_lower = xpr_output.lower()

    # Determine activation status from /xpr output (this is the source of truth)
    if "permanently activated" in xpr_lower:
        info["is_activated"] = True
        info["in_grace_period"] = False
    elif "initial grace period" in xpr_lower:
        info["is_activated"] = False
        info["in_grace_period"] = True
    elif "notification" in xpr_lower or "notice" in xpr_lower:
        info["is_activated"] = False
        info["in_grace_period"] = False
    else:
        # Default: assume not activated if we can't determine
        info["is_activated"] = False
        info["in_grace_period"] = False

    # Parse license details from /dli output
    for line in dli_output.split("\n"):
        line_lower = line.lower()
        if "license status" in line_lower:
            # Extract status (e.g., "License Status: Initial grace period")
            if ":" in line:
                status_part = line.split(":", 1)[1].strip()
                info["license_status"] = status_part

        elif "license edition" in line_lower or "edition" in line_lower:
            # Extract edition (OEM, Retail, Volume)
            if ":" in line:
                edition_part = line.split(":", 1)[1].strip()
                if "oem" in edition_part.lower():
                    info["license_type"] = "OEM"
                elif "volume" in edition_part.lower():
                    info["license_type"] = "Volume"
                elif "retail" in edition_part.lower():
                    info["license_type"] = "Retail"
                else:
                    info["license_type"] = edition_part

        elif "digital license" in line_lower:
            info["is_digital"] = True
        elif "product key" in line_lower:
            info["is_digital"] = False

    return info
