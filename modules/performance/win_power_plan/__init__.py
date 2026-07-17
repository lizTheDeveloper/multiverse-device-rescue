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
    name = "win_power_plan"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        active_scheme = self._get_active_scheme()
        all_schemes = self._get_all_schemes()

        findings = []

        # Parse active scheme
        active_name = None
        if active_scheme:
            active_name = _parse_active_scheme(active_scheme)

        # Parse all schemes to get names
        scheme_names = _parse_scheme_list(all_schemes)

        if active_name:
            # Check if Power Saver is active (WARNING)
            if "Power Saver" in active_name:
                findings.append(
                    Finding(
                        title="Power Saver mode detected",
                        description=(
                            "The system is running on Power Saver plan, which reduces CPU, "
                            "GPU, and memory speeds. This can cause noticeable performance degradation. "
                            "Consider switching to Balanced or High Performance mode."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"plan_name": active_name, "type": "power_saver_active"},
                    )
                )

            # Always report the active plan (INFO)
            findings.append(
                Finding(
                    title=f"Active power plan: {active_name}",
                    description=(
                        f"The system is currently using the '{active_name}' power plan."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"plan_name": active_name, "type": "active_plan"},
                )
            )

            # Report if Balanced or High Performance is active (INFO)
            if active_name in ["Balanced", "High Performance"]:
                findings.append(
                    Finding(
                        title=f"Optimal power plan active",
                        description=(
                            f"'{active_name}' mode provides a good balance between "
                            "performance and power consumption."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"plan_name": active_name, "type": "optimal_plan"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.data.get("type") == "power_saver_active":
                actions.append(
                    Action(
                        title="Switch from Power Saver mode",
                        description=(
                            "Power Saver mode restricts CPU and GPU performance. Switch to "
                            "'Balanced' or 'High Performance' mode via Settings > System > Power & sleep > "
                            "Power mode (Windows 11) or Control Panel > Power Options > Choose a power plan."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("type") == "active_plan":
                # Informational action for active plan
                actions.append(
                    Action(
                        title="Current power plan",
                        description=(
                            f"Active plan is '{finding.data.get('plan_name')}'. "
                            "Monitor performance and adjust if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("type") == "optimal_plan":
                # Informational action for optimal plan
                actions.append(
                    Action(
                        title="Power plan is optimized",
                        description=(
                            f"'{finding.data.get('plan_name')}' is a good choice for "
                            "system performance and power efficiency."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_active_scheme(self) -> str:
        """Get the active power scheme using powercfg /getactivescheme"""
        try:
            result = subprocess.run(
                ["powercfg", "/getactivescheme"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _get_all_schemes(self) -> str:
        """Get all power schemes using powercfg /list"""
        try:
            result = subprocess.run(
                ["powercfg", "/list"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_active_scheme(output: str) -> str | None:
    """Parse `powercfg /getactivescheme` output.

    Example::

        Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)
    """
    for line in output.splitlines():
        line = line.strip()
        if "Power Scheme GUID" in line and "(" in line and ")" in line:
            # Extract text between last parentheses
            start = line.rfind("(")
            end = line.rfind(")")
            if start != -1 and end != -1:
                return line[start + 1 : end]
    return None


def _parse_scheme_list(output: str) -> dict[str, str]:
    """Parse `powercfg /list` output.

    Example::

        Existing Power Schemes (* Active)
        -----------------------------------
        Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)*
        Power Scheme GUID: 8c5e7fda-e8bf-45a6-a6cc-4b3c1f7b834f  (Power Saver)
        Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2f  (High Performance)
    """
    schemes = {}
    for line in output.splitlines():
        line = line.strip()
        if "Power Scheme GUID" in line and "(" in line:
            # Extract GUID and name
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    guid_part = parts[1].split()[0] if parts[1].split() else ""
                    # Extract text between parentheses
                    start = line.rfind("(")
                    end = line.rfind(")")
                    if start != -1 and end != -1:
                        name = line[start + 1 : end].rstrip("*").strip()
                        schemes[guid_part] = name
    return schemes
