import re
import subprocess
from datetime import datetime

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
    name = "system_age_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get hardware info
        hardware_info = self._run_system_profiler_hardware()
        if not hardware_info:
            findings.append(
                Finding(
                    title="Unable to determine hardware information",
                    description="Failed to run system_profiler to retrieve hardware data",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"error": "No hardware info available"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Parse hardware info
        model = _extract_model(hardware_info)
        model_year = _extract_model_year(hardware_info)
        system_serial = _extract_serial(hardware_info)

        # Get macOS version and build
        try:
            version_str, build = self._run_sw_vers()
        except subprocess.CalledProcessError:
            version_str = "Unknown"
            build = "Unknown"

        # Get original install date
        try:
            install_date = self._run_install_date()
        except (subprocess.CalledProcessError, OSError):
            install_date = None

        # Calculate hardware age
        hardware_age_years = None
        if model_year:
            try:
                year = int(model_year)
                current_year = datetime.now().year
                hardware_age_years = current_year - year
            except (ValueError, TypeError):
                hardware_age_years = None

        # Determine vintage/obsolete status
        is_obsolete = hardware_age_years is not None and hardware_age_years > 10
        is_vintage = hardware_age_years is not None and hardware_age_years > 7

        # Parse macOS version
        major_version = _parse_version(version_str)
        current_major = 15  # macOS Sequoia is 15

        # Check macOS version lag
        version_lag = current_major - major_version

        # Create findings
        if is_obsolete:
            findings.append(
                Finding(
                    title=f"{model} is obsolete (over 10 years old)",
                    description=(
                        f"This {model} ({model_year}) is over 10 years old and is classified as obsolete "
                        "by Apple. It may no longer receive security updates and cannot run the latest "
                        "macOS. Consider whether repair is cost-effective compared to replacement."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "model": model,
                        "year": model_year,
                        "age_years": hardware_age_years,
                        "status": "obsolete",
                        "serial": system_serial,
                        "version": version_str,
                        "build": build,
                    },
                )
            )
        elif is_vintage:
            findings.append(
                Finding(
                    title=f"{model} is vintage (7-10 years old)",
                    description=(
                        f"This {model} ({model_year}) is 7-10 years old and is classified as vintage "
                        "by Apple. It may have limited security update support. Verify with Apple's "
                        "vintage and obsolete products list for your region."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "model": model,
                        "year": model_year,
                        "age_years": hardware_age_years,
                        "status": "vintage",
                        "serial": system_serial,
                        "version": version_str,
                        "build": build,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"{model} is within supported age range",
                    description=(
                        f"This {model} ({model_year}) is within Apple's supported product lifecycle. "
                        "Full security updates and support are typically available."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "model": model,
                        "year": model_year,
                        "age_years": hardware_age_years if hardware_age_years is not None else 0,
                        "status": "current",
                        "serial": system_serial,
                        "version": version_str,
                        "build": build,
                    },
                )
            )

        # Check macOS version lag
        if version_lag > 2:
            findings.append(
                Finding(
                    title=f"macOS is {version_lag} major versions behind current",
                    description=(
                        f"Your macOS version {major_version} is {version_lag} major versions behind "
                        f"the current macOS {current_major}. Consider upgrading if your hardware supports it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "current_version": major_version,
                        "latest_version": current_major,
                        "lag": version_lag,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        # Track which findings we've already handled
        handled_statuses = set()

        for finding in findings.findings:
            status = finding.data.get("status")
            lag = finding.data.get("lag")

            if status == "obsolete" and status not in handled_statuses:
                handled_statuses.add(status)
                model = finding.data.get("model", "Mac")
                year = finding.data.get("year", "Unknown")
                actions.append(
                    Action(
                        title=f"{model} ({year}) is obsolete",
                        description=(
                            f"This {model} from {year} is over 10 years old and classified as obsolete. "
                            "Apple no longer provides security updates. Evaluate repair costs against "
                            "replacement costs. If keeping the device, ensure it is not connected to "
                            "sensitive networks and do not use for financial transactions or sensitive data."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif status == "vintage" and status not in handled_statuses:
                handled_statuses.add(status)
                model = finding.data.get("model", "Mac")
                year = finding.data.get("year", "Unknown")
                actions.append(
                    Action(
                        title=f"{model} ({year}) is vintage",
                        description=(
                            f"This {model} from {year} is 7-10 years old and classified as vintage. "
                            "Verify the product support status with Apple for your region at "
                            "support.apple.com/vintage. Security updates may be limited. Consider "
                            "upgrading to a newer model if replacement is feasible."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif status == "current" and status not in handled_statuses:
                handled_statuses.add(status)
                model = finding.data.get("model", "Mac")
                year = finding.data.get("year", "Unknown")
                actions.append(
                    Action(
                        title=f"{model} ({year}) is within supported lifecycle",
                        description=(
                            f"This {model} from {year} is within Apple's standard support lifecycle. "
                            "Continue to keep macOS and all software updated with the latest security patches."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif lag is not None and lag not in handled_statuses:
                handled_statuses.add(lag)
                current_v = finding.data.get("current_version")
                latest_v = finding.data.get("latest_version")
                actions.append(
                    Action(
                        title=f"Upgrade macOS to latest version",
                        description=(
                            f"Your macOS {current_v} is {lag} major versions behind macOS {latest_v}. "
                            "Check if your hardware is compatible with newer macOS versions at "
                            "support.apple.com/macos. If supported, back up your data and upgrade "
                            "through System Settings > General > Software Update."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler_hardware(self) -> str:
        """Run system_profiler SPHardwareDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except Exception:
            return ""

    def _run_sw_vers(self) -> tuple[str, str]:
        """Run sw_vers to get version and build."""
        result = subprocess.run(
            ["sw_vers", "-productVersion"],
            capture_output=True,
            text=True,
            check=True,
        )
        version = result.stdout.strip()

        result = subprocess.run(
            ["sw_vers", "-buildVersion"],
            capture_output=True,
            text=True,
            check=True,
        )
        build = result.stdout.strip()

        return version, build

    def _run_install_date(self) -> str:
        """Try to get original install date via stat command."""
        try:
            result = subprocess.run(
                ["stat", "-f", "%SB", "/var/db/.AppleSetupDone"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None


def _extract_model(hardware_info: str) -> str:
    """Extract Mac model from system_profiler output."""
    match = re.search(r"Model Name:\s*(.+?)(?:\n|$)", hardware_info)
    if match:
        return match.group(1).strip()
    return "Unknown Mac"


def _extract_model_year(hardware_info: str) -> str:
    """Extract model year from system_profiler output."""
    match = re.search(r"Model Year:\s*(.+?)(?:\n|$)", hardware_info)
    if match:
        year_str = match.group(1).strip()
        # Extract just the year (e.g., "2017" from "2017")
        year_match = re.search(r"(\d{4})", year_str)
        if year_match:
            return year_match.group(1)
    return None


def _extract_serial(hardware_info: str) -> str:
    """Extract serial number from system_profiler output."""
    match = re.search(r"Serial Number \(system\):\s*(.+?)(?:\n|$)", hardware_info)
    if match:
        return match.group(1).strip()
    return None


def _parse_version(version_str: str) -> int:
    """Extract major version from version string."""
    parts = version_str.strip().split(".")
    if len(parts) >= 1:
        try:
            return int(parts[0])
        except ValueError:
            return 0
    return 0
