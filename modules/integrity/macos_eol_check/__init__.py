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
    name = "macos_eol_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            version_str, build = self._run_sw_vers()
        except subprocess.CalledProcessError as e:
            findings.append(
                Finding(
                    title="Unable to determine macOS version",
                    description=f"Failed to run sw_vers: {e}",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"error": str(e)},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        try:
            model = self._run_sysctl()
        except subprocess.CalledProcessError:
            model = "Unknown"

        # Parse major version
        major_version = _parse_version(version_str)

        # Get EOL status
        status = _get_eol_status(major_version)
        version_name = _get_version_name(major_version)

        # Create finding based on status
        if status == "supported":
            findings.append(
                Finding(
                    title=f"macOS {version_name} is supported",
                    description=f"Version {major_version} is currently supported with regular updates.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "version": str(major_version),
                        "build": build,
                        "model": model,
                        "status": "supported",
                    },
                )
            )
        elif status == "security_only":
            findings.append(
                Finding(
                    title=f"macOS {version_name} receives security updates only",
                    description=f"Version {major_version} is still supported but receives only security updates, not new features.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "version": str(major_version),
                        "build": build,
                        "model": model,
                        "status": "security_only",
                    },
                )
            )
        elif status == "eol":
            findings.append(
                Finding(
                    title=f"macOS {version_name} is end-of-life",
                    description=f"Version {major_version} is EOL and no longer receives security updates. Consider upgrading.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "version": str(major_version),
                        "build": build,
                        "model": model,
                        "status": "eol",
                    },
                )
            )
        else:  # critical_eol
            findings.append(
                Finding(
                    title=f"macOS {version_name} is critically end-of-life",
                    description=f"Version {major_version} is CRITICAL EOL with no security updates for over 2 years. Immediate upgrade required.",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "version": str(major_version),
                        "build": build,
                        "model": model,
                        "status": "critical_eol",
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            status = finding.data.get("status")
            version_name = finding.title.split("macOS ")[1].split(" ")[0] if "macOS" in finding.title else "macOS"

            if status == "supported":
                actions.append(
                    Action(
                        title=f"macOS {version_name} is supported",
                        description="Your macOS version is supported and receiving regular updates. No action required.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif status == "security_only":
                actions.append(
                    Action(
                        title=f"macOS {version_name} update available",
                        description="Your macOS version is supported but only receives security updates. Consider upgrading to the latest version for new features and improvements.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif status == "eol":
                model = finding.data.get("model", "Unknown")
                actions.append(
                    Action(
                        title=f"Upgrade macOS {version_name}",
                        description=f"Your macOS version is end-of-life. Upgrade to a supported version. Check {model} compatibility with newer macOS versions.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:  # critical_eol
                model = finding.data.get("model", "Unknown")
                actions.append(
                    Action(
                        title=f"Critical: Upgrade macOS {version_name} immediately",
                        description=f"Your macOS version is critically end-of-life with no security updates. This is a critical security risk. Upgrade immediately. Check {model} compatibility.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

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

    def _run_sysctl(self) -> str:
        """Run sysctl to get hardware model."""
        result = subprocess.run(
            ["sysctl", "hw.model"],
            capture_output=True,
            text=True,
            check=True,
        )
        return _parse_sysctl_output(result.stdout)


def _parse_version(version_str: str) -> float:
    """Extract major.minor version from version string."""
    parts = version_str.strip().split(".")
    if len(parts) >= 2:
        try:
            major = int(parts[0])
            minor = int(parts[1])
            return float(f"{major}.{minor}")
        except ValueError:
            return 0.0
    elif len(parts) == 1:
        try:
            major = int(parts[0])
            return float(major)
        except ValueError:
            return 0.0
    return 0.0


def _parse_sysctl_output(output: str) -> str:
    """Parse hw.model from sysctl output."""
    if "hw.model:" in output:
        return output.split("hw.model:")[1].strip()
    return "Unknown"


def _get_eol_status(version: float) -> str:
    """Get EOL status for a macOS version.

    Returns:
        - "supported": currently supported
        - "security_only": security updates only
        - "eol": end of life
        - "critical_eol": critically end of life (2+ years past EOL)
    """
    # macOS 15 (Sequoia): supported
    # macOS 14 (Sonoma): supported
    # macOS 13 (Ventura): supported (security updates only)
    # macOS 12 (Monterey): EOL
    # macOS 11 (Big Sur): EOL
    # macOS 10.15 (Catalina): CRITICAL EOL
    # macOS 10.14 and below: CRITICAL EOL

    if version >= 14.0:
        return "supported"
    elif version >= 13.0 and version < 14.0:
        return "security_only"
    elif (version >= 12.0 and version < 13.0) or (version >= 11.0 and version < 12.0):
        return "eol"
    elif version >= 10.0:
        # All 10.x versions are critical EOL
        return "critical_eol"
    else:
        return "critical_eol"


def _get_version_name(version: float) -> str:
    """Get the friendly name for a macOS version."""
    # Direct matches for major versions
    if version >= 14.0 and version < 15.0:
        return "Sonoma (14)"
    elif version >= 15.0:
        return "Sequoia (15)"
    elif version >= 13.0 and version < 14.0:
        return "Ventura (13)"
    elif version >= 12.0 and version < 13.0:
        return "Monterey (12)"
    elif version >= 11.0 and version < 12.0:
        return "Big Sur (11)"
    elif version >= 10.15 and version < 11.0:
        return "Catalina (10.15)"
    elif version >= 10.14 and version < 10.15:
        return "Mojave (10.14)"
    elif version < 10.14:
        return f"macOS ({version})"

    # Return generic name for unknown versions
    return f"macOS ({version})"
