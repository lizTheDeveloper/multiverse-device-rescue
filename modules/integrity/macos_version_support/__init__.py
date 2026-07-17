import re
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


# macOS version support mapping
MACOS_SUPPORT_STATUS = {
    "15": {"name": "Sequoia", "status": "current", "security_updates": True},
    "14": {"name": "Sonoma", "status": "supported", "security_updates": True},
    "13": {"name": "Ventura", "status": "supported", "security_updates": True},
    "12": {"name": "Monterey", "status": "limited", "security_updates": True},
    "11": {"name": "Big Sur", "status": "unsupported", "security_updates": False},
}


class Module(ModuleBase):
    name = "macos_version_support"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get macOS version and build
        version_info = self._get_version_info()
        if not version_info:
            findings.append(
                Finding(
                    title="Unable to determine macOS version",
                    description="Could not retrieve macOS version information.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "version_unavailable"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        macos_version = version_info.get("version", "")
        macos_build = version_info.get("build", "")
        major_version = macos_version.split(".")[0] if macos_version else ""

        # Get hardware info
        hardware_info = self._get_hardware_info()
        mac_model = hardware_info.get("model", "Unknown")
        model_name = hardware_info.get("model_name", "Unknown")
        architecture = hardware_info.get("architecture", "Unknown")

        # Add INFO finding with system information
        findings.append(
            Finding(
                title="macOS Version Information",
                description=(
                    f"macOS {macos_version} ({macos_build}), "
                    f"Model: {model_name} ({mac_model}), "
                    f"Architecture: {architecture}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "version_info",
                    "version": macos_version,
                    "build": macos_build,
                    "model": mac_model,
                    "model_name": model_name,
                    "architecture": architecture,
                },
            )
        )

        # Check support status
        support_info = MACOS_SUPPORT_STATUS.get(major_version)

        if support_info is None:
            # Newer or older version not in the map
            if int(major_version) > 15:
                # Newer than Sequoia
                support_info = {"name": f"macOS {major_version}", "status": "current", "security_updates": True}
            else:
                # Older than Big Sur
                support_info = {"name": f"macOS {major_version}", "status": "unsupported", "security_updates": False}

        # Check for unsupported versions (macOS 11 or older)
        if not support_info.get("security_updates", False):
            findings.append(
                Finding(
                    title=f"macOS version no longer receiving security updates",
                    description=(
                        f"This Mac is running {support_info.get('name', f'macOS {major_version}')}, "
                        "which is no longer receiving security updates from Apple. "
                        "This poses a security risk. Consider upgrading to a supported macOS version."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "unsupported_version",
                        "version": major_version,
                        "name": support_info.get("name"),
                    },
                )
            )

        # Check for limited security updates (macOS 12)
        elif major_version == "12":
            findings.append(
                Finding(
                    title="macOS Monterey receiving extended security updates only",
                    description=(
                        "This Mac is running macOS 12 (Monterey), which is receiving "
                        "extended security-only updates but no major feature updates. "
                        "Consider upgrading to macOS 13 (Ventura) or later for full support."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "limited_updates",
                        "version": major_version,
                    },
                )
            )

        # Check for Intel Macs approaching end of support
        if architecture == "x86_64":
            findings.append(
                Finding(
                    title="Intel Mac approaching end of Apple support lifecycle",
                    description=(
                        "This is an Intel-based Mac. Apple has transitioned to Apple Silicon, "
                        "and Intel Mac support will eventually end. Ensure this Mac is running "
                        "the latest macOS version compatible with your hardware."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "intel_mac",
                        "architecture": architecture,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "version_unavailable":
                actions.append(
                    Action(
                        title="Unable to check macOS version",
                        description=(
                            "The system could not retrieve macOS version information. "
                            "Try restarting your Mac if the issue persists."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "version_info":
                actions.append(
                    Action(
                        title="macOS version information",
                        description=(
                            f"{finding.description}\n\n"
                            "No action required. This is informational."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unsupported_version":
                actions.append(
                    Action(
                        title="Upgrade to a supported macOS version",
                        description=(
                            "This Mac is running an unsupported version of macOS that no longer "
                            "receives security updates. To upgrade:\n"
                            "1. Go to System Settings > General > Software Update\n"
                            "2. Follow the prompts to download and install the latest macOS\n\n"
                            "Note: Check Apple's website for the latest macOS version supported by "
                            "your Mac model."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "limited_updates":
                actions.append(
                    Action(
                        title="Consider upgrading from macOS Monterey",
                        description=(
                            "macOS Monterey is receiving extended security-only updates but no new "
                            "features. To upgrade to a fully supported macOS:\n"
                            "1. Go to System Settings > General > Software Update\n"
                            "2. If an update is available, follow the prompts to install\n\n"
                            "Upgrading will provide both security updates and new features."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "intel_mac":
                actions.append(
                    Action(
                        title="Intel Mac support guidance",
                        description=(
                            "Your Mac uses an Intel processor. Apple has transitioned all new Macs "
                            "to Apple Silicon. While Intel Macs continue to receive support, eventually "
                            "this will end. Ensure your Mac is running the latest compatible macOS:\n"
                            "1. Go to System Settings > General > Software Update\n"
                            "2. Install any available updates\n\n"
                            "Check Apple's support site for the maximum macOS version your model can run."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_version_info(self) -> dict:
        """Get macOS version and build info."""
        info = {}

        try:
            version_result = subprocess.run(
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if version_result.returncode == 0:
                info["version"] = version_result.stdout.strip()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        try:
            build_result = subprocess.run(
                ["sw_vers", "-buildVersion"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if build_result.returncode == 0:
                info["build"] = build_result.stdout.strip()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return info if info.get("version") else None

    def _get_hardware_info(self) -> dict:
        """Get Mac model, model name, and architecture."""
        info = {}

        # Get model via sysctl
        try:
            model_result = subprocess.run(
                ["sysctl", "hw.model"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if model_result.returncode == 0:
                match = re.search(r"hw\.model:\s*(.+)", model_result.stdout)
                if match:
                    info["model"] = match.group(1).strip()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        # Get model name via system_profiler
        try:
            profiler_result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if profiler_result.returncode == 0:
                match = re.search(r"Model Name:\s*(.+?)(?:\n|$)", profiler_result.stdout)
                if match:
                    info["model_name"] = match.group(1).strip()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        # Get architecture via uname
        try:
            arch_result = subprocess.run(
                ["uname", "-m"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if arch_result.returncode == 0:
                info["architecture"] = arch_result.stdout.strip()
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return info
