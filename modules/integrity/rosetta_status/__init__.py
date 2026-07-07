import os
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
    name = "rosetta_status"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Detect if on Apple Silicon
        is_apple_silicon = self._is_apple_silicon()
        rosetta_installed = self._is_rosetta_installed()

        if is_apple_silicon:
            if rosetta_installed:
                findings.append(
                    Finding(
                        title="Rosetta 2 is installed",
                        description="Apple Silicon Mac with Rosetta 2 installed. Older Intel apps can run, but with a performance penalty (typically 5-10% slower than native).",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "architecture": "arm64",
                            "rosetta_installed": True,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Rosetta 2 is NOT installed",
                        description="Apple Silicon Mac detected, but Rosetta 2 is not installed. Many older Intel-only apps will fail to launch. Consider installing Rosetta 2.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "architecture": "arm64",
                            "rosetta_installed": False,
                        },
                    )
                )
        else:
            # Intel Mac
            findings.append(
                Finding(
                    title="Intel Mac - Rosetta 2 not needed",
                    description="Running on Intel Mac. Rosetta 2 is not needed for compatibility.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "architecture": "x86_64",
                        "rosetta_installed": False,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            is_apple_silicon = finding.data.get("architecture") == "arm64"
            rosetta_installed = finding.data.get("rosetta_installed")

            if is_apple_silicon and not rosetta_installed:
                actions.append(
                    Action(
                        title="Install Rosetta 2",
                        description=(
                            "Run: softwareupdate --install-rosetta --agree-to-license\n"
                            "Or install manually via the App Store by attempting to run an Intel-only app.\n"
                            "Rosetta 2 will be automatically installed on first use of an Intel app."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif is_apple_silicon and rosetta_installed:
                actions.append(
                    Action(
                        title="Rosetta 2 is installed",
                        description="Rosetta 2 is available on this Apple Silicon Mac. Intel-only apps can run, though with a performance penalty.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                actions.append(
                    Action(
                        title="Intel Mac - no action needed",
                        description="Rosetta 2 is not needed on Intel Macs.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_apple_silicon(self) -> bool:
        """Check if running on Apple Silicon (arm64)."""
        try:
            # Try uname -m first
            result = subprocess.run(
                ["uname", "-m"],
                capture_output=True,
                text=True,
                check=True,
            )
            arch = result.stdout.strip()
            if arch == "arm64":
                return True
        except subprocess.CalledProcessError:
            pass

        # Try sysctl as fallback
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            )
            brand = result.stdout.strip()
            # Apple Silicon macs have "Apple" in their brand string
            if "Apple" in brand:
                return True
        except subprocess.CalledProcessError:
            pass

        return False

    def _is_rosetta_installed(self) -> bool:
        """Check if Rosetta 2 is installed."""
        # Check if Rosetta path exists
        if os.path.exists("/Library/Apple/usr/share/rosetta"):
            return True

        # Try to run arch -x86_64 /usr/bin/true - if it works, Rosetta is installed
        try:
            result = subprocess.run(
                ["arch", "-x86_64", "/usr/bin/true"],
                capture_output=True,
                text=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            # Rosetta not installed or error occurred
            return False
        except FileNotFoundError:
            # arch command not found
            return False
