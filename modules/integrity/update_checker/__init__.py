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
    name = "update_checker"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        os_updates = _parse_softwareupdate_output(self._run_softwareupdate())
        if os_updates:
            findings.append(
                Finding(
                    title=f"{len(os_updates)} macOS update(s) available",
                    description="Pending updates: " + ", ".join(os_updates),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "os_updates", "updates": os_updates},
                )
            )

        brew_output = self._run_brew_outdated()
        if brew_output is not None:
            outdated_packages = _parse_brew_outdated(brew_output)
            if outdated_packages:
                findings.append(
                    Finding(
                        title=f"{len(outdated_packages)} outdated Homebrew package(s)",
                        description="Outdated packages: " + ", ".join(outdated_packages),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "brew_outdated", "packages": outdated_packages},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "os_updates":
                actions.append(
                    Action(
                        title="macOS update guidance",
                        description=(
                            "Run `sudo softwareupdate -i -a` to install all "
                            "pending updates, or open System Settings > "
                            "General > Software Update."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "brew_outdated":
                actions.append(
                    Action(
                        title="Homebrew update guidance",
                        description="Run `brew upgrade` to update all outdated packages.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _run_softwareupdate(self) -> str:
        result = subprocess.run(
            ["softwareupdate", "-l"],
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _run_brew_outdated(self) -> str | None:
        try:
            result = subprocess.run(
                ["brew", "outdated"],
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        return result.stdout


def _parse_softwareupdate_output(output: str) -> list[str]:
    labels = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("* Label:"):
            labels.append(stripped.split("Label:", 1)[1].strip())
    return labels


def _parse_brew_outdated(output: str) -> list[str]:
    packages = []
    for line in output.strip().splitlines():
        line = line.strip()
        if line:
            packages.append(line.split()[0])
    return packages
