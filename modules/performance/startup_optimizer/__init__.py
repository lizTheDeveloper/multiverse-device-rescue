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

WARNING_COUNT = 3
CRITICAL_COUNT = 8


class Module(ModuleBase):
    name = "startup_optimizer"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_launchctl_list()
        labels = _parse_launchctl_list(output)
        third_party = [
            label for label in labels if not label.startswith("com.apple.")
        ]

        findings = []
        if len(third_party) >= CRITICAL_COUNT:
            findings.append(self._make_finding(third_party, Severity.CRITICAL))
        elif len(third_party) >= WARNING_COUNT:
            findings.append(self._make_finding(third_party, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            labels = finding.data.get("third_party_labels", [])
            preview = ", ".join(labels[:5])
            if len(labels) > 5:
                preview += ", ..."
            actions.append(
                Action(
                    title="Startup items report",
                    description=(
                        f"{finding.data.get('count', len(labels))} third-party "
                        f"startup item(s) detected: {preview}. Run the "
                        "startup_auditor module to review and disable the ones "
                        "you don't need."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(self, third_party: list[str], severity: Severity) -> Finding:
        return Finding(
            title=f"{len(third_party)} third-party startup items detected",
            description=(
                f"{len(third_party)} non-Apple launchd job(s) start "
                "automatically, which can slow down boot and login time."
            ),
            severity=severity,
            category=self.category,
            data={"third_party_labels": third_party, "count": len(third_party)},
        )

    def _run_launchctl_list(self) -> str:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
        )
        return result.stdout


def _parse_launchctl_list(output: str) -> list[str]:
    labels = []
    lines = output.strip().split("\n")
    for line in lines[1:]:  # skip header row
        parts = line.split()
        if len(parts) >= 3:
            labels.append(parts[-1])
    return labels
