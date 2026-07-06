from abc import ABC, abstractmethod
from typing import Any

from rescue.models import (
    CheckResult,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    SystemProfile,
)


class ModuleBase(ABC):
    name: str
    category: str
    platforms: list[Platform]
    risk_level: RiskLevel = RiskLevel.SAFE
    priority: int = 50
    depends_on: list[str] = []
    estimated_duration: str = "unknown"

    @abstractmethod
    def check(self, profile: SystemProfile) -> CheckResult:
        ...

    @abstractmethod
    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        ...

    def configure(self, config: dict[str, Any]) -> None:
        """Apply profile-driven configuration to this module. Default: no-op.

        Modules that care about profile settings (e.g. sensitivity level)
        override this to react to the `module_config` entry a profile YAML
        defines for them.
        """
        pass

    def report(self, check: CheckResult, fix: FixResult | None = None) -> str:
        lines = [f"=== {self.name} ==="]
        if not check.has_issues:
            lines.append("No issues found.")
            return "\n".join(lines)
        lines.append(f"Found {len(check.findings)} issue(s):")
        for f in check.findings:
            lines.append(f"  [{f.severity.value}] {f.title}: {f.description}")
        if fix:
            lines.append(f"\nActions taken: {len(fix.actions)}")
            for a in fix.actions:
                status = "OK" if a.success else f"FAILED: {a.error}"
                lines.append(f"  {a.title}: {status}")
        return "\n".join(lines)
