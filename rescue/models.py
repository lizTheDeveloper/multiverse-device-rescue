from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Platform(str, Enum):
    DARWIN = "darwin"
    WIN32 = "win32"
    LINUX = "linux"


class RiskLevel(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DESTRUCTIVE = "destructive"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Mode(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"
    CLI = "cli"


class ActionKind(str, Enum):
    GUIDANCE = "guidance"
    MUTATION = "mutation"


class CheckStatus(str, Enum):
    """Honest, distinguishable outcomes of a check.

    HEALTHY (ran, nothing wrong), ISSUES (findings), FAILED (the check errored),
    and UNSUPPORTED (could not run here — e.g. wrong platform or missing
    permission) must never collapse into one another; in particular an
    unsupported check must not read as a healthy result.
    """

    HEALTHY = "healthy"
    ISSUES = "issues"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass
class DiskInfo:
    device: str
    mount_point: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    filesystem: str
    is_ssd: bool | None = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_bytes: int
    command: str


@dataclass
class SystemProfile:
    platform: Platform
    os_name: str
    os_version: str
    architecture: str
    cpu_model: str
    cpu_cores: int
    ram_bytes: int
    disks: list[DiskInfo] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    startup_items: list[str] = field(default_factory=list)
    installed_software: list[str] = field(default_factory=list)
    hostname: str = ""


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    data: dict[str, Any] = field(default_factory=dict)
    # Optional evidence metadata (roadmap P1#1). Left None/empty by modules that
    # have not been migrated yet, so this stays backward compatible.
    confidence: float | None = None
    collected_at: str | None = None
    # Stable finding-type code linking this finding to a remediation
    # walkthrough. Scheme: "<category>.<module>.<slug>". None = no walkthrough.
    code: str | None = None


@dataclass
class CheckResult:
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    # A check that cannot run here reports supported=False rather than an empty
    # (falsely healthy) result. Backward compatible: defaults keep old behavior.
    supported: bool = True
    unsupported_reason: str | None = None

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0

    @property
    def status(self) -> "CheckStatus":
        if self.error:
            return CheckStatus.FAILED
        if not self.supported:
            return CheckStatus.UNSUPPORTED
        if self.findings:
            return CheckStatus.ISSUES
        return CheckStatus.HEALTHY


@dataclass
class Action:
    title: str
    description: str
    risk_level: RiskLevel
    kind: ActionKind = ActionKind.GUIDANCE
    executed: bool = False
    success: bool = False
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class FixResult:
    module_name: str
    actions: list[Action] = field(default_factory=list)

    @property
    def all_succeeded(self) -> bool:
        return all(a.success for a in self.actions)

    @property
    def applied_actions(self) -> list[Action]:
        return [action for action in self.actions if action.executed]

    @property
    def executed_mutations(self) -> list[Action]:
        """Actions that actually changed the system: executed MUTATIONs only.

        Guidance is never a system change, so it is excluded here regardless of
        any ``executed``/``success`` flags a module may set on it.
        """
        return [
            a
            for a in self.actions
            if a.kind == ActionKind.MUTATION and a.executed and a.success
        ]

    @property
    def guidance_actions(self) -> list[Action]:
        return [a for a in self.actions if a.kind == ActionKind.GUIDANCE]
