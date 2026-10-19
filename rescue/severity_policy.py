"""How alarming a finding may be, whatever its module says.

"Needs attention now" (critical) is for something that may be hurting the
person's security or data right now. A slow computer, an app that keeps
crashing or a missing backup is worth a look, not an emergency, so findings
from performance and bloatware checks, and from the crash and backup checks,
are at most a warning. The cap is applied once, where every check's result
comes back (rescue/orchestrator.py and ``rescue run``), so every screen and
export agrees.
"""

from __future__ import annotations

from rescue.models import Severity

CAPPED_CATEGORIES = frozenset({"performance", "bloatware"})
CAPPED_MODULES = frozenset({
    "crash_log_analyzer",
    "app_crash_analyzer",
    "application_crash_report",
    "kernel_panic_check",
    "win_bsod_analysis",
    "backup_status",
    "time_machine_check",
    "time_machine_health",
    "time_machine_exclusions",
})


def cap_severity(mod, check) -> None:
    """Lower any critical finding of a capped check to a warning, in place."""
    if check is None or getattr(check, "error", None):
        return
    capped = getattr(mod, "category", None) in CAPPED_CATEGORIES or getattr(mod, "name", None) in CAPPED_MODULES
    if not capped:
        return
    for f in getattr(check, "findings", []) or []:
        if getattr(f, "severity", None) == Severity.CRITICAL:
            f.severity = Severity.WARNING
