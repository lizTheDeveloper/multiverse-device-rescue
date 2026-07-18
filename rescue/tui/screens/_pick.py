"""Pick the walkthrough for the highest-severity coded finding in a check."""

from rescue.guides import Guide
from rescue.models import CheckResult, Severity
from rescue.remediation import walkthrough_for

_SEVERITY_ORDER = {Severity.CRITICAL: 3, Severity.WARNING: 2, Severity.INFO: 1}


def highest_severity_walkthrough(index: dict, check: CheckResult) -> Guide | None:
    best = None
    best_rank = 0
    for finding in check.findings:
        guide = walkthrough_for(index, finding.code)
        if guide is None:
            continue
        rank = _SEVERITY_ORDER.get(finding.severity, 0)
        if rank > best_rank:
            best, best_rank = guide, rank
    return best
