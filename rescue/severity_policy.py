"""How alarming a finding may be, whatever its module says.

"Needs attention now" (critical) is for something that may be hurting the
person's security or data right now. A program using a lot of power, an app
that keeps crashing or a missing backup is worth a look, not an emergency.

Only the findings named here are lowered, and only from critical to warning
(UX audit 1, P2-30). Each is named by its module and its ``data["check"]``
(``None`` for the modules whose findings carry no check key). Nothing is
lowered when it comes from a security check, or when its data names malware,
scareware, a crypto miner or adware: those keep whatever the module said.

Applied once, where every check's result comes back (rescue/orchestrator.py
and ``rescue run``), so every screen and export agrees.
"""

from __future__ import annotations

import re

from rescue.models import Severity

# (module, data["check"]) pairs that may be lowered from critical to warning.
CAPPABLE: frozenset[tuple[str, str | None]] = frozenset({
    ("crash_log_analyzer", None),                      # "X has crashed 50 times"
    ("resource_hog_identifier", None),                 # "X is using a lot of power"
    ("time_machine_check", "not_configured"),          # not backing up
    ("time_machine_check", "stale_backup"),            # last backup is old
    ("time_machine_health", "no_destination_configured"),
    ("backup_status", "timemachine_disabled"),
})
CAPPABLE_MODULES = frozenset(m for m, _ in CAPPABLE)

# Never lowered: anything whose data says it is harmful software.
_HARMFUL = re.compile(r"malware|scareware|crypto[\s_-]?miner|cryptojack|\bminer\b|xmrig|adware|trojan|spyware|stalkerware|keylogger", re.I)
_SECURITY_CATEGORIES = frozenset({"security"})


def _values(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _values(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _values(v)
    elif value is not None:
        yield str(value)


def names_harm(finding) -> bool:
    """True when the finding's data or category mentions harmful software."""
    data = getattr(finding, "data", None) or {}
    texts = [getattr(finding, "category", "") or "", *_values(data)]
    return any(_HARMFUL.search(t) for t in texts)


def may_cap(mod, finding) -> bool:
    name = getattr(mod, "name", None)
    if name not in CAPPABLE_MODULES:
        return False
    if getattr(mod, "category", None) in _SECURITY_CATEGORIES:
        return False
    if getattr(finding, "category", None) in _SECURITY_CATEGORIES:
        return False
    data = getattr(finding, "data", None) or {}
    check = data.get("check") if isinstance(data, dict) else None
    if (name, check) not in CAPPABLE:
        return False
    return not names_harm(finding)


def cap_severity(mod, check) -> None:
    """Lower each named critical finding of this check to a warning, in place."""
    if check is None or getattr(check, "error", None):
        return
    for f in getattr(check, "findings", []) or []:
        if getattr(f, "severity", None) == Severity.CRITICAL and may_cap(mod, f):
            f.severity = Severity.WARNING
