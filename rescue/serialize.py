from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def _plain(value: Any) -> Any:
    """Recursively convert values to JSON-serializable plain Python types.

    Module ``Finding.data`` dicts are free-form and occasionally hold values
    that ``json.dumps`` cannot encode (e.g. ``bytes`` from a subprocess). A
    single such value must never crash the whole scan's JSON output, so
    anything that is not a JSON-native scalar is coerced to a string.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if is_dataclass(value):
        return {k: _plain(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return str(value)


def _remediation(guide) -> dict:
    return {
        "title": guide.title,
        "estimated_time": guide.estimated_time,
        "steps": [{"number": s.number, "title": s.title, "body": s.body} for s in guide.steps],
    }


def _fixable(entry) -> dict:
    return {"will_change": entry["will_change"], "how_to_undo": list(entry["how_to_undo"])}


def _finding(finding, walkthroughs, fixable=None) -> dict:
    out = _plain(finding)
    if fixable is not None:
        out["fixable"] = _fixable(fixable)
    guide = walkthroughs.get(getattr(finding, "code", None)) if walkthroughs else None
    if guide is not None:
        out["remediation"] = _remediation(guide)
    return out


def checks_to_json(results, platform: str, walkthroughs=None, app_fixes=None) -> str:
    """Convert check results to a JSON string suitable for external consumption.

    Args:
        results: List of (ModuleBase, CheckResult) tuples from Orchestrator.run_checks()
        platform: Platform string (e.g. "darwin", "win32", "linux")
        walkthroughs: Optional {finding code: Guide}; a finding whose code has
            a walkthrough gets its steps under "remediation".
        app_fixes: Optional {module name: {will_change, how_to_undo}} allowlist
            (rescue/app_fixes.json). Findings of a listed module that ran
            cleanly get a "fixable" object so the app can offer a fix.

    Returns:
        JSON string with schema_version, platform, and modules array
    """
    modules = []
    for mod, check in results:
        entry = (app_fixes or {}).get(mod.name)
        offer = entry if entry is not None and not check.error and getattr(check, "supported", True) else None
        modules.append({
            "name": mod.name,
            "status": "error" if check.error else "ok",
            "error": check.error,
            # False means the check could not run here: not a clean result.
            "supported": getattr(check, "supported", True),
            "unsupported_reason": getattr(check, "unsupported_reason", None),
            "findings": [_finding(f, walkthroughs, offer) for f in check.findings],
        })
    return json.dumps(
        {"schema_version": 1, "platform": platform, "modules": modules},
        indent=2,
    )
