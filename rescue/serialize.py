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


SAFETY_NOTE = (
    "Before you remove or turn anything off: if you think someone close to you "
    "set this up to watch you, removing it can alert them. Talk to an advocate "
    "first. In the US: National Domestic Violence Hotline, 1-800-799-7233, or "
    "text START to 88788."
)


def _remediation(guide, code=None) -> dict:
    steps = guide.steps_for_code(code)
    out = {
        "title": guide.title,
        "estimated_time": guide.estimated_time,
        "steps": [{"number": s.number, "title": s.title, "body": s.body} for s in steps],
        "all_steps": len(steps) == len(guide.steps),
    }
    if getattr(guide, "monitoring_risk", False):
        out["safety_note"] = SAFETY_NOTE
    return out


def _fixable(entry) -> dict:
    return {"will_change": entry["will_change"], "how_to_undo": list(entry["how_to_undo"])}


def _action_fixable(finding, module_name, app_actions):
    """A per-finding `fixable` for the disable_launch_agent action, or None."""
    spec = (app_actions or {}).get("disable_launch_agent")
    if not isinstance(spec, dict) or module_name not in spec.get("modules", []):
        return None
    severity = getattr(getattr(finding, "severity", None), "value", None)
    if severity not in spec.get("severities", []):
        return None
    from rescue.actions.launch_agent import offer_target

    hit = offer_target(getattr(finding, "data", None), severity, module_name)
    if hit is None:
        return None
    return {
        "action": "disable_launch_agent",
        "target": hit["target"],
        "will_change": spec["will_change"].replace("{label}", hit["label"]),
        "how_to_undo": list(spec["how_to_undo"]),
    }


def _finding(finding, walkthroughs, fixable=None, made_by=None, action_fixable=None) -> dict:
    out = _plain(finding)
    if action_fixable is not None:
        out["fixable"] = action_fixable
    elif fixable is not None:
        out["fixable"] = _fixable(fixable)
    entries = made_by.get(id(finding)) if made_by else None
    if entries:
        out["made_by"] = _plain(entries)
    guide = walkthroughs.get(getattr(finding, "code", None)) if walkthroughs else None
    if guide is not None:
        out["remediation"] = _remediation(guide, getattr(finding, "code", None))
    return out


def checks_to_json(results, platform: str, walkthroughs=None, app_fixes=None, made_by=None, app_actions=None) -> str:
    """Convert check results to a JSON string suitable for external consumption.

    Args:
        results: List of (ModuleBase, CheckResult) tuples from Orchestrator.run_checks()
        platform: Platform string (e.g. "darwin", "win32", "linux")
        walkthroughs: Optional {finding code: Guide}; a finding whose code has
            a walkthrough gets its steps under "remediation".
        app_fixes: Optional {module name: {will_change, how_to_undo}} allowlist
            (rescue/app_fixes.json). Findings of a listed module that ran
            cleanly get a "fixable" object so the app can offer a fix.
        app_actions: Optional "actions" section of rescue/app_fixes.json. A
            warning/critical finding from a listed module whose data names a
            valid user LaunchAgent gets a per-finding action "fixable".
        made_by: Optional {id(finding): [maker entry]} from rescue.attribution;
            attached to each finding as "made_by".

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
            "findings": [
                _finding(
                    f, walkthroughs, offer, made_by,
                    None if check.error else _action_fixable(f, mod.name, app_actions),
                )
                for f in check.findings
            ],
        })
    return json.dumps(
        {"schema_version": 1, "platform": platform, "modules": modules},
        indent=2,
    )
