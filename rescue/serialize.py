from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from rescue.check_names import check_name, error_kind
from rescue.same_finding import same_key
from rescue.wording import tidy


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

    try:
        hit = offer_target(getattr(finding, "data", None), severity, module_name)
    except Exception:
        return None  # an odd data shape gets no fix offer, never a crash
    if hit is None:
        return None
    return {
        "action": "disable_launch_agent",
        "target": hit["target"],
        "will_change": spec["will_change"].replace("{label}", hit["label"]),
        "how_to_undo": list(spec["how_to_undo"]),
    }


def _markable(finding, module_name):
    """A `markable` block ("It's mine") for an eligible finding, or None."""
    from rescue.known_items import markable

    try:
        return markable(finding, module_name)
    except Exception:
        return None


def _link_task_marks(modules) -> None:
    """One background task reported by several checks is marked (and unmarked) as one."""
    from rescue.known_items import link_task_marks

    try:
        link_task_marks([f for m in modules for f in m["findings"]])
    except Exception:
        pass


def _makers_verified(entries, data) -> bool:
    """True when every program the finding names has a maker that was verified:
    each made_by entry is verified and, when the finding lists apps, each app
    has one. Lets a screen tell familiar, verified apps from look-alikes."""
    if not entries or not all(isinstance(e, dict) and e.get("verified") is True for e in entries):
        return False
    apps = data.get("apps") if isinstance(data, dict) else None
    if isinstance(apps, list):
        subjects = {e.get("subject") for e in entries if isinstance(e.get("subject"), str)}
        # Each app is matched only by the subject attribution actually looked
        # up for it, never by a name it reports about itself.
        return all((s := _app_subject(a)) is not None and s in subjects for a in apps)
    return True


def _app_subject(app) -> str | None:
    """The one string attribution identifies an app in "apps" by: the app
    itself when it is a string, else its path (rescue.attribution._candidates,
    first entry) for a {path, name} dict. A self-reported name, bundle id or
    "app" field never counts: a process can call itself anything."""
    if isinstance(app, str):
        return app
    if isinstance(app, dict):
        from rescue.attribution import _candidates

        found = _candidates(app)
        return found[0] if found else None
    return None


def _items_made_by(markable, made_by) -> None:
    """Each entry of a "mark entries" list gets the made_by entry looked up for
    it (matched by its key, the bundle id or path attribution was given), so
    the list and the evidence name the same maker for the same app."""
    items = markable.get("items") if isinstance(markable, dict) else None
    if not isinstance(items, list):
        return
    by_subject = {e.get("subject"): e for e in made_by if isinstance(e, dict) and isinstance(e.get("subject"), str)}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("key"), str) and item["key"] in by_subject:
            item["made_by"] = by_subject[item["key"]]


def _dedupe(findings: list) -> list:
    """One entry per identical finding: a check that reported the same thing
    twice (the same login item listed twice, one program seen as four
    processes) keeps one, with "repeats" saying how many times it was seen."""
    out, index = [], {}
    for f in findings:
        try:
            key = json.dumps(f, sort_keys=True)
        except (TypeError, ValueError):
            out.append(f)
            continue
        if key in index:
            kept = index[key]
            kept["repeats"] = kept.get("repeats", 1) + 1
            continue
        index[key] = f
        out.append(f)
    return out


def _finding(finding, walkthroughs, fixable=None, made_by=None, action_fixable=None, markable=None, module=None) -> dict:
    out = _plain(finding)
    # The same finding from another check gets the same key (rescue/same_finding.py).
    key = same_key(module, out) if module else None
    if key:
        out["same_key"] = key
    # Plurals that agree, "once", and plain days instead of ISO time stamps (rescue/wording.py).
    for key in ("title", "description"):
        out[key] = tidy(out.get(key))
    if markable is not None:
        out["markable"] = markable
    if action_fixable is not None:
        out["fixable"] = action_fixable
    elif fixable is not None:
        out["fixable"] = _fixable(fixable)
    entries = made_by.get(id(finding)) if made_by else None
    if entries:
        out["made_by"] = _plain(entries)
        out["makers_verified"] = _makers_verified(out["made_by"], out.get("data"))
        _items_made_by(out.get("markable"), out["made_by"])
    guide = walkthroughs.get(getattr(finding, "code", None)) if walkthroughs else None
    if guide is not None:
        out["remediation"] = _remediation(guide, getattr(finding, "code", None))
        # The safety note is for things worth acting on; informational
        # inventories would repeat it on every card.
        if getattr(getattr(finding, "severity", None), "value", None) == "info":
            out["remediation"].pop("safety_note", None)
    return out


def _safe_finding(finding, *args) -> tuple[dict, bool]:
    """``_finding``, or a minimal entry for a finding that could not be written
    (and False), so one odd finding never costs the person the whole checkup."""
    try:
        out = _finding(finding, *args)
        json.dumps(out)
        return out, True
    except Exception:
        out = {}
        for key in ("title", "description", "category", "code"):
            try:
                value = getattr(finding, key, None)
                out[key] = None if value is None else str(value)
            except Exception:
                out[key] = None
        severity = getattr(getattr(finding, "severity", None), "value", None)
        out["severity"] = severity if severity in ("critical", "warning", "info") else "warning"
        out["title"] = out["title"] or "A finding that couldn't be shown in full"
        out["description"] = out["description"] or ""
        out["data"] = {}
        out["serialize_error"] = True
        return out, False


# What a check's entry says when its results couldn't be written at all.
WRITE_FAILED = "This check's results couldn't be written out, so it may have missed something."


def safe_module_entry(mod, check, *args, **kwargs) -> dict:
    """``module_entry``, or a minimal "error" entry for a check whose results
    could not be serialized. Never raises: the rest of the document still gets
    written, and the failed check reads as not checked, never as clean."""
    try:
        entry = module_entry(mod, check, *args, **kwargs)
        json.dumps(entry)
        return entry
    except Exception:
        name = str(getattr(mod, "name", None) or getattr(check, "module_name", "") or "unknown")
        try:
            human = check_name(name)
        except Exception:
            human = name
        category = getattr(mod, "category", None)
        return {
            "name": name,
            "check_name": human,
            "category": category if isinstance(category, str) else None,
            "status": "error",
            "error": WRITE_FAILED,
            "supported": True,
            "unsupported_reason": None,
            "complete": False,
            "not_started": False,
            "error_kind": "error",
            "findings": [],
        }


def module_entry(mod, check, walkthroughs=None, app_fixes=None, made_by=None, app_actions=None) -> dict:
    """One entry of the "modules" array, for one finished check.

    ``checks_to_json`` builds the whole document from these; ``rescue scan
    --json --progress`` also streams each one on stderr as its check finishes.
    A streamed entry is built alone, so a "markable" block's "ids" cover only
    that module (the final document links them across modules).
    """
    entry = (app_fixes or {}).get(mod.name)
    offer = entry if entry is not None and not check.error and getattr(check, "supported", True) else None
    supported = getattr(check, "supported", True)
    complete = bool(getattr(check, "complete", True))
    not_started = getattr(check, "not_started", False) is True and not check.error and supported
    written = [
        _safe_finding(
            f, walkthroughs, offer, made_by,
            None if check.error else _action_fixable(f, mod.name, app_actions),
            None if check.error else _markable(f, mod.name),
            mod.name,
        )
        for f in check.findings
    ]
    if not all(ok for _, ok in written):
        complete = False  # a finding was cut down: what it held may be missing
    return {
        "name": mod.name,
        # The check's name for people, from one table (rescue/check_names.py).
        "check_name": check_name(mod.name),
        "category": getattr(mod, "category", None),
        "status": "error" if check.error else "ok",
        "error": check.error,
        # False means the check could not run here: not a clean result.
        "supported": getattr(check, "supported", True),
        "unsupported_reason": getattr(check, "unsupported_reason", None),
        # False means the check ran but didn't finish its job, so something it
        # didn't report may still be there: never read it as clean.
        "complete": complete,
        # What kind of "couldn't check" this was, or null when it ran:
        # timeout | permission | skipped | unsupported | error | unfinished.
        # True for an opt-in check that can run here but wasn't started (it
        # asks first): not "couldn't run", and not clean either.
        "not_started": not_started,
        "error_kind": error_kind(check.error, supported, complete, not_started),
        "findings": _dedupe([f for f, _ in written]),
    }


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

    A warning about a background task the person could mark as theirs gets a
    "markable" object (see rescue.known_items.markable), whose "ids" name every
    markable finding about the same task in this scan; a finding already marked
    gets "marked_ids" the same way (rescue.known_items.link_task_marks).

    Returns:
        JSON string with schema_version, platform, and modules array.
        Each module entry has name, check_name, category, status, error,
        supported, unsupported_reason, complete, error_kind, findings.
    """
    modules = [
        safe_module_entry(mod, check, walkthroughs, app_fixes, made_by, app_actions)
        for mod, check in results
    ]
    _link_task_marks(modules)
    return json.dumps(
        {"schema_version": 1, "platform": platform, "modules": modules},
        indent=2,
    )
