"""Threat -> remediation map: load, validate, and (Task 2) render.

A threat maps a curriculum-described threat type to what to RUN in the tool
(a profile, explicit modules, or a full scan), the finding-code clusters it
covers, and the curriculum write-up that explains it. The validation gate
guarantees the run target actually scans the modules owning the threat's codes.
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class RunTarget:
    profile: str | None = None
    modules: list[str] = field(default_factory=list)
    full: bool = False


@dataclass
class Threat:
    id: str
    title: str
    summary: str
    run: RunTarget
    codes: list[str] = field(default_factory=list)
    curriculum_url: str = ""
    curriculum_section: str = ""


def load_threat_map(path: Path) -> list[Threat]:
    data = yaml.safe_load(path.read_text()) or {}
    threats: list[Threat] = []
    for t in data.get("threats", []) or []:
        run = t.get("run", {}) or {}
        threats.append(Threat(
            id=(t.get("id") or "").strip(),
            title=(t.get("title") or "").strip(),
            summary=(t.get("summary") or "").strip(),
            run=RunTarget(
                profile=run.get("profile"),
                modules=list(run.get("modules", []) or []),
                full=bool(run.get("full", False)),
            ),
            codes=list(t.get("codes", []) or []),
            curriculum_url=(t.get("curriculum_url") or "").strip(),
            curriculum_section=(t.get("curriculum_section") or "").strip(),
        ))
    return threats


def expand_codes(patterns, all_codes) -> set[str]:
    all_codes = set(all_codes)
    out: set[str] = set()
    for p in patterns:
        if p in all_codes:
            out.add(p)
        elif any(ch in p for ch in "*?["):
            out |= {c for c in all_codes if fnmatch.fnmatch(c, p)}
    return out


def modules_for_codes(codes) -> set[str]:
    return {c.split(".")[1] for c in codes if c.count(".") >= 2}


def run_target_modules(run: RunTarget, profiles) -> set[str] | None:
    if run.full:
        return None
    if run.profile is not None:
        return set(profiles.get(run.profile, set()))
    return set(run.modules)


def _target_count(run: RunTarget) -> int:
    return sum([run.profile is not None, bool(run.modules), bool(run.full)])


def validate_threat_map(threats, profiles, all_codes, all_modules) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for t in threats:
        where = f"threat '{t.id or '<no id>'}'"
        if not t.id:
            errors.append(f"{where}: missing id")
        elif t.id in seen:
            errors.append(f"{where}: duplicate id")
        else:
            seen.add(t.id)
        for fld in ("title", "summary", "curriculum_url"):
            if not getattr(t, fld):
                errors.append(f"{where}: missing {fld}")
        n = _target_count(t.run)
        if n != 1:
            errors.append(f"{where}: run must have exactly one of profile/modules/full (found {n})")
        else:
            if t.run.profile is not None and t.run.profile not in profiles:
                errors.append(f"{where}: unknown profile '{t.run.profile}'")
            for m in t.run.modules:
                if m not in all_modules:
                    errors.append(f"{where}: unknown module '{m}'")
        resolved: set[str] = set()
        for p in t.codes:
            got = expand_codes([p], all_codes)
            if not got:
                errors.append(f"{where}: code pattern '{p}' matches no real code")
            resolved |= got
        target = run_target_modules(t.run, profiles)
        if target is not None:  # not a full scan
            missing = modules_for_codes(resolved) - target
            if missing:
                errors.append(
                    f"{where}: run target does not scan module(s) owning its codes: {sorted(missing)}")
    return errors
