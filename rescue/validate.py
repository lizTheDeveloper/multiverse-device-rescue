"""Whole-catalog validation of everything the tool ships.

Roadmap P1#3 asks for registry metadata to be validated "at startup and in CI:
unique names, valid dependencies, no cycles, compatible platforms, risk
declaration, and actionable support documentation". This module is that check,
expressed as data rather than as assertions, so the same logic can back a test,
a CI gate, and the ``rescue validate`` command a user can run against their own
installation to confirm nothing is missing or mismatched.

The design rule here is that a validator must never be the thing that breaks a
rescue. Every check returns a :class:`Problem`; nothing raises, and nothing
executes a module's ``check()``. Discovery already imports module code (roadmap
P0#10 tracks fixing that), but validation adds no further execution.

Severities are meaningful:

``ERROR``
    The catalog is internally inconsistent — a profile names a module that does
    not exist, two modules claim the same name, dependencies form a cycle. A
    user hitting one of these gets silently reduced functionality, so CI fails.

``WARNING``
    Metadata that is legal but degrades the product: a module with no estimated
    duration, a mutating module with no remediation codes to explain itself.
    ``--strict`` promotes these to failures.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from rescue.guides import discover_guides
from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiles import discover_profiles
from rescue.registry import discover_modules

# A module that takes longer than this without saying so makes a scan look
# hung. Modules declare duration as free text ("5s", "2m"), so this is only
# used to flag the ones that declare nothing at all.
_UNKNOWN_DURATION = "unknown"


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Problem:
    severity: Severity
    scope: str
    subject: str
    message: str

    def format(self) -> str:
        return f"[{self.severity.value}] {self.scope}:{self.subject}: {self.message}"


@dataclass
class ValidationReport:
    problems: list[Problem] = field(default_factory=list)
    module_count: int = 0
    profile_count: int = 0
    guide_count: int = 0

    @property
    def errors(self) -> list[Problem]:
        return [p for p in self.problems if p.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Problem]:
        return [p for p in self.problems if p.severity is Severity.WARNING]

    def ok(self, strict: bool = False) -> bool:
        return not self.errors and (not strict or not self.warnings)


def _error(scope: str, subject: str, message: str) -> Problem:
    return Problem(Severity.ERROR, scope, subject, message)


def _warning(scope: str, subject: str, message: str) -> Problem:
    return Problem(Severity.WARNING, scope, subject, message)


def validate_modules(modules: list[ModuleBase]) -> list[Problem]:
    """Check the registry's own metadata for internal consistency."""
    problems: list[Problem] = []

    seen: dict[str, int] = {}
    for module in modules:
        seen[module.name] = seen.get(module.name, 0) + 1
    for name, count in sorted(seen.items()):
        if count > 1:
            # Two modules answering to one name means profiles, the threat map,
            # and `rescue run` all silently pick whichever loaded last.
            problems.append(
                _error("module", name, f"declared {count} times; module names must be unique")
            )

    available = set(seen)
    for module in modules:
        problems.extend(_validate_module_metadata(module, available))

    problems.extend(_validate_dependency_graph(modules))
    return problems


def _validate_module_metadata(module: ModuleBase, available: set[str]) -> list[Problem]:
    problems: list[Problem] = []
    name = module.name

    if not name or not isinstance(name, str):
        problems.append(_error("module", str(name), "name is missing or not a string"))
    if not module.category:
        problems.append(_error("module", name, "category is missing"))

    if not module.platforms:
        problems.append(
            _error("module", name, "declares no platforms, so it can never be selected")
        )
    for platform in module.platforms:
        if not isinstance(platform, Platform):
            problems.append(
                _error("module", name, f"platform {platform!r} is not a Platform member")
            )

    if not isinstance(module.risk_level, RiskLevel):
        problems.append(
            _error("module", name, f"risk_level {module.risk_level!r} is not a RiskLevel member")
        )

    for dep in module.depends_on:
        if dep not in available:
            problems.append(
                _error("module", name, f"depends on '{dep}', which no module provides")
            )
        if dep == name:
            problems.append(_error("module", name, "depends on itself"))

    if not isinstance(module.priority, int) or not 0 <= module.priority <= 100:
        problems.append(
            _error("module", name, f"priority {module.priority!r} is outside 0-100")
        )

    # auto_apply is the switch that lets unattended mode change a system. It is
    # only defensible on a SAFE module, so the combination is an error rather
    # than a style note.
    if module.auto_apply and module.risk_level is not RiskLevel.SAFE:
        problems.append(
            _error(
                "module",
                name,
                f"sets auto_apply=True at risk level {module.risk_level.value}; "
                "unattended mutation is only allowed for SAFE modules",
            )
        )

    if not module.estimated_duration or module.estimated_duration == _UNKNOWN_DURATION:
        problems.append(
            _warning("module", name, "declares no estimated_duration; scans cannot show progress honestly")
        )

    if not _has_documentation(module):
        problems.append(
            _warning("module", name, "has no docstring explaining what it checks or why")
        )

    return problems


def _has_documentation(module: ModuleBase) -> bool:
    """True if the module carries prose a reader could learn from.

    The convention in this tree is a file-level docstring at the top of the
    module's ``__init__.py`` (see ``code_signature_audit``), so look there as
    well as at the class. Either satisfies "actionable support documentation";
    requiring both would flag almost every module and make the signal useless.
    """
    if (type(module).__doc__ or "").strip():
        return True
    containing = sys.modules.get(type(module).__module__)
    return bool((getattr(containing, "__doc__", "") or "").strip())


def _validate_dependency_graph(modules: list[ModuleBase]) -> list[Problem]:
    """Report every dependency cycle exactly once, named by its smallest member.

    ``registry.topological_sort`` cannot loop forever — it marks nodes visited
    on entry — but it silently emits a cycle in an arbitrary order, so a cycle
    turns into a module running before the thing it depends on. Better to fail
    the catalog than to schedule it wrongly.
    """
    problems: list[Problem] = []
    by_name = {m.name: m for m in modules}
    state: dict[str, int] = {}  # 0 = unvisited, 1 = on stack, 2 = done
    reported: set[tuple[str, ...]] = set()
    stack: list[str] = []

    def visit(name: str) -> None:
        if state.get(name, 0) == 2:
            return
        if state.get(name, 0) == 1:
            cycle = stack[stack.index(name):]
            # Rotate to start at the alphabetically smallest member so the same
            # cycle reached from different entry points is reported once.
            pivot = cycle.index(min(cycle))
            key = tuple(cycle[pivot:] + cycle[:pivot])
            if key not in reported:
                reported.add(key)
                problems.append(
                    _error(
                        "module",
                        key[0],
                        "dependency cycle: " + " -> ".join(key + (key[0],)),
                    )
                )
            return
        state[name] = 1
        stack.append(name)
        module = by_name.get(name)
        if module is not None:
            for dep in module.depends_on:
                if dep in by_name:
                    visit(dep)
        stack.pop()
        state[name] = 2

    for module in sorted(modules, key=lambda m: m.name):
        visit(module.name)
    return problems


def validate_profiles(profiles_dir: Path, modules: list[ModuleBase], guides_dir: Path) -> list[Problem]:
    """Every profile must select real modules and point at guides that exist."""
    problems: list[Problem] = []
    available = {m.name for m in modules}

    try:
        profiles = discover_profiles(profiles_dir)
    except Exception as exc:  # a malformed YAML file must not crash the tool
        return [_error("profile", str(profiles_dir), f"could not be loaded: {exc}")]

    for name, profile in sorted(profiles.items()):
        referenced = (
            set(profile.include_modules)
            | set(profile.exclude_modules)
            | set(profile.module_config)
        )
        for missing in sorted(referenced - available):
            problems.append(
                _error("profile", name, f"references module '{missing}', which does not exist")
            )

        if profile.include_modules:
            selected = [m for m in modules if m.name in set(profile.include_modules)]
            selected = [m for m in selected if m.name not in set(profile.exclude_modules)]
            if not selected:
                problems.append(
                    _error("profile", name, "selects no modules at all, so running it does nothing")
                )

        for guide_name in profile.guides:
            if not discover_guides(guides_dir, guide_name):
                problems.append(
                    _error("profile", name, f"names guide set '{guide_name}', which has no phases on disk")
                )

        if not profile.description:
            problems.append(_warning("profile", name, "has no description"))

    return problems


def validate_guides(guides_dir: Path, modules: list[ModuleBase]) -> list[Problem]:
    """A step may only be advertised as automatable if a module can do it.

    This is the roadmap's sequencing rule — "do not describe a guide step as
    automatable until it resolves to a registered module" — enforced instead of
    remembered.
    """
    problems: list[Problem] = []
    if not guides_dir.is_dir():
        return problems

    known_codes = {code for module in modules for code in module.emits_codes}

    for guide_set in sorted(p for p in guides_dir.iterdir() if p.is_dir()):
        if guide_set.name == "remediation":
            problems.extend(_validate_remediation_guides(guide_set, known_codes))
            continue
        for guide in discover_guides(guides_dir, guide_set.name):
            numbers = {step.number for step in guide.steps}
            for step_number in guide.automatable_steps:
                if step_number not in numbers:
                    problems.append(
                        _error(
                            "guide",
                            f"{guide_set.name}/phase_{guide.phase}",
                            f"marks step {step_number} automatable, but no such step exists",
                        )
                    )
            if not guide.title:
                problems.append(
                    _warning("guide", f"{guide_set.name}/phase_{guide.phase}", "has no title")
                )
    return problems


def _validate_remediation_guides(directory: Path, known_codes: set[str]) -> list[Problem]:
    """Remediation walkthroughs are keyed by finding code; orphans never show.

    A walkthrough whose `remediates:` code is emitted by no module is dead
    content: the TUI only offers it when a finding carries that code, so it can
    never be reached. That is a warning rather than an error because a code may
    legitimately be added ahead of the module that emits it.
    """
    problems: list[Problem] = []
    from rescue.guides import load_guide

    for path in sorted(directory.glob("*.md")):
        try:
            guide = load_guide(path)
        except Exception as exc:
            problems.append(_error("walkthrough", path.name, f"could not be parsed: {exc}"))
            continue
        if not guide.remediates:
            problems.append(
                _warning("walkthrough", path.name, "declares no 'remediates' codes, so nothing links to it")
            )
            continue
        for code in guide.remediates:
            if code not in known_codes:
                problems.append(
                    _warning(
                        "walkthrough",
                        path.name,
                        f"remediates '{code}', which no module declares in emits_codes",
                    )
                )
    return problems


def validate_catalog(
    modules_dir: Path,
    profiles_dir: Path,
    guides_dir: Path,
    modules: list[ModuleBase] | None = None,
) -> ValidationReport:
    """Validate the whole shipped catalog and return every problem found."""
    if modules is None:
        modules = discover_modules(modules_dir)

    report = ValidationReport(module_count=len(modules))
    report.problems.extend(validate_modules(modules))
    report.problems.extend(validate_profiles(profiles_dir, modules, guides_dir))
    report.problems.extend(validate_guides(guides_dir, modules))

    try:
        report.profile_count = len(discover_profiles(profiles_dir))
    except Exception:
        report.profile_count = 0
    if guides_dir.is_dir():
        report.guide_count = sum(1 for _ in guides_dir.glob("*/*.md"))

    if not modules:
        # Discovery finding nothing is the signature failure of a packaging bug
        # (roadmap P0#1): the tool installs, launches, and checks nothing.
        report.problems.append(
            _error("registry", str(modules_dir), "no modules were discovered; the install is missing its content")
        )
    return report
