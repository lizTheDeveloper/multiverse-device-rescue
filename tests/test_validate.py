"""Tests for the catalog validator (roadmap P1#3).

The validator is a safety gate, so the tests care about two things: that it
catches the inconsistencies it exists to catch, and that it never raises on
malformed input — a validator that crashes on a broken catalog tells the user
nothing about what is broken.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import CheckResult, FixResult, Mode, Platform, RiskLevel, SystemProfile
from rescue.module_base import ModuleBase
from rescue.validate import (
    Severity,
    validate_catalog,
    validate_guides,
    validate_modules,
    validate_profiles,
)

REPO_ROOT = Path(__file__).parent.parent


class _Stub(ModuleBase):
    """A minimal, well-formed module used as the baseline for each case."""

    name = "stub"
    category = "performance"
    platforms = [Platform.LINUX]
    estimated_duration = "1s"

    def check(self, profile: SystemProfile) -> CheckResult:
        return CheckResult(module_name=self.name)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        return FixResult(module_name=self.name)


def _module(name: str, **attrs) -> ModuleBase:
    namespace = {"name": name, **attrs}
    return type(f"Module_{name}", (_Stub,), namespace)()


def _messages(problems, severity=None):
    return [
        p.message
        for p in problems
        if severity is None or p.severity is severity
    ]


def test_duplicate_module_names_are_an_error():
    problems = validate_modules([_module("dupe"), _module("dupe")])
    assert any("must be unique" in m for m in _messages(problems, Severity.ERROR))


def test_missing_dependency_is_an_error():
    problems = validate_modules([_module("a", depends_on=["nope"])])
    assert any("which no module provides" in m for m in _messages(problems, Severity.ERROR))


def test_satisfied_dependency_is_not_an_error():
    problems = validate_modules([_module("a", depends_on=["b"]), _module("b")])
    assert not [p for p in problems if p.severity is Severity.ERROR]


def test_dependency_cycle_is_reported_once():
    modules = [
        _module("a", depends_on=["b"]),
        _module("b", depends_on=["c"]),
        _module("c", depends_on=["a"]),
    ]
    cycles = [p for p in validate_modules(modules) if "dependency cycle" in p.message]
    # Reachable from three entry points, but it is one cycle and should be
    # reported as one problem.
    assert len(cycles) == 1
    assert "a -> b -> c -> a" in cycles[0].message


def test_self_dependency_is_an_error():
    problems = validate_modules([_module("a", depends_on=["a"])])
    assert any("depends on itself" in m for m in _messages(problems, Severity.ERROR))


def test_module_with_no_platforms_is_an_error():
    problems = validate_modules([_module("a", platforms=[])])
    assert any("declares no platforms" in m for m in _messages(problems, Severity.ERROR))


def test_auto_apply_on_a_non_safe_module_is_an_error():
    """Unattended mutation is the one thing that must never be misdeclared."""
    problems = validate_modules(
        [_module("a", auto_apply=True, risk_level=RiskLevel.DESTRUCTIVE)]
    )
    assert any("unattended mutation" in m for m in _messages(problems, Severity.ERROR))


def test_auto_apply_on_a_safe_module_is_allowed():
    problems = validate_modules([_module("a", auto_apply=True, risk_level=RiskLevel.SAFE)])
    assert not [p for p in problems if p.severity is Severity.ERROR]


def test_out_of_range_priority_is_an_error():
    problems = validate_modules([_module("a", priority=500)])
    assert any("outside 0-100" in m for m in _messages(problems, Severity.ERROR))


def test_unknown_duration_is_a_warning_not_an_error():
    problems = validate_modules([_module("a", estimated_duration="unknown")])
    assert any("estimated_duration" in m for m in _messages(problems, Severity.WARNING))
    assert not [p for p in problems if p.severity is Severity.ERROR]


def test_profile_referencing_a_missing_module_is_an_error(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "p.yaml").write_text(
        "name: p\ndescription: test\nmodules:\n  include:\n    - ghost\n"
    )
    problems = validate_profiles(profiles, [_module("real")], tmp_path / "guides")
    assert any("does not exist" in m for m in _messages(problems, Severity.ERROR))


def test_profile_selecting_nothing_is_an_error(tmp_path):
    """A profile that runs no modules looks like it works and does nothing."""
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "p.yaml").write_text(
        "name: p\ndescription: test\nmodules:\n  include:\n    - real\n  exclude:\n    - real\n"
    )
    problems = validate_profiles(profiles, [_module("real")], tmp_path / "guides")
    assert any("selects no modules" in m for m in _messages(problems, Severity.ERROR))


def test_malformed_profile_yaml_does_not_raise(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "broken.yaml").write_text("name: [unclosed\n")
    problems = validate_profiles(profiles, [], tmp_path / "guides")
    assert any(p.severity is Severity.ERROR for p in problems)


def test_guide_marking_a_nonexistent_step_automatable_is_an_error(tmp_path):
    guides = tmp_path / "guides" / "demo"
    guides.mkdir(parents=True)
    (guides / "phase_0.md").write_text(
        "---\nprofile: demo\nphase: 0\ntitle: Demo\nautomatable_steps: [1, 9]\n---\n\n"
        "## Step 1: Real step\n\nBody.\n"
    )
    problems = validate_guides(tmp_path / "guides", [_module("a")])
    assert any("no such step exists" in m for m in _messages(problems, Severity.ERROR))


def test_walkthrough_with_an_unknown_code_is_a_warning(tmp_path):
    remediation = tmp_path / "guides" / "remediation"
    remediation.mkdir(parents=True)
    (remediation / "w.md").write_text(
        "---\ntitle: Do the thing\nremediates:\n  - security.nothing.emits_this\n---\n\n"
        "## Step 1: Act\n\nBody.\n"
    )
    problems = validate_guides(tmp_path / "guides", [_module("a")])
    assert any("no module declares in emits_codes" in m for m in _messages(problems, Severity.WARNING))


def test_empty_registry_is_an_error(tmp_path):
    """Discovering nothing is the signature of a packaging failure (P0#1)."""
    report = validate_catalog(tmp_path / "modules", tmp_path / "profiles", tmp_path / "guides")
    assert not report.ok()
    assert any("missing its content" in p.message for p in report.errors)


def test_the_shipped_catalog_is_consistent():
    """The real catalog must validate clean. This is the CI gate."""
    report = validate_catalog(
        modules_dir=REPO_ROOT / "modules",
        profiles_dir=REPO_ROOT / "profiles",
        guides_dir=REPO_ROOT / "guides",
    )
    assert report.module_count > 0
    assert report.errors == [], "\n".join(p.format() for p in report.errors)


def _undocumented(name: str) -> ModuleBase:
    """A module with neither a class docstring nor a documented source file.

    `__module__` matters: a real shipped module's prose usually lives in the
    file-level docstring of its `__init__.py`, so the validator looks there as
    well as at the class. Pointing it at a name that is not in sys.modules is
    how a test double gets to be genuinely undocumented.
    """
    return type(f"Module_{name}", (_Stub,), {"name": name, "__module__": "not_a_real_module"})()


def test_undocumented_modules_produce_one_warning_not_hundreds():
    """A per-module warning would bury the actionable problems in a backlog."""
    modules = [_undocumented(f"m{i}") for i in range(10)]
    warnings = [
        p for p in validate_modules(modules)
        if p.severity is Severity.WARNING and "docstring" in p.message
    ]
    assert len(warnings) == 1
    assert "10 of 10 modules" in warnings[0].message


def test_documented_modules_produce_no_documentation_warning():
    class _Documented(_Stub):
        """This module explains itself."""

        name = "documented"

    problems = validate_modules([_Documented()])
    assert not [p for p in problems if "docstring" in p.message]


def test_the_shipped_catalog_has_no_errors_only_the_documentation_backlog():
    """`rescue validate` (no --strict) is the CI gate, so it must exit clean."""
    report = validate_catalog(
        modules_dir=REPO_ROOT / "modules",
        profiles_dir=REPO_ROOT / "profiles",
        guides_dir=REPO_ROOT / "guides",
    )
    assert report.ok(strict=False), "\n".join(p.format() for p in report.errors)


def test_documentation_check_does_not_credit_nonetype_for_a_missing_module():
    """Regression: `getattr(None, "__doc__", "")` is not the default on 3.13.

    It returns NoneType's own docstring — empty on 3.11 and 3.12, and "The type
    of the None singleton." on 3.13. Written the obvious way, a module whose
    containing module is not in sys.modules counted as documented on one Python
    version and not the others.
    """
    from rescue.validate import _has_documentation

    assert not _has_documentation(_undocumented("ghost"))


def test_documentation_check_does_not_inherit_credit_from_a_base_class():
    """_Stub has a docstring; a subclass without one is still undocumented."""
    from rescue.validate import _has_documentation

    assert not _has_documentation(_undocumented("child"))
