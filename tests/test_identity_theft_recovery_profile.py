import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.guides import discover_guides
from rescue.profiles import (
    discover_profiles,
    filter_modules_by_profile,
    load_profile,
    validate_profile_modules,
)
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent
PROFILE_PATH = PROJECT_ROOT / "profiles" / "identity_theft_recovery.yaml"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"


def _guides():
    return discover_guides(GUIDES_DIR, "identity_theft_recovery")


def test_profile_loads_and_is_discovered():
    profiles = discover_profiles(PROJECT_ROOT / "profiles")
    assert "identity_theft_recovery" in profiles

    profile = load_profile(PROFILE_PATH)
    assert profile.display_name == "Identity Theft Recovery"
    assert profile.guides == ["identity_theft_recovery"]


def test_every_referenced_module_exists():
    profile = load_profile(PROFILE_PATH)
    validate_profile_modules(profile, discover_modules(MODULES_DIR))


def test_profile_answers_whether_the_device_is_leaking_credentials():
    profile = load_profile(PROFILE_PATH)
    matched = {
        m.name for m in filter_modules_by_profile(discover_modules(MODULES_DIR), profile)
    }
    assert {"keylogger_indicators", "stalkerware_scan"} <= matched
    assert {"browser_extension_audit", "certificate_trust_audit"} <= matched
    assert {"remote_login_check", "win_remote_access_audit"} <= matched


def test_guide_has_six_phases_in_order():
    assert [g.phase for g in _guides()] == [0, 1, 2, 3, 4, 5]


def test_recovery_runs_in_the_order_that_makes_it_work():
    titles = {g.phase: g.title for g in _guides()}
    # Freezing comes before reporting, reporting before disputing: a dispute
    # without an identity theft report gets a form-letter reply.
    assert "Freeze" in titles[2]
    assert "Report" in titles[3]
    assert "Dispute" in titles[4]


def test_only_the_device_phase_is_automatable():
    for guide in _guides():
        if guide.phase == 1:
            assert guide.automatable_steps
        else:
            assert guide.automatable_steps == [], (
                f"phase {guide.phase} claims automation the toolkit cannot deliver"
            )


def test_every_step_is_classified_exactly_once():
    for guide in _guides():
        classified = set(guide.automatable_steps) | set(guide.human_only_steps)
        assert classified == {step.number for step in guide.steps}
        assert not set(guide.automatable_steps) & set(guide.human_only_steps)


def test_automatable_steps_name_modules_the_profile_includes():
    profile = load_profile(PROFILE_PATH)
    available = {
        m.name for m in filter_modules_by_profile(discover_modules(MODULES_DIR), profile)
    }

    referenced = set()
    for guide in _guides():
        for step in guide.steps:
            if step.automatable:
                referenced |= {name for name in available if name in step.body}

    assert referenced, "automatable steps should name the modules they run"
    assert referenced <= available


def test_step_titles_stand_alone_as_a_checklist():
    """The CLI prints titles only, so a title has to be actionable by itself."""
    for guide in _guides():
        for step in guide.steps:
            assert len(step.title) >= 15
            assert step.body.strip(), f"phase {guide.phase} step {step.number} has no detail"


def test_guide_covers_the_reporting_channels_people_miss():
    body = "\n".join(step.body for guide in _guides() for step in guide.steps).lower()
    for expected in (
        "identitytheft.gov",       # the FTC report that unlocks the legal rights
        "police report",
        "annualcreditreport.com",  # the free source, not a paid lookalike
        "identity protection pin",  # tax refund fraud
        "oig.ssa.gov",             # SSN misuse
        "optoutprescreen.com",     # prescreened offers feed the fraud
    ):
        assert expected in body, f"guide should mention {expected}"


def test_guide_points_outside_the_us():
    body = "\n".join(step.body for guide in _guides() for step in guide.steps).lower()
    for expected in ("action fraud", "cifas", "anti-fraud centre", "idcare"):
        assert expected in body
