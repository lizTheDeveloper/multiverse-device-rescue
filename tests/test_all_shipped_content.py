"""Whole-catalog validation of every shipped profile and guide.

This is the profile-validation gate the roadmap requires (P0#8 / Phase 0 item 9):
it fails if any shipped profile references a module that is not registered, or a
guide that does not exist, or if any guide's automatable/human-only step lists do
not partition its actual steps. Adding a broken profile or guide breaks CI here.
"""

from pathlib import Path

import pytest

from rescue.guides import discover_guides
from rescue.profiles import (
    discover_profiles,
    validate_profile_modules,
)
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"

_ALL_PROFILES = discover_profiles(PROFILES_DIR)
_ALL_MODULES = discover_modules(MODULES_DIR)


def test_there_are_shipped_profiles():
    assert _ALL_PROFILES, "no profiles discovered under profiles/"


@pytest.mark.parametrize("profile_name", sorted(_ALL_PROFILES))
def test_shipped_profile_modules_all_registered(profile_name):
    profile = _ALL_PROFILES[profile_name]
    # Raises ProfileValidationError listing any unregistered module references.
    validate_profile_modules(profile, _ALL_MODULES)


@pytest.mark.parametrize("profile_name", sorted(_ALL_PROFILES))
def test_shipped_profile_guides_exist_and_are_non_empty(profile_name):
    profile = _ALL_PROFILES[profile_name]
    for guide_name in profile.guides:
        guide_dir = GUIDES_DIR / guide_name
        assert guide_dir.is_dir(), (
            f"Profile '{profile_name}' references guide '{guide_name}' "
            f"but {guide_dir} does not exist"
        )
        guides = discover_guides(GUIDES_DIR, guide_name)
        assert guides, f"Guide '{guide_name}' has no phases/steps"


@pytest.mark.parametrize("profile_name", sorted(_ALL_PROFILES))
def test_shipped_guides_step_lists_partition_actual_steps(profile_name):
    profile = _ALL_PROFILES[profile_name]
    for guide_name in profile.guides:
        for guide in discover_guides(GUIDES_DIR, guide_name):
            actual_steps = {step.number for step in guide.steps}
            classified = set(guide.automatable_steps) | set(guide.human_only_steps)
            # Every classified step number must be a real step.
            dangling = classified - actual_steps
            assert not dangling, (
                f"{guide_name} phase {guide.phase}: step list references "
                f"non-existent steps {sorted(dangling)}"
            )
            # Every real step must be classified as automatable or human-only.
            unclassified = actual_steps - classified
            assert not unclassified, (
                f"{guide_name} phase {guide.phase}: steps {sorted(unclassified)} "
                f"are neither automatable nor human-only"
            )
            # A step cannot be both.
            overlap = set(guide.automatable_steps) & set(guide.human_only_steps)
            assert not overlap, (
                f"{guide_name} phase {guide.phase}: steps {sorted(overlap)} "
                f"are marked both automatable and human-only"
            )
