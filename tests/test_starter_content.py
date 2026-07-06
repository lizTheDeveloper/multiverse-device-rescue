from pathlib import Path

from rescue.guides import discover_guides
from rescue.profiles import discover_profiles, filter_modules_by_profile
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"


def test_starter_profiles_discovered():
    profiles = discover_profiles(PROFILES_DIR)
    assert "digital_security_reset" in profiles
    assert "home_for_the_holidays" in profiles


def test_digital_security_reset_profile_fields():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["digital_security_reset"]
    assert profile.display_name == "Digital Security Reset"
    assert profile.guides == ["digital_security_reset"]
    assert "password_manager_check" in profile.include_modules


def test_home_for_the_holidays_profile_fields():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["home_for_the_holidays"]
    assert profile.display_name == "Home for the Holidays"
    assert profile.guides == ["home_for_the_holidays"]
    assert "disk_space" in profile.include_modules


def test_home_for_the_holidays_profile_matches_real_disk_space_module():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["home_for_the_holidays"]
    modules = discover_modules(MODULES_DIR)

    matched = filter_modules_by_profile(modules, profile)

    names = [m.name for m in matched]
    assert names == ["disk_space"]


def test_digital_security_reset_guides_all_six_phases():
    guides = discover_guides(GUIDES_DIR, "digital_security_reset")
    assert [g.phase for g in guides] == [0, 1, 2, 3, 4, 5]


def test_digital_security_reset_phase_3_matches_design_spec_example():
    guides = discover_guides(GUIDES_DIR, "digital_security_reset")
    phase_3 = next(g for g in guides if g.phase == 3)

    assert phase_3.title == "Systematic Cleanup"
    assert phase_3.automatable_steps == [1, 2, 5]
    assert phase_3.human_only_steps == [3, 4, 6]
    assert phase_3.steps[0].title == "Reset your primary email password"


def test_home_for_the_holidays_guide_thirteen_steps():
    guides = discover_guides(GUIDES_DIR, "home_for_the_holidays")
    assert len(guides) == 1
    checklist = guides[0]
    assert len(checklist.steps) == 13
    assert len(checklist.automatable_steps) + len(checklist.human_only_steps) == 13
