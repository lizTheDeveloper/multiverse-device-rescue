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
PROFILE_PATH = PROJECT_ROOT / "profiles" / "home_network_intrusion.yaml"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"


def test_profile_loads():
    profile = load_profile(PROFILE_PATH)
    assert profile.name == "home_network_intrusion"
    assert profile.display_name == "Home Network Intrusion & Cryptojacking Response"
    assert profile.guides == ["home_network_intrusion"]


def test_profile_is_discovered_alongside_the_others():
    profiles = discover_profiles(PROJECT_ROOT / "profiles")
    assert "home_network_intrusion" in profiles


def test_every_referenced_module_exists():
    profile = load_profile(PROFILE_PATH)
    validate_profile_modules(profile, discover_modules(MODULES_DIR))


def test_profile_covers_network_cryptojacking_and_monitoring():
    profile = load_profile(PROFILE_PATH)
    matched = {m.name for m in filter_modules_by_profile(discover_modules(MODULES_DIR), profile)}

    # The network has to be reclaimable before the devices are cleaned.
    assert {"lan_device_inventory", "arp_spoof_check", "router_security_audit"} <= matched
    # Cryptojacking, including what restarts a miner after it is killed.
    assert {
        "crypto_miner_detect",
        "win_crypto_miner_detect",
        "crypto_miner_persistence",
        "browser_cryptojacking_check",
    } <= matched
    # Who else has access to the machine.
    assert {"stalkerware_scan", "remote_login_check"} <= matched


def test_guide_has_all_six_phases_in_order():
    guides = discover_guides(GUIDES_DIR, "home_network_intrusion")
    assert [g.phase for g in guides] == [0, 1, 2, 3, 4, 5]


def test_guide_ends_with_reachable_help():
    guides = discover_guides(GUIDES_DIR, "home_network_intrusion")
    resources = guides[-1]
    assert "Resources" in resources.title

    body = "\n".join(step.body for step in resources.steps).lower()
    # Abuse support comes first, because it changes the order of everything.
    assert "1-800-799-7233" in body
    assert "techsafety.org" in body
    assert "accessnow.org/help" in body
    assert "ic3.gov" in body
    # And the warning that makes the rest of the list safe to use.
    assert "gift card" in body


def test_guide_opens_with_the_safety_check_not_a_scan():
    guides = discover_guides(GUIDES_DIR, "home_network_intrusion")
    phase_0 = next(g for g in guides if g.phase == 0)
    assert phase_0.automatable_steps == []
    assert "safety" in phase_0.steps[0].title.lower()


def test_every_step_is_classified_as_automatable_or_human_only():
    for guide in discover_guides(GUIDES_DIR, "home_network_intrusion"):
        classified = set(guide.automatable_steps) | set(guide.human_only_steps)
        assert classified == {step.number for step in guide.steps}
        assert not set(guide.automatable_steps) & set(guide.human_only_steps)


def test_automatable_steps_reference_modules_the_profile_actually_includes():
    profile = load_profile(PROFILE_PATH)
    available = {m.name for m in filter_modules_by_profile(discover_modules(MODULES_DIR), profile)}

    referenced = set()
    for guide in discover_guides(GUIDES_DIR, "home_network_intrusion"):
        for step in guide.steps:
            if not step.automatable:
                continue
            for module_name in available:
                if module_name in step.body:
                    referenced.add(module_name)

    assert referenced, "automatable steps should name the modules they run"
    assert referenced <= available
