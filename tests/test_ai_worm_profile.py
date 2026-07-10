import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Platform
from rescue.registry import discover_modules, filter_by_platform
from rescue.profiles import load_profile, filter_modules_by_profile


def test_profile_loads():
    """ai_worm_response profile loads without errors."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)
    assert profile.name == "ai_worm_response"
    assert profile.display_name == "AI Worm & Spyware Response"


def test_profile_includes_all_modules():
    """Profile includes all six AI worm detection modules."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert set(profile.include_modules) == expected


def test_profile_filters_modules():
    """Profile correctly filters discovered modules to only the AI worm pack."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    modules_dir = Path(__file__).parent.parent / "modules"
    all_modules = discover_modules(modules_dir)
    filtered = filter_modules_by_profile(all_modules, profile)

    filtered_names = {m.name for m in filtered}
    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert filtered_names == expected


def test_all_modules_discoverable():
    """All six modules are discovered by the registry."""
    modules_dir = Path(__file__).parent.parent / "modules"
    all_modules = discover_modules(modules_dir)
    module_names = {m.name for m in all_modules}

    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert expected.issubset(module_names)


def test_module_config_sensitivity():
    """Profile provides sensitivity config for AI worm modules."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    for module_name in [
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
    ]:
        assert module_name in profile.module_config
        assert profile.module_config[module_name]["sensitivity"] == "elevated"
