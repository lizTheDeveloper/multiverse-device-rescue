"""Several profiles at once: the checkup runs every module any of them selects."""

import itertools
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rescue import cli as cli_mod
from rescue.models import Platform, SystemProfile
from rescue.profiles import Profile, ProfileValidationError, discover_profiles, merge_profiles
from rescue.registry import discover_modules

ROOT = Path(__file__).parent.parent
NAMES = ["a_mod", "b_mod", "c_mod", "d_mod"]


def P(name, include=(), exclude=(), config=None):
    return Profile(name=name, display_name=name.title(), description="",
                   include_modules=list(include), exclude_modules=list(exclude), module_config=config or {})


def test_union_of_the_modules_each_profile_selects_in_module_order():
    merged = merge_profiles([P("one", ["c_mod", "a_mod"]), P("two", ["b_mod", "a_mod"])], NAMES)
    assert merged.include_modules == ["a_mod", "b_mod", "c_mod"]
    assert merged.name == "one+two" and merged.exclude_modules == []


def test_a_profile_with_no_include_list_selects_everything_but_its_excludes():
    merged = merge_profiles([P("all", exclude=["d_mod"]), P("one", ["a_mod"])], NAMES)
    assert merged.include_modules == ["a_mod", "b_mod", "c_mod"]
    merged = merge_profiles([P("all", exclude=["d_mod"]), P("dee", ["d_mod"])], NAMES)
    assert merged.include_modules == NAMES


def test_settings_are_kept_and_a_conflict_is_refused():
    merged = merge_profiles([
        P("one", ["a_mod"], config={"a_mod": {"sensitivity": "elevated"}}),
        P("two", ["b_mod"], config={"b_mod": {"x": 1}}),
    ], NAMES)
    assert merged.module_config == {"a_mod": {"sensitivity": "elevated"}, "b_mod": {"x": 1}}
    with pytest.raises(ProfileValidationError, match="differently"):
        merge_profiles([
            P("one", ["a_mod"], config={"a_mod": {"sensitivity": "elevated"}}),
            P("two", ["a_mod"], config={"a_mod": {"sensitivity": "normal"}}),
        ], NAMES)


def test_no_profiles_is_refused():
    with pytest.raises(ProfileValidationError):
        merge_profiles([], NAMES)


def test_every_pair_of_shipped_profiles_can_run_together():
    profiles = discover_profiles(ROOT / "profiles")
    names = [m.name for m in discover_modules(ROOT / "modules")]
    for a, b in itertools.combinations(sorted(profiles), 2):
        merged = merge_profiles([profiles[a], profiles[b]], names)
        assert set(merged.include_modules) >= set(profiles[a].include_modules) | set(profiles[b].include_modules)


def _system():
    return SystemProfile(platform=Platform.DARWIN, os_name="macOS", os_version="15.0", architecture="arm64",
                         cpu_model="Test CPU", cpu_cores=4, ram_bytes=8 * 1024**3, hostname="test-host")


def _run(args):
    seen = {}

    class FakeOrchestrator:
        def __init__(self, modules_dir=None, profile=None):
            seen["profile"] = profile

        def run_checks(self, on_progress=None):
            return []

    with patch.object(cli_mod, "_run_startup_integrity_check"), \
         patch.object(cli_mod, "gather_profile", return_value=_system()), \
         patch.object(cli_mod, "Orchestrator", FakeOrchestrator):
        result = CliRunner().invoke(cli_mod.main, args)
    return result, seen.get("profile")


def test_scan_with_two_profiles_runs_their_union():
    r, prof = _run(["scan", "--json", "--profile", "digital_security_reset", "--profile", "home_network_intrusion"])
    assert r.exit_code == 0, r.output
    profiles = discover_profiles(ROOT / "profiles")
    want = set(profiles["digital_security_reset"].include_modules) | set(profiles["home_network_intrusion"].include_modules)
    assert set(prof.include_modules) == want
    assert prof.name == "digital_security_reset+home_network_intrusion"


def test_one_profile_is_unchanged_and_profile_with_module_is_still_refused():
    r, prof = _run(["scan", "--json", "--profile", "digital_security_reset"])
    assert r.exit_code == 0 and prof.name == "digital_security_reset"
    r, _ = _run(["scan", "--json", "--profile", "digital_security_reset", "--module", "disk_space"])
    assert r.exit_code == 2


def test_an_unknown_profile_among_several_exits_1():
    r, _ = _run(["scan", "--json", "--profile", "digital_security_reset", "--profile", "nope"])
    assert r.exit_code == 1


def test_export_names_both_profiles():
    r, _ = _run(["export", "--stdout", "--profile", "digital_security_reset", "--profile", "identity_theft_recovery"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["rescue_profile"] == "digital_security_reset+identity_theft_recovery"
