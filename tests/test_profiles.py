from pathlib import Path

import pytest

from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiles import (
    Profile,
    ProfileValidationError,
    discover_profiles,
    filter_modules_by_profile,
    load_profile,
    validate_profile_modules,
)


PROFILE_YAML = """
name: test_profile
display_name: "Test Profile"
description: "A profile for testing."
modules:
  include:
    - mod_a
    - mod_b
  exclude:
    - mod_c
module_config:
  mod_a:
    sensitivity: elevated
guides:
  - test_profile
"""


def test_load_profile(tmp_path):
    profile_path = tmp_path / "test_profile.yaml"
    profile_path.write_text(PROFILE_YAML)

    profile = load_profile(profile_path)

    assert profile.name == "test_profile"
    assert profile.display_name == "Test Profile"
    assert profile.description == "A profile for testing."
    assert profile.include_modules == ["mod_a", "mod_b"]
    assert profile.exclude_modules == ["mod_c"]
    assert profile.module_config == {"mod_a": {"sensitivity": "elevated"}}
    assert profile.guides == ["test_profile"]


def test_load_profile_minimal(tmp_path):
    minimal_yaml = "name: minimal\n"
    profile_path = tmp_path / "minimal.yaml"
    profile_path.write_text(minimal_yaml)

    profile = load_profile(profile_path)

    assert profile.name == "minimal"
    assert profile.display_name == "minimal"
    assert profile.description == ""
    assert profile.include_modules == []
    assert profile.exclude_modules == []
    assert profile.module_config == {}
    assert profile.guides == []


def test_discover_profiles(tmp_path):
    (tmp_path / "a.yaml").write_text("name: profile_a\n")
    (tmp_path / "b.yaml").write_text("name: profile_b\n")
    (tmp_path / "not_a_profile.txt").write_text("ignore me")

    profiles = discover_profiles(tmp_path)

    assert set(profiles.keys()) == {"profile_a", "profile_b"}
    assert profiles["profile_a"].name == "profile_a"


def test_discover_profiles_missing_dir(tmp_path):
    missing = tmp_path / "does_not_exist"
    assert discover_profiles(missing) == {}


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModC(ModuleBase):
    name = "mod_c"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_filter_modules_by_profile_include_and_exclude():
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a", "mod_b", "mod_c"],
        exclude_modules=["mod_c"],
    )
    modules = [ModA(), ModB(), ModC()]

    result = filter_modules_by_profile(modules, profile)

    names = [m.name for m in result]
    assert names == ["mod_a", "mod_b"]


def test_filter_modules_by_profile_no_include_list_keeps_all():
    profile = Profile(name="test_profile", display_name="Test Profile", description="")
    modules = [ModA(), ModB(), ModC()]

    result = filter_modules_by_profile(modules, profile)

    assert len(result) == 3


def test_validate_profile_modules_rejects_missing_references():
    profile = Profile(
        name="invalid",
        display_name="Invalid",
        description="",
        include_modules=["mod_a", "missing"],
    )

    with pytest.raises(ProfileValidationError, match="missing"):
        validate_profile_modules(profile, [ModA()])
