from pathlib import Path
from unittest.mock import patch

from rescue.models import Platform, CheckResult, FixResult, RiskLevel, SystemProfile
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator
from rescue.profiles import Profile


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def __init__(self):
        self.configured_with = None

    def check(self, profile):
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)

    def configure(self, config):
        self.configured_with = config


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)


FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN,
    os_name="macOS",
    os_version="15.2",
    architecture="arm64",
    cpu_model="Apple M2",
    cpu_cores=8,
    ram_bytes=16 * 1024**3,
)


def test_run_checks_without_profile_runs_all_modules_and_skips_configure():
    mod_a, mod_b = ModA(), ModB()
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_checks()

    assert len(results) == 2
    assert mod_a.configured_with is None  # no profile means configure never called


def test_run_checks_with_profile_filters_and_configures():
    mod_a, mod_b = ModA(), ModB()
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a"],
        module_config={"mod_a": {"sensitivity": "elevated"}},
    )

    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"), profile=profile)
        results = orch.run_checks()

    names = [mod.name for mod, _ in results]
    assert names == ["mod_a"]
    assert mod_a.configured_with == {"sensitivity": "elevated"}


def test_run_checks_with_profile_no_config_for_module_gets_empty_dict():
    mod_a = ModA()
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a"],
    )

    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"), profile=profile)
        orch.run_checks()

    assert mod_a.configured_with == {}
