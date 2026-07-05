from pathlib import Path

from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.registry import filter_by_platform, topological_sort, discover_modules


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    depends_on = []

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN, Platform.LINUX]
    depends_on = ["mod_a"]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModC(ModuleBase):
    name = "mod_c"
    category = "test"
    platforms = [Platform.WIN32]
    depends_on = []

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_filter_by_platform_darwin():
    modules = [ModA(), ModB(), ModC()]
    result = filter_by_platform(modules, Platform.DARWIN)
    names = [m.name for m in result]
    assert "mod_a" in names
    assert "mod_b" in names
    assert "mod_c" not in names


def test_filter_by_platform_win32():
    modules = [ModA(), ModB(), ModC()]
    result = filter_by_platform(modules, Platform.WIN32)
    names = [m.name for m in result]
    assert names == ["mod_c"]


def test_topological_sort_respects_dependencies():
    modules = [ModB(), ModA()]  # B depends on A, given in wrong order
    sorted_mods = topological_sort(modules)
    names = [m.name for m in sorted_mods]
    assert names.index("mod_a") < names.index("mod_b")


def test_topological_sort_no_dependencies():
    modules = [ModA(), ModC()]
    sorted_mods = topological_sort(modules)
    assert len(sorted_mods) == 2


def test_topological_sort_missing_dependency():
    """Modules with dependencies not in the list still appear in output."""
    sorted_mods = topological_sort([ModB()])
    assert len(sorted_mods) == 1
    assert sorted_mods[0].name == "mod_b"


def test_discover_modules(tmp_path):
    # Create a fake module directory structure
    mod_dir = tmp_path / "modules" / "test_cat" / "fake_mod"
    mod_dir.mkdir(parents=True)
    init_file = mod_dir / "__init__.py"
    init_file.write_text('''
from rescue.module_base import ModuleBase
from rescue.models import Platform, CheckResult, FixResult

class Module(ModuleBase):
    name = "fake_mod"
    category = "test_cat"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)
''')

    modules = discover_modules(tmp_path / "modules")
    assert len(modules) == 1
    assert modules[0].name == "fake_mod"
