import importlib.util
import sys
from pathlib import Path

from rescue.models import Platform
from rescue.module_base import ModuleBase


def discover_modules(modules_dir: Path) -> list[ModuleBase]:
    modules = []
    if not modules_dir.is_dir():
        return modules

    for category_dir in sorted(modules_dir.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for module_dir in sorted(category_dir.iterdir()):
            if not module_dir.is_dir() or module_dir.name.startswith("_"):
                continue
            init_file = module_dir / "__init__.py"
            if not init_file.exists():
                continue
            mod = _load_module(init_file, module_dir.name)
            if mod is not None:
                modules.append(mod)
    return modules


def _load_module(init_file: Path, module_name: str) -> ModuleBase | None:
    spec = importlib.util.spec_from_file_location(
        f"rescue_modules.{module_name}", init_file
    )
    if spec is None or spec.loader is None:
        return None
    py_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = py_module
    spec.loader.exec_module(py_module)
    module_class = getattr(py_module, "Module", None)
    if module_class is None or not (
        isinstance(module_class, type) and issubclass(module_class, ModuleBase)
    ):
        return None
    return module_class()


def filter_by_platform(
    modules: list[ModuleBase], platform: Platform
) -> list[ModuleBase]:
    return [m for m in modules if platform in m.platforms]


def topological_sort(modules: list[ModuleBase]) -> list[ModuleBase]:
    by_name = {m.name: m for m in modules}
    visited: set[str] = set()
    result: list[ModuleBase] = []

    def visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        mod = by_name.get(name)
        if mod is None:
            return
        for dep in mod.depends_on:
            visit(dep)
        result.append(mod)

    for m in modules:
        visit(m.name)
    return result
