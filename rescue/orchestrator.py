from pathlib import Path

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.registry import discover_modules, filter_by_platform, topological_sort


class Orchestrator:
    def __init__(self, modules_dir: Path):
        self._modules_dir = modules_dir

    def run_checks(self) -> list[tuple[ModuleBase, CheckResult]]:
        profile = gather_profile()
        modules = discover_modules(self._modules_dir)
        modules = filter_by_platform(modules, profile.platform)
        modules = topological_sort(modules)

        results = []
        for mod in modules:
            check = mod.check(profile)
            results.append((mod, check))
        return results

    def run_fixes(
        self,
        check_results: list[tuple[ModuleBase, CheckResult]],
        mode: Mode,
    ) -> list[tuple[ModuleBase, CheckResult, FixResult]]:
        results = []
        for mod, check in check_results:
            if not check.has_issues:
                continue
            if mode == Mode.AUTO and mod.risk_level != RiskLevel.SAFE:
                continue
            fix = mod.fix(check, mode)
            results.append((mod, check, fix))
        return results

    def run_auto(
        self,
    ) -> list[tuple[ModuleBase, CheckResult, FixResult | None]]:
        check_results = self.run_checks()
        fix_results = self.run_fixes(check_results, Mode.AUTO)

        combined = []
        for mod, check in check_results:
            fix = next(
                (f for m, _, f in fix_results if m.name == mod.name), None
            )
            combined.append((mod, check, fix))
        return combined
