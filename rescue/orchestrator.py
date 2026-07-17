from pathlib import Path
import logging

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.profiles import Profile, filter_modules_by_profile, validate_profile_modules
from rescue.registry import discover_modules, filter_by_platform, topological_sort

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, modules_dir: Path, profile: Profile | None = None):
        self._modules_dir = modules_dir
        self._profile = profile

    def run_checks(self) -> list[tuple[ModuleBase, CheckResult]]:
        profile = gather_profile()
        modules = discover_modules(self._modules_dir)

        if self._profile is not None:
            validate_profile_modules(self._profile, modules)
            modules = filter_by_platform(modules, profile.platform)
            modules = filter_modules_by_profile(modules, self._profile)
            for mod in modules:
                mod.configure(self._profile.module_config.get(mod.name, {}))
        else:
            modules = filter_by_platform(modules, profile.platform)

        modules = topological_sort(modules)

        results = []
        for mod in modules:
            try:
                check = mod.check(profile)
            except Exception as exc:
                logger.exception("Module check failed: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
            results.append((mod, check))
        return results

    def run_fixes(
        self,
        check_results: list[tuple[ModuleBase, CheckResult]],
        mode: Mode,
    ) -> list[tuple[ModuleBase, CheckResult, FixResult]]:
        results = []
        for mod, check in check_results:
            if check.error or not check.has_issues:
                continue
            if mode == Mode.AUTO and mod.risk_level != RiskLevel.SAFE:
                continue
            try:
                fix = mod.fix(check, mode)
            except Exception as exc:
                logger.exception("Module fix failed: %s", mod.name)
                fix = FixResult(
                    module_name=mod.name,
                    actions=[],
                )
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
