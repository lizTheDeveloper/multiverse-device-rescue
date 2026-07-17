from pathlib import Path
import logging
import threading
import time
from typing import Callable, TypeVar

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.profiles import Profile, filter_modules_by_profile, validate_profile_modules
from rescue.registry import discover_modules, filter_by_platform, topological_sort

logger = logging.getLogger(__name__)

# A single module check should never wall off the whole session. Default high
# enough not to trip legitimate slow scans, low enough to bound a hang.
DEFAULT_MODULE_TIMEOUT = 60.0

_T = TypeVar("_T")


class _Timeout(Exception):
    """A module check exceeded its per-module time budget."""


def _call_with_timeout(fn: Callable[[], _T], timeout: float) -> _T:
    """Run ``fn`` on a daemon thread, abandoning it if it exceeds ``timeout``.

    Python cannot forcibly kill a thread stuck in a blocking syscall (e.g. a
    ``subprocess.run`` with no timeout), so on timeout the worker is left as a
    daemon and the caller moves on. This bounds the *session* even when an
    individual command cannot be interrupted.
    """
    box: dict[str, object] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller thread
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise _Timeout(f"timed out after {timeout}s")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box["value"]  # type: ignore[return-value]


class Orchestrator:
    def __init__(
        self,
        modules_dir: Path,
        profile: Profile | None = None,
        *,
        module_timeout: float = DEFAULT_MODULE_TIMEOUT,
        total_budget: float | None = None,
    ):
        self._modules_dir = modules_dir
        self._profile = profile
        self._module_timeout = module_timeout
        self._total_budget = total_budget

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
        start = time.monotonic()
        budget_exhausted = False
        for mod in modules:
            if budget_exhausted or (
                self._total_budget is not None
                and (time.monotonic() - start) >= self._total_budget
            ):
                budget_exhausted = True
                results.append(
                    (
                        mod,
                        CheckResult(
                            module_name=mod.name,
                            error="skipped: session time budget exhausted",
                        ),
                    )
                )
                continue
            try:
                check = _call_with_timeout(
                    lambda m=mod: m.check(profile), self._module_timeout
                )
            except _Timeout as exc:
                logger.warning("Module check timed out: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
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
            if mode == Mode.AUTO and (
                mod.risk_level != RiskLevel.SAFE
                or not getattr(mod, "auto_apply", False)
            ):
                # Auto mode is read-only unless a module has explicitly opted
                # in to unattended, idempotent SAFE mutation via `auto_apply`.
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
