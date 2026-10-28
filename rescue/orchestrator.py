from pathlib import Path
import logging
import threading
import time
from typing import Callable, TypeVar

from rescue.models import CheckResult, FixResult, Mode, RiskLevel, SystemProfile
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.profiles import Profile, filter_modules_by_profile, validate_profile_modules
from rescue.registry import discover_modules, filter_by_platform, topological_sort

logger = logging.getLogger(__name__)

# A single module check should never wall off the whole session. Default high
# enough not to trip legitimate slow scans, low enough to bound a hang.
DEFAULT_MODULE_TIMEOUT = 60.0

_T = TypeVar("_T")

OFFLINE_UNSUPPORTED_REASON = (
    "This check needs the computer's own system to be running, "
    "so it can't look at a disk from outside."
)


def _apply_item_marks(module_name: str, findings: list, marks, supported: bool = True):
    """Apply "marked as yours" for settings and installed items to one check's
    findings, and retire marks for items the check no longer sees.

    `marks` is (items, problem) from one read of the list per scan, or None
    until first needed. Returns it for the next module (without any marks
    this check retired). `supported` False means the check could not look,
    so nothing it did not report counts as gone. Never raises: a problem with
    the list must not break a check.
    """
    try:
        from rescue import known_items

        if module_name not in known_items.ITEM_MODULES:
            return marks
        if marks is None:
            marks = known_items.KnownItemsStore().load_for_scan()
        items, problem = marks
        if any(known_items.item_kind_for(getattr(f, "code", None)) for f in findings):
            known_items.apply_item_marks(module_name, findings, items, problem)
        if supported and not problem:
            gone = known_items.marks_gone(module_name, findings, items)
            if gone:
                retired = known_items.retire_marks(gone)
                findings.extend(known_items.retired_notice(i) for i in retired)
                retired_ids = {i.id for i in retired}
                marks = ([i for i in items if i.id not in retired_ids], problem)
    except Exception:
        logger.exception("Could not apply marked items to %s", module_name)
    return marks


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
        module_timeout: float | None = None,
        total_budget: float | None = None,
        system_profile: SystemProfile | None = None,
    ):
        self._system_profile = system_profile
        self._modules_dir = modules_dir
        self._profile = profile
        self._module_timeout = module_timeout
        self._total_budget = total_budget

    def _timeout_for(self, mod: ModuleBase) -> float:
        """A timeout the caller chose wins; otherwise a module's own check_timeout
        replaces the default."""
        if self._module_timeout is not None:
            return self._module_timeout
        return getattr(mod, "check_timeout", None) or DEFAULT_MODULE_TIMEOUT

    def run_checks(self, on_progress=None) -> list[tuple[ModuleBase, CheckResult]]:
        """Run every applicable module's check().

        ``on_progress(phase, index, total, module, check)``, if given, is called
        with phase "start" before each module (check is None) and "done" after
        it, so a caller can say what is happening during a long scan.
        """
        profile = self._system_profile or gather_profile()
        offline = profile.target is not None
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
        marks = None  # the "marked as yours" list, read once when first needed
        start = time.monotonic()
        budget_exhausted = False
        total = len(modules)
        report = on_progress or (lambda *args: None)
        for index, mod in enumerate(modules, start=1):
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
                report("done", index, total, mod, results[-1][1])
                continue
            report("start", index, total, mod, None)
            if offline and not getattr(mod, "offline_capable", False):
                # Not asked at all: it would describe this computer, not the disk.
                check = CheckResult(
                    module_name=mod.name,
                    supported=False,
                    unsupported_reason=OFFLINE_UNSUPPORTED_REASON,
                )
                results.append((mod, check))
                report("done", index, total, mod, check)
                continue
            try:
                check = _call_with_timeout(
                    lambda m=mod: m.check(profile), self._timeout_for(mod)
                )
            except _Timeout as exc:
                logger.warning("Module check timed out: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
            except Exception as exc:
                logger.exception("Module check failed: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
            if not check.error and not offline:
                marks = _apply_item_marks(mod.name, check.findings, marks, getattr(check, "supported", True))
            results.append((mod, check))
            report("done", index, total, mod, check)
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
