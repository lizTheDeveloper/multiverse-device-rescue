from pathlib import Path
import atexit
import errno
import logging
import os
import signal
import subprocess
import threading
import time
import weakref
from typing import Callable, TypeVar

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.profiles import Profile, filter_modules_by_profile, validate_profile_modules
from rescue.registry import discover_modules, filter_by_platform, topological_sort
from rescue.severity_policy import cap_severity

logger = logging.getLogger(__name__)

# A single module check should never wall off the whole session. Default high
# enough not to trip legitimate slow scans, low enough to bound a hang.
DEFAULT_MODULE_TIMEOUT = 60.0

_T = TypeVar("_T")


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


# What a person reads when a check ran out of time. The technical detail stays
# in brackets after it, so nothing is hidden from someone who wants it.
TIMEOUT_PLAIN = (
    "This check took too long, so it was stopped before it could finish. "
    "Running the scan again may let it finish."
)


def timeout_message(timeout: float) -> str:
    return f"{TIMEOUT_PLAIN} (timed out after {timeout}s)"


class _AbandonGuard:
    """Stop a check that ran out of time from running any more commands.

    Python cannot kill the abandoned worker thread, so without this it carries
    on in the background: on a real Mac one timed-out Wi-Fi check went on to
    run `system_profiler` 75 more times during the checks after it, slowing
    them down until they timed out too. The guard kills the commands an
    abandoned worker is running and refuses to start new ones (Popen raises
    OSError, which checks already handle as "command failed").

    It wraps ``subprocess.Popen`` once per process and stays: an abandoned
    worker can outlive the scan that abandoned it. For every other thread the
    wrapper only records the process and passes through. Threads are tracked
    by object, not ident (idents are reused), and only the worker thread
    itself; threads a check starts on its own are not.

    A command started from a check's worker thread gets its own process
    group, so stopping it kills the programs it started too, not just the
    direct child: on macOS and Linux a new session (unless the caller set one
    up), killed with killpg; on Windows CREATE_NEW_PROCESS_GROUP, killed with
    `taskkill /T /F` (falling back to killing the direct child). On macOS and
    Linux that also means the command has no terminal to ask for a password
    on: it fails instead of waiting.

    Those groups no longer get the terminal's Ctrl-C, so the commands still
    running are killed by :func:`stop_all_commands`: at normal interpreter
    exit (atexit, which also covers Ctrl-C) and, in `rescue scan`, on SIGTERM
    or SIGHUP (:func:`stop_commands_on_signals`). Nothing can run on SIGKILL,
    or when Windows ends the process with TerminateProcess; then they are
    left to finish or hit their own timeouts.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._abandoned: weakref.WeakSet = weakref.WeakSet()
        self._workers: weakref.WeakSet = weakref.WeakSet()
        self._live: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._atexit_registered = False

    def register_worker(self, thread: threading.Thread) -> None:
        with self._lock:
            self._workers.add(thread)

    def abandon(self, thread: threading.Thread) -> None:
        with self._lock:
            self._abandoned.add(thread)
            procs = list(self._live.pop(thread, ()))
        for proc in procs:
            _stop(proc)

    def _stop_all(self) -> None:
        with self._lock:
            procs = [p for group in self._live.values() for p in group]
        for proc in procs:
            _stop(proc)

    def _own_session(self, kwargs: dict) -> bool:
        """Give a check's command its own process group, if nothing else asked."""
        if threading.current_thread() not in self._workers:
            return False
        return _own_group_kwargs(kwargs, os.name)

    def _admit(self, proc) -> None:
        thread = threading.current_thread()
        with self._lock:
            if thread in self._abandoned:
                raise OSError(errno.ECANCELED, "not started: this check ran out of time")
            if proc is not None:
                self._live.setdefault(thread, weakref.WeakSet()).add(proc)

    def ensure_installed(self) -> None:
        """Wrap whatever ``subprocess.Popen`` is now, unless already wrapped."""
        current = subprocess.Popen
        if getattr(current, "_rescue_abandon_guard", None) is self:
            return
        guard = self
        if not self._atexit_registered:
            atexit.register(self._stop_all)
            self._atexit_registered = True

        class GuardedPopen(current):  # type: ignore[misc, valid-type]
            _rescue_abandon_guard = guard
            _rescue_own_group = False

            def __init__(self, *args, **kwargs):
                guard._admit(None)
                own_group = guard._own_session(kwargs)
                super().__init__(*args, **kwargs)
                self._rescue_own_group = own_group
                try:
                    guard._admit(self)
                except OSError:
                    # Abandoned while it was starting: stop it straight away
                    # and reap it, so it doesn't linger as a zombie.
                    _stop(self)
                    try:
                        self.wait(timeout=1)
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                    raise

        subprocess.Popen = GuardedPopen


# subprocess.CREATE_NEW_PROCESS_GROUP exists only on Windows builds.
_CREATE_NEW_PROCESS_GROUP = 0x00000200


def _own_group_kwargs(kwargs: dict, os_name: str) -> bool:
    """Set Popen kwargs so the command leads its own process group.

    Returns False (kwargs untouched) where the caller already chose how the
    child is grouped, or on an OS this doesn't handle.
    """
    if os_name == "posix":
        if any(k in kwargs for k in ("start_new_session", "process_group", "preexec_fn")):
            return False
        kwargs["start_new_session"] = True
        return True
    if os_name == "nt":
        flags = kwargs.get("creationflags", 0) or 0
        kwargs["creationflags"] = flags | _CREATE_NEW_PROCESS_GROUP
        return True
    return False


def _stop(proc, os_name: str | None = None) -> None:
    """Kill a still-running command, with everything it started if it leads
    its own process group."""
    os_name = os_name or os.name
    try:
        if proc.poll() is not None:
            return
        if getattr(proc, "_rescue_own_group", False):
            if os_name == "posix":
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    return
                except (OSError, AttributeError):
                    pass
            elif os_name == "nt":
                try:
                    done = subprocess.run(
                        ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                        capture_output=True,
                        timeout=5,
                    )
                    if done.returncode == 0:
                        return
                except (OSError, subprocess.SubprocessError):
                    pass
        proc.kill()
    except (OSError, ValueError):
        pass


_GUARD = _AbandonGuard()


def stop_all_commands() -> None:
    """Kill every command a check is still running (see :class:`_AbandonGuard`)."""
    _GUARD._stop_all()


def stop_commands_on_signals() -> None:
    """On SIGTERM (and SIGHUP on macOS/Linux), stop every running check
    command, then exit with 128 + the signal number.

    The desktop app has no cancel button; when it quits mid-scan it sends the
    engine SIGTERM (desktop/engine-runner.js stopRunningScans, on Electron's
    before-quit). Without this handler the commands checks had started kept
    running. On Windows that kill is TerminateProcess, which no handler sees.
    Call it from the main thread, as `rescue scan` does.
    """

    def handler(signum, frame):
        stop_all_commands()
        raise SystemExit(128 + signum)

    names = ["SIGTERM"] + (["SIGHUP"] if os.name == "posix" else [])
    for name in names:
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass  # not the main thread, or not allowed here


def _call_with_timeout(
    fn: Callable[[], _T],
    timeout: float,
    on_abandon: Callable[[threading.Thread], None] | None = None,
    on_start: Callable[[threading.Thread], None] | None = None,
) -> _T:
    """Run ``fn`` on a daemon thread, abandoning it if it exceeds ``timeout``.

    Python cannot forcibly kill a thread stuck in a blocking syscall (e.g. a
    ``subprocess.run`` with no timeout), so on timeout the worker is left as a
    daemon and the caller moves on. This bounds the *session* even when an
    individual command cannot be interrupted. ``on_abandon`` gets the worker
    thread so its commands can be stopped (see :class:`_AbandonGuard`).
    """
    box: dict[str, object] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller thread
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    if on_start is not None:
        on_start(worker)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        if on_abandon is not None:
            on_abandon(worker)
        raise _Timeout(timeout_message(timeout))
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

    def run_checks(self, on_progress=None, on_plan=None) -> list[tuple[ModuleBase, CheckResult]]:
        """Run every applicable module's check().

        ``on_progress(phase, index, total, module, check)``, if given, is called
        with phase "start" before each module (check is None) and "done" after
        it, so a caller can say what is happening during a long scan.

        ``on_plan(modules)``, if given, is called once with the modules about
        to run, in order, before the first one starts, so a caller can tell
        when every check of one kind has finished.
        """
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

        # Installed inside any --trace wrapper, so traced commands are guarded too.
        _GUARD.ensure_installed()

        results = []
        marks = None  # the "marked as yours" list, read once when first needed
        start = time.monotonic()
        budget_exhausted = False
        total = len(modules)
        report = on_progress or (lambda *args: None)
        if on_plan is not None:
            on_plan(list(modules))
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
            try:
                check = _call_with_timeout(
                    lambda m=mod: m.check(profile),
                    self._module_timeout,
                    on_abandon=_GUARD.abandon,
                    on_start=_GUARD.register_worker,
                )
            except _Timeout as exc:
                logger.warning("Module check timed out: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
            except Exception as exc:
                logger.exception("Module check failed: %s", mod.name)
                check = CheckResult(module_name=mod.name, error=str(exc))
            if not check.error:
                cap_severity(mod, check)
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
