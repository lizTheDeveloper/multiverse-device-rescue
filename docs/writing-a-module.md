# Writing a module

A module is one self-contained check. This page is the contract it has to
satisfy. Read [Architecture](architecture.md) first if you have not — it
explains where a module sits in a scan.

## The contract in one screen

Create `modules/<category>/<module_name>/__init__.py` defining a class named
exactly `Module` that subclasses `ModuleBase`. That is the whole registration
mechanism: there is no plugin manifest, no entry point, no registry file to
edit.

```python
class Module(ModuleBase):
    name: str                  # unique across the whole tree; matches the directory
    category: str              # must match the parent directory name
    platforms: list[Platform]  # [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level: RiskLevel      # SAFE | MODERATE | DESTRUCTIVE — describes fix(), not check()
    priority: int = 50         # 0-100; higher runs earlier within the same dependency level
    depends_on: list[str] = [] # module names that must run first
    emits_codes: list[str] = []  # every finding code check() can attach
    estimated_duration: str = "unknown"   # free text: "5s", "2m"
    auto_apply: bool = False   # opt in to unattended mutation. Leave it False.

    def check(self, profile: SystemProfile) -> CheckResult: ...
    def fix(self, findings: CheckResult, mode: Mode) -> FixResult: ...
    def configure(self, config: dict) -> None: ...   # optional; default no-op
```

Both `check()` and `fix()` are abstract — you must implement both, even if
`fix()` only returns guidance.

### The attributes, in detail

**`name`** — unique across all 287 modules. `rescue validate` reports a
duplicate as an error, because two modules answering to one name means
profiles, the threat map, and `rescue run` all silently pick whichever loaded
last. By convention it matches the directory name, and Windows-only modules are
prefixed `win_`, Linux-only ones `linux_`.

**`category`** — one of `security`, `integrity`, `performance`, `network`,
`bloatware`, matching the parent directory.

**`platforms`** — the coarse gate. A module not listing the running platform is
dropped before the scan starts. Declaring none at all is a validation error:
the module could never be selected.

**`risk_level`** — describes what `fix()` might do. `check()` is always
read-only, on every module, without exception. `SAFE` means low-impact and
reversible; `MODERATE` and `DESTRUCTIVE` require explicit confirmation and can
never be auto-applied.

**`priority`** — must be an integer in 0–100 or validation fails.

**`depends_on`** — module names, resolved by `topological_sort`. Every name
must exist and the graph must be acyclic; both are validation errors.

**`estimated_duration`** — free text. Leaving it `"unknown"` is a validation
*warning*, because a scan cannot show progress honestly without it.

**`auto_apply`** — leave it `False`. Setting it `True` opts your module into
running `fix()` unattended during `rescue --auto`, and it is only defensible
for an idempotent, low-impact, reversible `SAFE` mutation. Setting it on a
non-`SAFE` module is a validation **error**. Today no shipped module sets it,
which is what makes auto mode read-only — do not be the first without a
discussion.

**A file-level docstring** — required in practice. `rescue validate` warns
about a module with no docstring on either the class or the containing module,
and the [module catalog](modules.md) uses its first line as the module's
one-line description. Write the first line as a complete, plain sentence.

## `emits_codes` and finding codes

A finding code is the join key between a finding and its remediation
walkthrough. The scheme is `<category>.<module_name>.<slug>`:

```python
emits_codes = [
    "security.linux_firewall_check.no_firewall",
    "security.linux_firewall_check.firewall_inactive",
    "security.linux_firewall_check.default_allow_inbound",
    "security.linux_firewall_check.undetermined",
]
```

Declare **every** code `check()` can attach to a `Finding`. `emits_codes` is
what [the remediation catalog](REMEDIATION_CATALOG.md) and
[the threat map](THREAT_REMEDIATION.md) are generated from, and what
`rescue validate` uses to detect walkthroughs that nothing can ever reach.

A purely informational finding may carry `code=None`.

## Platform gating: `supported` and `unsupported_reason`

`platforms` is the coarse gate. Inside `check()`, guard again and return a
result that says *why* it could not run:

```python
if profile.platform is not Platform.LINUX:
    return CheckResult(
        module_name=self.name,
        supported=False,
        unsupported_reason=(
            "This check reads Linux firewall front-ends (ufw, firewalld, "
            f"nftables, iptables); this host reports {profile.platform.value}."
        ),
    )
```

Use the same pattern for a missing command, an unreadable path, or a permission
denial.

!!! danger "Never return an empty healthy result for something you could not check"
    `CheckResult(module_name=self.name)` means "I ran and found nothing wrong".
    An unreadable firewall ruleset is **not** that. From
    `linux_firewall_check`'s docstring:

    > It is deliberately conservative about claiming a machine is unprotected.
    > An unreadable ruleset (no privileges) is reported as "could not
    > determine", not as "no firewall": a rescue tool that tells someone their
    > firewall is off when it is merely unreadable teaches them to distrust the
    > tool.

    Three honest outcomes exist and they are all better than a false clean
    bill of health: `supported=False` with a reason, `error=...`, or an
    explicit `undetermined` finding.

## Running commands: use `rescue.command.run`

Never call `subprocess` directly. Use the bounded runner:

```python
from rescue.command import run

result = run(["ufw", "status", "verbose"], timeout=10.0)
if result.ok:
    parse(result.stdout)
```

`run()` gives you, in one place: a mandatory timeout (default 20 s); a cap on
captured output (default 5 MiB, streamed, with the child terminated on
overflow so peak memory stays bounded); a `TypeError` if you pass a string
instead of a token list, so you cannot accidentally invoke a shell; and a
structured `CommandResult` — it **never raises** for command failure, timeout,
or a missing executable.

```python
@dataclass
class CommandResult:
    args: list[str]
    returncode: int | None   # None if it timed out or could not launch
    stdout: str
    stderr: str
    timed_out: bool
    error: str | None
    duration_s: float
    truncated: bool

    @property
    def ok(self) -> bool: ...   # returncode == 0, not timed out, no error
```

A missing executable is `error="[Errno 2] No such file or directory"` with
`returncode=None` — which is usually the signal to report `supported=False`
rather than to report a problem.

## Walking the filesystem: use `rescue.fsbounds`

Never write an unbounded `rglob`. Use `bounded_walk`:

```python
from rescue.fsbounds import WalkLimits, bounded_walk, is_dir_nofollow

for path in bounded_walk(
    roots,
    WalkLimits(max_depth=4, max_files=2000, deadline_s=10.0, follow_symlinks=False),
):
    inspect(path)
```

`WalkLimits` bounds depth (measured per root), file count, total bytes, and
wall-clock time, and does not follow symlinks by default. Missing or unreadable
roots are skipped rather than raising. `is_file_nofollow` and `is_dir_nofollow`
give you no-follow stat checks that work on Python 3.11 (where
`Path.is_file(follow_symlinks=False)` does not exist).

## Testability: traversal roots as class attributes

A module that hardcodes `/etc/systemd/system` can only be tested against the
machine running the suite. Declare paths as class attributes so a test can
repoint them at a fixture tree. This is the convention, from
`linux_persistence_audit`:

```python
class Module(ModuleBase):
    ...
    # Traversal roots as class attributes so tests point them at a fixture tree
    # rather than at the machine running the suite. Absolute paths are used as
    # given; paths starting with "~" are expanded per user.
    system_unit_dirs: list[str] = ["/etc/systemd/system", "/usr/local/lib/systemd/system"]
    user_unit_dirs: list[str] = ["~/.config/systemd/user"]
    autostart_dirs: list[str] = ["~/.config/autostart", "/etc/xdg/autostart"]
    shell_rc_files: list[str] = ["~/.bashrc", "~/.zshrc"]
    max_files: int = 2000
```

Apply the same idea to limits and thresholds. It makes them configurable from a
profile's `module_config` for free.

## Guidance versus mutation

`fix()` returns `Action` objects, and the `kind` you choose is a factual claim
about what happened.

```python
Action(
    title="Enable the firewall",
    description="Run `sudo ufw enable`, then confirm with `sudo ufw status`.",
    risk_level=RiskLevel.SAFE,
    kind=ActionKind.GUIDANCE,      # nothing was done to the machine
)
```

The rules:

1. **Default to guidance.** Most of what matters in a rescue happens at a
   provider or in a system settings pane, not on disk. Telling someone
   precisely what to do is a complete, honest answer.
2. **A `MUTATION` must have actually run.** Set `executed=True` and
   `success=True/False` from the real outcome, and put the error text in
   `error` when it fails. Only `executed and success` mutations count as
   system changes.
3. **Never mark guidance as executed to make a report look better.** It will
   not work — `FixResult.executed_mutations` filters on `kind` first, and the
   case export re-derives `changed_the_system` the same way.
4. **Record how to undo it.** Put a rollback instruction in
   `action.data["rollback"]` and a verification step in
   `action.data["verification"]`. The case export surfaces both.
5. **Respect `mode`.** `Mode.AUTO` means unattended — a module reached in auto
   mode has already passed the `auto_apply` gate, but if you are unsure, return
   guidance. `Mode.MANUAL` means a human said yes at a prompt. `Mode.CLI` means
   `--yes` was passed.
6. **Match `risk_level` to reality.** A module whose `fix()` deletes files is
   `DESTRUCTIVE`, not `SAFE`, whatever the deletion is for.

## A complete example module

`modules/integrity/example_check/__init__.py`:

```python
"""Is this machine's clock being kept correct by something?

A drifted clock breaks HTTPS certificate validation, time-based one-time
passwords, and scheduled jobs — and it does it in ways that look like a network
fault, so people chase the wrong problem for hours. This check asks whether any
time-synchronisation service is running, and reports "could not determine"
rather than "nothing is running" when it cannot tell.
"""

from rescue.command import run
from rescue.models import (
    Action,
    ActionKind,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

_TIMEOUT = 5.0


class Module(ModuleBase):
    name = "example_check"
    category = "integrity"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 40
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "integrity.example_check.no_time_sync",
    ]

    # Class attributes, so a test can substitute its own list.
    services: list[str] = ["systemd-timesyncd", "chronyd", "ntpd"]

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads systemd service state; this host reports "
                    f"{profile.platform.value}."
                ),
            )

        active = []
        readable = False
        for service in self.services:
            result = run(["systemctl", "is-active", service], timeout=_TIMEOUT)
            if result.error is not None or result.timed_out:
                # systemctl is missing or hung: we learned nothing about this
                # service. Do not let that read as "not running".
                continue
            readable = True
            if result.stdout.strip() == "active":
                active.append(service)

        if not readable:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "systemctl could not be run, so service state is unknown on "
                    "this machine."
                ),
            )

        if active:
            return CheckResult(module_name=self.name)

        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="No time-synchronisation service appears to be running",
                    description=(
                        "Nothing is keeping this machine's clock correct. Checked "
                        f"for: {', '.join(self.services)}."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="integrity.example_check.no_time_sync",
                    confidence=0.9,
                )
            ],
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = [
            Action(
                title="Enable a time-synchronisation service",
                description=(
                    "Run `sudo systemctl enable --now systemd-timesyncd`, then "
                    "confirm with `timedatectl status` that 'System clock "
                    "synchronized' reads yes."
                ),
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                data={
                    "rollback": "sudo systemctl disable --now systemd-timesyncd",
                    "verification": "timedatectl status",
                },
            )
        ]
        return FixResult(module_name=self.name, actions=actions)
```

## The matching test

`tests/test_module_example_check.py`:

```python
"""Tests for example_check.

The behaviour worth protecting is the distinction between "nothing is running"
and "I could not tell". Conflating them produces a confident wrong answer.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import CheckStatus, Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "example_check")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _result(args, stdout="", returncode=0, error=None) -> CommandResult:
    return CommandResult(
        args=list(args),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        timed_out=False,
        error=error,
        duration_s=0.01,
        truncated=False,
    )


def _patched(mod, responses):
    """Patch the module's own `run`, dispatching on the service name.

    Modules are loaded by path under a synthetic ``rescue_modules.*`` name that
    is not an importable package, so ``patch("rescue_modules.x.run")`` cannot
    resolve it. Patching the loaded module object directly does.
    """
    import sys as _sys

    loaded = _sys.modules[type(mod).__module__]
    original = loaded.run

    def fake(args, **kwargs):
        return responses.get(args[-1], _result(args, stdout="inactive"))

    loaded.run = fake
    return original, loaded


def test_active_service_is_healthy():
    mod = _get_module()
    original, loaded = _patched(
        mod, {"chronyd": _result(["systemctl"], stdout="active\n")}
    )
    try:
        check = mod.check(_profile())
    finally:
        loaded.run = original
    assert check.status is CheckStatus.HEALTHY


def test_nothing_running_is_a_warning_with_a_code():
    mod = _get_module()
    original, loaded = _patched(mod, {})
    try:
        check = mod.check(_profile())
    finally:
        loaded.run = original
    assert check.status is CheckStatus.ISSUES
    assert check.findings[0].severity is Severity.WARNING
    assert check.findings[0].code == "integrity.example_check.no_time_sync"
    assert check.findings[0].code in mod.emits_codes


def test_missing_systemctl_is_unsupported_not_healthy():
    """The whole point: 'I could not look' must never read as 'all clear'."""
    mod = _get_module()
    original, loaded = _patched(mod, {})
    loaded.run = lambda args, **kw: _result(
        args, returncode=None, error="No such file or directory"
    )
    try:
        check = mod.check(_profile())
    finally:
        loaded.run = original
    assert check.status is CheckStatus.UNSUPPORTED
    assert check.unsupported_reason


def test_wrong_platform_is_unsupported():
    mod = _get_module()
    check = mod.check(_profile(platform=Platform.DARWIN))
    assert check.status is CheckStatus.UNSUPPORTED


def test_fix_is_guidance_only_and_changes_nothing():
    mod = _get_module()
    fix = mod.fix(mod.check(_profile()), Mode.MANUAL)
    assert fix.executed_mutations == []
    assert len(fix.guidance_actions) == 1


def test_module_does_not_opt_in_to_unattended_mutation():
    assert getattr(_get_module(), "auto_apply", False) is False
```

That last test is a convention worth copying — several shipped module tests
assert it, so auto mode staying read-only is protected by the suite and not
just by a habit.

## Before you open a pull request

```console
$ python -m pytest tests/test_module_example_check.py -q
$ rescue validate                    # 0 errors; check your module adds no warnings
$ rescue run example_check           # see the real output on a real machine
$ python scripts/generate_module_catalog.py   # the catalog page is generated
$ python scripts/generate_integrity_manifest.py   # only if you touched rescue/
```

The last two produce files that must be committed with your change; CI fails on
a stale catalog page or a stale integrity manifest. See
[Contributing](contributing.md).
