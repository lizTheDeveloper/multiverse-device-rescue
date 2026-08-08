# Contributing

Thanks for wanting to work on this. This document is the short version of what
CI enforces and what reviewers look for.

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first. This project gets
used by people in genuinely bad situations, and that shapes how we talk to each
other and to them.

## Development setup

Python 3.11, 3.12, or 3.13.

```bash
git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
cd multiverse-device-rescue
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Optional extras: `.[ai]` for the opt-in AI providers. Nothing in the core needs
them.

Run the CLI from the checkout without installing a console script:

```bash
.venv/bin/python -m rescue.cli --help
```

## The four checks before you push

CI runs all of these (`.github/workflows/tests.yml`). Running them locally first
saves a round trip.

### 1. Tests

```bash
.venv/bin/python -m pytest -q
```

The suite is large (takes a few minutes) and must be **deterministic**. A test
that passes on your machine and fails on a fresh one is a bug in the test, not
in CI. The historical failure mode here was environment coupling: modules that
short-circuit when a real path under `~/Library` is absent, a fixture with
absolute dates that aged into a warning, an assertion on a hardcoded uid.

The convention that prevents it: **a module's traversal roots are class
attributes**, so a test can point them at a fixture tree.

```python
class Module(ModuleBase):
    name = "example_check"
    SEARCH_ROOTS = [Path.home() / ".config"]     # overridable in tests

    def check(self, profile):
        for path in bounded_walk(self.SEARCH_ROOTS, ...):
            ...
```

```python
def test_flags_the_thing(tmp_path):
    mod = Module()
    mod.SEARCH_ROOTS = [tmp_path]                # no dependence on the host
```

Tests must not reach the network or an uncontrolled home directory. CI sets
`RESCUE_TEST_MODE=1`.

Run a single file while iterating:

```bash
.venv/bin/python -m pytest -q tests/test_module_disk_space.py
```

The suite should be fully green. If you see a failure you did not cause, say so
in the pull request rather than working around it.

### 2. Catalog validation

```bash
.venv/bin/python -m rescue.cli validate
```

Errors mean the shipped catalog is internally broken: duplicate module names, a
profile naming a module that does not exist, a dependency cycle, `auto_apply` on
a non-SAFE module, a guide advertising a step as automatable that no module can
perform. Errors must be zero, and this is what CI gates on.

`rescue validate --strict` also promotes warnings to failures. It fails today on
a single warning: 264 of 287 modules have no docstring. If you are adding a
module, give it a file-level docstring and you will not make that worse; paying
down the existing ones is welcome as its own pull request, and once the count
reaches zero `--strict` can go back into CI.

One thing to know if you are adding finding codes: `emits_codes` must match the
`code="..."` literals in your source exactly, and the literal has to be at the
call site. Building a code with an f-string, or picking it with a conditional
expression inside `Finding(...)`, makes it invisible to
`tests/test_module_code_consistency.py` and to the remediation catalog that test
protects.

### 3. Lint

```bash
.venv/bin/ruff check .
```

The rule set in `ruff.toml` is deliberately narrow — defects, not untidiness
(syntax errors, undefined names, redefinitions, comparison mistakes that change
meaning). Read the comment at the top of that file before proposing to widen it.

### 4. Integrity manifest

**Required whenever you change any file under `rescue/`.** The manifest is a
SHA-256 hash of every `.py` file in the package; if it is stale, every launch
prints a tamper warning, which trains users to ignore the one signal that would
tell them their install was modified.

```bash
.venv/bin/python scripts/generate_integrity_manifest.py
git add rescue/security/integrity_manifest.json
```

CI regenerates it and fails if `git diff --exit-code` on that file is non-empty.
This includes adding, deleting, or renaming a file under `rescue/` — deletions
and additions both fail the check.

Changes under `modules/`, `profiles/`, `guides/`, `docs/`, or `tests/` do **not**
require regeneration; the manifest deliberately covers only `rescue/**/*.py`.

## Writing a module

A module is one directory: `modules/<category>/<name>/__init__.py`, exporting a
class called `Module` that subclasses `ModuleBase`. Data files it needs go in
`modules/<category>/<name>/data/*.json`. Categories are `security`, `integrity`,
`performance`, `network`, `bloatware`.

```python
"""One paragraph on what this checks and why it matters.

A second paragraph on the decisions that shaped it — why this data source
and not the obvious one, what changes the severity. `rescue validate` requires
a docstring; reviewers require it to be worth reading.
"""

from rescue.command import run
from rescue.models import (
    Action, ActionKind, CheckResult, Finding, FixResult,
    Mode, Platform, RiskLevel, Severity, SystemProfile,
)
from rescue.module_base import ModuleBase


class Module(ModuleBase):
    name = "example_check"
    category = "security"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    estimated_duration = "2s"
    emits_codes = ["security.example_check.thing_is_wrong"]

    def check(self, profile: SystemProfile) -> CheckResult:
        result = run(["some", "command"], timeout=5)
        if not result.ok:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason="`some command` is not available here",
            )
        ...

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        ...
```

### Rules

**Bounded commands.** Use `rescue.command.run` (`rescue/command.py`), not
`subprocess.run` directly. It enforces a timeout (20s default) and an output cap
(5 MiB), and returns a `CommandResult` instead of raising. A large migration of
existing modules is outstanding, but new code must not add to the backlog.

**Bounded traversal.** Use `rescue.fsbounds.bounded_walk` for anything that
recurses. An unbounded walk of a real home directory stalls a rescue session on
the machines where it matters most. Use `is_file_nofollow` / `is_dir_nofollow`
from the same module rather than `Path.is_file(follow_symlinks=False)`, which
only exists on Python 3.13 and raises `TypeError` on 3.11.

**Guidance is not mutation.** This is the rule the product depends on.

- An `Action` that tells the user to do something is `ActionKind.GUIDANCE`. It
  renders as `MANUAL ACTION REQUIRED` and is excluded from
  `FixResult.executed_mutations` no matter what `executed`/`success` you set.
- An `Action` that changed the system is `ActionKind.MUTATION` with
  `executed=True` and an honest `success`.
- Never mark an instruction successful. "Told the user to enable the firewall"
  is not "enabled the firewall".

**Never report unsupported as healthy.** If a check cannot run — wrong platform
variant, missing permission, absent tool — return
`CheckResult(supported=False, unsupported_reason=...)` or set `error`. Returning
an empty `findings` list says "this machine is fine", which is the worst thing
this tool can say incorrectly.

**Do not opt into `auto_apply`.** It defaults `False` and no shipped module sets
it `True`. Turning it on requires a fix that is idempotent, low-impact,
reversible, `RiskLevel.SAFE`, and a reviewer who agrees on all four.

**Declare `emits_codes`.** Every `code=` string a `Finding` can carry must be
listed in `emits_codes`, and vice versa —
`tests/test_module_code_consistency.py` enforces the match. Codes follow
`<category>.<module>.<slug>` and are what links a finding to a walkthrough in
`guides/remediation/`.

**Never ask for a secret.** No password prompts, no 2FA codes, no recovery keys,
no API tokens. If the remediation requires one, it belongs in a guide step the
human does at the provider.

**Write findings for the person reading them.** Severity, a title that says what
is wrong, and a description that explains why it matters and what it does not
prove. Look at `modules/security/linux_ssh_hardening/__init__.py` for the tone.

### Adding a profile or guide

- Profiles are `profiles/<name>.yaml`. Every module they include, exclude, or
  configure must exist, and every guide set they name must have phases on disk.
- Guides are `guides/<profile>/phase_N.md` with YAML front matter. A step may
  only appear in `automatable_steps` if a registered module can perform it.
- Remediation walkthroughs are `guides/remediation/<slug>.md` with a
  `remediates:` list of finding codes. One that names a code no module emits is
  dead content and validation warns about it.
- `rescue validate` checks all of the above.

## Pull requests

- Branch from `main`. One logical change per PR; a mechanical sweep and a
  behaviour change should not share a diff.
- Every behaviour change comes with a test. For a bug fix, a test that fails
  before the fix.
- Fill in the PR template, including the test plan — say what you ran and what
  it printed, not "tested locally".

Checklist (also in the template):

- [ ] `.venv/bin/python -m pytest -q` passes
- [ ] `.venv/bin/python -m rescue.cli validate` exits 0 (**0 errors**)
- [ ] `.venv/bin/ruff check .` is clean
- [ ] If any file under `rescue/` changed: ran
      `python scripts/generate_integrity_manifest.py` and committed the result
- [ ] New/changed modules use `rescue.command.run` and bounded traversal
- [ ] Guidance actions are `ActionKind.GUIDANCE`; nothing instructional is
      reported as a completed change
- [ ] Unsupported and failed checks do not read as healthy
- [ ] No new module sets `auto_apply = True`
- [ ] Docs updated if behaviour or commands changed

## Reporting things

- Bugs, false positives, false negatives, new module proposals, and feature
  requests: use the issue templates in `.github/ISSUE_TEMPLATE/`.
- Security vulnerabilities: **do not open an issue.** See
  [SECURITY.md](SECURITY.md).
