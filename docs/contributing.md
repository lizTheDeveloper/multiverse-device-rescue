# Contributing

## Development setup

```console
$ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
$ cd multiverse-device-rescue
$ python3 -m venv .venv
$ source .venv/bin/activate          # Windows: .venv\Scripts\activate
$ pip install -e ".[dev]"
$ rescue version
multiverse-device-rescue 0.1.0
```

Python **3.11** is the floor. It is not aspirational — CI byte-compiles the
whole tree on 3.11 as its first job, because the largest defect ever found in
this repository was code that did not parse on the declared minimum (PEP 701
f-strings, plus thirty call sites using a keyword that only exists in 3.13).
Both shipped because nothing compiled the tree on 3.11.

Optional extras:

| Extra | Install | For |
| --- | --- | --- |
| `dev` | `pip install -e ".[dev]"` | pytest, pytest-asyncio, pyinstaller |
| `ai` | `pip install -e ".[ai]"` | the optional AI provider SDKs |
| `docs` | `pip install -e ".[docs]"` | building this documentation site |

## Running the suite

```console
$ python -m pytest -q
$ python -m pytest tests/test_module_linux_firewall_check.py -q   # one module
$ python -m pytest -q --maxfail=20                                # what CI runs
```

CI sets `RESCUE_TEST_MODE=1`. Tests must never reach the network or an
uncontrolled home directory — environment coupling is what once made this suite
pass on exactly one developer's machine. Structure a module so its traversal
roots, thresholds, and service lists are class attributes a test can repoint;
see [Writing a module](writing-a-module.md#testability-traversal-roots-as-class-attributes).

Module tests load through the real registry rather than importing the file:

```python
def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_firewall_check")
```

Modules are loaded under a synthetic `rescue_modules.*` name that is not an
importable package, so `patch("rescue_modules.x.run")` cannot resolve — patch
the loaded module object directly.

## Validating the catalog

```console
$ rescue validate
287 modules, 7 profiles, 110 guide phases checked: 0 error(s), 1 warning(s).
Catalog is consistent.

$ rescue validate --strict
```

`validate` executes no module's `check()`. It reads metadata and checks that:

- module names are unique
- `depends_on` entries resolve and form no cycles
- `platforms` and `risk_level` are real enum members and `priority` is 0–100
- no module sets `auto_apply = True` at a non-`SAFE` risk level
- every profile references only modules that exist and names guide sets that
  have phases on disk
- no guide advertises a step as automatable when no such step exists
- no remediation walkthrough claims a code that no module emits

Errors mean the catalog is inconsistent — a user hitting one gets silently
reduced functionality. Warnings mean legal but degraded metadata.

!!! warning "`--strict` currently fails on this tree"
    `rescue validate --strict` exits `1` today. There is exactly one warning
    left, and it is an aggregate:

    ```text
    [warning] registry:documentation: 264 of 287 modules have no docstring
    explaining what they check or why
    ```

    CI's `content` job runs the plain form, so it gates on errors and passes
    today; the workflow comment records that `--strict` goes back on once the
    docstring backlog reaches zero. Failing every pull request on a backlog
    would only teach people to route around the check.

    If you touch a module, adding its docstring is a free contribution — and
    the [module catalog](modules.md) uses the first line as its description, so
    it shows up on the site immediately.

## Regenerating generated files

Four files in this repository are generated, and CI fails on any of them being
stale. Regenerate and commit them alongside the change that made them stale.

**The integrity manifest** — after *any* change under `rescue/`:

```console
$ python scripts/generate_integrity_manifest.py
Wrote .../rescue/security/integrity_manifest.json
$ git diff --exit-code -- rescue/security/integrity_manifest.json
```

A stale manifest is worse than none: it prints a tamper warning on every launch
and trains users to ignore the one signal that would tell them their install
was modified.

**The module catalog** — after adding, removing, renaming, or re-documenting a
module:

```console
$ python scripts/generate_module_catalog.py
Wrote .../docs/modules.md (287 modules).
$ python scripts/generate_module_catalog.py --check
.../docs/modules.md is up to date (287 modules).
```

**The remediation catalog** — after changing any module's `emits_codes` or any
walkthrough in `guides/remediation/`:

```console
$ rescue remediation-catalog
Wrote .../docs/REMEDIATION_CATALOG.md (510 codes)
```

**The threat map** — after editing `docs/threat_remediation_map.yaml`:

```console
$ rescue threat-remediation
```

This one validates before it writes: a threat referencing an unknown profile,
finding code, or module prints `ERROR: …` and exits `1` without touching the
file.

## Building the documentation

```console
$ pip install -e ".[docs]"
$ mkdocs serve                # live preview on http://127.0.0.1:8000
$ mkdocs build --strict       # what CI runs — warnings are errors
```

The site builds to `site_build/` (gitignored). `site/` is the separate
marketing landing page and is not part of this site.

`--strict` turns every warning into a failure, and a broken internal link is a
warning — so a link to a page that does not exist fails the build. That is
deliberate: a dead link is a broken doc.

`docs/modules.md` is generated; do not edit it by hand. `docs/superpowers/` and
`docs/threat_remediation_map.yaml` are excluded from the site via `exclude_docs`
in `mkdocs.yml`. Any new page must be added to the `nav:` block.

## What CI checks

`.github/workflows/tests.yml`:

| Job | What it does |
| --- | --- |
| `syntax-floor` | `python -m compileall -q rescue modules scripts` on Python 3.11. Runs first and gates everything else. |
| `test` | `pytest -q --maxfail=20` across Ubuntu, macOS, and Windows × Python 3.11, 3.12, 3.13, with `RESCUE_TEST_MODE=1`. |
| `lint` | `ruff check .` (blocking) and `ruff format --diff` (advisory). |
| `integrity` | Regenerates the integrity manifest and fails on any diff. |
| `content` | `rescue validate --strict`. |
| `package` | Installs from source into a clean venv on all three OSes, runs the tool **from outside the source tree**, and confirms it discovers its own profiles and can run a module. |

That last job exists because `modules/`, `profiles/`, and `guides/` install
outside the Python package as `data_files`. A packaging mistake produces a tool
that installs cleanly, launches cleanly, and discovers nothing — and only a
clean-environment install from a different directory catches it.

`.github/workflows/docs.yml`:

| Step | What it does |
| --- | --- |
| Install | `pip install -e ".[docs]"` |
| Generate the module catalog | `python scripts/generate_module_catalog.py --check` — fails if the committed page has drifted from the registry. |
| Build | `mkdocs build --strict` |
| Deploy | Uploads `site_build/` and deploys to GitHub Pages, on `main` only. |

## Conventions worth knowing

- **A check is always read-only.** Every `check()`, on every module, without
  exception. `risk_level` describes `fix()`.
- **Never turn "I could not look" into "all clear."** Return
  `supported=False` with a reason, or an error. See
  [Writing a module](writing-a-module.md#platform-gating-supported-and-unsupported_reason).
- **Use `rescue.command.run`, not `subprocess`.** Use
  `rescue.fsbounds.bounded_walk`, not `rglob`.
- **Guidance is not a system change.** Get `ActionKind` right; the reporting
  layer will not let you fake it.
- **Do not set `auto_apply = True`** without a discussion. It is the single
  switch that makes unattended mode able to change a machine, and today nothing
  sets it.
- **Do not describe a guide step as automatable** until it resolves to a
  registered module. `rescue validate` enforces the structural half of this.
- **Do not edit generated files by hand**: `docs/modules.md`,
  `docs/REMEDIATION_CATALOG.md`, `docs/THREAT_REMEDIATION.md`,
  `rescue/security/integrity_manifest.json`.

## Where the work is

[`docs/ROADMAP.md`](ROADMAP.md) is the planning document;
[`docs/ROADMAP_STATUS.md`](ROADMAP_STATUS.md) is the honest accounting of what
is actually done. Two items are worth calling out for anyone looking for
something substantial:

- **P0#10 — discovery executes arbitrary Python.** The registry imports every
  module in-process. Process isolation is a Phase-4 architecture change and has
  not been started.
- **P0#7 — the `subprocess` migration.** `rescue/command.py` exists; migrating
  every remaining in-module call site to it is large but mechanical, and each
  migration is independently reviewable.

Items marked "human/infra required" in the status document — real signer key
material and custody, multi-platform CI on real hardware, signed release
artifacts — cannot be closed by a code change alone.
