# What this changes

<!-- One paragraph. What is different after this merges, and why. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New module
- [ ] New or changed profile / guide
- [ ] Engine change (anything under `rescue/`)
- [ ] Documentation
- [ ] Tests or CI only

## Test plan

<!--
Say what you ran and what it printed. "Tested locally" is not a test plan.
Paste the relevant output, trimmed and redacted.
-->

```console
$ .venv/bin/python -m pytest -q
...

$ .venv/bin/python -m rescue.cli validate
...
```

Manual verification (which OS, which command, what you observed):

<!-- e.g. "macOS 15.2, `rescue run linux_ssh_hardening` reports supported=False
     with a reason rather than an empty healthy result." -->

## Checklist

- [ ] `.venv/bin/python -m pytest -q` passes
- [ ] `.venv/bin/python -m rescue.cli validate` exits 0 (**0 errors**)
- [ ] `.venv/bin/ruff check .` is clean
- [ ] **Integrity manifest:** if any file under `rescue/` was added, changed,
      deleted, or renamed, I ran `python scripts/generate_integrity_manifest.py`
      and committed `rescue/security/integrity_manifest.json`. *(CI regenerates
      it and fails on any diff. A stale manifest makes every launch print a
      tamper warning.)*
- [ ] Not applicable — nothing under `rescue/` changed

## Safety review

Tick everything that applies to the code in this PR, or mark not applicable.

- [ ] Every mutation is confirmed by the user, or gated behind `--yes`
- [ ] Instructional actions use `ActionKind.GUIDANCE` and are never reported as
      completed changes
- [ ] Checks that cannot run return `supported=False` with a reason, or set
      `error` — never an empty healthy result
- [ ] No new module sets `auto_apply = True`
- [ ] External commands go through `rescue.command.run`; filesystem recursion
      goes through `rescue.fsbounds.bounded_walk`
- [ ] Traversal roots and command paths are class attributes so tests can point
      them at a fixture tree
- [ ] Nothing new reaches the network outside the opt-in AI layer and
      `rescue update`
- [ ] Nothing prompts for a password, one-time code, recovery key, or API token
- [ ] `emits_codes` matches the `code=` literals in the module
- [ ] Not applicable

## Anything a reviewer should look at closely

<!-- Where you are least sure. Say so here rather than hoping nobody notices. -->
