# Roadmap Status & Milestone Gap Analysis

Analysis date: 2026-07-17. Compares the 2026-07-09 ROADMAP.md against the current
tree (branch `roadmap-milestone-readonly-scan`, forked from
`wip-checkpoint-2026-07-16`). A week of commits landed after the roadmap was
written, so several P0 items are already substantially addressed.

This document scopes work to the roadmap's own **Recommended first milestone** —
a *trustworthy read-only scan* — because the full roadmap contains items no
automated pass can complete (real cryptographic trust roots with human key
custody, multi-platform CI on real hardware, SBOM / signed release artifacts,
Android/iOS companion apps). Those are itemized as "human/infra required" below.

## P0 status (after this branch's work)

| # | Item | Status | Notes |
| - | ---- | ------ | ----- |
| 1 | Package omits runtime content | **DONE ✓verified** | `setup.py` ships `modules/ profiles/ guides/` as `data_files`. Verified: clean-venv `pip install .`, then installed `rescue` (run from outside the source tree) discovered profiles and ran a read-only `disk_space` check end-to-end. |
| 2 | Content updates don't activate | **DONE** | `repo.checkout` atomically writes the `.git/rescue-applied-head` marker; `runtime.active_content_root()` gates on it and `content_directory/file` prefer applied content. Data content is updatable; Python modules stay bundled by design. Covered by `test_runtime.py` + `update/test_engine.py`. Retained-previous-version rollback is git-history only (see remainder). |
| 3 | Trust config is placeholder | **SOFTWARE DONE / KEYS HUMAN** | `validate_trusted_signers` rejects `REPLACE_WITH_...`/missing keys and the update engine enforces it on construction (`test_default_trust_configuration_rejects_placeholder_keys`). Real key material + rotation remain a human/org task. |
| 4 | Self-integrity non-blocking | **DONE** | `integrity.py` fails on added/modified/missing files. Manifest regenerated on this branch; verifies clean. |
| 5 | SAFE ≠ safe for auto | **DONE** | `ModuleBase.auto_apply` (default False) makes auto mode read-only; a fix is auto-applied only if a module opts in AND is SAFE. Nothing opts in yet → auto is fully read-only. |
| 6 | Advice vs remediation blurred | **DONE (core)** | `FixResult.executed_mutations`/`guidance_actions`: guidance never counts as a system change. CLI auto summary reports system changes vs manual actions separately. Per-module fix() audit for remaining edge cases is follow-up. |
| 7 | Checks can hang / no bounds | **DONE (orchestrator) / migration follow-up** | `rescue/command.py` (timeout+output cap), `rescue/fsbounds.py` (bounded_walk), orchestrator per-module timeout + session budget with daemon-thread isolation. Migrating all ~744 in-module `subprocess.run` sites to the runner is a large mechanical follow-up. |
| 8 | security-reset profile nonfunctional | **DONE** | Profile references only registered modules; misleading "Automates…" description corrected. Whole-catalog validation test (`test_all_shipped_content.py`) fails on any missing module/guide across all profiles. |
| 9 | Linux advertised but can't run | **DONE** | `profiler/linux.py` implemented; `gather_profile()` dispatches to it. |
| 10 | Discovery executes arbitrary Python | **PHASE-4** | Registry still imports every module in-process. Process isolation is a Phase-4 architecture change; out of milestone scope. |

## Milestone work delivered (this branch)

The "trustworthy read-only scan" milestone is met. Delivered on
`roadmap-milestone-readonly-scan`:

1. **Test determinism** — full suite runs to completion (no stall in
   `test_module_ai_threat_indicators`); baseline captured (3094 passing before
   this branch's additions).
2. **Bounded execution (P0#7)** — `rescue/command.py`, `rescue/fsbounds.py`,
   orchestrator per-module timeout + session budget. New tests:
   `test_command.py`, `test_fsbounds.py`, `test_orchestrator_bounds.py`.
3. **Package data (P0#1)** — verified end to end via clean-venv `pip install .`.
4. **Profile validation (P0#8)** — `test_all_shipped_content.py` guards every
   shipped profile + guide; misleading profile description corrected.
5. **Action semantics (P0#5/#6)** — read-only-by-default auto mode
   (`auto_apply`), guidance-vs-mutation accounting. `test_action_semantics.py`.
6. **Richer result schema (P1#1)** — `CheckStatus`, `supported`/
   `unsupported_reason`, `Finding.confidence`. `test_result_schema.py`.
7. **Integrity (P0#4)** — manifest regenerated; verifies clean.

Each landed as its own commit with tests.

## Remainder — needs human/infra decisions or is later-phase (report to human)

**Requires a human or organization (cannot be done by a coding pass):**
- P0#3: real signer key material, custody, rotation, revocation, threshold
  approvals, and the release-signing procedure. (Software guards are in place.)
- Phase 3: platform CI / smoke tests on real macOS Intel + Apple Silicon +
  Windows + Linux at standard and elevated privilege.
- Phase 4: SBOMs, reproducible + signed release artifacts, dependency scanning.
- Android/iOS companion workflows; vendor hardware-diagnostic adapters.

**Large, mechanical, or later-phase engineering follow-ups (scoped, not blocking
the read-only milestone):**
- P0#7 migration: route all ~744 in-module `subprocess.run` calls through
  `rescue.command.run`, then prohibit direct `subprocess` in modules. The
  orchestrator now bounds the *session*; per-call timeouts still want migrating.
- P0#10: run module discovery/analysis in a constrained subprocess instead of
  importing arbitrary Python in-process (Phase 4 architecture change).
- P0#2 rollback: retain the previous applied content version for one-step
  rollback (currently rollback is via git history).
- P0#6 audit: sweep every module `fix()` so any remaining "instruction marked
  successful" cases use `ActionKind.GUIDANCE`.
- P1#1 population: have modules populate `confidence`, `collected_at`, and
  `supported`/`unsupported_reason` (schema is in place; most modules not yet
  migrated). Add a rescue-case export (P1#2) and CI registry-metadata
  validation (P1#3).

## How to verify this milestone

```
python -m pytest -q                     # full suite is deterministic & green
python -m venv /tmp/rv && /tmp/rv/bin/pip install .
cd /tmp && /tmp/rv/bin/rescue profiles  # discovers shipped content
/tmp/rv/bin/rescue run disk_space --yes # end-to-end read-only check
python scripts/generate_integrity_manifest.py   # then startup verifies clean
```

---

# Update — 2026-08-05: branch consolidation, audit, and planned modules

This section corrects several claims above that did not hold on `main`, and
records what changed. Where an earlier claim was wrong, it is called out rather
than quietly edited, because "we verified this" appearing next to something
untrue is the failure mode worth avoiding.

## Corrections to the status above

**P0#4 (self-integrity) was recorded as "DONE — manifest regenerated; verifies
clean". It did not verify clean on `main`.** `verify_package_integrity` reported
8 tampered and 5 added files, so startup verification failed and every launch
printed a tamper warning. The regeneration was real, but it happened on a
different lineage; `main`'s own commits then added `remediation.py`,
`serialize.py`, `threat_map.py`, and two TUI screens without regenerating.
Regenerated here, and it now verifies clean.

**P0#8 (security-reset profile) was recorded as DONE.** It was made *valid* by
deleting the references to `password_manager_check`, `twofa_audit`, and
`session_revocation_scan` — the profile stopped naming modules that did not
exist, but the capability was never built. Those three modules now exist and the
profile references them again.

**The test-suite baseline was recorded as "3094 passing".** The suite was not
green: it was 64 failed / 3341 passed, and one file did not even parse under the
declared minimum Python. See below.

## Python version support was broken, not partially broken

`pyproject.toml` declares `requires-python = ">=3.11"`. On 3.11:

- 3 files failed to parse at all (PEP 701 nested-quote f-strings, and a
  backslash inside an f-string expression). Two were shipped modules, so module
  discovery broke.
- 30 call sites across 16 modules passed `follow_symlinks=` to
  `pathlib.Path.is_file()` / `is_dir()`. That keyword arrived in **3.13**, so
  every one raised `TypeError` at runtime. Those modules did not work on two of
  the three supported versions.

Both are fixed; `rescue.fsbounds` now exposes `is_file_nofollow` /
`is_dir_nofollow` with the same semantics on every supported version.

**Nothing was catching this.** There is no `.github/` directory and no CI. A
matrix that actually ran the suite on 3.11 would have caught the largest defect
in the tree. This is the highest-value remaining infrastructure gap.

## The 64 failures were environment coupling, not flakiness

Every one was a test that silently depended on the machine it ran on, so the
suite only passed on one developer's macOS box:

- Modules that check a real path under `~/Library` or `/Library` and return
  early if absent, so `check()` short-circuited before the mocked subprocess was
  reached (`notification_center_check`, `kext_audit`,
  `appleid_security_check`).
- A time bomb: `win_safe_mode_check` used absolute dates chosen to be "5 days
  ago" when written. Real time moved past them and the fixture aged into a
  >30-day uptime, tripping the warning it asserts is absent.
- `disk_permissions_repair` asserted ownership against a hardcoded uid 501, so
  it only passed as a typical macOS user account.
- `test_cli_scan_json` used `CliRunner(mix_stderr=...)`, removed in click 8.2.
- `update/test_verify` signed a tag without pinning `gpg.format`, so on a host
  configured for SSH commit signing it produced an SSH signature while asserting
  on the GPG path. **No trust check was weakened to green this**; the
  verification code was correct and only the test changed.

The pattern is now a convention: a module's traversal roots are class attributes
so tests can point them at a fixture tree.

Full suite: **3503 passed, 0 failed.**

## Planned modules — resolved

"Planned but missing" was resolved against the roadmap, not guessed. Profiles,
guides, and the threat map reference no missing modules, and every module named
in `docs/superpowers/plans/` exists. Two sources yielded real gaps, both now
closed:

| Module | Source | Why it exists |
| --- | --- | --- |
| `password_manager_check` | P0#8 | Named, never built |
| `twofa_audit` | P0#8 | Named, never built |
| `session_revocation_scan` | P0#8 | Named, never built |
| `code_signature_audit` | P2 "Trust and reputation verification" | No signature validation existed |
| `security_baseline_diff` | P2 "Baselines and differential scans" | No baseline capability existed |
| `evidence_bundle` | P2 "Evidence collection and forensic handoff" | Nothing preserved evidence before repair |

Registry now discovers **278** modules. The remaining P2 rows are framework- or
guide-level rather than module-shaped (transactional remediation, offline and
bootable recovery, incident triage), or already have substantial module coverage
(backup validation, hardware recovery), and are deliberately out of scope here.

## Remaining work, with current numbers

These were already recorded above as follow-ups. The counts have **grown** since
the roadmap was written, which is worth knowing before scheduling them:

- **P0#7 command-runner migration has not started.** 756 `subprocess.run` calls
  in modules, **0** routed through `rescue.command.run`, 435 with no timeout.
  The roadmap counted 744 and 395.
- **Remediation codes are ~38% migrated.** 169 of 272 pre-existing modules
  declare no `emits_codes`; 30% of `Finding()` constructions set `code=`.
  (`tests/test_module_code_consistency.py` does guard the ones that do.)
- **No CI**, as above.

Verified healthy, for balance: `auto_apply = True` appears in **zero** modules,
so auto mode genuinely is read-only as P0#5 intends; there are no
`NotImplementedError` stubs or placeholder TODOs; the only skipped tests are
correctly conditional on `gpg` being available; and both `setup.py` and
`rescue.spec` glob the content directories, so new modules ship without
packaging changes.
