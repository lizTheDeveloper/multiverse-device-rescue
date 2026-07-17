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

## P0 status

| # | Item | Status | Notes |
| - | ---- | ------ | ----- |
| 1 | Package omits runtime content | **DONE (verify)** | `setup.py` ships `modules/ profiles/ guides/` as `data_files` under `share/multiverse-device-rescue`; `runtime.bundled_root()` resolves there. Needs clean-venv pip-install test. |
| 2 | Content updates don't activate | **DONE (verify)** | `runtime.py` gates `active_content_root()` on a `rescue-applied-head` marker; `content_directory/file` prefer applied content. Needs an activation/rollback test. |
| 3 | Trust config is placeholder | **HUMAN REQUIRED** | `trusted_signers.json` still holds `REPLACE_WITH_...`. Real keys need human custody + rotation policy. Can add: schema validation + a test that fails on placeholder values in release mode. |
| 4 | Self-integrity non-blocking | **DONE** | `integrity.py` now sets `ok = not tampered and not missing and not added`. Startup gate behavior still to confirm. |
| 5 | SAFE ≠ safe for auto | **PARTIAL** | Auto mode still runs every SAFE module with findings. Need read-only default + per-action risk gating. |
| 6 | Advice vs remediation blurred | **PARTIAL** | `ActionKind.{GUIDANCE,MUTATION}` exists; `report()` labels GUIDANCE as "MANUAL ACTION REQUIRED". Need to enforce guide-never-counts-as-success across CLI/TUI + audit modules. |
| 7 | Checks can hang / no bounds | **LARGELY OPEN** | No orchestrator timeout/cancel/budget. ~744 of 754 `subprocess.run` calls lack a same-line timeout. No traversal bounds helper. **Biggest real work.** |
| 8 | security-reset profile nonfunctional | **OPEN** | `password_manager_check`, `twofa_audit`, `session_revocation_scan` still unregistered. Need modules (or profile repair) + a validation test. |
| 9 | Linux advertised but can't run | **DONE** | `profiler/linux.py` implemented; `gather_profile()` dispatches to it. |
| 10 | Discovery executes arbitrary Python | **HUMAN/PHASE-4** | Registry still imports every module in-process. Sandboxing is a Phase-4 architecture change; out of milestone scope. |

## Milestone work plan (this branch)

Sequenced by verifiability (tightest outward), per advisor guidance:

1. **Test determinism baseline** — confirm full suite completes; capture result.
2. **Bounded execution (P0#7)** — central `subprocess` timeout default + a
   `bounded_walk` traversal helper (roots/depth/count/bytes/time); orchestrator
   per-module timeout + overall budget with error isolation. TDD each.
3. **Package data verification (P0#1)** — clean-venv `pip install .` + read-only
   scan smoke test.
4. **Profile validation (P0#8)** — failing test first, then repair
   `digital_security_reset` (register the three modules or scope the profile).
5. **Action semantics (P0#5/#6)** — default scan read-only; guide never renders
   as a completed fix; per-action risk required for auto mutations.
6. **Richer result schema (P1#1)** — add status/confidence/collection-time/
   evidence to `Finding` without breaking existing modules.
7. **Trust schema guard (P0#3, partial)** — validate signer schema; fail on
   placeholder values; document the human key-custody steps.

## Explicitly NOT completable by this pass (report to human)

- P0#3 real signer keys, rotation, revocation, threshold approvals.
- P0#10 process isolation / plugin sandbox (Phase 4).
- Phase 3 platform CI on real macOS Intel + Apple Silicon + Windows + Linux.
- Phase 4 SBOMs, reproducible/signed release artifacts, dependency scanning.
- Android/iOS companion workflows.
- Vendor hardware-diagnostic adapters.
