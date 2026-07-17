# Device Rescue Toolkit Roadmap

## Review scope

This roadmap is based on a source review performed on 2026-07-09. It covers
the command-line interface, TUI, module registry and orchestration, profiles
and guides, profiler, update and trust code, packaging configuration, and the
test suite. It is a planning document, not a claim that every finding has been
reproduced on each supported operating system.

## Current position

The toolkit has a broad collection of point-in-time checks, grouped as
performance, integrity, security, network, and bloatware modules. The source
tree currently discovers 259 modules:

| Area | Modules |
| --- | ---: |
| Integrity | 103 |
| Security | 97 |
| Performance | 50 |
| Network | 5 |
| Bloatware | 4 |
| macOS support declared | 181 |
| Windows support declared | 81 |
| Linux support declared | 3 |

This is a strong inventory of ideas, but it is not yet a dependable rescue
product. The highest-value work is making diagnostics bounded and trustworthy,
making remediation truthful and reversible, and ensuring that the distributed
tool contains and uses its declared content.

## Priority problems

### P0 — Release blockers and safety risks

1. **The standard Python package omits runtime content.**
   `pyproject.toml` packages `rescue*` only, while modules, profiles, guides,
   JSON data, the TUI stylesheet, and security JSON are external runtime files.
   The generated `multiverse_device_rescue.egg-info/SOURCES.txt` contains none
   of those assets. Source-checkout and PyInstaller paths are handled
   differently, so a normal `pip` install is not a complete product.

2. **Signed content updates do not affect what the application executes.**
   The updater checks out content into `~/.local/share/rescue/content`, but
   module discovery and guide/profile loading continue to use the project or
   bundled root. The content manifest is only used to display a version; it is
   not validated or activated as a runtime content source. Therefore an
   apparently successful update does not update modules, profiles, or guides.

3. **The update trust configuration is a placeholder.**
   `rescue/security/trusted_signers.json` contains replacement strings instead
   of real public keys and identifiers. No production update can receive the
   required two valid approvals until a real trust root, key rotation process,
   and release procedure exist.

4. **The self-integrity signal is already invalid and non-blocking.**
   The checked-in manifest reports two modified files and eleven added package
   files during this review. Startup verification warns but catches every
   exception and always continues; added files also do not make the integrity
   result fail. This makes the result unsuitable as a release or safety gate.

5. **`SAFE` does not mean safe enough for unattended repair.**
   Of the discovered modules, 253 are marked `SAFE`; auto mode runs all of
   them with findings. Some `SAFE` modules directly change system state, such
   as starting Windows Update, enabling Defender real-time protection, or
   updating Defender signatures. Other safe-labelled modules recommend
   irreversible shell commands such as deleting caches or emptying Trash.
   Risk must be assigned to each proposed action, not only to a module.

6. **The application blurs advice and completed remediation.**
   Static review found direct subprocess execution in only six module `fix()`
   methods. Many other `fix()` methods produce instructional text but mark an
   action successful, which the CLI and TUI display as a completed fix. Users
   cannot reliably distinguish an observation, a manual instruction, and a
   system change.

7. **Checks can hang or abort an entire rescue session.**
   Module execution is serial and has no orchestrator-level timeout,
   cancellation, error isolation, or resource budget. A static scan found 739
   `subprocess.run` calls in modules, 395 without a timeout. Recursive scans
   can traverse real user configuration directories without a time or file
   limit. The full 3,031-test suite currently stalls in
   `test_module_ai_threat_indicators` after it begins such a scan.

8. **The security-reset profile is nonfunctional.**
   `digital_security_reset` names `password_manager_check`, `twofa_audit`, and
   `session_revocation_scan`, but none is registered. Its profile therefore
   selects no modules while its guide presents those checks as automatable.

9. **Linux is advertised but cannot run.**
   Three modules declare Linux support, but `gather_profile()` raises
   `NotImplementedError` for Linux before module execution begins.

10. **Module discovery executes arbitrary local Python code.**
    Registry discovery imports every module from a mutable filesystem tree.
    There is no module manifest, schema validation, signature verification, or
    process isolation. This is especially important for a security tool that
    may be run on a suspected compromised device.

### P1 — Product reliability and usability gaps

1. **No diagnostic evidence model.** Findings do not consistently carry the
   command, timestamp, scope, permissions, raw evidence reference, confidence,
   or a distinction between “healthy,” “not checked,” and “check failed.”

2. **No rescue case record.** There is no redacted export containing findings,
   actions actually taken, action outcomes, operator confirmations, rollback
   information, or post-fix verification. Session progress records only guide
   step numbers.

3. **No standard command runner.** Subprocess handling, privilege assumptions,
   parsing, errors, and timeouts are implemented independently in modules.
   Several Windows checks depend on deprecated WMIC, and there is no tested
   compatibility matrix for supported OS versions, CPU types, or permissions.

4. **No graceful degradation.** An exception from one `check()` or `fix()` can
   stop CLI, TUI, auto-mode, or AI explanation workflows. Dependency cycles,
   missing dependencies, and the declared priority and duration metadata are
   not validated or fully used.

5. **TUI flows are incomplete.** Guides in the TUI are explicitly a placeholder
   even though CLI guide storage exists. Long scans have no visible per-module
   progress, skip/retry controls, cancellation, or a clear “manual action
   required” result.

6. **Documentation and operator boundaries are missing.** The repository has
   no root README, supported-platform policy, privacy statement, permission
   guide, threat-model statement, recovery disclaimer, or contribution and
   release documentation.

### P2 — Missing rescue techniques

Existing modules cover many single checks. The following are missing as
coherent, evidence-driven rescue techniques rather than another collection of
isolated checks:

| Technique | Why it matters | Suggested scope |
| --- | --- | --- |
| Incident triage and containment | A compromised device needs a safe order of operations before cleanup. | Offline/clean-device warning, network-isolation guidance, evidence preservation, account recovery order, and escalation criteria. |
| Evidence collection and forensic handoff | Repair can destroy the information needed to understand a compromise. | Redacted evidence bundle, hashes, timestamps, provenance, encrypted export, and explicit chain-of-custody mode. |
| Baselines and differential scans | A single snapshot cannot identify what changed. | Signed baseline of persistence, services, extensions, network configuration, and critical security settings; display only meaningful diffs. |
| Trust and reputation verification | File-name and keyword checks create false positives. | Code-signing/notarization validation, package provenance, file hashes, local IOC/YARA-style rules, and optional privacy-preserving reputation lookups. |
| Offline and bootable recovery | Some malware cannot be assessed safely from the running OS. | Guided safe-mode/recovery-environment workflows, offline scanner integration, and clear limits when full forensic tooling is required. |
| Backup and restore validation | Backup presence does not prove recovery is possible. | Backup freshness, encryption, destination capacity, restore-point inventory, sampled restore drill, and recovery-key handling without collecting secrets. |
| Transactional remediation | Rescue actions must be reviewable and reversible. | Action plan, preflight backup/snapshot where supported, least-privilege elevation, change journal, rollback, and post-action recheck. |
| Account and browser recovery | Security-reset guidance currently promises capabilities that do not exist. | Human-led account inventory, password-manager migration checklist, session/device review links, extension inventory, and secure deletion guidance. Never collect account passwords or tokens. |
| Hardware recovery workflow | Device rescue also needs to distinguish hardware faults from software issues. | Unified storage, battery, thermal, memory, display, input, and network-adapter evidence with vendor diagnostics and repair/escalation thresholds. |
| Cross-platform recovery | Linux is inoperable and mobile is only mentioned in guides. | Finish Linux first; then build separate, permission-aware Android/iOS companion workflows instead of pretending desktop modules apply to mobile. |

## Phased delivery plan

### Phase 0 — Establish a trustworthy, shippable core

**Goal:** make every shipped result accurate, bounded, and safe to act on.

1. Define supported operating systems, versions, architectures, privilege
   expectations, and distribution channels. Mark unsupported paths clearly.
2. Make runtime assets first-class package data, or replace filesystem module
   discovery with an installed package/plugin mechanism. Add clean-environment
   tests for `pip` installation and PyInstaller execution.
3. Redesign the content update path: validate a signed manifest and schema,
   stage content, atomically activate it in the runtime content root, retain a
   previous version for rollback, and show the active content version.
4. Replace placeholder signer entries with real immutable trust roots. Add key
   rotation, revocation, expiration, threshold-approval, and release-signing
   procedures. Regenerate and verify the integrity manifest in release CI.
5. Introduce a central command runner with argument allowlists, timeout,
   cancellation, output-size limits, locale handling, redaction, and structured
   error outcomes. Prohibit direct subprocess calls in modules after migration.
6. Separate `observe`, `guide`, and `mutate` actions in the module contract.
   A guide must never render as a successful fix. Each mutation needs its own
   risk, privilege, side effects, rollback plan, and post-action verification.
7. Restrict auto mode to explicitly idempotent, low-impact mutations after
   preflight; make the default auto mode read-only until that catalog is
   reviewed. Require an action-by-action preview and confirmation for every
   destructive or externally visible change.
8. Add per-module exception isolation, retries only where safe, execution
   budgets, and cancellation. Bound filesystem traversal by roots, depth,
   file count, bytes, and time.
9. Remove or repair the unavailable security-reset module references and add a
   profile validation test that fails on every missing module, guide, or
   automatable step.

**Exit criteria**

- A clean `pip` install and the bundled executable discover the same declared
  content and run a read-only scan.
- A signed staged update changes the active content version; an invalid update
  cannot alter active content; rollback restores the previous version.
- Every action is accurately labelled as observation, manual guidance, or
  mutation, and mutation results include a recheck outcome.
- The full test suite completes with no access to uncontrolled user directories
  or network services.

### Phase 1 — Build the diagnostic and rescue foundation

**Goal:** turn module output into reliable case evidence and a usable workflow.

1. Version a richer result schema: status, severity, confidence, collection
   time, platform support, command/evidence reference, redacted details, and
   remediation eligibility.
2. Create a rescue-case record that exports a redacted JSON report and a
   human-readable summary. Record confirmations, exact mutations, failures,
   rollback steps, and post-fix checks.
3. Validate registry metadata at startup and in CI: unique names, valid
   dependencies, no cycles, compatible platforms, risk declaration, and
   actionable support documentation.
4. Make execution scheduling intentional: prioritize critical read-only checks,
   use bounded concurrency only for safe operations, show progress and elapsed
   time, and support skip, retry, and cancel in CLI and TUI.
5. Complete the TUI guide flow using the existing guide/session model, with
   real progress, links to the required modules, and an explicit split between
   automatable and human-only steps.
6. Add baseline/diff and report export primitives before increasing the module
   count.

**Exit criteria**

- A user can save, resume, export, and review a rescue case without exposing
  credentials or raw tokens.
- A failed or unsupported check appears as such and never stops unrelated
  checks.
- Every guide references registered capabilities and has automated-step
  verification where it claims automation.

### Phase 2 — Deliver high-value rescue techniques

**Goal:** add techniques that materially improve recovery decisions.

1. Implement incident triage: compromise severity questions, clean-device and
   network-isolation guidance, evidence-preservation mode, and clear advice to
   seek professional or emergency support when appropriate.
2. Add persistence and trust analysis based on baselines: launch agents,
   scheduled tasks, services, browser extensions, login items, remote access,
   code signatures, and package provenance.
3. Add a local IOC rule engine with versioned, signed rule data and fixtures.
   Treat heuristic matches as leads with confidence and evidence, not proof of
   compromise.
4. Add backup/restore readiness checks and a guided, opt-in restore drill.
5. Build a unified hardware diagnosis summary with explicit repair escalation
   thresholds; integrate vendor diagnostics only through documented adapters.
6. Replace generic cleanup guidance with an inventory, reclaimable-space
   estimate, selection UI, backup/Trash behavior, and reversible actions where
   possible.

**Exit criteria**

- The toolkit can produce a redacted incident bundle, a baselined persistence
  diff, and a verified backup-readiness report from the same rescue case.
- Heuristic security findings provide evidence, confidence, and safe next
  steps rather than automatically labelling normal software as malicious.

### Phase 3 — Make platform support real

**Goal:** support each advertised platform end to end.

1. Implement the Linux profiler and a small supported Linux module set using
   documented distributions and package managers. Do not list Linux in module
   metadata until the end-to-end scan works.
2. Replace WMIC dependencies with supported PowerShell/CIM APIs and test on
   supported Windows releases with standard and elevated permissions.
3. Test macOS Intel and Apple Silicon separately; verify modern macOS privacy,
   TCC, SIP, and sealed-system-volume behavior.
4. Design Android and iOS as separate companion workflows with their actual
   permission and sandbox constraints. Keep account recovery and human steps
   clearly separate from device telemetry.

**Exit criteria**

- Platform claims are backed by CI or release-candidate smoke tests on each
  platform and privilege level.
- Unsupported checks return an explicit “not supported” outcome with a manual
  alternative, not a false healthy result.

### Phase 4 — Harden the extension and release ecosystem

**Goal:** make the toolkit safe to extend and maintain.

1. Move extension metadata and detection content to a declarative, signed
   schema. Run third-party or high-risk analyzers in a constrained subprocess
   with a stable protocol rather than importing arbitrary Python in-process.
2. Publish a module authoring contract, security review checklist, fixture
   format, compatibility policy, and deprecation process.
3. Add SBOMs, reproducible builds where practical, signed release artifacts,
   vulnerability/dependency scanning, and independent verification instructions.
4. Add privacy controls for AI features: explicit data minimization, local-only
   option, provider disclosure, redaction before transmission, retention
   disclosure, and no AI-driven mutation authority.
5. Publish operator documentation: quick start, safe-use boundaries, supported
   platforms, permissions, recovery playbooks, incident escalation, and
   contribution/release guides.

## Sequencing rules

- Do not add more automatic fixes until Phase 0 action semantics, timeout, and
  rollback requirements are in place.
- Do not publish or advertise updates until real signer material, package-data
  delivery, active-content switching, and rollback are tested end to end.
- Do not describe a guide step as automatable until it resolves to a registered
  module and its outcome can be verified.
- Prefer removing duplicate or weak heuristic modules over increasing the raw
  module count. Depth, evidence, and recovery safety are more valuable than
  breadth.

## Recommended first milestone

Create a "trustworthy read-only scan" release. It should ship complete assets,
run only bounded read-only collection by default, report evidence and
unsupported checks honestly, complete reliably on supported macOS and Windows,
validate profiles, and make the full test suite deterministic. This establishes
the safety and delivery foundation needed before the toolkit performs broader
repair or incident-response actions.
