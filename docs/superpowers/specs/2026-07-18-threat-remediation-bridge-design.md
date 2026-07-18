# Two-Way Threat ↔ Remediation Bridge — Design

**Status:** approved (brainstorming), ready for implementation plan
**Date:** 2026-07-18

## Summary

The Multiverse School security curriculum describes threats (AI worms, mobile
spyware, credential compromise…); Multiverse Device Rescue can actually *check
and remediate* those threats on a real machine. Today the two are disconnected.
This feature builds a **two-way bridge** from a single source of truth: a
validated YAML in the tool repo maps ~8 curated **threat types** to the tool's
profiles, finding-code clusters, and the curriculum write-up each pairs with.
From that YAML the tool generates a public `docs/THREAT_REMEDIATION.md`; the
curriculum gains "Remediate on your own device →" links pointing back at it.

Two phases: **Phase 1** (tool repo — YAML, validation gate, generator, doc,
README pointer) is a self-contained, TDD-able unit. **Phase 2** (curriculum —
reverse-link callouts in the vault note + republished `/x/` page) is content
wiring that consumes Phase 1's anchors.

## Goals

- One source of truth (the YAML) that names, for each threat type, the exact
  `rescue` profile and finding-code cluster that remediate it, plus the
  curriculum URL that explains it.
- A validation gate so the map cannot name a profile or code that doesn't exist.
- A generated, public tool-side doc (`THREAT_REMEDIATION.md`) a curriculum
  reader can act on: "run `rescue --profile X`."
- Curriculum threat content that links out to that remediation, on both the
  vault note and the published `/x/` page.

## Non-Goals

- No per-case (129) or per-code (61) mapping — threat-type granularity only.
- No new hosted landing page; the public GitHub repo + generated doc is the
  link target (repo is PUBLIC, install-from-source).
- No change to the existing remediation walkthroughs, catalog, or scan modules.
- No Obsidian-Publish push; Phase 2 updates the git vault + the `/x/` DB page
  only (the public teaching surface), matching prior practice.

## Decisions (resolved in brainstorming)

1. Two-way bridge with a **shared source of truth**.
2. Source of truth = **validated YAML in the tool repo**, **threat-type
   granularity** (~8 types).
3. Link target for curriculum → tool = the tool's generated
   `docs/THREAT_REMEDIATION.md` (public repo).
4. Curriculum reach = the **AI-Assisted Hacking case studies** note (both vault
   + `/x/agentic-ai-security-cases`) plus a one-line pointer in the Course Index.

## Architecture

### Component overview

| Unit | Repo | Responsibility |
|---|---|---|
| `docs/threat_remediation_map.yaml` | tool | Source of truth: threats → profile/codes/curriculum_url |
| `rescue/threat_map.py` | tool | Load + validate the map; render the doc |
| `rescue threat-remediation` subcommand | tool | Write `docs/THREAT_REMEDIATION.md` |
| `tests/test_threat_map_validation.py` | tool | Gate: profiles/codes exist, fields present, ids unique |
| `docs/THREAT_REMEDIATION.md` | tool | Generated public doc (link target) |
| README pointer | tool | Discoverability |
| AI-Assisted Hacking note + `/x/` page | curriculum | Reverse links to the doc |
| Course Index pointer | curriculum | One-line "check your device" pointer |

### Phase 1 — tool repo

**1. `docs/threat_remediation_map.yaml`** — a list of threat entries:

```yaml
threats:
  - id: ai-worm-supply-chain
    title: "AI worm / malicious package supply-chain compromise"
    summary: >
      Self-propagating worms (Shai-Hulud, Miasma) spreading via npm/git/SSH and
      AI-agent tooling, planting persistence and C2.
    run:                       # exactly ONE of: profile | modules | full
      profile: ai_worm_response
    codes:
      - "security.ai_worm_persistence.*"
      - "security.ai_worm_filesystem.*"
      - "security.ai_worm_git_ssh.*"
      - "security.ai_worm_lateral.*"
    curriculum_url: "https://themultiverse.school/x/agentic-ai-security-cases"
    curriculum_section: "Criminal Tooling & AI-Written Malware"
```

- `id` — kebab-case, unique; becomes the anchor in `THREAT_REMEDIATION.md`.
- `run` — exactly one of: `profile: <name>` (a real profile in
  `profiles/*.yaml`) → `rescue --profile <name>`; `modules: [<m>…]` (real module
  names) → `rescue run <m…>`; `full: true` → `rescue` (full interactive scan).
- `codes` — exact codes or `namespace.*` globs; each MUST resolve to ≥1 real
  code in the union of all modules' `emits_codes`.
- **Coverage rule (validated):** the set of modules that OWN the threat's
  resolved `codes` MUST be covered by the run target — a subset of the profile's
  effective modules (`include` − `exclude`), of the explicit `modules` list, or
  trivially satisfied by `full`. This guarantees "run this" actually scans what
  the threat needs. (Real profile module sets are narrow: `ai_worm_response` =
  the 6 `ai_worm_*`/`mvt` modules; `digital_security_reset` includes
  `remote_login_check` but NOT `ssh_key_audit`/`firewall_audit`/`win_rdp_check`;
  the launch-persistence modules are in no profile — hence the `modules`/`full`
  run targets.)
- `curriculum_url` — required, non-empty; `curriculum_section` — the human
  section name (used in the doc text; the `/x/` markdown renderer does not emit
  heading anchors, so we link to the page, not a fragment).

**Draft threat set (8)** — run targets chosen so the coverage rule holds
(verify code globs + module membership during impl):
1. `ai-worm-supply-chain` → `profile: ai_worm_response` (ai_worm_persistence/filesystem/git_ssh/lateral — all in the profile)
2. `mobile-spyware` → `profile: ai_worm_response` (mvt_spyware_scan — in the profile)
3. `credential-ssh-compromise` → `modules: [ssh_key_audit]` (in no profile)
4. `unwanted-remote-access` → `modules: [remote_login_check, win_rdp_check]` (cross-platform; win_rdp_check in no profile)
5. `launch-persistence-malware` → `modules: [launchd_persistence_audit, launch_agent_audit]` (in no profile)
6. `network-c2-beaconing` → `profile: ai_worm_response` (ai_worm_network — in the profile)
7. `weak-firewall-exposure` → `modules: [firewall_audit]` (in no profile)
8. `general-device-compromise` → `full: true` (catch-all full scan; may list a broad `codes` set for context)

**2. `rescue/threat_map.py`**
- `load_threat_map(path) -> list[Threat]` — parse YAML into dataclasses
  (`Threat` holds `id, title, summary, run, codes, curriculum_url,
  curriculum_section`; `run` is a small dataclass with optional
  `profile`/`modules`/`full`).
- `expand_codes(code_patterns, all_codes) -> set[str]` — resolve exact codes +
  `namespace.*` globs against the real code universe.
- `modules_for_codes(codes) -> set[str]` — owning module of each code, parsed
  from the `<category>.<module>.<slug>` scheme (`code.split(".")[1]`).
- `run_target_modules(run, profiles) -> set[str] | None` — the modules a run
  target scans: profile's effective set (`profiles[name]`), the explicit
  `modules` set, or `None` for `full` (means "all modules — always covers").
- `validate_threat_map(threats, profiles, all_codes, all_modules) -> list[str]`
  — human-readable errors (empty = valid): a `run` block with != 1 target;
  unknown profile; unknown module in `modules`; a `codes` pattern resolving to 0
  real codes; **owning-modules NOT ⊆ run-target modules** (coverage rule; skipped
  for `full`); missing/empty `title`/`summary`/`curriculum_url`; duplicate `id`.
  `profiles` is `dict[profile_name, set[module_name]]` (effective = include −
  exclude); `all_modules` is the set of real module names.
- `render_threat_markdown(threats, profiles) -> str` — the doc (see below).

**3. `rescue threat-remediation` subcommand** (`rescue/cli.py`, Click) —
discovers modules (real module names + union of `emits_codes`), loads profile
effective-module sets from `profiles/*.yaml`, loads + validates the map (print
the error list and exit non-zero on any failure — generate nothing from an
invalid map), else writes `_project_root() / "docs" / "THREAT_REMEDIATION.md"`.

**4. `docs/THREAT_REMEDIATION.md`** (generated) — per threat: `## <title>`
(anchor = `id`), the summary, a **Run:** line rendered from the run target
(`rescue --profile <name>` | `rescue run <m…>` | `rescue`), the resolved
codes / linked walkthroughs it covers, and **Learn more:** the `curriculum_url`
(with `curriculum_section` as the link text). Header note "generated by
`rescue threat-remediation`, do not edit."

**5. Validation gate** `tests/test_threat_map_validation.py` — over the real
shipped map + real profiles/modules: `validate_threat_map(...)` returns no
errors (this single call exercises run-target validity, code resolution, the
coverage rule, required fields, and id uniqueness).

**6. README pointer** — a line under a "Threat coverage" heading linking to
`docs/THREAT_REMEDIATION.md`.

### Phase 2 — curriculum repo + published `/x/`

- **Vault note** `Curriculum/CyberSecurity/Agentic AI Security/AI-Assisted
  Hacking — Case Studies.md`: add a compact **"Remediate on your own device"**
  section near the top (after the existing intro callouts) that lists each
  threat → `Run Multiverse Device Rescue: rescue --profile <p>` linking to the
  matching `THREAT_REMEDIATION.md#<id>` anchor on the public repo. Plus a
  one-line inline pointer under the two most device-relevant category headings
  (`Real-World Incidents`, `Criminal Tooling & AI-Written Malware`).
- **Course Index** note: one line under an appropriate spot — "Worried you're
  affected? Check and remediate your own device with [Multiverse Device
  Rescue](…THREAT_REMEDIATION.md)."
- **Publish:** commit + push the vault (git only, no Obsidian Publish), then
  update the `/x/agentic-ai-security-cases` page (page id 1151) in place via the
  documented SQL `UPDATE` through the app container (per
  `docs/AGENT_PUBLISHING_GUIDE.md`), and the HedgeDoc index note if the Course
  Index pointer is added there. Re-run the earlier wiki-link→absolute conversion
  for the republished `/x/` content.

### The two-way property

Curriculum → tool: reverse-link callouts point to `THREAT_REMEDIATION.md#<id>`.
Tool → curriculum: each generated entry's **Learn more** points to
`curriculum_url`. Both URLs live in the one YAML entry, so they cannot diverge.

## Data flow

```
threat_remediation_map.yaml ──load+validate──> Threat[]
        │                                         │
        │ (validate against profiles/ + emits_codes)
        ▼                                         ▼
  gate test                         render_threat_markdown → docs/THREAT_REMEDIATION.md (public)
                                                  ▲                         │
     curriculum note "Remediate…" links ──────────┘   Learn-more links ─────┘→ /x/ curriculum page
```

## Error handling

- Map names a missing profile / a code-glob matching nothing / a missing field
  → `validate_threat_map` reports it; the subcommand aborts non-zero and the
  gate test fails. Nothing is generated from an invalid map.
- Missing map file → subcommand errors clearly; gate test fails loudly.
- `/x/` update: unknown page id → no-op row count 0 (surface it), never silent.

## Testing

- Unit: `expand_codes` (exact + glob + no-match); `modules_for_codes` (parses
  owner module); `run_target_modules` (profile set / explicit modules / full→None);
  `validate_threat_map` — each error class produces exactly one error and a good
  map produces none: two-target `run`, unknown profile, unknown module,
  zero-resolving glob, **coverage violation (a code whose owning module is not in
  the run target)**, missing field, duplicate id; `render_threat_markdown` (all
  three Run-line variants, per-threat anchor, curriculum link, summary present).
- Gate (real content): the shipped `threat_remediation_map.yaml` validates
  clean against real profiles + `emits_codes`.
- Generator determinism: regenerating with no change is a no-op (CI-checkable).

## Backward compatibility

Purely additive in the tool repo (new file, module, subcommand, doc, test); no
change to existing modules, profiles, walkthroughs, catalog, or the earlier
`remediation-catalog` command. Phase 2 only adds content to curriculum files.

## Files

**New (tool):** `docs/threat_remediation_map.yaml`, `rescue/threat_map.py`,
`docs/THREAT_REMEDIATION.md` (generated), `tests/test_threat_map.py`,
`tests/test_threat_map_validation.py`.
**Edited (tool):** `rescue/cli.py` (subcommand), `README.md` (pointer).
**Edited (curriculum):** `AI-Assisted Hacking — Case Studies.md`, `Agentic AI
Security — Course Index.md`; republished `/x/agentic-ai-security-cases` (+ HedgeDoc
index if the Course-Index pointer lands there).

## Open questions

None blocking. Future: extend the map as new scan modules gain codes; consider a
dedicated `/x/` "Device Rescue" landing page if the GitHub README proves too
technical for the target reader.
