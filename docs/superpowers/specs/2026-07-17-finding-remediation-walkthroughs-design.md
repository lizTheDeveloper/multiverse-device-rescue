# Finding-Linked Remediation Walkthroughs — Design

**Status:** approved (brainstorming), ready for implementation plan
**Date:** 2026-07-17

## Summary

Scans produce `Finding`s but a user has no in-tool path from a specific finding
to the steps that fix it. This feature gives each finding a stable **code**, lets
**remediation walkthroughs** declare which codes they remediate, builds a
**reverse index** at startup, and surfaces a **"Walkthrough" affordance** on the
findings screen that opens the matching step-by-step guide. A generated
**coverage catalog** documents, in the repo, which scans have a remediation
walkthrough and which are gaps.

This pass ships the full mechanism plus a hand-authored **starter set** of
walkthroughs; the remaining scans surface as gaps in the catalog and are filled
incrementally later.

## Goals

- A finding can name its remediation via a stable, namespaced code.
- Walkthroughs are decoupled from modules: a walkthrough declares the codes it
  remediates; modules never reference walkthrough filenames.
- From the TUI findings screen, a finding with a resolvable code opens its
  walkthrough.
- A repo-committed catalog maps every emittable code → module → walkthrough (or
  marks it a gap), with real links.
- A validation gate keeps codes, `emits_codes`, and `remediates:` consistent.

## Non-Goals

- No walkthrough content for every scan in this pass (starter set only).
- No AI-generated walkthrough content (security-sensitive; authored by hand).
- No cross-restart step-completion persistence (v1 is stateless — see §7).
- No change to the module-level "Apply Fixes" flow or the existing profile
  guides (`guides/<profile>/phase_N.md`); those remain as-is.

## Decisions (resolved in brainstorming)

1. **Core:** findings link to / launch in-tool walkthroughs.
2. **Linkage:** per-finding-type **stable codes** (not per-module, not
   profile-guide-only).
3. **Mapping:** **walkthroughs declare** `remediates: [codes]`; the tool builds a
   reverse index (decoupled).
4. **Scope:** mechanism + high-value **starter set** + coverage catalog.
5. **`emits_codes`** declared on modules (exact catalog + validation gate).
6. **Stateless v1** step completion (no `session` persistence).

## Architecture

### Component overview

| Unit | Responsibility | Depends on |
|---|---|---|
| `Finding.code` (`rescue/models.py`) | Carry the stable finding-type code | — |
| `ModuleBase.emits_codes` (`rescue/module_base.py`) | Declare the codes a module can emit | — |
| `Walkthrough` + parser (`rescue/guides.py`) | Parse `guides/remediation/*.md` incl. `remediates:` | `frontmatter` |
| `rescue/remediation.py` | Load walkthroughs, build `{code → Walkthrough}` reverse index, validate | guides parser, registry |
| `WalkthroughScreen` (`rescue/tui/screens/walkthrough.py`) | Render a walkthrough's steps | guides model, formatting |
| `FindingsScreen` (edit) | Show per-finding "Walkthrough" button when code resolves | remediation index |
| catalog generator (`rescue/remediation.py` + CLI subcommand) | Emit `docs/REMEDIATION_CATALOG.md` | registry, remediation index |

### 1. Finding codes

Add to `rescue/models.py`:

```python
@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    data: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    collected_at: str | None = None
    code: str | None = None   # NEW — stable finding-type code, e.g.
                              # "security.ai_worm_persistence.miasma_launchagent"
```

- **Backward compatible:** default `None`, mirroring how `confidence` was added.
- **Scheme:** `<category>.<module>.<slug>` where `<category>` is the module's
  `category`, `<module>` is the module's `name`, and `<slug>` is a stable,
  lowercase, `snake_case` identifier for the specific finding type. The
  category/module prefix guarantees global uniqueness and greppability.
- A finding may leave `code=None`; it then has no walkthrough affordance.

### 2. `emits_codes` on modules

Add to `rescue/module_base.py`:

```python
class ModuleBase(ABC):
    ...
    emits_codes: list[str] = []   # NEW — every code this module's check() can emit
```

- Lowercase to match existing declarative attributes (`depends_on`, `auto_apply`).
- Starter-set modules populate it; every value must match a `code=` the module
  actually passes to a `Finding` (enforced by test — see §8).
- Non-starter modules leave it `[]` (default), so they contribute no coverage and
  are catalog gaps. No runtime behavior change.

### 3. Remediation walkthroughs (content)

- New directory: `guides/remediation/<slug>.md`. Standalone — **not**
  profile/phase-bound.
- Front-matter:

  ```yaml
  ---
  title: "Remove a Miasma persistence LaunchAgent"
  remediates:
    - security.ai_worm_persistence.miasma_launchagent
  estimated_time: "15 minutes"
  platforms: [macos, linux]        # optional; omit = all
  automatable_steps: []            # existing convention, reused
  human_only_steps: [1, 2, 3]
  ---
  ## Step 1: ...
  ## Step 2: ...
  ```

- Steps use the existing `## Step N: <title>` format so the current parser is
  reused (see §4).

### 4. Guide/parser generalization (`rescue/guides.py`)

The current `Guide` requires `profile` + `phase`. Generalize minimally:

- Make `profile: str | None` and `phase: int | None` optional on `Guide`.
- Add `remediates: list[str] = field(default_factory=list)`.
- `parse_guide_markdown` reads `remediates` (default `[]`) and no longer requires
  `profile`/`phase` (uses `.get`).
- Existing profile guides are unaffected: they still set `profile`/`phase` and
  omit `remediates`.

> Alternative considered: a separate `Walkthrough` dataclass + second parser.
> Rejected — it would duplicate `GuideStep` and the `## Step N:` parsing. One
> model, one parser, keyed differently.

### 5. Reverse index (`rescue/remediation.py` — new)

```python
def load_remediation_walkthroughs(guides_dir: Path) -> dict[str, Guide]:
    """Scan guides/remediation/*.md → {code: Guide}. First-wins on conflict."""
```

- Loaded once at startup, alongside module discovery, via the same
  `_get_guides_dir()` root used elsewhere (works under PyInstaller too).
- Conflicts (two walkthroughs claim one code): keep first, log a warning.
- A walkthrough with an empty `remediates:` is ignored for indexing (warn).
- Lookup helper: `walkthrough_for(code) -> Guide | None`.

### 6. TUI: finding → walkthrough

- **`FindingsScreen`** (`rescue/tui/screens/findings.py`) — **primary entry point**:
  today each finding is a `Static` row and there is one module-level "Apply Fixes"
  button. Change so each finding whose `code` resolves in the reverse index renders
  with an inline **"Walkthrough"** button beneath its row (one button per resolvable
  finding). Findings with no resolvable code render exactly as today. "Apply Fixes"
  is unchanged.
- **`WalkthroughScreen`** (`rescue/tui/screens/walkthrough.py` — new): takes a
  `Guide` (walkthrough) and renders title, estimated time, and each step (number,
  title, body, an "automatable" marker where applicable), reusing existing
  guide/finding formatting helpers. Navigation: pushed when a finding's
  "Walkthrough" button is pressed; `escape` pops. **Stateless:** local, in-screen
  "mark done" toggles only; nothing persisted.
- **`GuidePlaceholderScreen`** (`rescue/tui/screens/fix_result.py:51`) is a
  pre-existing post-fix stub. Concrete rule: replace it with `WalkthroughScreen`
  opened on the walkthrough for the **highest-severity finding-with-a-resolvable-code
  in that module**; if the module has no such finding, the post-fix screen is
  omitted (no placeholder). This keeps a single walkthrough screen and removes the
  stub without inventing module-level walkthrough content.

### 7. Statelessness (v1)

Step completion is visual only, held in `WalkthroughScreen` instance state; it is
not written to `session`/`SessionState`. Rationale: the profile-guide session
machinery is phase-oriented and heavier than needed here. Persisting walkthrough
progress is a clean future addition and is called out as such.

### 8. Coverage catalog

- Generator lives in `rescue/remediation.py`; exposed as a CLI subcommand
  `rescue remediation-catalog` (writes/refreshes `docs/REMEDIATION_CATALOG.md`).
- Data sources: `discover_modules()` → every module's `emits_codes`; the reverse
  index → which codes have a walkthrough.
- Output: a Markdown table sorted by category/module (severity is per-finding at
  runtime, not statically known from a code, so it is intentionally not a column):

  | Code | Module | Walkthrough |
  |---|---|---|
  | `security.ai_worm_persistence.miasma_launchagent` | ai_worm_persistence | [Remove a Miasma persistence LaunchAgent](../guides/remediation/…md) |
  | `security.ssh_key_audit.world_readable_key` | ssh_key_audit | — **gap** |

  Plus a summary line: `N codes, M with walkthroughs (K% covered)`.
- This file is the repo-side "remediation link" artifact.

### 9. Starter content

Author walkthroughs + populate `emits_codes` + set `code=` on findings for:

- `ai_worm_persistence`, `ai_worm_filesystem`, `ai_worm_git_ssh`,
  `ai_worm_network`, `ai_worm_lateral`, `mvt_spyware_scan`.
- A few top-severity generic security scans: `ssh_key_audit`,
  `launchd_persistence_audit` / `launch_agent_audit`, `remote_login_check` /
  `win_rdp_check`, `firewall_audit`.

Exact per-finding slugs are enumerated during implementation (one code per
distinct finding type each module emits). The **dead-man-switch** ordering
warnings already in `ai_worm_persistence` MUST be reflected verbatim in that
walkthrough's step order (disable `gh-token-monitor` before other removal).

## Data flow

```
check() → Finding(code=…) ─┐
                           ├─ FindingsScreen: resolve code in reverse index
guides/remediation/*.md ───┘        │
   (remediates: […]) → load_remediation_walkthroughs() → {code: Guide}
                                    │
                          "Walkthrough" button → WalkthroughScreen(guide)
```

## Error handling

- Missing `guides/remediation/` dir → empty index, no walkthrough buttons (no
  crash).
- Malformed walkthrough front-matter → skip that file, log a warning, continue.
- Code in `remediates:` not declared by any module's `emits_codes` → validation
  test fails (catches typos); at runtime it's simply an unused index entry (warn).
- Finding `code` with no walkthrough → no button (identical to `code=None`).

## Testing

- **Unit:** `Finding.code` default/round-trip; parser reads `remediates` and
  tolerates missing `profile`/`phase`; reverse index build handles duplicates
  (first-wins + warn), empty `remediates`, and missing dir.
- **Validation gate** (matches the repo's existing whole-catalog gate culture):
  1. every walkthrough parses; 2. no two walkthroughs claim the same code;
  3. every code in any `remediates:` is present in some module's `emits_codes`;
  4. every code in a starter module's `emits_codes` is actually emitted by that
  module's `check()` under representative inputs (or asserted via a module-local
  fixture).
- **Catalog:** generator output is deterministic; regenerating is a no-op when
  nothing changed (so it can be a CI check).
- **TUI:** a finding with a resolvable code renders a "Walkthrough" button; the
  button pushes `WalkthroughScreen`; a finding without a code does not.

## Backward compatibility & migration

- `Finding.code` and `ModuleBase.emits_codes` default to `None`/`[]`; unmigrated
  modules and existing tests are unaffected.
- Existing profile guides keep working (parser change is additive).
- No profile YAML changes required.

## Files

**New**
- `rescue/remediation.py` — loader, reverse index, catalog generator
- `rescue/tui/screens/walkthrough.py` — `WalkthroughScreen`
- `guides/remediation/*.md` — starter walkthroughs
- `docs/REMEDIATION_CATALOG.md` — generated

**Edited**
- `rescue/models.py` — `Finding.code`
- `rescue/module_base.py` — `emits_codes`
- `rescue/guides.py` — optional `profile`/`phase`, `remediates`
- `rescue/tui/screens/findings.py` — per-finding walkthrough button
- `rescue/tui/screens/fix_result.py` — repoint `GuidePlaceholderScreen`
- `rescue/cli.py` — `remediation-catalog` subcommand; load index at startup
- starter modules under `modules/security/*` — `emits_codes` + `code=`

## Open questions

None blocking. Future: persist walkthrough step completion via `session`;
expand starter set to full coverage; per-step "automate this" execution hooks.
