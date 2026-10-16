# Game mode A: device missions

**Status:** approved in brainstorming 2026-10-15; written spec pending review.
**Part of:** [Consumer security game: overview](2026-10-16-consumer-security-game-overview.md)
**Goal:** the desktop app can show a scan as a Reclaim City-style city. Each real
finding is a mission (briefing, fix, re-check, debrief), and a building lights up
only when the engine confirms the problem is gone.

## 1. Overview

Today the results screen (`renderResults`, `desktop/renderer/app.js`) is a list of
finding cards grouped by severity. This spec adds a second view of the same scan,
**City**, built from Reclaim City's own screens, plus the engine and IPC support it
needs to re-check a single module.

### Decisions made in brainstorming

| Question | Decision |
| --- | --- |
| Where game mode runs | Bundled in the Electron app, offline. It is not the hosted game. |
| How the game code gets in | A git submodule, `desktop/vendor/reclaim-city/`, pinned to a commit on privacy-the-game `origin/main`. |
| Keeping it off the network | Set the game's own analytics switch-off. Never load the Sentry global. CSP stays `default-src 'self'`. |
| City layout | One district per finding category. Each finding is one building with one mission. |
| When a mission counts as done | When a re-check of that module no longer reports the finding. |

### Non-goals

- No account districts. That is [Spec B](2026-10-16-game-mode-one-city-design.md).
- No teaching missions before the scan. That is [Spec C](2026-10-16-game-mode-training-grounds-design.md).
- No changes to the privacy-the-game repo. If a vendored module turns out unusable
  as it is, a small upstream PR is a fallback (section 8). The plan is not to need one.
- No new kinds of fix. The game offers exactly the fixes and marks the list view
  offers.
- No sync with the hosted game, and no player accounts.

## 2. Architecture

```
desktop/
  vendor/reclaim-city/            git submodule (privacy-the-game), pinned
  renderer/
    index.html                    gains a <div id="city"> host and the game stylesheet
    app.js                        List/City switch; the Welcome button
    game/
      boot.js                     sets the opt-out keys, then imports everything else
      controller.js               the screen state machine (section 4)
      findings-to-city.js         pure: scan doc → {districts, accounts, missions}
      progress.js                 pure + storage: mission status, reconciliation
      gate.js                     pure: whether game mode is offered at all
      fonts/                      Orbitron, Inter and JetBrains Mono (local copies)
  main.js                         + 'recheck-module' IPC
  engine-runner.js                + runRecheck(module)
  fix-policy.js, mark-policy.js   + rememberModule(doc, module)
rescue/cli.py                     scan + --module <name>
```

### 2.1 The vendored code

These parts of `desktop/vendor/reclaim-city/src/` are loaded:

- `screens/city-map.js`, `district.js`, `briefing.js`, `debrief.js`, `milestone.js`
- `components/scout.js`, `building.js`, `city-lights.js`, `hud.js` (only if it
  renders without the payment links; otherwise not loaded)
- `utils/calc.js`, `mission-status.js`, `keyboard.js`, `bursts.js`, `lights.js`
- `style.css` and `assets/`

Never loaded: `src/app.js`, `src/index.html`, `src/sw.js`, `utils/analytics.js`,
`utils/errors.js` (it is imported from `state.js`, see section 8),
`utils/collective.js`, `utils/restore-send.js`, `screens/city-together.js`,
`screens/ghost.js`.

The renderer loads `game/boot.js` as `<script type="module">`. The first thing
`boot.js` does is set `reclaim-city.analytics-off = "1"` and `umami.disabled = "1"`
in localStorage. Only then does it use dynamic `import()` for the controller, which
imports the vendored modules. The game's `index.html`, the only place the Umami
loader and the Sentry CDN script exist, is never used.

The vendored `style.css` expects Google Fonts. Game mode loads local `@font-face`
copies from `game/fonts/` instead (all three faces are under the SIL Open Font
License), so the look survives the CSP.

### 2.2 Engine: re-check one module

Add `--module <name>` to `rescue scan`. It can be repeated, and it is mutually
exclusive with `--profile`. The scan runs only the named modules, with the same
read-only path and the same JSON output (including `remediation`, `fixable`,
`markable` and `made_by`). An unknown module name exits `1` and lists the valid
names on stderr, the same way `rescue run` does. Update `docs/cli.md`, which also
still says `scan` takes no profile.

### 2.3 IPC and gatekeeping

- `engine-runner.js`: `runRecheck(moduleName)` spawns
  `scan --json --module <name>`. The name must match `^[a-z0-9_]+$`, the same rule
  as profile and fix names.
- `main.js`: `ipcMain.handle('recheck-module', …)` runs it, then calls
  `fixPolicy.rememberModule(doc, name)` and `markPolicy.rememberModule(doc, name)`.
- `remember(doc)` replaces the whole allowance today. `rememberModule` replaces only
  the entries for that one module and leaves the rest of the last full scan's
  allowance alone. After a re-check, a fix for that module is allowed only if the
  re-check offered it again.
- `preload.js` exposes `rescue.recheckModule(name)`.

## 3. Turning a scan into a city (`findings-to-city.js`)

This is a pure function from the scan doc and the worry the person picked to the
data shapes Reclaim City's screens already take.

| Scan | City |
| --- | --- |
| `category` (`security`, `network`, `integrity`, `performance`, `bloatware`) | A device district: The Gatehouse, The Wires, The Foundations, The Engine Room, The Junkyard. The names are placeholders for review (section 9). Each is a facility-type district with plain descriptions. |
| A finding with `severity` `critical` or `warning` | One building (an `account` in game terms) plus one mission, keyed by the finding's identity (below). |
| `severity` | The building's `riskLevel`: critical → high, warning → medium. |
| A finding with `severity` `info` | No mission. It is listed in the district's **Notes** panel. |
| `remediation.steps` | `mission.steps`, using the steps in `steps_for[code]` when present. If there's no walkthrough, the steps are the "What to do" part of `description`. |
| `description` | The briefing text. Scout's line is a short fixed template for each severity, so no new prose is invented for each finding. |
| `fixable` / `markable` | Briefing actions: "Fix it for me" and "This is mine". |
| A module with `supported: false` or `status: "error"` | Its category's district shows **fog**, with the line "Couldn't check here. That doesn't mean it's safe." It also lists which checks couldn't run. A district made only of failed checks is entirely fog, never "clear". |
| A category with no findings and no failed checks | The district is shown lit, labeled "Nothing found here." |

**Finding identity:** `code` plus a stable part of `data` that the module provides,
such as the plist path or the program path. Where `markable.id` exists, that is the
identity. Otherwise it is `code` plus a hash of the module's identity fields, and
the plan lists which field that is for each module. If a code has no stable field,
it falls back to `code` alone. That means two findings with the same code share one
mission, and the briefing then lists both.

## 4. The player's flow (`controller.js`)

**Entry points:**
- Welcome screen: a second button, **"Play it as a game"**, under "Get started".
  It goes through the same worry and scan screens, then opens City instead of List.
- Results screen: a **List / City** switch at the top.
- The last view chosen is remembered (localStorage). Both views read the same scan
  and the same progress.

**Safety gate (`gate.js`):** game mode is hidden when the person may be watched.
That covers:
- a worry with `safety: true` (today, `watched`)
- the `phone` worry (iPhone spyware)
- a scan where a module in `ALWAYS_SAFETY_MODULES` reports a warning or critical
  finding

Those checks are pulled out of `learnMoreFor` into one shared helper,
`mayBeWatched(situation, doc)`, and both `learnMoreFor` and `gate.js` call it, so
they can't drift apart. The gate does **not** reuse `learnMoreFor` itself. That
function also returns null for worries that simply have no matching district
(`wifi`, `sketchy`), and those people should still get the game.

The Welcome button comes before any worry is picked, so the gate applies at two
points:
- After the worry screen. Picking `watched` or `phone` continues in the list view.
- After every scan.

When the gate is closed, the switch doesn't appear, and a City view that was
remembered falls back to List.

**One mission:**

1. **Map.** The device districts, with buildings unlit, dark (critical) or dim
   (warning), plus fog where checks couldn't run.
2. **District.** Its buildings and its Notes panel.
3. **Briefing.** The finding's description, Scout's line, and the steps.
   - "Fix it for me" opens the existing confirmation panel from `fix-flow.js`
     ("This will… / To undo later…" → "Yes, fix it" / Cancel), unchanged.
   - "This is mine" opens the existing `mark-flow.js` flow, unchanged.
   - "I did it" is for steps the person does themselves.
   - "Later" goes back to the district.
4. **Re-check.** This runs after a fix that `describeFixResult` reports as applied
   and verified, after a mark, or after "I did it". It calls
   `rescue.recheckModule(module)`.
   - The finding is gone: go to the debrief, and the building lights up.
   - Still there: "Not yet. Here's what's still showing", then back to the
     briefing with the fresh finding.
   - The re-check failed: "I couldn't re-check this. That doesn't mean it's fixed."
     There's a retry, and no credit is given.
5. **Debrief.** One question, "How did that go?", using the game's debrief screen
   with a single-question set. The answer only picks Scout's reply. It never
   changes the mission's status.
6. **Milestone.** Shown when every mission in a district is reclaimed or yours,
   using the game's milestone screen. Share cards are turned off, because they
   would describe the person's computer.

Undo works as it does today. A mission whose fix is undone goes back to open, and
its building goes dark.

## 5. Progress (`progress.js`)

The store is localStorage key `device-rescue.game.v1`:
`{version: 1, missions: {[identity]: {status, updatedAt, lastSeenScanAt}}}`.

| Status | Meaning | Counted as fixed |
| --- | --- | --- |
| `open` | The finding is present and hasn't been dealt with. | no |
| `reclaimed` | A re-check or a full scan no longer reports it. | yes |
| `yours` | The person marked it "This is mine" (`data.marked_by_user`). | **no**. It is shown in its own color and listed under "Marked as yours". |
| `later` | The person chose "Later". | no |

**After a full scan:**
- A mission whose finding is gone becomes `reclaimed`.
- A `reclaimed` mission whose finding is back becomes `open`, and Scout says so on
  the map ("This one came back.").
- A finding that is new gets a new `open` mission.
- `yours` follows `data.marked_by_user`.

The scan is always the source of truth. A store that is corrupt or from an unknown
version is discarded and rebuilt from the latest scan. The only thing lost is the
`later` flags.

## 6. Error handling

| Failure | What the person sees |
| --- | --- |
| The re-check fails, times out, or comes back `supported: false` | The mission stays open. "I couldn't re-check this. That doesn't mean it's fixed." There's a retry. |
| The fix fails or can't be confirmed | The existing `describeFixResult` text. No re-check is offered as if it had worked. |
| A vendored screen throws | The controller catches it, shows "The city view hit a problem. Here's the same thing as a list.", and switches to List. Logged to the console only. |
| A missing or corrupt progress store | Rebuilt from the scan, silently. |
| A build without the submodule | `prebuild` fails with "desktop/vendor/reclaim-city is empty. Run git submodule update --init." The app never ships without game mode. |

## 7. Testing

All JavaScript tests use the existing `node --test` runner in `desktop/test/`.

- `game-findings-to-city.test.js`:
  - findings land in districts by category
  - severity maps to risk
  - info findings go to Notes
  - fog for `supported: false` and for `status: "error"`
  - a district made only of failed checks is never shown as clear
  - steps come from `steps_for`, and fall back to "What to do" when there's no
    walkthrough
  - identity is stable across two scans of the same finding
- `game-progress.test.js`:
  - gone → reclaimed, back → open
  - `yours` is never counted as fixed
  - undo → open
  - a corrupt store is rebuilt
- `game-gate.test.js`:
  - closed for `watched` and for `phone`
  - closed when monitoring findings are present
  - **open** for `wifi`, `sketchy`, `hacked`, `identity`, `helping` and `unsure`
    when there are no monitoring findings
  - the existing `learn-more.test.js` still passes after `mayBeWatched` is pulled
    out
- `game-boot.test.js`: both opt-out keys are set before the first dynamic import
  (with a stubbed `import`).
- `game-vendor-contract.test.js`: imports the vendored screens through a minimal
  DOM shim and renders each one with the output of `findings-to-city` for a fixture
  scan, which must not throw. This test catches upstream changes to the data shapes
  whenever the submodule is bumped.
- `fix-policy.test.js` and `mark-policy.test.js`, extended:
  - `rememberModule` replaces only that module
  - a fix that a re-check didn't offer again is refused
  - other modules' allowances survive
- `engine-runner.test.js`: `runRecheck` builds `scan --json --module <name>` and
  rejects names that aren't plain identifiers.
- Python, `tests/test_cli_scan_module.py`:
  - `--module` runs only the named module and keeps the JSON shape
  - repeating `--module` works
  - an unknown module exits 1
  - using it with `--profile` is an error
  - it is read-only (no `fix()` call; it reuses the existing read-only scan test
    pattern)
- **CI:** `tests.yml` checks out with `submodules: true` and runs
  `cd desktop && npm ci && npm test`, which `tests.yml` doesn't run today.
  `release.yml` checks out with `submodules: true`.
- **Manual check before release, on a Mac:**
  1. Play one mission end to end: disable a test launch agent through "Fix it for
     me", watch the re-check light the building, then undo it and watch it go dark.
  2. Confirm with DevTools' network panel that game mode makes no network requests.

## 8. Risks to resolve while writing the plan

1. **Hidden imports.** `state.js` imports `utils/errors.js` (for `captureError`).
   `errors.js` does nothing when there's no `Sentry` global, so importing it is
   harmless, but game mode doesn't use the vendored `state.js` anyway (section 5).
   The plan must walk the actual import graph of every vendored module listed in
   section 2.1 at the pinned commit, and record anything that touches the network.
   Fallbacks, in order of preference: don't load that module; or map that one
   import to a local no-op through an import map in `index.html`; or a small
   upstream PR that passes the dependency in instead of importing it.
2. **ES modules from `file://` in Electron 41.** The renderer currently uses
   classic scripts. Confirm that module scripts and dynamic `import()` load under
   `loadFile` with the current CSP. If they don't, register an `app://` protocol
   with `protocol.handle` that serves `desktop/` read-only.
3. **What the screens expect.** The vendored screens may read global state, such as
   the `window.reclaimCity` handle or a shared `state` object, rather than taking
   arguments. The contract test exists to find out. Where a screen needs state,
   the controller passes it a Reclaim City-shaped state object built from
   `progress.js`.
4. **Two pipelines.** privacy-the-game ships from its own `production` branch.
   Device Rescue pins a commit and bumps it on purpose, rerunning the contract test
   each time.

## 9. Decisions to confirm in spec review

- The device district names (section 3): The Gatehouse, The Wires, The Foundations,
  The Engine Room, The Junkyard.
- Scout's fixed lines for each severity, and for "not yet", "couldn't re-check" and
  "came back". These will be drafted in the plan, and each will be checked against
  the finding's own description so it doesn't promise more than the finding says.
