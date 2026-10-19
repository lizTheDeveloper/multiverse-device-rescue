# Missions: the notes game (Signal or Noise in batches) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Good-to-know notes become an optional, incentivized mini-game: Signal or Noise in batches of five notes from one area. Each note is called Normal or Odd; an odd one becomes an item of its own type in a new mission (the runner does that). The summary reports the batch's points, "120 of 394 sorted", and the area bonus when every note in an area is sorted.

**Architecture:** One pure ES module, `desktop/renderer/missions/games/notes.js`, implementing the mini-game contract (`desktop/renderer/missions/contract.js`). It reuses the Signal or Noise clue builder (`game/clues.js`: `cluesFor`, `placeFor`, `pathOf`) so a note reads the same as on the deck, and `CITY_FORBIDDEN` from the contract to keep city output in game words. It exports `covers: [{ module: '*', severities: ['info'] }]` for the foundation's `types.js`, plus `batchNotes()` (batches of `BATCH_SIZE` = 5 per area) and `paneFor()` (settings-pane intents, macOS and Windows). Styling in `games/notes.css` on the city's CSS variables.

**Tech Stack:** plain JavaScript ES modules, `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `notes`; "Each mini-game" → notes). Brief: `.superpowers/sdd/missions-common.md`.

## Global Constraints

- Owns only: `desktop/renderer/missions/games/notes.js`, `games/notes.css`, `desktop/test/missions-notes.test.js`, `desktop/test/fixtures/missions/notes-*.json` (synthetic).
- Spec: "**notes** — Signal or Noise in batches of 5 notes from one area; Normal / Odd; odd turns the note into an item of its type in a new mission. Batches are optional and resumable, and incentivized: points per batch, a bonus for clearing an area; progress shows "120 of 394 sorted"."
- Contract: pure module; 2–3 decisions, labels ≤ 4 words, first is the safe default; link intents only; every scan value escaped with `ctx.esc`; `runContractChecks(game, items)` returns `[]`.
- City mode: game words only (`CITY_FORBIDDEN`); a monitoring check's note (`stalkerware_scan`, `mvt_spyware_scan`, `keylogger_indicators`) in city mode shows no evidence rows, no look-up and `copy: false`.
- Honesty: an item from a check that didn't finish says so; nothing says "all clear".
- No time words or estimates. Practice items synthetic only (no `/Users/…`).
- The runner renders decision buttons, research rows and links; `render` draws the note card only.

## Review Focus

- City output over practice, fixtures and hostile values: no forbidden words, inert HTML.
- `odd` effect carries `{ key, module, code }` so the runner can map the note to its type.
- Summary progress contract (`ctx.notes` or `results.progress`) is what the runner can supply.

## Task 1: Fixtures and failing tests

**Files:** Create `desktop/test/fixtures/missions/notes-batch.json`, `desktop/test/missions-notes.test.js`.

- [ ] Fixture: nine synthetic info findings across two areas ("The Gatehouse" ×6, "Harbor Row" ×3): a verified launch agent (`scheduled_tasks_audit.launch_agent_info`, `location` + `command`), a disabled one, `cron_jobs_audit.cron_entries_found`, `privacy_permissions_audit.microphone_access` (`service: kTCCServiceMicrophone`), `launchd_persistence_audit.non_apple_info`, `storage_cleanup`, an unfinished `dns_config`, `mvt_spyware_scan.mvt_scan_available`, a `win_startup_programs_audit` note. Field names from the module sources.
- [ ] Tests (15): contract checks `[]`; `covers`; decisions `normal`(note)/`odd`(odd + key/module/code) with labels `Looks normal`/`Looks odd`, city `Noise, normal`/`Signal, odd`; research rows/what/links (`login-items`, web look-up of the label, lesson `where-it-lives`), microphone → `privacy-microphone`; Windows panes (`startup-apps`, `windows-storage`, `windows-update`, `windows-privacy`; linux → null); render borrows `command` as WHERE IT LIVES and says "One clue: it lives in a hidden folder."; unfinished line; city monitoring note hushed; city never prints a forbidden word from scan text; practice 3 items normal/odd/normal; practice banner + step; summary points/progress/bonus (thousands separators), city words; `results.progress` fallback and empty batch; no time words; `batchNotes` 5 per area, held and to-do items left out.
- [ ] Run `node --test test/missions-notes.test.js` → fails (module missing).
- [ ] Commit.

## Task 2: The game module

**Files:** Create `desktop/renderer/missions/games/notes.js`.

- [ ] `decisions(item)`:
  ```js
  [{ id: 'normal', label: { standard: 'Looks normal', city: 'Noise, normal' }, effect: { kind: 'note', key } },
   { id: 'odd', label: { standard: 'Looks odd', city: 'Signal, odd' }, effect: { kind: 'odd', key, module, code } }]
  ```
- [ ] `research(item, ctx)` → `{ rows: ctx.evidenceRows(f, { mode }), what, links: [settings pane?, lookup?, lesson], copy, unfinished }`; hushed (no rows, look-up or copy) for a monitoring check's note in city mode.
- [ ] `paneFor(finding, platform)`: TCC `data.service` → privacy pane (Windows: `windows-privacy`); module-name rules → `login-items`/`startup-apps`, `storage`/`windows-storage`, `software-update`/`windows-update`, `firewall`/`windows-firewall`, `windows-security`, `sharing`, `dns`, `battery`.
- [ ] `render(view, ctx)`: card with kicker (GOOD TO KNOW / SIGNAL OR NOISE), area, "Note i of n", title, unfinished line, open clues from `cluesFor` (scheduled tasks lend `command`, else `location`, as the path), the tell ("One clue: …"), the lean line, practice banner + step. City text passes through `cityText` (any forbidden word → "The LIST tab has its own words.").
- [ ] `practice`: a verified Apple daily-cleanup daemon (normal), an unsigned agent running `~/.hidden/updater.sh` (odd), a camera note for one video-call app (normal); script steps say what to look at, both modes.
- [ ] `summary(results, ctx)`: counts normal/odd, odd → "became a mission"; `+N points for this batch` (sum of `results[].points` + `progress.batchPoints`); `sorted of total sorted`; `areaSorted of areaTotal in <area>`; cleared → "You sorted every note in <area>. +B bonus points."; "Sorting is the game’s. It changes nothing on your computer."
- [ ] `batchNotes(items, { areaOf, size })`.
- [ ] Run the test → pass. Commit.

## Task 3: Styles

**Files:** Create `desktop/renderer/missions/games/notes.css` (`.nt-*`, the city's variables, 800px breakpoint). Commit.

## Task 4: Verify

- [ ] `cd desktop && npm test && npm run check-game-files`.
- [ ] Preview HTML in the scratch folder (game.css + notes.css; practice + fixture items; standard and city; summary), screenshot at default and 800px.
- [ ] Report `.superpowers/sdd/missions-notes-report.md` in the main checkout.
