# Little missions: the foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A checkup becomes a lot of little missions. Findings are grouped by the kind of thing they are about (up to 4 items a mission), each item is decided one at a time inside a mini-game, the research is done for the person, and the city is the only screen that shows them.

**Architecture:**
- `missions/types.js`: the one mapping table (type → engine modules, optionally narrowed by finding-code prefix, macOS and Windows), the double-claim check, and `groupMissions(doc, {mode})` built on `NotChecked.displayItems`, so the counts are the list's (`scanCounts.todo`).
- `missions/research.js`: turns a game's link INTENTS into allowlisted URLs: `x-apple.systempreferences:` and `ms-settings:` per `SETTINGS_PANES` entry, look-ups from fixed templates with URL-encoded values, lessons by concept. City mode: look-ups are text only.
- `missions/runner.js`: pure state machine for one mission run (practice offer → practice steps → items → closer → summary). It never touches the DOM: decisions return an `act` the controller carries out through the existing paths (FixFlow, MarkFlow, recheck, open-setting). The removal warning is the runner's, injected above the decisions and into the fix confirm options; games cannot suppress it. Remembered answers (item key + evidence fingerprint) and practice gating are pure functions over the profile.
- `missions/games/index.js`: the registry. Loads `games/<type>.js` for every `TYPE_IDS` entry; a missing or invalid game falls back to `games/simple.js` (the reference implementation).
- Profile (`game/profile/player-profile.js`, `item-bank.js`): two innocuous fields, `rounds` (practice played/skipped per type) and `kept` (remembered answers by short hash); practice answers are evidence (`source: 'round'`) on the game's concepts, through bank items `round:<type>:<step>:<concept>`.
- Ledger (`game/ledger.js`): `decide`, `mission`, `notesBatch` (lifetime keys) and `notesArea` (per sweep) awards; CONFIRMED raised from 50 to 75; every key starts with the module so monitoring never pays.
- City wiring (`game/controller.js`, `views/district.js`, `views/deck.js`, `views/hud.js`, new `views/mission-run.js`): district mission rows (checkbox, title, count, severity, part N of M); INVESTIGATE NEXT opens the most important unfinished mission; the mission screen shows item N of M, the game's render, the runner's warning, decisions, Practice, the summary and NEXT MISSION. Behind the controller option `missions` (boot passes it on) so the old deck tests keep running until the Plain-retirement merge moves them.

**Tech Stack:** Electron 41, plain JavaScript ES modules (no bundler), `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md`. Contract: `desktop/renderer/missions/contract.js`.

## Global Constraints

- "One mission = one type within one district, at most **4 items**; bigger sets split into "part 1 of N"."
- "Order: critical first, then warnings; within a level, missions with a `removal_alert` item or a fix first."
- "Held items (city mode) never enter a mission"; "In standard mode there is no held."
- "`info` items go to the `notes` mission only." Notes come in optional batches of 5 (the notes game's own size).
- "Marked-as-yours items don't appear unless stale (`mark_stale`), then as a normal item."
- "**Settings pane**: `x-apple.systempreferences:` URLs per type …; Windows `ms-settings:` equivalents." "never a raw URL from scan data".
- "In stealth mode, look-up searches are shown as text to search on another device, never as links".
- "when an item has `removal_alert` or `safety_note`, the runner shows the removal warning line above the decisions and inside any `fix` confirm; games cannot suppress it."
- "Practice … First time per game, skippable, re-offered on gaps — and on request (a "Practice" button on every mission)". "Practice answers are recorded as profile evidence on the game's `concepts`".
- "Points: per decided item, a bonus when a mission is finished, a larger CONFIRMED award when a re-check proves a fix, points per notes batch and a bonus for clearing an area's notes. Held never pays; removal of monitoring-capable software never pays more than leaving it."
- "Remember answers: Until the evidence changes (path, signer, settings)". "Stored in the recipe-box profile with innocuous keys".
- "Fallback: a type without its game module yet uses `simple`."
- Plain view is being retired by another track: nothing here is wired into Plain.
- Copy: plain, calm, no time words; city output uses game words only (`CITY_FORBIDDEN`).

## Review Focus

- Counts: mission items (non-notes) equal `scanCounts(doc, {mode}).todo` for engine output; notes equal `.notes`.
- Nothing reads clean: a mission never says "all clear"; an item from an unfinished check says so.
- The runner is the only place effects become acts; the warning can't be dropped by a game.
- Stored keys and values pass `FORBIDDEN_ON_DISK`.

---

### Task 1: types.js — the table, double claims, groupMissions

**Files:** Create `desktop/renderer/missions/types.js`; Test `desktop/test/missions-foundation-types.test.js`.

- [ ] Failing tests: grouping caps at 4 and labels parts; order critical → warning, alert/fix first; city excludes held, standard keeps them; info only in notes (batches of 5); marked excluded, stale-marked included; counts equal `scanCounts.todo` / `.notes` on a synthetic doc; `doubleClaims` catches a module claimed whole twice and an overlapping code prefix; a game's `covers` replaces its type's base entry; every macOS module that can warn (read from `modules/**/__init__.py`) is mapped or listed in `ODD_JOBS`.
- [ ] Implement `TYPE_TITLES`, `BASE_COVERS`, `ODD_JOBS`, `buildTable(games)`, `doubleClaims(table)`, `typeOf(finding, table)`, `groupMissions(doc, {mode, table})`, `missionCounts`.
- [ ] Pass; commit.

### Task 2: research.js — panes, look-ups, lessons

**Files:** Create `desktop/renderer/missions/research.js`; Test `desktop/test/missions-foundation-research.test.js`.

- [ ] Failing tests: every `SETTINGS_PANES` entry resolves on darwin and win32 (or is listed in `NO_PANE` with a reason) and every URL passes `setting-urls.js isAllowedSettingUrl`; look-up values are encoded, control characters dropped, capped; Chrome Web Store only for a 32-letter a–p id; city mode gives text and no URL; a game's `href` is ignored; `whatOf` gives the verified program's `what`, else "Unknown maker"; `assemble` adds "This check didn’t finish" for an unfinished module.
- [ ] Implement `PANE_URLS`, `paneUrl`, `lookupUrl`, `resolveLink`, `resolveLinks`, `whatOf`, `assemble`.
- [ ] Pass; commit.

### Task 3: registry, simple game, contract additions

**Files:** Create `desktop/renderer/missions/games/simple.js`, `games/index.js`; Modify `missions/contract.js` (add `checkCovers`, `noDoubleClaims`); Test `desktop/test/missions-foundation-registry.test.js`.

- [ ] Failing tests: `runContractChecks(simple, items) == []`; registry with only simple loads every TYPE_ID (fallback marked); an invalid game falls back; `checkCovers` rejects a cover without a module or with a non-string code; `noDoubleClaims` across registered games.
- [ ] Implement; pass; commit.

### Task 4: runner.js — state machine, warning, practice, remembering

**Files:** Create `desktop/renderer/missions/runner.js`; Test `desktop/test/missions-foundation-runner.test.js`.

- [ ] Failing tests: start → item phase (or practice offer when due); decide with `later`/`keep`/`note` advances; `closer` keeps the item open and drops the closer decision; `mark`/`fix`/`settings`/`link`/`recheck` return acts and wait for `settle`; the warning line is injected for `removal_alert`/`safety_note` items and into fix options, even when a game tries to hide it; a game that puts `fix` first on an alerting item is reordered; practice steps record right/wrong by `expect`; `practiceDue` first time, not after played, again after a skip with a gap; `fingerprint` changes with path/signer/settings, not with volatile fields; `remember`/`recall` round-trip; summary results.
- [ ] Implement; pass; commit.

### Task 5: profile + ledger

**Files:** Modify `game/profile/player-profile.js`, `game/profile/item-bank.js`, `game/ledger.js`; Test `desktop/test/missions-foundation-profile.test.js`.

- [ ] Failing tests: `rounds` and `kept` survive save/load (salvage); keys/values pass `FORBIDDEN_ON_DISK`; `recordRound` gives evidence on the concept via bank `round:` items; `recordPractice`/`markRoundSkipped`; ledger `decide` pays once per item, `mission` once, `notesBatch`, `notesArea` per sweep; monitoring module keys never pay; `POINTS.fix` is 75.
- [ ] Implement; pass; commit.

### Task 6: missions.css + city screens

**Files:** Create `missions/missions.css`, `game/views/mission-run.js`; Modify `views/district.js`, `views/deck.js`, `views/hud.js`, `game/controller.js`, `game/boot-core.js`; Test `desktop/test/missions-foundation-city.test.js`.

- [ ] Failing tests (stubbed window, like game-deck-controller): district shows mission rows with checkbox, count, severity and "PART 1 OF 2"; INVESTIGATE NEXT opens the most important unfinished mission; the mission screen shows "ITEM 1 OF 4", the warning above the decisions for an alerting item, a Practice button; deciding Later moves on; the summary and NEXT MISSION; a fix decision renders the FixFlow control with the safety option; settings decision calls `rescue.openSetting` with an allowlisted URL; points for decisions and the mission bonus; a remembered answer survives a new scan with the same evidence and drops when the path changes; city mode output has no `CITY_FORBIDDEN` word.
- [ ] Implement; pass; full suite; commit.

### Task 7: visual check and report

- [ ] Preview HTML in the scratch folder rendering district rows and a mission screen in standard and city words; screenshot.
- [ ] `cd desktop && npm test && npm run check-game-files`.
- [ ] Report `.superpowers/sdd/missions-foundation-report.md`.
