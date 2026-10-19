# Missions: The Keyring (apps with powerful access) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** One mini-game module, `desktop/renderer/missions/games/keyring.js`, that turns "apps with powerful access"
findings into one decision each: the key (a privacy permission) and the apps holding it, shown as app cards with key
chips; per key **Keep** / **Hand back** (the exact privacy pane), plus **Look closer** when a maker isn't confirmed.

**Architecture:** A pure ES module (no DOM, storage, globals, network). It reads only the item and `ctx`, returns
decisions (effects), research (rows from `ctx.evidenceRows`, link INTENTS), HTML escaped with `ctx.esc`, and a
summary. A small `KEYS` table maps each finding (by `data.service` TCC id, else by code suffix / module) to a key:
its plain name, city name, what it lets an app do, its macOS pane and Windows pane. Styles live in
`games/keyring.css`, scoped under `.kr-` and using the game's CSS variables with fallbacks.

**Tech Stack:** plain JS ES modules, `node --test` (Node 22).

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `keyring`, "Each
mini-game" → keyring). **Contract:** `desktop/renderer/missions/contract.js`.

## Global Constraints

- Owns only: `desktop/renderer/missions/games/keyring.js`, `desktop/renderer/missions/games/keyring.css`,
  `desktop/test/missions-keyring.test.js`, `desktop/test/fixtures/missions/keyring-*.json` (synthetic).
- `runContractChecks(game, items)` returns `[]` for fixture items and practice items.
- 2–3 decisions, labels ≤ 4 words; the first is the safe default (**Keep**). Hand back is a `settings` effect, never
  `fix`; it is never first.
- Honest makers: an app known only by a bundle id (not a full path) is **never** shown as confirmed, even if a
  `made_by` entry says `verified: true` (serialize.py `_unverify_named_apps`; the game re-checks). Shown as "Maker not
  confirmed" / city "Maker unconfirmed".
- Removal warning: keyboard / input access (keylogger_indicators, input-monitoring keys) by an app whose maker isn't
  confirmed carries the removal warning line in the card, in addition to whatever the runner injects; any item with
  `removal_alert` or `safety_note` also shows it. City wording uses game words (help district).
- Held items never reach the game in city mode (foundation). Defensive: a held item rendered in city mode shows only a
  neutral game line, no app list.
- City output: game words only (CITY_FORBIDDEN); scan titles/descriptions are never rendered (they carry engine words).
- An item from a check that didn't finish says "This check didn't finish" (`item.unfinished`, `item.complete === false`,
  `finding.complete === false` or `data.incomplete`).
- No time words, plain calm copy, teach once (one short line per key + lesson link).
- Mac and Windows: `win_cortana_telemetry` location code; Windows panes via `windows-privacy` with a `permission` hint.

## Covers

| Module | Codes |
|---|---|
| app_permissions | all |
| privacy_permissions_audit | all |
| accessibility_permissions | all |
| keylogger_indicators | all (held items go to the help district first; non-held reach the game) |
| screen_time_audit | all |
| location_services | all |
| win_cortana_telemetry | `security.win_cortana_telemetry.location_services` |

## Review Focus

- Bundle-id apps never read as confirmed makers; `what` only for a confirmed maker.
- Keyboard keys from unconfirmed makers always show the warning; Hand back never first.
- Every scan value through `ctx.esc`; hostile names inert; city words clean.

## Tasks

### Task 1: Fixtures and failing tests
- [ ] Write `desktop/test/fixtures/missions/keyring-scan.json` (synthetic macOS scan: accessibility list with bundle
  ids, Input Monitoring by an unknown bundle id, a known-keylogger critical, screen recording by a path app with a
  verified maker, camera+mic combo, a Find My desktop location warning, Screen Time without passcode) and
  `keyring-windows.json` (win_cortana_telemetry location).
- [ ] Write `desktop/test/missions-keyring.test.js`:
  - contract checks are `[]` for every fixture item in both modes (items from `NotChecked.displayItems`, all lists);
  - key mapping (service id, code suffix, combos, keylogger, location, screen time, Windows);
  - decisions: Keep first, Hand back is `settings` with the key's pane (Windows: `windows-privacy` + permission);
    Look closer only when a maker isn't confirmed; alerting items never start with a removing kind;
  - makers: bundle-id app with `verified: true` renders "Maker not confirmed"; a path app with a verified maker renders
    the maker and `research.what`;
  - warning line for keyboard access by an unconfirmed maker, in both modes, city in game words;
  - city: held item renders no app names; no titles/descriptions rendered;
  - unfinished check line; practice: 3 synthetic items (screen recorder keep, game accessibility hand back, keyboard
    remapper closer), every script step's `expect` is a real decision id of its item;
  - summary counts kept / handed back / looked closer, never "all clear", city words clean.
- [ ] Run: `cd desktop && node --test test/missions-keyring.test.js` → fails (module missing). Commit.

### Task 2: The game module
- [ ] Implement `keyring.js`: `KEYS`, `keysOf(finding)`, `appsOf(item)`, `makerOf(finding, app)`, `decisions`,
  `research`, `render`, `summary`, `practice`, `covers`.
- [ ] Run the test file → passes. Commit.

### Task 3: Styles and preview
- [ ] `keyring.css` (`.kr-card`, `.kr-app`, `.kr-chip`, `.kr-warn`, `.kr-maker`), 800px-safe.
- [ ] Preview HTML in the scratch folder rendering practice + fixture items in both modes; screenshot; look.
- [ ] Full suite: `cd desktop && npm test && npm run check-game-files`. Commit.
