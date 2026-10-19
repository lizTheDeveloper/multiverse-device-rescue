# The Evidence Locker (locker mini-game) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A mini-game that tags each suspicious file (and the running programs, add-ons and settings these checks also report) with where it is, size, when it changed, what matched, and who made it. Each item gets its own decision: Mine / Quarantine / Look closer.

**Architecture:** One pure ES module, `desktop/renderer/missions/games/locker.js`, implementing the contract in `desktop/renderer/missions/contract.js`. It also has a `covers` list and a `groupKey` export. The item kind comes from the finding code (or `data.check` for code-less Windows findings) and picks the moves:
- file: Mine / Quarantine / Look closer
- process: Mine / Stop it / Look closer
- extension: Mine / Turn it off / Look closer
- setting: Mine, I know why / Look closer / Later
- system: Look closer / Mine, I know why / Later

A critical item puts Look closer first. Quarantine uses the engine's `fixable` (fix effect) when it is present. Otherwise it gives move-aside steps (a `closer` effect, `focus: 'move-aside'`) that never delete. Per rulings R1–R6, render returns only the tag card, and acting effects on alerting items carry `warning: true`.

**Tech Stack:** Plain JS ES modules, node:test, CSS using the game skin's variables.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `locker`, "Each mini-game: locker").

## Global Constraints
- Edit only: `games/locker.js`, `games/locker.css`, `test/missions-locker.test.js`, `test/fixtures/missions/locker-*.json` (synthetic).
- `runContractChecks(game, items)` returns `[]`; decisions 2–3, labels ≤ 4 words, no fix first on alerting items.
- City output uses game words only (CITY_FORBIDDEN), including hints, steps and checklists.
- Never delete: move aside to a Quarantine (city: "Set aside") folder; nothing in steps says delete, Trash or Recycle Bin.
- Mac and Windows: Finder/Activity Monitor vs File Explorer/Task Manager/Settings > Apps > Startup; `win_*` modules covered.
- No time words; never "all clear"; "This check didn't finish" when `item.unfinished`.

## Review Focus
- Real data field names (taken from `modules/**/__init__.py`): `path, config_path, plist_path, binary_path, binary, pattern, threat, sha256, modified_days_ago, process, pid, cpu_percent, dest, remote, port, extension_name, browser, registry_path, entry_name, entry_value, files, drivers, services, issues`.
- Engine fix only where `fixable` is well formed (today: `disable_launch_agent` on `ai_threat_indicators.launchagent_ai`). Mark only where `markable` is present (today: `ai_threat_indicators` ai_api_key_found / cron_ai_call); otherwise Mine is `{kind:'keep'}`.

## Task 1: Synthetic fixtures
- [ ] Write `locker-mac.json` (dev script, temp dropper, known hash, ssh keys with removal alert, fixable launch agent, markable cron, known miner, Safari add-on, SIP off, hidden root files, ClamAV missing, signed app), `locker-win.json` (temp script, code-less miner and pool, hidden-folder service, Run-key entry, unsigned driver, Secure Boot off) and `locker-group.json` (ten near-identical package scripts). Paths only under `/Users/example` and `C:\Users\example`; IPs only from 192.0.2.0/24.

## Task 2: Failing tests
- [ ] `desktop/test/missions-locker.test.js`: contract on all fixtures; covers are real modules and are not other games' modules; tag fields and flags; decisions per kind and order; engine fix vs move-aside; removal warning (`warning: true`, not first); mark vs keep; Windows steps and panes; research intents; city words; no time words / no "all clear"; unfinished; ten near-identical items (one groupKey, separate decisions, "N more look the same", grouped summary); practice script (Mine / Quarantine / Look closer); fixture privacy.
- [ ] Run `node --test test/missions-locker.test.js` and expect it to fail (the module is missing).

## Task 3: The game
- [ ] Implement `locker.js` (kindOf, pathOf, placeFlags, tagOf, groupKey, moveAsideSteps, stopSteps, turnOffSteps, checklistFor, decisions, research, render, summary, practice) and `locker.css`.
- [ ] Run the test file; expect it to pass. Run the full `npm test` and `npm run check-game-files`.

## Task 4: Visual check and report
- [ ] Preview HTML in the scratch folder (practice and fixture items, standard and city, default width and 800px); screenshot.
- [ ] Write `.superpowers/sdd/missions-locker-report.md`.
