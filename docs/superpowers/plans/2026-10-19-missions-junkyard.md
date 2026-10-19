# The Junkyard mini-game (storage and clutter) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `junkyard`, the storage-and-clutter mini-game: size-first cards, one decision per item
(Keep / Clear / Later; crashes get Update it), a practice round, and a summary that adds up the space the
Clear choices would free. It covers the macOS checks and their Windows equivalents.

**Architecture:** One pure ES module, `desktop/renderer/missions/games/junkyard.js`, default-exporting the
contract object (`renderer/missions/contract.js`). It sorts each item into one of four kinds by its module
(`space`, `crash`, `setting`, `hog`), reads real `data` fields from the engine modules, and returns decisions
whose effects are carried out by the runner. Clear is a `fix` effect only when the engine attached a
`fixable` block to the finding. Otherwise it is a `settings` effect (pane + steps) or a `closer` effect
(steps). Crash Update is a `link` effect holding a look-up intent. Styling lives in `games/junkyard.css`,
using the game's CSS variables.

**Tech stack:** Plain JS (ES modules), node:test, the contract helpers (`runContractChecks`, `testContext`, `makeItem`).

## Global Constraints

- Files owned: `desktop/renderer/missions/games/junkyard.js`, `desktop/renderer/missions/games/junkyard.css`,
  `desktop/test/missions-junkyard.test.js`, `desktop/test/fixtures/missions/junkyard-*.json`. Nothing else.
- Pure module: no DOM, storage, clipboard, network, globals, or imports. Everything comes through `ctx`.
- Every scan value goes through `ctx.esc`. Links are intents only (`settings` panes and `lookup` sources from
  the contract allowlists). No URLs.
- 2–3 decisions, labels of 4 words or fewer, and the first is safe. Keep is always first, so an item with a
  removal warning never defaults to a removing choice.
- Honesty: an item from an unfinished check says so (`item.unfinished`, `complete === false`). The summary
  never says "all clear". Freed space is called an estimate.
- City mode uses game words (scrap, haul off, yard) and none of `CITY_FORBIDDEN`. No time words.
- Fixtures are synthetic: made-up app names, `~/` paths, no serials, MACs or SSIDs.
- Real field names only. These come from the engine sources, for example: `data.type`, `size_bytes`, `size_formatted`,
  `total_bytes`, `count`, `item_count`, `browser`, `app_name`, `crash_count`, `system_apps`,
  `affected_apps` ([app, count] pairs), `top_sources` (dict), `stop_code`, `setting`, `issue`, `name`,
  `memory_bytes`, `cpu_percent`, `bloatware_name`, `resource_savings`, `caption`, `used_pct_str`,
  `free_bytes`, `recycle_bin_size`, `cache_size`.

## Review Focus

- Clear never claims a fix the engine didn't offer.
- The summary total doesn't double count. A check's "total" card overlaps the piles inside it, so each
  check contributes the larger of the two.
- Windows steps and macOS steps name real menus only, with no invented ones.
- Covers don't collide with other games. `temp_file_scanner` is the locker's in the spec table, and
  `win_startup` / `win_startup_programs_audit` are left to door.

## Covers

macOS: storage_cleanup, large_files_finder, library_cache_cleanup, browser_cache_cleanup, trash_cleanup,
docker_cleanup, xcode_cleanup, mail_attachment_cleanup, crash_log_analyzer, app_crash_analyzer,
application_crash_report, system_log_errors, energy_saver_check, energy_settings, power_settings,
resource_hog_identifier, process_scanner.
Windows: win_disk_cleanup, win_temp_cleanup, win_temp_files, win_temp_files_cleanup, win_disk_space,
win_event_errors, win_bsod_analysis, win_power_plan, win_power_plan_check, win_pagefile, win_pagefile_check,
win_visual_effects, win_bloatware.
None of these modules set finding codes, so `covers` claims whole modules with no `codes`.

---

### Task 1: Fixtures and the failing test suite

**Files:** Create `desktop/test/fixtures/missions/junkyard-mac.json` and `junkyard-win.json`, plus `desktop/test/missions-junkyard.test.js`.

- [ ] Step 1: Write the synthetic fixtures as `{ note, platform, findings: [ {module, severity, category, title, description, data} ] }`.
  Mac fixture: storage total (12.0 GB), library caches total (4.2 GB) and one app's cache inside it (1.5 GB),
  Safari cache, a large Trash, 17 dangling Docker images, Xcode DerivedData, Mail attachments, old downloads,
  a crash_log_analyzer app, app_crash_analyzer system and memory crashes (the second with a verified `made_by`),
  system_log_errors, never-sleep, display never off, a resource hog, and a process_scanner bloat item.
  Windows fixture: windows_old, winsxs, user_temp, total_reclaimable, recycle_bin (win_temp_files_cleanup),
  a 93%-full drive, a blue screen with a stop code, event errors, a power saver plan, the page file turned
  off, transparency on low RAM, and a pre-installed app.
- [ ] Step 2: Write the tests (full file in the commit). They check:
  - `runContractChecks(game, items)` returns `[]` for both fixtures and the practice items.
  - `covers` includes every module listed above, once each, and each exists in `modules/*/`. It excludes temp_file_scanner and the startup modules.
  - Space decisions are `['keep','clear','later']`. Clear is `fix` only when `finding.fixable` is present.
  - Without a fix, Clear gives `settings` with pane `storage` / `windows-storage` plus steps where Storage is where the work happens, and `closer` with steps elsewhere (Safari "Empty Caches", `docker system prune`, Disk Cleanup for winsxs).
  - Crash decisions are `['keep','update','later']`. Update is `{kind:'link', link:{kind:'lookup', …}}`: `web` with `"App" update`, `maker-site` when `made_by` is verified, `apple-support` for system crashes, `microsoft-support` with `stop code X` for blue screens. Research adds the `software-update` / `windows-update` pane.
  - Settings and programs: `change` (battery / lock-screen pane on Mac; real Windows steps for power plan, page file, transparency), `quit` (Activity Monitor), `remove` (windows-apps pane).
  - `headline(item)` puts the size first (`{size:'4.2 GB', rest:'of caches in your Library folder'}`), uses counts for Docker and crashes, and the used percentage for a full drive. City cards say "Scrap pile".
  - An unfinished item shows "didn't finish" (standard) or "stopped early" (city).
  - Evidence rows come from `ctx.evidenceRows(f, {mode})` and are escaped.
  - `freedBytes`: total 4.2 GB + inside 1.5 GB + Trash 3.1 GB = 4.2 + 3.1 (7.3 GB). The summary shows "7.3 GB … your Clear choices would free", "An estimate", "1 kept", "1 for later", and never "all clear". With nothing cleared it says "Nothing cleared this round". A full drive frees 0.
  - Practice is a browser cache (expect clear), a video you made (expect keep), and an app that keeps crashing (expect update). The highlighted step part gets `jy-look`. No `/Users/` paths.
  - No labels over 4 words and no time words in steps or render output.
  - Source purity: no `document`, `window`, storage, clipboard, `fetch`, `globalThis`, imports or `href=`.
- [ ] Step 3: Run `cd desktop && node --test test/missions-junkyard.test.js`. Expected: all fail (the module doesn't exist).
- [ ] Step 4: Commit with "Junkyard: synthetic fixtures and failing tests".

### Task 2: The game module

**Files:** Create `desktop/renderer/missions/games/junkyard.js`.

- [ ] Step 1: Implement it (full source in the commit). Key pieces:

```js
const KIND_BY_MODULE = { storage_cleanup: 'space', /* … */ crash_log_analyzer: 'crash', /* … */
  energy_saver_check: 'setting', /* … */ resource_hog_identifier: 'hog', process_scanner: 'hog', win_bloatware: 'hog' };
export const COVERS = Object.keys(KIND_BY_MODULE).map((module) => ({ module }));

export function bytesOf(item) {          // what Clear would free; a full drive's free space is not "freed"
  const f = findingOf(item);
  if (kindOf(item) !== 'space' || f.module === 'win_disk_space') return null;
  const d = dataOf(f);
  for (const k of ['size_bytes', 'total_bytes', 'total_size_bytes', 'total_size', 'cache_size', 'recycle_bin_size', 'total_reclaimable']) {
    const v = num(d[k]); if (v !== null) return v;
  }
  return null;
}

function decisions(item, ctx) {
  const kind = kindOf(item);
  if (kind === 'crash') return [KEEP, { id: 'update', label: L('Update it', 'Patch it'), effect: { kind: 'link', link: crashLookup(item) } }, LATER];
  if (kind === 'setting') return [KEEP, { id: 'change', label: L('Change it', 'Rewire it'), effect: stepsEffect(settingSteps(item, ctx)) }, LATER];
  if (kind === 'hog') { /* quit (resource hog) or remove (bloat): fix when offered, else steps */ }
  const clear = fixable(item)
    ? { id: 'clear', label: L('Clear it', 'Haul it off'), effect: { kind: 'fix' } }
    : { id: 'clear', label: L('Clear it', 'Haul it off'), effect: stepsEffect(spaceSteps(item, ctx)) };
  return [KEEP, clear, LATER];
}

export function freedBytes(results) {   // per check: max(aggregate, sum of the other piles)
  const byModule = new Map();
  for (const res of results) {
    if (decisionId(res) !== 'clear') continue;
    const b = bytesOf(res.item); if (b === null) continue;
    const e = byModule.get(module) || { total: 0, parts: 0 };
    if (isTotal(res.item)) e.total = Math.max(e.total, b); else e.parts += b;
    byModule.set(module, e);
  }
  return [...byModule.values()].reduce((s, e) => s + Math.max(e.total, e.parts), 0);
}
```

  `SPACE[type]` holds, for each pile type, the size-first phrase (standard and city), a verdict (safe / check
  / look / tool), and steps per platform with an optional pane. Verdicts teach "what's safe to clean":
  caches grow back, the Trash and Recycle Bin are final, your files are yours to judge, and the WinSxS store
  is cleared only by Windows' own tool.
  `summary(results)` accepts `{item, decision}`, where the decision is an id string or `{id}`, as well as `decisionId` or `choice`.
- [ ] Step 2: Run `node --test test/missions-junkyard.test.js`. Expected: PASS.
- [ ] Step 3: Commit with "Junkyard: the game module (size-first cards, Keep/Clear/Later, crash Update it, freed-space summary)".

### Task 3: Styles and the visual check

**Files:** Create `desktop/renderer/missions/games/junkyard.css`.

- [ ] Step 1: Write the `.jy-card` styles. The big amber `.jy-size` comes first. Each kind gets its own accent
  (crash magenta, setting cyan, hog lime). The verdict strip is coloured by verdict. `.jy-look` adds an outline for practice steps.
  At 800px and below the evidence rows stack into one column.
- [ ] Step 2: Build a preview HTML in the scratch folder that imports the game, loads `game.css` and
  `junkyard.css`, and renders the practice items, some fixture items and a summary in both modes. Screenshot it at
  default width and at 800px.
- [ ] Step 3: Run the full suite with `cd desktop && npm test && npm run check-game-files`. Expected: green.
- [ ] Step 4: Commit with "Junkyard: card styles".
