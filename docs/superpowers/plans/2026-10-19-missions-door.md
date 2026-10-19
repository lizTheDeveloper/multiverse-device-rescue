# The Door (missions: things that start on their own) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The `door` mini-game: each thing that starts on its own "knocks" with a card showing its name, the
program it runs (hidden or temporary folders highlighted), who signed it and whether that was verified, when it
appeared, and what the program is. The person decides **Mine** / **Look closer** / **Not mine**. macOS and the
Windows equivalents (startup entries, scheduled tasks, auto-start services).

**Architecture:** One pure ES module, `desktop/renderer/missions/games/door.js`, whose default export follows
`desktop/renderer/missions/contract.js` plus `covers`. It reads only `item.finding` (engine `data`, `made_by`,
`markable`, `fixable`, `removal_alert`) and what `ctx` hands it. Place notes and the home-folder rule come from the
existing pure `desktop/renderer/game/clues.js` (`placeFor`, `homeRelative`), so the Door and Signal or Noise read a
path the same way. Styling in `games/door.css` (game CSS variables only). Decision buttons and the removal warning
are the runner's chrome; `render` draws the knock card and, in practice, the step's pointer.

**Tech Stack:** plain JS ES modules, `node:test` (CJS test importing ESM by file URL, as
`desktop/test/missions-contract.test.js` does).

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `door`; "Each
mini-game" → door). Brief: `.superpowers/sdd/missions-common.md`.

## Global Constraints

- Edit only `desktop/renderer/missions/games/door.js`, `games/door.css`, `desktop/test/missions-door.test.js`,
  `desktop/test/fixtures/missions/door-*.json`, this plan.
- Pure: no DOM, storage, window, network, clipboard. Effects and link INTENTS only (`settings` panes from
  `SETTINGS_PANES`, `lookup` sources from `LOOKUP_SOURCES`, `lesson`). Never a URL.
- Every scan value goes through `ctx.esc` (which applies `ctx.visible`). Paths are split on separators and each
  part escaped before any `<mark>` is added.
- Data field names come from the module sources (listed in Task 1); a test greps the sources for them.
- Decisions: 3, labels ≤ 4 words. A `fix` is never first; on an item with a removal warning (or a critical item
  whose maker isn't verified) **Look closer** is first.
- "Not mine" is `fix` only when the engine offered one (`finding.fixable`); otherwise the settings pane that switches
  it off (Login Items on a Mac, Startup apps on Windows), else a `closer` with switch-off steps taken from the
  module's own "What to do" text (Task Scheduler, Services), never invented menus.
- "Mine" is `mark` only when `finding.markable`; otherwise `keep` (mission state).
- Honesty: an unfinished check says "This check didn't finish"; no maker read says "Not checked"; no date says
  "Not recorded"; the summary never says "all clear".
- City mode: game words (CITY_FORBIDDEN never matches), look-ups described as "search on another device".
- No time estimates or time words in copy.
- Fixtures synthetic: `~` paths, made-up labels, no serials/MACs/SSIDs/real account names.
- `cd desktop && npm test && npm run check-game-files` green.

## Review Focus

1. **A removing default.** `decisions()` order for alerting items (`item.removal_alert`, `finding.removal_alert`,
   `remediation.safety_note`) — Look closer first, Not mine last. Tests in Task 2.
2. **Hidden-folder emphasis vs escaping.** The `<mark>` wrapper must only ever surround escaped text; hostile
   values in `program`/`path`/`command` stay inert (contract hostile set). Tests in Task 3.
3. **Verified vs claimed.** "What it is" shows `made_by[].what` only for a verified entry; an unverified entry's
   name is shown with "not verified". Tests in Task 3.
4. **Windows parity.** win_autoruns_audit / win_startup* → Startup apps pane; scheduled tasks / services → closer
   steps from the module text. Tests in Task 2.

---

### Task 1: Fields, covers and the knock facts

**Files:** Create `desktop/renderer/missions/games/door.js`, `desktop/test/missions-door.test.js`,
`desktop/test/fixtures/missions/door-mac.json`, `desktop/test/fixtures/missions/door-windows.json`.

Real field names (from `modules/**/__init__.py`): launch_agent_audit / launchd_persistence_audit `label`,
`program`, `location`, `program_exists`; scheduled_tasks_audit `label`, `location`, `plist`, `command`, `reason`;
login_items `item_name`; login_items_cleanup `items`; cron_jobs_audit `entries`; startup_auditor `label`, `name`;
startup_optimizer `items`, `third_party_labels`; security_baseline_diff `added`, `baseline_captured_at`
(code `new_persistence` only); ai_worm_persistence `plist`, `label`, `task_name`, `command`, `file`, `path`,
`unit_name`; crypto_miner_persistence `location`, `mechanism`, `indicator`; kext_audit `path`, `name`,
`bundle_id`, `is_unsigned`; kernel_extensions_audit `kexts`; system_extensions_check `waiting_extensions`,
`terminated_extensions`; win_autoruns_audit `entry_name`, `location`, `command`; win_scheduled_tasks(_security)
`task_name`, `task_path`, `command`, `created_date`, `schedule`; win_services_audit `services`, `name`,
`display_name`, `path`; win_services_security_audit `service_name`, `display_name`, `path`; win_startup `names`;
win_startup_programs_audit `items`.

- [ ] **Step 1: failing tests** — covers lists every spec module + Windows set, no duplicate module;
  `nameOf`, `runsOf`, `appearedOf`, `makerOf`, `kindOf` over fixtures; fields exist in module sources.

```js
test('the Door reads names and paths from the fields the modules really write', async () => {
  const { nameOf, runsOf } = await door();
  assert.strictEqual(nameOf({ data: { label: 'com.x.a', program: '/p' } }), 'com.x.a');
  assert.strictEqual(nameOf({ data: { entry_name: 'Updater', command: 'C:\\x.exe' } }), 'Updater');
  assert.strictEqual(runsOf({ data: { program: '~/.hidden/a', location: '~/Library/LaunchAgents' } }), '~/.hidden/a');
  for (const [mod, fields] of Object.entries(FIELDS)) {
    const src = fs.readFileSync(moduleSource(mod), 'utf8');
    for (const k of fields) assert.ok(src.includes(`"${k}"`), `${mod} writes ${k}`);
  }
});
```

- [ ] **Step 2: implement** the helpers:

```js
const NAME_KEYS = ['label', 'entry_name', 'task_name', 'display_name', 'service_name', 'item_name', 'unit_name', 'name', 'bundle_id', 'indicator'];
const RUNS_KEYS = ['program', 'path', 'command', 'file', 'plist', 'location'];
export const nameOf = (f) => firstString(dataOf(f), NAME_KEYS) || String((f && f.title) || '');
export function runsOf(f) { const d = dataOf(f); for (const k of RUNS_KEYS) if (typeof d[k] === 'string' && d[k].trim()) return d[k]; return ''; }
```

- [ ] **Step 3: run** `cd desktop && node --test test/missions-door.test.js` → pass. **Commit.**

### Task 2: Decisions

- [ ] **Step 1: failing tests** — verified → `[mine, closer, not-mine]`; alerting/critical-unverified →
  `[closer, mine, not-mine]`; markable → `mark`, else `keep`; fixable → `fix`; mac without fix → settings
  `login-items`; win startup → `startup-apps`; win task/service → closer steps naming Task Scheduler / Services;
  closer checklist names Login Items, the maker, the name to search (city: "another device").
- [ ] **Step 2: implement** `decisions(item, ctx)`:

```js
const wary = alerting(item) || (f.severity === 'critical' && !(m && m.verified === true));
return wary ? [closer, mine, notMine] : [mine, closer, notMine];
```

- [ ] **Step 3: pass. Commit.**

### Task 3: Research and render (the knock card)

- [ ] **Step 1: failing tests** — `research` returns `ctx.evidenceRows(f, {mode})`, `what`, links (settings,
  lookup `maker-site` for a verified known program, `apple-support` for Apple, else `web`; lesson
  `where-it-lives`); `unfinished`. Render: `<mark class="door-hidden">.hidden</mark>`, Windows `Temp` marked,
  `~` for home folders, "verified"/"not verified" chip, "Not checked", "30 Sep 2026", "New since", "Not recorded",
  "This check didn't finish", lists capped at 4 + "and N more", practice pointer class.
- [ ] **Step 2: implement** `pathHtml` (split on `/` and `\`, escape each part, wrap a dot-folder or a risky
  temp/download folder in `<mark>`), `render`, `research`.
- [ ] **Step 3: pass. Commit.**

### Task 4: Practice, summary, contract

- [ ] **Step 1: failing tests** — practice has a verified Apple agent (expect `mine`), an unsigned agent in
  `~/.hidden` (expect `not-mine`), a developer tool you installed (expect `mine`); each `expect` is a decision id of
  its item; `summary` counts and never says "all clear"; `runContractChecks(game, fixtureItems)` is `[]`;
  fixtures pass a privacy scan.
- [ ] **Step 2: implement** `practice`, `summary`.
- [ ] **Step 3: pass; full suite `cd desktop && npm test && npm run check-game-files`. Commit.**

### Task 5: Styles and visual check

- [ ] `games/door.css` with `.door-*` classes on the game variables; preview HTML in the scratch folder rendering
  practice + fixture items in standard and city mode; screenshot both. **Commit.**
