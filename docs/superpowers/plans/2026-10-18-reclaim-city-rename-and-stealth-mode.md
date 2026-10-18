# Reclaim City: the Rename, the Safety Question and Stealth Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The desktop app becomes Reclaim City for everyone. One remembered question decides how much safety text a person sees. People worried about someone close to them get a city mode where the game is the cover and the help lives in one district, under a name generated for that install.

**Architecture:**
- **Two remembered values, both innocuous.** A new classic script, `display-mode.js`, stores the display preference (`city` | `standard`) and a per-install seed. That is all the new code writes to disk.
- **The question and its follow-up.** `first-question.js` holds both questions and maps each answer to a mode. `app.js` shows them on their own screen: once after the worry screen, and once a session when a standard-mode scan finds monitoring software.
- **Quiet text.** `quiet-notes.js` strips hotline and advocate paragraphs from every finding, except a monitoring-software finding. In standard mode that finding carries one line, with the full note behind it. In city mode it carries the hold line ("Don’t remove it yet…") and nothing else: no steps, no fix, no mark.
- **City mode.** The app opens into the game. Monitoring findings never become missions or signals (`game/held.js`), so nothing about them is scored or saved. They wait in a generated district (`game/district-names.js`, `game/side-district.js`). The district lives on the command deck, and Esc returns to the deck at once.
- **Rename.** Electron's product name, title, installer names and every shipped page say Reclaim City. The appId and the user-data folder stay as they were, so saved progress survives.

**Tech Stack:** Electron 41, plain JavaScript (classic scripts plus ES modules under `desktop/renderer/game/`, no bundler), `node --test` (Node 22); Python 3.11+ / pytest for the engine and repository checks; electron-builder; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-18-reclaim-city-rename-and-stealth-mode-design.md`. The help district lives on the command deck from `docs/superpowers/specs/2026-10-18-command-center-signal-or-noise-design.md`, which its own plan (`docs/superpowers/plans/2026-10-18-command-center-signal-or-noise.md`) builds. Only Task 8 depends on that plan.

## Global Constraints

From the spec (verbatim where quoted):
- Rename: "Device Rescue → Reclaim City, everywhere", including "installer and artifact names (`ReclaimCity-mac-arm64.dmg`, `ReclaimCity-mac-x64.dmg`, `ReclaimCity-windows-x64.exe`), Dock name, icon (a game icon, not a shield)."
- "**Kept stable on purpose:** the installer's `appId` (so updates and OS permissions carry over) and the user-data location (set explicitly so saved progress and the game store `device-rescue.game.v1` survive the rename). The storage key keeps its name; it's never shown."
- "**Not renamed:** the engine CLI `rescue` and the Python package (existing installs and AI-assistant instructions depend on it), and the GitHub repository (renaming it changes every link; a separate decision for the owner)."
- "The plain checkup is presented as **Plain view**, one way to play."
- "**Release links:** the stable `releases/latest/download/…` names change with the artifacts; the download page and README move to the new names in the same release. Old links stop working at that release, so the page must ship with it."
- "Publishing the site, the `/x/` page and a release are outward-facing and wait for the owner's go-ahead."
- The question, word for word: "Is there someone in your life you're worried might be watching your devices — a partner, an ex, a family member, someone you live with?" No → Standard. Yes, that's part of it → Stealth (`city`). I'd rather not say → Standard.
- "The worry "I think someone is watching me" goes straight to stealth mode without asking."
- "**Stored innocuously:** as a display preference, `city` or `standard`. The words partner, safety, stalking or watching never appear on disk."
- "**Changing it:** a quiet "Something changed?" link on the worry screen opens the question again. No nagging."
- "**Re-check when there's a reason:** if monitoring software turns up and the mode is standard, ask once: "We found something that can be used to watch a computer. Is that something you know about?" The answer can switch to stealth. This replaces today's rule that withdraws the game when monitoring is seen."
- Standard mode: "Safety paragraphs, the scan-screen banner and hotline lines are hidden (`wantsSafetyNote` becomes mode-driven instead of worry-driven)." "**Kept, always:** a finding that *is* monitoring software carries one line: "Removing this can alert whoever installed it. Read this first." with the full note behind it."
- Stealth mode: "**Opens into the game.**" "The pool holds only names that fit the city; none of them hint at safety." "**Monitoring findings never say "remove".** In stealth mode a monitoring finding goes to the help district as "Don't remove it yet. Talk to an advocate first," with how to capture evidence of it quietly. No fix, no "It's mine" prompt, no points for it."
- "**Panic key.** On any help-district screen, Esc or a "back to the game" button swaps instantly to the ordinary deck, with focus on the map."
- "**Quiet traces.** No notifications. Ops log and history entries for the help district are generic ("Visited Pier 9"). Nothing written names what was read."
- "stealth never prompts removal, never shows a fix for monitoring software, and always offers the help district."
- "Plain, calm, no fear. Every hotline, resource and step is traceable to the Six Roses guide or an existing project guide; a test checks the help-district text against those sources, like the lesson accuracy test."
- Out of scope: "Hiding the app from monitoring software that watches running processes; a per-install app icon or name; renaming the GitHub repo or the CLI."

Project rules:
- Renderer scripts that `index.html` loads with `<script src>` are classic scripts with a CommonJS export for Node tests (the `clear-list.js` pattern). Game code is plain ES modules under `desktop/renderer/game/`. No bundler, no new dependencies.
- No time estimates anywhere: none in UI copy, none in docs, none in this plan's tasks.
- Copy is for a frightened, non-technical person: short sentences, calm, never "you're safe".
- Nothing the app writes to disk names a partner, safety, stalking, watching, an advocate or a hotline. That covers storage keys, stored values, and the game's progress store. `monitoringSeen` and `recheckAsked` stay in memory only and are never persisted. New file names, storage keys and CSS classes are neutral too (`display-mode.js`, `side-district.js`, `.side-tile`).
- Read-only by default. Never pass `--auto`, `--yes` or `--i-understand` for the person. Every fix still goes through `FixFlow` and every mark through `MarkFlow`. In city mode, monitoring software gets neither.
- Escape every string from the engine with `escapeHtml` (app.js) or `esc` (game).
- Editing any `rescue/*.py` file means running `uv run python scripts/generate_integrity_manifest.py` and committing `rescue/security/integrity_manifest.json`, or CI fails.
- Work on a feature branch (for example `reclaim-city`). **Never merge to `main` and never push.** A push to `main` deploys `site/` and the docs (`.github/workflows/docs.yml`), so a merge is itself publishing. The merge has to land together with the release tag. Both are the owner's steps (Task 9).
- Tests: `cd desktop && node --test test/<file>.test.js` for one file, `cd desktop && npm test` for all of them, and `.venv/bin/python -m pytest -q` for Python.

## Review Focus

1. **An existing install upgrading, with progress saved under the old name.** Electron derives `userData` from the product name. Unpinned, the rename would open an empty `~/Library/Application Support/Reclaim City`, and the person's progress would be gone. Pinned in Task 3 (`userDataDir` is called before `app.whenReady`, and the folder is `Device Rescue`). Task 1 proves the mode store never removes or rewrites existing keys, and that a missing mode means the question is asked once.
2. **A "rather not say" person whose scan finds monitoring software.** They are in standard mode. Nothing lands, in the city or the list, until they answer the follow-up, and they are asked once per session. "No, I don’t" switches to `city` and re-renders the list so the card loses its fix and mark. "Yes, I know about it" keeps standard and the game. Pinned in Task 5 (asked once) and Task 7 (both answers, end to end).
3. **The panic key pressed mid-transition.** For example, Esc while "Open it in your browser" is still resolving and is then refused. Afterwards the deck must show no notice and no URL. A second Esc on the deck does nothing. A sweep that finishes while the person is in the district leaves them there, and Esc then lands on the new deck. Pinned in Task 8.
4. **A city-mode person picking a different worry later.** For example, Plain view, then Start over, then "Someone is on my Wi-Fi". They aren't asked again, the scan runs in the game, the mode stays `city`, and monitoring software found by that scan keeps them in the game. Pinned in Task 7.
5. **"Device Rescue" in a user-facing string the engine generates.** For example, the "It's mine" confirmation (`known_items.py`), the Undo steps for a background job (`app_fixes.json`, `actions/launch_agent.py`), or Find My Mac's "couldn't read" findings. The app shows these strings verbatim. Pinned in Task 4: a test reads the real engine constants and `app_fixes.json`, and a repository test greps every shipped file.

## Decisions made while planning (spec ambiguities)

- **"Rather not say" and "No" behave the same.** The storage rule allows only `city` and `standard`, so the two can't be told apart later. Standard mode already cuts safety text to the one line with "more" behind it, which is exactly what the spec asks for "rather not say".
- **The follow-up answers:** "Yes, I know about it" → `standard`, "No, I don’t" → `city`, "I’d rather not say" → `standard`. "No" goes to `city` because unexplained monitoring software is exactly the case where removing it is risky, and city mode never prompts removal. It is asked at most once per app session, and remembering that is memory only. Persisting "already asked" would itself be a trace.
- **The seed is written at first launch, for every install.** It isn't written at first entry into stealth mode, so its presence on disk doesn't single anyone out. The district is still picked from it when city mode is first shown.
- **City mode with no sweep yet opens the Training Grounds,** the game's home before a scan. Its scan uses the "I think someone is watching me" profile under a plain title ("Take back the city"). The district's tile is on the Training Grounds as well as the deck, and Esc returns to whichever is home.
- **The iPhone worry stays on its plain screen in both modes.** It reads a phone backup and has its own flow. This is today's behaviour, now for that reason only.
- **Monitoring software never becomes a game mission or signal, in either mode.** The command-center plan already keeps it out of signals. In standard mode the plain list still shows it with the one-line note and its usual controls, where the person can act after reading.
- **A monitoring card in standard mode keeps its own steps.** They are the careful removal steps from `respond_to_monitoring_software.md`. The spec's "no DV text except the one-line note on monitoring findings" is read as "except on monitoring-software cards".
- **Only the Six Roses guide opens from the help district.** The other resources are shown as text, so the browser's history doesn't fill with their names. The guide's own advice goes with it: "Delete this from your browser history after reading" and "Consider using a library or friend's computer".
- **Engine text the app shows** (marks, Undo steps, Find My Mac) says Reclaim City. The CLI's own help and banners (`rescue --help`, `rescue --auto`, the TUI) keep their wording, because the CLI isn't renamed. The real folder name `Application Support/Device Rescue` stays wherever a path is printed.
- **One line for upgraders** ("Reclaim City used to be called Device Rescue.") goes in the README, the download page and the release notes. The repository test allows exactly that phrase.
- **The Six Roses guide has changed since the spec was written.** It now has a "⚠️ Before You Remove Anything" warning ("Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it…") and cites NPR's 2014 survey for its figure. The spec's "Note for the Six Roses guide" is out of date on both points. The help district quotes that warning.
- **The web version's card on the download page** ("Device Rescue (Web)") becomes "Reclaim City (Web)" with everything else. The owner confirms the web tool's name before publishing (Task 9).

## Dependencies and parallel batches

| Task | Depends on | Batch |
|---|---|---|
| 1. Mode store | — | A |
| 2. District name pool | — | A |
| 3. Electron rename | — | A |
| 4. Copy rename and the name test | 3 | B |
| 5. The safety question | 1, 3 | B |
| 6. Standard mode: quiet notes | 5 | C |
| 7. City mode: routing and the rewritten gate | 6 | D |
| 8. The help district on the deck | 2, 7, **command-center plan merged** | E |
| 9. Manual QA and the owner's publishing checklist | all | F |

Tasks in the same batch touch no file in common:
- **A:** Task 1 creates `display-mode.js` and two test files. Task 2 creates `game/district-names.js` and its test. Task 3 touches `package.json`, `main.js`, `user-data.js`, `index.html`, `app.js` (one constant) and `release.yml`.
- **B:** Task 4 touches docs, site, shared, scripts, engine strings, game copy, `clear-list.js`, `ai-prompt.js`, `fix-policy.js` and a few test fixtures. Task 5 touches `index.html`, `app.js`, `styles.css`, `first-question.js` and desktop flow tests. Task 4 doesn't touch `index.html`, `app.js` or `styles.css`.
- Tasks 5, 6 and 7 each edit `app.js` and `index.html`, so they run one after another.
- **Collisions with the command-center plan, which is running in another worktree:**
  - Task 4 changes one string in `game/views/map.js`. That plan adds parameters to the same file, on different lines.
  - Tasks 6 and 7 each change two lines in `controller.js` (`rebuild`). Task 8 depends on that plan outright.
  - Task 7 replaces `desktop/test/game-flow-gate.test.js` whole, including any RE-SWEEP gate test that plan added. That test asserted the old withdrawal, and Task 7's file covers the replacement rule.
  - Task 7 adds `ALWAYS_SAFETY_MODULES` to `app.js`'s exports. That plan adds the same line, so keep one copy when merging.

---

## File Structure

**Renderer, classic scripts** (`desktop/renderer/`, loaded by `index.html` before `app.js`)
- Create `display-mode.js`: `DisplayMode` = `{ MODE_KEY, SEED_KEY, MODES, readMode, writeMode, ensureSeed }`.
- Create `first-question.js`: `FirstQuestion` = `{ QUESTIONS, STRAIGHT_TO_CITY, modeFor, afterWorry, recheckDue, questionHtml }`.
- Create `quiet-notes.js`: `QuietNotes` = `{ MONITORING_MODULES, MARKERS, LINE, HELD_LINE, HELD_MORE, isMonitoring, quiet, quietFinding, quietDoc, noteFor, cardText, lineHtml, heldHtml }`. Also set as `window.QuietNotes`.
- Modify `app.js`:
  - Task 3: `GAME_INTRO`.
  - Task 5: the question screen, `mode`, `setMode`, `ask`, `startWorry`, `RescueHost.mode` and `citySeed`, the follow-up.
  - Task 6: cards via `QuietNotes`, no banner.
  - Task 7: the gate rewrite, `CITY_SITUATION`, `opensInGame`, city launch, held cards.
- Modify `index.html`: Task 3 (name and copy), Task 5 (question screen, link, scripts), Task 6 (banners out, script).
- Modify `styles.css`: Task 5 (question screen).

**Game** (`desktop/renderer/game/`, ES modules)
- Create `district-names.js`: `NAMES`, `LOOKS`, `VOICES`, `GIVEAWAY`, `pickDistrict(seed)`.
- Create `held.js`: `HELD_MODULES`, `splitHeld(doc)`.
- Create `side-district.js`: `FIRST_STEPS`, `HELP`, `OPEN_NOTE`, `SIX_ROSES`, `LEAVING`, `HELD`.
- Create `views/side-district.js`: `sideTileHtml`, `heldNoticeHtml`, `renderSide`.
- Modify `controller.js`: Task 6 (`quietDoc`), Task 7 (`splitHeld`, `s.held`), Task 8 (the district screen, tile, Esc, log).
- Modify `game.css`: Task 8 (the district's looks).
- Modify copy only: `scout-lines.js`, `views/map.js`, `views/milestone.js`, `lessons/*.js` (Task 4).

**Main process** (`desktop/`)
- Create `user-data.js`: `DATA_DIR_NAME`, `userDataDir(appDataDir)`.
- Modify `main.js`, `package.json` (Task 3). Modify `setting-urls.js` (Task 8). Copy only in `ai-prompt.js`, `fix-policy.js` (Task 4).

**Tests** (`desktop/test/`)
- Create `disk-words.js` (helper), `display-mode.test.js` (Task 1).
- Create `game-district-names.test.js` (Task 2).
- Create `app-identity.test.js` (Task 3).
- Create `page-harness.js` (helper), `first-question.test.js`, `first-question-flow.test.js`; modify `game-worry-scan.test.js` (Task 5).
- Create `quiet-notes.test.js`; delete `safety-note.test.js` (Task 6).
- Rewrite `game-flow-gate.test.js` and `game-gate.test.js`; create `stealth-mode.test.js`; modify `game-worry-scan.test.js` (Task 7).
- Create `fixtures/six-roses-excerpt.txt`, `game-side-district.test.js`, `game-side-district-controller.test.js` (Task 8).

**Python, CI and docs**
- Create `tests/test_product_name.py` (Task 4).
- Modify `.github/workflows/release.yml` (Task 3), plus docs, site, shared, scripts and engine strings (Task 4). Modify `desktop/MANUAL-QA.md` (Task 9).

---

### Task 1: The mode store

**Files:**
- Create: `desktop/renderer/display-mode.js`
- Create: `desktop/test/disk-words.js`
- Test: `desktop/test/display-mode.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - Global `DisplayMode` (and `module.exports`):
    - `MODE_KEY = 'device-rescue.display'`, `SEED_KEY = 'device-rescue.city-seed'`, `MODES = ['city', 'standard']`
    - `readMode(storage) -> 'city' | 'standard' | null`
    - `writeMode(storage, mode) -> boolean` (writes only a value in `MODES`)
    - `ensureSeed(storage, random = Math.random) -> integer in [1, 2^31-1]`
  - Test helper `desktop/test/disk-words.js`: `FORBIDDEN_ON_DISK` (RegExp); `recordingStore(initial) -> { data, writes: [[k, v]], removed, getItem, setItem, removeItem, clear }`; `forbiddenWrites(store) -> string[]`.
  - Task 5 adds the `<script>` tag. This task doesn't touch `index.html`.

- [ ] **Step 1: Write the test helper**

Create `desktop/test/disk-words.js`:

```js
// Words that must never be written to disk by the app. A stored key or value
// containing one could tell whoever looks at this computer what the person
// was worried about. Used by the storage tests.
const FORBIDDEN_ON_DISK = /partner|safety|\bsafe\b|stalk|watch|abuse|violence|advocate|hotline|799-7233|88788|monitor|spy/i;

// A storage that records every write, for the tests.
function recordingStore(initial = {}) {
  const data = { ...initial };
  const writes = [];
  const removed = [];
  return {
    data, writes, removed,
    getItem: (k) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null),
    setItem: (k, v) => { writes.push([String(k), String(v)]); data[k] = String(v); },
    removeItem: (k) => { removed.push(String(k)); delete data[k]; },
    clear: () => { removed.push('*'); for (const k of Object.keys(data)) delete data[k]; },
  };
}

// The writes that broke the rule, as "key=value".
function forbiddenWrites(store) {
  return store.writes.filter(([k, v]) => FORBIDDEN_ON_DISK.test(k) || FORBIDDEN_ON_DISK.test(v)).map(([k, v]) => `${k}=${v}`);
}

module.exports = { FORBIDDEN_ON_DISK, recordingStore, forbiddenWrites };
```

- [ ] **Step 2: Write the failing tests**

Create `desktop/test/display-mode.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const DisplayMode = require('../renderer/display-mode.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };

test('only two values are ever written: city and standard', () => {
  const store = recordingStore();
  assert.strictEqual(DisplayMode.writeMode(store, 'city'), true);
  assert.strictEqual(DisplayMode.writeMode(store, 'standard'), true);
  for (const bad of ['stealth', 'watched', 'safety', '', null, undefined, 'CITY', ' city', 1, {}]) {
    assert.strictEqual(DisplayMode.writeMode(store, bad), false, String(bad));
  }
  assert.deepStrictEqual(store.writes, [[DisplayMode.MODE_KEY, 'city'], [DisplayMode.MODE_KEY, 'standard']]);
});

test('reading: a stored value, or null for anything else', () => {
  assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: 'city' })), 'city');
  assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: 'standard' })), 'standard');
  for (const raw of ['stealth', '', '{"mode":"city"}', 'City']) {
    assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: raw })), null, raw);
  }
  assert.strictEqual(DisplayMode.readMode(recordingStore()), null);
  assert.strictEqual(DisplayMode.readMode(null), null);
  assert.strictEqual(DisplayMode.readMode(throwing), null);
  assert.strictEqual(DisplayMode.writeMode(throwing, 'city'), false);
});

test('the keys and everything written say nothing about why', () => {
  const store = recordingStore();
  DisplayMode.writeMode(store, 'city');
  DisplayMode.writeMode(store, 'standard');
  DisplayMode.ensureSeed(store, () => 0.5);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.deepStrictEqual([...new Set(store.writes.map(([k]) => k))].sort(), [DisplayMode.MODE_KEY, DisplayMode.SEED_KEY].sort());
  assert.match(DisplayMode.MODE_KEY, /^device-rescue\./);
  assert.match(DisplayMode.SEED_KEY, /^device-rescue\./);
});

test('an existing install keeps everything it saved: nothing is removed or rewritten', () => {
  const saved = {
    'device-rescue.game.v1': JSON.stringify({ version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: '2026-10-01T00:00:00Z' } }, lessons: {} }),
    'device-rescue.view': 'city',
    'device-rescue.game.scan-confirmed.v1': '{"version":1,"missions":{}}',
    'reclaim-city.analytics-off': '1',
  };
  const store = recordingStore(saved);
  assert.strictEqual(DisplayMode.readMode(store), null, 'no mode yet: the question is asked once');
  DisplayMode.writeMode(store, 'standard');
  DisplayMode.ensureSeed(store, () => 0.25);
  for (const [k, v] of Object.entries(saved)) assert.strictEqual(store.getItem(k), v, k);
  assert.deepStrictEqual(store.removed, []);
  assert.ok(store.writes.every(([k]) => k === DisplayMode.MODE_KEY || k === DisplayMode.SEED_KEY));
});

test('the seed is made once and then kept', () => {
  const store = recordingStore();
  const a = DisplayMode.ensureSeed(store, () => 0.5);
  const b = DisplayMode.ensureSeed(store, () => 0.9);
  assert.strictEqual(a, b);
  assert.strictEqual(store.writes.length, 1);
  assert.ok(Number.isInteger(a) && a >= 1 && a <= 0x7fffffff);
  assert.strictEqual(DisplayMode.ensureSeed(store), a);
});

test('a seed that is missing or damaged is replaced; the extremes stay in range', () => {
  for (const raw of ['abc', '0', '-5', '1.5', '99999999999', '', ' 12']) {
    const store = recordingStore({ [DisplayMode.SEED_KEY]: raw });
    const n = DisplayMode.ensureSeed(store, () => 0.5);
    assert.ok(Number.isInteger(n) && n >= 1 && n <= 0x7fffffff, raw);
    assert.strictEqual(store.getItem(DisplayMode.SEED_KEY), String(n), raw);
  }
  assert.strictEqual(DisplayMode.ensureSeed(recordingStore(), () => 0), 1);
  assert.ok(DisplayMode.ensureSeed(recordingStore(), () => 0.9999999999) <= 0x7fffffff);
  assert.strictEqual(DisplayMode.ensureSeed(recordingStore({ [DisplayMode.SEED_KEY]: '424242' })), 424242);
});

test('blocked storage still gives a usable seed, without throwing', () => {
  const n = DisplayMode.ensureSeed(throwing, () => 0.5);
  assert.ok(Number.isInteger(n) && n >= 1);
  assert.ok(Number.isInteger(DisplayMode.ensureSeed(null, () => 0.5)));
});
```

- [ ] **Step 3: Run the tests to make sure they fail**

Run: `cd desktop && node --test test/display-mode.test.js`
Expected: FAIL with `Cannot find module '../renderer/display-mode.js'`.

- [ ] **Step 4: Write the module**

Create `desktop/renderer/display-mode.js`:

```js
'use strict';

/*
 * One display preference, kept as `city` or `standard` and nothing else.
 * `city` opens straight into the game. Also a number made once per install,
 * which the game uses to name and dress one of its districts. Neither value
 * says why it was chosen, and nothing here ever removes another key.
 *
 * Loaded as a plain script (global `DisplayMode`); tested from Node.
 */
const DisplayMode = (function () {
  const MODE_KEY = 'device-rescue.display';
  const SEED_KEY = 'device-rescue.city-seed';
  const MODES = ['city', 'standard'];
  const MAX_SEED = 0x7fffffff;

  function readMode(storage) {
    try {
      const v = storage ? storage.getItem(MODE_KEY) : null;
      return MODES.includes(v) ? v : null;
    } catch (_) {
      return null;
    }
  }

  function writeMode(storage, mode) {
    if (!MODES.includes(mode)) return false;
    try {
      storage.setItem(MODE_KEY, mode);
      return true;
    } catch (_) {
      return false;
    }
  }

  function ensureSeed(storage, random = Math.random) {
    try {
      const raw = storage ? storage.getItem(SEED_KEY) : null;
      if (typeof raw === 'string' && /^\d+$/.test(raw)) {
        const n = Number(raw);
        if (Number.isInteger(n) && n >= 1 && n <= MAX_SEED) return n;
      }
    } catch (_) { /* blocked storage: a seed for this session only */ }
    const seed = 1 + Math.floor(random() * (MAX_SEED - 1));
    try { storage.setItem(SEED_KEY, String(seed)); } catch (_) { /* this session only */ }
    return seed;
  }

  return { MODE_KEY, SEED_KEY, MODES, readMode, writeMode, ensureSeed };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DisplayMode;
}
```

- [ ] **Step 5: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/display-mode.test.js`
Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/display-mode.js desktop/test/disk-words.js desktop/test/display-mode.test.js
git commit -m "Display preference store: city or standard, and a per-install seed"
```

---

### Task 2: The district name pool

**Files:**
- Create: `desktop/renderer/game/district-names.js`
- Test: `desktop/test/game-district-names.test.js`

**Interfaces:**
- Consumes: `DISTRICTS`, `OUTSKIRTS` from `game/findings-to-city.js` (test only).
- Produces:
  - `NAMES: string[]` (48 names), `LOOKS: string[]` (`dusk`, `harbor`, `brass`, `moss`, `ember`, `neon`)
  - `VOICES: { id, hello, bye }[]` (6 voices), `GIVEAWAY: RegExp`
  - `pickDistrict(seed) -> { name: string, look: string, voice: { id, hello, bye } }`, deterministic per seed. Task 8 uses it.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/game-district-names.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const load = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

test('a large pool of names that fit the city, all different', async () => {
  const { NAMES } = await load('district-names.js');
  assert.ok(NAMES.length >= 40, `${NAMES.length} names`);
  assert.strictEqual(new Set(NAMES).size, NAMES.length);
  for (const n of NAMES) {
    assert.match(n, /^[A-Z0-9][\w’' ]*$/, n);
    assert.ok(n.length <= 24, n);
  }
});

test('nothing in a name, a look or a voice hints at what the district holds', async () => {
  const { NAMES, LOOKS, VOICES, GIVEAWAY } = await load('district-names.js');
  for (const text of [...NAMES, ...LOOKS, ...VOICES.flatMap((v) => [v.id, v.hello, v.bye])]) {
    assert.doesNotMatch(text, GIVEAWAY, text);
  }
  for (const bad of ['Safe Harbor', 'The Help Desk', 'Haven Street', 'Hope Lane', 'Shelter Point', 'Watchtower', 'Sanctuary Row']) {
    assert.match(bad, GIVEAWAY, `the check must catch ${bad}`);
  }
});

test('no name clashes with a district the game already has', async () => {
  const { NAMES } = await load('district-names.js');
  const { DISTRICTS, OUTSKIRTS } = await load('findings-to-city.js');
  const taken = new Set([...DISTRICTS, OUTSKIRTS].map((d) => d.name.toLowerCase()));
  for (const n of NAMES) assert.ok(!taken.has(n.toLowerCase()), n);
});

test('the same install always gets the same district', async () => {
  const { pickDistrict } = await load('district-names.js');
  for (const seed of [1, 7, 424242, 0x7fffffff]) assert.deepStrictEqual(pickDistrict(seed), pickDistrict(seed));
});

test('different installs get different districts', async () => {
  const { pickDistrict, LOOKS, VOICES } = await load('district-names.js');
  const names = new Set();
  const looks = new Set();
  const voices = new Set();
  for (let seed = 1; seed <= 500; seed += 1) {
    const d = pickDistrict(seed);
    names.add(d.name); looks.add(d.look); voices.add(d.voice.id);
  }
  assert.ok(names.size >= 30, `${names.size} names from 500 installs`);
  assert.strictEqual(looks.size, LOOKS.length);
  assert.strictEqual(voices.size, VOICES.length);
});

test('a bad seed still gives a district from the pools', async () => {
  const { pickDistrict, NAMES, LOOKS, VOICES } = await load('district-names.js');
  for (const seed of [0, -1, 1.5, NaN, null, undefined, '12']) {
    const d = pickDistrict(seed);
    assert.ok(NAMES.includes(d.name) && LOOKS.includes(d.look) && VOICES.includes(d.voice), String(seed));
  }
});
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `cd desktop && node --test test/game-district-names.test.js`
Expected: FAIL with `Cannot find module …/district-names.js`.

- [ ] **Step 3: Write the module**

Create `desktop/renderer/game/district-names.js`:

```js
// One district of the city is generated per install: its name, its look and
// the voice it greets you in are picked from these pools with the install's
// own number (DisplayMode's seed). The same install always gets the same
// district; different installs get different ones, so there is no fixed name
// to search for or recognise. Pure; no DOM.

export const NAMES = [
  'The Night Market', 'Pier 9', 'Clocktower Commons', 'The Observatory', 'Lantern Row', 'Copper Alley',
  'The Old Mill', 'Glasshouse Gardens', 'Ferry Landing', 'The Arcade', 'Tin Roof Lane', 'The Boardwalk',
  'Juniper Court', 'The Foundry', 'Canal Street', 'The Tramyard', 'Velvet Quarter', 'Pinecone Square',
  'The Waterworks', 'Moonlight Diner', 'Neon Strip', 'Harbor Lights', 'The Atrium', 'Saltmarsh Row',
  'Briar Lane', 'The Bandstand', 'Cobalt Yard', 'Orchard Street', 'The Greenhouse', 'Driftwood Quay',
  'Paper Lantern Plaza', 'Marigold Mews', 'The Roundhouse', 'Kite Hill', 'Ember Lane', 'Silverfish Wharf',
  'Thistle Court', 'The Planetarium', 'Crow’s Nest', 'Fig Tree Square', 'Starlight Rink', 'The Junction',
  'Brass Button Lane', 'Willow Steps', 'Ninth Street Garage', 'The Bakery Steps', 'Rooftop Terrace', 'Gaslight Row',
];

// Each look is a `.look-<id>` rule in game.css.
export const LOOKS = ['dusk', 'harbor', 'brass', 'moss', 'ember', 'neon'];

export const VOICES = [
  { id: 'market', hello: 'Lanterns are up. Pull up a crate and stay a while.', bye: 'The stalls will be here when you come back.' },
  { id: 'dock', hello: 'Tide’s in. Find a spot on the bench.', bye: 'The boats come in every night.' },
  { id: 'clock', hello: 'The gears are turning. Have a seat by the big wheel.', bye: 'The clock keeps going for you.' },
  { id: 'stars', hello: 'The dome is open. Plenty of room under the sky.', bye: 'The sky will still be here.' },
  { id: 'garden', hello: 'Mind the vines. There’s a bench in the shade.', bye: 'Come back when the flowers open.' },
  { id: 'diner', hello: 'The booth by the window is free. Coffee’s on.', bye: 'Your booth stays open.' },
];

// No name or voice may hint at what the district holds.
export const GIVEAWAY = /safe|help|hotline|advoca|abuse|partner|watch|stalk|shelter|refuge|haven|sanctuar|escape|rescue|secret|hidden|danger|violen|protect|support|crisis|hope|recover/i;

// mulberry32: a small, well-mixed generator; the same seed gives the same picks.
function generator(seed) {
  let a = seed | 0;
  return function next() {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pickDistrict(seed) {
  const n = Number.isInteger(seed) && seed > 0 ? seed : 1;
  const next = generator(n);
  const at = (list) => list[Math.floor(next() * list.length)];
  return { name: at(NAMES), look: at(LOOKS), voice: at(VOICES) };
}
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/game-district-names.test.js`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/district-names.js desktop/test/game-district-names.test.js
git commit -m "Game: a per-install district name, look and voice from city-only pools"
```

---

### Task 3: The Electron rename

**Files:**
- Create: `desktop/user-data.js`
- Modify: `desktop/package.json` (description, `productName`, `build`)
- Modify: `desktop/main.js:1-37` (requires, userData pin, title, About)
- Modify: `desktop/renderer/index.html:7`, `:15-16`, `:31-58`, `:86-89`, `:124-127`, `:163`
- Modify: `desktop/renderer/app.js:215` (`GAME_INTRO`)
- Modify: `.github/workflows/release.yml:12-15`, `:127-129`, `:146`, `:153-154`
- Test: `desktop/test/app-identity.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `desktop/user-data.js`: `DATA_DIR_NAME = 'Device Rescue'`, `userDataDir(appDataDir) -> string`.
  - Artifact names `ReclaimCity-mac-${arch}.${ext}` and `ReclaimCity-windows-${arch}.${ext}`. Task 4 points the README, the site and the USB-stick script at them.
  - `index.html` contains no "Device Rescue". Task 4's repository test relies on that.

**Icon:** electron-builder picks up `desktop/build/icon.png` (1024×1024) by itself. Until the owner supplies a game icon, it ships Electron's default icon, which isn't a shield. The header's shield emoji becomes a cityscape here. Asking for the icon is on the owner's list in Task 9.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/app-identity.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const pkg = require('../package.json');
const { userDataDir, DATA_DIR_NAME } = require('../user-data.js');

const DESKTOP = path.join(__dirname, '..');
const REPO = path.join(DESKTOP, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

test('the app is called Reclaim City everywhere the installer and the OS show it', () => {
  assert.strictEqual(pkg.productName, 'Reclaim City');
  assert.strictEqual(pkg.build.productName, 'Reclaim City');
  assert.strictEqual(pkg.build.dmg.title, 'Reclaim City');
  assert.strictEqual(pkg.build.nsis.shortcutName, 'Reclaim City');
  assert.strictEqual(pkg.build.mac.artifactName, 'ReclaimCity-mac-${arch}.${ext}');
  assert.strictEqual(pkg.build.win.artifactName, 'ReclaimCity-windows-${arch}.${ext}');
  assert.doesNotMatch(JSON.stringify(pkg), /Device ?Rescue/);
});

test('the installer id does not change, so updates and OS permissions carry over', () => {
  assert.strictEqual(pkg.build.appId, 'school.themultiverse.devicerescue');
});

test('saved data stays where every earlier version kept it', () => {
  assert.strictEqual(DATA_DIR_NAME, 'Device Rescue');
  assert.strictEqual(userDataDir('/Users/a/Library/Application Support'),
    path.join('/Users/a/Library/Application Support', 'Device Rescue'));
  const main = read('desktop/main.js');
  const pin = main.indexOf("app.setPath('userData', userDataDir(app.getPath('appData')));");
  assert.ok(pin > 0, 'main.js pins userData');
  assert.ok(pin < main.indexOf('app.whenReady('), 'before the app is ready');
  assert.ok(pin < main.indexOf('new BrowserWindow('), 'before any window');
  assert.ok(pkg.build.files.includes('user-data.js'), 'packaged');
});

test('the window, About and page titles are the new name, with no shield', () => {
  const main = read('desktop/main.js');
  assert.match(main, /title: 'Reclaim City'/);
  assert.match(main, /applicationName: 'Reclaim City'/);
  const html = read('desktop/renderer/index.html');
  assert.match(html, /<title>Reclaim City<\/title>/);
  assert.match(html, /<span class="brand-name">Reclaim City<\/span>/);
  assert.match(html, /<span class="route__eyebrow">Plain view<\/span>/);
  assert.doesNotMatch(html, /Device Rescue/);
  assert.doesNotMatch(html, /&#128737;/, 'no shield in the header');
});

test('the release workflow uploads, checksums and names the new artifacts', () => {
  const wf = read('.github/workflows/release.yml');
  assert.doesNotMatch(wf.replace('used to be called Device Rescue', ''), /DeviceRescue|Device Rescue/);
  assert.ok(wf.includes('desktop/dist/ReclaimCity-*.dmg'));
  assert.ok(wf.includes('desktop/dist/ReclaimCity-*.exe'));
  assert.ok(wf.includes('sha256sum ReclaimCity-* > SHA256SUMS.txt'));
  assert.ok(wf.includes('--title "Reclaim City $TAG"'));
  for (const a of ['ReclaimCity-mac-arm64.dmg', 'ReclaimCity-mac-x64.dmg', 'ReclaimCity-windows-x64.exe']) assert.ok(wf.includes(a), a);
});

test('an icon, once the owner adds one, is a 1024×1024 PNG where electron-builder looks', () => {
  const icon = path.join(DESKTOP, 'build', 'icon.png');
  if (!fs.existsSync(icon)) return; // until then electron-builder ships its default icon, not a shield
  const buf = fs.readFileSync(icon);
  assert.strictEqual(buf.toString('ascii', 1, 4), 'PNG');
  assert.strictEqual(buf.readUInt32BE(16), 1024);
  assert.strictEqual(buf.readUInt32BE(20), 1024);
});
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `cd desktop && node --test test/app-identity.test.js`
Expected: FAIL with `Cannot find module '../user-data.js'`.

- [ ] **Step 3: Pin the user-data folder**

Create `desktop/user-data.js`:

```js
// Where the app keeps what it saves (localStorage: the game's progress, the
// display preference). Electron names this folder after the app, so renaming
// the app would start everyone over with nothing. It stays in the folder
// every earlier version used. The name is never shown.
const path = require('path');

const DATA_DIR_NAME = 'Device Rescue';

function userDataDir(appDataDir) {
  return path.join(String(appDataDir), DATA_DIR_NAME);
}

module.exports = { DATA_DIR_NAME, userDataDir };
```

In `desktop/main.js`, after the line `const { APP_ORIGIN, serveApp } = require('./app-protocol');`, add:

```js
const { userDataDir } = require('./user-data');

// Before anything reads it: keep saved data in the folder earlier versions used.
app.setPath('userData', userDataDir(app.getPath('appData')));
```

Change `title: 'Device Rescue',` to `title: 'Reclaim City',`. Then make `app.whenReady().then(() => {` followed by `protocol.handle('app', …)` read:

```js
app.whenReady().then(() => {
  app.setAboutPanelOptions({ applicationName: 'Reclaim City' });
  protocol.handle('app', (request) => serveApp(request.url, __dirname));
```

- [ ] **Step 4: Rename the package and the installers**

In `desktop/package.json`:
- `"description": "Multiverse Device Rescue desktop app"` → `"description": "Reclaim City desktop app"`
- both `"productName": "Device Rescue"` → `"productName": "Reclaim City"`
- `"artifactName": "DeviceRescue-mac-${arch}.${ext}"` → `"artifactName": "ReclaimCity-mac-${arch}.${ext}"`
- `"artifactName": "DeviceRescue-windows-${arch}.${ext}"` → `"artifactName": "ReclaimCity-windows-${arch}.${ext}"`
- `"title": "Device Rescue"` (dmg) → `"title": "Reclaim City"`
- `"shortcutName": "Device Rescue"` → `"shortcutName": "Reclaim City"`
- in `build.files`, after `"main.js",` add `"user-data.js",`

`"name": "device-rescue"` and `"appId": "school.themultiverse.devicerescue"` stay.

- [ ] **Step 5: Rename the page**

In `desktop/renderer/index.html`:

`<title>Device Rescue</title>` → `<title>Reclaim City</title>`

The brand, from:
```html
        <span class="brand-mark" aria-hidden="true">&#128737;</span>
        <span class="brand-name">Device Rescue</span>
```
to:
```html
        <span class="brand-mark" aria-hidden="true">&#127961;&#65039;</span>
        <span class="brand-name">Reclaim City</span>
```

The welcome copy, from `<p class="lede">` through the end of the `route-choice` div's first button, becomes:
```html
          <p class="lede">
            Reclaim City looks over your Mac, Windows PC, or Linux machine for signs of
            trouble &mdash; unwanted software, risky settings, and things worth double-checking.
            It explains what it finds in plain language, so you can decide what to do next.
          </p>
          <div class="safety-note" role="note">
            <span class="safety-note__icon" aria-hidden="true">&#128274;</span>
            <div>
              <strong>Read-only by default.</strong>
              <span>Reclaim City only looks &mdash; it never changes anything on your device without your explicit OK.</span>
            </div>
          </div>
          <h2 class="route-prompt">How would you like to play?</h2>
          <div class="route-choice">
            <button id="btn-get-started" class="route route--check" type="button">
              <span class="route__eyebrow">Plain view</span>
              <span class="route__title">Get started</span>
              <span class="route__desc">Tell us what&rsquo;s worrying you, run a read-only checkup, and get a plain-language list of what to look at.</span>
              <span class="route__go" aria-hidden="true">Start in plain view &rarr;</span>
            </button>
```
In the second button, `<span class="route__eyebrow">Reclaim City</span>` → `<span class="route__eyebrow">The city</span>`.

The scan intro:
```html
          <p id="scan-intro" class="lede">
            When you click below, Reclaim City will look through your system for anything
            worth your attention. Nothing will be changed &mdash; this is just a look-around.
          </p>
```

The results lede:
```html
          <p class="lede">
            This is guidance, not action &mdash; Reclaim City hasn't changed anything on your
            device. Review each item and decide what, if anything, you'd like to do about it.
          </p>
```

The learn-more button: `>Open Reclaim City in your browser</button>` → `>Open the web version in your browser</button>`.

In `desktop/renderer/app.js`:
```js
const GAME_INTRO = 'Reclaim City is a free game from the same team.';
```
→
```js
const GAME_INTRO = 'Reclaim City also comes as a free game you play in your web browser.';
```

- [ ] **Step 6: Rename the release artifacts**

In `.github/workflows/release.yml`:
- Header lines 13–15: `DeviceRescue-mac-arm64.dmg`, `DeviceRescue-mac-x64.dmg` and `DeviceRescue-windows-x64.exe` → `ReclaimCity-mac-arm64.dmg`, `ReclaimCity-mac-x64.dmg` and `ReclaimCity-windows-x64.exe`.
- Upload paths:
  ```yaml
            desktop/dist/ReclaimCity-*.dmg
            desktop/dist/ReclaimCity-*.exe
  ```
- Checksums: `run: sha256sum ReclaimCity-* > SHA256SUMS.txt && cat SHA256SUMS.txt`
- The release command:
  ```yaml
            || gh release create "$TAG" -R "$GITHUB_REPOSITORY" --title "Reclaim City $TAG" \
                 --notes "Reclaim City used to be called Device Rescue. Download for Mac or Windows below. First time opening it? See https://lizthedeveloper.github.io/multiverse-device-rescue/#first-time"
  ```

- [ ] **Step 7: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/app-identity.test.js test/learn-more.test.js && npm test`
Expected: PASS. `learn-more.test.js` still finds "free game" in the suggestion.

- [ ] **Step 8: Commit**

```bash
git add desktop/user-data.js desktop/main.js desktop/package.json desktop/renderer/index.html desktop/renderer/app.js .github/workflows/release.yml desktop/test/app-identity.test.js
git commit -m "Desktop: the app is Reclaim City; appId and saved-data folder unchanged"
```

---

### Task 4: Copy rename across the site, docs and engine text, and the name test

**Files:**
- Modify (by the script in Step 3): `README.md`, `AGENTS.md`, `mkdocs.yml`, `docs/*.md`, `docs/scenarios/*.md`, `site/index.html`, `site/styles.css`, `site/guides/*.html`, `site/permissions-content.json`, `shared/permissions-content.json`, `desktop/renderer/permissions-content.json`, `scripts/build_rescue_stick.py`, `scripts/build-guides-html.py`, `scripts/build-usb-stick.sh`, `scripts/build-windows.bat`, `scripts/generate_command_catalog.py`, `rescue/known_items.py`, `rescue/app_fixes.json`, `rescue/app_fixes.py`, `rescue/actions/launch_agent.py`, `rescue/threat_map.py`, `modules/security/find_my_mac/__init__.py`, `modules/security/find_my_mac_check/__init__.py`, `desktop/ai-prompt.js`, `desktop/fix-policy.js`, `desktop/renderer/clear-list.js`, `desktop/renderer/game/scout-lines.js`, `desktop/renderer/game/views/map.js`, `desktop/renderer/game/views/milestone.js`, `desktop/renderer/game/lessons/{couldnt-check,locked-door,password-asker,starts-on-its-own,spot-the-fake}.js`, `tests/test_known_items.py`, `tests/test_launch_agent_action.py`, `desktop/test/{launch-agent-action,mark-flow,mark-items}.test.js`
- Modify by hand: `README.md` (upgrade note), `site/index.html` (upgrade note), `docs/index.md` (one sentence), `scripts/build-standalone-landing.py` (output name)
- Modify: `rescue/security/integrity_manifest.json` (regenerated)
- Test: `tests/test_product_name.py`

**Interfaces:**
- Consumes: Task 3's artifact names and its `index.html` copy.
- Produces: no shipped file says "Device Rescue" outside the allowlist in `tests/test_product_name.py`. Later tasks add no such text.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_product_name.py`:

```python
"""No shipped copy calls the app Device Rescue any more: it is Reclaim City.

The `rescue` command line keeps its name, so its own help and banners keep
theirs. So does the folder saved data lives in (a real path, never shown as a
name; moving it would lose everyone's progress).
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SHIPPED = [
    "README.md", "AGENTS.md", "CONTRIBUTING.md", "mkdocs.yml",
    "site/**/*", "shared/**/*", "docs/*.md", "docs/scenarios/**/*.md",
    "desktop/*.js", "desktop/package.json", "desktop/renderer/**/*",
    ".github/workflows/release.yml",
    "modules/**/*.py", "rescue/**/*.py", "rescue/**/*.json",
    "scripts/build_rescue_stick.py", "scripts/build-guides-html.py",
    "scripts/build-standalone-landing.py", "scripts/generate_command_catalog.py",
]
# The command line is not renamed: its help text, banners and TUI title stay.
CLI_FILES = {"rescue/cli.py", "rescue/__init__.py"}
CLI_DIRS = ("rescue/tui/",)
ALLOWED = [
    "Application Support/Device Rescue",        # the saved-data folder, a real path
    '"Application Support" / "Device Rescue"',
    "DATA_DIR_NAME = 'Device Rescue'",
    "Multiverse Device Rescue — Auto Mode",     # `rescue --auto` output, quoted in the docs
    "Multiverse Device Rescue — system diagnostic and repair toolkit",  # `rescue --help` output
    "used to be called Device Rescue",          # one line for people upgrading
]
OLD = re.compile(r"Device ?Rescue")
TEXT = {".md", ".html", ".json", ".js", ".mjs", ".py", ".css", ".sh", ".bat", ".yml", ".yaml", ".txt"}
CODE = {".js", ".mjs", ".py", ".css", ".sh", ".bat", ".yml", ".yaml"}
COMMENT = re.compile(r"^\s*(//|/\*|\*|#|<!--|REM\b)")
ARTIFACTS = ["ReclaimCity-mac-arm64.dmg", "ReclaimCity-mac-x64.dmg", "ReclaimCity-windows-x64.exe"]


def _without_allowed(text):
    for ok in ALLOWED:
        text = text.replace(ok, "")
    return text


def _shipped_files():
    seen = set()
    for pattern in SHIPPED:
        for p in sorted(ROOT.glob(pattern)):
            rel = p.relative_to(ROOT).as_posix()
            if (p.is_file() and p.suffix in TEXT and rel not in seen
                    and "/superpowers/" not in rel and "node_modules" not in rel):
                seen.add(rel)
                yield rel, p


def test_no_shipped_copy_says_device_rescue():
    bad = []
    for rel, p in _shipped_files():
        if rel in CLI_FILES or rel.startswith(CLI_DIRS):
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not OLD.search(_without_allowed(line)):
                continue
            if p.suffix in CODE and COMMENT.match(line):
                continue  # a code comment is never shown
            bad.append(f"{rel}:{n}: {line.strip()}")
    assert bad == [], "still says Device Rescue:\n" + "\n".join(bad)


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def test_engine_text_the_app_shows_uses_the_new_name():
    from rescue import known_items
    from rescue.actions import launch_agent

    texts = [known_items.MARK_WILL_CHANGE, *known_items.MARK_HOW_TO_UNDO, *launch_agent.UNDO_STEPS]
    texts += list(_strings(json.loads((ROOT / "rescue" / "app_fixes.json").read_text(encoding="utf-8"))))
    assert [t for t in texts if OLD.search(_without_allowed(t))] == []
    assert any("Reclaim City" in t for t in texts)
    # The real folder is still named where a path is printed.
    assert any("Application Support/Device Rescue/Quarantine" in t for t in launch_agent.UNDO_STEPS)


def test_download_links_use_the_new_artifact_names():
    for rel in ["README.md", "site/index.html", ".github/workflows/release.yml"]:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for a in ARTIFACTS:
            assert f"releases/latest/download/{a}" in text, f"{rel}: {a}"
    stick = (ROOT / "scripts" / "build_rescue_stick.py").read_text(encoding="utf-8")
    for a in ARTIFACTS:
        assert f'"{a}"' in stick, a
    pkg = json.loads((ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
    assert pkg["build"]["mac"]["artifactName"].startswith("ReclaimCity-mac-")
    assert pkg["build"]["win"]["artifactName"].startswith("ReclaimCity-windows-")
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/bin/python -m pytest tests/test_product_name.py -q`
Expected: FAIL. The first test lists lines in README.md, site/index.html, docs, rescue/known_items.py and others. The last test reports `README.md: ReclaimCity-mac-arm64.dmg`.

- [ ] **Step 3: Run the one-off rename**

Save this script **outside the repository** (for example as `rename_copy.py` in your scratch directory). Don't commit it.

```python
"""One-off: Device Rescue -> Reclaim City in shipped copy. Not committed."""
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
FILES = [
    "README.md", "AGENTS.md", "mkdocs.yml",
    "site/index.html", "site/styles.css", "site/permissions-content.json",
    "shared/permissions-content.json", "desktop/renderer/permissions-content.json",
    "scripts/build_rescue_stick.py", "scripts/build-guides-html.py", "scripts/build-usb-stick.sh",
    "scripts/build-windows.bat", "scripts/generate_command_catalog.py",
    "rescue/known_items.py", "rescue/app_fixes.json", "rescue/app_fixes.py",
    "rescue/actions/launch_agent.py", "rescue/threat_map.py",
    "modules/security/find_my_mac/__init__.py", "modules/security/find_my_mac_check/__init__.py",
    "desktop/ai-prompt.js", "desktop/fix-policy.js", "desktop/renderer/clear-list.js",
    "desktop/renderer/game/scout-lines.js", "desktop/renderer/game/views/map.js",
    "desktop/renderer/game/views/milestone.js",
    "desktop/renderer/game/lessons/couldnt-check.js", "desktop/renderer/game/lessons/locked-door.js",
    "desktop/renderer/game/lessons/password-asker.js", "desktop/renderer/game/lessons/starts-on-its-own.js",
    "desktop/renderer/game/lessons/spot-the-fake.js",
    "tests/test_known_items.py", "tests/test_launch_agent_action.py",
    "desktop/test/launch-agent-action.test.js", "desktop/test/mark-flow.test.js", "desktop/test/mark-items.test.js",
]
GLOBS = ["docs/*.md", "docs/scenarios/*.md", "site/guides/*.html"]
KEEP = [
    "Application Support/Device Rescue",
    '"Application Support" / "Device Rescue"',
    "Multiverse Device Rescue — Auto Mode",
    "Multiverse Device Rescue — system diagnostic and repair toolkit",
]
RULES = [("Multiverse Device Rescue", "Reclaim City"), ("Device Rescue", "Reclaim City"), ("DeviceRescue-", "ReclaimCity-")]

paths = [ROOT / f for f in FILES] + [p for g in GLOBS for p in sorted(ROOT.glob(g))]
for p in paths:
    if "superpowers" in p.parts:
        continue
    text = p.read_text(encoding="utf-8")
    new = text
    for i, keep in enumerate(KEEP):
        new = new.replace(keep, f"\x00KEEP{i}\x00")
    for old, rep in RULES:
        new = new.replace(old, rep)
    for i, keep in enumerate(KEEP):
        new = new.replace(f"\x00KEEP{i}\x00", keep)
    if new != text:
        p.write_text(new, encoding="utf-8")
        print("renamed", p.relative_to(ROOT))
```

Run: `python3 -I /path/to/rename_copy.py "$PWD"` from the repository root.
Expected: a "renamed …" line for each changed file. `git diff --stat` shows only the files listed above.

Then read the diff (`git diff`) and check four things:
- `rescue/actions/launch_agent.py` and `rescue/app_fixes.json` still name `~/Library/Application Support/Device Rescue/Quarantine` as the path, and now say "Open Reclaim City and choose Undo on this item".
- `docs/cli.md` still shows `Multiverse Device Rescue — system diagnostic and repair toolkit.` and `Multiverse Device Rescue — Auto Mode`, because those are the CLI's own output.
- `docs/THREAT_REMEDIATION.md` and `rescue/threat_map.py` changed identically.
- `docs/commands.md` and `scripts/generate_command_catalog.py` changed identically.

- [ ] **Step 4: Hand edits**

In `README.md`, after the paragraph that ends `…the button above is right.`, add:

```markdown
**Upgrading?** Reclaim City used to be called Device Rescue. Your saved progress carries over. On a Mac, the old app stays in Applications under its old name; you can drag it to the Trash.
```

In `site/index.html`, directly after the paragraph that holds the Intel download link (`Older Mac with an Intel processor? …`), add:

```html
        <p class="small">Upgrading? Reclaim City used to be called Device Rescue. Your saved progress carries over.</p>
```

In `docs/index.md`, directly under the `# Reclaim City` heading, add:

```markdown
Reclaim City is the desktop app. Underneath it is the `rescue` command line, which this site documents and which keeps its name.
```

In `scripts/build-standalone-landing.py`, change both `dist/device-rescue-landing.html` mentions (the docstring and `main()`) to `dist/reclaim-city-landing.html`. The `/x/device-rescue` address in the docstring stays: the slug is the owner's decision (Task 9).

- [ ] **Step 5: Regenerate what CI compares**

Run:
```bash
uv run python scripts/generate_integrity_manifest.py
.venv/bin/python scripts/generate_command_catalog.py --check
```
Expected: the manifest is rewritten for `rescue/known_items.py`, `rescue/app_fixes.py`, `rescue/actions/launch_agent.py` and `rescue/threat_map.py`. The catalog check passes.

- [ ] **Step 6: Run the tests to make sure they pass**

Run: `.venv/bin/python -m pytest -q && (cd desktop && npm test)`
Expected: PASS. In particular `tests/test_product_name.py`, `tests/test_threat_map_validation.py`, `tests/test_known_items.py`, `tests/test_launch_agent_action.py`, `tests/test_build_rescue_stick.py` (still ASCII, still the hotline), `desktop/test/game-lessons.test.js` and `desktop/test/clear-list.test.js` pass.

- [ ] **Step 7: Commit**

```bash
git add -A README.md AGENTS.md mkdocs.yml docs site shared scripts rescue modules desktop tests ':!docs/superpowers'
git commit -m "Copy: Device Rescue is Reclaim City in the site, docs and engine text; the CLI keeps its name"
```

---

### Task 5: The safety question

**Files:**
- Create: `desktop/renderer/first-question.js`
- Create: `desktop/test/page-harness.js`
- Modify: `desktop/renderer/index.html` (scripts, the question screen, the worry-screen link)
- Modify: `desktop/renderer/app.js`: screens, state, `ask`, `startWorry`, worry clicks, `runCheckup`, `RescueHost`
- Modify: `desktop/renderer/styles.css` (append)
- Modify: `desktop/test/game-worry-scan.test.js` (use the harness; one test updated)
- Test: `desktop/test/first-question.test.js`, `desktop/test/first-question-flow.test.js`

**Interfaces:**
- Consumes: `DisplayMode` (Task 1).
- Produces:
  - Global `FirstQuestion` (and `module.exports`):
    - `QUESTIONS.first` / `QUESTIONS.recheck`, each `{ kind, title, text, note, answers: [{ id, label, mode }] }`
    - `STRAIGHT_TO_CITY = 'watched'`
    - `modeFor(kind, answerId) -> mode | null`, `afterWorry(situation, mode) -> 'city' | 'standard' | 'ask'`
    - `recheckDue({ mode, monitoringSeen, asked }) -> boolean`, `questionHtml(kind, esc) -> html`
  - In `app.js`'s closure: `mode`, `setMode(next)`, `recheckAsked`, `ask(kind, then)`, `startWorry()`.
  - `RescueHost.mode() -> 'city' | 'standard' | null` and `RescueHost.citySeed() -> integer`, for Tasks 7 and 8.
  - `#screen-question` (`data-screen="question"`) with `#question-card`, and `#btn-something-changed`.
  - Test helper `desktop/test/page-harness.js`: `page({ store, ready }) -> { byId, calls, sandbox, storage, shown, pick, answer, fire, finish }`, plus `clean`, `monitoring`, `tick`. It loads every classic script `index.html` lists, in order, so later tasks' scripts arrive by themselves.

- [ ] **Step 1: Write the pure tests**

Create `desktop/test/first-question.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const FQ = require('../renderer/first-question.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

test('the question, word for word, with its three answers and their modes', () => {
  const q = FQ.QUESTIONS.first;
  assert.strictEqual(q.text, 'Is there someone in your life you’re worried might be watching your devices — a partner, an ex, a family member, someone you live with?');
  assert.deepStrictEqual(q.answers.map((a) => [a.id, a.label, a.mode]), [
    ['no', 'No', 'standard'],
    ['yes', 'Yes, that’s part of it', 'city'],
    ['rather-not', 'I’d rather not say', 'standard'],
  ]);
});

test('the follow-up when monitoring software turns up', () => {
  const q = FQ.QUESTIONS.recheck;
  assert.strictEqual(q.text, 'We found something that can be used to watch a computer. Is that something you know about?');
  assert.deepStrictEqual(q.answers.map((a) => [a.id, a.label, a.mode]), [
    ['known', 'Yes, I know about it', 'standard'],
    ['unknown', 'No, I don’t', 'city'],
    ['rather-not', 'I’d rather not say', 'standard'],
  ]);
});

test('every answer maps to a mode; anything else to nothing', () => {
  assert.strictEqual(FQ.modeFor('first', 'yes'), 'city');
  assert.strictEqual(FQ.modeFor('first', 'no'), 'standard');
  assert.strictEqual(FQ.modeFor('recheck', 'unknown'), 'city');
  assert.strictEqual(FQ.modeFor('first', 'unknown'), null);
  assert.strictEqual(FQ.modeFor('nope', 'yes'), null);
});

test('"I think someone is watching me" is city at once; otherwise ask until there is an answer', () => {
  for (const mode of [null, 'standard', 'city']) assert.strictEqual(FQ.afterWorry({ id: 'watched' }, mode), 'city');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, null), 'ask');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'junk'), 'ask');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'standard'), 'standard');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'city'), 'city');
  assert.strictEqual(FQ.afterWorry(null, null), 'ask');
});

test('the follow-up is due once, in standard mode, after monitoring software was seen', () => {
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: true, asked: false }), true);
  assert.strictEqual(FQ.recheckDue({ mode: null, monitoringSeen: true, asked: false }), true);
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: true, asked: true }), false);
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: false, asked: false }), false);
  assert.strictEqual(FQ.recheckDue({ mode: 'city', monitoringSeen: true, asked: false }), false);
});

test('the question screen: a heading, the question, one button per answer, all escaped', () => {
  const html = FQ.questionHtml('first', esc);
  assert.match(html, /<h1 id="question-title">One more question<\/h1>/);
  assert.ok(html.includes(esc(FQ.QUESTIONS.first.text)));
  assert.strictEqual((html.match(/data-answer="/g) || []).length, 3);
  assert.ok(html.includes('data-answer="rather-not"'));
  assert.strictEqual(FQ.questionHtml('nope', esc), '');
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/first-question.test.js`
Expected: FAIL with `Cannot find module '../renderer/first-question.js'`.

- [ ] **Step 3: Write the module**

Create `desktop/renderer/first-question.js`:

```js
'use strict';

/*
 * The one question asked after the worry screen, and the follow-up asked
 * once a session when a scan turns up software that can be used to watch a
 * computer. Each answer picks the display preference (DisplayMode): 'city'
 * or 'standard'. The answer itself is never stored, only the preference.
 *
 * Loaded as a plain script (global `FirstQuestion`); tested from Node.
 */
const FirstQuestion = (function () {
  const FIRST = {
    kind: 'first',
    title: 'One more question',
    text: 'Is there someone in your life you’re worried might be watching your devices — a partner, an ex, a family member, someone you live with?',
    note: 'Your answer only changes what this app shows you. You can change it with “Something changed?” on the worry screen.',
    answers: [
      { id: 'no', label: 'No', mode: 'standard' },
      { id: 'yes', label: 'Yes, that’s part of it', mode: 'city' },
      { id: 'rather-not', label: 'I’d rather not say', mode: 'standard' },
    ],
  };
  const RECHECK = {
    kind: 'recheck',
    title: 'Before you go on',
    text: 'We found something that can be used to watch a computer. Is that something you know about?',
    note: 'Nothing has been changed or removed.',
    answers: [
      { id: 'known', label: 'Yes, I know about it', mode: 'standard' },
      { id: 'unknown', label: 'No, I don’t', mode: 'city' },
      { id: 'rather-not', label: 'I’d rather not say', mode: 'standard' },
    ],
  };
  const QUESTIONS = { first: FIRST, recheck: RECHECK };

  // "I think someone is watching me" goes straight to 'city' without asking.
  const STRAIGHT_TO_CITY = 'watched';

  function modeFor(kind, answerId) {
    const q = QUESTIONS[kind];
    const a = q && q.answers.find((x) => x.id === answerId);
    return a ? a.mode : null;
  }

  // After a worry is picked: the mode to use now, or 'ask' for the question first.
  function afterWorry(situation, mode) {
    if (situation && situation.id === STRAIGHT_TO_CITY) return 'city';
    return mode === 'city' || mode === 'standard' ? mode : 'ask';
  }

  // Monitoring software turned up: ask once a session, and never in 'city',
  // which already keeps it out of reach. `asked` lives in memory only.
  function recheckDue({ mode, monitoringSeen, asked }) {
    return mode !== 'city' && !!monitoringSeen && !asked;
  }

  function questionHtml(kind, esc) {
    const q = QUESTIONS[kind];
    if (!q) return '';
    return `<h1 id="question-title">${esc(q.title)}</h1>
      <p class="lede">${esc(q.text)}</p>
      <ul class="question-answers">${q.answers.map((a) => `
        <li><button type="button" class="btn btn--secondary question-answer" data-answer="${esc(a.id)}">${esc(a.label)}</button></li>`).join('')}
      </ul>
      <p class="muted">${esc(q.note)}</p>`;
  }

  return { QUESTIONS, STRAIGHT_TO_CITY, modeFor, afterWorry, recheckDue, questionHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FirstQuestion;
}
```

Run: `cd desktop && node --test test/first-question.test.js`
Expected: PASS (6 tests).

- [ ] **Step 4: Write the page harness**

Create `desktop/test/page-harness.js`:

```js
// app.js's own wiring in a stubbed page, for the flow tests. Every classic
// script index.html loads runs in one global scope, in index.html's order, so
// a new script there is picked up here by itself. FixFlow, MarkFlow and
// ClearList are stand-ins: a card's fix and mark controls leave a marker, so a
// test can see whether a card offered them.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { recordingStore } = require('./disk-words.js');

const RENDERER = path.join(__dirname, '..', 'renderer');
const STUBBED = new Set(['fix-flow.js', 'mark-flow.js', 'clear-list.js']);
const INDEX = fs.readFileSync(path.join(RENDERER, 'index.html'), 'utf8');
const SCRIPTS = [...INDEX.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]).filter((f) => !STUBBED.has(f));
const SRC = SCRIPTS.map((f) => fs.readFileSync(path.join(RENDERER, f), 'utf8')).join('\n;\n');
const tick = () => new Promise((r) => setTimeout(r, 0));

class El {
  constructor() {
    this.hidden = false; this.disabled = false; this.textContent = ''; this.dataset = {}; this.style = {};
    this.listeners = {}; this.kids = []; this._html = '';
    this.classList = { toggle() {}, add() {}, remove() {}, contains: () => false };
  }
  // The buttons the page makes from HTML: one per data-situation or data-answer.
  set innerHTML(html) {
    this._html = String(html);
    this.kids = [...this._html.matchAll(/data-(situation|answer)="([^"]+)"/g)].map((m) => {
      const b = new El(); b.dataset[m[1]] = m[2]; return b;
    });
  }
  // escapeHtml sets textContent and reads innerHTML back.
  get innerHTML() { return this._html || String(this.textContent).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() { (this.listeners.click || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  querySelectorAll(sel) {
    const m = /^\[data-(situation|answer)\]$/.exec(sel);
    return m ? this.kids.filter((k) => m[1] in k.dataset) : [];
  }
  querySelector() { return null; }
  getAttribute() { return null; }
  setAttribute() {}
  appendChild() {}
  focus() {}
  scrollIntoView() {}
}

const helper = () => new Proxy(() => '', { get: (_t, k) => (k === 'attach' ? () => helper() : () => '') });

function page({ store = { 'device-rescue.display': 'standard' }, ready = true } = {}) {
  const els = {};
  const byId = (id) => (els[id] = els[id] || new El());
  const calls = { game: [], scans: [], guides: [], last: null };
  const winListeners = {};
  const storage = recordingStore(store || {});
  let finishScan = () => {};
  const sandbox = {
    console, setTimeout, Promise, JSON,
    document: { getElementById: byId, querySelectorAll: () => [], createElement: () => new El(), addEventListener() {} },
    localStorage: storage,
    fetch: () => Promise.reject(new Error('no network in tests')),
    navigator: { userAgent: 'Macintosh' },
    ClearList: helper(),
    FixFlow: { attach: () => helper(), fixControlsHtml: () => '[FIX IT]' },
    MarkFlow: { attach: () => helper(), markControlsHtml: () => '[IT IS MINE]' },
  };
  sandbox.window = sandbox;
  sandbox.scrollTo = () => {};
  sandbox.addEventListener = (type, fn) => { (winListeners[type] = winListeners[type] || []).push(fn); };
  sandbox.dispatchEvent = () => true;
  sandbox.rescue = {
    platform: 'darwin',
    onScanEvent: () => () => {},
    // Read-only: the scan IPC, with the worry's profile. Nothing else is called.
    runScan: (profile) => { calls.scans.push(profile); return new Promise((r) => { finishScan = r; }); },
    openGuide: (url) => { calls.guides.push(url); return Promise.resolve(true); },
  };
  const rec = (name, ret) => (...args) => {
    calls.game.push(name);
    calls.last = { name, args };
    return typeof ret === 'function' ? ret(...args) : ret;
  };
  sandbox.RescueGame = { isReady: ready, newWorry: rec('newWorry'), showBoss: rec('showBoss', true),
    showTraining: rec('showTraining', true), scanEvent() {}, scanDone: rec('scanDone', true),
    scanFailed: rec('scanFailed', true), show: rec('show', true) };
  vm.runInNewContext(SRC, sandbox);
  const shown = () => ['welcome', 'worry', 'question', 'scan', 'results', 'city'].filter((k) => !byId(`screen-${k}`).hidden);
  const pick = (id) => byId('situations').kids.find((b) => b.dataset.situation === id).click();
  const answer = (id) => byId('question-card').kids.find((b) => b.dataset.answer === id).click();
  const fire = (type) => (winListeners[type] || []).forEach((fn) => fn({ type }));
  const finish = async (doc) => { finishScan(doc); await tick(); await tick(); };
  return { byId, calls, sandbox, storage, shown, pick, answer, fire, finish };
}

const clean = { schema_version: 1, platform: 'darwin', modules: [] };
const monitoring = { schema_version: 1, platform: 'darwin', modules: [{ name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true,
  findings: [{ severity: 'warning', title: 'Monitoring app found', description: 'An app that can record what you type.', category: 'security', data: {} }] }] };

module.exports = { page, clean, monitoring, tick };
```

- [ ] **Step 5: Move `game-worry-scan.test.js` onto the harness**

Replace everything in `desktop/test/game-worry-scan.test.js` above the first `test(` call, from `// app.js's own wiring` through the `const monitoring = …` line, with:

```js
// app.js's own wiring, in a stubbed page: picking a worry in game mode starts
// the same read-only scan the plain route runs, straight onto the sweep screen.
const test = require('node:test');
const assert = require('node:assert');
const { SITUATIONS } = require('../renderer/app.js');
const { page, clean, monitoring } = require('./page-harness.js');

const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;
```

The test `once a scan found monitoring software, the next worry gets the plain screen, not the game` now meets the follow-up question first. Replace that test with:

```js
test('once a scan found monitoring software, the follow-up comes first; then the next worry gets the plain screen', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('known');
  assert.ok(!p.calls.game.includes('scanDone'), 'nobody lands in the city');
  assert.deepStrictEqual(p.shown(), ['results']);
  p.calls.game.length = 0;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
});
```

Task 7 changes what this test lands on.

- [ ] **Step 6: Write the failing flow tests**

Create `desktop/test/first-question-flow.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { page, monitoring } = require('./page-harness.js');

const KEY = 'device-rescue.display';
const modeWrites = (p) => p.storage.writes.filter(([k]) => k === KEY);

test('the question comes once, after the worry, before any scan', () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.deepStrictEqual(p.calls.scans, []);
  assert.deepStrictEqual(modeWrites(p), []);
  p.answer('no');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['home_network_intrusion']);
});

test('each answer stores its mode, and only the mode', () => {
  for (const [answer, mode] of [['no', 'standard'], ['yes', 'city'], ['rather-not', 'standard']]) {
    const p = page({ store: {} });
    p.byId('btn-get-started').click();
    p.pick('hacked');
    p.answer(answer);
    assert.deepStrictEqual(modeWrites(p), [[KEY, mode]], answer);
  }
});

test('once answered, the question isn’t asked again', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), []);
});

test('"I think someone is watching me" never asks: it is city', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
});

test('"Something changed?" opens the question again, then back to the worry screen', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('yes');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
  assert.deepStrictEqual(p.shown(), ['worry']);
});

test('monitoring software in a standard-mode scan: the follow-up, once a session', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.match(p.byId('question-card').innerHTML, /We found something that can be used to watch a computer\. Is that something you know about\?/);
  p.answer('known');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  await p.finish(monitoring);
  assert.ok(!p.shown().includes('question'), 'asked once a session');
});

test('the follow-up never comes in city mode', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-play-game').click();
  p.pick('hacked');
  await p.finish(monitoring);
  assert.ok(!p.shown().includes('question'));
});

test('the seed is written for every install, so it says nothing about anyone', () => {
  for (const store of [{}, { [KEY]: 'standard' }, { [KEY]: 'city' }]) {
    const p = page({ store });
    assert.ok(/^\d+$/.test(p.storage.getItem('device-rescue.city-seed')), JSON.stringify(store));
  }
});
```

Run: `cd desktop && node --test test/first-question-flow.test.js test/game-worry-scan.test.js`
Expected: FAIL. `shown()` never includes `question`, there is no `question-card` button to click (`Cannot read properties of undefined (reading 'click')`), and nothing is written to `device-rescue.display`.

- [ ] **Step 7: Add the screen and the link to `index.html`**

In `desktop/renderer/index.html`, after `<ul id="situations" class="situations"></ul>` add:

```html
          <p class="worry-change"><button id="btn-something-changed" class="link-button" type="button">Something changed?</button></p>
```

After the worry screen's closing `</section>`, add:

```html
      <!-- Screen 2b: one question, or the follow-up after a scan. Filled in by app.js. -->
      <section id="screen-question" class="screen" data-screen="question" aria-labelledby="question-title" hidden>
        <div id="question-card" class="card card--wide"></div>
      </section>
```

Before `<script src="app.js"></script>`, add:

```html
  <script src="display-mode.js"></script>
  <script src="first-question.js"></script>
```

- [ ] **Step 8: Wire it in `app.js`**

In the `screens` object, after `worry: document.getElementById('screen-worry'),`, add:

```js
      question: document.getElementById('screen-question'),
```

In `showScreen`, change `const dotName = name === 'city' ? 'results' : name;` to:

```js
      const dotName = name === 'city' ? 'results' : name === 'question' ? 'worry' : name;
```

After the line `let monitoringSeen = false;`, add:

```js
    // The display preference (DisplayMode): 'city', 'standard', or null before the question.
    const store = (() => { try { return window.localStorage; } catch (_) { return null; } })();
    let mode = DisplayMode.readMode(store);
    // Whether the follow-up was asked this session. Memory only, like monitoringSeen.
    let recheckAsked = false;
    function setMode(next) {
      mode = next;
      DisplayMode.writeMode(store, next);
    }
    // Made once per install for the game's own use, and written for everyone alike.
    const citySeed = DisplayMode.ensureSeed(store);

    // One question on its own screen (FirstQuestion): the answer picks the
    // display preference, then `then` carries on where the person was going.
    function ask(kind, then) {
      const card = document.getElementById('question-card');
      card.innerHTML = FirstQuestion.questionHtml(kind, escapeHtml);
      card.querySelectorAll('[data-answer]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const next = FirstQuestion.modeFor(kind, btn.dataset.answer);
          if (next) setMode(next);
          then();
        });
      });
      showScreen('question');
    }
```

In `window.RescueHost`, after `wantsSafety(finding) { … },`, add:

```js
      // The display preference and the install's seed, for the game.
      mode() { return mode; },
      citySeed() { return citySeed; },
```

Also in `window.RescueHost`, replace `docChanged(doc) { … }` with:

```js
      docChanged(doc) {
        lastScanDoc = doc;
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        renderPlayButton();
        renderResults(doc);
        renderLearnMore(doc);
        renderCitySwitch(doc);
        if (FirstQuestion.recheckDue({ mode, monitoringSeen, asked: recheckAsked })) {
          recheckAsked = true;
          ask('recheck', () => showCity(doc));
          return false;
        }
        if (!gameStillOffered(situation, doc, monitoringSeen)) { showScreen('results'); return false; }
        return true;
      },
```

In `renderSituations`, replace the click handler body:

```js
        btn.addEventListener('click', () => {
          situation = SITUATIONS.find((s) => s.id === btn.dataset.situation) || null;
          const next = FirstQuestion.afterWorry(situation, mode);
          if (next === 'ask') { ask('first', startWorry); return; }
          if (next !== mode) setMode(next);
          startWorry();
        });
```

and add this function right after `renderSituations`:

```js
    // What a picked worry does once the display preference is known.
    function startWorry() {
      if (!scanRunning && worryStartsGameScan({ situation, lastScanDoc, monitoringSeen, wantsCity,
        ready: !!(window.RescueGame && window.RescueGame.isReady) })) {
        leftGame = false;
        window.RescueGame.newWorry(situation);
        // The city screen first: if the sweep can't be drawn, leaveGame() then
        // shows the plain scan screen, where the same scan carries on.
        showScreen('city');
        runCheckup({ game: true });
        return;
      }
      goToScan();
    }
```

In `runCheckup`, wrap the landing (everything from `const view = postScanView({` through the `else { showScreen('results'); }` that ends it) in `land`, and ask first when due:

```js
        const land = () => {
          const view = postScanView({
            inGame, left: leftGame, wantsCity, rememberedCity: rememberedView() === 'city',
            offered: gameStillOffered(situation, doc, monitoringSeen), ready: !!(window.RescueGame && window.RescueGame.isReady),
          });
          if (view === 'boss-city') {
            if (window.RescueGame.scanDone(doc, situation) === false) {
              showScreen('results'); // the city couldn't be drawn: the list, which has the same results
            } else {
              rememberView('city');
              showScreen('city');
            }
          } else if (view === 'city') {
            showCity(doc);
          } else {
            showScreen('results');
          }
        };
        if (FirstQuestion.recheckDue({ mode, monitoringSeen, asked: recheckAsked })) {
          recheckAsked = true;
          ask('recheck', land);
        } else {
          land();
        }
```

After the `btn-play-game` click listener, add:

```js
    // "Something changed?": the question again, then back to the worry screen.
    document.getElementById('btn-something-changed').addEventListener('click', () => {
      ask('first', () => showScreen('worry'));
    });
```

- [ ] **Step 9: Style the screen**

Append to `desktop/renderer/styles.css`:

```css
/* The one question after the worry screen, and the follow-up after a scan */
.question-answers { list-style: none; padding: 0; margin: 1.25rem 0; display: grid; gap: 0.75rem; }
.question-answer { width: 100%; text-align: left; }
.worry-change { margin-top: 1rem; text-align: right; }
.link-button { background: none; border: 0; padding: 0; color: inherit; font: inherit; text-decoration: underline; cursor: pointer; opacity: 0.75; }
.link-button:hover, .link-button:focus-visible { opacity: 1; }
```

- [ ] **Step 10: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/first-question.test.js test/first-question-flow.test.js test/game-worry-scan.test.js && npm test`
Expected: PASS. `stylesheets.test.js` still finds every block closed.

- [ ] **Step 11: Commit**

```bash
git add desktop/renderer/first-question.js desktop/renderer/index.html desktop/renderer/app.js desktop/renderer/styles.css desktop/test/page-harness.js desktop/test/first-question.test.js desktop/test/first-question-flow.test.js desktop/test/game-worry-scan.test.js
git commit -m "The one question after the worry screen, its follow-up, and Something changed?"
```

---

### Task 6: Standard mode, with quiet notes

**Files:**
- Create: `desktop/renderer/quiet-notes.js`
- Modify: `desktop/renderer/index.html` (remove `#scan-safety` and `#results-next-safety`; add the script)
- Modify: `desktop/renderer/app.js`: remove `wantsSafetyNote`, `withoutSafetyParagraphs`, `safetyNoteHtml` and their exports; rewrite `renderSeverityGroup`; trim `renderScanIntro` and `renderNextStep`; `RescueHost.wantsSafety`
- Modify: `desktop/renderer/game/controller.js` (`rebuild`)
- Delete: `desktop/test/safety-note.test.js`
- Test: `desktop/test/quiet-notes.test.js`

**Interfaces:**
- Consumes: `mode` in app.js's closure (Task 5); `page`, `monitoring` (Task 5).
- Produces: global `QuietNotes` (also `window.QuietNotes`, and `module.exports`):
  - `MONITORING_MODULES: Set`, `MARKERS: RegExp`, `LINE: string`
  - `isMonitoring(finding)`, `quiet(text) -> string`, `quietFinding(finding)`, `quietDoc(doc)`
  - `noteFor(mode, finding) -> 'line' | 'none'` (Task 7 adds `'held'`)
  - `cardText(mode, finding) -> { note, description, steps, full }`, `lineHtml(card, esc) -> html`
  - In the game: `rebuild` builds the city from `win.QuietNotes.quietDoc(doc)`, so missions, notes and the deck's clues never carry hotline text.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/quiet-notes.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Q = require('../renderer/quiet-notes.js');
const { page, monitoring } = require('./page-harness.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const DV = /799-7233|88788|advocate|domestic\s+violence/i;
const REPO = path.join(__dirname, '..', '..');

test('standard mode: one line on monitoring software, nothing on anything else', () => {
  for (const mode of ['standard', null]) {
    for (const module of ['stalkerware_scan', 'keylogger_indicators', 'mvt_spyware_scan']) assert.strictEqual(Q.noteFor(mode, { module }), 'line', module);
    assert.strictEqual(Q.noteFor(mode, { module: 'remote_login_check' }), 'none');
  }
});

test('a hotline paragraph comes out of a description; the rest stays', () => {
  const text = 'Screen Sharing is on.\n\nIf you think someone close to you set this up, call 1-800-799-7233.\n\nWhat to do: turn it off.';
  assert.strictEqual(Q.quiet(text), 'Screen Sharing is on.\n\nWhat to do: turn it off.');
  assert.strictEqual(Q.quiet(''), '');
  assert.strictEqual(Q.quiet(null), '');
});

test('in a list, only the item that carries it comes out', () => {
  const body = '- If this is a work computer, call security.\n- If another person may be involved, talk to a domestic violence advocate before\n  you remove anything: 1-800-799-7233.\n- For everyone else, go ahead.';
  assert.strictEqual(Q.quiet(body), '- If this is a work computer, call security.\n- For everyone else, go ahead.');
});

test('a card for anything else has no such text, in its description or its steps', () => {
  const finding = { module: 'remote_login_check', description: 'Remote Login is on.\n\nTalk to an advocate first (1-800-799-7233).',
    remediation: { safety_note: 'Talk to an advocate.', steps: [{ number: 1, title: 'Turn it off', body: 'Open System Settings.\n\nCall 1-800-799-7233 first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'none');
  assert.doesNotMatch(card.description + card.steps.map((s) => s.body).join(' '), DV);
  assert.match(card.description, /Remote Login is on/);
  assert.match(card.steps[0].body, /Open System Settings/);
  assert.strictEqual(Q.lineHtml(card, esc), '');
});

test('monitoring software: one line with the full note behind it, and its own steps kept', () => {
  const finding = { module: 'stalkerware_scan', description: 'An app that records what you type.\n\nIf a partner set this up, call 1-800-799-7233.',
    remediation: { safety_note: 'Before you remove or turn anything off: talk to an advocate first.', steps: [{ number: 1, title: 'Decide', body: 'Talk to a domestic violence advocate first.' }] } };
  const card = Q.cardText('standard', finding);
  assert.strictEqual(card.note, 'line');
  assert.doesNotMatch(card.description, DV);
  assert.deepStrictEqual(card.steps, finding.remediation.steps);
  const html = Q.lineHtml(card, esc);
  assert.match(html, /^<details class="finding-card__note"><summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  assert.match(html, /talk to an advocate first/);
  assert.match(html, /799-7233/);
  // With nothing of its own to say, the note still says it.
  assert.match(Q.lineHtml(Q.cardText('standard', { module: 'keylogger_indicators', description: 'x' }), esc), /799-7233/);
});

test('quietDoc quiets every finding but monitoring software, and leaves the scan alone', () => {
  const doc = { modules: [
    { name: 'remote_login_check', findings: [{ description: 'On.\n\nCall 1-800-799-7233.', remediation: { safety_note: 'n', steps: [{ title: 't', body: 'Call 88788.' }] } }] },
    { name: 'stalkerware_scan', findings: [{ description: 'Found.\n\nCall 1-800-799-7233.' }] },
  ] };
  const out = Q.quietDoc(doc);
  assert.strictEqual(out.modules[0].findings[0].description, 'On.');
  assert.strictEqual(out.modules[0].findings[0].remediation.steps[0].body, '');
  assert.ok(!('safety_note' in out.modules[0].findings[0].remediation));
  assert.strictEqual(out.modules[1], doc.modules[1], 'monitoring software is the game’s to hold (Task 7)');
  assert.match(doc.modules[0].findings[0].description, /799-7233/, 'the scan itself is untouched');
  assert.strictEqual(Q.quietDoc(null), null);
});

test('every remediation guide reads cleanly in standard mode, and keeps its other lines', () => {
  const dir = path.join(REPO, 'guides', 'remediation');
  for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.md'))) {
    if (file === 'respond_to_monitoring_software.md') continue; // monitoring software keeps its steps
    const body = fs.readFileSync(path.join(dir, file), 'utf8').replace(/^---[\s\S]*?---\n/, '');
    const quiet = Q.quiet(body);
    assert.doesNotMatch(quiet, DV, file);
    const kept = body.split('\n').filter((l) => l.trim() && !DV.test(l)).length;
    if (kept) assert.ok(quiet.trim().length > 0, `${file}: nothing left`);
  }
});

test('the scan screen and the results never carry the banner or the reminder any more', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  assert.doesNotMatch(html, /scan-safety|results-next-safety|799-7233/);
});

test('the list in standard mode: no hotline text except the one line on monitoring software', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [
    { name: 'remote_login_check', category: 'security', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 'Remote Login is on',
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.', category: 'security', data: {} }] },
    ...monitoring.modules,
  ] });
  p.answer('known'); // the follow-up (Task 5)
  const html = p.byId('results-groups').innerHTML;
  assert.strictEqual(html.split('Removing this can alert whoever installed it. Read this first.').length, 2, 'the one line, once');
  assert.doesNotMatch(html.replace(/<details class="finding-card__note">[\s\S]*?<\/details>/g, ''), DV);
});

test('the game’s mission screens read the same quiet text', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const ctl = createController({ win, storage: null, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  const doc = { schema_version: 1, platform: 'darwin', modules: [{ name: 'remote_login_check', category: 'security', status: 'ok', supported: true,
    findings: [{ title: 'Remote Login is on', severity: 'warning', category: 'security', data: {},
      description: 'Remote Login is on.\n\nIf someone close to you set this up, call 1-800-799-7233.' }] }] };
  ctl.show(doc, { id: 'unsure' });
  const id = findingsToCity(doc).districts[0].missions[0].id;
  const el = { getAttribute: (k) => (k === 'data-go' ? `mission:${id}` : null) };
  clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  assert.match(frame.innerHTML, /Remote Login is on/);
  assert.doesNotMatch(frame.innerHTML, /799-7233/);
});
```

(`loadDrillBank` is ignored until the command-center plan adds it. Passing it now keeps this test stable after that plan merges.)

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/quiet-notes.test.js`
Expected: FAIL with `Cannot find module '../renderer/quiet-notes.js'`.

- [ ] **Step 3: Write the module**

Create `desktop/renderer/quiet-notes.js`:

```js
'use strict';

/*
 * How much the list and the game say to someone who may be watched by a
 * person close to them. Standard mode: none of it, except on a finding that
 * is itself monitoring software, which carries one line with the full note
 * behind it. Everything here works on copies; the scan is never changed.
 *
 * Loaded as a plain script (global `QuietNotes`, also on window for the game).
 */
const QuietNotes = (function () {
  // The same three checks app.js's ALWAYS_SAFETY_MODULES names; a test keeps them equal.
  const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  // A paragraph or list item that speaks to someone close to the person.
  const MARKERS = /799-7233|88788|\badvocates?\b|domestic\s+violence|someone\s+close\s+to\s+you|\b(ex-)?partner\b|\babuser\b/i;
  const LINE = 'Removing this can alert whoever installed it. Read this first.';
  const DEFAULT_FULL = 'If someone close to you may have installed it, talk to an advocate before you remove anything. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.';

  function isMonitoring(finding) {
    return !!finding && MONITORING_MODULES.has(finding.module);
  }

  const isItem = (line) => /^\s*([-*]|\d+\.)\s+/.test(line);

  function quietParagraph(p) {
    const lines = p.split('\n');
    if (!lines.some(isItem)) return MARKERS.test(p) ? '' : p;
    // A list: only the items (with their wrapped lines) that carry it come out.
    const items = [];
    for (const line of lines) {
      if (isItem(line) || !items.length) items.push([line]);
      else items[items.length - 1].push(line);
    }
    return items.filter((it) => !MARKERS.test(it.join(' '))).map((it) => it.join('\n')).join('\n');
  }

  function paragraphs(text) {
    return String(text == null ? '' : text).split(/\n\s*\n/);
  }

  function quiet(text) {
    return paragraphs(text).map(quietParagraph).filter((p) => p.trim() !== '').join('\n\n');
  }

  function loud(text) {
    return paragraphs(text).map((p) => p.trim()).filter((p) => p && MARKERS.test(p));
  }

  function quietFinding(f) {
    if (!f || typeof f !== 'object') return f;
    const out = { ...f };
    if (f.description != null) out.description = quiet(f.description);
    const rem = f.remediation && typeof f.remediation === 'object' ? f.remediation : null;
    if (rem) {
      out.remediation = { ...rem };
      delete out.remediation.safety_note;
      if (Array.isArray(rem.steps)) out.remediation.steps = rem.steps.map((s) => (s && typeof s === 'object' ? { ...s, body: quiet(s.body) } : s));
    }
    return out;
  }

  function quietDoc(doc) {
    if (!doc || !Array.isArray(doc.modules)) return doc;
    return { ...doc, modules: doc.modules.map((m) => {
      if (!m || !Array.isArray(m.findings) || MONITORING_MODULES.has(m.name)) return m;
      return { ...m, findings: m.findings.map(quietFinding) };
    }) };
  }

  // 'line': the one line, with the full note behind it. 'none': nothing.
  function noteFor(mode, finding) {
    return isMonitoring(finding) ? 'line' : 'none';
  }

  function fullNote(f) {
    const out = [];
    const sn = f.remediation && f.remediation.safety_note;
    if (sn) out.push(String(sn));
    for (const p of loud(f.description)) if (!out.includes(p)) out.push(p);
    return out.length ? out : [DEFAULT_FULL];
  }

  // What one card may say. Monitoring software keeps its own steps: they are
  // the careful way to deal with it, read after the line.
  function cardText(mode, finding) {
    const f = finding || {};
    const note = noteFor(mode, f);
    const steps = f.remediation && Array.isArray(f.remediation.steps) ? f.remediation.steps : [];
    if (note === 'line') return { note, description: quiet(f.description), steps, full: fullNote(f) };
    const q = quietFinding(f);
    return { note, description: q.description == null ? '' : q.description,
      steps: q.remediation && Array.isArray(q.remediation.steps) ? q.remediation.steps : [], full: [] };
  }

  function lineHtml(card, esc) {
    if (!card || card.note !== 'line') return '';
    return `<details class="finding-card__note"><summary>${esc(LINE)}</summary>${card.full.map((p) => `<p>${esc(p)}</p>`).join('')}</details>`;
  }

  return { MONITORING_MODULES, MARKERS, LINE, isMonitoring, quiet, quietFinding, quietDoc, noteFor, cardText, lineHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = QuietNotes;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.QuietNotes = QuietNotes;
}
```

- [ ] **Step 4: Remove the banner and the reminder; load the script**

In `desktop/renderer/index.html`:
- Delete the whole `<div id="scan-safety" class="safety-note safety-note--alert" role="note" hidden>…</div>` block (the "Before you remove anything" banner).
- Delete the `<p id="results-next-safety" class="muted" hidden>…</p>` paragraph.
- Before `<script src="app.js"></script>`, add `<script src="quiet-notes.js"></script>`.

- [ ] **Step 5: Use it in `app.js`**

Delete the functions `wantsSafetyNote`, `withoutSafetyParagraphs` and `safetyNoteHtml`, with their doc comments, and their three entries in `module.exports`. Keep `ALWAYS_SAFETY_MODULES`.

In `renderScanIntro`, delete the line `document.getElementById('scan-safety').hidden = !(situation && situation.safety);`.
In `renderNextStep`, delete the line `document.getElementById('results-next-safety').hidden = !situation.safety;`.

In `window.RescueHost`, replace `wantsSafety(finding) { return wantsSafetyNote(situation, finding); },` with:

```js
      // The game's briefing shows a mission's safety note only where the list shows the line.
      wantsSafety(finding) { return QuietNotes.noteFor(mode, finding) === 'line'; },
```

Replace `renderSeverityGroup` with:

```js
    function renderSeverityGroup(severity, findings) {
      if (findings.length === 0) return '';
      // City mode: the fix panel's extra warning about whoever set something up.
      const watched = mode === 'city';
      const items = findings
        .map((finding) => {
          const key = String(nextCardKey++);
          const pick = copyAiPick(finding);
          cardPicks.set(key, pick);
          cardTech.set(key, {
            check: finding.module,
            code: finding.code || null,
            category: finding.category,
            confidence: finding.confidence == null ? null : finding.confidence,
            evidence: finding.data || {},
          });
          const marked = !!(finding.data && finding.data.marked_by_user === true);
          // On the list: everything worth acting on, plus what was marked as yours.
          const counts = severity === 'critical' || severity === 'warning' || marked;
          // What this card may say (QuietNotes): no hotline text, except the one line on monitoring software.
          const card = QuietNotes.cardText(mode, finding);
          return `
            <li class="finding-card finding-card--${severity}" data-card-key="${key}" data-card-counts="${counts ? '1' : '0'}"${marked ? ' data-marked-before' : ''}>
              <div class="finding-card__header">
                <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
                <h3>${escapeHtml(finding.title || 'Untitled finding')}</h3>
              </div>
              <div class="cleared-note" data-cleared-note role="status" aria-live="polite" hidden></div>
              ${descriptionHtml(card.description, escapeHtml)}
              ${madeByHtml(finding.made_by, escapeHtml)}
              <div class="card-answers">
              ${FixFlow.fixControlsHtml(finding, { watched })}
              ${MarkFlow.markControlsHtml(finding, { watched })}
              ${marked ? '' : ClearList.didControlsHtml(finding, severity, escapeHtml)}
              </div>
              ${QuietNotes.lineHtml(card, escapeHtml)}
              ${card.steps.length ? `
              <div class="next-steps">
                <h4>What to do</h4>
                <ol>${card.steps.map((step) => `<li>${escapeHtml(stepTitle(step.title))}</li>`).join('')}</ol>
              </div>` : ''}
              ${SettingPanes.findingButtonHtml(finding, currentPlatform())}
              ${finding.remediation ? `
              <details class="fix-steps">
                <summary>${finding.fixable ? 'Or fix it yourself, step by step' : 'Show me how, step by step'}</summary>
                <ol class="fix-steps__list">
                  ${card.steps.map((step) => `
                    <li>
                      <h4>${escapeHtml(step.title)}</h4>
                      <div class="fix-steps__body">${renderMiniMarkdown(step.body)}</div>
                    </li>`).join('')}
                </ol>
              </details>` : ''}
              ${askButtonHtml(finding)}
              ${copyAiButtonHtml(finding, pick)}
              <details class="tech-details">
                <summary>Technical details</summary>
                <pre class="tech-log" data-tech-log>${escapeHtml(techText(key, null))}</pre>
              </details>
            </li>
          `;
        })
        .join('');

      return `
        <section class="results-group results-group--${severity}" data-results-group="${severity}">
          <h2>
            <span class="chip chip--${severity}">${escapeHtml(SEVERITY_LABELS[severity])}</span>
            <span class="results-group__count">${findings.length}</span>
          </h2>
          <p class="muted">${escapeHtml(SEVERITY_DESCRIPTIONS[severity])}</p>
          <p class="muted results-group__empty" data-group-empty hidden>Nothing left here. Everything in this group is in “Cleared” below.</p>
          <ul class="findings-list" data-group-list>${items}</ul>
        </section>
      `;
    }
```

In `desktop/renderer/styles.css`, change the selector `.finding-card__safety {` to `.finding-card__safety, .finding-card__note {` so the line keeps the existing amber note style.

- [ ] **Step 6: Quiet the game's city**

In `desktop/renderer/game/controller.js`, inside `createController`, directly above `function rebuild(`, add:

```js
  // The same quiet text as the list (QuietNotes): no hotline paragraphs in missions, notes or clues.
  const quietDoc = (d) => (win.QuietNotes ? win.QuietNotes.quietDoc(d) : d);
```

In `rebuild`, change `s.city = findingsToCity(doc);` to `s.city = findingsToCity(quietDoc(doc));`.

- [ ] **Step 7: Retire the old test and run everything**

Run:
```bash
git rm desktop/test/safety-note.test.js
cd desktop && node --test test/quiet-notes.test.js && npm test
```
Expected: PASS. Every other test passes unchanged: `game-views.test.js` still renders briefings with `wantsSafety` true and false.

- [ ] **Step 8: Commit**

```bash
git add desktop/renderer/quiet-notes.js desktop/renderer/index.html desktop/renderer/app.js desktop/renderer/styles.css desktop/renderer/game/controller.js desktop/test/quiet-notes.test.js
git commit -m "Standard mode: no hotline text, except one line on monitoring software"
```

---

### Task 7: City mode, with the gate rewritten

**Files:**
- Create: `desktop/renderer/game/held.js`
- Modify: `desktop/renderer/quiet-notes.js` (`'held'`, `HELD_LINE`, `HELD_MORE`, `heldHtml`)
- Modify: `desktop/renderer/app.js`:
  - pure helpers: `gameOfferedFor`, `opensInGame`, `worryStartsGameScan`, `postScanView` and `CITY_SITUATION`; `gameStillOffered` and `playButtonShown` removed; exports
  - wiring: `cityAvailable`, `docChanged`, `setMode`, `startWorry`, `runCheckup`, `renderScanIntro`, `renderSeverityGroup`, `openCityHome` and start-up; `renderPlayButton` removed
- Modify: `desktop/renderer/game/controller.js` (`rebuild`, `s.held`)
- Rewrite: `desktop/test/game-flow-gate.test.js`, `desktop/test/game-gate.test.js`
- Modify: `desktop/test/game-worry-scan.test.js` (two tests)
- Test: `desktop/test/stealth-mode.test.js`

**Interfaces:**
- Consumes:
  - From Task 5: `mode`, `setMode`, `ask`, `recheckAsked`, `startWorry`, `RescueHost.mode()`.
  - From Task 6: `QuietNotes.cardText`, `lineHtml`, `quietDoc`.
  - Test helpers: `page`, `monitoring`, `recordingStore`, `forbiddenWrites`.
- Produces:
  - `app.js` exports: `CITY_SITUATION`, `opensInGame(mode)`, `gameOfferedFor(situation)`, `worryStartsGameScan({ situation, wantsCity, mode, ready })`, `postScanView({ inGame, left, wantsCity, rememberedCity, offered, ready, mode })`, `ALWAYS_SAFETY_MODULES`. `gameStillOffered` and `playButtonShown` are gone.
  - `QuietNotes.noteFor(mode, finding) -> 'line' | 'held' | 'none'`, `QuietNotes.HELD_LINE = 'Don’t remove it yet. Talk to an advocate first.'`, `QuietNotes.heldHtml(card, esc)`.
  - `game/held.js`: `HELD_MODULES: Set`, `splitHeld(doc) -> { doc, held: [{ module, title }] }`.
  - Controller state `s.held` (memory only), for Task 8.

- [ ] **Step 1: Rewrite the gate tests**

Replace all of `desktop/test/game-flow-gate.test.js` with:

```js
// The gate, rewritten on purpose. Monitoring software no longer takes anyone
// out of the game. In 'city' the game is the cover: it never prompts removal,
// never offers a fix or a mark for monitoring software, and never makes a
// mission of it. In 'standard' the person is asked first (first-question.js).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { gameScanFirst, postScanView, gameOfferedFor, worryStartsGameScan, noteMonitoring, opensInGame,
  CITY_SITUATION, ALWAYS_SAFETY_MODULES, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

test('the game is offered for every worry but the iPhone check, monitoring software or not', () => {
  for (const s of SITUATIONS) assert.strictEqual(gameOfferedFor(s), s.id !== 'phone', s.id);
  assert.strictEqual(gameOfferedFor(CITY_SITUATION), true);
  assert.strictEqual(gameOfferedFor(null), false);
});

test('city always plays: a worry starts its scan in the game, even from Get started', () => {
  for (const s of SITUATIONS) {
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: false, mode: 'city', ready: true }), s.id !== 'phone', s.id);
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: false, mode: 'standard', ready: true }), false, s.id);
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: true, mode: 'standard', ready: true }), s.id !== 'phone', s.id);
  }
  assert.strictEqual(worryStartsGameScan({ situation: byId('unsure'), wantsCity: true, mode: 'city', ready: false }), false);
  assert.strictEqual(gameScanFirst({ wantsCity: true, offered: true, ready: true }), true);
  assert.strictEqual(opensInGame('city'), true);
  assert.strictEqual(opensInGame('standard'), false);
  assert.strictEqual(opensInGame(null), false);
});

test('after a game scan: the city, whatever it found; Plain view stays plain', () => {
  const base = { inGame: true, left: false, wantsCity: true, rememberedCity: false, offered: gameOfferedFor(byId('unsure')), ready: true };
  assert.strictEqual(postScanView({ ...base, mode: 'standard' }), 'boss-city');
  assert.strictEqual(postScanView({ ...base, mode: 'city' }), 'boss-city');
  assert.strictEqual(postScanView({ ...base, left: true, mode: 'city' }), 'results');
  assert.strictEqual(postScanView({ ...base, ready: false, mode: 'city' }), 'results');
});

test('outside the game: the city when chosen, remembered, or in city mode', () => {
  const base = { inGame: false, left: false, wantsCity: false, rememberedCity: false, offered: true, ready: true, mode: 'standard' };
  assert.strictEqual(postScanView(base), 'results');
  assert.strictEqual(postScanView({ ...base, wantsCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, mode: 'city' }), 'city');
  assert.strictEqual(postScanView({ ...base, mode: 'city', offered: false }), 'results', 'the iPhone check');
});

test('monitoring software seen once is remembered for the session; it decides the follow-up', () => {
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'warning' }] }] };
  const narrowClean = { modules: [{ name: 'disk_space', findings: [] }] };
  let seen = false;
  seen = noteMonitoring(seen, monitoring);
  seen = noteMonitoring(seen, narrowClean);
  seen = noteMonitoring(seen, null);
  assert.strictEqual(seen, true);
  assert.strictEqual(noteMonitoring(false, narrowClean), false);
  assert.strictEqual(noteMonitoring(false, { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'info' }] }] }), false);
});

test('city mode never prompts removal: monitoring software gets the hold line, no steps, no fix, no mark', () => {
  for (const module of ALWAYS_SAFETY_MODULES) {
    const f = { module, description: 'An app that records what you type.', remediation: { steps: [{ number: 1, title: 'Remove it', body: 'Uninstall it.' }] } };
    const card = Q.cardText('city', f);
    assert.strictEqual(card.note, 'held');
    assert.deepStrictEqual(card.steps, []);
    const html = Q.heldHtml(card, String);
    assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
    assert.doesNotMatch(html, /uninstall|delete|fix it|turn it off/i);
    assert.strictEqual(Q.lineHtml(card, String), '');
  }
  assert.strictEqual(Q.noteFor('city', { module: 'remote_login_check' }), 'none');
  assert.strictEqual(Q.heldHtml(Q.cardText('standard', { module: 'stalkerware_scan' }), String), '');
});

test('one list of monitoring checks, everywhere', async () => {
  const { HELD_MODULES } = await game('held.js');
  assert.deepStrictEqual([...HELD_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
  assert.deepStrictEqual([...Q.MONITORING_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
});

test('the game never makes a mission of monitoring software, so nothing about it is saved', async () => {
  const { splitHeld } = await game('held.js');
  const { findingsToCity } = await game('findings-to-city.js');
  const { reconcile, saveProgress, emptyProgress, ranOkModules } = await game('progress.js');
  const doc = { modules: [
    { name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true, findings: [
      { severity: 'critical', title: 'Stalkerware found: mSpy', description: 'd' }, { severity: 'info', title: 'Checked for monitoring apps' }] },
    { name: 'remote_login_check', category: 'security', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 'Remote Login is on', description: 'd' }] },
  ] };
  const split = splitHeld(doc);
  assert.deepStrictEqual(split.held, [{ module: 'stalkerware_scan', title: 'Stalkerware found: mSpy' }]);
  assert.strictEqual(doc.modules[0].findings.length, 2, 'the scan itself is untouched');
  const city = findingsToCity(split.doc);
  assert.deepStrictEqual(city.districts.flatMap((d) => d.missions).map((m) => m.module), ['remote_login_check']);
  assert.ok(city.districts.find((d) => d.id === 'gatehouse').checksRan >= 2, 'the check still counts as having run');
  const store = recordingStore();
  saveProgress(store, reconcile(emptyProgress(), city, ranOkModules(doc), '2026-10-18T00:00:00Z').progress);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.doesNotMatch(JSON.stringify(store.data), /mSpy|stalkerware/i);
  assert.deepStrictEqual(splitHeld(null), { doc: null, held: [] });
});
```

Replace all of `desktop/test/game-gate.test.js` with:

```js
const test = require('node:test');
const assert = require('node:assert');
const { mayBeWatched, gameOfferedFor, learnMoreFor, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const withFinding = (module, severity) => ({ modules: [{ name: module, findings: [{ severity }] }] });

test('open for every worry but the iPhone check, which keeps its own plain screen', () => {
  for (const id of ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping', 'unsure']) {
    assert.strictEqual(gameOfferedFor(byId(id)), true, id);
  }
  assert.strictEqual(gameOfferedFor(byId('phone')), false);
});

test('monitoring software found no longer closes it: the follow-up question decides', () => {
  for (const mod of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    for (const sev of ['critical', 'warning']) {
      assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding(mod, sev)), true, `${mod} ${sev}`);
    }
  }
});

test('closed with no worry picked', () => {
  assert.strictEqual(gameOfferedFor(null), false);
});

test('learnMoreFor still hides the web game link exactly when mayBeWatched says so', () => {
  for (const s of SITUATIONS) {
    if (mayBeWatched(s, { modules: [] })) assert.strictEqual(learnMoreFor(s, { modules: [] }), null, s.id);
  }
  assert.strictEqual(learnMoreFor(byId('hacked'), withFinding('stalkerware_scan', 'warning')), null);
});
```

In `desktop/test/game-worry-scan.test.js`, replace the test `worries where someone may be watching never start the game, even from "Play it as a game"` with:

```js
test('the iPhone check stays on its own plain screen, even from "Play it as a game"', () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('phone');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.calls.scans, [], 'the plain scan screen, waiting for Run');
  assert.deepStrictEqual(p.shown(), ['scan']);
});
```

and replace the test `once a scan found monitoring software, the follow-up comes first; then the next worry gets the plain screen` (from Task 5) with:

```js
test('monitoring software in standard mode: the follow-up first, and "Yes, I know about it" keeps the game', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.ok(!p.calls.game.includes('scanDone'), 'nothing lands before the answer');
  p.answer('known');
  assert.ok(p.calls.game.includes('scanDone'));
  assert.deepStrictEqual(p.shown(), ['city']);
  p.calls.game.length = 0;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss'], 'the next worry plays too');
});
```

- [ ] **Step 2: Write the failing flow tests**

Create `desktop/test/stealth-mode.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, monitoring } = require('./page-harness.js');
const { forbiddenWrites } = require('./disk-words.js');

const KEY = 'device-rescue.display';

test('city mode opens straight into the game, under a plain title', () => {
  const p = page({ store: { [KEY]: 'city' } });
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.deepStrictEqual(p.calls.game, ['showTraining']);
  const [situation] = p.calls.last.args;
  assert.strictEqual(situation.id, 'city');
  assert.doesNotMatch(situation.title, /watch|partner|safe/i);
  assert.deepStrictEqual(p.calls.scans, [], 'no scan until the person starts one');
});

test('city mode waits for the game to load, then opens it', () => {
  const p = page({ store: { [KEY]: 'city' }, ready: false });
  assert.deepStrictEqual(p.shown(), ['welcome']);
  p.sandbox.RescueGame.isReady = true;
  p.fire('rescue-game-ready');
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('standard mode and a first launch open on the welcome screen', () => {
  for (const store of [{ [KEY]: 'standard' }, {}]) {
    const p = page({ store });
    assert.deepStrictEqual(p.shown(), ['welcome']);
    assert.deepStrictEqual(p.calls.game, []);
  }
});

test('"I think someone is watching me" goes straight into the game, without the question', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.deepStrictEqual(p.storage.writes.filter(([k]) => k === KEY), [[KEY, 'city']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the scan screen in city mode names no worry', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-situation').textContent, 'Checking your computer');
});

test('a city-mode person who picks a different worry later stays in the game, with no question', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.leaveGame(); // PLAIN VIEW
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(p.calls.game.slice(-2), ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['home_network_intrusion']);
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['city'], 'monitoring software doesn’t take them out of the game');
  assert.strictEqual(p.storage.getItem(KEY), 'city');
  const list = p.byId('results-groups').innerHTML;
  assert.match(list, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.doesNotMatch(list, /\[FIX IT\]|\[IT IS MINE\]/);
});

test('rather not say, then monitoring software: asked once, and "No, I don’t" switches to city', async () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('unsure');
  p.answer('rather-not');
  assert.strictEqual(p.storage.getItem(KEY), 'standard');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.match(p.byId('question-card').innerHTML, /We found something that can be used to watch a computer/);
  assert.ok(!p.calls.game.includes('scanDone'), 'nothing lands until they answer');
  p.answer('unknown');
  assert.strictEqual(p.storage.getItem(KEY), 'city');
  assert.ok(p.calls.game.includes('scanDone'));
  assert.deepStrictEqual(p.shown(), ['city']);
  const list = p.byId('results-groups').innerHTML;
  assert.match(list, /Don’t remove it yet\. Talk to an advocate first\./, 'the list was redrawn for city mode');
  assert.doesNotMatch(list, /\[FIX IT\]|\[IT IS MINE\]/, 'no fix and no “It’s mine” for monitoring software');
  assert.doesNotMatch(list, /Removing this can alert/);
});

test('rather not say, then "Yes, I know about it": still standard, the game stays, and the card has the one line', async () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('unsure');
  p.answer('rather-not');
  await p.finish(monitoring);
  p.answer('known');
  assert.strictEqual(p.storage.getItem(KEY), 'standard');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.match(p.byId('results-groups').innerHTML, /Removing this can alert whoever installed it\. Read this first\./);
});

test('nothing the app writes says why, on any route', async () => {
  const runs = [];
  { const p = page({ store: {} }); p.byId('btn-get-started').click(); p.pick('watched'); await p.finish(monitoring); runs.push(p); }
  { const p = page({ store: {} }); p.byId('btn-play-game').click(); p.pick('unsure'); p.answer('yes'); await p.finish(monitoring); runs.push(p); }
  { const p = page({ store: {} }); p.byId('btn-play-game').click(); p.pick('hacked'); p.answer('rather-not'); await p.finish(monitoring); p.answer('unknown'); runs.push(p); }
  { const p = page({ store: { [KEY]: 'city' } }); p.byId('btn-something-changed').click(); p.answer('no'); runs.push(p); }
  for (const p of runs) {
    assert.deepStrictEqual(forbiddenWrites(p.storage), []);
    for (const [k, v] of p.storage.writes) {
      assert.ok(['device-rescue.display', 'device-rescue.city-seed', 'device-rescue.view'].includes(k), k);
      if (k === KEY) assert.ok(['city', 'standard'].includes(v), v);
    }
  }
});

test('the app never shows a notification or calls attention to itself', () => {
  const root = path.join(__dirname, '..');
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  const sources = [path.join(root, 'main.js'), path.join(root, 'preload.js'), ...walk(path.join(root, 'renderer')).filter((f) => f.endsWith('.js'))];
  for (const f of sources) {
    assert.doesNotMatch(fs.readFileSync(f, 'utf8'), /\bNotification\b|showNotification|setBadge|dock\.bounce|requestAttention|flashFrame/, f);
  }
});
```

- [ ] **Step 3: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-flow-gate.test.js test/game-gate.test.js test/stealth-mode.test.js test/game-worry-scan.test.js`
Expected: FAIL.
- `game-flow-gate`: `opensInGame is not a function`, and `Cannot find module …/held.js`.
- `game-gate`: `watched` and the monitoring cases are still closed.
- `stealth-mode`: city mode opens on `welcome`, and the watched worry lands on `scan`.

- [ ] **Step 4: The held findings**

Create `desktop/renderer/game/held.js`:

```js
// Findings from the checks that look for monitoring software. The game never
// turns them into missions or signals, so nothing about them is scored or
// stored: in 'city' they wait in the generated district (memory only), and
// in 'standard' the list shows them with the one line. The same three checks
// as app.js's ALWAYS_SAFETY_MODULES; a test keeps them equal.
export const HELD_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

// `doc` without those findings (their checks still count as having run), and
// the warnings and criticals they held. The scan itself is never changed.
export function splitHeld(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return { doc, held: [] };
  const held = [];
  const modules = doc.modules.map((m) => {
    if (!m || !HELD_MODULES.has(m.name)) return m;
    for (const f of Array.isArray(m.findings) ? m.findings : []) {
      if (f && (f.severity === 'critical' || f.severity === 'warning')) held.push({ module: m.name, title: String(f.title || '') });
    }
    return { ...m, findings: [] };
  });
  return { doc: { ...doc, modules }, held };
}
```

In `desktop/renderer/game/controller.js`:
- Add `import { splitHeld } from './held.js';` after the `findingsToCity` import.
- In the initial state object `s = { …`, after `doc: null,` add `held: [],`.
- In `rebuild`, replace `s.city = findingsToCity(quietDoc(doc));` with:

```js
    // Monitoring software never becomes a mission or a signal (held.js).
    const split = splitHeld(doc);
    s.held = split.held;
    s.city = findingsToCity(quietDoc(split.doc));
```

- [ ] **Step 5: The hold line**

In `desktop/renderer/quiet-notes.js`:

After `const LINE = …;`, add:

```js
  const HELD_LINE = 'Don’t remove it yet. Talk to an advocate first.';
  const HELD_MORE = 'Open the city to see how to keep a quiet record of it.';
```

Replace `noteFor` with:

```js
  // 'line': the one line, full note behind it (standard). 'held': the hold
  // line and nothing to act on (city). 'none': nothing.
  function noteFor(mode, finding) {
    if (!isMonitoring(finding)) return 'none';
    return mode === 'city' ? 'held' : 'line';
  }
```

In `cardText`, after `const note = noteFor(mode, f);`, add:

```js
    if (note === 'held') return { note, description: quiet(f.description), steps: [], full: [] };
```

After `lineHtml`, add:

```js
  function heldHtml(card, esc) {
    if (!card || card.note !== 'held') return '';
    return `<p class="finding-card__note" role="note"><strong>${esc(HELD_LINE)}</strong> ${esc(HELD_MORE)}</p>`;
  }
```

Change the return line to:

```js
  return { MONITORING_MODULES, MARKERS, LINE, HELD_LINE, HELD_MORE, isMonitoring, quiet, quietFinding, quietDoc, noteFor, cardText, lineHtml, heldHtml };
```

- [ ] **Step 6: The gate, rewritten in `app.js`'s pure helpers**

Replace the doc comment and body of `gameOfferedFor` with:

```js
/**
 * Whether to offer game mode: every worry but the iPhone check, which reads a
 * phone backup on its own plain screen. Monitoring software no longer closes
 * it. In 'city' the game is the cover and its help lives in one district; in
 * 'standard' the person is asked first (FirstQuestion's follow-up).
 */
function gameOfferedFor(situation) {
  return !!situation && situation.id !== 'phone';
}

/** 'city' always plays: the app opens into the game, and every worry's scan runs there. */
function opensInGame(mode) {
  return mode === 'city';
}

/**
 * The game's home when the app opens in 'city' with no worry picked: the same
 * checkup as "I think someone is watching me", under a plain title.
 */
const CITY_SITUATION = Object.freeze({
  id: 'city', icon: '', title: 'Take back the city', sub: '',
  profile: 'digital_security_reset', guide: 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/',
});
```

Delete `playButtonShown` and `gameStillOffered`, with their doc comments.

Replace `worryStartsGameScan` with:

```js
/** The worry click: its scan starts at once in the game, or the plain scan screen. */
function worryStartsGameScan({ situation, wantsCity, mode, ready }) {
  return gameScanFirst({ wantsCity: !!wantsCity || opensInGame(mode), offered: gameOfferedFor(situation), ready });
}
```

Replace `postScanView` with:

```js
/**
 * Where a finished scan lands. Monitoring software doesn't change it: the
 * follow-up question, when due, comes before this. "Plain view" stays plain.
 */
function postScanView({ inGame, left, wantsCity, rememberedCity, offered, ready, mode }) {
  if (!offered || !ready || left) return 'results';
  if (inGame) return 'boss-city';
  return wantsCity || rememberedCity || opensInGame(mode) ? 'city' : 'results';
}
```

In `module.exports`, remove `gameStillOffered,` and `playButtonShown,`, and add `opensInGame,`, `CITY_SITUATION,` and `ALWAYS_SAFETY_MODULES,`. If the command-center plan already added `ALWAYS_SAFETY_MODULES,`, keep one.

- [ ] **Step 7: The wiring in `app.js`**

`cityAvailable`:

```js
    function cityAvailable() {
      return gameOfferedFor(situation) && !!(window.RescueGame && window.RescueGame.isReady);
    }
```

`setMode` redraws the list when the mode changes, so a card loses or gains its controls at once:

```js
    function setMode(next) {
      const changed = next !== mode;
      mode = next;
      DisplayMode.writeMode(store, next);
      if (changed && lastScanDoc) renderResults(lastScanDoc);
    }
```

`RescueHost.docChanged`:

```js
      docChanged(doc) {
        lastScanDoc = doc;
        monitoringSeen = noteMonitoring(monitoringSeen, doc);
        renderResults(doc);
        renderLearnMore(doc);
        renderCitySwitch(doc);
        if (FirstQuestion.recheckDue({ mode, monitoringSeen, asked: recheckAsked })) {
          recheckAsked = true;
          ask('recheck', () => showCity(doc));
          return false;
        }
        return true;
      },
```

Delete the function `renderPlayButton` and its comment. Delete the three calls `renderPlayButton();`: in `runCheckup`, in `resetToWelcome`, and the one removed from `docChanged` above.

In `startWorry`, change the condition to:

```js
      if (!scanRunning && worryStartsGameScan({ situation, wantsCity, mode,
        ready: !!(window.RescueGame && window.RescueGame.isReady) })) {
```

In `runCheckup`'s `land`, change the `postScanView({ … })` argument to:

```js
          const view = postScanView({
            inGame, left: leftGame, wantsCity, rememberedCity: rememberedView() === 'city',
            offered: gameOfferedFor(situation), ready: !!(window.RescueGame && window.RescueGame.isReady), mode,
          });
```

In `renderScanIntro`, replace the `scan-situation` assignment with:

```js
      // City mode names no worry on screen.
      document.getElementById('scan-situation').textContent = !situation ? ''
        : opensInGame(mode) ? 'Checking your computer' : `Checking for: ${situation.title}`;
```

In `renderSeverityGroup`, after `const card = QuietNotes.cardText(mode, finding);`, add `const held = card.note === 'held';`, then make these edits:
- `const counts = severity === 'critical' || severity === 'warning' || marked;` → `const counts = !held && (severity === 'critical' || severity === 'warning' || marked);`. Move it below the `held` line.
- `${FixFlow.fixControlsHtml(finding, { watched })}` → `${held ? '' : FixFlow.fixControlsHtml(finding, { watched })}`
- `${MarkFlow.markControlsHtml(finding, { watched })}` → `${held ? '' : MarkFlow.markControlsHtml(finding, { watched })}`
- `${marked ? '' : ClearList.didControlsHtml(finding, severity, escapeHtml)}` → `${marked || held ? '' : ClearList.didControlsHtml(finding, severity, escapeHtml)}`
- `${QuietNotes.lineHtml(card, escapeHtml)}` → `${QuietNotes.lineHtml(card, escapeHtml)}${QuietNotes.heldHtml(card, escapeHtml)}`
- `${SettingPanes.findingButtonHtml(finding, currentPlatform())}` → `${held ? '' : SettingPanes.findingButtonHtml(finding, currentPlatform())}`
- `${finding.remediation ? \`` (the fix-steps block) → `${finding.remediation && !held ? \``

At the end of the IIFE, replace:

```js
    renderSituations();
    showScreen('welcome');
```

with:

```js
    // 'city' opens straight into the game: the Training Grounds until a sweep
    // has run. Plain view, Start over and every worry still work from there.
    function openCityHome() {
      if (!(window.RescueGame && window.RescueGame.isReady)) return false;
      situation = CITY_SITUATION;
      wantsCity = true;
      leftGame = false;
      if (window.RescueGame.showTraining(situation) !== false) showScreen('city');
      return true;
    }

    renderSituations();
    showScreen('welcome');
    // The game's module may still be loading.
    if (opensInGame(mode) && !openCityHome()) {
      window.addEventListener('rescue-game-ready', () => {
        if (opensInGame(mode) && !screens.welcome.hidden) openCityHome();
      });
    }
```

- [ ] **Step 8: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/game-flow-gate.test.js test/game-gate.test.js test/stealth-mode.test.js test/game-worry-scan.test.js test/first-question-flow.test.js test/quiet-notes.test.js && npm test`
Expected: PASS. If `npm test` reports `gameStillOffered is not a function` or `playButtonShown is not a function` anywhere, a caller was missed: run `grep -rn "gameStillOffered\|playButtonShown\|renderPlayButton" desktop/renderer desktop/test` and update it.

- [ ] **Step 9: Commit**

```bash
git add desktop/renderer/game/held.js desktop/renderer/game/controller.js desktop/renderer/quiet-notes.js desktop/renderer/app.js desktop/test/game-flow-gate.test.js desktop/test/game-gate.test.js desktop/test/game-worry-scan.test.js desktop/test/stealth-mode.test.js
git commit -m "City mode: opens into the game; monitoring software is held, never fixed, marked or scored"
```

---

### Task 8: The help district on the deck

**Depends on the command-center plan being merged.** This task edits the deck it builds: `deckHtml()`, `logEntry()`, `s.signal`, the `filter:<id>` map buttons and `createController({ …, loadDrillBank })`.

**Files:**
- Create: `desktop/renderer/game/side-district.js`
- Create: `desktop/renderer/game/views/side-district.js`
- Create: `desktop/test/fixtures/six-roses-excerpt.txt`
- Modify: `desktop/renderer/game/controller.js` (district state, screen, tile, clicks, Esc, `showCityFrom`, `deckHtml`, HUD)
- Modify: `desktop/renderer/game/game.css` (append)
- Modify: `desktop/setting-urls.js` (one exact URL)
- Test: `desktop/test/game-side-district.test.js`, `desktop/test/game-side-district-controller.test.js`

**Interfaces:**
- Consumes:
  - `pickDistrict(seed)` (Task 2); `RescueHost.mode()`, `RescueHost.citySeed()` (Task 5); `s.held` (Task 7); `QuietNotes.HELD_LINE` (Task 7).
  - From the command-center plan: `logEntry(kind, text)`, `deckHtml()`'s `cityHtml` and `notice`, the deck map's `data-go="filter:<districtId>"` buttons, and `s.signal`.
  - `win.rescue.openGuide(url)` (existing preload).
- Produces:
  - `side-district.js`: `FIRST_STEPS`, `HELP`, `OPEN_NOTE`, `SIX_ROSES`, `LEAVING` and `HELD`. Each entry is `{ text, quotes: string[], source }`; steps also carry `id` and `title`, resources carry `id`, `name` and maybe `url`.
  - `views/side-district.js`: `sideTileHtml(district, heldCount)`, `heldNoticeHtml(district)`, `renderSide({ district, held, notice, scout })`.
  - Controller screen `'side'`; clicks `data-go="side"`, `data-act="side-back"`, `data-act="side-open-guide"`; the Esc key.
  - `setting-urls.js`: `EXACT_GUIDE_URLS`.

- [ ] **Step 1: Check in the source excerpt**

Create `desktop/test/fixtures/six-roses-excerpt.txt`. The lines below the header are copied verbatim from the page's text:

```text
# Checked-in excerpt of the Six Roses guide, for desktop/test/game-side-district.test.js.
# Source: https://themultiverse.school/x/six-roses (text fetched 2026-10-18).
# Links on that page: https://techsafety.org https://nnedv.org/safetynet https://womenslaw.org https://ceta.tech.cornell.edu/ https://www.techsafety.org/resources-survivors/technology-safety-plan/
# If the page changes, refresh this file from it, then fix whatever the test reports.

The Story of Six Roses
How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life
a Digital Safety Guide for Domestic Violence Survivors
When Your Ex-Partner Knows Too Much
By Liz Howard, The Multiverse School
🚨 Your Safety Comes First
If you are in immediate danger, call 911
National Domestic Violence Hotline: 1-800-799-7233 (SAFE)
Text "START" to 88788
Before You Begin:
This guide assumes you're in a safe physical location
If you're still living with your abuser, see the "Still Living Together" section at the end
Delete this from your browser history after reading
Consider using a library or friend's computer

🛡️ Phase 1: Immediate Safety Planning
A. Document Everything (Safely)
Use a NEW notebook that stays hidden:
- [ ] Write down all accounts you think they might access
- [ ] List all devices you've shared or they've touched
- [ ] Note any threats they've made about "knowing everything"
- [ ] Track strange occurrences with dates/times
- [ ] Keep receipts/screenshots of harassment
Photo evidence:
- [ ] Use a friend's phone or new device to photograph evidence
- [ ] Email photos to a new, secret email account
- [ ] Don't use your regular cloud storage
B. Safety Communication Setup
Get a burner phone ($30-50 at Walmart/Target):
- [ ] Pay cash if possible
- [ ] Don't activate at home
- [ ] Don't save contacts with real names
- [ ] This is your "safety phone" - guard it carefully
- [ ] Keep it OFF and battery out when not using
Create a code system with trusted friend:
- [ ] "Thinking of you" = I'm okay
- [ ] "Let's get coffee" = I need help but not emergency
- [ ] "Can you pick up milk?" = Call 911 for me
You can change these phrases to match your normal patterns, these are just examples.

🔐 Phase 2: Breaking Their Digital Access
2 New Email Foundation
[ ] Create email on friend's device or library computer
[ ] Use fake name for recovery email
[ ] NEVER access from your current devices
[ ] Don't use identifying info in address
[ ] This becomes your "freedom email"

📱 Phase 3: Device Liberation
⚠️ Before You Remove Anything:
Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it, and some abusers escalate when they lose access. This step can make things more dangerous, so plan it.
- [ ] Document it first - screenshots/photos taken with a DIFFERENT device
- [ ] Plan the timing with a DV advocate (Hotline: 1-800-799-7233, or text "START" to 88788)
- [ ] Sometimes it's safer to leave it in place for now and use a separate, safe device for anything private
See TechSafety.org's Technology Safety Plan for more.

🆘 Resources
Hotlines:
National DV Hotline: 1-800-799-7233
Helpful Websites:
WomensLaw.org - Legal information
TechSafety.org - Tech abuse resources
NNEDV Safety Net - Technology safety

Still Living Together?
Remember: Leaving is the most dangerous time. Plan carefully with DV advocates.
**More Resources: Clinic to End Tech Abuse
Delete browser history after reading. Stay safe. 💜
```

Before going on, open https://themultiverse.school/x/six-roses and check that each quoted line still reads the same. If the page has changed, refresh the excerpt from it and adjust the quotes in Step 4 to match.

- [ ] **Step 2: Write the failing content and view tests**

Create `desktop/test/game-side-district.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { isAllowedGuideUrl } = require('../setting-urls.js');

const REPO = path.join(__dirname, '..', '..');
const SOURCES = {
  'six-roses': path.join(__dirname, 'fixtures', 'six-roses-excerpt.txt'),
  'guides/remediation/respond_to_monitoring_software.md': path.join(REPO, 'guides', 'remediation', 'respond_to_monitoring_software.md'),
  'guides/remediation/preserve_evidence_first.md': path.join(REPO, 'guides', 'remediation', 'preserve_evidence_first.md'),
};
const norm = (s) => String(s).toLowerCase().replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[–—]/g, '-').replace(/\s+/g, ' ').trim();
const source = (key) => norm(fs.readFileSync(SOURCES[key], 'utf8'));
const load = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

async function everything() {
  const c = await load('side-district.js');
  return [...c.FIRST_STEPS, ...c.HELP, c.OPEN_NOTE, c.SIX_ROSES, c.SIX_ROSES.note, c.LEAVING, c.HELD.heading, ...c.HELD.steps];
}

test('every line is the source’s own words, with only a few joining words of ours', async () => {
  for (const item of await everything()) {
    assert.ok(item.source in SOURCES, `${item.text}: unknown source ${item.source}`);
    const src = source(item.source);
    const text = norm(item.text);
    let rest = text;
    for (const q of item.quotes) {
      assert.ok(src.includes(norm(q)), `not in ${item.source}: "${q}"`);
      assert.ok(text.includes(norm(q)), `quote not in the text: "${q}"`);
      rest = rest.replace(norm(q), '');
    }
    assert.ok(rest.replace(/[^a-z0-9]/g, '').length <= 50, `too much of our own wording in "${item.text}"`);
  }
});

test('every number and every address is in the source', async () => {
  for (const item of await everything()) {
    const src = source(item.source) + ' ' + source('six-roses');
    for (const n of norm(item.text).match(/\d[\d-]*\d|\d/g) || []) assert.ok(src.includes(n), `${n} in "${item.text}"`);
    if (item.url) assert.ok(src.includes(norm(item.url)), item.url);
  }
});

test('it holds what the spec lists, and nothing tells the person how long anything takes', async () => {
  const c = await load('side-district.js');
  const { TIME_WORDS } = await load('training.js');
  assert.deepStrictEqual(c.FIRST_STEPS.map((x) => x.id), ['record', 'phone', 'code-words', 'freedom-email', 'evidence-first']);
  assert.deepStrictEqual(c.HELP.map((x) => x.id), ['911', 'hotline', 'techsafety', 'safety-net', 'womenslaw', 'ceta']);
  assert.strictEqual(c.SIX_ROSES.url, 'https://themultiverse.school/x/six-roses');
  assert.strictEqual(c.LEAVING.text, 'Leaving is the most dangerous time. Plan carefully with DV advocates.');
  assert.strictEqual(c.HELD.heading.text, 'Don’t remove it yet. Talk to an advocate first.');
  assert.strictEqual(c.HELD.heading.text, Q.HELD_LINE, 'the list and the district say the same');
  for (const item of await everything()) assert.doesNotMatch(item.text, TIME_WORDS, item.text);
  for (const s of c.HELD.steps) assert.doesNotMatch(s.text, /^(remove|uninstall|delete|turn off|reset)/i, s.text);
  for (const s of c.FIRST_STEPS) assert.ok(s.title.length <= 50 && !/\d/.test(s.title), s.title);
});

test('only the guide opens, through the guide allowlist; every other address is text', async () => {
  const { renderSide } = await load('views/side-district.js');
  const { pickDistrict } = await load('district-names.js');
  const c = await load('side-district.js');
  const html = renderSide({ district: pickDistrict(7), held: [], notice: false });
  assert.strictEqual((html.match(/data-act="side-open-guide"/g) || []).length, 1);
  assert.strictEqual((html.match(/data-act="side-back"/g) || []).length, 1);
  assert.doesNotMatch(html, /<a\s/);
  for (const r of c.HELP) if (r.url) assert.ok(html.includes(`<code>${r.url}</code>`), r.url);
  assert.ok(isAllowedGuideUrl(c.SIX_ROSES.url));
  for (const bad of [`${c.SIX_ROSES.url}/`, `${c.SIX_ROSES.url}?x=1`, `${c.SIX_ROSES.url}-evil`, c.SIX_ROSES.url.replace('https', 'http'), 'https://themultiverse.school/x/']) {
    assert.strictEqual(isAllowedGuideUrl(bad), false, bad);
  }
});

test('the district screen: its name and voice, the held findings escaped, BACK TO THE GAME', async () => {
  const { renderSide, sideTileHtml, heldNoticeHtml } = await load('views/side-district.js');
  const { pickDistrict } = await load('district-names.js');
  const d = pickDistrict(424242);
  const html = renderSide({ district: d, held: [{ module: 'stalkerware_scan', title: '<img src=x onerror=alert(1)>' }], notice: true });
  assert.ok(html.includes(d.name.toUpperCase().replace(/’/g, '&#39;')) || html.includes(d.name.toUpperCase()));
  assert.ok(html.includes(d.voice.hello.replace(/’/g, '’')));
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(html, /BACK TO THE GAME/);
  assert.match(html, /It couldn’t be opened from here\./);
  assert.doesNotMatch(renderSide({ district: d, held: [] }), /Don’t remove it yet/);
  assert.match(sideTileHtml(d, 0), /data-go="side"/);
  assert.match(sideTileHtml(d, 2), /NEW/);
  assert.match(heldNoticeHtml(d), /data-go="side"/);
  assert.doesNotMatch(sideTileHtml(d, 1) + heldNoticeHtml(d), /advocate|remove|monitor|watch/i, 'the deck names only the place');
});

test('every look has its colours in game.css', async () => {
  const { LOOKS } = await load('district-names.js');
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'game.css'), 'utf8');
  for (const look of LOOKS) assert.ok(css.includes(`.look-${look} {`), look);
});
```

- [ ] **Step 3: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-side-district.test.js`
Expected: FAIL with `Cannot find module …/side-district.js`.

- [ ] **Step 4: Write the content**

Create `desktop/renderer/game/side-district.js`:

```js
// What the generated district holds. Every line is traceable, word for word,
// to the Six Roses guide (https://themultiverse.school/x/six-roses, checked in
// as desktop/test/fixtures/six-roses-excerpt.txt) or to one of this project's
// guides; desktop/test/game-side-district.test.js enforces it. `quotes` are
// the source's own words inside `text`; the rest of `text` is joining words.
const SIX = 'six-roses';
const RESPOND = 'guides/remediation/respond_to_monitoring_software.md';

export const FIRST_STEPS = [
  { id: 'record', title: 'Keep a hidden record.', source: SIX,
    text: 'Use a new notebook that stays hidden. Write down all accounts you think they might access. List all devices you’ve shared or they’ve touched. Track strange occurrences with dates/times.',
    quotes: ['Use a NEW notebook that stays hidden', 'Write down all accounts you think they might access', "List all devices you've shared or they've touched", 'Track strange occurrences with dates/times'] },
  { id: 'phone', title: 'A safety phone.', source: SIX,
    text: 'Get a burner phone. This is your “safety phone” - guard it carefully. Don’t activate at home. Don’t save contacts with real names. Keep it OFF and battery out when not using.',
    quotes: ['Get a burner phone', 'This is your "safety phone" - guard it carefully', "Don't activate at home", "Don't save contacts with real names", 'Keep it OFF and battery out when not using'] },
  { id: 'code-words', title: 'Code words with a trusted friend.', source: SIX,
    text: 'Create a code system with trusted friend: “Thinking of you” = I’m okay. “Let’s get coffee” = I need help but not emergency. “Can you pick up milk?” = Call 911 for me. You can change these phrases to match your normal patterns.',
    quotes: ['Create a code system with trusted friend', '"Thinking of you" = I\'m okay', '"Let\'s get coffee" = I need help but not emergency', '"Can you pick up milk?" = Call 911 for me', 'You can change these phrases to match your normal patterns'] },
  { id: 'freedom-email', title: 'A separate “freedom email”.', source: SIX,
    text: 'Create email on friend’s device or library computer. NEVER access from your current devices. Don’t use identifying info in address. This becomes your “freedom email”.',
    quotes: ["Create email on friend's device or library computer", 'NEVER access from your current devices', "Don't use identifying info in address", 'This becomes your "freedom email"'] },
  { id: 'evidence-first', title: 'Keep the evidence before you change anything.', source: SIX,
    text: 'Document it first - screenshots/photos taken with a DIFFERENT device. Keep receipts/screenshots of harassment.',
    quotes: ['Document it first - screenshots/photos taken with a DIFFERENT device', 'Keep receipts/screenshots of harassment'] },
];

export const HELP = [
  { id: '911', name: '911', source: SIX, text: 'If you are in immediate danger, call 911.', quotes: ['If you are in immediate danger, call 911'] },
  { id: 'hotline', name: 'National Domestic Violence Hotline', source: SIX,
    text: 'National Domestic Violence Hotline: 1-800-799-7233. Text “START” to 88788.',
    quotes: ['National Domestic Violence Hotline: 1-800-799-7233', 'Text "START" to 88788'] },
  { id: 'techsafety', name: 'TechSafety.org', source: SIX, url: 'https://techsafety.org',
    text: 'TechSafety.org - Tech abuse resources', quotes: ['TechSafety.org - Tech abuse resources'] },
  { id: 'safety-net', name: 'NNEDV Safety Net', source: SIX, url: 'https://nnedv.org/safetynet',
    text: 'NNEDV Safety Net - Technology safety', quotes: ['NNEDV Safety Net - Technology safety'] },
  { id: 'womenslaw', name: 'WomensLaw.org', source: SIX, url: 'https://womenslaw.org',
    text: 'WomensLaw.org - Legal information', quotes: ['WomensLaw.org - Legal information'] },
  { id: 'ceta', name: 'Clinic to End Tech Abuse', source: SIX, url: 'https://ceta.tech.cornell.edu/',
    text: 'Clinic to End Tech Abuse', quotes: ['Clinic to End Tech Abuse'] },
];

// Shown as text: opening them from here would leave their names in the browser's history.
export const OPEN_NOTE = { source: SIX, text: 'Consider using a library or friend’s computer to look these up.',
  quotes: ["Consider using a library or friend's computer"] };

export const SIX_ROSES = {
  name: 'The Story of Six Roses', url: 'https://themultiverse.school/x/six-roses', source: SIX,
  text: 'How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life',
  quotes: ['How a Gluten Free, Dairy Free Rose Apple Tart Saved My Life'],
  note: { source: SIX, text: 'It opens in your web browser and reads like a recipe. Delete this from your browser history after reading.',
    quotes: ['Delete this from your browser history after reading'] },
};

export const LEAVING = { source: SIX, text: 'Leaving is the most dangerous time. Plan carefully with DV advocates.',
  quotes: ['Leaving is the most dangerous time. Plan carefully with DV advocates.'] };

// For monitoring software the checkup found: never "remove", and how to keep a quiet record of it.
export const HELD = {
  heading: { source: RESPOND, text: 'Don’t remove it yet. Talk to an advocate first.', quotes: [] },
  steps: [
    { source: SIX, text: 'Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it.',
      quotes: ['Removing spyware/stalkerware or a tracker, or factory resetting a device, can tip off the person who installed it'] },
    { source: RESPOND, text: 'On paper or on another device, write down the name the scan found, where it was found, and today’s date. Take a photo of the scan result with your phone.',
      quotes: ["On paper or on another device, write down the name the scan found, where it was found, and today's date", 'Take a photo of the scan result with your phone'] },
    { source: SIX, text: 'Plan the timing with a DV advocate (Hotline: 1-800-799-7233, or text “START” to 88788).',
      quotes: ['Plan the timing with a DV advocate (Hotline: 1-800-799-7233, or text "START" to 88788)'] },
    { source: SIX, text: 'Sometimes it’s safer to leave it in place for now and use a separate, safe device for anything private.',
      quotes: ["Sometimes it's safer to leave it in place for now and use a separate, safe device for anything private"] },
  ],
};
```

- [ ] **Step 5: Write the views**

Create `desktop/renderer/game/views/side-district.js`:

```js
import { esc } from '../escape.js';
import { FIRST_STEPS, HELP, OPEN_NOTE, SIX_ROSES, LEAVING, HELD } from '../side-district.js';

// The district's tile, on the deck's city and on the Training Grounds. It names only the place.
export function sideTileHtml(district, heldCount = 0) {
  return `<div class="side-tile look-${esc(district.look)}">
    <button type="button" class="btn-s" data-go="side">${esc(district.name.toUpperCase())} ▶</button>${heldCount ? ' <span class="badge">NEW</span>' : ''}</div>`;
}

// On the deck when the checkup found something that belongs there. Only the place again.
export function heldNoticeHtml(district) {
  return `<p class="link-notice" role="status">Something new in ${esc(district.name)}. <button type="button" class="btn-t" data-go="side">GO THERE ▶</button></p>`;
}

export function renderSide({ district, held = [], notice = false, scout = () => '' }) {
  const v = district.voice;
  const heldHtml = held.length ? `
    <div class="panel active" role="note"><div class="label">${esc(HELD.heading.text)}</div>
      <ul class="notes">${held.map((h) => `<li>${esc(h.title)}</li>`).join('')}</ul>
      <ol class="side-steps">${HELD.steps.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ol></div>` : '';
  const help = HELP.map((r) => `<li>${esc(r.text)}${r.url ? ` <code>${esc(r.url)}</code>` : ''}</li>`).join('');
  return `
  <section class="side look-${esc(district.look)}" aria-labelledby="side-title">
    <header class="hud side-top"><h2 class="hud-title" id="side-title">${esc(district.name.toUpperCase())}</h2>
      <button type="button" class="btn-p" data-act="side-back">BACK TO THE GAME</button></header>
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(v.hello)}</p></div>
    ${heldHtml}
    <div class="panel"><div class="label">QUIET FIRST STEPS</div>
      <ol class="side-steps">${FIRST_STEPS.map((x) => `<li><b>${esc(x.title)}</b> ${esc(x.text)}</li>`).join('')}</ol></div>
    <div class="panel"><div class="label">WHO CAN HELP</div><ul class="notes">${help}</ul>
      <p class="intel">${esc(OPEN_NOTE.text)}</p></div>
    <div class="panel"><div class="label">${esc(SIX_ROSES.name.toUpperCase())}</div>
      <p class="intel">${esc(SIX_ROSES.text)}</p><p class="intel">${esc(SIX_ROSES.note.text)}</p>
      <button type="button" class="btn-s" data-act="side-open-guide">OPEN IT IN YOUR BROWSER</button>
      ${notice ? `<p class="link-notice" role="status">${esc('It couldn’t be opened from here.')}</p>` : ''}</div>
    <div class="panel"><p class="intel"><b>${esc(LEAVING.text)}</b></p></div>
    <p class="say">${esc(v.bye)}</p>
    <p class="intel">Press Esc to go back to the game.</p>
  </section>`;
}
```

In `desktop/renderer/game/game.css`, append:

```css
/* The generated district: one of six looks, picked per install (district-names.js). */
.side { --side-accent: var(--lime); }
.look-dusk { --side-accent: #B49CFF; }
.look-harbor { --side-accent: #5EC8FF; }
.look-brass { --side-accent: #E8B04A; }
.look-moss { --side-accent: #8FD694; }
.look-ember { --side-accent: #FF8A5C; }
.look-neon { --side-accent: #FF5FD2; }
.side-tile { display: flex; gap: 8px; align-items: center; margin: 0 0 12px; }
.side-tile .btn-s, .side .hud-title { color: var(--side-accent, var(--lime)); }
.side-top { display: flex; align-items: center; gap: 12px; }
.side-steps li { margin: 6px 0; }
.side-steps b { color: var(--side-accent, var(--lime)); margin-right: 4px; }
```

In `desktop/setting-urls.js`, after `const ALLOWED_GUIDE_PREFIXES = [GUIDE_URL_PREFIX, GAME_URL_PREFIX];` add:

```js
// Exact pages, not prefixes: the one guide the game's generated district opens.
const EXACT_GUIDE_URLS = ['https://themultiverse.school/x/six-roses'];
```

Change `isAllowedGuideUrl` to:

```js
function isAllowedGuideUrl(url) {
  return typeof url === 'string'
    && (EXACT_GUIDE_URLS.includes(url) || ALLOWED_GUIDE_PREFIXES.some((prefix) => url.startsWith(prefix)));
}
```

Add `EXACT_GUIDE_URLS,` to `module.exports`.

Run: `cd desktop && node --test test/game-side-district.test.js test/learn-more.test.js test/situations.test.js`
Expected: PASS.

- [ ] **Step 6: Write the failing controller tests**

Create `desktop/test/game-side-district-controller.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 4) => { for (let i = 0; i < n; i += 1) await tick(); };
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const finding = (title, severity) => ({ title, description: 'd', severity, category: 'security', data: {} });
const DOC = scan(mod('remote_login_check', [finding('Remote Login is on', 'warning')]), mod('stalkerware_scan', [finding('Stalkerware found: mSpy', 'critical')]));
const CLEAN = scan(mod('remote_login_check', [finding('Remote Login is on', 'warning')]));
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

function stub({ mode = 'city', seed = 424242, openGuide = async () => true } = {}) {
  const clicks = [];
  const keys = [];
  const focused = [];
  const calls = { guides: [] };
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: (sel) => {
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      return m && frame.innerHTML.includes(`${m[1]}="${m[2]}"`) ? { focus: () => focused.push(sel) } : null;
    },
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: (type, fn) => { if (type === 'keydown') keys.push(fn); },
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => seed, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: (url) => { calls.guides.push(url); return openGuide(url); } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const press = (key) => {
    const ev = { key, prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} };
    keys.forEach((fn) => fn(ev));
    return ev;
  };
  return { win, frame, calls, click, press, focused, html: () => frame.innerHTML };
}

async function setup(opts = {}, doc = DOC) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = recordingStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl, storage };
}

test('city mode: the district is on the deck and on the Training Grounds, under its generated name', async () => {
  const { pickDistrict } = await game('district-names.js');
  const name = pickDistrict(424242).name.toUpperCase();
  const t = await setup({}, CLEAN);
  assert.match(t.html(), /data-go="side"/);
  assert.ok(t.html().includes(name) || t.html().includes(name.replace(/’/g, '&#39;')));
  t.ctl.showTraining({ id: 'city', title: 'Take back the city' });
  assert.match(t.html(), /data-go="side"/, 'before any sweep too');
});

test('standard mode: no district anywhere, and its routes and Esc do nothing', async () => {
  const t = await setup({ mode: 'standard' });
  assert.doesNotMatch(t.html(), /data-go="side"/);
  t.click({ 'data-go': 'side' });
  assert.doesNotMatch(t.html(), /side-title/);
  assert.strictEqual(t.press('Escape').prevented, false);
});

test('monitoring software waits in the district: not on the deck, no mission, no points, nothing saved', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await setup();
  const deck = t.html();
  assert.doesNotMatch(deck, /mSpy/);
  assert.ok(deck.includes(`Something new in ${pickDistrict(424242).name}`.replace(/’/g, '&#39;')) || deck.includes(`Something new in ${pickDistrict(424242).name}`));
  t.click({ 'data-go': 'side' });
  assert.match(t.html(), /mSpy/);
  assert.match(t.html(), /Don’t remove it yet\. Talk to an advocate first\./);
  assert.doesNotMatch(t.html(), /data-fix-module|data-mark-card|data-act="tag:/);
  const saved = JSON.parse(t.storage.getItem('device-rescue.game.v1'));
  assert.strictEqual(saved.deck.points, 0);
  assert.doesNotMatch(JSON.stringify(saved), /mSpy|stalkerware/i);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('Esc, or BACK TO THE GAME, swaps straight to the deck with focus on the map', async () => {
  for (const leave of ['esc', 'button']) {
    const t = await setup();
    t.click({ 'data-go': 'side' });
    assert.match(t.html(), /side-title/);
    if (leave === 'esc') assert.strictEqual(t.press('Escape').prevented, true);
    else t.click({ 'data-act': 'side-back' });
    assert.doesNotMatch(t.html(), /side-title/, leave);
    assert.match(t.html(), /INCOMING SIGNALS/, leave);
    assert.ok(t.focused.includes('[data-go="filter:gatehouse"]'), `${leave}: ${t.focused.join(', ')}`);
  }
});

test('Esc mid-transition: a guide still opening says nothing afterwards, and a second Esc does nothing', async () => {
  let resolveOpen;
  const t = await setup({ openGuide: () => new Promise((r) => { resolveOpen = r; }) });
  t.click({ 'data-go': 'side' });
  t.click({ 'data-act': 'side-open-guide' });
  await tick();
  t.press('Escape');
  resolveOpen(false);
  await ticks();
  assert.doesNotMatch(t.html(), /side-title|couldn’t be opened|six-roses/);
  const before = t.html();
  assert.strictEqual(t.press('Escape').prevented, false);
  assert.strictEqual(t.html(), before);
});

test('a sweep that finishes in the district stays there; Esc then lands on the new deck', async () => {
  const t = await setup();
  t.click({ 'data-go': 'side' });
  t.ctl.scanDone(CLEAN, { id: 'city', title: 'Take back the city' });
  assert.match(t.html(), /side-title/);
  t.press('Escape');
  assert.match(t.html(), /INCOMING SIGNALS/);
  assert.doesNotMatch(t.html(), /Something new in/, 'the new sweep held nothing');
});

test('Esc on any other screen is left alone', async () => {
  const t = await setup();
  assert.strictEqual(t.press('Escape').prevented, false);
  t.ctl.showTraining({ id: 'city', title: 'x' });
  assert.strictEqual(t.press('Escape').prevented, false);
});

test('the ops log says only where they went', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await setup();
  t.click({ 'data-go': 'side' });
  t.press('Escape');
  const log = t.html().split('OPS LOG')[1] || '';
  assert.ok(log.includes(`Visited ${pickDistrict(424242).name}`) || log.includes(`Visited ${pickDistrict(424242).name.replace(/’/g, '&#39;')}`));
  assert.doesNotMatch(log, /advocate|hotline|799|watch|remove|guide|roses/i);
});

test('opening the guide goes through openGuide with the one exact address; a refusal shows in the district only', async () => {
  const t = await setup({ openGuide: async () => false });
  t.click({ 'data-go': 'side' });
  t.click({ 'data-act': 'side-open-guide' });
  await ticks();
  assert.deepStrictEqual(t.calls.guides, ['https://themultiverse.school/x/six-roses']);
  assert.match(t.html(), /It couldn’t be opened from here\./);
  t.press('Escape');
  assert.doesNotMatch(t.html(), /couldn’t be opened/);
});

test('the same install gets the same district after a restart', async () => {
  const a = await setup({ seed: 99 }, CLEAN);
  const b = await setup({ seed: 99 }, CLEAN);
  const tile = (h) => /data-go="side">([^<]*)</.exec(h)[1];
  assert.strictEqual(tile(a.html()), tile(b.html()));
});
```

Run: `cd desktop && node --test test/game-side-district-controller.test.js`
Expected: FAIL. There's no `data-go="side"` on the deck, and Esc isn't handled.

- [ ] **Step 7: Wire the district into the controller**

In `desktop/renderer/game/controller.js`:

Imports, after the other view imports:

```js
import { pickDistrict } from './district-names.js';
import { SIX_ROSES } from './side-district.js';
import { renderSide, sideTileHtml, heldNoticeHtml } from './views/side-district.js';
```

In the initial state object `s = { …`, add `sideTicket: 0, sideNotice: false,`.

Directly after the `s = { … }` declaration, add:

```js
  // The generated district (city mode only): help that looks like the rest of the city.
  const inCity = () => !!(win.RescueHost && typeof win.RescueHost.mode === 'function' && win.RescueHost.mode() === 'city');
  let sideDistrict = null;
  const side = () => sideDistrict
    || (sideDistrict = pickDistrict(win.RescueHost && typeof win.RescueHost.citySeed === 'function' ? win.RescueHost.citySeed() : 1));
  const sideTile = () => (inCity() ? sideTileHtml(side(), s.held.length) : '');
  const heldNotice = () => (inCity() && s.held.length ? heldNoticeHtml(side()) : '');
```

In `screenHtml()`, add as its first lines:

```js
    if (s.screen === 'side') {
      if (inCity()) return renderSide({ district: side(), held: s.held, notice: s.sideNotice, scout });
      s.screen = s.city ? 'map' : 'training';
    }
```

In the same function's `if (s.screen === 'training') { return renderTraining(…); }` branch, change `return renderTraining(` to `return sideTile() + renderTraining(`.

In `deckHtml()` (from the command-center plan):
- Change the `const cityHtml = s.rc || s.accountsError ? … : …;` assignment so its value is prefixed with the tile: `const cityHtml = sideTile() + (s.rc || s.accountsError ? … : …);`. The two branches inside stay exactly as they are.
- In the `renderDeck({ … })` call, change `notice: s.linkNotice` to `notice: heldNotice() + s.linkNotice`.

In `render()`:
- Change `if (!s.city && !TRAINING_SCREENS.has(s.screen)) s.screen = 'training';` to `if (!s.city && !TRAINING_SCREENS.has(s.screen) && s.screen !== 'side') s.screen = 'training';`.
- The line that builds `hud` (in whatever form the command-center plan left it, `const hud = … ;`) becomes `const hud = s.screen === 'side' ? '' : (…the existing expression…);`.

In the first `frame.addEventListener('click', …)` handler, directly after `if (act === 'leave') { win.RescueHost.leaveGame(); return; }`, add:

```js
    // Always works, like LIST: back to the ordinary game.
    if (act === 'side-back') { leaveSide(); return; }
```

and directly after `if (go) s.linkNotice = '';`, add:

```js
    if (go === 'side') { if (inCity()) openSide(); return; }
    if (act === 'side-open-guide') { if (s.screen === 'side') openSideGuide(); return; }
```

After the `recheck` function, add:

```js
  function openSide() {
    s.signal = null; // a Signal or Noise panel left open closes
    s.sideNotice = false;
    s.screen = 'side';
    logEntry('VISIT', `Visited ${side().name}`);
    render();
  }

  // The panic key and BACK TO THE GAME: the ordinary game at once, focus on the map.
  function leaveSide() {
    s.sideTicket += 1; // a guide still opening says nothing afterwards
    s.sideNotice = false;
    s.screen = s.city ? 'map' : 'training';
    render();
    const first = s.city && s.city.districts.length ? s.city.districts[0] : null;
    const target = first
      ? frame.querySelector(`[data-go="filter:${first.id}"]`) || frame.querySelector(`[data-go="district:${first.id}"]`)
      : frame.querySelector('[data-act="start-checkup"]');
    if (target && typeof target.focus === 'function') target.focus();
  }

  // Only the Six Roses guide opens, through main's guide allowlist.
  function openSideGuide() {
    const ticket = s.sideTicket;
    Promise.resolve().then(() => win.rescue.openGuide(SIX_ROSES.url)).then((ok) => ok === true, () => false).then((ok) => {
      if (ok || ticket !== s.sideTicket || s.screen !== 'side') return;
      s.sideNotice = true;
      render();
    });
  }

  // Esc on the district, wherever focus is. Capture phase, so nothing else sees it first.
  if (typeof win.addEventListener === 'function') {
    win.addEventListener('keydown', (e) => {
      if (!e || e.key !== 'Escape' || s.screen !== 'side') return;
      if (typeof e.preventDefault === 'function') e.preventDefault();
      if (typeof e.stopPropagation === 'function') e.stopPropagation();
      leaveSide();
    }, true);
  }
```

In `showCityFrom(doc)`, add `const stay = s.screen === 'side' && inCity();` as the function's first line. Change its `s.screen = 'map';` to `s.screen = stay ? 'side' : 'map';`, and its `s.focusPending = true;` to `s.focusPending = !stay;`.

- [ ] **Step 8: Run the tests to make sure they pass**

Run: `cd desktop && node --test test/game-side-district.test.js test/game-side-district-controller.test.js && npm test`
Expected: PASS. Every command-center deck test and every earlier controller test still passes: in standard mode, and with no `RescueHost.mode`, nothing about the deck changes.

- [ ] **Step 9: Commit**

```bash
git add desktop/renderer/game/side-district.js desktop/renderer/game/views/side-district.js desktop/renderer/game/controller.js desktop/renderer/game/game.css desktop/setting-urls.js desktop/test/fixtures/six-roses-excerpt.txt desktop/test/game-side-district.test.js desktop/test/game-side-district-controller.test.js
git commit -m "City mode: the generated district on the deck, sourced from Six Roses, with the Esc panic key"
```

---

### Task 9: Manual QA, and the owner's publishing checklist

**Files:**
- Modify: `desktop/MANUAL-QA.md`

**Interfaces:**
- Consumes: everything above.
- Produces: checks a person runs on a real Mac before the release, and the owner's list of outward-facing steps. Nothing here publishes anything.

- [ ] **Step 1: Replace the steps the new rules changed**

In `desktop/MANUAL-QA.md`, section "Game mode, end to end", replace step 7 with:

```markdown
7. Start over, pick **I think someone is watching me**, and run the checkup. No question is asked. The checkup runs on the sweep screen, and the city opens with the generated district's tile on it (see "City mode" below).
```

In "Training Grounds and the final boss", replace step 10 with:

```markdown
10. Start over and pick the iPhone worry after **Play it as a game**. The plain scan screen opens, waiting for **Run checkup**: no sweep, no lessons, and no checkup started for you.
```

Replace the sentence that ends step 11 (`Run with \`RESCUE_ENGINE=/tmp/fake-rescue\`, click **Play it as a game** …`) with:

```markdown
    In DevTools' Console run `localStorage.setItem('device-rescue.display', 'standard')` and reload. Run with `RESCUE_ENGINE=/tmp/fake-rescue`, click **Play it as a game** and pick **I’m not sure — check everything**. When the sweep finishes, "We found something that can be used to watch a computer. Is that something you know about?" appears before anything else. Click **Yes, I know about it**: the city opens, and on the list (**LIST**) the card has one line, "Removing this can alert whoever installed it. Read this first.", which opens to the full note. Keep `/tmp/fake-rescue` for "City mode" below.
```

- [ ] **Step 2: Add the new sections**

Append before the closing line `Record anything that doesn't match…`:

```markdown
## Reclaim City: the name

1. Build with `cd desktop && npx electron-builder --mac --publish never -c.mac.identity=-`. `desktop/dist/` holds `ReclaimCity-mac-arm64.dmg` (or `-x64`). Its window title is "Reclaim City".
2. Install it from the dmg. The app is "Reclaim City" in Applications, the Dock, the menu bar and **Reclaim City → About Reclaim City**. If the owner has added `desktop/build/icon.png`, the Dock shows the game icon; otherwise Electron's default. Never a shield.
3. On a Mac that had Device Rescue with saved game progress: open Reclaim City. Lessons marked DONE and missions saved for LATER are still there. `~/Library/Application Support/Device Rescue/` is still the folder in use, and no `~/Library/Application Support/Reclaim City/` folder appears.
4. Search every screen you pass through below for "Device Rescue". It appears nowhere, except where the real folder path `~/Library/Application Support/Device Rescue/Quarantine` is printed in a background job's Undo steps.

## The question and the two modes

Start from a clean slate each time: in DevTools' Console run `localStorage.removeItem('device-rescue.display')` and reload.

1. **Get started**, pick **I think I’ve been hacked**. "One more question" appears with the question and three answers. Click **No**. The scan screen opens. Reload, go back to the worry screen: the question isn't asked again.
2. On the worry screen, click **Something changed?**. The question appears. Answer **Yes, that’s part of it**, and you're back on the worry screen.
3. DevTools → Application → Local Storage → `app://rescue`. The only new keys are `device-rescue.display` (`city` or `standard`) and `device-rescue.city-seed` (a number). Search every value for "partner", "safety", "stalk", "watch", "advocate" and "hotline": none appear.
4. Standard mode, a normal checkup: no card, the scan screen or the "What to do next" box mentions a hotline or an advocate.

## City mode

1. With `device-rescue.display` set to `city`, quit and reopen the app. It opens straight into the game (the Training Grounds before any sweep), with no welcome screen. Its title reads "Take back the city", not a worry.
2. The generated district's tile is there. Note its name. Quit, reopen: same name, same colours. On a second Mac (or after deleting `device-rescue.city-seed`), the name is usually different.
3. Open the district. QUIET FIRST STEPS, WHO CAN HELP, the Six Roses guide and "Leaving is the most dangerous time. Plan carefully with DV advocates." are there. Only **OPEN IT IN YOUR BROWSER** opens anything: it opens https://themultiverse.school/x/six-roses, which reads as a recipe.
4. Press **Esc**. You're back on the game at once, with keyboard focus on the first district on the map. Open the district again and click **BACK TO THE GAME**: the same.
5. Click **OPEN IT IN YOUR BROWSER** and press **Esc** straight away. Back in the app, the deck shows no notice and no address.
6. Run with `RESCUE_ENGINE=/tmp/fake-rescue` (from "Training Grounds and the final boss", step 11) and start a sweep. When it finishes, the deck says "Something new in <the district>" and shows nothing named "Monitoring app found". The district shows it under "Don’t remove it yet. Talk to an advocate first.", with how to keep a record of it. On **LIST**, its card has the same line and no **Fix it for me**, no **This is mine**, no step-by-step and no System Settings button. Points on the deck didn't change.
7. The ops log reads "Visited <the district>" for each visit, and nothing else about it. The app never shows a notification or bounces the Dock icon.
8. **PLAIN VIEW**, **Start over**, **Get started**, **Someone is on my Wi-Fi…**: no question, and the checkup runs in the game.
9. Quit and delete `/tmp/fake-rescue`. In DevTools, `localStorage.removeItem('device-rescue.display')`.

## Before publishing (the owner's steps, never an agent's)

Each of these is outward-facing. The plan prepares them; the owner does them:
1. Supply the game icon as `desktop/build/icon.png`, 1024×1024 (`app-identity.test.js` checks the size).
2. Confirm the name of the web version on the download page and the USB stick ("Reclaim City (Web)").
3. Choose the version in `desktop/package.json` and write the release notes (they begin "Reclaim City used to be called Device Rescue.").
4. Merge the branch into `main` and push the `v*` tag together. Merging deploys `site/` and the docs with the new `ReclaimCity-*` download links, and those links only work once the release exists.
5. Rebuild the `/x/` page with `python scripts/build-standalone-landing.py` (it writes `dist/reclaim-city-landing.html`) and seed it per `~/src/themultiverse.school/docs/AGENT_PUBLISHING_GUIDE.md` Part 2. Decide whether the slug stays `/x/device-rescue`.
6. Windows: install the new `ReclaimCity-windows-x64.exe` over an existing Device Rescue install, and check that it updates in place (same appId) and keeps saved progress.
7. Optional, outside this repo: the Six Roses guide's figure cites NPR's 2014 survey now; the spec's suggested note about the removal warning is already addressed on the page.
```

- [ ] **Step 3: Check the docs build and the tests**

Run: `.venv/bin/python -m pytest tests/test_product_name.py -q && (cd desktop && npm test)`
Expected: PASS. `desktop/MANUAL-QA.md` is outside the name test's scope, and its "Device Rescue" mentions are about the old app.

- [ ] **Step 4: Commit**

```bash
git add desktop/MANUAL-QA.md
git commit -m "MANUAL-QA: the rename, the question, city mode, and the owner's publishing checklist"
```

---

## Self-Review Notes

| Spec section | Task |
|---|---|
| §1 productName, window title, About, installer and artifact names, Dock name | 3 |
| §1 icon (a game icon, not a shield) | 3 (shield gone; the icon file is the owner's, Task 9) |
| §1 appId and user-data location kept; `device-rescue.game.v1` survives | 3 (pinned), 1 (no key removed) |
| §1 README, download page, `/x/` page, docs site, CONTRIBUTING, AGENTS.md, in-app copy, release notes | 4, 3 (release notes), 9 (`/x/` build and seed) |
| §1 "Plain view" | 3 (welcome eyebrow; PLAIN VIEW already in the game) |
| §1 not renamed: CLI, Python package, repository | 4 (allowlist, CLI files skipped) |
| §1 release links move in the same release | 3, 4, 9 (merge with the tag) |
| §2 the question, the three answers, the watched shortcut | 5 |
| §2 stored innocuously | 1, 7 (whole-app audit), 8 (deck store) |
| §2 "Something changed?" | 5 |
| §2 re-check on monitoring; replaces the withdrawal | 5, 7 |
| §3 standard mode: paragraphs, banner, hotline lines hidden; one line kept | 6 |
| §4 opens into the game | 7 |
| §4 generated district: name, look, voice; seeded, stable | 2, 8 |
| §4 content sourced from Six Roses | 8 |
| §4 monitoring findings: never remove, no fix, no mark, no points | 7 (list, city), 8 (deck, points) |
| §4 panic key | 8 |
| §4 quiet traces: no notifications, generic log | 7 (notifications), 8 (log) |
| §4 gate tests rewritten | 7 |
| §5 copy rules and the accuracy test | 8 |
| §6 testing list | 1, 4, 5, 6, 7, 8 |

The Review Focus items are pinned as follows:
1. Task 3 (`saved data stays where every earlier version kept it`) and Task 1 (`an existing install keeps everything it saved`).
2. Task 5 (`the follow-up, once a session`) and Task 7 (`rather not say, then monitoring software…`, both answers).
3. Task 8 (`Esc mid-transition…`, `a sweep that finishes in the district…`).
4. Task 7 (`a city-mode person who picks a different worry later…`).
5. Task 4 (`test_engine_text_the_app_shows_uses_the_new_name`, `test_no_shipped_copy_says_device_rescue`).

Names used across tasks:
- `DisplayMode.{readMode, writeMode, ensureSeed, MODE_KEY, SEED_KEY}` (1 → 5, 7)
- `FirstQuestion.{afterWorry, modeFor, recheckDue, questionHtml}` (5 → 7)
- `QuietNotes.{cardText, lineHtml, heldHtml, quietDoc, noteFor, HELD_LINE, MONITORING_MODULES}` (6, 7 → 8)
- `splitHeld` / `s.held` (7 → 8)
- `pickDistrict` (2 → 8)
- `RescueHost.mode()` / `citySeed()` (5 → 7, 8)
- `page()` / `recordingStore()` / `forbiddenWrites()` (1, 5 → 6, 7, 8)
