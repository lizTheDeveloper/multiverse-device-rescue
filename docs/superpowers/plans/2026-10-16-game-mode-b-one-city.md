# Game Mode B: One City Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One map holds the person's computer and their accounts. The device districts come from the real scan (Plan A), and Reclaim City's own districts come from the vendored game. Where a check on this computer can confirm a step of one of the game's missions, the step says so. Self-reported progress and confirmed progress are always counted separately.

**Architecture:**
- **What's loaded.** The 48 game files the account screens need are served through `app://rescue/rc/`. They're listed in `desktop/rc-files.json`, and a test proves the list matches the real import graph. `rc/components/hud.js`, which has the payment links, is replaced by a stand-in that draws nothing.
- **How the game code reaches the controller.** `game/rc-load.js` imports the vendored modules into one namespace object, and Plan A's controller receives it. In tests the same function imports the files from disk.
- **Click handling.** The game's own `app.js` isn't loaded, so its click handling is reimplemented as pure functions in `game/rc-actions.js`, with DOM helpers in `game/rc-dom.js`.
- **Confirmation.** `game/verified-missions.js` maps steps of the game's computer missions to Device Rescue modules. `game/one-city.js` produces the honest counts, the cards for the account districts, and where the camera starts.
- **Links.** Links in missions open only through a new `open-mission-link` IPC, against an exact list in `desktop/mission-links.json`. A script generates that file from the vendored data, and a test fails if it's out of date.

**Tech Stack:** Electron 41, plain JS ES modules with no bundler, `node --test` (Node 22). The vendored privacy-the-game is pinned at `317e61c`.

**Spec:** `docs/superpowers/specs/2026-10-16-game-mode-one-city-design.md`. Read its "Changes made during planning" section first, because it overrides parts of the sections below it. This plan builds on `docs/superpowers/plans/2026-10-16-game-mode-a-device-missions.md`, which must be fully done first. Reuse its names exactly.

**Defaults taken for the spec's "Decisions to confirm".** The user may override any of these before execution:
1. "Your computer" is the first ring on the map, and the game's districts follow in chapter order.
2. There's no import from the hosted game. Players start fresh in the app.
3. The confirmation table lives in Device Rescue (`game/verified-missions.js`), and a test catches upstream renames.
4. The phishing quiz and Quick Quests are left to Spec C. Their routes go to the one-city map.

## Global Constraints

Everything in Plan A's Global Constraints still applies, plus:
- **Two kinds of progress, always shown apart:** "Confirmed" means the computer proved it: Plan A's `reclaimed`, plus game missions confirmed by the current scan. "You reported" means the person filed it in the game's debrief and the scan doesn't confirm it now. `yours` is never counted.
- **The person's answer is never overwritten.** Game state (`reclaim-city-state`) changes only through the person's own actions, or through "Finish from the scan", which the person clicks.
- **A step is confirmed only when every one of its modules ran** (`status: "ok"`, `supported: true`) on a platform the step names, and reported no warning or critical finding that matches. A module that's missing, errored or unsupported gives "Couldn't check this one".
- **Links:** only the exact `https://` URLs in `desktop/mission-links.json` open, through `shell.openExternal`. Anything else opens nothing, and the URL is shown as text to copy.
- **Game files:** only the files in `desktop/rc-files.json` are served under `rc/`. `components/hud.js` is always served from `renderer/game/rc-overrides/hud.js`. `utils/analytics.js`, `utils/collective.js`, `utils/restore-send.js`, `utils/notifications.js`, `app.js`, `sw.js` and `index.html` are never served.
- **Storage keys:** `reclaim-city-state` (the vendored `state.js`, in the `app://rescue` origin, separate from the hosted game) and `device-rescue.game.scan-confirmed.v1`.
- **Starting point** (the same mapping as `LEARN_MORE`): `hacked` → `master-keys`, `identity` → `reclamation`, anything else → "Your computer".
- **No share cards, no payment links, no notifications, no analytics calls**, anywhere in game mode.

## Review Focus

1. **A game link to a screen this plan doesn't include** (`#/garage`, `#/timeline`, `#/quiz/phishing`, `#/quickquest`, `#/stats`, `#/city-together`, `#/ghost`, and also `#/city`) must land on the one-city map. It must never leave a blank frame or try to change the page's real hash. Owned by Task 4 (`routeFor` test).
2. **A step link that isn't https, or isn't in the data** (`about:preferences#privacy`, or a look-alike host) must open nothing and must show the URL as text to copy. Owned by Task 3 (allowlist tests) and Task 8 (the controller's refused-link notice, checked by hand).
3. **A confirmed step whose module wasn't in this scan** (for example, the person picked a worry whose profile leaves `find_my_mac_check` out) must say "Couldn't check this one", never "confirmed". Owned by Task 5.
4. **The person filed "Done" and the scan disagrees.** Both must show, and the game state must be byte-for-byte unchanged. Owned by Task 5 (`disagreement` test) and Task 6 (counts test).
5. **A corrupt or blocked `device-rescue.game.scan-confirmed.v1` or `reclaim-city-state`** must rebuild empty without breaking the map. Device progress (`device-rescue.game.v1`) must be untouched. Owned by Task 5 (store test) and Task 2 (the vendored `loadState` with throwing storage).

---

## File Structure

**Desktop main process (CommonJS)**
- Create `desktop/rc-files.json`: the 48 vendored files plus `style.css`, and the HUD override.
- Modify `desktop/app-protocol.js`: `RC_ALLOW` is built from `rc-files.json`, and overrides are served.
- Create `desktop/scripts/build-mission-links.mjs`: `collectMissionLinks(srcDir)`, and it writes the JSON.
- Create `desktop/mission-links.json` (generated) and `desktop/mission-links.js` (`isAllowedMissionLink`).
- Modify `desktop/main.js` and `desktop/preload.js`: `open-mission-link` and `openMissionLink`.
- Modify `desktop/package.json`: `build.files`.

**Renderer, game mode (ES modules)**
- `game/rc-overrides/hud.js`: the HUD stand-in that draws nothing.
- `game/rc-load.js`: `RC_ENTRY_FILES`, `loadRc(importFile)`.
- `game/rc-actions.js`: `SUPPORTED_RC_SCREENS`, `routeFor`, `applyRcAction`, `fileRc`, `afterRecorded`.
- `game/rc-dom.js`: `readAnswers`, `refreshDebriefForm`.
- `game/verified-missions.js`: `VERIFIED_MISSIONS`, `stepStatus`, `verifyMission`, `disagreement`, plus the store functions.
- `game/one-city.js`: `focusFor`, `accountDistrictCards`, `countConfirmedAndReported`, `deviceMissionFor`.
- `game/views/one-city-map.js`: `renderOneCityMap`.
- `game/views/verification.js`: `renderVerification`, `renderMilestoneSplit`.
- Modify `game/views/hud.js` (an optional `counts`), `game/controller.js` (account mode) and `game/game.css`.

**Tests (`desktop/test/`)**
- `rc-import-graph.test.js`, `mission-links.test.js`, `game-rc-actions.test.js`, `game-rc-dom.test.js`, `game-verified-missions.test.js`, `game-one-city.test.js`
- Extended: `app-protocol.test.js`, `game-vendor-contract.test.js`, `game-views.test.js`

**Docs**
- Modify `desktop/MANUAL-QA.md` and `README.md`.

---

### Task 1: Serve exactly the game files the account screens need, minus the payment links

**Files:**
- Create: `desktop/rc-files.json`, `desktop/renderer/game/rc-overrides/hud.js`
- Modify: `desktop/app-protocol.js` (the `RC_ALLOW` const and the `rc` branch of `resolveAppPath`)
- Modify: `desktop/package.json` (`build.files`)
- Test: `desktop/test/rc-import-graph.test.js`, `desktop/test/app-protocol.test.js` (amend)

**Interfaces:**
- Consumes: Plan A's `resolveAppPath(url, baseDir)` and `RC_ALLOW`.
- Produces:
  - `rc-files.json` = `{ files: string[], overrides: {[vendorPath]: rendererPath} }`
  - `app-protocol.js` exports `RC_FILES: Set<string>` and `RC_OVERRIDES` in addition to Plan A's exports.
  - `rc-load.js`'s `RC_ENTRY_FILES` is created in Task 2. The graph test here uses its own copy of the entry list, and Task 2 switches it to the import.

- [ ] **Step 1: Write the failing import-graph test**

Create `desktop/test/rc-import-graph.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const RC = require('../rc-files.json');
const { resolveAppPath, APP_ORIGIN } = require('../app-protocol');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const BASE = path.join(__dirname, '..');
// What game mode imports from the game (the same list as rc-load.js RC_ENTRY_FILES).
const ENTRIES = ['screens/district.js', 'screens/briefing.js', 'screens/debrief.js', 'screens/milestone.js',
  'state.js', 'data/missions.js', 'data/accounts.js', 'data/districts.js', 'utils/debrief.js',
  'utils/bursts.js', 'utils/pm-categories.js', 'utils/scout-feelings.js', 'utils/mission-status.js',
  'utils/calc.js', 'router.js', 'utils/keyboard.js', 'components/scout.js'];
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\b[^;'"`]*?\bfrom\s*['"]([^'"]+)['"]/g;
const BARE_RE = /(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g;

function walk(entries) {
  const seen = new Set();
  const queue = [...entries];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    const text = fs.readFileSync(path.join(SRC, rel), 'utf8');
    for (const re of [IMPORT_RE, BARE_RE]) {
      for (const m of text.matchAll(re)) queue.push(path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1])));
    }
  }
  return [...seen].sort();
}

const reachable = walk(ENTRIES);
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

test('rc-files.json is exactly the reachable graph plus the stylesheet', () => {
  assert.deepStrictEqual([...RC.files].sort(), [...reachable, 'style.css'].sort());
});

test('nothing reachable talks to the network or loads code at runtime', () => {
  for (const rel of reachable) {
    const text = read(rel);
    assert.doesNotMatch(text, /\bfetch\s*\(|sendBeacon|XMLHttpRequest|WebSocket|new Image\(/, rel);
    assert.doesNotMatch(text, /\bimport\(/, `${rel} uses dynamic import`);
  }
});

test('Sentry is only touched by utils/errors.js, behind a typeof guard', () => {
  for (const rel of reachable) {
    if (rel === 'utils/errors.js') continue;
    assert.doesNotMatch(read(rel), /Sentry/, rel);
  }
  assert.match(read('utils/errors.js'), /typeof Sentry === 'undefined'/);
});

test('payment links live only in the HUD, and the HUD is always replaced', () => {
  for (const rel of reachable) {
    if (rel === 'components/hud.js') continue;
    assert.doesNotMatch(read(rel), /buy\.stripe\.com|patreon\.com/, rel);
  }
  assert.strictEqual(RC.overrides['components/hud.js'], 'game/rc-overrides/hud.js');
  const served = resolveAppPath(`${APP_ORIGIN}rc/components/hud.js`, BASE);
  assert.strictEqual(served.file, path.join(BASE, 'renderer', 'game', 'rc-overrides', 'hud.js'));
});

test('the HUD stand-in exports everything the real HUD does', async () => {
  const real = await import(path.join(SRC, 'components', 'hud.js'));
  const stand = await import(path.join(BASE, 'renderer', 'game', 'rc-overrides', 'hud.js'));
  assert.deepStrictEqual(Object.keys(stand).sort(), Object.keys(real).sort());
  assert.strictEqual(stand.renderHud({}), '');
});

test('the never-load list stays unserved', () => {
  for (const rel of ['utils/analytics.js', 'utils/collective.js', 'utils/restore-send.js', 'utils/notifications.js', 'app.js', 'sw.js', 'index.html']) {
    assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/${rel}`, BASE), null, rel);
    assert.ok(!RC.files.includes(rel), rel);
  }
});
```

In `desktop/test/app-protocol.test.js` (from Plan A), replace the `'rc/ serves only the allowlisted game sources'` test with:

```js
test('rc/ serves only the files in rc-files.json', () => {
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/components/scout.js`, BASE).file, V('components/scout.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/screens/district.js`, BASE).file, V('screens/district.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/style.css`, BASE).mime, 'text/css; charset=utf-8');
  // errors.js is reachable through state.js; it is inert without the Sentry global.
  assert.ok(resolveAppPath(`${APP_ORIGIN}rc/utils/errors.js`, BASE));
  for (const p of ['rc/app.js', 'rc/index.html', 'rc/sw.js', 'rc/utils/analytics.js', 'rc/utils/collective.js', 'rc/screens/ghost.js', 'rc/data/phishing.js']) {
    assert.strictEqual(resolveAppPath(`${APP_ORIGIN}${p}`, BASE), null, p);
  }
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/rc-import-graph.test.js test/app-protocol.test.js`
Expected: FAIL with `Cannot find module '../rc-files.json'`.

- [ ] **Step 3: Create `desktop/rc-files.json`**

```json
{
  "files": [
    "components/building.js", "components/hud.js", "components/password-progress.js", "components/scout.js",
    "data/accounts-clinic.js", "data/accounts-foundry.js", "data/accounts-freeway.js", "data/accounts-grid.js",
    "data/accounts-perimeter.js", "data/accounts-reclamation.js", "data/accounts-sam-additions.js",
    "data/accounts-trail.js", "data/accounts-vault-capitol-additions.js", "data/accounts.js",
    "data/dialogue.js", "data/districts.js",
    "data/missions-clinic.js", "data/missions-foundry.js", "data/missions-freeway.js", "data/missions-grid.js",
    "data/missions-osint-sieve.js", "data/missions-passwords.js", "data/missions-perimeter.js",
    "data/missions-reclamation.js", "data/missions-recon-accounts.js",
    "data/missions-square-archives-marketplace.js", "data/missions-trail.js", "data/missions-vault-capitol.js",
    "data/missions.js",
    "router.js",
    "screens/briefing.js", "screens/debrief.js", "screens/district.js", "screens/milestone.js",
    "state.js",
    "utils/bursts.js", "utils/calc.js", "utils/debrief.js", "utils/errorNoise.js", "utils/errors.js",
    "utils/keyboard.js", "utils/migrate-answers.js", "utils/mission-status.js", "utils/password-need.js",
    "utils/pm-categories.js", "utils/pm-numbers.js", "utils/scout-feelings.js", "utils/two-factor.js",
    "style.css"
  ],
  "overrides": { "components/hud.js": "game/rc-overrides/hud.js" }
}
```

- [ ] **Step 4: Create the HUD stand-in**

`desktop/renderer/game/rc-overrides/hud.js`:

```js
// Stands in for Reclaim City's components/hud.js inside Device Rescue. Every game
// screen draws the game's HUD at the top, and that HUD carries the game's
// payment links. Device Rescue draws its own HUD (the two counts) above the
// screen instead, so this one draws nothing. app-protocol.js serves this file at
// rc/components/hud.js; rc-files.json says so.
export function renderHud() {
  return '';
}
```

- [ ] **Step 5: Change `desktop/app-protocol.js`**

Replace Plan A's `RC_ALLOW` line with:

```js
const RC = require('./rc-files.json');
// Game sources game mode may load: exactly the files in rc-files.json, which a
// test keeps equal to the real import graph. Overrides are served from renderer/.
const RC_FILES = new Set(RC.files);
const RC_OVERRIDES = RC.overrides || {};
const RC_ALLOW = [...RC_FILES].map((f) => new RegExp(`^${f.replace(/[.]/g, '\\.')}$`));
```

Replace the `rc` branch of `resolveAppPath` with:

```js
  } else if (parts[0] === 'rc') {
    const inner = parts.slice(1).join('/');
    if (!RC_FILES.has(inner)) return null;
    if (RC_OVERRIDES[inner]) {
      root = path.join(baseDir, 'renderer');
      file = path.join(root, RC_OVERRIDES[inner]);
    } else {
      root = vendorSrc;
      file = path.join(vendorSrc, inner);
    }
```

Change the exports to `module.exports = { APP_ORIGIN, RC_ALLOW, RC_FILES, RC_OVERRIDES, MIME, resolveAppPath, serveApp };`.

- [ ] **Step 6: Package the files**

In `desktop/package.json` `build.files`, replace Plan A's `"vendor/reclaim-city/src/components/scout.js"` entry with these lines. The protocol still serves only the listed files.

```json
      "rc-files.json",
      "vendor/reclaim-city/src/components/**",
      "vendor/reclaim-city/src/data/**",
      "vendor/reclaim-city/src/screens/**",
      "vendor/reclaim-city/src/utils/**",
      "vendor/reclaim-city/src/state.js",
      "vendor/reclaim-city/src/router.js",
```

- [ ] **Step 7: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add desktop/rc-files.json desktop/renderer/game/rc-overrides/hud.js desktop/app-protocol.js desktop/package.json desktop/test/rc-import-graph.test.js desktop/test/app-protocol.test.js
git commit -m "Serve the game's account screens, exactly the files they import, without its payment links"
```

---

### Task 2: Load the game's modules as one namespace (`rc-load.js`)

**Files:**
- Create: `desktop/renderer/game/rc-load.js`
- Modify: `desktop/test/rc-import-graph.test.js` (use `RC_ENTRY_FILES`)
- Test: `desktop/test/game-vendor-contract.test.js` (extend)

**Interfaces:**
- Produces:
  - `RC_ENTRY_FILES: string[]`
  - `loadRc(importFile = (rel) => import('../rc/' + rel)) -> Promise<Rc>`. `Rc` is a plain object with these members (the exact names later tasks use): `renderDistrict, renderBriefing, renderDebrief, debriefReaction, renderMilestone, loadState, saveState, createInitialState, markMissionStarted, toggleAccount, updateStreak, streakAfterFiling, MISSIONS, missionDistrict, ACCOUNTS, DISTRICTS, fileDebrief, recordNotNeeded, visibleQuestions, ensureBurst, startBurst, applyCategoryAction, noteFirstTwoFactor, markTwoFactorHugSeen, isMissionDone, DONE_STATUSES, calcDistrictProgress, parseRoute, keyActivationTarget, newScreenVisit`.

- [ ] **Step 1: Write the failing tests**

Add to `desktop/test/game-vendor-contract.test.js`:

```js
const { pathToFileURL } = require('url');
const fromDisk = (rel) => import(pathToFileURL(path.join(SRC, rel)).href);
const loadRcFromDisk = async () => (await import('../renderer/game/rc-load.js')).loadRc(fromDisk);

test('loadRc gives every name game mode uses', async () => {
  const rc = await loadRcFromDisk();
  for (const name of ['renderDistrict', 'renderBriefing', 'renderDebrief', 'debriefReaction', 'renderMilestone',
    'loadState', 'saveState', 'createInitialState', 'markMissionStarted', 'toggleAccount', 'updateStreak',
    'streakAfterFiling', 'missionDistrict', 'fileDebrief', 'recordNotNeeded', 'visibleQuestions', 'ensureBurst',
    'startBurst', 'applyCategoryAction', 'noteFirstTwoFactor', 'markTwoFactorHugSeen', 'isMissionDone',
    'calcDistrictProgress', 'parseRoute', 'keyActivationTarget', 'newScreenVisit']) {
    assert.strictEqual(typeof rc[name], 'function', name);
  }
  assert.ok(Array.isArray(rc.MISSIONS) && rc.MISSIONS.length > 100);
  assert.ok(Array.isArray(rc.DISTRICTS) && rc.DISTRICTS.some((d) => d.type === 'facility'));
  assert.ok(rc.ACCOUNTS.gmail);
  assert.ok(rc.DONE_STATUSES.has('completed'));
});

test('the account screens render in Node for a real account and a facility district', async () => {
  const rc = await loadRcFromDisk();
  const st = rc.createInitialState();
  const district = rc.renderDistrict(st, 'master-keys');
  assert.match(district, /data-action="toggle-account"/);
  assert.ok(rc.renderDistrict(st, 'perimeter').length > 1000);
  assert.match(rc.renderBriefing(st, 'gmail-recon-breach'), /data-action="go-do-it"/);
  assert.match(rc.renderDebrief(st, 'device_security-fortify-computer'), /data-action="submit-debrief"/);
  assert.ok(rc.renderMilestone(st, 'master-keys').length > 1000);
});

test('loadState rebuilds from defaults when storage throws or holds junk', async () => {
  const rc = await loadRcFromDisk();
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.ok(rc.loadState(throwing).accounts.gmail);
  assert.ok(rc.loadState({ getItem: () => '{not json' }).accounts.gmail);
  assert.doesNotThrow(() => rc.saveState(rc.createInitialState(), throwing));
});

test('every account building is served through app://rescue/assets/ and exists', async () => {
  const { resolveAppPath, APP_ORIGIN } = require('../app-protocol');
  const rc = await loadRcFromDisk();
  const paths = new Set(Object.values(rc.ACCOUNTS).flatMap((a) => [a.building, a.buildingDark]).filter(Boolean));
  assert.ok(paths.size > 50);
  for (const p of paths) {
    const hit = resolveAppPath(`${APP_ORIGIN}${p}`, path.join(__dirname, '..'));
    assert.ok(hit, `not served: ${p}`);
    assert.ok(fs.existsSync(hit.file), `missing on disk: ${p}`);
  }
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-vendor-contract.test.js`
Expected: FAIL with `Cannot find module '../renderer/game/rc-load.js'`.

- [ ] **Step 3: Write `desktop/renderer/game/rc-load.js`**

```js
// Loads the parts of Reclaim City that game mode uses, as one object, so the
// rest of game mode can take it as a plain argument (and tests can load the
// same files from disk). In the app the files come from app://rescue/rc/.
const FILES = {
  district: 'screens/district.js', briefing: 'screens/briefing.js', debrief: 'screens/debrief.js',
  milestone: 'screens/milestone.js', state: 'state.js', missions: 'data/missions.js',
  accounts: 'data/accounts.js', districts: 'data/districts.js', debriefUtil: 'utils/debrief.js',
  bursts: 'utils/bursts.js', pmCategories: 'utils/pm-categories.js', feelings: 'utils/scout-feelings.js',
  status: 'utils/mission-status.js', calc: 'utils/calc.js', router: 'router.js',
  keyboard: 'utils/keyboard.js', scout: 'components/scout.js',
};
export const RC_ENTRY_FILES = Object.values(FILES);

export async function loadRc(importFile = (rel) => import(`../rc/${rel}`)) {
  const entries = await Promise.all(Object.entries(FILES).map(async ([k, rel]) => [k, await importFile(rel)]));
  const m = Object.fromEntries(entries);
  return {
    renderDistrict: m.district.renderDistrict,
    renderBriefing: m.briefing.renderBriefing,
    renderDebrief: m.debrief.renderDebrief,
    debriefReaction: m.debrief.debriefReaction,
    renderMilestone: m.milestone.renderMilestone,
    loadState: m.state.loadState,
    saveState: m.state.saveState,
    createInitialState: m.state.createInitialState,
    markMissionStarted: m.state.markMissionStarted,
    toggleAccount: m.state.toggleAccount,
    updateStreak: m.state.updateStreak,
    streakAfterFiling: m.state.streakAfterFiling,
    MISSIONS: m.missions.MISSIONS,
    missionDistrict: m.missions.missionDistrict,
    ACCOUNTS: m.accounts.ACCOUNTS,
    DISTRICTS: m.districts.DISTRICTS,
    fileDebrief: m.debriefUtil.fileDebrief,
    recordNotNeeded: m.debriefUtil.recordNotNeeded,
    visibleQuestions: m.debriefUtil.visibleQuestions,
    ensureBurst: m.bursts.ensureBurst,
    startBurst: m.bursts.startBurst,
    applyCategoryAction: m.pmCategories.applyCategoryAction,
    noteFirstTwoFactor: m.feelings.noteFirstTwoFactor,
    markTwoFactorHugSeen: m.feelings.markTwoFactorHugSeen,
    isMissionDone: m.status.isMissionDone,
    DONE_STATUSES: m.status.DONE_STATUSES,
    calcDistrictProgress: m.calc.calcDistrictProgress,
    parseRoute: m.router.parseRoute,
    keyActivationTarget: m.keyboard.keyActivationTarget,
    newScreenVisit: m.scout.newScreenVisit,
  };
}
```

`import(`../rc/${rel}`)` resolves against `rc-load.js`'s URL, `app://rescue/game/rc-load.js`, so it becomes `app://rescue/rc/<rel>`.

- [ ] **Step 4: Make the graph test use the single list**

In `desktop/test/rc-import-graph.test.js`, replace the `ENTRIES` constant and the `reachable` line with the following. Each test that reads `reachable` must then begin with `const reachable = await reachableP;` and become `async`.

```js
let ENTRIES;
const reachableP = import('../renderer/game/rc-load.js').then((m) => { ENTRIES = m.RC_ENTRY_FILES; return walk(ENTRIES); });
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/rc-load.js desktop/test/game-vendor-contract.test.js desktop/test/rc-import-graph.test.js
git commit -m "Load Reclaim City's account screens and data as one namespace"
```

---

### Task 3: Open mission links from an exact list (`open-mission-link`)

**Files:**
- Create: `desktop/scripts/build-mission-links.mjs`, `desktop/mission-links.json` (generated), `desktop/mission-links.js`
- Modify: `desktop/main.js` (a new handler next to `open-guide`), `desktop/preload.js`, `desktop/package.json` (`build.files`)
- Test: `desktop/test/mission-links.test.js`

**Interfaces:**
- Produces:
  - `collectMissionLinks(srcDir) -> Promise<string[]>`: sorted, unique, `https://` only.
  - `isAllowedMissionLink(url) -> boolean`
  - IPC `open-mission-link` resolves `true` if the link opened and `false` if it was refused.
  - Preload: `window.rescue.openMissionLink(url)`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/mission-links.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { isAllowedMissionLink } = require('../mission-links');
const { links } = require('../mission-links.json');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');

test('mission-links.json is current (run: node desktop/scripts/build-mission-links.mjs)', async () => {
  const { collectMissionLinks } = await import('../scripts/build-mission-links.mjs');
  assert.deepStrictEqual(links, await collectMissionLinks(SRC));
});

test('every link is https, and there are plenty of them', () => {
  assert.ok(links.length > 100);
  for (const l of links) assert.ok(l.startsWith('https://'), l);
});

test('an exact link from the game is allowed', () => {
  assert.strictEqual(isAllowedMissionLink(links[0]), true);
  assert.strictEqual(isAllowedMissionLink(links[links.length - 1]), true);
});

test('anything else is refused', () => {
  const l = links[0];
  for (const url of [
    `${l}x`, `${l}/extra`, `${l}${l.includes('?') ? '&' : '?'}a=1`, ` ${l}`, `${l} `,
    l.replace('https://', 'http://'), l.replace('https://', 'https://evil.example/?'),
    l.replace(/^https:\/\/([^/]+)/, 'https://$1.evil.example'),
    'about:preferences#privacy', 'javascript:alert(1)', 'file:///etc/passwd', '', null, undefined, 42, {},
  ]) {
    assert.strictEqual(isAllowedMissionLink(url), false, String(url));
  }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/mission-links.test.js`
Expected: FAIL with `Cannot find module '../mission-links'`.

- [ ] **Step 3: Write the generator**

`desktop/scripts/build-mission-links.mjs`:

```js
// Writes desktop/mission-links.json: every https link in Reclaim City's
// missions (any "url" field, at any depth, so stepsByManager and reportSteps
// count too) and every account's securityUrl. The main process opens exactly
// these and nothing else. Re-run after bumping the game submodule; a test fails
// if the file is out of date.
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SRC = path.join(here, '..', 'vendor', 'reclaim-city', 'src');

export async function collectMissionLinks(srcDir = DEFAULT_SRC) {
  const load = (rel) => import(pathToFileURL(path.join(srcDir, rel)).href);
  const [{ MISSIONS }, { ACCOUNTS }] = await Promise.all([load('data/missions.js'), load('data/accounts.js')]);
  const out = new Set();
  const walk = (v) => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (!v || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      if (k === 'url' && typeof x === 'string') out.add(x);
      else walk(x);
    }
  };
  walk(MISSIONS);
  for (const a of Object.values(ACCOUNTS)) if (typeof a.securityUrl === 'string') out.add(a.securityUrl);
  return [...out].filter((u) => u.startsWith('https://')).sort();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const links = await collectMissionLinks();
  writeFileSync(path.join(here, '..', 'mission-links.json'), `${JSON.stringify({ links }, null, 2)}\n`);
  console.log(`wrote ${links.length} links`);
}
```

Run it: `node desktop/scripts/build-mission-links.mjs`
Expected: `wrote 178 links` (178 at `317e61c`).

- [ ] **Step 4: Write `desktop/mission-links.js`**

```js
// Allowlist for the 'open-mission-link' IPC channel: exact URLs from the
// vendored game's own mission data (mission-links.json, generated). Matching is
// exact string equality, so look-alike hosts, extra paths and added queries
// never match, and nothing is rewritten first.
const { links } = require('./mission-links.json');

const ALLOWED = new Set(links.filter((l) => typeof l === 'string' && l.startsWith('https://')));

function isAllowedMissionLink(url) {
  return typeof url === 'string' && ALLOWED.has(url);
}

module.exports = { isAllowedMissionLink };
```

- [ ] **Step 5: Wire up the IPC**

In `main.js`, add `const { isAllowedMissionLink } = require('./mission-links');`, and add this after the `open-guide` handler:

```js
  // A link inside a Reclaim City mission (an account's security page). Only the
  // exact links in the game's own data open; the renderer shows anything else as
  // text to copy.
  ipcMain.handle('open-mission-link', (_e, url) => {
    if (!isAllowedMissionLink(url)) return false;
    shell.openExternal(url);
    return true;
  });
```

In `preload.js`, add this after `openGuide`:

```js
  openMissionLink: (url) => ipcRenderer.invoke('open-mission-link', url),
```

In `package.json` `build.files`, add `"mission-links.js"` and `"mission-links.json"`.

- [ ] **Step 6: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add desktop/scripts/build-mission-links.mjs desktop/mission-links.json desktop/mission-links.js desktop/main.js desktop/preload.js desktop/package.json desktop/test/mission-links.test.js
git commit -m "Open Reclaim City's mission links only from an exact list"
```

---

### Task 4: The game's click actions and routes, without its `app.js` (`rc-actions.js`)

**Files:**
- Create: `desktop/renderer/game/rc-actions.js`
- Test: `desktop/test/game-rc-actions.test.js`

**Interfaces:**
- Consumes: `Rc` from Task 2.
- Produces:
  - `SUPPORTED_RC_SCREENS = new Set(['district', 'briefing', 'debrief', 'milestone'])`
  - `routeFor(hash, parseRoute) -> {screen, params}`. `screen` is one of the supported screens, or `'map'`.
  - `applyRcAction(rc, state, action, data) -> RcResult`
  - `fileRc(rc, state, missionId, answers) -> RcResult`
  - `afterRecorded(rc, state, mission) -> RcResult`
  - `RcResult = { state, route?: string, open?: string, ui?: {resetAnyway?: string}, incomplete?: true, reaction?: {districtId, reaction} }`
  - `data` is the clicked element's `dataset`, plus `href` (for `mission-step`), `raw` (pm-category number) and `name` (custom account). The controller fills those in.
  - Nothing here mutates `state`, and nothing here touches the DOM.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-rc-actions.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const setup = async () => {
  const rc = await (await import('../renderer/game/rc-load.js')).loadRc((rel) => import(pathToFileURL(path.join(SRC, rel)).href));
  const a = await import('../renderer/game/rc-actions.js');
  return { rc, ...a };
};
const snapshot = (s) => JSON.stringify(s);

test('routes this plan supports pass through; everything else goes to the map', async () => {
  const { rc, routeFor } = await setup();
  assert.deepStrictEqual(routeFor('#/district/master-keys?tab=fortify', rc.parseRoute), { screen: 'district', params: { id: 'master-keys', tab: 'fortify' } });
  assert.strictEqual(routeFor('#/mission/gmail-recon-breach/briefing', rc.parseRoute).screen, 'briefing');
  assert.strictEqual(routeFor('#/mission/gmail-recon-breach/debrief', rc.parseRoute).screen, 'debrief');
  assert.strictEqual(routeFor('#/milestone/vault', rc.parseRoute).screen, 'milestone');
  for (const h of ['#/city', '#/garage', '#/timeline', '#/quiz/phishing', '#/quickquest', '#/stats', '#/city-together', '#/ghost', '#/ghost/done', '#/nope', '', null]) {
    assert.deepStrictEqual(routeFor(h, rc.parseRoute), { screen: 'map', params: {} }, String(h));
  }
});

test('go-do-it remembers the start, opens only https, and goes to the debrief', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const before = snapshot(st);
  const r = applyRcAction(rc, st, 'go-do-it', { mission: 'gmail-recon-breach', url: 'https://haveibeenpwned.com/' });
  assert.ok(r.state.startedMissions['gmail-recon-breach']);
  assert.strictEqual(r.open, 'https://haveibeenpwned.com/');
  assert.strictEqual(r.route, '#/mission/gmail-recon-breach/debrief');
  assert.strictEqual(snapshot(st), before, 'input state not mutated');
  assert.strictEqual(applyRcAction(rc, st, 'go-do-it', { mission: 'gmail-recon-breach', url: '#' }).open, undefined);
  assert.strictEqual(applyRcAction(rc, st, 'go-do-it', { mission: 'x', url: 'javascript:alert(1)' }).open, undefined);
});

test('mission-step remembers the start and opens its link; i-did-it goes to the debrief', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const r = applyRcAction(rc, st, 'mission-step', { mission: 'gmail-recon-breach', href: 'https://example.org/a' });
  assert.ok(r.state.startedMissions['gmail-recon-breach']);
  assert.strictEqual(r.open, 'https://example.org/a');
  assert.strictEqual(r.route, undefined);
  assert.strictEqual(applyRcAction(rc, st, 'i-did-it', { mission: 'gmail-recon-breach' }).route, '#/mission/gmail-recon-breach/debrief');
});

test('the survey toggle, intro, password manager and custom accounts change state without mutating it', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  const before = snapshot(st);
  const was = st.accounts.gmail.enabled;
  assert.strictEqual(applyRcAction(rc, st, 'toggle-account', { account: 'gmail' }).state.accounts.gmail.enabled, !was);
  assert.strictEqual(applyRcAction(rc, st, 'toggle-account', { account: 'nope' }).state, st);
  assert.strictEqual(applyRcAction(rc, st, 'dismiss-intro', { district: 'vault' }).state.seenIntros.vault, true);
  assert.strictEqual(applyRcAction(rc, st, 'set-password-manager', { pm: 'bitwarden' }).state.passwordManager, 'bitwarden');
  const added = applyRcAction(rc, st, 'add-custom-account', { district: 'vault', name: '  Credit Union  ' }).state;
  assert.deepStrictEqual(added.customAccounts.vault, ['Credit Union']);
  assert.strictEqual(applyRcAction(rc, st, 'add-custom-account', { district: 'vault', name: '   ' }).state, st);
  const removed = applyRcAction(rc, added, 'remove-custom-account', { district: 'vault', index: '0' }).state;
  assert.deepStrictEqual(removed.customAccounts.vault, []);
  assert.deepStrictEqual(added.customAccounts.vault, ['Credit Union'], 'remove does not mutate');
  assert.strictEqual(snapshot(st), before);
});

test('reset-anyway is a view flag; share-card and unknown actions change nothing', async () => {
  const { rc, applyRcAction } = await setup();
  const st = rc.createInitialState();
  assert.deepStrictEqual(applyRcAction(rc, st, 'reset-anyway', { mission: 'gmail-fortify-password' }).ui, { resetAnyway: 'gmail-fortify-password' });
  for (const action of ['share-card', 'share-stat', 'toggle-analytics', 'go-ghost', 'begin-game', 'whatever']) {
    const r = applyRcAction(rc, st, action, {});
    assert.strictEqual(r.state, st, action);
    assert.strictEqual(r.route, undefined, action);
    assert.strictEqual(r.open, undefined, action);
  }
});

test('filing a debrief records it and lands on the district tab', async () => {
  const { rc, fileRc } = await setup();
  const st = rc.createInitialState();
  const r = fileRc(rc, st, 'device_security-fortify-computer', { action: 'completed' });
  assert.strictEqual(r.state.missions['device_security-fortify-computer'].status, 'completed');
  assert.ok(r.state.missions['device_security-fortify-computer'].completedAt);
  assert.strictEqual(r.route, '#/district/perimeter?tab=fortify');
  assert.strictEqual(st.missions['device_security-fortify-computer'], undefined, 'input not mutated');
});

test('an incomplete debrief files nothing; an unknown mission goes to the map', async () => {
  const { rc, fileRc } = await setup();
  const st = rc.createInitialState();
  const r = fileRc(rc, st, 'device_security-fortify-computer', {});
  assert.strictEqual(r.incomplete, true);
  assert.strictEqual(r.state, st);
  assert.strictEqual(fileRc(rc, st, 'no-such-mission', {}).route, '#/city');
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-rc-actions.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write `desktop/renderer/game/rc-actions.js`**

```js
// Reclaim City's click actions, re-done for Device Rescue. The game's own app.js
// (which also sends analytics, asks for notifications and talks to its server)
// is never loaded, so this is the part of it game mode needs, as pure functions:
// they take the game state and return the next one, plus where to go and what
// link to open. Nothing here is tracked or sent anywhere.
export const SUPPORTED_RC_SCREENS = new Set(['district', 'briefing', 'debrief', 'milestone']);
const MAP = { screen: 'map', params: {} };
const PM_KIND = { 'pm-cat-flag': 'flag', 'pm-cat-changed': 'changed', 'pm-cat-none': 'clear', 'pm-cat-clear': 'clear', 'pm-cat-reopen': 'reopen' };
const httpsOnly = (u) => (typeof u === 'string' && u.startsWith('https://') ? u : undefined);

export function routeFor(hash, parseRoute) {
  if (typeof hash !== 'string' || !hash.startsWith('#/')) return MAP;
  const r = parseRoute(hash);
  return SUPPORTED_RC_SCREENS.has(r.screen) ? r : MAP;
}

export function afterRecorded(rc, state, mission) {
  const districtId = rc.missionDistrict(mission);
  const wasComplete = Boolean(state.seenProgress?.[districtId]?.includes(100));
  const reaction = rc.debriefReaction(state, mission);
  const progress = rc.calcDistrictProgress(state, districtId);
  let next = state;
  if (districtId && rc.isMissionDone(state.missions[mission.id])) {
    const seen = new Set(state.seenProgress?.[districtId] || []);
    for (const m of [25, 50, 75, 100]) if (progress.percent >= m) seen.add(m);
    next = { ...state, seenProgress: { ...state.seenProgress, [districtId]: [...seen].sort((a, b) => a - b) } };
  }
  if (progress.total > 0 && progress.percent === 100 && !wasComplete) {
    return { state: next, route: `#/milestone/${districtId}` };
  }
  return {
    state: next,
    route: `#/district/${districtId}${mission.phase ? `?tab=${mission.phase}` : ''}`,
    reaction: reaction ? { districtId, reaction } : null,
  };
}

export function fileRc(rc, state, missionId, answers) {
  const mission = rc.MISSIONS.find((m) => m.id === missionId);
  if (!mission) return { state, route: '#/city' };
  const filed = rc.fileDebrief(state, mission, answers);
  if (!filed) return { state, incomplete: true };
  const next = rc.ensureBurst(rc.streakAfterFiling(
    rc.noteFirstTwoFactor(filed.state, mission, filed.state.missions[missionId]), filed.event));
  return afterRecorded(rc, next, mission);
}

export function applyRcAction(rc, state, action, data = {}) {
  const id = data.mission;
  switch (action) {
    case 'go-do-it':
      return { state: rc.markMissionStarted(state, id), open: httpsOnly(data.url), route: `#/mission/${id}/debrief` };
    case 'i-did-it':
      return { state, route: `#/mission/${id}/debrief` };
    case 'mission-step':
      return { state: rc.markMissionStarted(state, id), open: httpsOnly(data.href) };
    case 'password-not-needed': {
      const mission = rc.MISSIONS.find((m) => m.id === id);
      const next = mission ? rc.recordNotNeeded(state, id) : state;
      if (next === state) return { state };
      return afterRecorded(rc, rc.ensureBurst(rc.updateStreak(next)), mission);
    }
    case 'reset-anyway':
      return { state, ui: { resetAnyway: id } };
    case 'line-up-burst':
      return { state: rc.startBurst(state) };
    case 'set-password-manager':
      return { state: { ...state, passwordManager: data.pm } };
    case 'toggle-account': {
      const acct = state.accounts && state.accounts[data.account];
      if (!acct) return { state };
      return { state: rc.toggleAccount(state, data.account, !acct.enabled) };
    }
    case 'add-custom-account': {
      const name = typeof data.name === 'string' ? data.name.trim() : '';
      if (!name) return { state };
      const list = [...(state.customAccounts?.[data.district] || []), name];
      return { state: { ...state, customAccounts: { ...state.customAccounts, [data.district]: list } } };
    }
    case 'remove-custom-account': {
      const list = state.customAccounts?.[data.district];
      const i = Number(data.index);
      if (!list || !Number.isInteger(i) || i < 0 || i >= list.length) return { state };
      return { state: { ...state, customAccounts: { ...state.customAccounts, [data.district]: list.filter((_, j) => j !== i) } } };
    }
    case 'dismiss-intro':
      return { state: { ...state, seenIntros: { ...state.seenIntros, [data.district]: true } } };
    default:
      if (PM_KIND[action]) {
        const next = rc.applyCategoryAction(state, data.district, PM_KIND[action], data.raw);
        return { state: next };
      }
      return { state }; // share-card and every action game mode doesn't include
  }
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-rc-actions.test.js`
Expected: PASS (7 tests). If `routeFor('#/district/master-keys?tab=fortify')` deep-equals with `tab` present but other keys differ, use the shape `parseRoute` actually returns, `{id, tab}`, and keep the assertion on those two keys.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/rc-actions.js desktop/test/game-rc-actions.test.js
git commit -m "Handle Reclaim City's mission actions and routes without its app.js"
```

---

### Task 5: Steps the computer can confirm (`verified-missions.js`)

**Files:**
- Create: `desktop/renderer/game/verified-missions.js`
- Test: `desktop/test/game-verified-missions.test.js`

**Interfaces:**
- Consumes: scan JSON (Plan A Task 1 shape, with `platform`), and game mission records (`{status, completedAt, ...}`).
- Produces:
  - `VERIFIED_MISSIONS: {[missionId]: Array<{step: number, platforms: string[], modules: string[], dataCheck?: string, claim: string}>}`
  - `stepStatus(doc, row) -> 'confirmed'|'problem'|'couldnt'|'other-platform'`
  - `problemFindings(doc, row) -> Finding[]`, with `module` set on each.
  - `verifyMission(missionId, doc) -> null | {steps: Array<{step, status, claim, problems, modules}>, allConfirmed: boolean}`
  - `disagreement(record, verification) -> null | {reportedAt: string|null, problems: Finding[]}`
  - `SCAN_CONFIRMED_KEY = 'device-rescue.game.scan-confirmed.v1'`
  - `loadScanConfirmed(storage) -> {version: 1, missions: {[id]: {at}}}`, `saveScanConfirmed(storage, store) -> boolean`, `markScanConfirmed(store, id, now) -> store`
  - `DONE = new Set(['completed', 'not-needed'])`. It must equal the vendored `DONE_STATUSES`, which the test checks.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-verified-missions.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const load = () => import('../renderer/game/verified-missions.js');
const ok = (name, findings = []) => ({ name, status: 'ok', supported: true, findings });
const mac = (...modules) => ({ platform: 'darwin', modules });
const warn = (extra = {}) => ({ title: 'x', severity: 'warning', data: {}, ...extra });
const FC = 'device_security-fortify-computer';
const ROUTER = 'smart_network-recon-router';

function moduleDir(name) {
  for (const cat of fs.readdirSync(path.join(ROOT, 'modules'))) {
    const p = path.join(ROOT, 'modules', cat, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

test('every row names a real game mission step, a real module, and platforms that module runs on', async () => {
  const { VERIFIED_MISSIONS } = await load();
  const { MISSIONS } = await import(pathToFileURL(path.join(SRC, 'data', 'missions.js')).href);
  const PLAT = { darwin: 'DARWIN', win32: 'WIN32', linux: 'LINUX' };
  for (const [id, rows] of Object.entries(VERIFIED_MISSIONS)) {
    const m = MISSIONS.find((x) => x.id === id);
    assert.ok(m, `mission gone upstream: ${id}`);
    for (const row of rows) {
      assert.ok(row.step >= 0 && row.step < m.steps.length, `${id} step ${row.step}`);
      for (const mod of row.modules) {
        const dir = moduleDir(mod);
        assert.ok(dir, `module missing: ${mod}`);
        const src = fs.readFileSync(path.join(dir, '__init__.py'), 'utf8');
        for (const p of row.platforms) assert.match(src, new RegExp(`Platform\\.${PLAT[p]}`), `${mod} on ${p}`);
        if (row.dataCheck) assert.ok(src.includes(`"${row.dataCheck}"`), `${mod} never emits check ${row.dataCheck}`);
      }
    }
  }
});

test('DONE matches the game', async () => {
  const { DONE } = await load();
  const { DONE_STATUSES } = await import(pathToFileURL(path.join(SRC, 'utils', 'mission-status.js')).href);
  assert.deepStrictEqual([...DONE].sort(), [...DONE_STATUSES].sort());
});

test('Harden Your Computer on a Mac: confirmed, problem, couldnt, other platform', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery'), ok('find_my_mac_check', [warn({ severity: 'critical' })])));
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.strictEqual(by[0], 'confirmed');
  assert.strictEqual(by[1], 'other-platform');
  assert.strictEqual(by[2], 'other-platform');
  assert.strictEqual(by[3], 'other-platform');
  assert.strictEqual(by[4], 'couldnt', 'screen_lock_check and lock_screen_check were not in this scan');
  assert.strictEqual(by[5], 'problem');
  assert.strictEqual(v.steps.find((s) => s.step === 5).problems[0].module, 'find_my_mac_check');
  assert.strictEqual(v.allConfirmed, false);
});

test('a module that errored or could not run never confirms', async () => {
  const { verifyMission } = await load();
  for (const bad of [{ name: 'encryption_check', status: 'error', error: 'x', findings: [] }, { name: 'encryption_check', status: 'ok', supported: false, findings: [] }]) {
    const v = verifyMission(FC, mac(bad, ok('filevault_recovery')));
    assert.strictEqual(v.steps.find((s) => s.step === 0).status, 'couldnt');
  }
});

test('all Mac steps confirmed means the mission can be finished from the scan', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery'), ok('screen_lock_check'), ok('lock_screen_check'), ok('find_my_mac_check', [{ severity: 'info', data: {} }])));
  assert.strictEqual(v.allConfirmed, true);
});

test('Windows uses the BitLocker steps and leaves the Mac ones alone', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, { platform: 'win32', modules: [ok('win_bitlocker_check')] });
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.deepStrictEqual([by[0], by[1], by[2], by[4], by[5]], ['other-platform', 'confirmed', 'confirmed', 'other-platform', 'other-platform']);
});

test('the router step only looks at the UPnP finding', async () => {
  const { verifyMission } = await load();
  const upnp = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'upnp_enabled' } })])));
  assert.strictEqual(upnp.steps[0].status, 'problem');
  const admin = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'admin_service_open' } })])));
  assert.strictEqual(admin.steps[0].status, 'confirmed');
  assert.strictEqual(verifyMission(ROUTER, mac()).steps[0].status, 'couldnt');
});

test('a mission with no row, or no scan, is not verified', async () => {
  const { verifyMission } = await load();
  assert.strictEqual(verifyMission('gmail-recon-breach', mac()), null);
  assert.strictEqual(verifyMission(FC, null).steps.every((s) => s.status === 'couldnt' || s.status === 'other-platform'), true);
});

test('a disagreement shows both sides and never changes the record', async () => {
  const { verifyMission, disagreement } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check', [warn({ title: 'FileVault is off' })]), ok('filevault_recovery')));
  const record = Object.freeze({ status: 'completed', action: 'completed', completedAt: '2026-10-09T10:00:00Z' });
  const before = JSON.stringify(record);
  const d = disagreement(record, v);
  assert.strictEqual(d.reportedAt, '2026-10-09T10:00:00Z');
  assert.strictEqual(d.problems[0].title, 'FileVault is off');
  assert.strictEqual(JSON.stringify(record), before);
  assert.strictEqual(disagreement({ status: 'skipped' }, v), null, 'not reported done: nothing to disagree with');
  assert.strictEqual(disagreement(undefined, v), null);
  assert.strictEqual(disagreement(record, verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery')))), null);
});

test('the scan-confirmed store survives junk and blocked storage', async () => {
  const { loadScanConfirmed, saveScanConfirmed, markScanConfirmed, SCAN_CONFIRMED_KEY } = await load();
  const mem = {}; const s = { getItem: (k) => mem[k] ?? null, setItem: (k, v) => { mem[k] = v; } };
  const store = markScanConfirmed(loadScanConfirmed(s), FC, '2026-10-16T00:00:00Z');
  assert.strictEqual(saveScanConfirmed(s, store), true);
  assert.deepStrictEqual(loadScanConfirmed(s).missions[FC], { at: '2026-10-16T00:00:00Z' });
  const empty = { version: 1, missions: {} };
  assert.deepStrictEqual(loadScanConfirmed({ getItem: () => '{nope' }), empty);
  assert.deepStrictEqual(loadScanConfirmed({ getItem: () => '{"version":2,"missions":{}}' }), empty);
  assert.deepStrictEqual(loadScanConfirmed({ getItem() { throw new Error('x'); } }), empty);
  assert.strictEqual(saveScanConfirmed({ setItem() { throw new Error('x'); } }, store), false);
  assert.ok(SCAN_CONFIRMED_KEY.startsWith('device-rescue.game.'));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-verified-missions.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write `desktop/renderer/game/verified-missions.js`**

```js
// Steps of Reclaim City missions that a check on this computer can confirm.
// Each row is one step of one game mission (its index in mission.steps), the
// platforms it applies to, and the Device Rescue modules that look at it. A row
// with dataCheck only counts findings whose data.check matches (the network
// modules give no finding codes). A test proves every mission, step, module,
// platform and data.check here is real.
//
// Left out on purpose: App Permission Audit (phone-only steps) and encrypted DNS
// (phone/browser/router steps; the scan reads this computer's system DNS). See
// the spec's "Changes made during planning".
export const VERIFIED_MISSIONS = {
  'device_security-fortify-computer': [
    { step: 0, platforms: ['darwin'], modules: ['encryption_check', 'filevault_recovery'], claim: 'FileVault is on' },
    { step: 1, platforms: ['win32'], modules: ['win_bitlocker_check'], claim: 'BitLocker is on for your drives' },
    { step: 2, platforms: ['win32'], modules: ['win_bitlocker_check'], claim: 'Your drive is encrypted' },
    { step: 3, platforms: ['linux'], modules: ['linux_disk_encryption_check'], claim: 'Your disk is encrypted' },
    { step: 4, platforms: ['darwin'], modules: ['screen_lock_check', 'lock_screen_check'], claim: 'A password is needed after sleep or the screen saver' },
    { step: 5, platforms: ['darwin'], modules: ['find_my_mac_check'], claim: 'Find My Mac is on' },
  ],
  'smart_network-recon-router': [
    { step: 3, platforms: ['darwin', 'win32', 'linux'], modules: ['router_security_audit'], dataCheck: 'upnp_enabled', claim: 'Your router didn’t answer UPnP requests from this computer' },
  ],
};
export const DONE = new Set(['completed', 'not-needed']);
export const SCAN_CONFIRMED_KEY = 'device-rescue.game.scan-confirmed.v1';
const SERIOUS = new Set(['warning', 'critical']);

function moduleIn(doc, name) {
  return (doc && Array.isArray(doc.modules) ? doc.modules : []).find((m) => m && m.name === name) || null;
}

export function problemFindings(doc, row) {
  const out = [];
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    for (const f of (mod && Array.isArray(mod.findings) ? mod.findings : [])) {
      if (!f || !SERIOUS.has(f.severity)) continue;
      if (row.dataCheck && !(f.data && f.data.check === row.dataCheck)) continue;
      out.push({ ...f, module: name });
    }
  }
  return out;
}

export function stepStatus(doc, row) {
  if (!doc || !row.platforms.includes(doc.platform)) return doc ? 'other-platform' : 'couldnt';
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    if (!mod || mod.status === 'error' || mod.supported === false) return 'couldnt';
  }
  return problemFindings(doc, row).length ? 'problem' : 'confirmed';
}

export function verifyMission(missionId, doc) {
  const rows = VERIFIED_MISSIONS[missionId];
  if (!rows) return null;
  const steps = rows.map((row) => {
    const status = stepStatus(doc, row);
    return { step: row.step, status, claim: row.claim, modules: row.modules, problems: status === 'problem' ? problemFindings(doc, row) : [] };
  });
  const relevant = steps.filter((s) => s.status !== 'other-platform');
  return { steps, allConfirmed: relevant.length > 0 && relevant.every((s) => s.status === 'confirmed') };
}

export function disagreement(record, verification) {
  if (!record || !DONE.has(record.status) || !verification) return null;
  const problems = verification.steps.flatMap((s) => s.problems);
  return problems.length ? { reportedAt: record.completedAt || null, problems } : null;
}

const emptyStore = () => ({ version: 1, missions: {} });

export function loadScanConfirmed(storage) {
  try {
    const raw = storage ? storage.getItem(SCAN_CONFIRMED_KEY) : null;
    if (!raw) return emptyStore();
    const p = JSON.parse(raw);
    const ok = p && p.version === 1 && p.missions && typeof p.missions === 'object' && !Array.isArray(p.missions)
      && Object.values(p.missions).every((r) => r && typeof r.at === 'string');
    return ok ? p : emptyStore();
  } catch (_) {
    return emptyStore();
  }
}

export function saveScanConfirmed(storage, store) {
  try {
    storage.setItem(SCAN_CONFIRMED_KEY, JSON.stringify(store));
    return true;
  } catch (_) {
    return false;
  }
}

export function markScanConfirmed(store, id, now) {
  return { version: 1, missions: { ...store.missions, [id]: { at: now } } };
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-verified-missions.test.js`
Expected: PASS (10 tests).

If the row-integrity test fails for a module:
- Fix the row to match `modules/`. Don't loosen the test.
- If a mission's step index has moved upstream, update `step:`.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/verified-missions.js desktop/test/game-verified-missions.test.js
git commit -m "Map Reclaim City mission steps to the checks that can confirm them"
```

---

### Task 6: One city: honest counts, district cards, the map and the verification panel

**Files:**
- Create: `desktop/renderer/game/one-city.js`, `game/views/one-city-map.js`, `game/views/verification.js`
- Modify: `desktop/renderer/game/views/hud.js` (Plan A's `renderHud` gets an optional `counts`)
- Test: `desktop/test/game-one-city.test.js`, `desktop/test/game-views.test.js` (extend)

**Interfaces:**
- Consumes:
  - Plan A: `countReclaimed(progress)`, `City`, `skyline`, `districtBadges`, `districtLine` (exported from `views/map.js`), `esc`, `SCOUT`, `mapScoutLine`.
  - Task 5: `verifyMission`, `disagreement`, `VERIFIED_MISSIONS`, `DONE`.
- Produces:
  - `focusFor(situation) -> 'master-keys'|'reclamation'|'computer'`
  - `countConfirmedAndReported({progress, rcState, scanConfirmed, doc}) -> {confirmed, reported}`
  - `accountDistrictCards({rc, rcState, doc}) -> Array<{id, name, description, chapter, percent, total, completed, checkAgain}>`
  - `deviceMissionFor(city, modules: string[]) -> Mission|null`
  - `renderHud({title, city, progress, counts?}) -> string`. With `counts` it shows CONFIRMED and YOU REPORTED in place of RECLAIMED.
  - `renderOneCityMap({city, accountCards, focus, cameBack, scout, accountsError}) -> string`
  - `renderVerification({mission, verification, disagreement, canFinish, platform, deviceMissionFor}) -> string`
  - `renderMilestoneSplit({confirmed: string[], reported: string[]}) -> string`

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/game-one-city.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const FC = 'device_security-fortify-computer';
const ok = (name, findings = []) => ({ name, status: 'ok', supported: true, findings });
const allMac = { platform: 'darwin', modules: ['encryption_check', 'filevault_recovery', 'screen_lock_check', 'lock_screen_check', 'find_my_mac_check'].map((n) => ok(n)) };
const brokenMac = { platform: 'darwin', modules: [ok('encryption_check', [{ title: 'FileVault is off', severity: 'warning', data: {} }]), ...allMac.modules.slice(1)] };
const setup = async () => ({
  ...(await import('../renderer/game/one-city.js')),
  rc: await (await import('../renderer/game/rc-load.js')).loadRc((rel) => import(pathToFileURL(path.join(SRC, rel)).href)),
});

test('focus follows the worry, like the Reclaim City link', async () => {
  const { focusFor } = await setup();
  assert.strictEqual(focusFor({ id: 'hacked' }), 'master-keys');
  assert.strictEqual(focusFor({ id: 'identity' }), 'reclamation');
  for (const id of ['wifi', 'sketchy', 'helping', 'unsure']) assert.strictEqual(focusFor({ id }), 'computer');
  assert.strictEqual(focusFor(null), 'computer');
});

test('confirmed and reported are counted apart; yours is never counted', async () => {
  const { countConfirmedAndReported } = await setup();
  const progress = { version: 1, missions: { a: { status: 'reclaimed' }, b: { status: 'reclaimed' }, c: { status: 'yours' }, d: { status: 'open' } } };
  const rcState = { missions: { [FC]: { status: 'completed' }, 'gmail-recon-breach': { status: 'completed' }, 'x-later': { status: 'skipped' } } };
  const scanConfirmed = { version: 1, missions: { [FC]: { at: '2026-10-16T00:00:00Z' } } };
  assert.deepStrictEqual(countConfirmedAndReported({ progress, rcState, scanConfirmed, doc: allMac }), { confirmed: 3, reported: 1 });
});

test('a scan-confirmed mission the scan no longer confirms counts as reported, not confirmed', async () => {
  const { countConfirmedAndReported } = await setup();
  const rcState = { missions: { [FC]: { status: 'completed' } } };
  const scanConfirmed = { version: 1, missions: { [FC]: { at: 'x' } } };
  assert.deepStrictEqual(countConfirmedAndReported({ progress: { version: 1, missions: {} }, rcState, scanConfirmed, doc: brokenMac }), { confirmed: 0, reported: 1 });
});

test('counting never changes the game state', async () => {
  const { countConfirmedAndReported } = await setup();
  const rcState = { missions: { [FC]: { status: 'completed', completedAt: 't' } } };
  const before = JSON.stringify(rcState);
  countConfirmedAndReported({ progress: { version: 1, missions: {} }, rcState, scanConfirmed: { version: 1, missions: {} }, doc: brokenMac });
  assert.strictEqual(JSON.stringify(rcState), before);
});

test('account district cards: every game district, in chapter order, with check-again where reports disagree', async () => {
  const { accountDistrictCards, rc } = await setup();
  const st = rc.createInitialState();
  st.missions[FC] = { status: 'completed', completedAt: '2026-10-09T00:00:00Z' };
  const cards = accountDistrictCards({ rc, rcState: st, doc: brokenMac });
  assert.deepStrictEqual(cards.map((c) => c.id), [...rc.DISTRICTS].sort((a, b) => a.chapter - b.chapter).map((d) => d.id));
  assert.strictEqual(cards.find((c) => c.id === 'perimeter').checkAgain, true);
  assert.strictEqual(cards.find((c) => c.id === 'vault').checkAgain, false);
  assert.ok(cards.every((c) => typeof c.percent === 'number'));
});

test('deviceMissionFor finds the device mission for a module', async () => {
  const { deviceMissionFor } = await setup();
  const city = { districts: [{ missions: [{ id: 'm1', module: 'encryption_check' }] }] };
  assert.strictEqual(deviceMissionFor(city, ['filevault_recovery', 'encryption_check']).id, 'm1');
  assert.strictEqual(deviceMissionFor(city, ['find_my_mac_check']), null);
});
```

Add to `desktop/test/game-views.test.js`:

```js
test('the HUD shows confirmed and reported apart when given counts, and stays as before without', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [] });
  const two = v.renderHud({ title: 'T', city, progress: v.emptyProgress(), counts: { confirmed: 3, reported: 5 } });
  assert.match(two, />3<\/b> <small>CONFIRMED/);
  assert.match(two, />5<\/b> <small>YOU REPORTED/);
  assert.doesNotMatch(two, /RECLAIMED/);
  assert.match(v.renderHud({ title: 'T', city, progress: v.emptyProgress() }), /RECLAIMED/);
});

test('the one-city map: two rings, focus, check again, escaped, and a notice if accounts failed to load', async () => {
  const v = await views();
  const { renderOneCityMap } = await import('../renderer/game/views/one-city-map.js');
  const city = v.findingsToCity({ modules: [] });
  const cards = [{ id: 'master-keys', name: EVIL, description: EVIL, chapter: 1, percent: 40, total: 5, completed: 2, checkAgain: true }];
  const html = renderOneCityMap({ city, accountCards: cards, focus: 'master-keys', cameBack: [], scout, accountsError: false });
  assert.match(html, /YOUR COMPUTER/);
  assert.match(html, /YOUR ACCOUNTS/);
  assert.match(html, /data-go="rc:#\/district\/master-keys"/);
  assert.match(html, /data-focus/);
  assert.match(html, /CHECK AGAIN/);
  assert.ok(!html.includes('<img src=x'));
  const failed = renderOneCityMap({ city, accountCards: [], focus: 'computer', cameBack: [], scout, accountsError: true });
  assert.match(failed, /Your accounts’ districts couldn’t load\./);
});

test('the verification panel labels every step and links a problem to its device mission', async () => {
  const { renderVerification } = await import('../renderer/game/views/verification.js');
  const mission = { id: 'device_security-fortify-computer', steps: [{ text: 'A' }, { text: 'B' }, { text: 'C' }, { text: 'D' }, { text: 'E' }, { text: 'F' }, { text: 'G' }] };
  const verification = { allConfirmed: false, steps: [
    { step: 0, status: 'problem', claim: 'FileVault is on', modules: ['encryption_check'], problems: [{ title: EVIL, module: 'encryption_check' }] },
    { step: 1, status: 'other-platform', claim: 'x', modules: [], problems: [] },
    { step: 4, status: 'confirmed', claim: 'A password is needed', modules: [], problems: [] },
    { step: 5, status: 'couldnt', claim: 'Find My Mac is on', modules: [], problems: [] },
  ] };
  const html = renderVerification({ mission, verification, disagreement: { reportedAt: '2026-10-09T10:00:00Z', problems: [{ title: EVIL }] }, canFinish: false, platform: 'darwin',
    deviceMissionFor: () => ({ id: 'dev-1', districtId: 'gatehouse' }) });
  assert.match(html, /PROBLEM FOUND/);
  assert.match(html, /FOR WINDOWS COMPUTERS/);
  assert.match(html, /CONFIRMED BY YOUR COMPUTER/);
  assert.match(html, /COULDN’T CHECK/);
  assert.match(html, /YOURS TO CHECK/, 'unmapped steps (index 6) are yours');
  assert.match(html, /data-go="mission:dev-1"/);
  assert.match(html, /You reported this done/);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html, /data-act="confirm-from-scan"/);
  assert.match(renderVerification({ mission, verification: { ...verification, allConfirmed: true }, disagreement: null, canFinish: true, platform: 'darwin', deviceMissionFor: () => null }), /data-act="confirm-from-scan"/);
});

test('the milestone split lists confirmed and reported apart', async () => {
  const { renderMilestoneSplit } = await import('../renderer/game/views/verification.js');
  const html = renderMilestoneSplit({ confirmed: ['Harden Your Computer'], reported: [EVIL] });
  assert.match(html, /CONFIRMED BY YOUR COMPUTER/);
  assert.match(html, /YOU REPORTED/);
  assert.ok(!html.includes('<img src=x'));
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-one-city.test.js test/game-views.test.js`
Expected: FAIL with `Cannot find module`, and the HUD test fails.

- [ ] **Step 3: Write `desktop/renderer/game/one-city.js`**

```js
// The one-city view's numbers. Two kinds of progress, never mixed:
// confirmed (the computer proved it) and reported (the person said so).
import { countReclaimed } from './progress.js';
import { VERIFIED_MISSIONS, verifyMission, disagreement, DONE } from './verified-missions.js';

const FOCUS = { hacked: 'master-keys', identity: 'reclamation' };

export function focusFor(situation) {
  return (situation && FOCUS[situation.id]) || 'computer';
}

export function countConfirmedAndReported({ progress, rcState, scanConfirmed, doc }) {
  let confirmed = countReclaimed(progress);
  let reported = 0;
  const records = (rcState && rcState.missions) || {};
  for (const [id, record] of Object.entries(records)) {
    if (!record || !DONE.has(record.status)) continue;
    const v = scanConfirmed && scanConfirmed.missions[id] ? verifyMission(id, doc) : null;
    if (v && v.allConfirmed) confirmed += 1;
    else reported += 1;
  }
  return { confirmed, reported };
}

export function accountDistrictCards({ rc, rcState, doc }) {
  const checkAgain = new Set();
  for (const id of Object.keys(VERIFIED_MISSIONS)) {
    if (disagreement(rcState.missions[id], verifyMission(id, doc))) {
      const m = rc.MISSIONS.find((x) => x.id === id);
      if (m) checkAgain.add(rc.missionDistrict(m));
    }
  }
  return [...rc.DISTRICTS].sort((a, b) => a.chapter - b.chapter).map((d) => {
    const p = rc.calcDistrictProgress(rcState, d.id);
    return { id: d.id, name: d.name, description: d.description, chapter: d.chapter,
      percent: p.percent, total: p.total, completed: p.completed, checkAgain: checkAgain.has(d.id) };
  });
}

export function deviceMissionFor(city, modules) {
  for (const d of (city && city.districts) || []) {
    for (const m of d.missions || []) if (modules.includes(m.module)) return m;
  }
  return null;
}
```

- [ ] **Step 4: Give Plan A's `renderHud` an optional `counts`**

In `desktop/renderer/game/views/hud.js`, change the signature to `export function renderHud({ title, city, progress, counts }) {`. Then replace the RECLAIMED stat line with:

```js
    ${counts
      ? `<span class="stat lime"><b>${counts.confirmed}</b> <small>CONFIRMED</small></span>
    <span class="stat cyan"><b>${counts.reported}</b> <small>YOU REPORTED</small></span>`
      : `<span class="stat lime"><b>${done}</b> <small>RECLAIMED</small></span>`}
```

- [ ] **Step 5: Write `desktop/renderer/game/views/one-city-map.js`**

```js
import { esc } from '../escape.js';
import { SCOUT, mapScoutLine } from '../scout-lines.js';
import { skyline, districtBadges, districtLine } from './map.js';

function accountSkyline(percent) {
  const img = percent >= 100 ? 'iso_liberated' : percent > 0 ? 'iso_progress' : 'iso_occupied';
  const tone = percent >= 100 ? 'lit' : percent > 0 ? 'warm' : 'dark';
  return `<div class="skyline" aria-hidden="true"><img class="${tone}" src="assets/${img}.png" alt=""><img class="tower ${tone}" src="assets/${percent >= 100 ? 'iso_tower_lib' : 'iso_tower_occ'}.png" alt=""></div>`;
}

export function renderOneCityMap({ city, accountCards, focus, cameBack, scout, accountsError }) {
  const device = city.districts.map((d) => `
      <button type="button" class="district ${esc(d.status)}" data-go="district:${esc(d.id)}">
        <h4>${esc(d.name.toUpperCase())}</h4>${skyline(d.status)}
        <p>${esc(districtLine(d))}</p><span class="d-foot">${districtBadges(d)}</span>
      </button>`).join('');
  const accounts = accountCards.map((c) => `
      <button type="button" class="district account${c.checkAgain ? ' warmish' : ''}" data-go="rc:#/district/${esc(c.id)}"${focus === c.id ? ' data-focus' : ''}>
        <h4>${esc(String(c.name).toUpperCase())}</h4>${accountSkyline(c.percent)}
        <p>${esc(c.description)}</p>
        <span class="d-foot">${c.completed ? `<span class="badge cyan">${esc(c.percent)}% REPORTED</span>` : '<span class="badge skip">NOT STARTED</span>'}
        ${c.checkAgain ? '<span class="badge warn">CHECK AGAIN</span>' : ''}</span>
      </button>`).join('');
  const line = cameBack && cameBack.length ? SCOUT.cameBack : mapScoutLine(city);
  return `
  <section class="map" aria-label="Your computer and your accounts as one city">
    <div class="ring-label"${focus === 'computer' ? ' data-focus' : ''}><span class="label">YOUR COMPUTER · FROM THE CHECKUP</span></div>
    <div class="districts">${device}</div>
    <div class="ring-label"><span class="label">YOUR ACCOUNTS · YOU REPORT THESE</span></div>
    ${accountsError
      ? `<p class="say">${esc('Your accounts’ districts couldn’t load. Your computer’s districts still work.')}</p>`
      : `<div class="districts">${accounts}</div>`}
    <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(line)}</p></div>
  </section>`;
}
```

- [ ] **Step 6: Write `desktop/renderer/game/views/verification.js`**

```js
import { esc } from '../escape.js';

const PLATFORM_NAME = { darwin: 'MAC', win32: 'WINDOWS', linux: 'LINUX' };
const OTHER = { darwin: 'win32', win32: 'darwin', linux: 'darwin' };

function badge(status, row, platform) {
  if (status === 'confirmed') return '<span class="badge safe">CONFIRMED BY YOUR COMPUTER</span>';
  if (status === 'problem') return '<span class="badge crit">PROBLEM FOUND</span>';
  if (status === 'couldnt') return '<span class="badge fog">COULDN’T CHECK</span>';
  if (status === 'other-platform') {
    const p = (row && row.platforms && row.platforms[0]) || OTHER[platform] || 'win32';
    return `<span class="badge skip">FOR ${PLATFORM_NAME[p] || 'OTHER'} COMPUTERS</span>`;
  }
  return '<span class="badge skip">YOURS TO CHECK</span>';
}

export function renderVerification({ mission, verification, disagreement, canFinish, platform, deviceMissionFor }) {
  const byStep = new Map(verification.steps.map((s) => [s.step, s]));
  const rows = mission.steps.map((st, i) => {
    const v = byStep.get(i);
    const status = v ? v.status : 'yours';
    let detail = '';
    if (v && status === 'confirmed') detail = `<small>${esc(v.claim)}.</small>`;
    if (v && status === 'couldnt') detail = '<small>Couldn’t check this one. That doesn’t mean it’s done.</small>';
    if (v && status === 'problem') {
      const dm = deviceMissionFor(v.modules);
      detail = `<small>Your computer says: ${esc(v.problems.map((p) => p.title).join('; '))}</small>${dm
        ? `<button type="button" class="btn-t" data-go="mission:${esc(dm.id)}">Fix it on your computer →</button>` : ''}`;
    }
    return `<li class="step"><span class="step-n">${i + 1}</span><span class="step-t">${esc(String(st.text).slice(0, 140))}${detail}</span>${badge(status, v && { platforms: [] }, platform)}</li>`;
  }).join('');
  const reported = disagreement ? `
    <div class="panel disagree" role="note">
      <p class="intel"><strong>You reported this done${disagreement.reportedAt ? ` on ${esc(new Date(disagreement.reportedAt).toLocaleDateString())}` : ''}.</strong>
      Your computer still shows: ${esc(disagreement.problems.map((p) => p.title).join('; '))}. Your answer is kept.</p>
    </div>` : '';
  return `
  <section class="verify" aria-label="What your computer can confirm">
    ${reported}
    <div class="panel active"><div class="label">WHO VOUCHES FOR EACH STEP</div><ol class="steps">${rows}</ol></div>
    ${canFinish ? '<button type="button" class="btn-p" data-act="confirm-from-scan">FINISH FROM THE CHECKUP ✓</button>' : ''}
  </section>`;
}

export function renderMilestoneSplit({ confirmed, reported }) {
  const list = (xs) => (xs.length ? `<ul class="notes">${xs.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p class="intel">None yet.</p>');
  return `
  <section class="panel milestone-split">
    <div class="label">CONFIRMED BY YOUR COMPUTER</div>${list(confirmed)}
    <div class="label">YOU REPORTED</div>${list(reported)}
  </section>`;
}
```

The `other-platform` label needs the row's own platforms, but `verifyMission`'s step objects don't carry them. Fix that in `verified-missions.js`: add `platforms: row.platforms` to the object `verifyMission` returns for each step. Then change the `badge` call to `badge(status, v, platform)`. Add an assertion to Task 5's Windows test: `assert.deepStrictEqual(v.steps.find((s) => s.step === 0).platforms, ['darwin'])`. Re-run Task 5's tests.

- [ ] **Step 7: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add desktop/renderer/game/one-city.js desktop/renderer/game/views desktop/renderer/game/verified-missions.js desktop/test/game-one-city.test.js desktop/test/game-views.test.js desktop/test/game-verified-missions.test.js
git commit -m "Count confirmed and reported progress apart, and show who vouches for each step"
```

---

### Task 7: The debrief form in the shadow root (`rc-dom.js`)

**Files:**
- Create: `desktop/renderer/game/rc-dom.js`
- Test: `desktop/test/game-rc-dom.test.js`

**Interfaces:**
- Consumes: `Rc` (`MISSIONS`, `visibleQuestions`).
- Produces:
  - `readAnswers(root, mission) -> answers`: the same logic as the game's `app.js` `readAnswers`.
  - `refreshDebriefForm(event, rc)`: the same logic as the game's `refreshDebriefForm`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-rc-dom.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');

// A tiny stand-in for querySelectorAll over radio/checkbox/number inputs.
function fakeForm(inputs) {
  return {
    querySelectorAll(sel) {
      const m = sel.match(/^input\[name="([^"]+)"\]:checked$/);
      if (m) return inputs.filter((i) => i.name === m[1] && i.checked);
      return [];
    },
    querySelector(sel) {
      const m = sel.match(/^input\[type="number"\]\[name="([^"]+)"\]$/);
      return m ? inputs.find((i) => i.type === 'number' && i.name === m[1]) || null : null;
    },
  };
}

test('readAnswers reads single, multi and number questions like the game does', async () => {
  const { readAnswers } = await import('../renderer/game/rc-dom.js');
  const mission = { debriefQs: [{ id: 'action' }, { id: 'flagged', multi: true }, { id: 'flagged_count', type: 'number' }, { id: 'unanswered' }] };
  const root = fakeForm([
    { name: 'q_action', value: 'completed', checked: true },
    { name: 'q_flagged', value: 'gmail', checked: true }, { name: 'q_flagged', value: 'venmo', checked: true },
    { name: 'q_flagged_count', type: 'number', value: '4', checked: false },
  ]);
  assert.deepStrictEqual(readAnswers(root, mission), { action: 'completed', flagged: ['gmail', 'venmo'], flagged_count: '4' });
});

test('a checked option beside a number wins over the typed number', async () => {
  const { readAnswers } = await import('../renderer/game/rc-dom.js');
  const mission = { debriefQs: [{ id: 'n', type: 'number' }] };
  const root = fakeForm([{ name: 'q_n', value: 'skip', checked: true }, { name: 'q_n', type: 'number', value: '3' }]);
  assert.deepStrictEqual(readAnswers(root, mission), { n: 'skip' });
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-rc-dom.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write `desktop/renderer/game/rc-dom.js`**

```js
// Reclaim City's debrief form behaviour, the same as its app.js, scoped to a
// root (the shadow-root frame) instead of the game's #app element.
export function readAnswers(root, mission) {
  const answers = {};
  for (const q of mission.debriefQs) {
    const checked = [...root.querySelectorAll(`input[name="q_${q.id}"]:checked`)].map((el) => el.value);
    if (q.type === 'number') {
      const typed = root.querySelector(`input[type="number"][name="q_${q.id}"]`)?.value;
      if (checked.length) answers[q.id] = checked[0];
      else if (typed !== undefined && typed !== '') answers[q.id] = typed;
    } else if (q.multi) {
      if (checked.length) answers[q.id] = checked;
    } else if (checked.length) answers[q.id] = checked[0];
  }
  return answers;
}

// Follow-up questions appear once the answers they depend on are given; "none"
// and "couldn't check" stand alone in a pick-all list; a number and a
// "couldn't check" beside it clear each other.
export function refreshDebriefForm(e, rc) {
  const input = e.target;
  if (!input || input.tagName !== 'INPUT' || !String(input.name || '').startsWith('q_')) return;
  const form = input.closest('[data-debrief]');
  if (!form) return;
  if (input.type === 'checkbox' && input.checked) {
    const alone = input.value === 'none' || input.value === 'skip';
    for (const other of form.querySelectorAll(`input[name="${input.name}"]`)) {
      if (other === input) continue;
      if (other.type === 'number') { if (alone) other.value = ''; continue; }
      if (alone || other.value === 'none' || other.value === 'skip') other.checked = false;
    }
  }
  if (input.type === 'number' && input.value !== '') {
    for (const other of form.querySelectorAll(`input[type="checkbox"][name="${input.name}"]`)) other.checked = false;
  }
  const mission = rc.MISSIONS.find((m) => m.id === form.dataset.debrief);
  if (!mission) return;
  const shown = new Set(rc.visibleQuestions(mission, readAnswers(form, mission)).map((q) => q.id));
  for (const group of form.querySelectorAll('[data-question]')) group.hidden = !shown.has(group.dataset.question);
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-rc-dom.test.js`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/rc-dom.js desktop/test/game-rc-dom.test.js
git commit -m "Read and refresh Reclaim City's debrief form inside the city"
```

---

### Task 8: Wire account mode into the controller

**Files:**
- Modify: `desktop/renderer/game/controller.js` (Plan A's `createController`)
- Modify: `desktop/renderer/game/game.css` (append)
- Test: all of the above, plus the manual check in Step 6.

**Interfaces:**
- Consumes: everything in Tasks 1–7, `window.rescue.openMissionLink`, and Plan A's `RescueHost`.
- Produces: no new exports. `createController` keeps Plan A's signature and return value. It now also handles `data-go="rc:<hash>"`, `data-act="confirm-from-scan"`, every game `data-action`, and `#/…` and `https://` anchors inside the frame.

- [ ] **Step 1: Add the imports and the state**

At the top of `controller.js`, add:

```js
import { loadRc } from './rc-load.js';
import { routeFor, applyRcAction, fileRc, afterRecorded } from './rc-actions.js';
import { readAnswers, refreshDebriefForm } from './rc-dom.js';
import { verifyMission, disagreement, loadScanConfirmed, saveScanConfirmed, markScanConfirmed, DONE } from './verified-missions.js';
import { focusFor, countConfirmedAndReported, accountDistrictCards, deviceMissionFor } from './one-city.js';
import { renderOneCityMap } from './views/one-city-map.js';
import { renderVerification, renderMilestoneSplit } from './views/verification.js';
```

Add these fields to the `s` object: `rc: null, rcState: null, rcRoute: null, rcUi: {}, landing: null, accountsError: false, scanConfirmed: loadScanConfirmed(storage), linkNotice: ''`.

After the `frame` is created, start loading the game:

```js
  loadRc().then((rc) => {
    s.rc = rc;
    s.rcState = rc.loadState(storage);
    if (s.city) render();
  }).catch((err) => {
    console.error('Reclaim City content could not load:', err);
    s.accountsError = true;
    if (s.city) render();
  });
```

- [ ] **Step 2: Render the map and the game screens**

Add these helpers inside `createController`:

```js
  function setRcState(next) {
    if (next === s.rcState) return;
    s.rcState = next;
    s.rc.saveState(next, storage);
  }

  function rcScreenHtml() {
    const { screen, params } = s.rcRoute;
    const rc = s.rc;
    const st = s.rcState;
    if (screen === 'district') {
      const reaction = s.landing && s.landing.districtId === params.id ? s.landing.reaction : null;
      return rc.renderDistrict(st, params.id, params.tab, { reaction });
    }
    if (screen === 'briefing') {
      const mission = rc.MISSIONS.find((m) => m.id === params.id);
      const v = mission ? verifyMission(mission.id, s.doc) : null;
      const record = st.missions[params.id];
      const panel = v ? renderVerification({
        mission, verification: v, disagreement: disagreement(record, v),
        canFinish: v.allConfirmed && !(record && DONE.has(record.status)),
        platform: s.doc && s.doc.platform, deviceMissionFor: (mods) => deviceMissionFor(s.city, mods),
      }) : '';
      return panel + rc.renderBriefing(st, params.id, { resetAnyway: s.rcUi.resetAnyway === params.id });
    }
    if (screen === 'debrief') return rc.renderDebrief(st, params.id);
    if (screen === 'milestone') {
      const done = rc.MISSIONS.filter((m) => rc.missionDistrict(m) === params.districtId && st.missions[m.id] && DONE.has(st.missions[m.id].status));
      const confirmedIds = new Set(done.filter((m) => s.scanConfirmed.missions[m.id] && (verifyMission(m.id, s.doc) || {}).allConfirmed).map((m) => m.id));
      return renderMilestoneSplit({
        confirmed: done.filter((m) => confirmedIds.has(m.id)).map((m) => m.title),
        reported: done.filter((m) => !confirmedIds.has(m.id)).map((m) => m.title),
      }) + rc.renderMilestone(st, params.districtId);
    }
    return '';
  }

  function counts() {
    if (!s.rc) return undefined;
    return countConfirmedAndReported({ progress: s.progress, rcState: s.rcState, scanConfirmed: s.scanConfirmed, doc: s.doc });
  }
```

In `screenHtml()`, add this as the first branch:

```js
    if (s.screen === 'rc' && s.rc && s.rcRoute) return rcScreenHtml();
```

Replace its final map line (`return renderMap({...})`) with:

```js
    if (s.rc || s.accountsError) {
      return renderOneCityMap({ city: s.city, scout, cameBack: s.cameBack, focus: focusFor(s.situation),
        accountCards: s.rc ? accountDistrictCards({ rc: s.rc, rcState: s.rcState, doc: s.doc }) : [],
        accountsError: s.accountsError });
    }
    return renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout });
```

In `render()`:
- Pass `counts: counts()` to `renderHud`, and change the title to `s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER'`.
- Prepend `s.linkNotice` to the frame HTML.
- After setting `frame.innerHTML`, add:

```js
      // No share cards in Device Rescue: they would describe this person's progress.
      frame.querySelectorAll('[data-action="share-card"], #milestone-card-preview').forEach((el) => el.remove());
      const focused = s.screen === 'map' ? frame.querySelector('[data-focus]') : null;
      if (focused && s.focusPending) { focused.scrollIntoView({ block: 'start' }); s.focusPending = false; }
```

In the returned `show()`, add `s.focusPending = true;`.

- [ ] **Step 3: Handle game navigation, actions and links**

Add these helpers inside `createController`:

```js
  function goRc(hash) {
    const r = routeFor(hash, s.rc.parseRoute);
    s.linkNotice = '';
    if (r.screen === 'map') { s.screen = 'map'; render(); return; }
    s.rc.newScreenVisit();
    s.screen = 'rc';
    s.rcRoute = r;
    if (r.screen !== 'district') s.landing = null;
    render();
  }

  async function openLink(url) {
    let ok = false;
    try { ok = await win.rescue.openMissionLink(url); } catch (_) { ok = false; }
    if (!ok) {
      s.linkNotice = `<p class="link-notice" role="status">This link can’t be opened from here. You can copy it: <code>${esc(url)}</code></p>`;
      render();
    }
  }

  function applyResult(r) {
    if (!r) return;
    setRcState(r.state);
    if (r.ui) s.rcUi = { ...s.rcUi, ...r.ui };
    if (r.reaction) s.landing = r.reaction;
    if (r.open) openLink(r.open);
    if (r.route) goRc(r.route); else render();
  }

  function onRcAction(el) {
    const action = el.getAttribute('data-action');
    const data = { ...el.dataset };
    if (action === 'mission-step') data.href = el.getAttribute('href');
    if (action === 'add-custom-account') data.name = (frame.querySelector('#custom-account-input') || {}).value;
    if (action.startsWith('pm-cat-')) data.raw = (frame.querySelector(`#pm-cat-num-${data.district}`) || {}).value;
    if (action === 'submit-debrief') {
      const mission = s.rc.MISSIONS.find((m) => m.id === data.mission);
      applyResult(mission ? fileRc(s.rc, s.rcState, mission.id, readAnswers(frame, mission)) : { state: s.rcState, route: '#/city' });
      return;
    }
    applyResult(applyRcAction(s.rc, s.rcState, action, data));
  }

  function confirmFromScan() {
    const id = s.rcRoute && s.rcRoute.params.id;
    const mission = id && s.rc.MISSIONS.find((m) => m.id === id);
    const v = mission && verifyMission(id, s.doc);
    if (!v || !v.allConfirmed) { render(); return; }
    // File the mission with its own "completed" answer; the scan's part is kept apart.
    const q = mission.debriefQs.find((x) => (x.options || []).some((o) => o.value === 'completed'));
    const filed = q ? s.rc.fileDebrief(s.rcState, mission, { [q.id]: 'completed' }) : null;
    if (!filed) { s.linkNotice = '<p class="link-notice" role="status">This one has a few questions only you can answer. Use I DID IT below.</p>'; render(); return; }
    s.scanConfirmed = markScanConfirmed(s.scanConfirmed, id, now());
    saveScanConfirmed(storage, s.scanConfirmed);
    applyResult(afterRecorded(s.rc, s.rc.ensureBurst(s.rc.streakAfterFiling(filed.state, filed.event)), mission));
  }

  frame.addEventListener('click', (e) => {
    if (!s.rc || s.busy) return;
    const actEl = e.target.closest('[data-action]');
    if (actEl && frame.contains(actEl)) { e.preventDefault(); onRcAction(actEl); return; }
    const a = e.target.closest('a[href]');
    if (!a || !frame.contains(a)) return;
    const href = a.getAttribute('href') || '';
    if (href.startsWith('#')) { e.preventDefault(); goRc(href); return; }
    if (/^[a-z]+:/i.test(href)) { e.preventDefault(); openLink(href); }
  });
  frame.addEventListener('keydown', (e) => {
    if (!s.rc) return;
    const el = s.rc.keyActivationTarget(e);
    if (el && frame.contains(el)) { e.preventDefault(); el.click(); }
  });
  frame.addEventListener('change', (e) => { if (s.rc) refreshDebriefForm(e, s.rc); });
  frame.addEventListener('input', (e) => { if (s.rc) refreshDebriefForm(e, s.rc); });
```

In Plan A's existing click handler, add these lines:

```js
    if (go && go.startsWith('rc:')) { if (s.rc) goRc(go.slice(3)); return; }
    if (act === 'confirm-from-scan') { if (s.rc) confirmFromScan(); return; }
```

Put them before the `mission:` branch. Plan A's handler only looks at `data-go` and `data-act`, and the vendored screens use `data-action`, so the two handlers never act on the same click. A `data-go` inside the verification panel (`mission:<device id>`) goes to Plan A's device briefing, as intended.

- [ ] **Step 4: Append styles to `game/game.css`**

```css
.ring-label { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
.ring-label::after { content: ''; flex: 1; height: 1px; background: var(--line); }
.district.account .skyline img { width: 46px; }
.verify { padding: 18px 22px 0; display: grid; gap: 14px; }
.panel.disagree { border-color: rgba(255,159,0,0.45); }
.link-notice { margin: 12px 18px; padding: 10px 12px; border: 1px solid rgba(255,159,0,0.4); font-size: 14px; }
.link-notice code { font-family: var(--font-mono); overflow-wrap: anywhere; user-select: all; }
.milestone-split { margin: 18px 22px 0; display: grid; gap: 8px; }
```

- [ ] **Step 5: Run the suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 6: Manual check on a Mac**

Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start`, then check:
1. **Play it as a game**, then **I think I've been hacked**, then run the checkup. The map shows "YOUR COMPUTER" with the device districts, then "YOUR ACCOUNTS", and the view is scrolled to The Master Keys. The HUD reads CONFIRMED and YOU REPORTED, with no RECLAIMED, and there are no payment links anywhere.
2. Open The Master Keys. The survey ("Do you have a Gmail account?") toggles, and a toggled account appears or disappears.
3. Open a Gmail mission and click **GO DO IT**. The page opens in your browser, not in the app, and the app moves to the debrief. Answer it and **SUBMIT REPORT**. You land back on the district, and YOU REPORTED goes up by 1.
4. Open The Perimeter, then **Harden Your Computer**. Every step has a badge: CONFIRMED BY YOUR COMPUTER, PROBLEM FOUND, COULDN'T CHECK, FOR WINDOWS COMPUTERS, or YOURS TO CHECK. If FileVault is off, PROBLEM FOUND links to the device mission.
5. If every Mac step is confirmed, click **FINISH FROM THE CHECKUP**. CONFIRMED goes up by 1, not YOU REPORTED. Then, in DevTools, delete the `device-rescue.game.scan-confirmed.v1` key and reload. That mission now counts under YOU REPORTED.
6. Find a step whose link isn't https (the Firefox `about:preferences#privacy` step in a browser-privacy mission). Clicking it shows "This link can't be opened from here" and the URL to copy.
7. A link to `#/quiz/phishing` (a Quick Quest or the phishing chapter, if one shows) lands on the one-city map.
8. DevTools → Network: every request is `app://rescue/…`. The pages opened in step 3 open in the system browser, not as requests from the app.

Add these steps to `desktop/MANUAL-QA.md` under a new "One city (Spec B)" heading.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/renderer/game/game.css desktop/MANUAL-QA.md
git commit -m "Put your accounts' districts on the same map as your computer"
```

---

### Task 9: Docs

**Files:**
- Modify: `README.md` (Plan A's "Prefer to play?" paragraph)
- Modify: `CONTRIBUTING.md` (Plan A's submodule note)

- [ ] **Step 1: In `README.md`, add this to the end of Plan A's "Prefer to play?" paragraph:**

```markdown
The same city also holds Reclaim City's districts for your accounts: email,
banking, social media and more. Those you do in your own browser and report
back. The city always counts what your computer confirmed separately from what
you reported, so it never claims more than it knows.
```

- [ ] **Step 2: In `CONTRIBUTING.md`, add this after the submodule note:**

```markdown
After bumping the Reclaim City submodule, run `node desktop/scripts/build-mission-links.mjs`
and then `npm test` in `desktop/`. The tests fail if the game's import graph,
mission links or confirmed steps changed in a way game mode doesn't expect.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CONTRIBUTING.md
git commit -m "Document the one-city map and how to bump the game"
```

---

## Self-Review Notes

- **Spec coverage:**

  | Spec section | Task |
  | --- | --- |
  | §2 map, rings, focus, survey | 6, 8 |
  | §3 account missions, state, links, self-reported | 2, 3, 4, 7, 8 |
  | §4 confirmed by your computer (as amended), rules 1–5 | 5, 6, 8 |
  | §5 honest counts and milestone split | 6, 8 |
  | §6 safety | Plan A's gate is unchanged. It runs on every scan and re-check, and the account districts are only reached through the city, which the gate already closes. |
  | §7 errors | accounts fail to load → 6 and 8; link refused → 3 and 8; corrupt state → 2 and 5; missing module → 5 |
  | §8 tests | each task |

- **Names this plan relies on from Plan A** (check they exist before starting): `countReclaimed`, `renderHud`, `renderMap`, `skyline`, `districtBadges`, `districtLine`, `esc`, `SCOUT`, `mapScoutLine`, `createController`'s `s`, `render`, `screenHtml`, `frame` and `now`, `RescueHost`, and `resolveAppPath`'s `rc` branch.
- **Known limitation:** the vendored briefing draws its own Scout and full-page layout under the verification panel, so a briefing with a panel is longer than one without. That's acceptable for now, and a later design pass can merge them.
