# Command Center and Signal or Noise Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In game mode, the city's home becomes a command center (the deck). Every finding is a signal to sort with clues, and clearly marked practice drills are mixed in. Points reward investigating, never the verdict, and confirmed fixes are always counted apart from what the person reported.

**Architecture:**
- **Pure modules** hold all the logic, and each one has its own test file:
  - `ledger.js`: points, ranks, game tags, sweep history.
  - `signals.js`: the queue, city integrity, heat.
  - `clues.js`: sourced place notes, "how to read this" lines, Scout's read.
  - `drills.js` and `drills/*.js`: the drill bank and how drills are mixed into the queue.
- `progress.js` moves to version 3, with a `deck` field.
- **New pure views** draw the deck, its instruments, and the Signal or Noise panel. The existing maps learn three optional arguments, so the deck's centre is today's city.
- **`controller.js` wires it all in.** The `map` screen draws the deck, and Signal or Noise is a panel over it. The DRILL RANGE is a new `range` screen. RE-SWEEP calls the existing `RescueHost.startCheckup()`, which is the same read-only scan path, so `app.js`'s gate decides where a finished scan lands, exactly as it does today.

**Tech Stack:** plain JS ES modules (game mode) and classic scripts (`app.js`), with no bundler; Electron 41; `node --test` with `node:assert` on Node 22.

**Spec:** `docs/superpowers/specs/2026-10-18-command-center-signal-or-noise-design.md` (binding). It builds on the game mode plans A, B and C (`docs/superpowers/plans/2026-10-16-game-mode-*.md`). All three are done and merged. Every name this plan takes from them is listed in a task's **Consumes** line.

**Decisions this plan made where the spec is silent or open** (each one is pinned by a test):
1. **Clue points:** "Opening a clue (once per finding per scan)" means each kind of clue (who made it, where it lives, what it does, when it showed up) pays once per finding per sweep.
2. **City integrity counts scan facts only.** A district counts as open when the scan shows a critical or warning finding there that the person hasn't marked as theirs with the real "It's mine" step. Game tags never change integrity, so tagging everything MINE can't raise it.
3. **CONFIRMED** counts device fixes a re-check proved, plus account missions finished from the checkup. A finding that's simply gone after a re-sweep is logged "no longer seen" and isn't counted. The HUD on the other screens uses the same rule (`countDeckBars`), so no two screens ever disagree about CONFIRMED.
4. **Clean sweep:** the bonus pays when a re-sweep is the one that makes the board clean. A second clean re-sweep in a row pays nothing, so re-sweeping can't farm points.
5. **Drills:** each drill pays once ever. The number per scan is `ceil(real / 4)`, capped at 3. Drills already answered right are offered last.
6. **Storage:** the ops log is kept in memory only. A sweep record is a date plus counts only, and that includes counts of checked and secured districts so the sparkline can be drawn. Each tag stores a short fingerprint of its finding, so a tag on a finding that changed is set aside and the finding shows "changed since you tagged it", the same way `data.mark_stale` works for real marks.
7. **"These are all fine"** puts info signals in the MINE (known) pile, and pays nothing.
8. **Monitoring checks** (`stalkerware_scan`, `mvt_spyware_scan`, `keylogger_indicators`) never become signals, not even their info findings, and nothing keyed to them can be tagged or scored.
9. **Network clues** ("where it's going", "how often", "who owns that address") come from network pieces N3 and N4, so they aren't built here. Network findings get the same four clues as everything else.

## Global Constraints

Rules copied from the spec (verbatim where quoted):
- "Real changes always keep their own explicit OK for that specific change. The game makes that moment dramatic; it never skips it." MINE only *offers* MarkFlow's own step, with its own confirmation question. THREAT only links to the existing briefing, where FixFlow asks first.
- "Scoring: real findings score the investigation, never the verdict; clearly marked DRILLs are scored right/wrong."
- "tags are game sorting only; they change nothing on the computer."
- "Never earns points: removing or deleting anything for its own sake; anything touching monitoring software (the game isn't offered then); speed."
- "City integrity = share of *checked* districts with no open critical or warning signal. Unchecked districts are excluded, so fog never inflates it." "districts the scan couldn't check are fogged, never clear."
- "Bars: sorted · confirmed fixed (proven by re-check) · you reported. Confirmed and reported are never summed."
- "Rank never drops." Ranks: ROOKIE → SIGNAL ANALYST → NETRUNNER → SYSOP → CITY WARDEN.
- Storage: "the existing progress store (`device-rescue.game.v1`), migrated to version 3: points, rank, drill stats, tags keyed by `findingIdentity` (stable keys, not titles), and sweep history as dates + severity counts only — no names, no paths. `monitoringSeen` stays in memory only, never persisted."
- Drills: "Always visibly different: **DRILL** stamp, hatched lime border, 'Practice. This isn't on your computer.'" "Never counted in integrity, the sparkline, or sorted/confirmed/reported." "About one per four real signals, at most three per scan, drawn from the same districts as the real queue." "No drills about stalkerware, monitoring apps, or being watched." "Same accuracy gate as lessons: paths and 'how to read this' lines must be traceable to cited guides; a test enforces it."
- Scout's read: "Never 'wrong'. The person's call stands."
- Couldn't-check: "a COULDN'T CHECK signal in the queue that can't be tagged MINE/THREAT — it's **NOTED**, with a link to the couldn't-check lesson."
- "`data.marked_by_user`: arrives pre-tagged MINE with a MARKED badge, still visible. `data.mark_stale: true` returns it to the queue as 'changed since you marked it'."
- "Monitoring appears in a re-sweep: the game is withdrawn immediately and the person lands on plain results (existing gate: `gameStillOffered`, `postScanView`, `noteMonitoring`)." Every existing gate test keeps passing unchanged.
- Accessibility: "Keyboard-navigable deck; the queue is a list of real buttons; every graph has a text equivalent ('City integrity 72%, up from 61% last sweep'); redraws keep focus (existing controller behaviour); reduced motion respected."
- "Windows/Linux: the same deck; System Settings buttons are Mac-only."
- "Out of scope here: Pieces 2–7 above. Windows/Linux settings deep links. Any change to what the engine scans."

Project rules:
- Plain JS ES modules under `desktop/renderer/game/`, with no bundler and no new dependencies.
- New game files are served by `app://rescue/game/…` (the `renderer/` root in `desktop/app-protocol.js`) and packaged by `renderer/**` in `desktop/package.json`. `desktop/rc-files.json` lists only vendored Reclaim City files, so it doesn't change, and neither does `rc-import-graph.test.js`. Nothing new is vendored, so `npm run check-game-files` must still pass unchanged.
- Escape every string from the engine or the drill bank with `esc()` (`desktop/renderer/game/escape.js`). The CSP in `desktop/renderer/index.html` doesn't change: no inline scripts, and inline `style=""` is already allowed.
- No `rescue/*.py` changes, so the integrity manifest isn't touched.
- No time estimates anywhere: no durations in UI copy, and none in docs.
- Copy is for a frightened, non-technical person. Use short sentences. Never say "you're safe". Never say a change was made when only a page opened, or when only a game tag changed.
- Tests use `node:test` + `node:assert`, in `desktop/test/*.test.js`. Run one file with `cd desktop && node --test test/<file>.test.js`, and all of them with `cd desktop && npm test`.

## Review Focus

1. **A scan where every check errored or was unsupported.** Every district is fogged. Integrity reads "no reading", never 100% and never 0%. The queue holds only COULDN'T CHECK signals, there are no drills, and the deck says NOTHING COULD BE CHECKED, never CLEAR BOARD. Pinned in Task 3 (`cityIntegrity` with `checked: 0`), Task 6 (the view) and Task 8 (the controller).
2. **A finding with no `made_by`, no path in `data`, no date, and maybe no description.** It offers only the clues its evidence supports, possibly none ("The scan recorded no clues for this one"). It can still be tagged, and the two-clue bonus is simply out of reach. Pinned in Task 4 (`cluesFor`) and Task 7 (the panel).
3. **`findingIdentity` collisions.** Two info findings with the same identity are one signal with `count: 2`, never two queue rows with the same key. A re-sweep where the identity is the same but the finding changed (same plist, new program) drops the old tag and shows CHANGED SINCE YOU TAGGED IT. Pinned in Task 3 and Task 2 (`reconcileDeck`).
4. **A saved store from version 1 or 2 with missions marked "yours", or a version 3 store with a corrupt deck.** Missions and lessons are always kept. The deck starts empty, and no MINE tag is made up from old "yours" records: MINE comes from the scan's own `data.marked_by_user`. Pinned in Task 1.
5. **Hundreds of info findings.** One folded row reads "LOW-PRIORITY SIGNALS (N)". Opened, it shows at most 50 rows plus "And N more". THESE ARE ALL FINE sorts every one and pays nothing, and the known pile is capped the same way. Pinned in Task 3 (folding), Task 6 (view caps) and Task 8 (the controller's batch).

---

## File Structure

**New game files** (`desktop/renderer/game/`, ES modules)
- `ledger.js`: `POINTS`, `RANKS`, `MONITORING_MODULES`, `MAX_SWEEPS`, `moduleOfKey`, `rankIndexFor`, `rankOf`, `award`, `setTag`, `recordDrill`, `confirmFix`, `sweepPercent`, `recordSweep`, `reconcileDeck`.
- `signals.js`: `fingerprint`, `buildSignals`, `compareSignals`, `queueOf`, `sortedCount`, `cityIntegrity`, `districtHeat`, `sweepCounts`.
- `clues.js`: `PLACES`, `READING`, `CLUE_LABEL`, `COULDNT_READ`, `homeRelative`, `placeFor`, `pathOf`, `whenOf`, `cluesFor`, `drillClues`, `scoutRead`, `drillRead`.
- `drills.js`: `DRILL_FILES`, `MAX_DRILLS`, `DRILL_ANSWERS`, `MONITORING_WORDS`, `loadDrills`, `drillCount`, `pickDrills`, `chooseDrills`, `drillSignal`, `mixDrills`.
- `drills/gatehouse.js`, `drills/wires.js`, `drills/engine-room.js`, `drills/junkyard.js`: drill data, each with a default export of an array.
- `views/deck.js`: `SEV_BADGE`, `LOW_SHOWN`, `LOG_SHOWN`, `signalRow`, `nextMoveHtml`, `renderDeck`.
- `views/instruments.js`: `integrityText`, `sparklineSvg`, `renderInstruments`.
- `views/signal.js`: `TAG_NOTE`, `renderSignalPanel`, `renderRange`.

**Changed files**
- `game/progress.js`: version 3, `emptyDeck`, `validDeck`, `validSweep`, `setDeck`, `TAGS`, `SWEEP_FIELDS`.
- `game/one-city.js`: `countDeckBars`.
- `game/views/map.js` and `game/views/one-city-map.js`: optional `goFor`, `heat` and `selected` arguments.
- `game/views/training.js`: the DRILL RANGE button.
- `game/controller.js`: the deck, the panel, tags, drills, sweeps, the range, confirmed and reported points, and the ops log.
- `game/game.css`: the deck, the panel, drills, instruments and moments.
- `desktop/renderer/app.js`: exports `ALWAYS_SAFETY_MODULES`. That's the only change, and no behaviour changes.

**Tests** (`desktop/test/`)
- New: `game-ledger.test.js`, `game-signals.test.js`, `game-clues.test.js`, `game-drills.test.js`, `game-deck-views.test.js`, `game-signal-view.test.js`, `game-deck-controller.test.js`.
- Changed: `game-progress.test.js` (version 3), `game-controller.test.js` (two `district:` → `filter:` assertions, plus two scoring tests), `game-flow-gate.test.js` (a RE-SWEEP gate test).

**Docs:** `desktop/MANUAL-QA.md`, `README.md`.

---

### Task 1: Progress store version 3, with the deck

**Files:**
- Modify: `desktop/renderer/game/progress.js` (whole file below)
- Test: `desktop/test/game-progress.test.js` (five existing assertions move to version 3; new tests appended)

**Interfaces:**
- Consumes (Plans A/C): `STORE_KEY`, `loadProgress`, `saveProgress`, `ranOkModules`, `reconcile`, `setStatus`, `setLessonDone`, `lessonDone`, `reclaimedIn`, `recheckOutcome`, `countReclaimed`. Their signatures are unchanged.
- Produces:
  - `emptyDeck() -> Deck`, where `Deck = { points: int, rank: int, drills: { right: int, tried: int }, tags: { [identity]: { tag: 'mine'|'threat'|'closer'|'noted', at: string, fp: string } }, confirmed: { [identity]: string }, once: { [awardKey]: true }, sweep: { at: string|null, keys: { [awardKey]: true } }, sweeps: Sweep[] }`
  - `Sweep = { at: string, checks, critical, warning, info, fog, checked, secured }`: all non-negative integers, with no other keys.
  - `emptyProgress() -> { version: 3, missions: {}, lessons: {}, deck: emptyDeck() }`
  - `TAGS: Set<string>`, `SWEEP_FIELDS: string[]`, `validSweep(w) -> boolean`, `validDeck(d) -> boolean`
  - `migrate(raw) -> Progress` accepts versions 1, 2 and 3.
  - `setDeck(progress, deck) -> Progress` refuses an invalid deck and keeps the old one.
  - Every function that returns a Progress keeps `deck`.

- [ ] **Step 1: Move the existing version assertions to version 3**

In `desktop/test/game-progress.test.js`, make these five replacements.

(a) In `'storage: round trip, corrupt JSON, wrong version, and storage that throws'`, replace:

```js
  const { loadProgress, saveProgress, STORE_KEY, emptyProgress } = await load();
  const s = memStore();
  const p = { version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: {} };
```

with:

```js
  const { loadProgress, saveProgress, STORE_KEY, emptyProgress, emptyDeck } = await load();
  const s = memStore();
  const p = { version: 3, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: {}, deck: emptyDeck() };
```

(b) In `'an older record without district or title still loads and is filled in from the scan'`, replace:

```js
  const { loadProgress, reconcile, STORE_KEY } = await load();
  const old = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(old) }));
  assert.deepStrictEqual(p, { version: 2, missions: old.missions, lessons: {} });
```

with:

```js
  const { loadProgress, reconcile, STORE_KEY, emptyDeck } = await load();
  const old = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(old) }));
  assert.deepStrictEqual(p, { version: 3, missions: old.missions, lessons: {}, deck: emptyDeck() });
```

(c) Replace the whole test `'a saved version 1 store from Plan A migrates to version 2 and keeps every mission'` with:

```js
test('a saved version 1 store from Plan A migrates to version 3 and keeps every mission', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const v1 = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', updatedAt: NOW }, b: { status: 'later', module: 'n', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(v1) }));
  assert.deepStrictEqual(p, { version: 3, missions: v1.missions, lessons: {}, deck: emptyDeck() });
});
```

(d) Replace the whole test `'a corrupt lessons field is dropped but the missions survive'` with:

```js
test('a corrupt lessons field is dropped but the missions survive', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const missions = { a: { status: 'open', module: 'm', updatedAt: NOW } };
  for (const lessons of [null, [], 'x', { l: { completedAt: 5 } }, { l: null }]) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 2, missions, lessons }) }));
    assert.deepStrictEqual(p, { version: 3, missions, lessons: {}, deck: emptyDeck() }, JSON.stringify(lessons));
  }
});
```

(e) In `'reconcile and setStatus keep finished lessons'`, replace `assert.strictEqual(p.version, 2);` with `assert.strictEqual(p.version, 3);`.

- [ ] **Step 2: Add the version 3 tests to the end of the file**

```js
test('a version 2 store migrates to version 3: missions and lessons kept, the deck starts empty', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const v2 = { version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: { 'locked-door': { completedAt: NOW } } };
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: JSON.stringify(v2) })),
    { version: 3, missions: v2.missions, lessons: v2.lessons, deck: emptyDeck() });
});

// Review Focus 4: old "yours" records stay as they were; MINE comes from the scan's own mark.
test('a version 1 or 2 store with missions marked as yours keeps them, and no game tag is made up from them', async () => {
  const { loadProgress, STORE_KEY } = await load();
  const missions = { 'launch_agent_audit|security.launch_agent_audit.agent_info|plist=/Users/a/Library/LaunchAgents/x.plist':
    { status: 'yours', module: 'launch_agent_audit', updatedAt: NOW } };
  for (const version of [1, 2]) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version, missions, lessons: {} }) }));
    assert.deepStrictEqual(p.missions, missions, `v${version}`);
    assert.deepStrictEqual(p.deck.tags, {}, `v${version}: MINE comes from data.marked_by_user, not old records`);
    assert.strictEqual(p.deck.points, 0);
  }
});

test('a version 3 store with a bad deck keeps its missions and lessons and starts the deck empty', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const missions = { a: { status: 'open', module: 'm', updatedAt: NOW } };
  const lessons = { l: { completedAt: NOW } };
  const good = emptyDeck();
  const sweep = { at: NOW, checks: 1, critical: 0, warning: 0, info: 0, fog: 0, checked: 1, secured: 1 };
  const bad = [null, [], 'x', { ...good, points: -1 }, { ...good, rank: 1.5 }, { ...good, drills: null },
    { ...good, tags: { a: { tag: 'delete', at: NOW, fp: 'f' } } }, { ...good, tags: { a: { tag: 'mine', at: NOW } } },
    { ...good, confirmed: { a: 5 } }, { ...good, once: { k: 1 } }, { ...good, sweep: { at: 5, keys: {} } },
    { ...good, sweeps: {} }, { ...good, sweeps: [{ ...sweep, title: 'Unsigned helper' }] }, { ...good, sweeps: [{ at: NOW, checks: 1 }] }];
  for (const deck of bad) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 3, missions, lessons, deck }) }));
    assert.deepStrictEqual(p, { version: 3, missions, lessons, deck: emptyDeck() }, JSON.stringify(deck));
  }
});

test('a version 3 store round-trips with its deck', async () => {
  const { loadProgress, saveProgress, emptyDeck } = await load();
  const s = memStore();
  const deck = { ...emptyDeck(), points: 35, drills: { right: 1, tried: 2 },
    tags: { 'm|c|plist=/a': { tag: 'threat', at: NOW, fp: 'abc' } }, confirmed: { 'm|c|plist=/b': NOW },
    once: { 'fix:m|c|plist=/b': true }, sweep: { at: NOW, keys: { 'clue:m|c|plist=/a#maker': true } },
    sweeps: [{ at: NOW, checks: 290, critical: 1, warning: 2, info: 30, fog: 3, checked: 4, secured: 3 }] };
  const p = { version: 3, missions: {}, lessons: {}, deck };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
});

test('setDeck changes only the deck; reconcile, setStatus and setLessonDone keep it', async () => {
  const { emptyProgress, emptyDeck, setDeck, reconcile, setStatus, setLessonDone } = await load();
  const deck = { ...emptyDeck(), points: 10 };
  let p = setLessonDone(emptyProgress(), 'l', NOW);
  p = setDeck(p, deck);
  assert.deepStrictEqual([p.deck, p.lessons.l.completedAt], [deck, NOW]);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  p = setStatus(p, 'a', 'later', 'm', NOW);
  p = setLessonDone(p, 'k', NOW);
  assert.strictEqual(p.deck.points, 10);
  assert.strictEqual(p.version, 3);
  assert.strictEqual(setDeck(p, { points: 'lots' }).deck.points, 10, 'a bad deck is refused');
});
```

- [ ] **Step 3: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-progress.test.js`
Expected: FAIL. `emptyDeck` is not a function, and the version 3 assertions fail.

- [ ] **Step 4: Replace `desktop/renderer/game/progress.js` with:**

```js
// Mission progress for game mode, finished lessons, and the command center's
// deck. The scan is the source of truth: progress only remembers what the
// person chose ("later"), what changed between scans, which lessons they
// finished, and the deck (points, rank, drill stats, game tags and sweep
// history). "reclaimed" is only ever set by evidence: a re-check or a full scan
// where the finding's module ran and no longer reports it. Lessons never count
// toward fixes, and nothing in the deck changes anything on the computer.
//
// The key keeps its v1 name so a saved Plan A store is found and migrated.
// monitoringSeen is never stored here: app.js keeps it in memory only.
export const STORE_KEY = 'device-rescue.game.v1';
const STATUSES = new Set(['open', 'later', 'yours', 'reclaimed']);
// Game tags: sorting only.
export const TAGS = new Set(['mine', 'threat', 'closer', 'noted']);
// A sweep is a date and counts. Nothing else: no names, no paths.
export const SWEEP_FIELDS = ['checks', 'critical', 'warning', 'info', 'fog', 'checked', 'secured'];

export function emptyDeck() {
  return { points: 0, rank: 0, drills: { right: 0, tried: 0 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] };
}

export function emptyProgress() {
  return { version: 3, missions: {}, lessons: {}, deck: emptyDeck() };
}

function plainObject(x) {
  return !!x && typeof x === 'object' && !Array.isArray(x);
}

const count = (n) => Number.isInteger(n) && n >= 0;

function validMissions(m) {
  return plainObject(m) && Object.values(m).every((r) => r && STATUSES.has(r.status));
}

function validLessons(l) {
  return plainObject(l) && Object.values(l).every((r) => r && typeof r.completedAt === 'string');
}

export function validSweep(w) {
  return plainObject(w) && typeof w.at === 'string' && SWEEP_FIELDS.every((k) => count(w[k]))
    && Object.keys(w).every((k) => k === 'at' || SWEEP_FIELDS.includes(k));
}

export function validDeck(d) {
  return plainObject(d) && count(d.points) && count(d.rank)
    && plainObject(d.drills) && count(d.drills.right) && count(d.drills.tried)
    && plainObject(d.tags) && Object.values(d.tags).every((t) => plainObject(t) && TAGS.has(t.tag) && typeof t.at === 'string' && typeof t.fp === 'string')
    && plainObject(d.confirmed) && Object.values(d.confirmed).every((v) => typeof v === 'string')
    && plainObject(d.once) && Object.values(d.once).every((v) => v === true)
    && plainObject(d.sweep) && (d.sweep.at === null || typeof d.sweep.at === 'string') && plainObject(d.sweep.keys)
    && Array.isArray(d.sweeps) && d.sweeps.every(validSweep);
}

// Accepts a stored version 1, 2 or 3 document. Missions are kept whenever they
// are valid; a bad lessons field only costs the lessons, and a bad deck only
// costs the deck.
export function migrate(raw) {
  if (!plainObject(raw) || !validMissions(raw.missions)) return emptyProgress();
  const lessons = validLessons(raw.lessons) ? raw.lessons : {};
  if (raw.version === 1) return { version: 3, missions: raw.missions, lessons: {}, deck: emptyDeck() };
  if (raw.version === 2) return { version: 3, missions: raw.missions, lessons, deck: emptyDeck() };
  if (raw.version === 3) return { version: 3, missions: raw.missions, lessons, deck: validDeck(raw.deck) ? raw.deck : emptyDeck() };
  return emptyProgress();
}

export function loadProgress(storage) {
  try {
    const raw = storage ? storage.getItem(STORE_KEY) : null;
    if (!raw) return emptyProgress();
    return migrate(JSON.parse(raw));
  } catch (_) {
    return emptyProgress();
  }
}

export function saveProgress(storage, progress) {
  try {
    storage.setItem(STORE_KEY, JSON.stringify(progress));
    return true;
  } catch (_) {
    return false;
  }
}

// Only a module that says it ran (status "ok") counts; no status checked nothing.
export function ranOkModules(doc) {
  const out = new Set();
  for (const m of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    if (m && typeof m.name === 'string' && m.status === 'ok' && m.supported !== false) out.add(m.name);
  }
  return out;
}

function allMissions(city) {
  return (city && Array.isArray(city.districts) ? city.districts : []).flatMap((d) => d.missions || []);
}

function base(progress) {
  return {
    version: 3,
    missions: { ...((progress && progress.missions) || {}) },
    lessons: { ...((progress && progress.lessons) || {}) },
    deck: progress && validDeck(progress.deck) ? progress.deck : emptyDeck(),
  };
}

// The deck changes only through the ledger (ledger.js); an invalid one is refused.
export function setDeck(progress, deck) {
  const next = base(progress);
  if (validDeck(deck)) next.deck = deck;
  return next;
}

export function reconcile(progress, city, ranOk, now) {
  const next = base(progress);
  const cameBack = [];
  const present = new Set();
  for (const m of allMissions(city)) {
    present.add(m.id);
    const prev = next.missions[m.id];
    let status;
    if (m.marked) status = 'yours';
    else if (!prev || prev.status === 'yours') status = 'open';
    else if (prev.status === 'reclaimed') { status = 'open'; cameBack.push(m.id); }
    else status = prev.status;
    // districtId and title are kept so a reclaimed mission, which is no longer
    // in the scan, can still be shown in its district and on its milestone.
    // Older records without them still load; they are filled in here.
    if (!prev || prev.status !== status || prev.districtId !== m.districtId || prev.title !== m.title) {
      next.missions[m.id] = { status, module: m.module, districtId: m.districtId, title: m.title,
        updatedAt: !prev || prev.status !== status ? now : prev.updatedAt };
    }
  }
  for (const [id, rec] of Object.entries(next.missions)) {
    if (present.has(id) || rec.status === 'reclaimed' || rec.status === 'yours') continue;
    if (ranOk.has(rec.module)) next.missions[id] = { ...rec, status: 'reclaimed', updatedAt: now };
  }
  return { progress: next, cameBack };
}

// `about` is { districtId, title } of the mission, when known.
export function setStatus(progress, id, status, module, now, about = {}) {
  const prev = progress.missions[id] || {};
  const next = base(progress);
  next.missions[id] = { ...prev, ...about, status, module, updatedAt: now };
  return next;
}

export function setLessonDone(progress, id, now) {
  const next = base(progress);
  next.lessons[id] = { completedAt: now };
  return next;
}

export function lessonDone(progress, id) {
  return !!(progress && progress.lessons && progress.lessons[id]);
}

// Missions in this district that are reclaimed: the ones still in the scan with
// that status, and the ones the scan no longer reports (kept in progress).
export function reclaimedIn(progress, district) {
  const records = (progress && progress.missions) || {};
  const present = new Map((district.missions || []).map((m) => [m.id, m]));
  return Object.entries(records)
    .filter(([id, r]) => r.status === 'reclaimed' && (present.has(id) || r.districtId === district.id))
    .map(([id, r]) => ({ id, title: (present.get(id) || {}).title || r.title || 'Something that’s gone now' }));
}

export function recheckOutcome(missionId, cityAfter, response) {
  if (!response || response.ok !== true || !response.module) return 'couldnt';
  if (response.module.status === 'error' || response.module.supported === false) return 'couldnt';
  const m = allMissions(cityAfter).find((x) => x.id === missionId);
  if (!m) return 'reclaimed';
  return m.marked ? 'yours' : 'not-yet';
}

export function countReclaimed(progress) {
  return Object.values((progress && progress.missions) || {}).filter((r) => r.status === 'reclaimed').length;
}
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-progress.test.js`
Expected: PASS, every test.

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`
Expected: PASS. Nothing else compares a stored document by version.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/progress.js desktop/test/game-progress.test.js
git commit -m "Game: progress store version 3 with the command center's deck"
```

---

### Task 2: The ledger: points, ranks, tags and sweep history

**Files:**
- Create: `desktop/renderer/game/ledger.js`
- Modify: `desktop/renderer/app.js` (add `ALWAYS_SAFETY_MODULES,` to `module.exports`)
- Test: `desktop/test/game-ledger.test.js`

**Interfaces:**
- Consumes (Task 1): `emptyDeck`, `TAGS`, `SWEEP_FIELDS`, `validDeck` from `progress.js`.
- Produces:
  - `POINTS = { clue: 5, tagBonus: 10, drill: 15, drillClueBonus: 5, fix: 50, report: 20, clean: 40 }`
  - `RANKS: { name, min }[]`, `MONITORING_MODULES: Set<string>`, `MAX_SWEEPS = 20`
  - `moduleOfKey(key: string) -> string`
  - `rankIndexFor(points) -> int`, `rankOf(deck) -> { index, name, points, min, next: {name,min}|null, toNext }`
  - `award(deck, kind, key, extra = 0) -> { deck, points, rankUp }`, where `kind` is `fix|report|drill` (pays once ever) or `clue|tagBonus|clean` (pays once per sweep)
  - `setTag(deck, id, tag, fp, now) -> Deck`, `recordDrill(deck, right) -> Deck`
  - `confirmFix(deck, id, now) -> { deck, points, rankUp }`
  - `sweepPercent(sweep) -> int|null`
  - `recordSweep(deck, counts, now) -> { deck, points, rankUp, clean }`
  - `reconcileDeck(deck, signals, ranOk: Set) -> { deck, changed: string[], gone: string[] }`. `signals` are `buildSignals` results (Task 3): `{ id, kind, fp }`.

- [ ] **Step 1: Export the gate's monitoring list from `app.js`**

In `desktop/renderer/app.js`, inside `module.exports = { … }`, add a line `    ALWAYS_SAFETY_MODULES,` directly after `    mayBeWatched,`. Nothing else in `app.js` changes.

- [ ] **Step 2: Write the failing tests in `desktop/test/game-ledger.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');
const load = async () => ({ ...(await import('../renderer/game/ledger.js')), ...(await import('../renderer/game/progress.js')) });
const NOW = '2026-10-18T12:00:00Z';
const LATER = '2026-10-19T12:00:00Z';

test('a key pays once: clue and tag bonus per sweep; fix, report and drill for life', async () => {
  const { award, emptyDeck, recordSweep, POINTS } = await load();
  let d = emptyDeck();
  let r = award(d, 'clue', 'm|c|path=/a#maker');
  assert.strictEqual(r.points, POINTS.clue); d = r.deck;
  assert.strictEqual(award(d, 'clue', 'm|c|path=/a#maker').points, 0, 'the same clue again pays nothing');
  r = award(d, 'clue', 'm|c|path=/a#where'); assert.strictEqual(r.points, POINTS.clue); d = r.deck;
  d = award(d, 'tagBonus', 'm|c|path=/a').deck;
  assert.strictEqual(award(d, 'tagBonus', 'm|c|path=/a').points, 0, 'no farming by re-tagging');
  r = award(d, 'fix', 'm|c|path=/a'); assert.strictEqual(r.points, POINTS.fix); d = r.deck;
  assert.strictEqual(d.points, 70);
  d = recordSweep(d, { checks: 3, checked: 1, secured: 1 }, NOW).deck;
  assert.strictEqual(award(d, 'clue', 'm|c|path=/a#maker').points, POINTS.clue, 'a new sweep: clues pay again');
  assert.strictEqual(award(d, 'fix', 'm|c|path=/a').points, 0, 'a fix pays once, ever');
  assert.strictEqual(award(d, 'report', 'gmail-fortify-2fa').points, POINTS.report);
  assert.strictEqual(award(d, 'drill', 'upd8r', POINTS.drillClueBonus).points, POINTS.drill + POINTS.drillClueBonus);
});

test('nothing pays for an unknown kind, an empty key, or anything from a monitoring check', async () => {
  const { award, emptyDeck, setTag } = await load();
  const d = emptyDeck();
  for (const [kind, key] of [['delete', 'x|y'], ['speed', 'x|y'], ['clue', ''], ['clue', null],
    ['clue', 'stalkerware_scan|security.stalkerware_scan.x#maker'], ['fix', 'keylogger_indicators|k'], ['tagBonus', 'couldnt|mvt_spyware_scan']]) {
    const r = award(d, kind, key);
    assert.strictEqual(r.points, 0, `${kind} ${key}`);
    assert.strictEqual(r.deck.points, 0);
  }
  assert.deepStrictEqual(setTag(d, 'stalkerware_scan|x', 'mine', 'fp', NOW).tags, {}, 'never tagged either');
});

test('ranks climb with points and never drop', async () => {
  const { award, emptyDeck, rankOf, RANKS } = await load();
  assert.deepStrictEqual(RANKS.map((r) => r.name), ['ROOKIE', 'SIGNAL ANALYST', 'NETRUNNER', 'SYSOP', 'CITY WARDEN']);
  let d = emptyDeck();
  assert.deepStrictEqual([rankOf(d).name, rankOf(d).toNext], ['ROOKIE', 100]);
  d = award(d, 'fix', 'a|1').deck;
  const r = award(d, 'fix', 'a|2');
  assert.strictEqual(r.rankUp, true);
  assert.strictEqual(rankOf(r.deck).name, 'SIGNAL ANALYST');
  assert.strictEqual(rankOf({ ...r.deck, points: 0 }).name, 'SIGNAL ANALYST', 'a stored rank is never lowered');
  const top = rankOf({ ...r.deck, points: 5000, rank: 4 });
  assert.deepStrictEqual([top.name, top.next, top.toNext], ['CITY WARDEN', null, 0]);
});

test('a sweep keeps a date and counts only, at most twenty, and the deck stays valid', async () => {
  const { recordSweep, emptyDeck, validDeck, MAX_SWEEPS } = await load();
  let d = emptyDeck();
  const counts = { checks: 290, critical: 1, warning: 3, info: 40, fog: 2, checked: 5, secured: 3, title: 'Unsigned helper', path: '/Users/ann/x' };
  for (let i = 0; i < MAX_SWEEPS + 5; i += 1) d = recordSweep(d, counts, `2026-10-${String(1 + (i % 28)).padStart(2, '0')}T00:00:00Z`).deck;
  assert.strictEqual(d.sweeps.length, MAX_SWEEPS);
  assert.deepStrictEqual(Object.keys(d.sweeps[0]).sort(), ['at', 'checked', 'checks', 'critical', 'fog', 'info', 'secured', 'warning']);
  assert.ok(!JSON.stringify(d).includes('Unsigned helper') && !JSON.stringify(d).includes('/Users/ann'));
  assert.strictEqual(validDeck(d), true);
  const odd = recordSweep(emptyDeck(), { checked: 2, secured: 9, critical: -4, warning: 'x' }, NOW).deck.sweeps[0];
  assert.deepStrictEqual([odd.checked, odd.secured, odd.critical, odd.warning], [2, 2, 0, 0]);
});

test('a clean sweep pays when a re-sweep makes the board clean: not every time, never the first', async () => {
  const { recordSweep, emptyDeck, POINTS } = await load();
  assert.strictEqual(recordSweep(emptyDeck(), { checked: 3, secured: 3 }, NOW).clean, false, 'nothing to compare with');
  const r = recordSweep(recordSweep(emptyDeck(), { checked: 3, secured: 2 }, NOW).deck, { checked: 3, secured: 3 }, LATER);
  assert.deepStrictEqual([r.clean, r.points], [true, POINTS.clean]);
  const again = recordSweep(r.deck, { checked: 3, secured: 3 }, '2026-10-20T00:00:00Z');
  assert.deepStrictEqual([again.clean, again.points], [false, 0]);
  const blind = recordSweep(recordSweep(emptyDeck(), { checked: 3, secured: 2 }, NOW).deck, { checked: 0, secured: 0 }, LATER);
  assert.strictEqual(blind.clean, false, 'nothing checked is never a clean sweep');
});

// Review Focus 3: same identity, changed finding.
test('tags: kept by identity, set aside when the finding changed, dropped when it’s gone from a check that ran', async () => {
  const { setTag, reconcileDeck, emptyDeck } = await load();
  let d = emptyDeck();
  d = setTag(d, 'm|c|plist=/a', 'mine', 'fp1', NOW);
  d = setTag(d, 'm|c|plist=/b', 'threat', 'fp2', NOW);
  d = setTag(d, 'n|c|plist=/c', 'closer', 'fp3', NOW);
  d = setTag(d, 'couldnt|q', 'noted', 'couldnt', NOW);
  assert.strictEqual(setTag(d, 'm|x', 'delete', 'f', NOW), d, 'only the four tags');
  const signals = [{ id: 'm|c|plist=/a', kind: 'real', fp: 'fp1' }, { id: 'm|c|plist=/b', kind: 'real', fp: 'CHANGED' }];
  const r = reconcileDeck(d, signals, new Set(['m', 'q']));
  assert.deepStrictEqual(Object.keys(r.deck.tags).sort(), ['m|c|plist=/a', 'n|c|plist=/c'], 'n didn’t run: its tag stays');
  assert.deepStrictEqual(r.changed, ['m|c|plist=/b']);
  assert.deepStrictEqual(r.gone, ['couldnt|q'], 'q ran this time, so its couldn’t-check note is done');
});

test('a confirmed fix counts until the finding shows up again; its points stay', async () => {
  const { confirmFix, reconcileDeck, emptyDeck, POINTS } = await load();
  let r = confirmFix(emptyDeck(), 'm|c|plist=/a', NOW);
  assert.strictEqual(r.points, POINTS.fix);
  assert.deepStrictEqual(Object.keys(r.deck.confirmed), ['m|c|plist=/a']);
  let d = reconcileDeck(r.deck, [], new Set(['m'])).deck;
  assert.ok(d.confirmed['m|c|plist=/a'], 'still gone: still confirmed');
  d = reconcileDeck(d, [{ id: 'm|c|plist=/a', kind: 'real', fp: 'x' }], new Set(['m'])).deck;
  assert.deepStrictEqual(d.confirmed, {});
  assert.strictEqual(d.points, POINTS.fix, 'no points are taken back');
  r = confirmFix(d, 'm|c|plist=/a', LATER);
  assert.strictEqual(r.points, 0, 'fixing it again pays nothing');
  assert.ok(r.deck.confirmed['m|c|plist=/a']);
});

test('drill stats count tries and right answers', async () => {
  const { recordDrill, emptyDeck } = await load();
  assert.deepStrictEqual(recordDrill(recordDrill(emptyDeck(), true), false).drills, { right: 1, tried: 2 });
});

test('the monitoring list matches the app’s safety gate', async () => {
  const { MONITORING_MODULES } = await load();
  const { ALWAYS_SAFETY_MODULES } = require('../renderer/app.js');
  assert.deepStrictEqual([...MONITORING_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
});
```

- [ ] **Step 3: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-ledger.test.js`
Expected: FAIL with `Cannot find module '…/ledger.js'`.

- [ ] **Step 4: Write `desktop/renderer/game/ledger.js`**

```js
// The command center's points, ranks, game tags and sweep history. Pure.
//
// Real findings score the investigation, never the verdict: opening clues, and
// tagging after looking. A drill (invented, clearly marked) scores right or
// wrong. A confirmed fix (a re-check proved it) scores most; a reported step
// scores less and is labelled YOU REPORTED. Nothing scores for deleting
// anything, for speed, or for anything touching monitoring software.
//
// Every award has a key, and a key pays once: lifetime keys (fix, report,
// drill) or keys for the current sweep (clue, tag bonus, clean sweep). So
// re-tagging, re-opening or re-sweeping can't farm points.
import { emptyDeck, TAGS, SWEEP_FIELDS, validDeck } from './progress.js';

export const POINTS = { clue: 5, tagBonus: 10, drill: 15, drillClueBonus: 5, fix: 50, report: 20, clean: 40 };
export const RANKS = [
  { name: 'ROOKIE', min: 0 },
  { name: 'SIGNAL ANALYST', min: 100 },
  { name: 'NETRUNNER', min: 300 },
  { name: 'SYSOP', min: 700 },
  { name: 'CITY WARDEN', min: 1500 },
];
// The same three checks app.js's gate watches (ALWAYS_SAFETY_MODULES). A test keeps them equal.
export const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
export const MAX_SWEEPS = 20;
const LIFETIME = new Set(['fix', 'report', 'drill']);
const PER_SWEEP = new Set(['clue', 'tagBonus', 'clean']);

const deckOf = (deck) => (validDeck(deck) ? deck : emptyDeck());
const none = (deck) => ({ deck, points: 0, rankUp: false });

// The module an award key or an identity belongs to:
// "module|code|…", "couldnt|module", or "identity#clue".
export function moduleOfKey(key) {
  const k = String(key == null ? '' : key).split('#')[0];
  return k.startsWith('couldnt|') ? k.slice(8) : k.split('|')[0];
}

export function rankIndexFor(points) {
  let i = 0;
  RANKS.forEach((r, n) => { if (points >= r.min) i = n; });
  return i;
}

// Rank never drops: the stored rank is the highest one reached.
export function rankOf(deck) {
  const d = deckOf(deck);
  const index = Math.min(RANKS.length - 1, Math.max(d.rank, rankIndexFor(d.points)));
  const next = RANKS[index + 1] || null;
  return { index, name: RANKS[index].name, points: d.points, min: RANKS[index].min, next,
    toNext: next ? Math.max(0, next.min - d.points) : 0 };
}

// `extra` adds points to this award (the drill clue bonus).
export function award(deck, kind, key, extra = 0) {
  const d = deckOf(deck);
  if (!LIFETIME.has(kind) && !PER_SWEEP.has(kind)) return none(d);
  if (typeof key !== 'string' || key === '' || MONITORING_MODULES.has(moduleOfKey(key))) return none(d);
  const k = `${kind}:${key}`;
  const lifetime = LIFETIME.has(kind);
  if (lifetime ? d.once[k] : d.sweep.keys[k]) return none(d);
  const points = POINTS[kind] + (Number.isInteger(extra) && extra > 0 ? extra : 0);
  const total = d.points + points;
  const rank = Math.max(d.rank, rankIndexFor(total));
  return {
    deck: { ...d, points: total, rank,
      once: lifetime ? { ...d.once, [k]: true } : d.once,
      sweep: lifetime ? d.sweep : { ...d.sweep, keys: { ...d.sweep.keys, [k]: true } } },
    points,
    rankUp: rank > d.rank,
  };
}

// Game sorting only: a tag changes nothing on the computer. `fp` is the
// finding's fingerprint (signals.js): when it changes, the tag stops applying.
export function setTag(deck, id, tag, fp, now) {
  const d = deckOf(deck);
  if (typeof id !== 'string' || id === '' || !TAGS.has(tag) || MONITORING_MODULES.has(moduleOfKey(id))) return d;
  return { ...d, tags: { ...d.tags, [id]: { tag, at: String(now), fp: String(fp == null ? '' : fp) } } };
}

export function recordDrill(deck, right) {
  const d = deckOf(deck);
  return { ...d, drills: { right: d.drills.right + (right ? 1 : 0), tried: d.drills.tried + 1 } };
}

// A re-check proved the fix: it counts as CONFIRMED, and the fix points pay
// once per finding, ever.
export function confirmFix(deck, id, now) {
  const d = deckOf(deck);
  if (typeof id !== 'string' || id === '') return none(d);
  return award({ ...d, confirmed: { ...d.confirmed, [id]: String(now) } }, 'fix', id);
}

export const sweepPercent = (w) => (w && w.checked > 0 ? Math.round((w.secured / w.checked) * 100) : null);
const isClean = (w) => !!w && w.checked > 0 && w.secured === w.checked;

// A finished scan, recorded as a date and counts only. It starts a new sweep,
// so clue and tag bonuses can be earned again. The clean-sweep bonus pays when
// a re-sweep is the one that made the board clean, not on every clean re-sweep.
export function recordSweep(deck, counts, now) {
  const d = deckOf(deck);
  const entry = { at: String(now) };
  for (const k of SWEEP_FIELDS) {
    const n = Math.floor(Number(counts && counts[k]));
    entry[k] = Number.isFinite(n) && n > 0 ? n : 0;
  }
  if (entry.secured > entry.checked) entry.secured = entry.checked;
  const prev = d.sweeps.length ? d.sweeps[d.sweeps.length - 1] : null;
  const next = { ...d, sweep: { at: entry.at, keys: {} }, sweeps: [...d.sweeps, entry].slice(-MAX_SWEEPS) };
  if (!(prev && isClean(entry) && !isClean(prev))) return { deck: next, points: 0, rankUp: false, clean: false };
  return { ...award(next, 'clean', entry.at), clean: true };
}

// After any scan or re-check, with buildSignals(…) for the new city. A tag
// whose finding changed is set aside (changed). A tag whose finding is gone
// from a check that ran is dropped (gone). A confirmed fix that shows up again
// is no longer counted as confirmed. Points are never taken back.
export function reconcileDeck(deck, signals, ranOk) {
  const d = deckOf(deck);
  const byId = new Map((signals || []).filter((x) => x && x.kind !== 'drill').map((x) => [x.id, x]));
  const tags = {};
  const changed = [];
  const gone = [];
  for (const [id, rec] of Object.entries(d.tags)) {
    const sig = byId.get(id);
    if (sig) {
      if (sig.fp === rec.fp) tags[id] = rec; else changed.push(id);
      continue;
    }
    if (ranOk && ranOk.has(moduleOfKey(id))) gone.push(id); else tags[id] = rec;
  }
  const confirmed = {};
  for (const [id, at] of Object.entries(d.confirmed)) if (!byId.has(id)) confirmed[id] = at;
  return { deck: { ...d, tags, confirmed }, changed, gone };
}
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-ledger.test.js`
Expected: PASS, every test.

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`
Expected: PASS. The gate tests are unchanged, and `app.js` only gained an export.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/ledger.js desktop/test/game-ledger.test.js desktop/renderer/app.js
git commit -m "Game: the command center's ledger (points, ranks, tags, sweeps)"
```

---

### Task 3: Signals: the queue, its order, folding, NOTED, marked pre-tags and integrity

**Files:**
- Create: `desktop/renderer/game/signals.js`
- Modify: `desktop/renderer/game/one-city.js` (add `countDeckBars`)
- Test: `desktop/test/game-signals.test.js`

**Interfaces:**
- Consumes: `findingIdentity`, `DISTRICTS`, `OUTSKIRTS` and the `findingsToCity` city shape (Plan A/C) from `findings-to-city.js`; `MONITORING_MODULES` (Task 2); `countConfirmedAndReported` (Plan B) in `one-city.js`.
- Produces:
  - `Signal = { id, kind: 'real'|'couldnt'|'drill', severity: 'critical'|'warning'|'info'|'couldnt', title, description, districtId, module, finding, missionId: string|null, fixable, marked, stale, fp, count, tag: 'mine'|'threat'|'closer'|'noted'|null, changed }`. Drill signals (Task 5) add `drill`.
  - `fingerprint(finding) -> string`
  - `buildSignals(city, deck, changedIds?: Set) -> Signal[]`
  - `compareSignals(a, b) -> number`
  - `queueOf(signals, filterDistrictId = null) -> { urgent, low, threats, known, noted }`. Each list is sorted. `urgent` and `low` hold untagged or `closer` signals.
  - `sortedCount(signals) -> int` (drills are never counted)
  - `cityIntegrity(city, signals) -> { percent: int|null, checked, secured, checkedIds: Set, securedIds: Set }`
  - `districtHeat(city, signals) -> { [districtId]: 'hot'|'warn' }`
  - `sweepCounts(doc, city, integrity) -> { checks, critical, warning, info, fog, checked, secured }`
  - `countDeckBars({ rc, deck, rcState, scanConfirmed, doc }) -> { confirmed, reported }` in `one-city.js`

- [ ] **Step 1: Write the failing tests in `desktop/test/game-signals.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');
const load = async () => ({
  ...(await import('../renderer/game/signals.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/ledger.js')),
  ...(await import('../renderer/game/progress.js')),
  ...(await import('../renderer/game/one-city.js')),
});
const NOW = '2026-10-18T12:00:00Z';
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title} d`, severity, category: 'security', data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const net = (name, findings, extra = {}) => ({ ...mod(name, findings, extra), category: 'network' });
const doc = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
async function build(d, deck) {
  const v = await load();
  const city = v.findingsToCity(d);
  return { v, city, sigs: v.buildSignals(city, deck || v.emptyDeck()) };
}

test('the queue: critical, then warning, then couldn’t check; info is folded apart', async () => {
  const { v, sigs } = await build(doc(
    mod('a_mod', [f('Warn A', 'warning', { plist: '/a' }), f('Crit', 'critical', { plist: '/c' }), f('Note', 'info', { name: 'n1' })]),
    net('b_mod', [f('Warn B', 'warning', { path: '/b' })]),
    mod('broken', [], { status: 'error', error: 'boom' }),
  ));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual(q.urgent.map((x) => x.title), ['Crit', 'Warn A', 'Warn B', 'A check couldn’t run here']);
  assert.deepStrictEqual(q.low.map((x) => x.title), ['Note']);
  assert.deepStrictEqual([q.urgent[3].kind, q.urgent[3].id, q.urgent[3].description], ['couldnt', 'couldnt|broken', 'boom']);
  assert.deepStrictEqual(v.queueOf(sigs, 'wires').urgent.map((x) => x.title), ['Warn B'], 'a district filter');
});

test('a finding marked as yours arrives tagged MINE; one that changed since is back in the queue', async () => {
  const marked = f('Mine', 'info', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' });
  const stale = f('Stale', 'info', { plist: '/s', marked_by_user: true, mark_stale: true, original_severity: 'warning', known_item_id: 'k2' });
  const { v, sigs } = await build(doc(mod('a_mod', [marked, stale])));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual(q.known.map((x) => [x.title, x.marked, x.tag]), [['Mine', true, 'mine']]);
  assert.deepStrictEqual(q.urgent.map((x) => [x.title, x.stale, x.tag]), [['Stale', true, null]]);
  assert.strictEqual(v.sortedCount(sigs), 1);
});

test('tags carry over by identity; a changed finding with the same identity loses its tag and says so', async () => {
  const same = () => doc(mod('a_mod', [f('Helper', 'warning', { plist: '/h', program: '/Applications/H.app' })]));
  const { v, sigs } = await build(same());
  const deck = v.setTag(v.emptyDeck(), sigs[0].id, 'threat', sigs[0].fp, NOW);
  assert.strictEqual(v.buildSignals(v.findingsToCity(same()), deck)[0].tag, 'threat', 'same identity, same finding: same tag');
  const moved = v.buildSignals(v.findingsToCity(doc(mod('a_mod', [f('Helper', 'warning', { plist: '/h', program: '/tmp/h' })]))), deck)[0];
  assert.strictEqual(moved.id, sigs[0].id, 'the identity is the plist, so it collides');
  assert.deepStrictEqual([moved.tag, moved.changed], [null, true]);
  const later = v.buildSignals(v.findingsToCity(same()), v.emptyDeck(), new Set([sigs[0].id]))[0];
  assert.strictEqual(later.changed, true, 'after the tag was set aside, the controller’s set keeps the badge');
});

// Review Focus 3.
test('two info findings with the same identity are one signal, counted twice', async () => {
  const { v, sigs } = await build(doc(mod('a_mod', [f('Same', 'info'), f('Same', 'info')])));
  const q = v.queueOf(sigs);
  assert.strictEqual(q.low.length, 1);
  assert.strictEqual(q.low[0].count, 2);
  assert.strictEqual(new Set(sigs.map((x) => x.id)).size, sigs.length, 'no two signals share a key');
});

test('integrity: checked districts with nothing open; fog excluded; game tags change nothing', async () => {
  const { v, city, sigs } = await build(doc(
    mod('a_mod', [f('Crit', 'critical', { plist: '/c' })]),
    net('b_mod', [f('Note', 'info')]),
    { ...mod('c_mod', []), category: 'integrity' },
    { ...mod('d_mod', [], { status: 'error', error: 'x' }), category: 'performance' },
  ));
  const i = v.cityIntegrity(city, sigs);
  assert.deepStrictEqual([i.checked, i.secured, i.percent], [3, 2, 67]);
  assert.ok(!i.checkedIds.has('engine-room'), 'a district nothing ran in is never counted');
  const crit = sigs.find((x) => x.title === 'Crit');
  const tagged = v.buildSignals(city, v.setTag(v.emptyDeck(), crit.id, 'mine', crit.fp, NOW));
  assert.strictEqual(tagged.find((x) => x.id === crit.id).tag, 'mine');
  assert.strictEqual(v.cityIntegrity(city, tagged).percent, 67, 'a game tag changes nothing');
  assert.deepStrictEqual(v.districtHeat(city, sigs), { gatehouse: 'hot' });
});

// Review Focus 1.
test('every check errored: no reading, nothing checked, only COULDN’T CHECK signals', async () => {
  const d = doc(mod('a', [], { status: 'error', error: 'x' }), net('b', [], { supported: false, unsupported_reason: 'Windows only' }));
  const { v, city, sigs } = await build(d);
  const i = v.cityIntegrity(city, sigs);
  assert.deepStrictEqual([i.percent, i.checked], [null, 0]);
  assert.ok(sigs.length === 2 && sigs.every((x) => x.kind === 'couldnt'));
  assert.deepStrictEqual(v.sweepCounts(d, city, i), { checks: 0, critical: 0, warning: 0, info: 0, fog: 2, checked: 0, secured: 0 });
});

test('monitoring checks never become signals, even their info findings or a check that couldn’t run', async () => {
  const { sigs } = await build(doc(mod('stalkerware_scan', [f('No monitoring apps found', 'info')]),
    mod('keylogger_indicators', [], { status: 'error', error: 'x' }), mod('a_mod', [f('Other', 'info')])));
  assert.deepStrictEqual(sigs.map((x) => x.title), ['Other']);
});

// Review Focus 5.
test('hundreds of info findings stay in the one low-priority list', async () => {
  const { v, sigs } = await build(doc(mod('a_mod', Array.from({ length: 500 }, (_, i) => f(`Note ${i}`, 'info', { name: `n${i}` })))));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual([q.urgent.length, q.low.length], [0, 500]);
});

test('sweep counts are counts', async () => {
  const d = doc(mod('a_mod', [f('C', 'critical', { plist: '/c' }), f('W', 'warning', { plist: '/w' }), f('I', 'info')]), mod('gone', [], { status: 'error', error: 'x' }));
  const { v, city, sigs } = await build(d);
  assert.deepStrictEqual(v.sweepCounts(d, city, v.cityIntegrity(city, sigs)), { checks: 1, critical: 1, warning: 1, info: 1, fog: 1, checked: 1, secured: 0 });
});

test('the deck’s bars: confirmed fixes plus account missions the checkup confirmed; reported apart, never summed', async () => {
  const { countDeckBars } = await load();
  const deck = { confirmed: { a: NOW, b: NOW } };
  assert.deepStrictEqual(countDeckBars({ rc: null, deck }), { confirmed: 2, reported: 0 });
  const r = countDeckBars({ rc: { MISSIONS: [] }, deck, rcState: { missions: { x: { status: 'completed' } } }, scanConfirmed: { missions: {} }, doc: null });
  assert.deepStrictEqual(r, { confirmed: 2, reported: 1 });
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-signals.test.js`
Expected: FAIL with `Cannot find module '…/signals.js'`.

- [ ] **Step 3: Write `desktop/renderer/game/signals.js`**

```js
// The command center's queue: every finding as a signal to sort. Pure.
// Warnings and criticals come first, and info is folded into one low-priority
// list. A check that couldn't run is a COULDN'T CHECK signal, tagged NOTED and
// never MINE or THREAT. A finding the person marked as theirs arrives
// pre-tagged MINE; one that changed since (data.mark_stale) is back in the
// queue. Monitoring checks are never signals: the game isn't offered when they
// find something, and nothing about them is scored.
import { findingIdentity, DISTRICTS, OUTSKIRTS } from './findings-to-city.js';
import { MONITORING_MODULES } from './ledger.js';

const ORDER = { critical: 0, warning: 1, couldnt: 2, info: 3 };
const DISTRICT_ORDER = [...DISTRICTS, OUTSKIRTS].map((d) => d.id);
const OPEN = new Set(['critical', 'warning']);
const REAL_TAGS = new Set(['mine', 'threat', 'closer']);

// What a tag sticks to. If the title, the program, the path or who made it
// changes, the tag no longer applies. A short hash: nothing readable is stored.
export function fingerprint(finding) {
  const f = finding || {};
  const d = f.data && typeof f.data === 'object' ? f.data : {};
  const mb = Array.isArray(f.made_by) ? f.made_by.map((m) => `${m && m.name}|${m && m.verified}|${m && m.subject}`).join(';') : '';
  const text = [f.title, d.program, d.path, d.target, mb].map((x) => String(x == null ? '' : x)).join('\n');
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) h = ((h * 33) ^ text.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

// `changedIds`: tags the controller set aside this session, so the
// "changed since you tagged it" badge stays after reconcileDeck dropped them.
export function buildSignals(city, deck, changedIds = null) {
  const tags = (deck && deck.tags) || {};
  const out = [];
  const byId = new Map();
  const add = (sig) => {
    const have = byId.get(sig.id);
    if (have) { have.count += 1; return; }
    const rec = tags[sig.id];
    const fits = !!rec && (sig.kind === 'couldnt' ? rec.tag === 'noted' : REAL_TAGS.has(rec.tag));
    const changed = (!!rec && rec.fp !== sig.fp) || !!(changedIds && changedIds.has(sig.id));
    const tag = sig.marked ? 'mine' : (fits && rec.fp === sig.fp ? rec.tag : null);
    const full = { ...sig, tag, changed: changed && !sig.marked };
    byId.set(sig.id, full);
    out.push(full);
  };
  for (const d of (city && city.districts) || []) {
    for (const m of d.missions || []) {
      if (MONITORING_MODULES.has(m.module)) continue;
      const f = m.primary || {};
      const stale = !!(f.data && f.data.mark_stale === true);
      add({ id: m.id, kind: 'real', severity: m.severity, title: m.title, description: m.description || '', districtId: d.id,
        module: m.module, finding: f, missionId: m.id, fixable: !!m.fixable, marked: !!m.marked && !stale, stale, fp: fingerprint(f), count: 1 });
    }
    for (const n of d.notes || []) {
      if (MONITORING_MODULES.has(n.module)) continue;
      add({ id: findingIdentity(n), kind: 'real', severity: 'info', title: n.title || 'Something the checkup noted',
        description: n.description || '', districtId: d.id, module: n.module, finding: n, missionId: null, fixable: false,
        marked: false, stale: false, fp: fingerprint(n), count: 1 });
    }
    for (const g of d.fog || []) {
      if (MONITORING_MODULES.has(g.module)) continue;
      add({ id: `couldnt|${g.module}`, kind: 'couldnt', severity: 'couldnt', title: 'A check couldn’t run here',
        description: String(g.reason == null ? '' : g.reason), districtId: d.id, module: g.module, finding: null,
        missionId: null, fixable: false, marked: false, stale: false, fp: 'couldnt', count: 1 });
    }
  }
  return out;
}

export function compareSignals(a, b) {
  return (ORDER[a.severity] - ORDER[b.severity])
    || (Number(a.tag === 'closer') - Number(b.tag === 'closer'))
    || (DISTRICT_ORDER.indexOf(a.districtId) - DISTRICT_ORDER.indexOf(b.districtId))
    || String(a.title).localeCompare(String(b.title))
    || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

// LOOK CLOSER stays in the queue, after the untagged ones of the same severity.
export function queueOf(signals, filter = null) {
  const list = (signals || []).filter((x) => !filter || x.districtId === filter);
  const unsorted = (x) => !x.tag || x.tag === 'closer';
  const sorted = (xs) => xs.sort(compareSignals);
  return {
    urgent: sorted(list.filter((x) => unsorted(x) && x.severity !== 'info')),
    low: sorted(list.filter((x) => unsorted(x) && x.severity === 'info')),
    threats: sorted(list.filter((x) => x.tag === 'threat')),
    known: sorted(list.filter((x) => x.tag === 'mine')),
    noted: sorted(list.filter((x) => x.tag === 'noted')),
  };
}

export function sortedCount(signals) {
  return (signals || []).filter((x) => x.kind !== 'drill' && x.tag && x.tag !== 'closer').length;
}

// Open means the scan shows it now. Game tags don't close anything; the real
// "It's mine" step (data.marked_by_user) does, unless it changed since.
const isOpen = (x) => x.kind === 'real' && OPEN.has(x.severity) && !x.marked;

export function cityIntegrity(city, signals) {
  const openIn = new Set((signals || []).filter(isOpen).map((x) => x.districtId));
  const checkedIds = new Set();
  const securedIds = new Set();
  for (const d of (city && city.districts) || []) {
    if (!(d.checksRan > 0)) continue;
    checkedIds.add(d.id);
    if (!openIn.has(d.id)) securedIds.add(d.id);
  }
  const checked = checkedIds.size;
  const secured = securedIds.size;
  return { percent: checked ? Math.round((secured / checked) * 100) : null, checked, secured, checkedIds, securedIds };
}

export function districtHeat(city, signals) {
  const out = {};
  for (const x of (signals || []).filter(isOpen)) {
    out[x.districtId] = out[x.districtId] === 'hot' || x.severity === 'critical' ? 'hot' : 'warn';
  }
  return out;
}

// What a sweep record holds: counts only (see progress.js SWEEP_FIELDS).
export function sweepCounts(doc, city, integrity) {
  const t = (city && city.totals) || {};
  const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
  return {
    checks: mods.filter((m) => m && m.status === 'ok' && m.supported !== false).length,
    critical: t.critical || 0, warning: t.warning || 0, info: t.info || 0, fog: t.fog || 0,
    checked: (integrity && integrity.checked) || 0, secured: (integrity && integrity.secured) || 0,
  };
}
```

- [ ] **Step 4: Add `countDeckBars` to the end of `desktop/renderer/game/one-city.js`**

```js
// The deck's bars (and every HUD): CONFIRMED is device fixes a re-check
// proved (deck.confirmed) plus game missions finished from the checkup that it
// still confirms. A finding that's simply gone after a re-sweep isn't counted.
// YOU REPORTED is everything else the person filed as done. Never summed.
export function countDeckBars({ rc, deck, rcState, scanConfirmed, doc }) {
  const fixes = Object.keys((deck && deck.confirmed) || {}).length;
  if (!rc) return { confirmed: fixes, reported: 0 };
  const accounts = countConfirmedAndReported({ rc, progress: { missions: {} }, rcState, scanConfirmed, doc });
  return { confirmed: fixes + accounts.confirmed, reported: accounts.reported };
}
```

- [ ] **Step 5: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-signals.test.js`
Expected: PASS, every test.

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/signals.js desktop/renderer/game/one-city.js desktop/test/game-signals.test.js
git commit -m "Game: signals, the queue, and city integrity with fog excluded"
```

---

### Task 4: Clues, sourced place notes, "how to read this", and Scout's read

**Files:**
- Create: `desktop/renderer/game/clues.js`
- Test: `desktop/test/game-clues.test.js`

**Interfaces:**
- Consumes: the finding shape from `rescue scan --json` (`made_by` entries `{ subject, name, verified, how, location_note, what }`, and `data`); `DIAGNOSTIC_PHRASES` and `TIME_WORDS` from `training.js` (Plan C, test only); and a `Signal` from Task 3 for `scoutRead`.
- Produces:
  - `PLACES: { id, kind: 'prefix'|'contains', pattern, risky, short, note, source, quote }[]`
  - `READING: { verified, unverified, apple, place, placeUnknown, what, when }`, each `{ text, source, quote }`
  - `CLUE_LABEL = { maker: 'WHO MADE IT', where: 'WHERE IT LIVES', what: 'WHAT IT DOES', when: 'WHEN IT SHOWED UP' }`, plus `COULDNT_READ: string`
  - `homeRelative(path) -> string`, `placeFor(path) -> Place|null`
  - `pathOf(finding) -> string|null`, `whenOf(finding) -> 'YYYY-MM-DD'|null`
  - `Clue = { kind: 'maker'|'where'|'what'|'when', label, lines: string[], reading: READING[*] }`
  - `cluesFor(finding) -> Clue[]` (only the clues the evidence supports, in that order)
  - `drillClues(drill) -> Clue[]` (the same shape, built from `drill.clues`)
  - `scoutRead(signal, tag) -> string`, `drillRead(drill, right) -> string`

- [ ] **Step 1: Write the failing tests in `desktop/test/game-clues.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..', '..');
const load = () => import('../renderer/game/clues.js');
const norm = (s) => String(s).replace(/\s+/g, ' ');
const src = (rel) => norm(fs.readFileSync(path.join(ROOT, rel), 'utf8'));

// The same kind of gate as game-lessons.test.js: every claim names a source,
// and the source says it.
test('every place note and every how-to-read line is sourced: its file holds its pattern and its quote word for word', async () => {
  const { PLACES, READING } = await load();
  assert.strictEqual(new Set(PLACES.map((p) => p.id)).size, PLACES.length);
  for (const p of PLACES) {
    assert.ok(['prefix', 'contains'].includes(p.kind), p.id);
    assert.ok(fs.existsSync(path.join(ROOT, p.source)), `${p.id}: no ${p.source}`);
    const text = src(p.source);
    assert.ok(text.includes(p.pattern), `${p.id}: "${p.pattern}" isn’t in ${p.source}`);
    assert.ok(text.includes(norm(p.quote)), `${p.id}: its quote isn’t in ${p.source}`);
    assert.ok(p.note && p.short, p.id);
  }
  for (const [key, r] of Object.entries(READING)) {
    assert.ok(fs.existsSync(path.join(ROOT, r.source)), `${key}: no ${r.source}`);
    assert.ok(src(r.source).includes(norm(r.quote)), `${key}: its quote isn’t in ${r.source}`);
    assert.ok(r.text, key);
  }
});

test('no clue text diagnoses this computer or names a duration', async () => {
  const { PLACES, READING, COULDNT_READ } = await load();
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await import('../renderer/game/training.js');
  for (const text of [...PLACES.map((p) => p.note), ...Object.values(READING).map((r) => r.text), COULDNT_READ]) {
    for (const phrase of DIAGNOSTIC_PHRASES) assert.ok(!text.toLowerCase().includes(phrase), text);
    assert.doesNotMatch(text, TIME_WORDS, text);
  }
});

test('placeFor: home folders, /private/tmp, Windows paths, and places with no note', async () => {
  const { placeFor } = await load();
  const id = (p) => (placeFor(p) || {}).id || null;
  assert.strictEqual(id('/Users/ann/Library/LaunchAgents/com.x.plist'), 'user-launch-agents');
  assert.strictEqual(id('/Library/LaunchAgents/com.x.plist'), 'launch-agents');
  assert.strictEqual(id('/Library/LaunchDaemons/com.x.plist'), 'launch-daemons');
  assert.strictEqual(id('/private/tmp/x'), 'tmp');
  assert.strictEqual(id('/home/ann/.config/autostart/x.desktop'), 'hidden-config');
  assert.strictEqual(id('C:\\Users\\ann\\AppData\\Local\\Temp\\x.exe'), 'windows-temp');
  assert.strictEqual(id('C:\\Program Files\\Zoom\\zoom.exe'), 'program-files');
  assert.strictEqual(id('/Users/ann/Downloads/setup'), 'downloads');
  assert.strictEqual(id('/tmpfoo/x'), null, 'a prefix matches whole folder names only');
  assert.strictEqual(id('/opt/thing/bin'), null);
  assert.strictEqual(placeFor(''), null);
  assert.strictEqual(placeFor(null), null);
});

test('clues come only from evidence the finding has, in a fixed order', async () => {
  const { cluesFor, placeFor, READING } = await load();
  const full = cluesFor({ title: 't', description: 'Starts at login.\n\nWhat to do: remove it.',
    data: { program: '/tmp/x', first_seen: '2026-09-30T10:00:00Z' },
    made_by: [{ subject: '/tmp/x', name: 'Unknown maker', verified: false, how: 'unsigned', location_note: '' }] });
  assert.deepStrictEqual(full.map((c) => c.kind), ['maker', 'where', 'what', 'when']);
  assert.deepStrictEqual(full.map((c) => c.label), ['WHO MADE IT', 'WHERE IT LIVES', 'WHAT IT DOES', 'WHEN IT SHOWED UP']);
  assert.deepStrictEqual(full[0].lines, ['Unknown maker, not verified (unsigned)']);
  assert.strictEqual(full[0].reading, READING.unverified);
  assert.deepStrictEqual(full[1].lines, ['/tmp/x', placeFor('/tmp/x').note]);
  assert.strictEqual(full[1].reading, READING.place);
  assert.deepStrictEqual(full[2].lines, ['Starts at login.']);
  assert.deepStrictEqual(full[3].lines, ['2026-09-30']);
});

// Review Focus 2.
test('no made_by, no path, no date: only the clue it can support; no description either: none', async () => {
  const { cluesFor } = await load();
  assert.deepStrictEqual(cluesFor({ title: 't', description: 'Plain words.', data: { check: 'x', count: 3 } }).map((c) => c.kind), ['what']);
  assert.deepStrictEqual(cluesFor({ title: 't', description: '', data: {} }), []);
  assert.deepStrictEqual(cluesFor(null), []);
  assert.deepStrictEqual(cluesFor({ data: { first_seen: 'not a date', path: 'relative/x' }, made_by: 'nope' }), []);
});

test('who made it: verified, Apple, several programs, and the program’s description only when verified', async () => {
  const { cluesFor, READING } = await load();
  const v = cluesFor({ made_by: [{ name: 'Google LLC', verified: true, how: 'Developer ID signature', what: 'Chrome: a browser.' }] })[0];
  assert.deepStrictEqual(v.lines, ['Google LLC, verified (Developer ID signature)', 'Chrome: a browser.']);
  assert.strictEqual(v.reading, READING.verified);
  assert.strictEqual(cluesFor({ made_by: [{ name: 'Apple', verified: true, how: 'Apple system file' }] })[0].reading, READING.apple);
  const two = cluesFor({ made_by: [{ subject: '/Applications/A.app', name: 'A Co', verified: true, how: 'Developer ID signature' },
    { subject: '/tmp/b', name: '', verified: false, how: 'unsigned', what: 'never shown' }] })[0];
  assert.deepStrictEqual(two.lines, ['A.app: A Co, verified (Developer ID signature)', 'b: Unknown maker, not verified (unsigned)']);
  assert.strictEqual(two.reading, READING.unverified);
});

test('a place with no note still shows its path, with the plain how-to-read line', async () => {
  const { cluesFor, READING } = await load();
  assert.deepStrictEqual(cluesFor({ data: { path: '/opt/x/bin' } }), [{ kind: 'where', label: 'WHERE IT LIVES', lines: ['/opt/x/bin'], reading: READING.placeUnknown }]);
});

test('Scout’s read: says whether the scan agrees and why; never “wrong”; the person’s call stands', async () => {
  const { scoutRead } = await load();
  const sig = (severity, finding = {}, extra = {}) => ({ kind: 'real', severity, finding, marked: false, ...extra });
  const unsigned = { made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }], data: { program: '/tmp/x' } };
  const same = scoutRead(sig('critical', unsigned), 'threat');
  assert.match(same, /sees it the same way/);
  assert.match(same, /nobody has vouched for who made it/);
  const differ = scoutRead(sig('critical', unsigned), 'mine');
  assert.match(differ, /You called it yours\. Your call stands/);
  assert.match(scoutRead(sig('warning', { data: { program: '/tmp/x' } }), 'closer'), /it lives in a temporary folder/);
  const all = [same, differ, scoutRead(sig('warning', {}, { marked: true }), 'mine'),
    ...['mine', 'threat', 'closer'].flatMap((t) => ['critical', 'warning', 'info'].map((sv) => scoutRead(sig(sv), t)))];
  for (const line of all) assert.doesNotMatch(line, /\bwrong\b|incorrect|mistake/i, line);
});

test('a drill’s read: right, or the tell, and it costs nothing', async () => {
  const { drillRead } = await load();
  const d = { why: 'It runs from a hidden folder.' };
  assert.strictEqual(drillRead(d, true), 'Right. It runs from a hidden folder.');
  assert.match(drillRead(d, false), /^Not this time, and it costs you nothing\. The tell: It runs from a hidden folder\.$/);
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-clues.test.js`
Expected: FAIL with `Cannot find module '…/clues.js'`.

- [ ] **Step 3: Write `desktop/renderer/game/clues.js`**

```js
// Clues for Signal or Noise, built from a finding's own evidence, and Scout's
// read after the person tags it. Pure. Only clues the evidence supports are
// made. Every place note and every "how to read this" line names a file in
// this repo and a phrase from it; desktop/test/game-clues.test.js checks both.
const LAUNCH = { source: 'guides/remediation/review_launch_persistence.md', quote: 'starts on every login' };
const TEMP = { source: 'rescue/attribution.py', quote: 'a temporary folder any program can write to' };
const HIDDEN = { source: 'guides/remediation/clean_ai_worm_filesystem.md', quote: 'dropped scripts under' };
const CRON = { source: 'guides/remediation/review_cron_jobs.md', quote: 'system crontabs' };

// Most specific first. `prefix` matches whole folder names from the start of
// the path (after ~ for a home folder); `contains` matches whole folder names
// anywhere, for Windows paths.
export const PLACES = [
  { id: 'user-launch-agents', kind: 'prefix', pattern: '~/Library/LaunchAgents', risky: false, short: 'your launch agents folder',
    note: 'Things set to start on their own when you log in.', ...LAUNCH },
  { id: 'launch-agents', kind: 'prefix', pattern: '/Library/LaunchAgents', risky: false, short: 'the launch agents folder',
    note: 'Things set to start on their own when someone logs in.', ...LAUNCH },
  { id: 'launch-daemons', kind: 'prefix', pattern: '/Library/LaunchDaemons', risky: false, short: 'the launch daemons folder',
    note: 'Background jobs for the whole computer. They run with full control of it.',
    source: 'guides/remediation/respond_to_malware_indicators.md', quote: 'system-wide, runs as root' },
  { id: 'tmp', kind: 'prefix', pattern: '/tmp', risky: true, short: 'a temporary folder',
    note: 'A temporary folder any program can write to. Installed apps don’t normally run from here.', ...TEMP },
  { id: 'var-tmp', kind: 'prefix', pattern: '/var/tmp', risky: true, short: 'a temporary folder',
    note: 'A temporary folder any program can write to. Installed apps don’t normally run from here.', ...TEMP },
  { id: 'hidden-cache', kind: 'prefix', pattern: '~/.cache', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'hidden-config', kind: 'prefix', pattern: '~/.config', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'hidden-local-bin', kind: 'prefix', pattern: '~/.local/bin', risky: true, short: 'a hidden folder in your home folder',
    note: 'A hidden folder in your home folder. Apps keep files here, and dropped scripts hide here too.', ...HIDDEN },
  { id: 'app-support', kind: 'prefix', pattern: '~/Library/Application Support', risky: false, short: 'your apps’ own files',
    note: 'Where apps keep their own files. An unfamiliar name here is worth a look.',
    source: 'guides/remediation/remove_cryptominer.md', quote: 'under an unfamiliar name' },
  { id: 'applications', kind: 'prefix', pattern: '/Applications', risky: false, short: 'the Applications folder',
    note: 'Where Mac apps are normally installed.',
    source: 'guides/remediation/investigate_keylogger_indicators.md', quote: 'check its install location' },
  { id: 'cron-d', kind: 'prefix', pattern: '/etc/cron.d', risky: false, short: 'the system’s scheduled jobs',
    note: 'Scheduled jobs for the whole computer.', ...CRON },
  { id: 'crontab', kind: 'prefix', pattern: '/etc/crontab', risky: false, short: 'the system’s scheduled jobs',
    note: 'Scheduled jobs for the whole computer.', ...CRON },
  { id: 'hosts', kind: 'prefix', pattern: '/etc/hosts', risky: false, short: 'the hosts file',
    note: 'A small file that can send website names to different addresses, ahead of the internet’s normal lookup.',
    source: 'guides/remediation/clean_hosts_file.md', quote: 'overrides DNS entirely' },
  { id: 'windows-temp', kind: 'contains', pattern: 'AppData\\Local\\Temp', risky: true, short: 'a temporary folder (Temp)',
    note: 'A temporary folder. Installed software doesn’t normally run from here.',
    source: 'guides/remediation/audit_windows_autoruns.md', quote: 'not a scratch/download location' },
  { id: 'downloads', kind: 'contains', pattern: 'Downloads', risky: true, short: 'your Downloads folder',
    note: 'Your Downloads folder, where files from the internet land. Installed software doesn’t normally run from here.',
    source: 'rescue/attribution.py', quote: 'where files from the internet land' },
  { id: 'program-files', kind: 'contains', pattern: 'Program Files', risky: false, short: 'Program Files',
    note: 'Where Windows programs are normally installed.',
    source: 'guides/remediation/audit_windows_autoruns.md', quote: 'legitimate installed software runs from `Program Files`' },
];

export const READING = {
  verified: { text: 'Verified signature: the maker’s seal is real and names who made it. It tells you who made it, not that it’s safe or that you wanted it.',
    source: 'desktop/renderer/app.js', quote: 'means the seal is real and names the maker' },
  unverified: { text: 'Not verified: nobody has vouched for who made it. That isn’t proof of anything bad, so look at where it lives too.',
    source: 'desktop/renderer/app.js', quote: 'is not proof of anything bad, but nobody has vouched for it' },
  apple: { text: 'Part of macOS: this file comes with the operating system.',
    source: 'desktop/renderer/app.js', quote: "'Apple system file': 'part of macOS'" },
  place: { text: 'Where something lives often tells you more than its name. A temporary or hidden folder is a stronger warning sign than an app’s own install folder.',
    source: 'guides/remediation/review_launch_persistence.md', quote: 'a program path in `/tmp`, `/var/tmp`, or a hidden directory' },
  placeUnknown: { text: 'This is where the scan found it. Device Rescue has no note about this place, so the other clues matter more.',
    source: 'guides/remediation/review_launch_persistence.md', quote: 'reported in the finding' },
  what: { text: 'This is the checkup’s own plain-language description of what it found.',
    source: 'AGENTS.md', quote: 'plain-language explanation' },
  when: { text: 'The date the scan recorded for it. Did you install something around then? If you didn’t, something else may have.',
    source: 'guides/remediation/review_changes_since_baseline.md', quote: "did I install something around then? If you didn't, something else may have." },
};

export const CLUE_LABEL = { maker: 'WHO MADE IT', where: 'WHERE IT LIVES', what: 'WHAT IT DOES', when: 'WHEN IT SHOWED UP' };
export const COULDNT_READ = 'Noted. This check couldn’t run, so nothing here was looked at. That doesn’t mean it’s safe.';

// Data fields that hold the path of the thing a finding names, most useful first.
const PATH_KEYS = ['program', 'path', 'plist', 'file', 'executable', 'target'];
// Only dates the scan recorded. Most findings have none, and then there's no clue.
const DATE_KEYS = ['first_seen', 'created', 'installed', 'modified', 'date'];
const looksLikePath = (v) => typeof v === 'string' && v.length < 1024 && (/^[~/]/.test(v) || /^[A-Za-z]:\\/.test(v));

export function homeRelative(p) {
  return String(p == null ? '' : p).trim()
    .replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)/, '~')
    .replace(/^\/private(?=\/(?:tmp|var\/tmp)(?:\/|$))/, '');
}

const underPrefix = (p, prefix) => p === prefix || p.startsWith(`${prefix}/`);
const hasFolder = (p, part) => `/${p.replace(/\\/g, '/').toLowerCase()}/`.includes(`/${part.replace(/\\/g, '/').toLowerCase()}/`);

export function placeFor(path) {
  if (typeof path !== 'string' || path === '') return null;
  const p = homeRelative(path);
  return PLACES.find((pl) => (pl.kind === 'prefix' ? underPrefix(p, pl.pattern) : hasFolder(p, pl.pattern))) || null;
}

const dataOf = (finding) => (finding && finding.data && typeof finding.data === 'object' ? finding.data : {});

export function pathOf(finding) {
  const d = dataOf(finding);
  for (const k of PATH_KEYS) if (looksLikePath(d[k])) return d[k];
  return null;
}

export function whenOf(finding) {
  const d = dataOf(finding);
  for (const k of DATE_KEYS) {
    const v = d[k];
    if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v) && !Number.isNaN(Date.parse(v))) return v.slice(0, 10);
  }
  return null;
}

function makerClue(entries) {
  const several = entries.length > 1;
  const lines = [];
  for (const e of entries) {
    const name = typeof e.name === 'string' && e.name.trim() ? e.name.trim() : 'Unknown maker';
    const how = typeof e.how === 'string' && e.how.trim() ? ` (${e.how.trim()})` : '';
    const sub = several && typeof e.subject === 'string' ? (e.subject.split(/[\\/]/).filter(Boolean).pop() || '') : '';
    lines.push(`${sub ? `${sub}: ` : ''}${name}, ${e.verified === true ? 'verified' : 'not verified'}${how}`);
    // The engine only says what a program is for when its signature proved which program it is.
    if (e.verified === true && typeof e.what === 'string' && e.what.trim()) lines.push(e.what.trim());
  }
  const allVerified = entries.every((e) => e.verified === true);
  const reading = allVerified && entries.some((e) => e.how === 'Apple system file') ? READING.apple
    : allVerified ? READING.verified : READING.unverified;
  return { kind: 'maker', label: CLUE_LABEL.maker, lines, reading };
}

export function cluesFor(finding) {
  if (!finding || typeof finding !== 'object') return [];
  const out = [];
  const entries = Array.isArray(finding.made_by) ? finding.made_by.filter((e) => e && typeof e === 'object') : [];
  if (entries.length) out.push(makerClue(entries));
  const where = pathOf(finding);
  if (where) {
    const place = placeFor(where);
    out.push({ kind: 'where', label: CLUE_LABEL.where, lines: place ? [where, place.note] : [where],
      reading: place ? READING.place : READING.placeUnknown });
  }
  // The description's first paragraph, before any "What to do".
  const what = String(finding.description || '').split(/\n\s*\n/)[0].split(/what to do:?/i)[0].trim().slice(0, 400);
  if (what) out.push({ kind: 'what', label: CLUE_LABEL.what, lines: [what], reading: READING.what });
  const when = whenOf(finding);
  if (when) out.push({ kind: 'when', label: CLUE_LABEL.when, lines: [when], reading: READING.when });
  return out;
}

export function drillClues(drill) {
  const c = (drill && drill.clues) || {};
  return cluesFor({ made_by: c.maker ? [c.maker] : [], data: { path: c.path || undefined, first_seen: c.when || undefined }, description: c.what || '' });
}

// The scan's own view of a signal, in tag terms: critical leans THREAT, a
// warning leans LOOK CLOSER, info leans MINE, and a real mark is MINE.
const VIEW = { critical: 'threat', warning: 'closer', info: 'mine' };
const VIEW_LINE = { critical: 'The checkup marked this critical', warning: 'The checkup marked this worth a look', info: 'The checkup only noted this' };
const TAG_WORD = { mine: 'yours', threat: 'a threat', closer: 'worth a closer look' };

function clueReason(sig) {
  const f = sig.finding || {};
  const mb = Array.isArray(f.made_by) ? f.made_by.filter((e) => e && typeof e === 'object') : [];
  if (sig.marked) return 'you told Device Rescue it’s yours';
  if (mb.some((e) => e.verified !== true)) return 'nobody has vouched for who made it';
  const place = placeFor(pathOf(f));
  if (place && place.risky) return `it lives in ${place.short}`;
  if (mb.length) return 'its maker’s signature checked out, which says who made it, not that it’s safe';
  return '';
}

// Never "wrong": the person's call stands, and a tag only sorts the game.
export function scoutRead(sig, tag) {
  const view = sig.marked ? 'mine' : VIEW[sig.severity] || 'closer';
  const head = sig.marked ? 'You marked this as yours on this computer' : VIEW_LINE[sig.severity] || 'The checkup flagged this';
  const why = clueReason(sig);
  const clue = why ? ` One clue: ${why}.` : '';
  if (tag === view) return `${head}, so the scan sees it the same way.${clue}`;
  return `${head}.${clue} You called it ${TAG_WORD[tag] || 'something else'}. Your call stands; it only changes how the game sorts it.`;
}

export function drillRead(drill, right) {
  const why = (drill && drill.why) || '';
  return right ? `Right. ${why}` : `Not this time, and it costs you nothing. The tell: ${why}`;
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-clues.test.js`
Expected: PASS, every test. If a quote check fails, the source file changed. Fix the quote so it matches the source word for word; never loosen the test.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/clues.js desktop/test/game-clues.test.js
git commit -m "Game: sourced clues, how-to-read lines and Scout's read"
```

---

### Task 5: The drill bank, its accuracy gate, and mixing drills into the queue

**Files:**
- Create: `desktop/renderer/game/drills.js`, `desktop/renderer/game/drills/gatehouse.js`, `desktop/renderer/game/drills/wires.js`, `desktop/renderer/game/drills/engine-room.js`, `desktop/renderer/game/drills/junkyard.js`
- Test: `desktop/test/game-drills.test.js`

**Interfaces:**
- Consumes: `placeFor`, `drillClues` and `READING` (Task 4); `cityIntegrity` and `sortedCount` (Task 3); `reconcileDeck` and `MONITORING_MODULES` (Task 2); `emptyDeck` (Task 1); `DISTRICTS` and `districtIdFor` (Plan C); `DIAGNOSTIC_PHRASES` and `TIME_WORDS` (Plan C, test only); `MADE_BY_VERIFIED_LABEL` and `MADE_BY_REASON` from `app.js` (test only).
- Produces:
  - `Drill = { id, district, severity: 'critical'|'warning'|'info', modules: string[], title, setup: string, clues: { maker: {name, verified, how}|null, path: string|null, what: string, when: 'YYYY-MM-DD'|null }, answer: 'mine'|'threat'|'closer', why, sources: string[] }`
  - `DRILL_FILES: string[]` (specifiers relative to the game folder), `MAX_DRILLS = 3`, `DRILL_ANSWERS`, `MONITORING_WORDS: RegExp`
  - `loadDrills(importModule) -> Promise<Drill[]>` (never rejects; a bad file is left out)
  - `drillCount(realCount) -> int`, `pickDrills(bank, districtIds, deck, seed = 0) -> Drill[]`, `chooseDrills(bank, realSignals, deck, seed = 0) -> Drill[]`
  - `drillSignal(drill) -> Signal` with `kind: 'drill'`, `id: 'drill:<id>'`, `tag: null` and `drill`
  - `mixDrills(realSignals, drills) -> Signal[]`

- [ ] **Step 1: Write the failing tests in `desktop/test/game-drills.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const imp = (rel) => import(pathToFileURL(path.join(GAME, rel)).href);
// The same specifiers the controller passes, mapped onto files on disk.
const loadAll = async () => {
  const drills = await imp('drills.js');
  return { drills, bank: await drills.loadDrills((spec) => imp(spec)) };
};
const norm = (s) => String(s).replace(/\s+/g, ' ');
const sourceText = (d) => norm(d.sources.map((s) => fs.readFileSync(path.join(ROOT, s), 'utf8')).join('\n'));
// The lessons' gate (game-lessons.test.js): UI paths and backticked text must be word for word in a source.
const SEG = "[A-Z][\\w&]*(?: [\\w&]+)*";
const PATH_RE = new RegExp(`${SEG}(?: (?:>|→) ${SEG})+`, 'g');
const TICKS_RE = /`([^`]+)`/g;
function unsourced(text, src) {
  const bad = [];
  for (const p of norm(text).match(PATH_RE) || []) if (!src.includes(p)) bad.push(`UI path "${p}"`);
  for (const [, inner] of norm(text).matchAll(TICKS_RE)) if (!src.includes(inner)) bad.push(`\`${inner}\``);
  return bad;
}
const ownText = (d) => [d.title, d.setup, d.clues.what, d.why].filter((t) => typeof t === 'string' && t);
function moduleDistricts(name, districtIdFor) {
  const mods = path.join(ROOT, 'modules');
  return fs.readdirSync(mods).filter((cat) => fs.existsSync(path.join(mods, cat, name))).map((cat) => districtIdFor(cat));
}

test('every drill file loads and adds drills; ids are unique', async () => {
  const { drills, bank } = await loadAll();
  assert.ok(bank.length >= 12, `${bank.length} drills`);
  assert.strictEqual(new Set(bank.map((d) => d.id)).size, bank.length);
  for (const f of drills.DRILL_FILES) {
    const m = await imp(f);
    assert.ok(Array.isArray(m.default) && m.default.length >= 2, f);
  }
});

test('every drill has what the panel needs, and every tag is the right answer somewhere', async () => {
  const { bank } = await loadAll();
  const { DISTRICTS } = await imp('findings-to-city.js');
  const ids = new Set(DISTRICTS.map((d) => d.id));
  for (const d of bank) {
    assert.ok(ids.has(d.district), `${d.id}: district ${d.district}`);
    assert.ok(['critical', 'warning', 'info'].includes(d.severity), d.id);
    assert.ok(['mine', 'threat', 'closer'].includes(d.answer), d.id);
    assert.ok(d.title && d.why && d.clues && d.clues.what && typeof d.setup === 'string', d.id);
    assert.ok(d.clues.when === null || /^\d{4}-\d{2}-\d{2}$/.test(d.clues.when), d.id);
    assert.ok(d.clues.path === null || typeof d.clues.path === 'string', d.id);
    const m = d.clues.maker;
    assert.ok(m === null || (typeof m.name === 'string' && typeof m.verified === 'boolean' && typeof m.how === 'string'), d.id);
  }
  assert.deepStrictEqual([...new Set(bank.map((d) => d.answer))].sort(), ['closer', 'mine', 'threat']);
});

test('every drill cites sources that exist, and modules that exist and sweep its district', async () => {
  const { bank } = await loadAll();
  const { districtIdFor } = await imp('findings-to-city.js');
  const { MONITORING_MODULES } = await imp('ledger.js');
  for (const d of bank) {
    assert.ok(Array.isArray(d.sources) && d.sources.length, `${d.id} has no sources`);
    for (const s of d.sources) assert.ok(fs.existsSync(path.join(ROOT, s)), `${d.id}: missing source ${s}`);
    assert.ok(Array.isArray(d.modules) && d.modules.length, `${d.id} names no module`);
    const backed = new Set(d.modules.flatMap((m) => moduleDistricts(m, districtIdFor)));
    for (const m of d.modules) {
      assert.ok(moduleDistricts(m, districtIdFor).length, `${d.id}: no module ${m}`);
      assert.ok(!MONITORING_MODULES.has(m), `${d.id}: no drills about monitoring software`);
    }
    assert.ok(backed.has(d.district), `${d.id}: none of its modules is swept in ${d.district}`);
  }
});

test('every drill path is a place with a sourced note, and the drill’s own sources name that place', async () => {
  const { bank } = await loadAll();
  const { placeFor } = await imp('clues.js');
  for (const d of bank.filter((x) => x.clues.path)) {
    const place = placeFor(d.clues.path);
    assert.ok(place, `${d.id}: no sourced place for ${d.clues.path}`);
    assert.ok(sourceText(d).includes(place.pattern), `${d.id}: its sources don’t name ${place.pattern}`);
  }
});

test('who made it uses the engine’s own words, and every how-to-read line is a sourced one', async () => {
  const { bank } = await loadAll();
  const { MADE_BY_VERIFIED_LABEL, MADE_BY_REASON } = require('../renderer/app.js');
  const { drillClues, READING } = await imp('clues.js');
  const lines = new Set(Object.values(READING));
  for (const d of bank) {
    const m = d.clues.maker;
    if (m && m.verified) assert.ok(m.how in MADE_BY_VERIFIED_LABEL, `${d.id}: "${m.how}" isn’t a verified kind the app knows`);
    if (m && !m.verified) assert.ok(m.how in MADE_BY_REASON || m.how === 'script', `${d.id}: "${m.how}" isn’t a reason the app knows`);
    const cs = drillClues(d);
    assert.ok(cs.length >= 2, `${d.id}: at least two clues, so the clue bonus can be earned`);
    for (const c of cs) assert.ok(lines.has(c.reading), `${d.id}: ${c.kind} has an unsourced reading`);
  }
});

test('no drill diagnoses this computer, names a duration, touches monitoring, or makes up a UI path', async () => {
  const { drills, bank } = await loadAll();
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await imp('training.js');
  for (const d of bank) {
    const src = sourceText(d);
    for (const text of ownText(d)) {
      for (const phrase of DIAGNOSTIC_PHRASES) assert.ok(!text.toLowerCase().includes(phrase), `${d.id}: "${phrase}"`);
      assert.doesNotMatch(text, TIME_WORDS, `${d.id}: time word in "${text}"`);
      assert.doesNotMatch(text, drills.MONITORING_WORDS, `${d.id}: no drills about monitoring or being watched`);
      assert.deepStrictEqual(unsourced(text, src), [], `${d.id}: not word for word in its sources`);
    }
  }
});

test('the gate catches a made-up place', async () => {
  const { placeFor } = await imp('clues.js');
  assert.strictEqual(placeFor('/Users/x/Secret Stash/run'), null);
  assert.strictEqual(placeFor('C:\\Hidden\\x.exe'), null);
});

test('about one drill per four real signals, at most three', async () => {
  const { drillCount, MAX_DRILLS } = await imp('drills.js');
  assert.deepStrictEqual([0, 1, 4, 5, 8, 9, 12, 40].map(drillCount), [0, 1, 1, 2, 2, 3, 3, 3]);
  assert.strictEqual(MAX_DRILLS, 3);
});

test('drills come from the districts in the real queue, fresh ones first', async () => {
  const { chooseDrills, pickDrills } = await imp('drills.js');
  const { emptyDeck } = await imp('progress.js');
  const bank = [{ id: 'g1', district: 'gatehouse' }, { id: 'g2', district: 'gatehouse' }, { id: 'j1', district: 'junkyard' }, { id: 'w1', district: 'wires' }];
  const real = (district, n) => Array.from({ length: n }, (_, i) => ({ id: `${district}${i}`, kind: 'real', districtId: district }));
  assert.deepStrictEqual(chooseDrills(bank, real('gatehouse', 5), emptyDeck(), 0).map((d) => d.id), ['g1', 'g2']);
  assert.deepStrictEqual(chooseDrills(bank, [...real('gatehouse', 4), ...real('junkyard', 4)], emptyDeck(), 0).map((d) => d.id), ['g1', 'j1']);
  assert.deepStrictEqual(chooseDrills(bank, real('foundations', 8), emptyDeck(), 0), [], 'no drill from a district that isn’t in the queue');
  assert.deepStrictEqual(chooseDrills(bank, [], emptyDeck(), 0), [], 'zero findings: no drills mixed in');
  const done = { ...emptyDeck(), once: { 'drill:g1': true } };
  assert.deepStrictEqual(pickDrills(bank, ['gatehouse'], done, 0).map((d) => d.id), ['g2', 'g1']);
  assert.deepStrictEqual(pickDrills(bank, ['gatehouse'], emptyDeck(), 1).map((d) => d.id), ['g2', 'g1'], 'the seed rotates which comes first');
});

test('drills sit after every fourth real signal, the rest at the end', async () => {
  const { mixDrills, drillSignal } = await imp('drills.js');
  const real = Array.from({ length: 5 }, (_, i) => ({ id: `r${i}` }));
  const d = (id) => ({ id, district: 'gatehouse', severity: 'warning', title: id, clues: { what: 'w' } });
  assert.deepStrictEqual(mixDrills(real, [d('a'), d('b')]).map((x) => x.id), ['r0', 'r1', 'r2', 'r3', 'drill:a', 'r4', 'drill:b']);
  const s = drillSignal(d('a'));
  assert.deepStrictEqual([s.kind, s.tag, s.missionId, s.finding, s.districtId], ['drill', null, null, null, 'gatehouse']);
});

test('a drill never counts in integrity, sorted, or the deck’s tags', async () => {
  const { drillSignal } = await imp('drills.js');
  const { cityIntegrity, sortedCount } = await imp('signals.js');
  const { reconcileDeck } = await imp('ledger.js');
  const { emptyDeck } = await imp('progress.js');
  const city = { districts: [{ id: 'gatehouse', checksRan: 1, missions: [], notes: [], fog: [] }] };
  const sigs = [{ ...drillSignal({ id: 'a', district: 'gatehouse', severity: 'critical', title: 'a', clues: { what: 'w' } }), tag: 'threat' }];
  assert.strictEqual(cityIntegrity(city, sigs).percent, 100);
  assert.strictEqual(sortedCount(sigs), 0);
  assert.deepStrictEqual(reconcileDeck(emptyDeck(), sigs, new Set()).deck.tags, {});
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-drills.test.js`
Expected: FAIL with `Cannot find module '…/drills.js'`.

- [ ] **Step 3: Write `desktop/renderer/game/drills.js`**

```js
// The drill bank: invented findings for practice, kept as data files beside
// the lessons. Pure, except loadDrills, which takes the import function it
// should use. A drill is always stamped DRILL, never counted in integrity,
// sorted, confirmed or reported, and never about monitoring software.
export const DRILL_FILES = ['./drills/gatehouse.js', './drills/wires.js', './drills/engine-room.js', './drills/junkyard.js'];
export const MAX_DRILLS = 3;
export const DRILL_ANSWERS = ['mine', 'threat', 'closer'];
// Words no drill may use (desktop/test/game-drills.test.js).
export const MONITORING_WORDS = /stalker|monitor|spy|keylog|watching|being watched|track(?:s|ing)? (?:you|someone)/i;

// One file at a time: a broken file is left out, never the whole bank.
export async function loadDrills(importModule) {
  const results = await Promise.allSettled(DRILL_FILES.map((f) => Promise.resolve().then(() => importModule(f)).then((m) => m && m.default)));
  const out = [];
  const ids = new Set();
  for (const r of results) {
    if (r.status !== 'fulfilled' || !Array.isArray(r.value)) continue;
    for (const d of r.value) {
      if (d && typeof d.id === 'string' && !ids.has(d.id) && DRILL_ANSWERS.includes(d.answer)) { ids.add(d.id); out.push(d); }
    }
  }
  return out;
}

// About one per four real signals, at most three.
export function drillCount(realCount) {
  return Math.min(MAX_DRILLS, Math.ceil(Math.max(0, Number(realCount) || 0) / 4));
}

// Drills for these districts. The ones already answered right come last; the
// seed rotates which one comes first, so a new sweep offers a different one.
export function pickDrills(bank, districtIds, deck, seed = 0) {
  const want = new Set(districtIds || []);
  const pool = (bank || []).filter((d) => d && want.has(d.district));
  const right = (d) => !!(deck && deck.once && deck.once[`drill:${d.id}`]);
  const rotate = (xs) => {
    if (xs.length < 2) return xs;
    const k = ((Math.floor(Number(seed) || 0) % xs.length) + xs.length) % xs.length;
    return [...xs.slice(k), ...xs.slice(0, k)];
  };
  return [...rotate(pool.filter((d) => !right(d))), ...rotate(pool.filter(right))];
}

// This sweep's drills, drawn from the districts the real queue is in, taking
// turns across those districts in the queue's order.
export function chooseDrills(bank, realSignals, deck, seed = 0) {
  const real = (realSignals || []).filter((x) => x && x.kind === 'real');
  const n = drillCount(real.length);
  if (!n) return [];
  const districts = [...new Set(real.map((x) => x.districtId))];
  const lists = districts.map((id) => pickDrills(bank, [id], deck, seed));
  const out = [];
  for (let round = 0; out.length < n && lists.some((l) => l.length > round); round += 1) {
    for (const l of lists) if (out.length < n && l[round]) out.push(l[round]);
  }
  return out;
}

export function drillSignal(d) {
  return { id: `drill:${d.id}`, kind: 'drill', severity: d.severity, title: d.title,
    description: (d.clues && d.clues.what) || '', districtId: d.district, module: null, finding: null,
    missionId: null, fixable: false, marked: false, stale: false, fp: 'drill', count: 1, tag: null, changed: false, drill: d };
}

// A drill after every fourth real signal; any left over go at the end.
export function mixDrills(real, drills) {
  const out = [];
  let k = 0;
  (real || []).forEach((x, i) => {
    out.push(x);
    if ((i + 1) % 4 === 0 && k < drills.length) { out.push(drillSignal(drills[k])); k += 1; }
  });
  while (k < (drills || []).length) { out.push(drillSignal(drills[k])); k += 1; }
  return out;
}
```

- [ ] **Step 4: Write `desktop/renderer/game/drills/gatehouse.js`**

```js
// Practice signals for The Gatehouse. Invented: none of this is on the
// person's computer. Each path's place, each maker word and each text is
// checked against the cited sources by desktop/test/game-drills.test.js.
export default [
  {
    id: 'upd8r-hidden-cache',
    district: 'gatehouse',
    severity: 'warning',
    modules: ['launch_agent_audit'],
    title: 'A helper you don’t recognise starts at login',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'unsigned' },
      path: '~/.cache/.u/upd8r',
      what: 'A background item set to start every time you log in. It runs a program called upd8r.',
      when: '2026-09-30',
    },
    answer: 'threat',
    why: 'Nobody has vouched for who made it, and it runs from a hidden folder in your home folder. A program in a temporary or hidden folder is one of the strongest warning signs the checkup looks for.',
    sources: ['guides/remediation/clean_ai_worm_filesystem.md', 'guides/remediation/review_launch_persistence.md', 'desktop/renderer/game/lessons/starts-on-its-own.js'],
  },
  {
    id: 'zoom-helper-signed',
    district: 'gatehouse',
    severity: 'info',
    modules: ['launchd_persistence_audit'],
    title: 'A video-call helper starts at login',
    setup: 'Practice setup: you use Zoom for work calls.',
    clues: {
      maker: { name: 'Zoom Video Communications, Inc.', verified: true, how: 'Developer ID signature' },
      path: '/Applications/zoom.us.app',
      what: 'A background helper for the Zoom app, set to start when you log in.',
      when: null,
    },
    answer: 'mine',
    why: 'A verified signature names the maker, and it lives where Mac apps are installed. You use Zoom, so this is the ordinary case. The signature tells you who made it, not that you wanted it; knowing you use the app is what makes it yours.',
    sources: ['guides/remediation/investigate_keylogger_indicators.md', 'desktop/renderer/app.js'],
  },
  {
    id: 'tmp-script-agent',
    district: 'gatehouse',
    severity: 'critical',
    modules: ['launch_agent_audit'],
    title: 'A background job runs a script from /tmp',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'script' },
      path: '/tmp/.sys/run.sh',
      what: 'A background job set to start at login. It runs a script.',
      when: null,
    },
    answer: 'threat',
    why: 'It runs from /tmp, a temporary folder any program can write to, and a script carries no signature at all. Installed apps don’t run from there.',
    sources: ['rescue/attribution.py', 'guides/remediation/review_launch_persistence.md'],
  },
  {
    id: 'sync-keepalive',
    district: 'gatehouse',
    severity: 'info',
    modules: ['launchd_persistence_audit'],
    title: 'A sync app restarts itself and starts at login',
    setup: 'Practice setup: you use Dropbox to share files.',
    clues: {
      maker: { name: 'Dropbox, Inc', verified: true, how: 'Developer ID signature' },
      path: '/Applications/Dropbox.app',
      what: 'A background item set to restart itself and to start at every login.',
      when: null,
    },
    answer: 'mine',
    why: 'Sync clients and VPN helpers restart themselves on purpose. This one is signed by its maker, lives where Mac apps are installed, and you use it.',
    sources: ['guides/remediation/review_launch_persistence.md', 'guides/remediation/investigate_keylogger_indicators.md'],
  },
  {
    id: 'unfamiliar-app-support',
    district: 'gatehouse',
    severity: 'warning',
    modules: ['launch_agent_audit'],
    title: 'A program in an app folder with an unfamiliar name',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'ad-hoc signed' },
      path: '~/Library/Application Support/.cfgd/cfgd',
      what: 'A program in a folder you don’t remember, set to start at login.',
      when: null,
    },
    answer: 'closer',
    why: 'It’s only self-signed by whoever built it, and the folder name is unfamiliar. That’s worth a closer look before you decide. On its own it isn’t proof of anything bad.',
    sources: ['guides/remediation/remove_cryptominer.md', 'desktop/renderer/app.js'],
  },
  {
    id: 'hosts-bank-redirect',
    district: 'gatehouse',
    severity: 'critical',
    modules: ['hosts_file_check'],
    title: 'Your hosts file sends your bank’s name somewhere else',
    setup: '',
    clues: {
      maker: null,
      path: '/etc/hosts',
      what: 'A line in this file sends the name of your bank’s website to an address that isn’t your bank’s.',
      when: null,
    },
    answer: 'threat',
    why: 'This file overrides the internet’s normal lookup for the names in it. Sending a bank’s name somewhere else is the most severe case the checkup looks for here.',
    sources: ['guides/remediation/clean_hosts_file.md'],
  },
  {
    id: 'dev-cert-app',
    district: 'gatehouse',
    severity: 'warning',
    modules: ['code_signature_audit'],
    title: 'An app signed with a developer’s test certificate',
    setup: 'Practice setup: you didn’t build this app, and you don’t remember installing it.',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'development certificate' },
      path: '/Applications/PhotoTool.app',
      what: 'An app in your Applications folder whose signature is a developer’s test certificate.',
      when: null,
    },
    answer: 'closer',
    why: 'A test certificate isn’t a published one, so nobody has vouched for this copy. You don’t remember installing it, so look closer at where it came from before you decide.',
    sources: ['desktop/renderer/app.js', 'guides/remediation/check_app_signatures.md', 'guides/remediation/investigate_keylogger_indicators.md'],
  },
];
```

- [ ] **Step 5: Write `desktop/renderer/game/drills/wires.js`**

```js
// Practice signals for The Wires. Invented: none of this is on the person's computer.
export default [
  {
    id: 'proxy-unknown',
    district: 'wires',
    severity: 'warning',
    modules: ['network_proxy_check'],
    title: 'A web proxy is set that you don’t remember',
    setup: 'Practice setup: this is your own laptop at home. No workplace or school manages it.',
    clues: {
      maker: null,
      path: null,
      what: 'Your network settings send web traffic through a proxy server.',
      when: '2026-10-12',
    },
    answer: 'threat',
    why: 'A proxy you didn’t set up can read and change your web traffic. On a home computer nobody manages, an unexplained proxy is a meaningful finding.',
    sources: ['guides/remediation/remove_unwanted_proxy.md'],
  },
  {
    id: 'proxy-work',
    district: 'wires',
    severity: 'info',
    modules: ['network_proxy_check'],
    title: 'A proxy is set on a work laptop',
    setup: 'Practice setup: this is a work laptop, and your IT team set up its network.',
    clues: {
      maker: null,
      path: null,
      what: 'Your network settings send web traffic through your workplace’s proxy server.',
      when: '2025-03-04',
    },
    answer: 'mine',
    why: 'Workplaces often route traffic through their own proxy, so this is expected. If you’re ever unsure, check with your IT department before changing anything.',
    sources: ['guides/remediation/remove_unwanted_proxy.md'],
  },
];
```

- [ ] **Step 6: Write `desktop/renderer/game/drills/engine-room.js`**

```js
// Practice signals for The Engine Room. Invented: none of this is on the person's computer.
export default [
  {
    id: 'busy-miner',
    district: 'engine-room',
    severity: 'critical',
    modules: ['resource_hog_identifier'],
    title: 'Something keeps your processor busy all the time',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'unsigned' },
      path: '/var/tmp/kworkerd',
      what: 'A program named kworkerd that uses most of your processor, even when you aren’t doing anything.',
      when: null,
    },
    answer: 'threat',
    why: 'It runs from /var/tmp, a temporary folder, with no signature, and it keeps the processor busy for no reason you know of. Those are signs of a hidden cryptocurrency miner.',
    sources: ['guides/remediation/remove_cryptominer.md', 'rescue/attribution.py'],
  },
  {
    id: 'busy-video-export',
    district: 'engine-room',
    severity: 'info',
    modules: ['resource_hog_identifier'],
    title: 'A video app is using a lot of the processor',
    setup: 'Practice setup: you’re exporting a video in iMovie right now.',
    clues: {
      maker: { name: 'Apple', verified: true, how: 'Mac App Store signature' },
      path: '/Applications/iMovie.app',
      what: 'iMovie is using most of the processor.',
      when: null,
    },
    answer: 'mine',
    why: 'It’s signed, installed where Mac apps go, and you’re using it right now. A busy processor while you export a video is normal.',
    sources: ['guides/remediation/investigate_keylogger_indicators.md', 'desktop/renderer/app.js'],
  },
];
```

- [ ] **Step 7: Write `desktop/renderer/game/drills/junkyard.js`**

```js
// Practice signals for The Junkyard. Invented: none of this is on the person's computer.
export default [
  {
    id: 'preinstalled-trial',
    district: 'junkyard',
    severity: 'info',
    modules: ['win_bloatware'],
    title: 'A trial app came with the computer',
    setup: 'Practice setup: this trial came with your new laptop, and you never open it.',
    clues: {
      maker: { name: 'Example Trial Co', verified: true, how: 'Authenticode signature' },
      path: 'C:\\Program Files\\Example Trial\\trial.exe',
      what: 'A preinstalled trial that starts with Windows and shows offers.',
      when: null,
    },
    answer: 'mine',
    why: 'It’s signed and installed where Windows programs go, and you know where it came from. It’s clutter, not a threat. Removing it is up to you.',
    sources: ['guides/remediation/audit_windows_autoruns.md'],
  },
  {
    id: 'downloads-login-item',
    district: 'junkyard',
    severity: 'warning',
    modules: ['login_items'],
    title: 'A login item runs a program from Downloads',
    setup: '',
    clues: {
      maker: { name: 'Unknown maker', verified: false, how: 'unsigned' },
      path: '~/Downloads/installer-helper',
      what: 'Something set to open when you log in. It runs a program from your Downloads folder.',
      when: null,
    },
    answer: 'threat',
    why: 'Installed software doesn’t run from Downloads, where files from the internet land. A login item pointing there is a strong warning sign.',
    sources: ['rescue/attribution.py', 'guides/remediation/audit_windows_autoruns.md'],
  },
];
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-drills.test.js`
Expected: PASS, every test. If a source check fails, fix the drill's text or its sources so the claim is traceable; never loosen the gate.

- [ ] **Step 9: Run the whole suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add desktop/renderer/game/drills.js desktop/renderer/game/drills desktop/test/game-drills.test.js
git commit -m "Game: the drill bank, its accuracy gate, and drill mixing"
```

---

### Task 6: The deck's views: layout, queue, instruments, ops log, and the city in the middle

**Files:**
- Create: `desktop/renderer/game/views/deck.js`, `desktop/renderer/game/views/instruments.js`
- Modify: `desktop/renderer/game/views/map.js` (`renderMap`), `desktop/renderer/game/views/one-city-map.js` (`renderOneCityMap`), `desktop/renderer/game/game.css` (append)
- Test: `desktop/test/game-deck-views.test.js`

**Interfaces:**
- Consumes: `esc` (Plan A); the `Signal` shape (Task 3); `rankOf` output (Task 2); `findingsToCity` and `emptyProgress` (test only).
- Produces:
  - `SEV_BADGE: { critical, warning, info, couldnt }` (HTML strings), `LOW_SHOWN = 50`, `LOG_SHOWN = 12`
  - `signalRow(signal, districtName: (id) => string) -> html` (a `<li>` with `data-go="signal:<id>"`)
  - `nextMoveHtml(signal) -> html` (`data-go="mission:<id>"` when the signal has a mission, else `data-act="list"`)
  - `renderDeck({ title, rank, lastSweep, items, low, lowOpen, threats, known, filter, cityHtml, instrumentsHtml, log, moment, panelHtml, nothingChecked, scanRunning, districtName, notice }) -> html`
  - `integrityText(current: int|null, previous: int|null) -> string`, `sparklineSvg(values: (int|null)[]) -> html`
  - `renderInstruments({ integrity, previous, history, bars: { sorted, confirmed, reported }, rank }) -> html`
  - `renderMap({ …as before, goFor = (d) => 'district:<id>', heat = {}, selected = null })`, and the same three options for `renderOneCityMap`. Its output is unchanged when they're left out.

- [ ] **Step 1: Write the failing tests in `desktop/test/game-deck-views.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/deck.js')),
  ...(await import('../renderer/game/views/instruments.js')),
  ...(await import('../renderer/game/views/map.js')),
  ...(await import('../renderer/game/views/one-city-map.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/progress.js')),
  ...(await import('../renderer/game/ledger.js')),
});
const sig = (id, severity, extra = {}) => ({ id, kind: 'real', severity, title: `T ${id}`, districtId: 'gatehouse', missionId: null,
  tag: null, marked: false, stale: false, changed: false, count: 1, ...extra });
async function deck(over = {}) {
  const v = await views();
  return v.renderDeck({ title: 'YOUR COMPUTER', rank: v.rankOf(v.emptyDeck()), lastSweep: { at: '2026-10-18T12:00:00Z', checks: 290 },
    items: [], low: [], lowOpen: false, threats: [], known: [], filter: null, cityHtml: '<div id="city"></div>',
    instrumentsHtml: '<div id="inst"></div>', log: [], moment: null, panelHtml: '', nothingChecked: false, scanRunning: false,
    districtName: () => 'The Gatehouse', ...over });
}

test('the deck: top bar, queue, city, instruments, log; engine text is escaped', async () => {
  const html = await deck({ items: [sig('a', 'critical', { title: EVIL }), sig('b', 'warning')],
    log: [{ at: '2026-10-18T12:00:00Z', kind: 'TAG', text: EVIL }] });
  assert.match(html, /RANK<\/small> ROOKIE/);
  assert.match(html, /290 CHECKS/);
  assert.match(html, /data-act="resweep"[^>]*>RE-SWEEP ⟳/);
  assert.match(html, /data-go="training"/);
  assert.match(html, /data-act="list"/);
  assert.match(html, /INCOMING SIGNALS[\s\S]*data-act="investigate-next"[\s\S]*data-go="signal:a"[\s\S]*data-go="signal:b"/);
  assert.match(html, /<div class="deck-city"><div id="city"><\/div><\/div>/);
  assert.match(html, /<div id="inst"><\/div>/);
  assert.match(html, /OPS LOG[\s\S]*TAG/);
  assert.match(html, /<button type="button" class="sig sev-critical"/, 'each signal is a real button');
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x/);
  assert.match(await deck({ scanRunning: true }), /SWEEPING/);
  assert.doesNotMatch(await deck({ scanRunning: true }), /data-act="resweep"/);
});

// Review Focus 5.
test('hundreds of info signals stay folded: one row; opened, at most 50 and a count; the batch line', async () => {
  const v = await views();
  const low = Array.from({ length: 300 }, (_, i) => sig(`n${i}`, 'info'));
  const shut = await deck({ low });
  assert.match(shut, /data-act="toggle-low" aria-expanded="false">LOW-PRIORITY SIGNALS \(300\)/);
  assert.strictEqual((shut.match(/data-go="signal:n/g) || []).length, 0);
  const open = await deck({ low, lowOpen: true });
  assert.match(open, /aria-expanded="true"/);
  assert.strictEqual((open.match(/data-go="signal:n/g) || []).length, v.LOW_SHOWN);
  assert.match(open, /And 250 more/);
  assert.match(open, /data-act="batch-fine"[^>]*>THESE ARE ALL FINE/);
  assert.match(open, /earns no points/);
  const known = await deck({ known: low.map((x) => ({ ...x, tag: 'mine' })) });
  assert.match(known, /KNOWN AND NOTED \(300\)/);
  assert.strictEqual((known.match(/data-go="signal:n/g) || []).length, v.LOW_SHOWN, 'the known pile is capped too');
});

// Review Focus 1.
test('an empty board offers the drill range; nothing checked never says clear', async () => {
  const clear = await deck();
  assert.match(clear, /CLEAR BOARD/);
  assert.match(clear, /lowers the odds of a problem; it doesn’t rule one out/);
  assert.match(clear, /data-go="range"[^>]*>DRILL RANGE ▶/);
  assert.doesNotMatch(clear, /investigate-next/);
  const fog = await deck({ nothingChecked: true, items: [sig('couldnt|a', 'couldnt', { kind: 'couldnt', title: 'A check couldn’t run here' })] });
  assert.match(fog, /NOTHING COULD BE CHECKED/);
  assert.match(fog, /That doesn’t mean it’s safe/);
  assert.doesNotMatch(fog, /CLEAR BOARD/);
  assert.match(fog, /COULDN’T CHECK/);
});

test('rows say what they are: DRILL, LOOK CLOSER, MARKED, changed; the threat board has next moves', async () => {
  const html = await deck({
    items: [sig('drill:x', 'warning', { kind: 'drill' }), sig('c', 'warning', { tag: 'closer' }), sig('s', 'warning', { stale: true }), sig('g', 'warning', { changed: true })],
    threats: [sig('t1', 'critical', { tag: 'threat', missionId: 't1', fixable: true }), sig('t2', 'info', { tag: 'threat' })],
    known: [sig('k', 'warning', { tag: 'mine', marked: true })] });
  assert.match(html, /class="sig sev-warning drill"[\s\S]*?DRILL/);
  assert.match(html, /data-go="signal:c"[\s\S]*?LOOK CLOSER/);
  assert.match(html, /CHANGED SINCE YOU MARKED IT/);
  assert.match(html, /CHANGED SINCE YOU TAGGED IT/);
  assert.match(html, /THREAT BOARD \(2\)[\s\S]*data-go="mission:t1"[^>]*>SEE THE FIX ▶[\s\S]*data-act="list"[^>]*>SEE IT IN THE LIST ▶/);
  assert.match(html, /Tagging changes nothing on your computer/);
  assert.match(html, /KNOWN AND NOTED \(1\)[\s\S]*MARKED/);
});

test('a moment is a banner with a role; a filter shows its district with a way back', async () => {
  const html = await deck({ moment: { kind: 'clean', title: 'CLEAN SWEEP', text: 'No open signals.' }, filter: { id: 'wires', name: 'The Wires' } });
  assert.match(html, /<div class="moment moment-clean" role="status"><b>CLEAN SWEEP<\/b> No open signals\.<\/div>/);
  assert.match(html, /SHOWING THE WIRES[\s\S]*data-go="filter:all"[\s\S]*data-go="district:wires"/);
  assert.doesNotMatch(html, /CLEAR BOARD/, 'an empty filter isn’t a clear board');
  assert.match(html, /Nothing to sort here/);
});

test('instruments: integrity with a text equivalent, a hidden sparkline, confirmed and reported apart, rank progress', async () => {
  const v = await views();
  assert.strictEqual(v.integrityText(72, 61), 'City integrity 72%, up from 61% last sweep.');
  assert.strictEqual(v.integrityText(50, 61), 'City integrity 50%, down from 61% last sweep.');
  assert.strictEqual(v.integrityText(50, 50), 'City integrity 50%, the same as last sweep.');
  assert.strictEqual(v.integrityText(50, null), 'City integrity 50%.');
  assert.match(v.integrityText(null, 80), /no reading/);
  assert.strictEqual(v.sparklineSvg([50]), '', 'one point is not a line');
  assert.match(v.sparklineSvg([20, null, 80]), /<svg class="spark"[^>]*aria-hidden="true"[^>]*>[\s\S]*<polyline points="0\.0,[\d.]+ 100\.0,[\d.]+"/);
  const html = v.renderInstruments({ integrity: 72, previous: 61, history: [61, 72], bars: { sorted: 4, confirmed: 2, reported: 3 },
    rank: v.rankOf({ ...v.emptyDeck(), points: 40 }) });
  assert.match(html, /<b>72%<\/b>/);
  assert.match(html, /City integrity 72%, up from 61% last sweep\./);
  assert.match(html, /<b>4<\/b> <small>SORTED<\/small>[\s\S]*<b>2<\/b> <small>CONFIRMED<\/small>[\s\S]*<b>3<\/b> <small>YOU REPORTED<\/small>/);
  assert.doesNotMatch(html, /<b>5<\/b>/, 'confirmed and reported are never summed');
  assert.match(html, /ROOKIE[\s\S]*40 POINTS[\s\S]*aria-valuenow="40"[\s\S]*60 points to SIGNAL ANALYST/);
  const none = v.renderInstruments({ integrity: null, previous: null, history: [null], bars: {}, rank: v.rankOf(v.emptyDeck()) });
  assert.match(none, /<b>—<\/b>/);
  assert.doesNotMatch(none, /<b>\d+%<\/b>/);
});

test('the city in the middle: districts filter the queue, glow by heat, and fog is never clear', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [
    { name: 'a', category: 'security', status: 'ok', supported: true, findings: [{ title: 'x', severity: 'critical', data: {} }] },
    { name: 'b', category: 'network', status: 'error', error: 'no', findings: [] },
  ] });
  const opts = { goFor: (d) => `filter:${d.id}`, heat: { gatehouse: 'hot' }, selected: 'gatehouse' };
  const html = v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout, ...opts });
  assert.match(html, /class="district hot heat-hot" data-go="filter:gatehouse" aria-current="true"/);
  assert.match(html, /class="district fog" data-go="filter:wires"/);
  assert.match(html, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  assert.match(v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout }), /class="district hot" data-go="district:gatehouse">/, 'the default is unchanged');
  const one = v.renderOneCityMap({ city, progress: v.emptyProgress(), accountCards: [], focus: 'computer', cameBack: [], scout, ...opts });
  assert.match(one, /class="district hot heat-hot" data-go="filter:gatehouse" aria-current="true"/);
});

test('the deck stacks queue, city, instruments, log when narrow; drills are hatched; moments animate unless motion is reduced', () => {
  const css = fs.readFileSync(path.join(__dirname, '../renderer/game/game.css'), 'utf8');
  assert.match(css, /@media \(max-width: 900px\) \{ \.deck \{[^}]*grid-template-areas: "queue" "city" "instruments" "log"/);
  assert.match(css, /\.sig\.drill, \.sig-panel\.drill \{[^}]*border: 2px solid var\(--lime\)[^}]*repeating-linear-gradient/);
  assert.match(css, /\.moment \{[^}]*animation: moment-in/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ \*, \*::before, \*::after \{ animation: none !important/);
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-deck-views.test.js`
Expected: FAIL with `Cannot find module '…/views/deck.js'`.

- [ ] **Step 3: Give `renderMap` the three options**

In `desktop/renderer/game/views/map.js`, replace:

```js
export function renderMap({ city, progress, cameBack, scout }) {
  const cards = city.districts.map((d) => {
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}" data-go="district:${esc(d.id)}">
```

with:

```js
// `goFor(d)`: what a district card opens (the deck filters its queue instead).
// `heat`: districtId → 'hot' | 'warn' for open signals. `selected`: the filtered district.
export function renderMap({ city, progress, cameBack, scout, goFor = (d) => `district:${d.id}`, heat = {}, selected = null }) {
  const cards = city.districts.map((d) => {
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}${heat[d.id] ? ` heat-${esc(heat[d.id])}` : ''}" data-go="${esc(goFor(d))}"${selected === d.id ? ' aria-current="true"' : ''}>
```

- [ ] **Step 4: Give `renderOneCityMap` the same options**

In `desktop/renderer/game/views/one-city-map.js`, replace:

```js
export function renderOneCityMap({ city, progress, accountCards, focus, cameBack, scout, accountsError }) {
  const device = city.districts.map((d) => {
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}" data-go="district:${esc(d.id)}">
```

with:

```js
// goFor, heat and selected: as in map.js's renderMap. Account districts are unchanged.
export function renderOneCityMap({ city, progress, accountCards, focus, cameBack, scout, accountsError,
  goFor = (d) => `district:${d.id}`, heat = {}, selected = null }) {
  const device = city.districts.map((d) => {
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}${heat[d.id] ? ` heat-${esc(heat[d.id])}` : ''}" data-go="${esc(goFor(d))}"${selected === d.id ? ' aria-current="true"' : ''}>
```

- [ ] **Step 5: Write `desktop/renderer/game/views/deck.js`**

```js
// The command center's deck: the city's home screen in game mode. Pure.
// Left: incoming signals, with drills mixed in and info folded. Centre: the
// city. Right: the instruments. Bottom: the ops log. Every string from the
// engine or the drill bank is escaped.
import { esc } from '../escape.js';

export const SEV_BADGE = {
  critical: '<span class="badge crit">CRITICAL</span>',
  warning: '<span class="badge warn">WARNING</span>',
  info: '<span class="badge skip">LOW PRIORITY</span>',
  couldnt: '<span class="badge fog">COULDN’T CHECK</span>',
};
export const LOW_SHOWN = 50;
export const LOG_SHOWN = 12;

function clock(iso, withDate = false) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return withDate ? d.toLocaleString() : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function signalRow(sig, districtName = () => '') {
  const drill = sig.kind === 'drill';
  const badges = [
    drill ? '<span class="badge drill-stamp">DRILL</span>' : '',
    SEV_BADGE[sig.severity] || '',
    sig.marked ? '<span class="badge yours">MARKED</span>' : '',
    sig.tag === 'closer' ? '<span class="badge cyan">LOOK CLOSER</span>' : '',
    sig.stale ? '<span class="badge warn">CHANGED SINCE YOU MARKED IT</span>' : '',
    sig.changed ? '<span class="badge warn">CHANGED SINCE YOU TAGGED IT</span>' : '',
  ].join('');
  return `<li><button type="button" class="sig sev-${esc(sig.severity)}${drill ? ' drill' : ''}" data-go="signal:${esc(sig.id)}">
      <span class="sig-badges">${badges}</span><span class="sig-title">${esc(sig.title)}</span><small>${esc(districtName(sig.districtId))}</small></button></li>`;
}

// THREAT's next move: the finding's own briefing, where any real fix asks first.
// Breach Protocol (piece 3) and account steps (piece 5) aren't built yet.
export function nextMoveHtml(sig) {
  if (sig.missionId) {
    return `<button type="button" class="btn-s mag" data-go="mission:${esc(sig.missionId)}">${sig.fixable ? 'SEE THE FIX ▶' : 'SEE THE STEPS ▶'}</button>`;
  }
  return '<button type="button" class="btn-t" data-act="list">SEE IT IN THE LIST ▶</button>';
}

export function renderDeck({ title, rank, lastSweep, items = [], low = [], lowOpen = false, threats = [], known = [], filter = null,
  cityHtml = '', instrumentsHtml = '', log = [], moment = null, panelHtml = '', nothingChecked = false, scanRunning = false,
  districtName = () => '', notice = '' }) {
  const dn = districtName;
  const top = `
  <header class="hud deck-top">
    <span class="hud-title">${esc(title)}</span>
    <span class="stat lime"><small>RANK</small> ${esc(rank.name)}</span>
    <span class="stat grey">${lastSweep ? `<small>LAST SWEEP</small> ${esc(clock(lastSweep.at, true))} · ${esc(lastSweep.checks)} CHECKS` : '<small>NO SWEEP YET</small>'}</span>
    ${scanRunning ? '<span class="stat cyan"><small>SWEEPING…</small></span>' : '<button type="button" class="btn-s" data-act="resweep">RE-SWEEP ⟳</button>'}
    <span class="switch"><button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
  const head = filter ? `
      <div class="row"><span class="label">SHOWING ${esc(String(filter.name).toUpperCase())}</span>
        <button type="button" class="btn-t" data-go="filter:all">SHOW ALL</button>
        <button type="button" class="btn-t" data-go="district:${esc(filter.id)}">OPEN THE DISTRICT ▶</button></div>` : '';
  const anything = items.length > 0 || low.length > 0;
  let blank = '';
  if (nothingChecked) {
    blank = '<div class="panel fogged" role="note"><div class="label">NOTHING COULD BE CHECKED</div><p class="intel">None of the checks could run, so nothing was looked at. That doesn’t mean it’s safe.</p></div>';
  } else if (!anything && filter) {
    blank = '<p class="intel">Nothing to sort here.</p>';
  } else if (!anything) {
    blank = '<div class="panel clear-board"><div class="label">CLEAR BOARD</div><p class="intel">Nothing to sort from this checkup. A clean checkup lowers the odds of a problem; it doesn’t rule one out. Want practice? Try the DRILL RANGE below.</p></div>';
  }
  const next = anything ? '<button type="button" class="btn-p" data-act="investigate-next">INVESTIGATE NEXT ▶</button>' : '';
  const lowHtml = low.length ? `
      <li class="low-group">
        <button type="button" class="sig low-row" data-act="toggle-low" aria-expanded="${lowOpen ? 'true' : 'false'}">LOW-PRIORITY SIGNALS (${low.length})</button>
        ${lowOpen ? `<ul class="queue">${low.slice(0, LOW_SHOWN).map((x) => signalRow(x, dn)).join('')}</ul>
        ${low.length > LOW_SHOWN ? `<p class="intel">And ${low.length - LOW_SHOWN} more. THESE ARE ALL FINE sorts every one.</p>` : ''}
        <button type="button" class="btn-s" data-act="batch-fine">THESE ARE ALL FINE</button>
        <p class="intel">Sorting them all at once earns no points. Open one to look at its clues.</p>` : ''}
      </li>` : '';
  const threatHtml = threats.length ? `
      <section class="panel threat-board" aria-label="Threat board"><div class="label">THREAT BOARD (${threats.length})</div>
        <ul class="queue">${threats.map((x) => `<li class="threat"><span class="sig-title">${esc(x.title)}</span>${nextMoveHtml(x)}</li>`).join('')}</ul>
        <p class="intel">Tagging changes nothing on your computer. A fix happens only when you say yes to it.</p></section>` : '';
  const knownHtml = known.length ? `
      <details class="panel known"><summary class="label">KNOWN AND NOTED (${known.length})</summary>
        <ul class="queue">${known.slice(0, LOW_SHOWN).map((x) => signalRow(x, dn)).join('')}</ul>
        ${known.length > LOW_SHOWN ? `<p class="intel">And ${known.length - LOW_SHOWN} more.</p>` : ''}</details>` : '';
  const logHtml = `
    <section class="panel deck-log" aria-label="Ops log"><div class="label">OPS LOG</div>
      ${log.length ? `<ol class="log">${log.slice(0, LOG_SHOWN).map((e) => `<li><time>${esc(clock(e.at))}</time> <span class="badge skip">${esc(e.kind)}</span> ${esc(e.text)}</li>`).join('')}</ol>`
    : '<p class="intel">Nothing yet. Tags, sweeps, fixes and reports show up here.</p>'}
    </section>`;
  const momentHtml = moment ? `<div class="moment moment-${esc(moment.kind)}" role="status"><b>${esc(moment.title)}</b> ${esc(moment.text)}</div>` : '';
  return `${top}${notice}${momentHtml}
  <div class="deck">
    <aside class="deck-queue" aria-label="Incoming signals">
      <div class="label">INCOMING SIGNALS</div>${head}${blank}${next}
      <ul class="queue">${items.map((x) => signalRow(x, dn)).join('')}${lowHtml}</ul>
      ${threatHtml}${knownHtml}
      <button type="button" class="btn-s lime" data-go="range">DRILL RANGE ▶</button>
    </aside>
    <div class="deck-city">${cityHtml}</div>
    <aside class="deck-instruments" aria-label="Instruments">${instrumentsHtml}</aside>
    ${logHtml}
  </div>
  ${panelHtml}`;
}
```

- [ ] **Step 6: Write `desktop/renderer/game/views/instruments.js`**

```js
// The deck's instruments: city integrity, its sparkline, the three bars and
// rank progress. Pure. Every graph has a text equivalent; the sparkline itself
// is hidden from screen readers because the sentence says the same thing.
import { esc } from '../escape.js';

const pct = (n) => Math.max(0, Math.min(100, Math.round(Number(n) || 0)));

export function integrityText(current, previous) {
  if (current == null) return 'City integrity: no reading. Nothing could be checked, and fog never counts as secure.';
  if (previous == null) return `City integrity ${current}%.`;
  if (current > previous) return `City integrity ${current}%, up from ${previous}% last sweep.`;
  if (current < previous) return `City integrity ${current}%, down from ${previous}% last sweep.`;
  return `City integrity ${current}%, the same as last sweep.`;
}

// The last ten sweeps. A sweep that checked nothing (null) is a gap, not a zero.
export function sparklineSvg(values) {
  const vs = (values || []).slice(-10);
  const pts = vs.map((v, i) => (typeof v === 'number' ? [i, v] : null)).filter(Boolean);
  if (pts.length < 2) return '';
  const step = vs.length > 1 ? 100 / (vs.length - 1) : 0;
  const points = pts.map(([i, v]) => `${(i * step).toFixed(1)},${(29 - pct(v) * 0.28).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true" focusable="false"><polyline points="${points}" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
}

function bar(n, max, label, tone) {
  const value = Number(n) || 0;
  const w = max > 0 ? pct((value / max) * 100) : 0;
  return `<div class="ibar ${tone}"><span class="ibar-n"><b>${value}</b> <small>${label}</small></span><span class="ibar-track" aria-hidden="true"><i style="--pct: ${w}%"></i></span></div>`;
}

export function renderInstruments({ integrity, previous, history, bars, rank }) {
  const b = bars || {};
  const max = Math.max(1, Number(b.sorted) || 0, Number(b.confirmed) || 0, Number(b.reported) || 0);
  const toward = rank.next ? pct(((rank.points - rank.min) / (rank.next.min - rank.min)) * 100) : 100;
  const next = rank.next ? `${rank.toNext} points to ${rank.next.name}.` : 'Top rank.';
  return `
  <section class="panel instruments">
    <div class="label">CITY INTEGRITY</div>
    <p class="integrity"><b>${integrity == null ? '—' : `${esc(integrity)}%`}</b></p>
    ${sparklineSvg(history)}
    <p class="intel">${esc(integrityText(integrity, previous))}</p>
    <div class="label">SIGNALS</div>
    ${bar(b.sorted, max, 'SORTED', 'cyan')}${bar(b.confirmed, max, 'CONFIRMED', 'lime')}${bar(b.reported, max, 'YOU REPORTED', 'amb')}
    <p class="intel">Confirmed means Device Rescue checked again and it’s gone. You reported is your word for it. They’re counted apart.</p>
    <div class="label">RANK</div>
    <p class="rank-name"><b>${esc(rank.name)}</b> <small>${esc(rank.points)} POINTS</small></p>
    <div class="bar" role="progressbar" aria-label="Rank progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${toward}"><i style="--pct: ${toward}%"></i></div>
    <p class="intel">${esc(next)}</p>
  </section>`;
}
```

- [ ] **Step 7: Append the deck's styles to `desktop/renderer/game/game.css`**

```css
/* ---------- the command center (the deck) ---------- */
.deck { display: grid; gap: 14px; padding: 14px 18px; grid-template-columns: minmax(240px, 1fr) minmax(0, 2fr) minmax(220px, 1fr); grid-template-areas: "queue city instruments" "log log log"; }
.deck-queue { grid-area: queue; display: grid; gap: 10px; align-content: start; min-width: 0; }
.deck-city { grid-area: city; min-width: 0; }
.deck-instruments { grid-area: instruments; min-width: 0; }
.deck-log { grid-area: log; }
@media (max-width: 900px) { .deck { grid-template-columns: 1fr; grid-template-areas: "queue" "city" "instruments" "log"; } }
.queue { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.sig { display: grid; gap: 4px; width: 100%; padding: 10px 12px; border: 1px solid var(--line); background: var(--panel); }
.sig.sev-critical { border-left: 3px solid var(--magenta); }
.sig.sev-warning { border-left: 3px solid var(--amber); }
.sig.sev-couldnt { border-left: 3px dashed #9fb3c8; }
.sig.low-row { font-family: var(--font-display); font-size: 10px; letter-spacing: 1px; color: var(--dim); }
.sig-title { font-weight: 600; }
.sig-badges { display: flex; flex-wrap: wrap; gap: 4px; }
.sig.drill, .sig-panel.drill { border: 2px solid var(--lime); background-image: repeating-linear-gradient(45deg, rgba(198,255,0,0.08) 0 6px, transparent 6px 12px); }
.badge.drill-stamp { color: var(--midnight); background: var(--lime); border-color: var(--lime); }
.threat-board .threat { display: grid; gap: 6px; }
.district.heat-hot { box-shadow: 0 0 22px rgba(255,45,155,0.35); }
.district.heat-warn { box-shadow: 0 0 18px rgba(255,159,0,0.3); }
.district[aria-current="true"] { outline: 2px solid var(--cyan); outline-offset: 2px; }
.integrity b { font-family: var(--font-display); font-size: 28px; color: var(--cyan); }
.spark { display: block; width: 100%; height: 36px; color: var(--cyan); }
.ibar { display: grid; gap: 4px; margin: 6px 0; }
.ibar-track { height: 8px; border: 1px solid var(--line); position: relative; }
.ibar-track i { position: absolute; inset: 0 auto 0 0; width: var(--pct, 0%); background: currentColor; }
.ibar.cyan { color: var(--cyan); }
.ibar.lime { color: var(--lime); }
.ibar.amb { color: var(--amber); }
.log { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; font-family: var(--font-mono); font-size: 12px; }
.log time { color: var(--faint); margin-right: 6px; }
.moment { margin: 10px 18px 0; padding: 12px 16px; border: 1px solid var(--lime); color: var(--lime); background: rgba(198,255,0,0.07); font-family: var(--font-display); letter-spacing: 1px; animation: moment-in 700ms ease-out; }
@keyframes moment-in { from { opacity: 0; transform: translateY(-8px) scale(0.98); } to { opacity: 1; transform: none; } }
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-deck-views.test.js test/game-views.test.js test/stylesheets.test.js`
Expected: PASS. `game-views.test.js` proves the maps' default output is unchanged.

- [ ] **Step 9: Commit**

```bash
git add desktop/renderer/game/views/deck.js desktop/renderer/game/views/instruments.js desktop/renderer/game/views/map.js desktop/renderer/game/views/one-city-map.js desktop/renderer/game/game.css desktop/test/game-deck-views.test.js
git commit -m "Game: the deck's views (queue, instruments, ops log, city filter)"
```

---

### Task 7: The Signal or Noise panel, the drill range view, and DRILL RANGE in the Training Grounds

**Files:**
- Create: `desktop/renderer/game/views/signal.js`
- Modify: `desktop/renderer/game/views/training.js` (`renderTraining`), `desktop/renderer/game/game.css` (append)
- Test: `desktop/test/game-signal-view.test.js`

**Interfaces:**
- Consumes: `esc`; `SEV_BADGE` and `nextMoveHtml` (Task 6); `Clue` (Task 4); `Signal` (Tasks 3 and 5).
- Produces:
  - `TAG_NOTE: string`
  - `renderSignalPanel({ signal, districtName, clues, opened: string[], tagged: tag|null, right: boolean, read: string, points: int, scout, mineHtml = '', range: { hasCity }|null }) -> html`. The buttons are `data-act="clue:<kind>"`, `data-act="tag:mine|closer|threat|noted"`, `data-act="close-signal"`, and in the range `data-act="next-drill"` and `data-act="leave-range"`.
  - `renderRange({ loaded, panelHtml, hasCity }) -> html`
  - `renderTraining` also offers `data-go="range"` ("DRILL RANGE ▶").

- [ ] **Step 1: Write the failing tests in `desktop/test/game-signal-view.test.js`**

```js
const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/signal.js')),
  ...(await import('../renderer/game/clues.js')),
  ...(await import('../renderer/game/views/training.js')),
});
const FINDING = { title: 'Helper', description: 'Starts at login.', data: { program: '/tmp/x' }, made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] };
const real = (extra = {}) => ({ id: 'm|c|program=/tmp/x', kind: 'real', severity: 'critical', title: 'Helper', districtId: 'gatehouse',
  finding: FINDING, missionId: 'm|c|program=/tmp/x', fixable: true, marked: false, stale: false, changed: false, tag: null, ...extra });
const DRILL = { id: 'x', district: 'gatehouse', severity: 'warning', title: 'Practice thing', setup: 'Practice setup: you use it.',
  clues: { maker: null, path: '/tmp/y', what: 'Runs.', when: null }, answer: 'threat', why: 'Because.' };
const drillSig = { id: 'drill:x', kind: 'drill', severity: 'warning', title: DRILL.title, districtId: 'gatehouse', drill: DRILL, missionId: null, tag: null };
async function panel(over = {}) {
  const v = await views();
  const signal = over.signal || real();
  const clues = signal.kind === 'drill' ? v.drillClues(signal.drill) : signal.kind === 'real' ? v.cluesFor(signal.finding) : [];
  return v.renderSignalPanel({ signal, districtName: 'The Gatehouse', clues, opened: [], tagged: null, right: false, read: '', points: 0,
    scout, mineHtml: '', range: null, ...over });
}

test('clues are locked until SCAN CLUE, then show with their how-to-read line', async () => {
  const shut = await panel();
  assert.match(shut, /role="region" aria-labelledby="sig-title"/);
  assert.match(shut, /CRITICAL[\s\S]*The Gatehouse[\s\S]*id="sig-title"[^>]*>Helper/);
  for (const k of ['maker', 'where', 'what']) assert.match(shut, new RegExp(`data-act="clue:${k}"`));
  assert.doesNotMatch(shut, /How to read this/);
  assert.match(shut, /data-act="tag:mine"[\s\S]*data-act="tag:closer"[\s\S]*data-act="tag:threat"/);
  assert.match(shut, /They change nothing on your computer/);
  const open = await panel({ opened: ['maker', 'where'] });
  assert.match(open, /WHO MADE IT[\s\S]*Unknown maker, not verified \(unsigned\)[\s\S]*How to read this:<\/b> Not verified/);
  assert.match(open, /WHERE IT LIVES[\s\S]*\/tmp\/x[\s\S]*temporary folder/);
  assert.match(open, /data-act="clue:what"/);
});

test('engine text is escaped everywhere in the panel', async () => {
  const evil = { title: EVIL, description: EVIL, data: { program: `/tmp/${EVIL}` }, made_by: [{ name: EVIL, verified: false, how: EVIL }] };
  const html = await panel({ signal: real({ title: EVIL, finding: evil }), opened: ['maker', 'where', 'what'], tagged: 'threat', read: EVIL });
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x/);
});

test('a couldn’t-check signal can only be NOTED, and links the lesson', async () => {
  const html = await panel({ signal: { id: 'couldnt|m', kind: 'couldnt', severity: 'couldnt', title: 'A check couldn’t run here',
    description: 'Needs permission.', districtId: 'wires', finding: null, missionId: null, tag: null } });
  assert.match(html, /COULDN’T CHECK/);
  assert.match(html, /Needs permission\./);
  assert.match(html, /That doesn’t mean it’s safe/);
  assert.match(html, /data-act="tag:noted"[^>]*>NOTED/);
  assert.match(html, /data-go="lesson:couldnt-check"/);
  assert.doesNotMatch(html, /data-act="tag:(mine|threat|closer)"|SCAN CLUE/);
});

test('a drill: stamped, practice-only, its setup shown, and never the real “It’s mine” step', async () => {
  const html = await panel({ signal: drillSig, mineHtml: '<b>MARK</b>' });
  assert.match(html, /class="sig-panel drill"/);
  assert.match(html, /DRILL<\/span> Practice\. This isn’t on your computer\./);
  assert.match(html, /Practice setup: you use it\./);
  assert.match(html, /data-act="clue:where"/);
  assert.doesNotMatch(html, /data-act="clue:maker"/, 'no maker in this drill, so no maker clue');
  const after = await panel({ signal: drillSig, tagged: 'mine', right: false, read: 'Not this time, and it costs you nothing. The tell: Because.', mineHtml: '<b>MARK</b>' });
  assert.doesNotMatch(after, /<b>MARK<\/b>/);
  assert.match(after, /The tell: Because\./);
  assert.match(after, /aria-disabled="true"/, 'a drill takes one answer');
  assert.doesNotMatch(after, /POINTS/, 'a wrong answer scores nothing');
});

test('after tagging: Scout’s read, the points, and each tag’s next step', async () => {
  const mine = await panel({ tagged: 'mine', read: 'The checkup marked this critical.', points: 20, mineHtml: '<div data-mark-card>MARK IT</div>' });
  assert.match(mine, /The checkup marked this critical\./);
  assert.match(mine, /\+20 POINTS for the clues you checked/);
  assert.match(mine, /OPTIONAL: TELL DEVICE RESCUE TOO[\s\S]*It asks first, and you can undo it\.[\s\S]*MARK IT/);
  assert.match(mine, /data-act="tag:mine" aria-pressed="true"/);
  const threat = await panel({ tagged: 'threat', read: 'r' });
  assert.match(threat, /ON YOUR THREAT BOARD[\s\S]*data-go="mission:m\|c\|program=\/tmp\/x"[^>]*>SEE THE FIX ▶/);
  assert.doesNotMatch(threat, /MARK IT/);
  assert.doesNotMatch(threat, /POINTS/);
  assert.match(await panel({ tagged: 'closer', read: 'r' }), /It stays in your queue/);
});

// Review Focus 2.
test('a finding with no clues says so, and can still be tagged', async () => {
  const html = await panel({ signal: real({ finding: { title: 'x', description: '', data: {} } }) });
  assert.match(html, /recorded no clues for this one/);
  assert.match(html, /data-act="tag:threat"/);
});

test('marked, changed since marking, and changed since tagging each say so', async () => {
  assert.match(await panel({ signal: real({ marked: true, tag: 'mine' }) }), /MARKED<\/span> You told Device Rescue this is yours\. It stays listed\./);
  assert.match(await panel({ signal: real({ stale: true }) }), /CHANGED SINCE YOU MARKED IT/);
  assert.match(await panel({ signal: real({ changed: true }) }), /CHANGED SINCE YOU TAGGED IT/);
});

test('the drill range: getting ready, nothing loaded, and a drill with next and back', async () => {
  const v = await views();
  assert.match(v.renderRange({ loaded: false, panelHtml: '', hasCity: false }), /THE DRILL RANGE[\s\S]*Getting the drills ready/);
  const empty = v.renderRange({ loaded: true, panelHtml: '', hasCity: true });
  assert.match(empty, /The drills couldn’t load/);
  assert.match(empty, /data-act="leave-range">BACK TO THE DECK/);
  const html = v.renderRange({ loaded: true, panelHtml: await panel({ signal: drillSig, range: { hasCity: false } }), hasCity: false });
  assert.match(html, /None of this is on your computer/);
  assert.match(html, /data-act="next-drill"[^>]*>NEXT DRILL ▶/);
  assert.match(html, /data-act="leave-range"[^>]*>BACK TO THE TRAINING GROUNDS/);
  assert.doesNotMatch(html, /data-act="close-signal"/);
});

test('the Training Grounds offer the DRILL RANGE, with or without a scan', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} },
    scan: { running: false, index: 0, total: 0, error: null }, scout, lessonsLoaded: true });
  assert.match(html, /data-go="range"[^>]*>DRILL RANGE ▶/);
  assert.match(html, /Nothing in the range touches your computer/);
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-signal-view.test.js`
Expected: FAIL with `Cannot find module '…/views/signal.js'`.

- [ ] **Step 3: Write `desktop/renderer/game/views/signal.js`**

```js
// The Signal or Noise panel: one finding (or one drill) over the deck. Pure.
// Clues stay locked until SCAN CLUE, and only clues the evidence supports are
// offered at all. Tags are game sorting only; a real change keeps its own OK.
import { esc } from '../escape.js';
import { SEV_BADGE, nextMoveHtml } from './deck.js';

export const TAG_NOTE = 'Tags are game sorting only. They change nothing on your computer.';
const TAG_BUTTONS = [['mine', 'MINE'], ['closer', 'LOOK CLOSER'], ['threat', 'THREAT']];

function clueItem(c, opened) {
  if (!opened.includes(c.kind)) {
    return `<li><button type="button" class="clue locked" data-act="clue:${esc(c.kind)}">SCAN CLUE: ${esc(c.label)} ▶</button></li>`;
  }
  return `<li class="clue open"><div class="label">${esc(c.label)}</div>${c.lines.map((l) => `<p class="clue-line">${esc(l)}</p>`).join('')}
      <p class="reading"><b>How to read this:</b> ${esc(c.reading.text)}</p></li>`;
}

export function renderSignalPanel({ signal: sig, districtName = '', clues = [], opened = [], tagged = null, right = false, read = '',
  points = 0, scout, mineHtml = '', range = null }) {
  const drill = sig.kind === 'drill';
  const couldnt = sig.kind === 'couldnt';
  const stamp = drill ? `<p class="drill-banner"><span class="badge drill-stamp">DRILL</span> Practice. This isn’t on your computer.</p>
    ${sig.drill && sig.drill.setup ? `<p class="intel">${esc(sig.drill.setup)}</p>` : ''}` : '';
  const notes = [
    sig.marked ? '<p class="intel"><span class="badge yours">MARKED</span> You told Device Rescue this is yours. It stays listed.</p>' : '',
    sig.stale ? '<p class="intel"><span class="badge warn">CHANGED SINCE YOU MARKED IT</span> It changed after you marked it, so it’s back in your queue.</p>' : '',
    sig.changed ? '<p class="intel"><span class="badge warn">CHANGED SINCE YOU TAGGED IT</span> It changed since you tagged it, so your old tag was set aside.</p>' : '',
  ].join('');
  let clueHtml;
  if (couldnt) {
    clueHtml = `<p class="intel">${esc(sig.description || 'This check couldn’t run.')}</p>
      <p class="intel">A check that couldn’t run checked nothing. That doesn’t mean it’s safe.</p>`;
  } else if (clues.length) {
    clueHtml = `<ul class="clues">${clues.map((c) => clueItem(c, opened)).join('')}</ul>`;
  } else {
    clueHtml = '<p class="intel">The scan recorded no clues for this one. Its title is all there is to go on.</p>';
  }
  const current = tagged || sig.tag;
  const call = couldnt
    ? `<div class="row tags"><button type="button" class="btn-s" data-act="tag:noted"${current === 'noted' ? ' aria-pressed="true"' : ''}>NOTED</button>
      <button type="button" class="btn-t" data-go="lesson:couldnt-check">WHAT “COULDN’T CHECK” MEANS ▶</button></div>`
    : `<div class="row tags">${TAG_BUTTONS.map(([t, label]) => `<button type="button" class="btn-s tag-${t}" data-act="tag:${t}"${current === t ? ' aria-pressed="true"' : ''}${drill && tagged ? ' aria-disabled="true"' : ''}>${label}</button>`).join('')}</div>`;
  const after = !tagged ? '' : `
    <div class="scout-row">${scout(drill && !right ? 'thinkingA' : 'happy', 54)}<p class="say">${esc(read)}</p></div>
    ${points > 0 ? `<p class="points">+${esc(points)} POINTS${drill ? '' : ' for the clues you checked'}</p>` : ''}
    ${!drill && tagged === 'mine' && mineHtml ? `<div class="panel"><div class="label">OPTIONAL: TELL DEVICE RESCUE TOO</div>
      <p class="intel">The MINE pile is the game’s sorting. This asks Device Rescue itself to remember it’s yours, so it stops flagging it. It asks first, and you can undo it.</p>${mineHtml}</div>` : ''}
    ${!drill && tagged === 'threat' ? `<div class="panel"><div class="label">ON YOUR THREAT BOARD</div><p class="intel">Your next move:</p>${nextMoveHtml(sig)}</div>` : ''}
    ${!drill && tagged === 'closer' ? '<p class="intel">It stays in your queue. Open its clues again any time, or use LIST for every detail the scan recorded.</p>' : ''}`;
  const foot = range
    ? `<div class="row"><button type="button" class="btn-p" data-act="next-drill">NEXT DRILL ▶</button>
      <button type="button" class="btn-t" data-act="leave-range">${range.hasCity ? 'BACK TO THE DECK' : 'BACK TO THE TRAINING GROUNDS'}</button></div>`
    : '<button type="button" class="btn-t" data-act="close-signal">BACK TO THE DECK</button>';
  return `
  <section class="sig-panel${drill ? ' drill' : ''}" role="region" aria-labelledby="sig-title">
    ${stamp}
    <div class="sig-head">${SEV_BADGE[sig.severity] || ''} <small>${esc(districtName)}</small></div>
    <h2 class="m-title" id="sig-title" tabindex="-1">${esc(sig.title)}</h2>
    ${notes}
    <div class="label">CLUES</div>${clueHtml}
    <div class="label">YOUR CALL</div>${call}
    <p class="intel faint">${esc(drill ? 'Practice only. A drill never touches your computer.' : TAG_NOTE)}</p>
    ${after}
    ${foot}
  </section>`;
}

// The DRILL RANGE screen: more drills, any time, with or without a scan.
export function renderRange({ loaded, panelHtml = '', hasCity = false }) {
  const body = !loaded ? '<p class="intel">Getting the drills ready.</p>'
    : panelHtml || '<p class="intel">The drills couldn’t load. The checkup and the deck still work.</p>';
  return `
  <header class="hud"><span class="hud-title">THE DRILL RANGE</span>
    <span class="switch"><button type="button" data-act="leave-range">${hasCity ? 'BACK TO THE DECK' : 'BACK TO THE TRAINING GROUNDS'}</button></span></header>
  <section class="range" aria-label="The drill range">
    <p class="intel">Practice with made-up signals. None of this is on your computer, and nothing here changes it.</p>
    ${body}
  </section>`;
}
```

- [ ] **Step 4: Add DRILL RANGE to the Training Grounds**

In `desktop/renderer/game/views/training.js`, inside `renderTraining`, replace:

```js
    <div class="quiz">
      <div class="scout-row">${scout('happy', 72)}<p class="say">${esc('These are short. Pick any one, or go straight to the checkup.')}</p></div>
    </div>
```

with:

```js
    <div class="quiz">
      <div class="scout-row">${scout('happy', 72)}<p class="say">${esc('These are short. Pick any one, or go straight to the checkup.')}</p></div>
      <button type="button" class="btn-s lime" data-go="range">DRILL RANGE ▶</button>
      <p class="intel">Practice sorting made-up signals. Nothing in the range touches your computer.</p>
    </div>
```

- [ ] **Step 5: Append the panel's styles to `desktop/renderer/game/game.css`**

```css
/* ---------- Signal or Noise ---------- */
.sig-panel { position: fixed; top: 12px; right: 12px; bottom: 12px; width: min(460px, calc(100% - 24px)); overflow-y: auto; display: grid; gap: 10px; align-content: start; padding: 18px; background: #0d1018; border: 1px solid rgba(0,229,255,0.45); box-shadow: 0 0 40px rgba(0,0,0,0.6); z-index: 10; }
.range .sig-panel { position: static; width: auto; box-shadow: none; }
.range { display: grid; gap: 12px; padding: 14px 18px; max-width: 640px; }
.drill-banner { font-family: var(--font-display); font-size: 10px; letter-spacing: 1px; color: var(--lime); }
.clues { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.clue.locked { width: 100%; padding: 10px 12px; border: 1px dashed rgba(0,229,255,0.4); font-family: var(--font-display); font-size: 10px; letter-spacing: 1px; color: var(--cyan); }
.clue.open { border-left: 2px solid var(--cyan); padding: 4px 12px; }
.clue-line { margin: 2px 0; font-family: var(--font-mono); font-size: 13px; overflow-wrap: anywhere; }
.reading { font-size: 13px; color: var(--dim); }
.tags { display: flex; flex-wrap: wrap; gap: 8px; }
.tags [aria-pressed="true"] { background: var(--cyan); color: var(--midnight); }
.points { font-family: var(--font-mono); color: var(--lime); }
.faint { color: var(--faint); }
```

- [ ] **Step 6: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-signal-view.test.js test/game-training-views.test.js test/stylesheets.test.js`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/views/signal.js desktop/renderer/game/views/training.js desktop/renderer/game/game.css desktop/test/game-signal-view.test.js
git commit -m "Game: the Signal or Noise panel and the drill range view"
```

---

### Task 8: The controller, part 1: the deck as home, Signal or Noise, tags, drills in the queue, the filter and batch sorting

**Files:**
- Modify: `desktop/renderer/game/controller.js` (the edits below)
- Modify: `desktop/test/game-controller.test.js` (two `district:` assertions become `filter:`)
- Test: `desktop/test/game-deck-controller.test.js` (new)

**Interfaces:**
- Consumes: everything from Tasks 1–7, as named in their **Produces** lines; Plan A/B/C's `createController` internals (`s`, `render`, `district`, `mission`, `counts`, `focusFor`, `accountDistrictCards`, `renderMap`, `renderOneCityMap`, `win.MarkFlow.markControlsHtml(finding)`).
- Produces:
  - `createController({ win, storage, scoutSprite, loadGame, loadTraining, loadDrillBank })`. The new argument `loadDrillBank` defaults to loading `DRILL_FILES` next to `controller.js`; tests pass `async () => DRILLS`.
  - On the deck, these clicks: `data-go="signal:<id>"` (and `signal:drill:<id>`), `data-go="filter:<districtId>|all"`, `data-act="investigate-next"`, `clue:<kind>`, `tag:<tag>`, `close-signal`, `toggle-low`, `batch-fine`.
  - Controller helpers that Task 9 calls: `logEntry(kind, text)`, `commitDeck(deck)`, `commitAward(result) -> points`, `signalsNow()`, `sweepDrillsNow()`, `deckQueue() -> { sigs, q, items }`, `findSignal(id)`, `openedFor(id)`, `signalPanelHtml()`, `nameOf(districtId)`.
  - State: `s.signal = { id, tagged, right, read, points } | null`, plus `s.filter`, `s.lowOpen`, `s.log` (memory only), `s.moment`, `s.opened`, `s.changedTags`, `s.drillBank`, `s.drillsLoaded`, `s.sweepDrills`, `s.drillAnswers`, `s.range` and `s.sweptDoc`.

- [ ] **Step 1: Point the two existing "district card" assertions at the deck's filter**

In `desktop/test/game-controller.test.js`, replace:

```js
  assert.match(stub.frame.innerHTML, /data-go="district:/);
```

with:

```js
  assert.match(stub.frame.innerHTML, /data-go="filter:/, 'the deck’s city filters the queue');
```

and replace:

```js
    assert.match(t.html(), /data-go="district:/);
```

with:

```js
    assert.match(t.html(), /data-go="filter:/);
```

- [ ] **Step 2: Write the failing tests in `desktop/test/game-deck-controller.test.js`**

```js
// The command center against a stubbed window (no DOM library), like
// game-controller.test.js: a frame whose innerHTML the tests read, and clicks
// delivered as elements with attributes.
const test = require('node:test');
const assert = require('node:assert');

const STORE = 'device-rescue.game.v1';
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, category: 'security', data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const drill = (id, district, answer) => ({ id, district, severity: 'warning', modules: [], title: `Drill ${id}`, setup: '',
  clues: { maker: { name: 'Unknown maker', verified: false, how: 'unsigned' }, path: '/tmp/d', what: 'Practice only.', when: null },
  answer, why: `Why ${id}.`, sources: [] });
const DRILLS = [drill('gate-1', 'gatehouse', 'threat'), drill('gate-2', 'gatehouse', 'mine'), drill('junk-1', 'junkyard', 'closer')];
const DOC = scan(mod('a_mod', [
  f('Unsigned helper', 'critical', { plist: '/Users/ann/Library/LaunchAgents/x.plist', program: '/tmp/x' },
    { code: 'security.a_mod.unsigned', made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] }),
  f('Old note', 'info', { name: 'n' }),
]));
const queueOf = (html, end = 'deck-city') => html.split('INCOMING SIGNALS')[1].split(end)[0];

function stub(recheckDocs = []) {
  const listeners = [];
  const calls = { startCheckup: 0, recheck: [], showList: 0 };
  const focused = [];
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: (sel) => {
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      if (m && frame.innerHTML.includes(`${m[1]}="${m[2]}"`)) return { focus: () => focused.push(sel) };
      return null;
    },
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: (_r, _a, h) => { hooks.fix = h; }, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: (_r, _a, h) => { hooks.mark = h; },
      markControlsHtml: (finding) => (finding && finding.markable ? '<div data-mark-card>MARK IT</div>' : '') },
    RescueHost: { showList() { calls.showList += 1; }, docChanged: () => true, wantsSafety: () => false,
      startCheckup() { calls.startCheckup += 1; }, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async (name) => {
      calls.recheck.push(name);
      const doc = recheckDocs.shift();
      return { ok: true, doc, module: doc.modules.find((m) => m.name === name) };
    } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const focusOn = (attrs) => { shadow.activeElement = attrs ? { getAttribute: (k) => (k in attrs ? attrs[k] : null) } : null; };
  return { win, frame, hooks, calls, click, focused, focusOn };
}

async function deckSetup(doc, { storage = memStore(), situation = { id: 'unsure' }, recheckDocs = [], drills = DRILLS } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const t = stub(recheckDocs);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => drills });
  await tick();
  if (doc) ctl.show(doc, situation);
  return { ...t, ctl, storage, html: () => t.frame.innerHTML, saved: () => JSON.parse(storage.getItem(STORE) || 'null') };
}
async function ids(doc) {
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  return findingsToCity(doc).districts.flatMap((d) => d.missions.map((m) => m.id));
}

test('the deck is the city’s home: queue, city, instruments, log, and its own top bar', async () => {
  const t = await deckSetup(DOC);
  const html = t.html();
  assert.match(html, /INCOMING SIGNALS/);
  assert.match(html, /data-act="investigate-next"/);
  assert.match(html, /aria-label="Your computer as a city"/);
  assert.match(html, /data-go="filter:gatehouse"/);
  assert.match(html, /City integrity/);
  assert.match(html, /OPS LOG/);
  assert.match(html, /LOW-PRIORITY SIGNALS \(1\)/);
  assert.match(html, /data-act="resweep"/);
  assert.doesNotMatch(html, /class="hud">/, 'the deck’s top bar replaces the HUD');
});

test('INVESTIGATE NEXT opens the most important signal; clues unlock one at a time and pay once per scan', async () => {
  const t = await deckSetup(DOC);
  t.click({ 'data-act': 'investigate-next' });
  assert.match(t.html(), /id="sig-title"[^>]*>Unsigned helper/);
  assert.match(t.html(), /data-act="clue:maker"/);
  assert.doesNotMatch(t.html(), /How to read this/);
  t.click({ 'data-act': 'clue:maker' });
  assert.match(t.html(), /WHO MADE IT[\s\S]*Unknown maker, not verified \(unsigned\)[\s\S]*How to read this/);
  assert.strictEqual(t.saved().deck.points, 5);
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'close-signal' });
  assert.doesNotMatch(t.html(), /id="sig-title"/);
  t.click({ 'data-act': 'investigate-next' });
  assert.match(t.html(), /Unknown maker, not verified/, 'an opened clue stays open this scan');
  t.click({ 'data-act': 'clue:maker' });
  assert.strictEqual(t.saved().deck.points, 5, 'the same clue pays once per scan');
  t.click({ 'data-act': 'clue:when' });
  assert.strictEqual(t.saved().deck.points, 5, 'a clue the evidence doesn’t support can’t be opened');
});

test('tagging after two clues pays a bonus once; tags are keyed by identity; re-tagging pays nothing more', async () => {
  const [id] = await ids(DOC);
  const t = await deckSetup(DOC);
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'clue:where' });
  t.click({ 'data-act': 'tag:threat' });
  const saved = t.saved();
  assert.strictEqual(saved.deck.points, 5 + 5 + 10);
  assert.strictEqual(saved.deck.tags[id].tag, 'threat');
  assert.ok(!JSON.stringify(saved.deck.tags).includes('Unsigned helper'), 'tags keep identities, not titles');
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.saved().deck.points, 20);
  assert.match(t.html(), /OPS LOG[\s\S]*THREAT: Unsigned helper/);
  assert.doesNotMatch(t.html(), /\bwrong\b/i);
});

test('THREAT goes to the threat board with its next move; LOOK CLOSER stays in the queue; neither touches the computer', async () => {
  const two = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { fixable: true }), f('B', 'warning', { plist: '/b' })]));
  const [ia, ib] = await ids(two);
  const t = await deckSetup(two);
  t.click({ 'data-go': `signal:${ia}` });
  t.click({ 'data-act': 'tag:threat' });
  assert.match(t.html(), /ON YOUR THREAT BOARD[\s\S]*data-go="mission:[^"]*"[^>]*>SEE THE FIX ▶/);
  t.click({ 'data-act': 'close-signal' });
  assert.match(t.html(), /THREAT BOARD \(1\)/);
  t.click({ 'data-go': `signal:${ib}` });
  t.click({ 'data-act': 'tag:closer' });
  t.click({ 'data-act': 'close-signal' });
  assert.match(queueOf(t.html(), 'THREAT BOARD'), /data-go="signal:[^"]*"[\s\S]*?LOOK CLOSER/);
  assert.deepStrictEqual(t.calls.recheck, [], 'tags never touch the computer');
});

test('MINE offers the real “It’s mine” step only for a finding that has one, and only as an option', async () => {
  const doc = scan(mod('a_mod', [f('Mine?', 'warning', { plist: '/m' }, { markable: { id: 'abcdef012345', kind: 'background_task' } }),
    f('Plain', 'warning', { plist: '/p' })]));
  const [im, ip] = await ids(doc);
  const t = await deckSetup(doc);
  t.click({ 'data-go': `signal:${im}` });
  t.click({ 'data-act': 'tag:mine' });
  assert.match(t.html(), /OPTIONAL: TELL DEVICE RESCUE TOO[\s\S]*MARK IT/);
  t.click({ 'data-go': `signal:${ip}` });
  t.click({ 'data-act': 'tag:mine' });
  assert.doesNotMatch(t.html(), /MARK IT/);
  assert.deepStrictEqual(t.calls.recheck, [], 'nothing was marked: the person didn’t press it');
});

test('a couldn’t-check signal can only be NOTED, and links the lesson', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]), mod('broken', [], { status: 'error', error: 'Needs Full Disk Access.' })));
  t.click({ 'data-go': 'signal:couldnt|broken' });
  assert.match(t.html(), /Needs Full Disk Access\./);
  assert.match(t.html(), /data-act="tag:noted"/);
  assert.match(t.html(), /data-go="lesson:couldnt-check"/);
  assert.doesNotMatch(t.html(), /data-act="tag:(mine|threat|closer)"/);
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.saved().deck.tags['couldnt|broken'], undefined);
  t.click({ 'data-act': 'tag:noted' });
  assert.strictEqual(t.saved().deck.tags['couldnt|broken'].tag, 'noted');
  assert.match(t.html(), /That doesn’t mean it’s safe/);
});

test('clicking a district filters the queue to it; SHOW ALL brings back the rest', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('Gate thing', 'warning', { plist: '/a' })]),
    { ...mod('b_mod', [f('Wire thing', 'warning', { path: '/b' })]), category: 'network' }));
  t.click({ 'data-go': 'filter:wires' });
  assert.match(t.html(), /SHOWING THE WIRES/);
  assert.match(queueOf(t.html()), /Wire thing/);
  assert.doesNotMatch(queueOf(t.html()), /Gate thing/);
  assert.match(t.html(), /data-go="district:wires"/);
  t.click({ 'data-go': 'filter:all' });
  assert.match(queueOf(t.html()), /Gate thing/);
});

// Review Focus 5.
test('low-priority signals stay folded; THESE ARE ALL FINE sorts every one and pays nothing', async () => {
  const t = await deckSetup(scan(mod('a_mod', Array.from({ length: 120 }, (_, i) => f(`Note ${i}`, 'info', { name: `n${i}` })))));
  assert.match(t.html(), /LOW-PRIORITY SIGNALS \(120\)/);
  assert.doesNotMatch(t.html(), /Note 7\b/, 'folded');
  t.click({ 'data-act': 'toggle-low' });
  assert.strictEqual((t.html().match(/data-go="signal:a_mod/g) || []).length, 50);
  assert.match(t.html(), /And 70 more/);
  t.click({ 'data-act': 'batch-fine' });
  const saved = t.saved();
  assert.strictEqual(Object.keys(saved.deck.tags).length, 120);
  assert.strictEqual(saved.deck.points, 0);
  assert.doesNotMatch(t.html(), /LOW-PRIORITY SIGNALS/);
  assert.match(t.html(), /<b>120<\/b> <small>SORTED<\/small>/);
});

test('marked by the person: pre-tagged MINE with a MARKED badge, still visible; changed since: back in the queue', async () => {
  const marked = f('Mine', 'info', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' });
  const stale = f('Stale', 'info', { plist: '/s', marked_by_user: true, mark_stale: true, original_severity: 'warning', known_item_id: 'k2' });
  const t = await deckSetup(scan(mod('a_mod', [marked, stale])));
  const queue = queueOf(t.html(), 'KNOWN AND NOTED');
  assert.doesNotMatch(queue, />Mine</);
  assert.match(queue, /CHANGED SINCE YOU MARKED IT[\s\S]*Stale/);
  assert.match(t.html(), /KNOWN AND NOTED \(1\)[\s\S]*MARKED[\s\S]*>Mine</);
  assert.match(t.html(), /<b>1<\/b> <small>SORTED<\/small>/);
});

test('monitoring checks never become signals, and nothing about them is stored', async () => {
  const t = await deckSetup(scan(mod('stalkerware_scan', [f('No monitoring apps found', 'info')]), mod('a_mod', [f('Other', 'info', { name: 'o' })])));
  assert.doesNotMatch(t.html(), /No monitoring apps found/);
  t.click({ 'data-act': 'toggle-low' });
  t.click({ 'data-act': 'batch-fine' });
  assert.doesNotMatch(t.storage.getItem(STORE), /stalkerware|monitoringSeen/);
});

test('drills join the queue: about one per four real signals, from the same districts, stamped DRILL', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  const drills = queueOf(t.html()).match(/data-go="signal:drill:[^"]+"/g) || [];
  assert.strictEqual(drills.length, 2);
  assert.ok(drills.every((d) => /gate-/.test(d)), 'only drills from the districts in the queue');
});

test('a drill: right pays drill points, wrong pays nothing and gives the tell; neither touches integrity or the bars', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  const integrity = () => t.html().match(/City integrity[^<]*/)[0];
  const before = integrity();
  t.click({ 'data-go': 'signal:drill:gate-1' });
  assert.match(t.html(), /DRILL[\s\S]*Practice\. This isn’t on your computer\./);
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'clue:where' });
  assert.strictEqual(t.saved().deck.points, 0, 'drill clues pay nothing on their own');
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.saved().deck.points, 15 + 5);
  assert.deepStrictEqual(t.saved().deck.drills, { right: 1, tried: 1 });
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.saved().deck.drills.tried, 1, 'a drill takes one answer');
  t.click({ 'data-act': 'close-signal' });
  assert.doesNotMatch(t.html(), /signal:drill:gate-1/, 'an answered drill leaves the queue');
  t.click({ 'data-go': 'signal:drill:gate-2' });
  t.click({ 'data-act': 'tag:threat' });
  assert.match(t.html(), /The tell: Why gate-2\./);
  assert.strictEqual(t.saved().deck.points, 20);
  t.click({ 'data-act': 'close-signal' });
  assert.strictEqual(integrity(), before);
  assert.match(t.html(), /<b>0<\/b> <small>SORTED<\/small>/);
  assert.deepStrictEqual(t.saved().deck.tags, {}, 'drills are never tagged in the store');
});

test('a rank-up is a moment and a log entry', async () => {
  const { emptyDeck } = await import('../renderer/game/progress.js');
  const storage = memStore();
  storage.setItem(STORE, JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { ...emptyDeck(), points: 95 } }));
  const t = await deckSetup(DOC, { storage });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'clue:maker' });
  assert.match(t.html(), /class="moment moment-rank" role="status"><b>RANK UP<\/b> You’re now SIGNAL ANALYST/);
  assert.match(t.html(), /RANK UP<\/span> SIGNAL ANALYST/);
  t.click({ 'data-act': 'clue:where' });
  assert.doesNotMatch(t.html(), /class="moment/, 'a moment shows once');
});

test('zero findings: a clear board and the DRILL RANGE', async () => {
  const t = await deckSetup(scan(mod('a_mod', [])));
  assert.match(t.html(), /CLEAR BOARD/);
  assert.match(t.html(), /data-go="range"/);
  assert.doesNotMatch(t.html(), /data-act="investigate-next"/);
});

// Review Focus 1.
test('every check errored: no reading, never a clear board, and the couldn’t-check signals', async () => {
  const t = await deckSetup(scan(mod('a', [], { status: 'error', error: 'x' }),
    { ...mod('b', [], { supported: false, unsupported_reason: 'Mac only' }), category: 'network' }));
  const html = t.html();
  assert.match(html, /NOTHING COULD BE CHECKED/);
  assert.match(html, /City integrity: no reading/);
  assert.doesNotMatch(html, /CLEAR BOARD|100%/);
  assert.match(html, /data-go="signal:couldnt\|a"/);
  assert.doesNotMatch(html, /signal:drill:/, 'no drills without real signals');
});

test('redraws on the deck keep keyboard focus', async () => {
  const t = await deckSetup(DOC);
  t.focusOn({ 'data-act': 'toggle-low' });
  t.click({ 'data-act': 'toggle-low' });
  assert.deepStrictEqual(t.focused, ['[data-act="toggle-low"]']);
});
```

- [ ] **Step 3: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-deck-controller.test.js test/game-controller.test.js`
Expected: FAIL. The deck isn't drawn yet, so `INCOMING SIGNALS` isn't found, and the two `filter:` assertions fail.

- [ ] **Step 4: Imports and constants in `controller.js`**

Replace:

```js
import { findingsToCity } from './findings-to-city.js';
import { loadProgress, saveProgress, reconcile, setStatus, setLessonDone, ranOkModules, recheckOutcome } from './progress.js';
```

with:

```js
import { findingsToCity, DISTRICTS } from './findings-to-city.js';
import { loadProgress, saveProgress, reconcile, setStatus, setLessonDone, ranOkModules, recheckOutcome, setDeck } from './progress.js';
import { buildSignals, queueOf, cityIntegrity, districtHeat, sortedCount, sweepCounts } from './signals.js';
import { award, setTag, recordDrill, recordSweep, confirmFix, reconcileDeck, rankOf, sweepPercent, POINTS } from './ledger.js';
import { cluesFor, drillClues, scoutRead, drillRead, COULDNT_READ } from './clues.js';
import { loadDrills, chooseDrills, mixDrills, drillSignal, pickDrills } from './drills.js';
import { renderDeck } from './views/deck.js';
import { renderInstruments } from './views/instruments.js';
import { renderSignalPanel, renderRange } from './views/signal.js';
```

Replace:

```js
import { focusFor, countConfirmedAndReported, accountDistrictCards, deviceMissionFor } from './one-city.js';
```

with:

```js
import { focusFor, countDeckBars, accountDistrictCards, deviceMissionFor } from './one-city.js';
```

Replace:

```js
const TRAINING_SCREENS = new Set(['training', 'lesson', 'boss']);
```

with:

```js
const TRAINING_SCREENS = new Set(['training', 'lesson', 'boss']);
// Screens drawn without a city, and screens whose redraws keep keyboard focus.
const NO_CITY_SCREENS = new Set([...TRAINING_SCREENS, 'range']);
const KEEP_FOCUS = new Set([...TRAINING_SCREENS, 'map', 'range']);
const LOG_MAX = 100;
const TAG_WORD = { mine: 'MINE', threat: 'THREAT', closer: 'LOOK CLOSER', noted: 'NOTED' };
// Specifiers resolve against this file, like the lessons'.
const loadDrillsHere = () => loadDrills((spec) => import(spec));
```

- [ ] **Step 5: The new argument and the new state**

Replace:

```js
export function createController({ win, storage, scoutSprite, loadGame = loadRc, loadTraining = loadLessonsHere }) {
```

with:

```js
export function createController({ win, storage, scoutSprite, loadGame = loadRc, loadTraining = loadLessonsHere, loadDrillBank = loadDrillsHere }) {
```

Replace:

```js
    lessons: [], lessonsLoaded: false, lesson: null, pendingCity: false, tips: [], tipsOpen: true, scan: idleScan(), boss: bossInit() };
```

with:

```js
    lessons: [], lessonsLoaded: false, lesson: null, pendingCity: false, tips: [], tipsOpen: true, scan: idleScan(), boss: bossInit(),
    // The command center. The ops log is kept in memory only.
    signal: null, filter: null, lowOpen: false, log: [], moment: null, opened: {}, changedTags: new Set(),
    drillBank: [], drillsLoaded: false, sweepDrills: null, drillAnswers: {}, range: null, sweptDoc: null };
```

- [ ] **Step 6: Load the drill bank like the lessons**

Directly after the block that starts `new Promise((r) => r(loadTraining()))` and ends with its `});`, add:

```js
  // The drill bank, the same way: a drill file that fails to load is left out.
  new Promise((r) => r(loadDrillBank())).catch(() => []).then((ds) => {
    s.drillBank = Array.isArray(ds) ? ds : [];
    s.drillsLoaded = true;
    if (s.city && s.sweepDrills === null) s.sweepDrills = sweepDrillsNow();
    if (s.screen === 'range' || (s.screen === 'map' && s.city && !s.busy)) render();
  });
```

- [ ] **Step 7: `rebuild` keeps the deck in step with the scan**

Replace the whole `rebuild` function:

```js
  function rebuild(doc, putBack = null) {
    s.doc = doc;
    s.city = findingsToCity(doc);
    const r = reconcile(s.progress, s.city, ranOkModules(doc), now());
    s.progress = r.progress;
    s.cameBack = r.cameBack.filter((id) => id !== putBack);
    saveProgress(storage, s.progress);
  }
```

with:

```js
  function rebuild(doc, putBack = null) {
    s.doc = doc;
    s.city = findingsToCity(doc);
    const ranOk = ranOkModules(doc);
    const r = reconcile(s.progress, s.city, ranOk, now());
    s.cameBack = r.cameBack.filter((id) => id !== putBack);
    // The deck follows the scan too: a changed finding's tag is set aside, a
    // gone one's is dropped, and a confirmed fix that came back no longer counts.
    const rd = reconcileDeck(r.progress.deck, buildSignals(s.city, r.progress.deck), ranOk);
    rd.changed.forEach((id) => s.changedTags.add(id));
    s.progress = setDeck(r.progress, rd.deck);
    saveProgress(storage, s.progress);
  }
```

- [ ] **Step 8: One rule for CONFIRMED and YOU REPORTED everywhere**

Replace the whole `counts` function:

```js
  function counts() {
    if (!s.rc) return undefined;
    return countConfirmedAndReported({ rc: s.rc, progress: s.progress, rcState: s.rcState, scanConfirmed: s.scanConfirmed, doc: s.doc });
  }
```

with:

```js
  // CONFIRMED is what a re-check (or the checkup, for an account mission)
  // proved; YOU REPORTED is the person's word. The deck and every HUD agree.
  function counts() {
    return countDeckBars({ rc: s.rc, deck: s.progress.deck, rcState: s.rcState, scanConfirmed: s.scanConfirmed, doc: s.doc });
  }
```

- [ ] **Step 9: The deck's helpers**

Directly before `  function screenHtml() {`, add:

```js
  // ---------------------------------------------------------------------------
  // The command center. Everything here reads the scan and changes game state
  // (the deck) only; nothing touches the computer. Real changes go through
  // FixFlow and MarkFlow, which ask first.
  // ---------------------------------------------------------------------------
  function logEntry(kind, text) {
    s.log = [{ at: now(), kind, text: String(text == null ? '' : text) }, ...s.log].slice(0, LOG_MAX);
  }
  function commitDeck(deck) {
    s.progress = setDeck(s.progress, deck);
    saveProgress(storage, s.progress);
  }
  // A ledger result: keep its deck. A rank-up is a moment and a log entry.
  function commitAward(r) {
    if (!r) return 0;
    commitDeck(r.deck);
    if (r.rankUp) {
      const name = rankOf(r.deck).name;
      s.moment = { kind: 'rank', title: 'RANK UP', text: `You’re now ${name}.` };
      logEntry('RANK UP', name);
    }
    return r.points || 0;
  }
  const signalsNow = () => (s.city ? buildSignals(s.city, s.progress.deck, s.changedTags) : []);
  // This sweep's drills: about one per four real signals, from their districts.
  function sweepDrillsNow() {
    const real = queueOf(signalsNow(), null).urgent.filter((x) => x.kind === 'real');
    return chooseDrills(s.drillBank, real, s.progress.deck, s.progress.deck.sweeps.length);
  }
  function deckQueue() {
    const sigs = signalsNow();
    const q = queueOf(sigs, s.filter);
    const drills = (s.sweepDrills || []).filter((d) => !s.drillAnswers[d.id] && (!s.filter || d.district === s.filter));
    return { sigs, q, items: mixDrills(q.urgent, drills) };
  }
  function findSignal(id) {
    if (typeof id !== 'string') return null;
    if (id.startsWith('drill:')) {
      const d = s.drillBank.find((x) => x.id === id.slice(6));
      return d ? drillSignal(d) : null;
    }
    return signalsNow().find((x) => x.id === id) || null;
  }
  // Clues opened this sweep, per signal. Memory only.
  const openedFor = (id) => { if (!s.opened[id]) s.opened[id] = []; return s.opened[id]; };
  const cluesOf = (sig) => (sig.kind === 'drill' ? drillClues(sig.drill) : sig.kind === 'real' ? cluesFor(sig.finding) : []);
  const nameOf = (id) => ((s.city && district(id)) || DISTRICTS.find((d) => d.id === id) || {}).name || '';

  function signalPanelHtml() {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) { s.signal = null; return ''; }
    // The real "It's mine" step, offered only for a finding that has one. MarkFlow asks its own question.
    const mine = sig.kind === 'real' && sig.missionId && !sig.marked ? win.MarkFlow.markControlsHtml(sig.finding) : '';
    return renderSignalPanel({ signal: sig, districtName: nameOf(sig.districtId), clues: cluesOf(sig), opened: openedFor(sig.id),
      tagged: s.signal.tagged, right: s.signal.right, read: s.signal.read, points: s.signal.points, scout, mineHtml: mine,
      range: s.screen === 'range' ? { hasCity: !!s.city } : null });
  }

  function deckHtml() {
    const { sigs, q, items } = deckQueue();
    const integ = cityIntegrity(s.city, sigs);
    const deck = s.progress.deck;
    const history = deck.sweeps.map(sweepPercent);
    const c = counts();
    const goFor = (d) => `filter:${d.id}`;
    const heat = districtHeat(s.city, sigs);
    const cityHtml = s.rc || s.accountsError
      ? renderOneCityMap({ city: s.city, progress: s.progress, scout, cameBack: s.cameBack, focus: focusFor(s.situation),
        accountCards: s.rc ? accountDistrictCards({ rc: s.rc, rcState: s.rcState, doc: s.doc }) : [],
        accountsError: s.accountsError, goFor, heat, selected: s.filter })
      : renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout, goFor, heat, selected: s.filter });
    const fd = s.filter ? district(s.filter) : null;
    const moment = s.moment;
    s.moment = null; // a moment shows once
    return renderDeck({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', rank: rankOf(deck),
      lastSweep: deck.sweeps.length ? deck.sweeps[deck.sweeps.length - 1] : null,
      items, low: q.low, lowOpen: s.lowOpen, threats: q.threats, known: [...q.known, ...q.noted],
      filter: fd ? { id: fd.id, name: fd.name } : null, cityHtml,
      instrumentsHtml: renderInstruments({ integrity: integ.percent, previous: history.length > 1 ? history[history.length - 2] : null,
        history, bars: { sorted: sortedCount(sigs), confirmed: c.confirmed, reported: c.reported }, rank: rankOf(deck) }),
      log: s.log, moment, panelHtml: s.signal ? signalPanelHtml() : '', nothingChecked: integ.percent === null,
      scanRunning: s.scan.running, districtName: nameOf, notice: s.linkNotice });
  }

  function openSignal(id) {
    const sig = findSignal(id);
    s.signal = sig ? { id: sig.id, tagged: null, right: false, read: '', points: 0 } : null;
    // FixFlow and MarkFlow results re-check s.missionId. An info signal has no mission.
    if (sig) s.missionId = sig.missionId || null;
    s.screen = 'map';
    render();
    const title = s.signal ? frame.querySelector('#sig-title') : null;
    if (title && typeof title.focus === 'function') title.focus();
  }

  // Opening a clue on a real finding pays once per finding per sweep (the ledger keys it).
  function scanClue(kind) {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) return;
    const opened = openedFor(sig.id);
    if (!opened.includes(kind) && cluesOf(sig).some((c) => c.kind === kind)) {
      opened.push(kind);
      if (sig.kind === 'real') s.signal.points += commitAward(award(s.progress.deck, 'clue', `${sig.id}#${kind}`));
    }
    render();
  }

  // A tag is game sorting only. The bonus is for looking first (two or more
  // clues), never for which tag was picked.
  function tagSignal(tag) {
    const sig = s.signal && findSignal(s.signal.id);
    if (!sig) return;
    if (sig.kind === 'drill') { answerDrill(sig, tag); return; }
    if (!(sig.kind === 'couldnt' ? ['noted'] : ['mine', 'threat', 'closer']).includes(tag)) return;
    commitDeck(setTag(s.progress.deck, sig.id, tag, sig.fp, now()));
    s.changedTags.delete(sig.id);
    if (sig.kind === 'real' && openedFor(sig.id).length >= 2) s.signal.points += commitAward(award(s.progress.deck, 'tagBonus', sig.id));
    s.signal = { ...s.signal, tagged: tag, read: sig.kind === 'couldnt' ? COULDNT_READ : scoutRead(sig, tag) };
    logEntry('TAG', `${TAG_WORD[tag]}: ${sig.title}`);
    render();
  }

  // A drill takes one answer: right pays (with the clue bonus), wrong pays
  // nothing and costs nothing. Drill answers never touch the deck's tags.
  function answerDrill(sig, tag) {
    if (s.signal.tagged || !['mine', 'threat', 'closer'].includes(tag)) return;
    const d = sig.drill;
    const right = tag === d.answer;
    commitDeck(recordDrill(s.progress.deck, right));
    const points = right ? commitAward(award(s.progress.deck, 'drill', d.id, openedFor(sig.id).length >= 2 ? POINTS.drillClueBonus : 0)) : 0;
    if (s.screen !== 'range') s.drillAnswers[d.id] = { tag, right };
    s.signal = { ...s.signal, tagged: tag, right, points, read: drillRead(d, right) };
    logEntry('DRILL', `${right ? 'Right' : 'Not this time'}: ${d.title}`);
    render();
  }

  // "These are all fine": the visible low-priority signals go to the known pile. No points.
  function batchFine() {
    const { q } = deckQueue();
    if (q.low.length) {
      let deck = s.progress.deck;
      for (const sig of q.low) deck = setTag(deck, sig.id, 'mine', sig.fp, now());
      commitDeck(deck);
      logEntry('TAG', `${q.low.length} low-priority signal${q.low.length === 1 ? '' : 's'} sorted as fine`);
    }
    s.lowOpen = false;
    render();
  }

```

- [ ] **Step 10: The deck replaces the one-city map as the home screen**

At the end of `screenHtml`, replace:

```js
    s.screen = 'map';
    if (s.rc || s.accountsError) {
      return renderOneCityMap({ city: s.city, progress: s.progress, scout, cameBack: s.cameBack, focus: focusFor(s.situation),
        accountCards: s.rc ? accountDistrictCards({ rc: s.rc, rcState: s.rcState, doc: s.doc }) : [],
        accountsError: s.accountsError });
    }
    return renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout });
  }
```

with:

```js
    s.screen = 'map';
    return deckHtml();
  }
```

- [ ] **Step 11: `render` draws the deck without the HUD, and keeps focus on it**

In `render`, replace:

```js
      // No city yet (the scan hasn't finished): the Training Grounds.
      if (!s.city && !TRAINING_SCREENS.has(s.screen)) s.screen = 'training';
      // A redraw of the same training screen (a progress event, an answer)
      // mustn't lose keyboard or screen-reader focus.
      const keep = TRAINING_SCREENS.has(s.screen) && s.screen === drawnScreen ? focusSelector(shadow.activeElement) : null;
      const hud = TRAINING_SCREENS.has(s.screen) ? ''
        : renderHud({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', city: s.city, progress: s.progress, counts: counts() }) + s.linkNotice;
      frame.innerHTML = hud + screenHtml();
```

with:

```js
      // No city yet (the scan hasn't finished): the Training Grounds.
      if (!s.city && !NO_CITY_SCREENS.has(s.screen)) s.screen = 'training';
      // A redraw of the same screen (a progress event, an answer, a clue, a
      // tag) mustn't lose keyboard or screen-reader focus.
      const keep = KEEP_FOCUS.has(s.screen) && s.screen === drawnScreen ? focusSelector(shadow.activeElement) : null;
      const body = screenHtml();
      // The deck has its own top bar; the training and range screens have theirs.
      const hud = NO_CITY_SCREENS.has(s.screen) || s.screen === 'map' ? ''
        : renderHud({ title: s.rc ? 'RECLAIM CITY' : 'YOUR COMPUTER', city: s.city, progress: s.progress, counts: counts() }) + s.linkNotice;
      frame.innerHTML = hud + body;
```

- [ ] **Step 12: The deck's clicks**

In the first `frame.addEventListener('click', …)` handler, replace:

```js
    if (go) s.linkNotice = '';
```

with:

```js
    if (go) s.linkNotice = '';
    // The deck: the queue, the Signal or Noise panel, and the district filter.
    if (go && go.startsWith('signal:')) { openSignal(go.slice(7)); return; }
    if (go && go.startsWith('filter:')) {
      const id = go.slice(7);
      s.filter = id === 'all' || s.filter === id ? null : id;
      s.signal = null; s.screen = 'map'; render(); return;
    }
    if (act === 'investigate-next') {
      const { q, items } = deckQueue();
      const next = items[0] || q.low[0];
      if (next) openSignal(next.id); else render();
      return;
    }
    if (act && act.startsWith('clue:')) { scanClue(act.slice(5)); return; }
    if (act && act.startsWith('tag:')) { tagSignal(act.slice(4)); return; }
    if (act === 'close-signal') { s.signal = null; s.screen = 'map'; render(); return; }
    if (act === 'toggle-low') { s.lowOpen = !s.lowOpen; render(); return; }
    if (act === 'batch-fine') { batchFine(); return; }
```

and replace:

```js
    if (go === 'map') { s.screen = 'map'; render(); return; }
```

with:

```js
    if (go === 'map') { s.screen = 'map'; s.signal = null; render(); return; }
```

- [ ] **Step 13: A new scan resets this sweep's clues and drills**

Replace the whole `showCityFrom` function:

```js
  function showCityFrom(doc) {
    s.shown += 1;
    rebuild(doc);
    s.screen = 'map'; s.outcome = null; s.lastFix = null; s.linkNotice = ''; s.rcRoute = null; s.landing = null;
    s.lesson = null; s.pendingCity = false;
    s.focusPending = true;
  }
```

with:

```js
  function showCityFrom(doc) {
    s.shown += 1;
    rebuild(doc);
    // A new scan, not the same one shown again: clues, drills and drill answers start over.
    if (doc !== s.sweptDoc) { s.sweptDoc = doc; s.opened = {}; s.drillAnswers = {}; s.sweepDrills = s.drillsLoaded ? sweepDrillsNow() : null; }
    s.screen = 'map'; s.outcome = null; s.lastFix = null; s.linkNotice = ''; s.rcRoute = null; s.landing = null;
    s.lesson = null; s.pendingCity = false;
    s.signal = null; s.filter = null; s.lowOpen = false; s.range = null;
    s.focusPending = true;
  }
```

- [ ] **Step 14: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-deck-controller.test.js test/game-controller.test.js`
Expected: PASS. Every Plan A/B/C controller test still passes. The deck's centre keeps their map markup (`aria-label`, ring labels, `data-focus`, district badges), and the deck's bars use the same `<b>n</b> <small>LABEL</small>` form that `hudCount` reads.

- [ ] **Step 15: Run the whole suite and the game-files check**

Run: `cd desktop && npm test && npm run check-game-files`
Expected: PASS, and no output from `check-game-files`.

- [ ] **Step 16: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/test/game-deck-controller.test.js desktop/test/game-controller.test.js
git commit -m "Game: the command center deck, Signal or Noise, tags and drills in the controller"
```

---

### Task 9: The controller, part 2: sweeps, RE-SWEEP, confirmed and reported points, moments, the DRILL RANGE and the gate

**Files:**
- Modify: `desktop/renderer/game/controller.js` (the edits below)
- Modify: `desktop/test/game-controller.test.js` (two scoring tests appended), `desktop/test/game-flow-gate.test.js` (one gate test appended)
- Test: `desktop/test/game-deck-controller.test.js` (tests appended)

**Interfaces:**
- Consumes: the Task 8 helpers (`logEntry`, `commitDeck`, `commitAward`, `signalsNow`, `sweepDrillsNow`, `signalPanelHtml`, `nameOf`); `recordSweep`, `confirmFix`, `award`, `pickDrills`, `cityIntegrity`, `sweepCounts`, `renderRange` (Tasks 2–7); `win.RescueHost.startCheckup()` and `docChanged()` (Plan C); `DONE` from `verified-missions.js`; and `applyResult` and `confirmFromScan` (Plan B).
- Produces:
  - Clicks: `data-act="resweep"`, `data-go="range"`, `data-act="next-drill"`, `data-act="leave-range"`.
  - On a new scan doc, `newSweep(doc, prevSignals)` records the sweep (counts only), logs SWEEP and NO LONGER SEEN, pays a clean sweep, and picks this sweep's drills.
  - `noteSecured(before, after)` turns a district that became secured into a moment and a log entry.
  - `recheck` with outcome `reclaimed` after a `fix` or `i-did-it` calls `confirmFix` and logs CONFIRMED.
  - `applyResult(r, refused = '', confirmedId = null)` calls `creditReports`: a newly completed game mission is a `report` (YOU REPORTED), or a `fix` with the key `rc:<id>` when it was finished from the checkup.
  - The `range` screen (`rangeHtml()`), drawn with or without a city.

- [ ] **Step 1: Append the failing tests to `desktop/test/game-deck-controller.test.js`**

```js
test('RE-SWEEP runs the same game checkup, and only once at a time', async () => {
  const t = await deckSetup(DOC);
  assert.match(t.html(), /OPS LOG[\s\S]*SWEEP<\/span> \d+ checks?:/);
  t.click({ 'data-act': 'resweep' });
  assert.strictEqual(t.calls.startCheckup, 1);
  t.ctl.showBoss();
  t.click({ 'data-act': 'resweep' });
  assert.strictEqual(t.calls.startCheckup, 1, 'not while a checkup runs');
});

test('a re-sweep: tags carry over, a gone finding is NO LONGER SEEN with no points, and isn’t CONFIRMED', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }), f('B', 'warning', { plist: '/b' })]));
  const [ia, ib] = await ids(before);
  const t = await deckSetup(before);
  t.click({ 'data-go': `signal:${ia}` }); t.click({ 'data-act': 'tag:threat' });
  t.click({ 'data-go': `signal:${ib}` }); t.click({ 'data-act': 'tag:mine' });
  const points = t.saved().deck.points;
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })])), { id: 'unsure' });
  const saved = t.saved();
  assert.strictEqual(saved.deck.tags[ia].tag, 'threat', 'carried over by identity');
  assert.strictEqual(saved.deck.tags[ib], undefined);
  assert.strictEqual(saved.deck.points, points, 'gone is not a fix: no points');
  assert.deepStrictEqual(saved.deck.confirmed, {});
  assert.strictEqual(saved.deck.sweeps.length, 2);
  assert.ok(saved.deck.sweeps.every((w) => Object.keys(w).every((k) => k === 'at' || typeof w[k] === 'number')), 'dates and counts only');
  assert.match(t.html(), /NO LONGER SEEN<\/span> B/);
  assert.match(t.html(), /<b>0<\/b> <small>CONFIRMED<\/small>/);
  assert.match(t.html(), /City integrity 0%, the same as last sweep\./);
});

test('the same scan shown twice is one sweep', async () => {
  const t = await deckSetup(DOC);
  t.click({ 'data-act': 'list' });
  t.ctl.show(DOC, { id: 'unsure' });
  assert.strictEqual(t.saved().deck.sweeps.length, 1);
});

test('a re-check that proves a fix is CONFIRMED, secures the district, and pays once, ever', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { fixable: true })]));
  const after = scan(mod('a_mod', []));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [after, before, after] });
  t.click({ 'data-go': `mission:${ia}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: { quarantine_id: 'q' }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.html(), /RECLAIMED/);
  let saved = t.saved();
  assert.strictEqual(saved.deck.points, 50);
  assert.ok(saved.deck.confirmed[ia]);
  t.click({ 'data-go': 'map' });
  assert.match(t.html(), /<b>1<\/b> <small>CONFIRMED<\/small>/);
  assert.match(t.html(), /CONFIRMED<\/span> A/);
  assert.match(t.html(), /class="moment moment-secured" role="status"><b>DISTRICT SECURED<\/b>/);
  assert.match(t.html(), /SECURED<\/span> The Gatehouse/);
  // Undo puts it back: no longer confirmed. Fixing it again is confirmed again, and pays nothing more.
  t.hooks.fix.onResult({ kind: 'undo', module: 'a_mod', result: { restored: true }, described: { restored: true } });
  await tick(); await tick();
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
  t.click({ 'data-go': `mission:${ia}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: { quarantine_id: 'q2' }, described: { tone: 'success' } });
  await tick(); await tick();
  saved = t.saved();
  assert.strictEqual(saved.deck.points, 50);
  assert.ok(saved.deck.confirmed[ia]);
});

test('a clean sweep: the re-sweep that clears the board gets the moment and the bonus; the next clean one doesn’t', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })])));
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [])), { id: 'unsure' });
  assert.match(t.html(), /class="moment moment-clean" role="status"><b>CLEAN SWEEP<\/b>/);
  assert.match(t.html(), /CLEAN SWEEP<\/span>/);
  assert.strictEqual(t.saved().deck.points, 40);
  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.html(), /class="moment/, 'a moment shows once');
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [])), { id: 'unsure' });
  assert.strictEqual(t.saved().deck.points, 40);
});

test('the DRILL RANGE runs without a scan, from the Training Grounds', async () => {
  const t = await deckSetup(null);
  t.ctl.showTraining({ id: 'unsure', title: 'Not sure' });
  assert.match(t.html(), /data-go="range"/);
  t.click({ 'data-go': 'range' });
  assert.match(t.html(), /THE DRILL RANGE/);
  assert.match(t.html(), /data-act="next-drill"/);
  const title = () => /id="sig-title"[^>]*>([^<]+)/.exec(t.html())[1];
  const first = title();
  t.click({ 'data-act': 'tag:closer' });
  assert.match(t.html(), /The tell:|Right\./);
  t.click({ 'data-act': 'next-drill' });
  assert.notStrictEqual(title(), first);
  t.click({ 'data-act': 'leave-range' });
  assert.match(t.html(), /THE TRAINING GROUNDS/);
});

test('the DRILL RANGE from a clear board, and back to the deck', async () => {
  const t = await deckSetup(scan(mod('a_mod', [])));
  t.click({ 'data-go': 'range' });
  assert.match(t.html(), /THE DRILL RANGE[\s\S]*BACK TO THE DECK/);
  t.click({ 'data-act': 'leave-range' });
  assert.match(t.html(), /INCOMING SIGNALS/);
});

test('a re-check that closes the gate stops the deck: nothing is scored', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [scan(mod('a_mod', []))] });
  t.win.RescueHost.docChanged = () => false;
  t.click({ 'data-go': `mission:${ia}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.strictEqual(t.saved().deck.points, 0);
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
});
```

- [ ] **Step 2: Append the scoring tests to `desktop/test/game-controller.test.js`**

Add them after the test `'FINISH FROM THE CHECKUP shows only when every step is confirmed, and counts as CONFIRMED'`:

```js
test('SUBMIT REPORT is logged as YOU REPORTED and pays the smaller amount, once', async () => {
  const t = await rcSetup();
  t.click({ 'data-go': `rc:#/mission/${FC}/debrief` });
  t.form.action = 'completed';
  t.click({ 'data-action': 'submit-debrief', 'data-mission': FC });
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 20);
  t.click({ href: '#/city' }, 'A');
  assert.match(t.html(), /YOU REPORTED<\/span> [^<]+/);
  assert.strictEqual(hudCount(t.html(), 'YOU REPORTED'), 1);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 0);
});

test('FINISH FROM THE CHECKUP is logged as CONFIRMED and pays the fix amount', async () => {
  const t = await rcSetup({ doc: allMac });
  t.click({ 'data-go': `rc:#/mission/${FC}/briefing` });
  t.click({ 'data-act': 'confirm-from-scan' });
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 50);
  t.click({ href: '#/city' }, 'A');
  assert.match(t.html(), /CONFIRMED<\/span> [^<]+/);
  assert.strictEqual(hudCount(t.html(), 'CONFIRMED'), 1);
});
```

- [ ] **Step 3: Append the RE-SWEEP gate test to `desktop/test/game-flow-gate.test.js`**

```js
test('a RE-SWEEP from the deck is the same game scan: monitoring software in it lands on the list, and the city stays closed', () => {
  const unsure = byId('unsure');
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'warning' }] }] };
  const seen = noteMonitoring(false, monitoring);
  assert.strictEqual(postScanView({ inGame: true, left: false, wantsCity: true, rememberedCity: true,
    offered: gameStillOffered(unsure, monitoring, seen), ready: true }), 'results');
  assert.strictEqual(gameStillOffered(unsure, { modules: [] }, seen), false);
});
```

- [ ] **Step 4: Run the tests and watch them fail**

Run: `cd desktop && node --test test/game-deck-controller.test.js test/game-controller.test.js test/game-flow-gate.test.js`
Expected: FAIL. The new deck-controller tests (no SWEEP log, no CONFIRMED points, no range screen) and the two scoring tests fail. The flow-gate test passes already, because it pins the existing gate for the new button.

- [ ] **Step 5: `rebuild` notices districts that became secured**

Replace the whole `rebuild` function (the Task 8 version) with:

```js
  function rebuild(doc, putBack = null) {
    const before = s.city ? cityIntegrity(s.city, signalsNow()) : null;
    s.doc = doc;
    s.city = findingsToCity(doc);
    const ranOk = ranOkModules(doc);
    const r = reconcile(s.progress, s.city, ranOk, now());
    s.cameBack = r.cameBack.filter((id) => id !== putBack);
    // The deck follows the scan too: a changed finding's tag is set aside, a
    // gone one's is dropped, and a confirmed fix that came back no longer counts.
    const rd = reconcileDeck(r.progress.deck, buildSignals(s.city, r.progress.deck), ranOk);
    rd.changed.forEach((id) => s.changedTags.add(id));
    s.progress = setDeck(r.progress, rd.deck);
    saveProgress(storage, s.progress);
    if (before) noteSecured(before, cityIntegrity(s.city, signalsNow()));
  }
```

- [ ] **Step 6: Record each new scan as a sweep**

Replace the whole `showCityFrom` function (the Task 8 version) with:

```js
  function showCityFrom(doc) {
    s.shown += 1;
    const prev = signalsNow();
    rebuild(doc);
    // A new scan, not the same one shown again, is a sweep.
    if (doc !== s.sweptDoc) newSweep(doc, prev);
    s.screen = 'map'; s.outcome = null; s.lastFix = null; s.linkNotice = ''; s.rcRoute = null; s.landing = null;
    s.lesson = null; s.pendingCity = false;
    s.signal = null; s.filter = null; s.lowOpen = false; s.range = null;
    s.focusPending = true;
  }
```

- [ ] **Step 7: Add the sweep, moment, range and report helpers**

Directly after the `batchFine` function (Task 8, Step 9), add:

```js
  // A finished scan: a date and counts in the store, a SWEEP line in the log,
  // "no longer seen" for what's gone (no points: only a re-check confirms),
  // the clean-sweep bonus when this re-sweep cleared the board, and new drills.
  function newSweep(doc, prev) {
    s.sweptDoc = doc;
    const sigs = signalsNow();
    const counts = sweepCounts(doc, s.city, cityIntegrity(s.city, sigs));
    const r = recordSweep(s.progress.deck, counts, now());
    commitAward(r);
    logEntry('SWEEP', `${counts.checks} check${counts.checks === 1 ? '' : 's'}: ${counts.critical} critical, ${counts.warning} warning, ${counts.fog} couldn’t check.`);
    if (r.clean) {
      s.moment = { kind: 'clean', title: 'CLEAN SWEEP', text: 'No critical or warning signal is open in any district that could be checked.' };
      logEntry('CLEAN SWEEP', 'Every district that could be checked is secured.');
    }
    const here = new Set(sigs.map((x) => x.id));
    for (const p of prev) {
      if (p.kind === 'real' && (p.tag || p.severity !== 'info') && !here.has(p.id)) logEntry('NO LONGER SEEN', p.title);
    }
    s.opened = {};
    s.drillAnswers = {};
    s.sweepDrills = s.drillsLoaded ? sweepDrillsNow() : null;
  }

  // A district that had something open and now has nothing open in the checks that ran.
  function noteSecured(before, after) {
    for (const id of after.securedIds) {
      if (before.securedIds.has(id) || !before.checkedIds.has(id)) continue;
      const name = nameOf(id) || id;
      s.moment = { kind: 'secured', title: 'DISTRICT SECURED', text: `${name}: nothing critical or warning is open in the checks that ran.` };
      logEntry('SECURED', name);
    }
  }

  // The DRILL RANGE: every district's drills, the ones not yet answered right first.
  function rangeHtml() {
    if (!s.range) s.range = { order: [], i: 0 };
    if (s.drillsLoaded && !s.range.order.length) {
      s.range.order = pickDrills(s.drillBank, DISTRICTS.map((d) => d.id), s.progress.deck, s.progress.deck.drills.tried).map((d) => d.id);
    }
    const order = s.range.order;
    const id = order.length ? order[s.range.i % order.length] : null;
    if (id && (!s.signal || s.signal.id !== `drill:${id}`)) s.signal = { id: `drill:${id}`, tagged: null, right: false, read: '', points: 0 };
    return renderRange({ loaded: s.drillsLoaded, panelHtml: id ? signalPanelHtml() : '', hasCity: !!s.city });
  }

  // Game missions the person just finished. Finished from the checkup (confirmedId)
  // is a confirmed fix; anything else is the person's report. Each pays once, ever.
  function creditReports(before, after, confirmedId) {
    const was = (before && before.missions) || {};
    for (const [id, rec] of Object.entries((after && after.missions) || {})) {
      if (!rec || !DONE.has(rec.status) || (was[id] && DONE.has(was[id].status))) continue;
      const title = (rcMission(id) || {}).title || 'A mission';
      if (id === confirmedId) {
        commitAward(award(s.progress.deck, 'fix', `rc:${id}`));
        logEntry('CONFIRMED', title);
      } else {
        if (rec.status === 'completed') commitAward(award(s.progress.deck, 'report', id));
        logEntry('YOU REPORTED', title);
      }
    }
  }
```

- [ ] **Step 8: The range screen in `screenHtml`**

Replace:

```js
  function screenHtml() {
    if (s.screen === 'training') {
```

with:

```js
  function screenHtml() {
    if (s.screen === 'range') return rangeHtml();
    if (s.screen === 'training') {
```

- [ ] **Step 9: RE-SWEEP and the range's clicks**

Replace (the line Task 8 added):

```js
    // The deck: the queue, the Signal or Noise panel, and the district filter.
```

with:

```js
    // RE-SWEEP: the same read-only scan as the plain route, through app.js, whose
    // gate decides where it lands (monitoring software: the plain list).
    if (act === 'resweep') { if (!s.scan.running) win.RescueHost.startCheckup(); return; }
    // The DRILL RANGE: more drills, with or without a scan.
    if (go === 'range') { s.signal = null; s.range = { order: [], i: 0 }; s.screen = 'range'; render(); return; }
    if (act === 'next-drill' && s.range) { s.range = { ...s.range, i: s.range.i + 1 }; s.signal = null; render(); return; }
    if (act === 'leave-range') { s.range = null; s.signal = null; s.screen = s.city ? 'map' : 'training'; render(); return; }
    // The deck: the queue, the Signal or Noise panel, and the district filter.
```

- [ ] **Step 10: Only a re-check confirms a fix**

In `recheck`, replace:

```js
    const outcome = recheckOutcome(m.id, s.city, res);
```

with:

```js
    const outcome = recheckOutcome(m.id, s.city, res);
    // Only a re-check proves a fix: CONFIRMED, and the fix points pay once per finding, ever.
    if (outcome === 'reclaimed' && (trigger === 'fix' || trigger === 'i-did-it')) {
      commitAward(confirmFix(s.progress.deck, m.id, now()));
      logEntry('CONFIRMED', m.title);
    }
    if (outcome === 'yours') logEntry('MARKED', m.title);
```

- [ ] **Step 11: Reported and confirmed game missions**

Replace:

```js
  // `refused` is a link the game data gave that isn't https, so nothing opens.
  function applyResult(r, refused = '') {
    if (!r || r.incomplete) return; // an unfinished form stays as the person left it
    setRcState(r.state);
```

with:

```js
  // `refused` is a link the game data gave that isn't https, so nothing opens.
  // `confirmedId`: the mission "Finish from the checkup" just filed.
  function applyResult(r, refused = '', confirmedId = null) {
    if (!r || r.incomplete) return; // an unfinished form stays as the person left it
    const before = s.rcState;
    setRcState(r.state);
    creditReports(before, s.rcState, confirmedId);
```

and in `confirmFromScan`, replace:

```js
    saveScanConfirmed(storage, s.scanConfirmed);
    applyResult(r);
```

with:

```js
    saveScanConfirmed(storage, s.scanConfirmed);
    applyResult(r, '', id);
```

- [ ] **Step 12: Run the tests and watch them pass**

Run: `cd desktop && node --test test/game-deck-controller.test.js test/game-controller.test.js test/game-flow-gate.test.js test/game-gate.test.js test/game-worry-scan.test.js`
Expected: PASS. Every existing gate test passes unchanged.

- [ ] **Step 13: Run the whole suite and the game-files check**

Run: `cd desktop && npm test && npm run check-game-files`
Expected: PASS.

- [ ] **Step 14: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/test/game-deck-controller.test.js desktop/test/game-controller.test.js desktop/test/game-flow-gate.test.js
git commit -m "Game: sweeps, RE-SWEEP, confirmed and reported points, moments, and the drill range"
```

---

### Task 10: Manual QA and docs

**Files:**
- Modify: `desktop/MANUAL-QA.md` (a new section before the closing "Record anything…" line)
- Modify: `README.md` (one paragraph in the game section)

**Interfaces:**
- Consumes: the finished feature (Tasks 1–9).
- Produces: release checks a person runs on a real Mac, and the README's description of the deck.

- [ ] **Step 1: Add the deck's checks to `desktop/MANUAL-QA.md`**

Insert this section directly before the line `Record anything that doesn't match as a bug and fix it before the release goes out.`:

````markdown
## Command center (the deck)

Set up the test launch agent from "Game mode, end to end" first. Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start`, with DevTools open, and check:
1. Click **Play it as a game**, then **I'm not sure**. When the sweep finishes, the deck appears: **INCOMING SIGNALS** on the left, the city in the middle, **CITY INTEGRITY**, **SIGNALS** and **RANK** on the right, and the **OPS LOG** at the bottom with a SWEEP line. The top bar shows RANK, LAST SWEEP with the check count, and **RE-SWEEP ⟳**. There is no separate HUD row.
2. Click **INVESTIGATE NEXT ▶**. The most important signal opens in a panel. Its clues are **SCAN CLUE** buttons, and each opens with a "How to read this" line. For the `com.devicerescue.qa.helper` signal, **WHERE IT LIVES** names its folder under Application Support, with the note "Where apps keep their own files. An unfamiliar name here is worth a look."
3. Tag it **THREAT**. Scout's read appears. It says whether the scan agrees and why, and never says you're wrong. Close the panel: the signal is on the **THREAT BOARD** with **SEE THE STEPS ▶** or **SEE THE FIX ▶**. In Terminal, `ls ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist` still finds the file, because a tag changes nothing.
4. Open it again and tag it **MINE**. **OPTIONAL: TELL DEVICE RESCUE TOO** shows the "It's mine" button. Press it: its own confirmation question appears. Press **Cancel**. Nothing was marked.
5. Click **The Gatehouse** in the city. The queue shows only its signals, with **SHOW ALL** and **OPEN THE DISTRICT ▶**. Click **SHOW ALL**.
6. Open **LOW-PRIORITY SIGNALS (N)**. At most 50 show, plus "And N more" if there are more. Click **THESE ARE ALL FINE**. The row goes, SORTED goes up, and the points under RANK don't change.
7. If a **DRILL** row is in the queue, it has a hatched lime border and the DRILL stamp, and its panel says "Practice. This isn't on your computer." Answer it. A right answer adds points and a DRILL line in the log. A wrong one shows "The tell:" and adds nothing. CITY INTEGRITY doesn't move either way.
8. From the threat board, open the helper's steps, click **Fix it for me**, then **Yes, fix it**. After **RECLAIMED**, go back to the city. CONFIRMED reads 1, the log has a CONFIRMED line, and if nothing else was open in The Gatehouse, a **DISTRICT SECURED** banner shows once. Turn on System Settings → Accessibility → Display → Reduce motion and repeat with another fix: the banner appears without moving.
9. Click **RE-SWEEP ⟳**. The sweep screen runs the same checkup. Back on the deck, there's another SWEEP line, the sparkline has two points, and the sentence under it says "up from", "down from" or "the same as" last sweep. A finding you tagged that is still there keeps its tag. If one is gone, the log says "NO LONGER SEEN", and CONFIRMED doesn't go up for it.
10. Click **DRILL RANGE ▶**. A drill opens. **NEXT DRILL ▶** moves on, and **BACK TO THE DECK** returns. Then click **Start over**, **Play it as a game** and a worry, and click **ALL LESSONS** on the sweep: the Training Grounds offer **DRILL RANGE ▶** too, before the checkup has finished.
11. Make the window narrow (about 700 px wide). The panels stack in this order: queue, city, instruments, log. The Signal panel fits the width with no sideways scrolling.
12. Keyboard and VoiceOver: Tab reaches each queue row as a button, Enter opens it, and focus stays put when a clue opens or a tag is set. VoiceOver reads the sentence under CITY INTEGRITY, for example "City integrity 50%, up from 0% last sweep."
13. DevTools → Application → Local Storage → `device-rescue.game.v1`: `version` is 3, `deck.sweeps` entries have only `at` and numbers, `deck.tags` keys look like `launch_agent_audit|…`, and nothing anywhere says `monitoringSeen`.
14. Monitoring software in a re-sweep. Quit, save this as `/tmp/fake-rescue`, and run `chmod +x /tmp/fake-rescue`:
    ```sh
    #!/bin/sh
    # The first scan is the real engine; every scan after that "finds" monitoring software.
    case " $* " in
      *" scan "*)
        if [ -f /tmp/fake-rescue.ran ]; then
          echo '{"schema_version":1,"platform":"darwin","modules":[{"name":"stalkerware_scan","category":"security","status":"ok","error":null,"supported":true,"findings":[{"title":"Monitoring app found (test)","description":"Test only.","severity":"critical","category":"security","data":{}}]}]}'
          exit 0
        fi
        touch /tmp/fake-rescue.ran ;;
    esac
    exec "$REAL_RESCUE" "$@"
    ```
    Run `rm -f /tmp/fake-rescue.ran; REAL_RESCUE="$PWD/.venv/bin/rescue" RESCUE_ENGINE=/tmp/fake-rescue npm --prefix desktop start`. Play it as a game with **I'm not sure**. When the deck appears, click **RE-SWEEP ⟳**. When it finishes, the plain list results show, not the deck. **Start over** no longer offers **Play it as a game**. Quit, then delete `/tmp/fake-rescue` and `/tmp/fake-rescue.ran`.
15. On Windows or Linux (if available), the same deck appears, and there are no **OPEN IN SYSTEM SETTINGS** buttons.
16. Clean up the test launch agent as in "Game mode, end to end", step 8.

````

- [ ] **Step 2: Describe the deck in `README.md`**

In `README.md`, directly after the paragraph that ends "…nothing in the city lights up because of one.", add:

```markdown
In the game, the city's home is a command center. Each finding arrives as a
signal to sort. Open its clues (who made it, where it lives, what it does),
then call it MINE, LOOK CLOSER or THREAT. Tags only sort the game. They
change nothing on your computer, and a real change still asks you first.
Points come from looking closely, never from deleting anything or from
speed. Practice drills are mixed in, clearly marked and never about your
computer, and the Drill Range has more whenever you want them.
```

- [ ] **Step 3: Check that nothing in the docs gives a duration**

Run: `grep -nE "\b(seconds?|minutes?|hours?|days?|weeks?)\b" desktop/MANUAL-QA.md README.md | grep -i -E "deck|drill|signal|sweep" || echo "none"`
Expected: `none`.

- [ ] **Step 4: Run the whole suite one last time**

Run: `cd desktop && npm test && npm run check-game-files`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add desktop/MANUAL-QA.md README.md
git commit -m "Docs: the command center deck in manual QA and the README"
```

---

## Self-Review Notes

**Spec coverage:**

| Spec section | Task |
| --- | --- |
| §1 Deck replaces the city home in game mode | 8 (Steps 10–11) |
| §1 Top bar: rank, last sweep, check count, RE-SWEEP | 6 (`renderDeck`), 9 (Step 9) |
| §1 Incoming signals: order, info folded, drills mixed in, INVESTIGATE NEXT | 3 (`queueOf`), 5 (`mixDrills`), 6, 8 |
| §1 City: heat, fog never clear, district filter, account districts stay | 3 (`districtHeat`), 6 (map options), 8 (`filter:`) |
| §1 Instruments: integrity with fog excluded, sparkline, bars apart, rank | 3 (`cityIntegrity`), 6 (`renderInstruments`), 3 (`countDeckBars`) |
| §1 Ops log | 8 (`logEntry`), 9 (sweep, confirmed, reported, no longer seen, secured) |
| §2 Signal, clues locked until SCAN CLUE, only supported clues, how to read this | 4 (`cluesFor`), 7 (panel), 8 (`scanClue`) |
| §2 Network clues | Not built: they come from N3 and N4 (decision 9) |
| §2 MINE / LOOK CLOSER / THREAT, and Scout's read never "wrong" | 4 (`scoutRead`), 7, 8 (`tagSignal`) |
| §2 MINE offers MarkFlow; THREAT goes to the threat board with a next move; LOOK CLOSER stays | 6 (`nextMoveHtml`), 7, 8 |
| §2 Info batch-tagged; only opened ones earn | 8 (`batchFine`, which pays nothing) |
| §3 Drill bank as data files with an accuracy gate | 5 |
| §3 DRILL stamp, hatched border, practice line, never counted | 5 (tests), 6 (CSS), 7 (panel), 8 (test) |
| §3 About one per four, at most three, same districts; DRILL RANGE any time | 5 (`chooseDrills`), 8, 9 (range) |
| §3 Right scores (+ clue bonus); wrong scores nothing; the tell | 2 (`award` drill), 4 (`drillRead`), 8 (`answerDrill`) |
| §3 No drills about monitoring | 5 (`MONITORING_WORDS`, and no monitoring modules) |
| §4 Points table and what never earns | 2 (`POINTS`, `award` refusing kinds and monitoring keys), 8, 9 |
| §4 Ranks never drop; moments with a reduced-motion fallback | 2 (`rankOf`), 6 (CSS), 8 (rank-up), 9 (secured, clean) |
| §4 Storage v3; sweeps are counts; `monitoringSeen` never persisted | 1, 2 (`recordSweep`), 8 (monitoring test) |
| §5 Couldn't check → NOTED with the lesson link | 3, 7, 8 |
| §5 `marked_by_user` pre-tagged with a MARKED badge; `mark_stale` back in the queue | 3, 6, 8 |
| §5 Re-sweep: tags carry over; gone is "no longer seen"; only a re-check confirms | 2 (`reconcileDeck`), 9 |
| §5 Monitoring in a re-sweep withdraws the game | 9 (flow-gate test, `docChanged` test), 10 (QA step 14) |
| §5 Zero findings; hundreds of info; narrow window; Windows/Linux | 6, 8, 6 (CSS), 10 |
| Accessibility | 6 (real buttons, text equivalents, `aria-hidden` sparkline), 8 (focus kept), 10 (QA 12) |
| Testing section | Each task; existing gate tests run in 9 Step 12 |

**Placeholder scan:** every code step has complete code. The only references to future pieces (Breach Protocol, account steps, network clues) are in comments and in the decisions above, where they explain what this plan deliberately doesn't build.

**Type consistency:**
- Signal fields are `id`, `kind`, `severity`, `title`, `description`, `districtId`, `module`, `finding`, `missionId`, `fixable`, `marked`, `stale`, `fp`, `count`, `tag` and `changed` (plus `drill`). They're used with these names in Tasks 3, 5, 6, 7, 8 and 9.
- Deck fields are `points`, `rank`, `drills`, `tags`, `confirmed`, `once`, `sweep` and `sweeps`, in Tasks 1, 2, 8 and 9.
- `rankOf` returns `{ index, name, points, min, next, toNext }`, and `renderInstruments` reads `points`, `min`, `next` and `toNext`.
- `Clue` is `{ kind, label, lines, reading }` in Tasks 4, 5 and 7.
- `renderSignalPanel` takes `{ signal, districtName, clues, opened, tagged, right, read, points, scout, mineHtml, range }` in Task 7, and Task 8 passes exactly those.
