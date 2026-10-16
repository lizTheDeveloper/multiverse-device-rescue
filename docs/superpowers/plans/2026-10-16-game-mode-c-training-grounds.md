# Game Mode C: Training Grounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Before the scan, someone who chose "Play it as a game" can play short lessons in **The Training Grounds**. Those lessons explain how computers get compromised and what Device Rescue will and won't do. The real scan then runs as **the final boss**: Scout sweeps the city one district at a time. When the scan finishes, Plan A's city appears.

**Architecture:**
- **Lessons are data files** in `desktop/renderer/game/lessons/`. Each one cites its sources in this repo, and a mechanical accuracy test checks it against them. "Spot the fake message" is built from Reclaim City's vendored phishing data.
- **Pure modules** do the logic:
  - `training.js` orders and loads lessons, and decides what happens when a scan finishes.
  - `boss.js` turns scan progress events into district sweep states.
  - `progress.js` (version 2) records lessons the person has finished.
- **New pure views** render the Training Grounds, a lesson, and the boss screen.
- **Plan A's `controller.js` gains** the screens `training`, `lesson` and `boss`, and the methods `showTraining`, `showBoss`, `scanEvent`, `scanDone` and `scanFailed`.
- **`app.js`** still owns the scan:
  - It sends a picked worry into the Training Grounds.
  - It starts the checkup when the game asks.
  - It forwards progress events to the boss.
  - It decides with a pure `postScanView()` whether the person lands in the city or the list. The safety gate is checked again after the scan.

**Tech Stack:** plain JS ES modules (game mode) and classic scripts (`app.js`), with no bundler; Electron 41; `node --test` on Node 22.

**Spec:** `docs/superpowers/specs/2026-10-16-game-mode-training-grounds-design.md`. Read its "Changes made during planning" section first. It builds on `docs/superpowers/specs/2026-10-16-game-mode-device-missions-design.md` and on **Plan A, `docs/superpowers/plans/2026-10-16-game-mode-a-device-missions.md`, which must be fully done first.** Every name this plan takes from Plan A is listed in a task's **Consumes** line.

**Defaults used for the spec's "Decisions to confirm" (the user may override any of them):**
1. The Training Grounds is its own screen at the gate, before the scan. It isn't a building inside a district.
2. The first lesson set is the spec's seven lessons, plus "Spot the fake message".
3. Lessons stay in Device Rescue. They aren't upstreamed to Reclaim City.
4. The phishing quiz is included, as the lesson "Spot the fake message". Its data is pure (it has no imports).

**Works without Spec B.** Nothing here needs Plan B. If Plan B has already widened `RC_ALLOW` to cover `data/*.js`, Task 4's `RC_ALLOW` line is already covered; keep the test anyway.

## Global Constraints

- **The scan is never locked behind lessons.** Every Training Grounds screen state and every lesson screen offers `data-act="start-checkup"` ("SKIP TO THE CHECKUP ▶" / "START THE CHECKUP ▶"). While a scan is running, they offer `data-go="boss"` ("BACK TO THE CHECKUP ▶") instead.
- **Lessons teach. They never diagnose.** No lesson text contains a phrase from `DIAGNOSTIC_PHRASES` in Task 2.
- **Every claim has a source.** Every lesson has at least one entry in `sources`, and each is a repo-relative path that exists. Any UI path (`A > B`, `A → B`) and any backticked text in a lesson appears word for word in one of its sources, with whitespace normalized.
- **No time words in lesson text:** none of `second(s)`, `minute(s)`, `hour(s)`, `day(s)`, `week(s)`.
- **No scores.** Lessons record only `completedAt`. A wrong answer gets feedback, never a penalty.
- **Lessons never count toward fixes.** `countReclaimed` reads only `missions`.
- **The safety gate:** the Training Grounds is reached only when Plan A's `gameOfferedFor(situation, null)` is true. After the boss scan, `postScanView` sends the person to the list whenever `gameOfferedFor(situation, doc)` is false.
- **Before the scan finishes,** districts on the boss screen are only `waiting`, `sweeping` or `swept`. They're never safe, clear or unsafe.
- **Real worry ids only:** `hacked`, `watched`, `wifi`, `identity`, `sketchy`, `phone`, `helping`, `unsure`. `password-asker` comes first for every worry.
- **Storage:** the key stays `device-rescue.game.v1`, and the stored `version` becomes `2`.
- **The vendored commit and Plan A's constraints all still apply.** That means opt-out first, escaping everything that comes from the engine, and the CSP unchanged.
- **Copy** is for a frightened non-technical person: short sentences, no time estimates, never "you're safe".

## Review Focus

1. **The scan finishes while the person is partway through a lesson.** They must not be pulled out of the lesson. A "Your checkup is done" banner appears, the answer they picked is kept, and the city is one click away. Pinned in Task 6 (`afterScanDone`) and Task 6 (the lesson view with `pendingCity`).
2. **The scan fails during the boss screen.** The person lands back in the Training Grounds with the error in plain words and "START THE CHECKUP ▶". They're never left on a frozen boss screen. Pinned in Task 6 (the training view with `scan.error`) and Task 7 (`scanFailed` sets the training screen).
3. **Malformed progress events:** missing or unknown `category`, `index > total`, a negative or missing `findings`, non-progress events, and events that arrive after the scan finished. Unknown categories go to The Outskirts, numbers are clamped, and late events are ignored. Pinned in Task 3.
4. **The boss scan finds monitoring software, or the person chose "Plain view" mid-scan.** They must land on the list results, never the city. Pinned in Task 7 (`postScanView`).
5. **Saved progress from Plan A (version 1), or version 2 with a corrupt `lessons` field.** Missions are kept and lessons start empty. The city never loses mission state because of a lessons problem. Pinned in Task 1.

---

## File Structure

**Plan A files this plan changes**
- `desktop/renderer/game/progress.js`: version 2, `lessons`, `migrate`, `setLessonDone`, `lessonDone`.
- `desktop/renderer/game/findings-to-city.js`: export `OUTSKIRTS` and `districtIdFor`.
- `desktop/renderer/game/views/briefing.js`: an optional `learned` link.
- `desktop/renderer/game/controller.js`: the training, lesson and boss screens, and the new methods.
- `desktop/renderer/game/game.css`: `.train`, `.boss` and the lesson rules.
- `desktop/renderer/app.js`: `trainingFirst`, `postScanView`, the worry click, `runCheckup`, and `RescueHost.startCheckup`/`scanTips`/`leaveGame`.
- `desktop/app-protocol.js`: `RC_ALLOW` gains `data/phishing.js`.
- `desktop/package.json`: `build.files` gains the vendored `phishing.js`.
- `desktop/test/game-progress.test.js`: one assertion updated for version 2.

**New game files** (ES modules)
- `game/boss.js`: `bossInit`, `bossApply`, `bossFinish`, `bossDistricts`, `bossPercent`.
- `game/training.js`: `WORRY_IDS`, `FIRST_LESSON`, `LESSON_FILES`, `DIAGNOSTIC_PHRASES`, `orderLessons`, `loadLessons`, `lessonForModule`, `afterScanDone`.
- `game/lessons/password-asker.js`, `starts-on-its-own.js`, `locked-door.js`, `whos-on-wifi.js`, `browser-add-ons.js`, `couldnt-check.js`, `poisoned-packages.js`, each with a default export.
- `game/lessons/spot-the-fake.js`: `PICKS`, `buildSpotTheFake(messages)`.
- `game/views/training.js` (`skipBar`, `cityBanner`, `lessonText`, `renderTraining`), `game/views/lesson.js` (`renderLesson`), `game/views/boss.js` (`renderBoss`).

**Tests** (`desktop/test/`)
- `game-progress.test.js` (extended), `game-boss.test.js`, `game-lessons.test.js`, `game-training.test.js`, `game-training-views.test.js`, `game-flow-gate.test.js`
- `game-vendor-contract.test.js` and `app-protocol.test.js` (both extended)

**Docs**
- `README.md`, `desktop/MANUAL-QA.md`

---

### Task 1: Progress version 2, with lessons

**Files:**
- Modify: `desktop/renderer/game/progress.js` (Plan A Task 8)
- Modify: `desktop/test/game-progress.test.js`

**Interfaces:**
- Consumes (Plan A): `STORE_KEY`, `emptyProgress`, `loadProgress`, `saveProgress`, `ranOkModules`, `reconcile`, `setStatus`, `recheckOutcome` and `countReclaimed`, with unchanged signatures.
- Produces:
  - `emptyProgress() -> {version: 2, missions: {}, lessons: {}}`
  - `migrate(raw) -> Progress`
  - `setLessonDone(progress, id, now) -> Progress`
  - `lessonDone(progress, id) -> boolean`
  - `Progress.lessons = {[lessonId]: {completedAt: string}}`
  - Every function that returns a Progress keeps `lessons`.

- [ ] **Step 1: Update the one Plan A assertion that hard-codes version 1, and add the version 2 tests**

In `desktop/test/game-progress.test.js`, find the `'storage: round trip, corrupt JSON, wrong version, and storage that throws'` test. Replace its first three lines after `const s = memStore();`:

```js
  const p = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
```

with:

```js
  const p = { version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: {} };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
```

Add these tests to the end of the file:

```js
test('a saved version 1 store from Plan A migrates to version 2 and keeps every mission', async () => {
  const { loadProgress, STORE_KEY } = await load();
  const v1 = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', updatedAt: NOW }, b: { status: 'later', module: 'n', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(v1) }));
  assert.deepStrictEqual(p, { version: 2, missions: v1.missions, lessons: {} });
});

test('a corrupt lessons field is dropped but the missions survive', async () => {
  const { loadProgress, STORE_KEY } = await load();
  const missions = { a: { status: 'open', module: 'm', updatedAt: NOW } };
  for (const lessons of [null, [], 'x', { l: { completedAt: 5 } }, { l: null }]) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 2, missions, lessons }) }));
    assert.deepStrictEqual(p, { version: 2, missions, lessons: {} }, JSON.stringify(lessons));
  }
});

test('setLessonDone records completion only, and lessons never count as fixes', async () => {
  const { emptyProgress, setLessonDone, lessonDone, countReclaimed } = await load();
  const p = setLessonDone(emptyProgress(), 'password-asker', NOW);
  assert.deepStrictEqual(p.lessons, { 'password-asker': { completedAt: NOW } });
  assert.strictEqual(lessonDone(p, 'password-asker'), true);
  assert.strictEqual(lessonDone(p, 'other'), false);
  assert.strictEqual(countReclaimed(p), 0);
});

test('reconcile and setStatus keep finished lessons', async () => {
  const { emptyProgress, setLessonDone, reconcile, setStatus } = await load();
  let p = setLessonDone(emptyProgress(), 'locked-door', NOW);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  p = setStatus(p, 'a', 'later', 'm', NOW);
  assert.deepStrictEqual(p.lessons, { 'locked-door': { completedAt: NOW } });
  assert.strictEqual(p.version, 2);
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-progress.test.js`
Expected: FAIL. You'll see `setLessonDone is not a function`, and the round-trip assertion fails on `version`.

- [ ] **Step 3: Replace `desktop/renderer/game/progress.js` with the version 2 code**

```js
// Mission progress for game mode, plus finished lessons. The scan is the source
// of truth: progress only remembers what the person chose ("later"), what
// changed between scans, and which lessons they finished. "reclaimed" is only
// ever set by evidence: a re-check or a full scan where the finding's module ran
// and no longer reports it. Lessons never count toward fixes.
//
// The key keeps its v1 name so a saved Plan A store is found and migrated.
export const STORE_KEY = 'device-rescue.game.v1';
const STATUSES = new Set(['open', 'later', 'yours', 'reclaimed']);

export function emptyProgress() {
  return { version: 2, missions: {}, lessons: {} };
}

function plainObject(x) {
  return !!x && typeof x === 'object' && !Array.isArray(x);
}

function validMissions(m) {
  return plainObject(m) && Object.values(m).every((r) => r && STATUSES.has(r.status));
}

function validLessons(l) {
  return plainObject(l) && Object.values(l).every((r) => r && typeof r.completedAt === 'string');
}

export function migrate(raw) {
  if (!plainObject(raw) || !validMissions(raw.missions)) return emptyProgress();
  if (raw.version === 1) return { version: 2, missions: raw.missions, lessons: {} };
  if (raw.version === 2) return { version: 2, missions: raw.missions, lessons: validLessons(raw.lessons) ? raw.lessons : {} };
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

export function ranOkModules(doc) {
  const out = new Set();
  for (const m of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    if (m && typeof m.name === 'string' && m.status !== 'error' && m.supported !== false) out.add(m.name);
  }
  return out;
}

function allMissions(city) {
  return (city && Array.isArray(city.districts) ? city.districts : []).flatMap((d) => d.missions || []);
}

function base(progress) {
  return {
    version: 2,
    missions: { ...((progress && progress.missions) || {}) },
    lessons: { ...((progress && progress.lessons) || {}) },
  };
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
    if (!prev || prev.status !== status) next.missions[m.id] = { status, module: m.module, updatedAt: now };
  }
  for (const [id, rec] of Object.entries(next.missions)) {
    if (present.has(id) || rec.status === 'reclaimed') continue;
    if (ranOk.has(rec.module)) next.missions[id] = { ...rec, status: 'reclaimed', updatedAt: now };
  }
  return { progress: next, cameBack };
}

export function setStatus(progress, id, status, module, now) {
  const next = base(progress);
  next.missions[id] = { status, module, updatedAt: now };
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

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS. That includes Plan A's `game-views.test.js`, whose HUD test builds a progress object by hand with only `missions`; `countReclaimed` still reads it.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/progress.js desktop/test/game-progress.test.js
git commit -m "Keep finished lessons in game progress (store version 2)"
```

---

### Task 2: Lesson framework, accuracy test, and the first lesson

**Files:**
- Create: `desktop/renderer/game/training.js`, `desktop/renderer/game/lessons/password-asker.js`
- Test: `desktop/test/game-lessons.test.js`, `desktop/test/game-training.test.js`

**Interfaces:**
- Consumes: `lessonDone(progress, id)` (Task 1).
- Produces:
  - `WORRY_IDS: string[]`
  - `FIRST_LESSON = 'password-asker'`
  - `LESSON_FILES: string[]`, specifiers relative to `game/`
  - `DIAGNOSTIC_PHRASES: string[]`, `TIME_WORDS: RegExp`
  - `orderLessons(lessons, worryId) -> {recommended: Lesson[], other: Lesson[]}`
  - `loadLessons(importModule) -> Promise<Lesson[]>`. It never rejects.
  - `lessonForModule(lessons, progress, module) -> Lesson | null`
  - `afterScanDone(screen) -> 'banner' | 'city'`
  - `Lesson = { id, title, type?: 'phishing', recommendedFor: string[], modules: string[], sources: string[], briefing, whatTheScanLooksFor, questions: [{ prompt, message?: {type, from, subject, body}, options: [{ text, correct: boolean, feedback }] }] }`

- [ ] **Step 1: Write the failing accuracy test**

Create `desktop/test/game-lessons.test.js`. It loads every lesson the app would load and checks each one against this repo:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');

// The same specifiers the controller passes, mapped onto files on disk.
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const loadAll = async () => {
  const training = await import(pathToFileURL(path.join(GAME, 'training.js')).href);
  return { training, lessons: await training.loadLessons(importModule) };
};

// A UI path is two or more capitalised segments joined by " > " or " → ",
// e.g. "System Settings > Privacy & Security > FileVault".
const SEG = "[A-Z][\\w&]*(?: [A-Z&][\\w&]*)*";
const PATH_RE = new RegExp(`${SEG}(?: (?:>|→) ${SEG})+`, 'g');
const TICKS_RE = /`([^`]+)`/g;
const norm = (s) => String(s).replace(/\s+/g, ' ');

function ownText(lesson) {
  // For the phishing lesson, the messages and their tells are Reclaim City's
  // content. Only Device Rescue's wrapper text is checked here.
  const qs = lesson.questions.flatMap((q) => (lesson.type === 'phishing'
    ? [q.prompt]
    : [q.prompt, ...q.options.flatMap((o) => [o.text, o.feedback])]));
  return [lesson.title, lesson.briefing, lesson.whatTheScanLooksFor, ...qs];
}

function sourceText(lesson) {
  return norm(lesson.sources.map((s) => fs.readFileSync(path.join(ROOT, s), 'utf8')).join('\n'));
}

function moduleExists(name) {
  const mods = path.join(ROOT, 'modules');
  return fs.readdirSync(mods).some((cat) => fs.existsSync(path.join(mods, cat, name)));
}

test('every lesson file loads, and ids are unique', async () => {
  const { training, lessons } = await loadAll();
  assert.strictEqual(lessons.length, training.LESSON_FILES.length + 1, 'every lesson plus Spot the fake message');
  assert.strictEqual(new Set(lessons.map((l) => l.id)).size, lessons.length);
});

test('every lesson cites sources that exist, and modules that exist', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    assert.ok(Array.isArray(l.sources) && l.sources.length > 0, `${l.id} has no sources`);
    for (const s of l.sources) assert.ok(fs.existsSync(path.join(ROOT, s)), `${l.id}: missing source ${s}`);
    for (const m of l.modules) assert.ok(moduleExists(m), `${l.id}: no module ${m}`);
  }
});

test('every UI path and every backticked bit in a lesson appears word for word in its sources', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    const src = sourceText(l);
    for (const text of ownText(l)) {
      for (const p of norm(text).match(PATH_RE) || []) {
        assert.ok(src.includes(p), `${l.id}: UI path "${p}" is not in ${l.sources.join(', ')}`);
      }
      for (const [, inner] of norm(text).matchAll(TICKS_RE)) {
        assert.ok(src.includes(inner), `${l.id}: \`${inner}\` is not in ${l.sources.join(', ')}`);
      }
      if (/\bSystem Settings\b/.test(text)) assert.ok(src.includes('System Settings'), `${l.id}: names System Settings without a source that does`);
    }
  }
});

test('no lesson tells the person what is wrong with their own computer, or how long things take', async () => {
  const { training, lessons } = await loadAll();
  for (const l of lessons) {
    for (const text of ownText(l)) {
      const lower = text.toLowerCase();
      for (const phrase of training.DIAGNOSTIC_PHRASES) assert.ok(!lower.includes(phrase), `${l.id}: "${phrase}" in "${text}"`);
      assert.doesNotMatch(text, training.TIME_WORDS, `${l.id}: time word in "${text}"`);
    }
  }
});

test('every question has two or more options, exactly one right answer, and feedback on every option', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    assert.ok(l.questions.length >= 1 && l.questions.length <= 3, `${l.id}: 1–3 questions`);
    for (const q of l.questions) {
      assert.ok(q.options.length >= 2, `${l.id}: "${q.prompt}" needs options`);
      assert.strictEqual(q.options.filter((o) => o.correct === true).length, 1, `${l.id}: "${q.prompt}" needs exactly one right answer`);
      for (const o of q.options) assert.ok(typeof o.feedback === 'string' && o.feedback.trim(), `${l.id}: "${o.text}" has no feedback`);
    }
  }
});

test('recommendedFor uses only real worry ids, and matches the app’s worries', async () => {
  const { training, lessons } = await loadAll();
  const { SITUATIONS } = require('../renderer/app.js');
  assert.deepStrictEqual([...training.WORRY_IDS].sort(), SITUATIONS.map((s) => s.id).sort());
  for (const l of lessons) for (const w of l.recommendedFor) assert.ok(training.WORRY_IDS.includes(w), `${l.id}: unknown worry ${w}`);
});
```

Create `desktop/test/game-training.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/training.js');

const L = (id, recommendedFor = [], modules = []) => ({ id, title: id, recommendedFor, modules, questions: [] });

test('the password lesson comes first for every worry, then the recommended ones, then the rest', async () => {
  const { orderLessons, WORRY_IDS } = await load();
  const lessons = [L('a', ['wifi']), L('password-asker', []), L('b', ['wifi', 'hacked']), L('c', [])];
  for (const w of WORRY_IDS) {
    const { recommended } = orderLessons(lessons, w);
    assert.strictEqual(recommended[0].id, 'password-asker', w);
  }
  const wifi = orderLessons(lessons, 'wifi');
  assert.deepStrictEqual(wifi.recommended.map((l) => l.id), ['password-asker', 'a', 'b']);
  assert.deepStrictEqual(wifi.other.map((l) => l.id), ['c']);
  assert.deepStrictEqual(orderLessons(lessons, undefined).recommended.map((l) => l.id), ['password-asker']);
});

test('a lesson file that fails to load is left out; the rest still load', async () => {
  const { loadLessons, LESSON_FILES } = await load();
  const lessons = await loadLessons(async (spec) => {
    if (spec === LESSON_FILES[1]) throw new Error('broken file');
    if (spec === '../rc/data/phishing.js') throw new Error('no vendor');
    return { default: L(spec) };
  });
  assert.strictEqual(lessons.length, LESSON_FILES.length - 1);
  assert.ok(!lessons.some((l) => l.id === LESSON_FILES[1]));
});

test('lessonForModule links a mission to a lesson only once that lesson is done', async () => {
  const { lessonForModule } = await load();
  const lessons = [L('x', [], ['launch_agent_audit'])];
  assert.strictEqual(lessonForModule(lessons, { lessons: {} }, 'launch_agent_audit'), null);
  assert.strictEqual(lessonForModule(lessons, { lessons: { x: { completedAt: 'now' } } }, 'launch_agent_audit').id, 'x');
  assert.strictEqual(lessonForModule(lessons, { lessons: { x: { completedAt: 'now' } } }, 'disk_space'), null);
});

test('a scan that finishes mid-lesson shows a banner instead of pulling the person out', async () => {
  const { afterScanDone } = await load();
  assert.strictEqual(afterScanDone('lesson'), 'banner');
  for (const s of ['training', 'boss', 'map', undefined]) assert.strictEqual(afterScanDone(s), 'city');
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-lessons.test.js test/game-training.test.js`
Expected: FAIL with `Cannot find module …/training.js`.

- [ ] **Step 3: Write `desktop/renderer/game/training.js`**

`LESSON_FILES` lists all seven lessons now. Until Task 3 adds the other six, `loadLessons` leaves the missing ones out. So the "every lesson file loads" test fails until Task 3, which is expected. Mark that one test `{ todo: 'Task 3 adds the remaining lessons' }` for this task's commit, and remove the `todo` in Task 3.

```js
// The Training Grounds: which lessons exist, in what order, and how they load.
// Pure, except loadLessons, which takes the import function it should use.
import { lessonDone } from './progress.js';

export const WORRY_IDS = ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'];
export const FIRST_LESSON = 'password-asker';

// Specifiers relative to this file. Order is the order shown under "ALSO HERE".
export const LESSON_FILES = [
  './lessons/password-asker.js',
  './lessons/starts-on-its-own.js',
  './lessons/locked-door.js',
  './lessons/whos-on-wifi.js',
  './lessons/browser-add-ons.js',
  './lessons/couldnt-check.js',
  './lessons/poisoned-packages.js',
];

// Lessons teach; the scan diagnoses. None of these may appear in lesson text.
export const DIAGNOSTIC_PHRASES = [
  'your computer has', 'your mac has', 'your pc has', 'your computer is infected',
  'your computer is compromised', 'you are infected', 'you’re infected', "you're infected",
  'you have been hacked', 'you’ve been hacked', "you've been hacked", 'someone is on your',
];
export const TIME_WORDS = /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i;

export function orderLessons(lessons, worryId) {
  const list = Array.isArray(lessons) ? lessons : [];
  const first = list.filter((l) => l.id === FIRST_LESSON);
  const rest = list.filter((l) => l.id !== FIRST_LESSON);
  const fits = (l) => (l.recommendedFor || []).includes(worryId);
  return { recommended: [...first, ...rest.filter(fits)], other: rest.filter((l) => !fits(l)) };
}

async function loadSpotTheFake(importModule) {
  const [{ buildSpotTheFake }, { CURATED_MESSAGES }] = await Promise.all([
    importModule('./lessons/spot-the-fake.js'),
    importModule('../rc/data/phishing.js'),
  ]);
  return buildSpotTheFake(CURATED_MESSAGES);
}

// One file at a time: a broken lesson is left out, never the whole Training Grounds.
export async function loadLessons(importModule) {
  const tries = [
    ...LESSON_FILES.map((f) => Promise.resolve().then(() => importModule(f)).then((m) => m && m.default)),
    Promise.resolve().then(() => loadSpotTheFake(importModule)),
  ];
  const results = await Promise.allSettled(tries);
  return results
    .filter((r) => r.status === 'fulfilled' && r.value && typeof r.value.id === 'string')
    .map((r) => r.value);
}

export function lessonForModule(lessons, progress, module) {
  return (lessons || []).find((l) => (l.modules || []).includes(module) && lessonDone(progress, l.id)) || null;
}

export function afterScanDone(screen) {
  return screen === 'lesson' ? 'banner' : 'city';
}
```

Note on `loadSpotTheFake`: until Task 4 adds `lessons/spot-the-fake.js`, it rejects and is left out. The `game-training.test.js` test above stubs it out.

- [ ] **Step 4: Write `desktop/renderer/game/lessons/password-asker.js`**

Each claim comes from these sources:
- `docs/trust-and-safety.md`: "There is no prompt in the tool for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password."
- `desktop/renderer/permissions-content.json`: the administrator password line.
- `guides/remediation/review_windows_remote_access.md`: "unsolicited call/pop-up telling you to install remote-access software".
- `guides/home_network_intrusion/phase_3.md`: "TeamViewer, AnyDesk, VNC … Common leftovers from "tech support" phone scams".

```js
export default {
  id: 'password-asker',
  title: 'The tool that asks for your password',
  recommendedFor: ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'],
  modules: ['win_remote_access_audit'],
  sources: [
    'docs/trust-and-safety.md',
    'desktop/renderer/permissions-content.json',
    'guides/remediation/review_windows_remote_access.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'Device Rescue never asks for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password. There is no prompt for any of them anywhere in the tool. Your computer itself may ask for your administrator password, but only if you choose to apply a fix that changes a system setting. Read-only checks never ask for your password. Anything else that asks, whether it’s a pop-up, a phone call or a chat message, is a red flag. A common scam is an unexpected call or pop-up telling you to install remote-access software, which hands someone your screen.',
  whatTheScanLooksFor: 'The checkup looks for remote-access tools like TeamViewer, AnyDesk and VNC, which are common leftovers from “tech support” phone scams.',
  questions: [
    {
      prompt: 'A pop-up claims a virus was found and gives you a number to call for help. What should you do?',
      options: [
        { text: 'Call the number so they can fix it', correct: false,
          feedback: 'That’s how the scam starts. The caller usually asks you to install remote-access software, which hands them your screen.' },
        { text: 'Don’t call. Close it, and run a checkup you started yourself.', correct: true,
          feedback: 'Right. A checkup you opened yourself is one you can trust, and Device Rescue never asks for your passwords or codes.' },
        { text: 'Read them the code your phone just got, to prove it’s you', correct: false,
          feedback: 'Never read a code to anyone who contacted you. Device Rescue never asks for a one-time code.' },
      ],
    },
    {
      prompt: 'A box that says it’s from Device Rescue asks for your email password to “finish the scan”. What is it?',
      options: [
        { text: 'A normal part of the checkup', correct: false,
          feedback: 'Device Rescue has no prompt like that anywhere. Its checks never need your email password.' },
        { text: 'Something pretending to be Device Rescue. Don’t type anything, and close it.', correct: true,
          feedback: 'Right. The only password your computer may ask for is its own administrator password, and only when you choose a fix that changes a system setting.' },
      ],
    },
  ],
};
```

- [ ] **Step 5: Run the tests**

Run: `cd desktop && node --test test/game-lessons.test.js test/game-training.test.js`
Expected: PASS. The one test marked `todo` is reported as todo.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/training.js desktop/renderer/game/lessons/password-asker.js desktop/test/game-lessons.test.js desktop/test/game-training.test.js
git commit -m "Add the Training Grounds lesson framework, an accuracy test, and the password lesson"
```

---

### Task 3: The other six lessons

**Files:**
- Create: `desktop/renderer/game/lessons/starts-on-its-own.js`, `locked-door.js`, `whos-on-wifi.js`, `browser-add-ons.js`, `couldnt-check.js`, `poisoned-packages.js`
- Modify: `desktop/test/game-lessons.test.js` (remove the `todo` added in Task 2)

**Interfaces:**
- Produces: six default-exported `Lesson` objects, in the shape from Task 2.

- [ ] **Step 1: Remove the `todo` from the "every lesson file loads" test, and run it to see it fail**

Run: `cd desktop && node --test test/game-lessons.test.js`
Expected: FAIL, because the lesson count is short by six.

- [ ] **Step 2: Write `starts-on-its-own.js`**

Sources:
- `review_launch_persistence.md`: "a legitimate pattern for some background apps (sync clients, VPN helpers) but also a common persistence technique for unwanted software", "a program path in `/tmp`, `/var/tmp`, or a hidden directory", and "Move the plist to a quarantine folder rather than deleting outright".
- `audit_windows_autoruns.md`: the Run keys and Startup folders, and "legitimate installed software runs from `Program Files` … not a scratch/download location".
- `rescue/app_fixes.json`: the `will_change` text.
- `desktop/renderer/app.js`: the "verified signature" and "not signed" labels.

```js
export default {
  id: 'starts-on-its-own',
  title: 'Things that start on their own',
  recommendedFor: ['hacked', 'sketchy', 'helping', 'unsure'],
  modules: ['launch_agent_audit', 'launchd_persistence_audit', 'win_autoruns_audit'],
  sources: [
    'guides/remediation/review_launch_persistence.md',
    'guides/remediation/audit_windows_autoruns.md',
    'rescue/app_fixes.json',
    'desktop/renderer/app.js',
  ],
  briefing: 'Some programs set themselves up to start every time you log in. On a Mac these are launch agents. On Windows they sit in Run keys and the Startup folders. Lots of ordinary apps do this, like sync clients and VPN helpers. Unwanted software does it too, so it keeps running after a restart. For each program, Device Rescue tells you who made it and whether that could be checked: a “verified signature”, or “not signed”.',
  whatTheScanLooksFor: 'The checkup lists what starts on its own, and flags items that run from a hidden or temporary folder.',
  questions: [
    {
      prompt: 'Which of these is a warning sign in something that starts on its own?',
      options: [
        { text: 'It’s made by a company you know, with a verified signature', correct: false,
          feedback: 'That’s the reassuring case. A verified signature means the maker’s name was checked.' },
        { text: 'It runs a program from a hidden folder or a temporary folder', correct: true,
          feedback: 'Right. Installed software runs from its own install folder. A program in a temporary, Downloads or hidden folder is a strong sign of something that shouldn’t be there.' },
        { text: 'It’s a sync app you use all the time', correct: false,
          feedback: 'Sync clients and VPN helpers start on their own on purpose. That’s normal.' },
      ],
    },
    {
      prompt: 'You don’t recognise a background item. What’s the safest first move?',
      options: [
        { text: 'Delete it straight away', correct: false,
          feedback: 'Look before you remove anything, and move it aside rather than deleting it, so you can put it back if it turns out to be yours.' },
        { text: 'Check who made it, then switch it off in a way you can undo', correct: true,
          feedback: 'Right. Device Rescue’s “Fix it for me” stops the background job and moves its settings file to a quarantine folder. Nothing is deleted.' },
        { text: 'Leave it. Everything on a computer starts on its own.', correct: false,
          feedback: 'Some things do, on purpose. It’s still worth knowing what each one is, because unwanted software uses the same trick.' },
      ],
    },
  ],
};
```

- [ ] **Step 3: Write `locked-door.js`**

Sources:
- `enable_automatic_updates.md`: "Open System Settings > General > Software Update", "Click the "i" (info) button next to "Automatic updates"", and "Install Security Responses and system files … the most important one to enable, since it covers … rapid-response security patches".
- `enable_disk_encryption.md`: "FileVault encrypts the entire startup disk so its contents cannot be read without the correct password or recovery key, even if the physical disk is removed", "System Settings > Privacy & Security > FileVault", "write it down or save it in a password manager", "do not paste it into this tool, into chat, into a note synced to an account you don't control", and "anyone who has it can decrypt the entire disk".
- `enforce_lock_screen.md`: "System Settings > Lock Screen", and "set the delay to "Immediately"".

```js
export default {
  id: 'locked-door',
  title: 'Updates and the locked door',
  recommendedFor: ['identity', 'helping', 'unsure'],
  modules: ['automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'win_bitlocker_check', 'lock_screen_check', 'screen_lock_check'],
  sources: [
    'guides/remediation/enable_automatic_updates.md',
    'guides/remediation/enable_disk_encryption.md',
    'guides/remediation/enforce_lock_screen.md',
  ],
  briefing: 'Three settings do a lot of quiet work. Automatic updates install security fixes. On a Mac, “Install Security Responses and system files” is the most important one, because it covers rapid-response security patches. FileVault encrypts the whole startup disk, so its contents can’t be read without the password or recovery key, even if the disk is taken out. And a lock screen that asks for your password straight away stops someone using the computer while you step away.',
  whatTheScanLooksFor: 'The checkup looks at your update settings, whether the disk is encrypted, and how soon the screen asks for a password.',
  questions: [
    {
      prompt: 'On a Mac, where do you turn on automatic updates?',
      options: [
        { text: 'System Settings > General > Software Update', correct: true,
          feedback: 'Right. Click the “i” next to “Automatic updates” to see each switch.' },
        { text: 'System Settings > Privacy & Security > FileVault', correct: false,
          feedback: 'That’s disk encryption. Updates are under General.' },
        { text: 'System Settings > Lock Screen', correct: false,
          feedback: 'That’s where the lock screen settings live. Updates are under General.' },
      ],
    },
    {
      prompt: 'You turn on FileVault and it shows you a recovery key. Where should it go?',
      options: [
        { text: 'Paste it into Device Rescue so it’s kept safe', correct: false,
          feedback: 'Don’t paste it into this tool or into a chat. Anyone who has it can unlock the whole disk.' },
        { text: 'Write it down, or save it in a password manager', correct: true,
          feedback: 'Right. Treat it like a master password.' },
        { text: 'In a note that syncs to an account someone else can get into', correct: false,
          feedback: 'Keep it where only you can read it. Anyone who has it can unlock the whole disk.' },
      ],
    },
    {
      prompt: 'How soon after the screen locks should your Mac ask for the password?',
      options: [
        { text: 'Immediately', correct: true,
          feedback: 'Right. A long delay gives someone a chance to use it while you’re away.' },
        { text: 'Only after a restart', correct: false,
          feedback: 'That leaves it open whenever you step away. Choose “Immediately” in the Lock Screen settings.' },
      ],
    },
  ],
};
```

- [ ] **Step 4: Write `whos-on-wifi.js`**

This lesson cites the `home_network_intrusion` phase guides, because there's no router remediation guide. It covers only what those guides say:
- `phase_0.md`: "Slow computers, fans running constantly, a hot laptop doing nothing", and "Cutting off someone's access tells them they have been found out".
- `phase_1.md`: "It only shows devices that have been active recently, so it can be incomplete — the router's own admin page is the authoritative list", "twenty is normal now", "unplug or power off a suspected device and re-run Step 1. The entry that disappears is that device", "a hardware address can be changed in seconds, and blocking one only tells the intruder which address to stop using", and "The change that actually removes everyone you have not authorised is a new Wi-Fi passphrase".
- `phase_3.md`: "Mining is what a hot, loud, slow machine usually turns out to be".
- `phase_2.md`: what `router_security_audit` checks.

```js
export default {
  id: 'whos-on-wifi',
  title: 'Who’s on your Wi-Fi',
  recommendedFor: ['wifi'],
  modules: ['lan_device_inventory', 'arp_spoof_check', 'router_security_audit', 'wifi_security_audit', 'crypto_miner_detect', 'win_crypto_miner_detect'],
  sources: [
    'guides/home_network_intrusion/phase_0.md',
    'guides/home_network_intrusion/phase_1.md',
    'guides/home_network_intrusion/phase_2.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'A slow computer, fans running all the time, a hot laptop doing nothing: these are the usual reasons people worry about their Wi-Fi. On their own they don’t prove anyone is on it. A hot, loud, slow machine usually turns out to be something running on the computer itself, and the checkup looks at that separately. It can also list devices that have talked to this computer recently, but that list can be incomplete. The router’s own admin page is the full list. If the person you’re worried about is someone you know, read the safety note first: cutting off their access tells them they’ve been found out.',
  whatTheScanLooksFor: 'The checkup lists devices that have talked to this computer, checks what your router offers to the network, and looks for programs working the computer hard in the background.',
  questions: [
    {
      prompt: 'Your laptop is hot and the fan is loud. What does that tell you about your Wi-Fi?',
      options: [
        { text: 'Someone is definitely on my network', correct: false,
          feedback: 'Not on its own. Heat is about what’s running on the computer, not who’s on your Wi-Fi.' },
        { text: 'Not much on its own. Heat usually means a program is working hard.', correct: true,
          feedback: 'Right. The checkup looks at what’s running and at your network separately, so you’ll see which one it is.' },
        { text: 'My router has been hacked', correct: false,
          feedback: 'A hot laptop doesn’t point at the router. The checkup looks at the router’s settings on their own.' },
      ],
    },
    {
      prompt: 'The list shows more devices than you expected. What’s most likely?',
      options: [
        { text: 'Strangers have joined', correct: false,
          feedback: 'Maybe, but check first. Phones, TVs, printers, speakers and smart plugs all count. Twenty devices is normal in a home now.' },
        { text: 'They’re your own things: phones, TV, printer, smart plugs', correct: true,
          feedback: 'Usually, yes. Name each one. For anything you can’t name, unplug it and look again. The one that disappears is that device.' },
      ],
    },
    {
      prompt: 'What actually removes everyone you haven’t allowed onto your Wi-Fi?',
      options: [
        { text: 'A new Wi-Fi passphrase', correct: true,
          feedback: 'Right. Every device has to join again with the new one.' },
        { text: 'Blocking devices by hardware address', correct: false,
          feedback: 'A hardware address is easy to change, so blocking one only tells an intruder which address to stop using.' },
        { text: 'Restarting the laptop', correct: false,
          feedback: 'That doesn’t change who can join. A new Wi-Fi passphrase does.' },
      ],
    },
  ],
};
```

- [ ] **Step 5: Write `browser-add-ons.js`**

Sources (`review_browser_extensions.md`):
- "Many legitimate extensions (ad blockers, password managers, session managers) need exactly this permission set to function, so this is a prompt to verify, not a verdict."
- The password manager vs "screenshot tool" example.
- `chrome://extensions/`, `about:addons`, and "Safari > Settings > Extensions".
- "have I used this in the last month? If not, remove it — you can always reinstall later".
- "more code running on every page you visit".

```js
export default {
  id: 'browser-add-ons',
  title: 'Browser add-ons',
  recommendedFor: ['hacked', 'sketchy', 'helping'],
  modules: ['browser_extension_audit', 'chrome_extensions', 'safari_extensions'],
  sources: ['guides/remediation/review_browser_extensions.md'],
  briefing: 'Browser extensions run code on the pages you visit. Many good ones, like ad blockers and password managers, need broad permissions to do their job, so a long list of permissions is a prompt to look, not a verdict. What matters is whether the permissions fit what the extension is for, and whether you recognise and trust the publisher.',
  whatTheScanLooksFor: 'The checkup lists your extensions, flags names known to be harmful or adware, and points out ones asking for an unusual set of permissions.',
  questions: [
    {
      prompt: 'Which extension’s permissions would you question?',
      options: [
        { text: 'A screenshot tool that wants to read your cookies and block web requests', correct: true,
          feedback: 'Right. A screenshot tool has no reason to need those.' },
        { text: 'A password manager that wants to work on every site', correct: false,
          feedback: 'That one’s expected. It has to fill in passwords everywhere.' },
        { text: 'An ad blocker that sees every page', correct: false,
          feedback: 'Also expected. It can’t block ads on pages it can’t see.' },
      ],
    },
    {
      prompt: 'Where do you see your extensions in Chrome?',
      options: [
        { text: '`chrome://extensions/`', correct: true,
          feedback: 'Right. Firefox uses `about:addons`, and Safari has Safari > Settings > Extensions.' },
        { text: '`about:addons`', correct: false,
          feedback: 'That’s Firefox’s page. Chrome’s is `chrome://extensions/`.' },
        { text: 'Safari > Settings > Extensions', correct: false,
          feedback: 'That’s Safari. Chrome’s is `chrome://extensions/`.' },
      ],
    },
    {
      prompt: 'You haven’t used an extension in the last month. What’s a good move?',
      options: [
        { text: 'Remove it. You can always reinstall it later.', correct: true,
          feedback: 'Right. Fewer extensions means less code running on every page you visit.' },
        { text: 'Keep every extension, just in case', correct: false,
          feedback: 'Each one is more code running on every page you visit. If you don’t use it, it can go.' },
      ],
    },
  ],
};
```

- [ ] **Step 6: Write `couldnt-check.js`**

Sources:
- `README.md`: "A check that couldn't run says so. It doesn't pretend everything is fine."
- `AGENTS.md`: "A module with `"supported": false` or `"status": "error"` checked nothing", and "a clean scan lowers the odds of a problem without ruling one out".
- `desktop/renderer/index.html`: "they aren't a clean bill of health. Often it just means a permission or tool is missing."

```js
export default {
  id: 'couldnt-check',
  title: 'What “couldn’t check” means',
  recommendedFor: ['unsure'],
  modules: [],
  sources: ['README.md', 'AGENTS.md', 'desktop/renderer/index.html'],
  briefing: 'Not every check can run on every computer. Some need a permission or a tool that’s missing, and some are only for another kind of computer. A check that couldn’t run checked nothing, so it isn’t a clean bill of health. Device Rescue says so instead of pretending everything is fine. In the city, those places show as fog. Even a checkup that finds nothing lowers the odds of a problem without ruling one out.',
  whatTheScanLooksFor: 'After the checkup, anything that couldn’t run is listed by name, so you know exactly what wasn’t looked at.',
  questions: [
    {
      prompt: 'A district on your map is covered in fog. What does that mean?',
      options: [
        { text: 'Those checks couldn’t run, so nobody knows yet', correct: true,
          feedback: 'Right. Often it just means a permission or a tool is missing.' },
        { text: 'Everything there is safe', correct: false,
          feedback: 'Fog means the opposite: nothing was checked there.' },
        { text: 'Something bad is hiding there', correct: false,
          feedback: 'Fog doesn’t mean danger either. It means a check couldn’t look.' },
      ],
    },
    {
      prompt: 'The checkup found nothing at all. What can you say?',
      options: [
        { text: 'The odds of a problem are lower, but it isn’t a guarantee', correct: true,
          feedback: 'Right. A clean checkup lowers the odds without ruling a problem out.' },
        { text: 'This computer is definitely clean', correct: false,
          feedback: 'No checkup can promise that. It lowers the odds; it doesn’t rule a problem out.' },
      ],
    },
  ],
};
```

- [ ] **Step 7: Write `poisoned-packages.js`**

Sources:
- `README.md`: "the "worm" attacks that spread through developer tools (npm, PyPI, GitHub)".
- `clean_ai_worm_filesystem.md`: "dropped scripts under `~/.local/bin`, `~/.config`, `~/.cache`, `/tmp`", "Inspect before moving anything", and "Quarantine, don't delete".
- `cut_ai_worm_c2.md`: "an active network connection was matched against a known AI worm C2/exfiltration domain", and "the process itself is the compromise; the network connection is only the symptom".
- `secure_git_ssh_after_worm.md`: "every `git clone` or `git init` silently installs a malicious hook", and "inspect the hook scripts … (don't run them)".

```js
export default {
  id: 'poisoned-packages',
  title: 'Poisoned packages',
  recommendedFor: ['sketchy'],
  modules: ['ai_worm_filesystem', 'ai_worm_git_ssh', 'ai_worm_persistence', 'ai_worm_network', 'ai_worm_lateral'],
  sources: [
    'README.md',
    'guides/remediation/clean_ai_worm_filesystem.md',
    'guides/remediation/cut_ai_worm_c2.md',
    'guides/remediation/secure_git_ssh_after_worm.md',
  ],
  briefing: 'This one is mostly for people who write code. Some attacks spread through developer tools like npm, PyPI and GitHub. A bad package drops scripts into hidden folders, talks to the attacker’s servers, and can change your git settings so that every project you clone quietly picks up a malicious hook. If you don’t use developer tools, you can skip this lesson.',
  whatTheScanLooksFor: 'The checkup looks for files these worms are known to drop, connections to their known servers, changed git settings, and anything set to start them again.',
  questions: [
    {
      prompt: 'The checkup flags a script a worm is known to drop. What do the guides say to do with it?',
      options: [
        { text: 'Read it first, then move it to a quarantine folder instead of deleting it', correct: true,
          feedback: 'Right. Inspect before moving anything, and quarantine rather than delete, so it can be looked at later.' },
        { text: 'Delete it straight away', correct: false,
          feedback: 'Read it first. What it does tells you which passwords and keys to change afterwards.' },
        { text: 'Run it to see what it does', correct: false,
          feedback: 'Never run it. Read it, don’t execute it.' },
      ],
    },
    {
      prompt: 'A program is talking to a known worm server. Is blocking that address enough?',
      options: [
        { text: 'No. The program itself is the problem; the connection is only the symptom.', correct: true,
          feedback: 'Right. Stop the program and find what keeps starting it.' },
        { text: 'Yes. Block it and carry on.', correct: false,
          feedback: 'The program would still be running. The connection is only the part you happened to see.' },
      ],
    },
  ],
};
```

- [ ] **Step 8: Run the accuracy test until it passes**

Run: `cd desktop && node --test test/game-lessons.test.js`
Expected: PASS, apart from the count check, which still waits for Task 4's lesson. If the count check alone fails, set it to `{ todo: 'Task 4 adds Spot the fake message' }`.

If a path or backtick check fails, the lesson text has drifted from its source. Fix the lesson text, never the regex.

- [ ] **Step 9: Commit**

```bash
git add desktop/renderer/game/lessons desktop/test/game-lessons.test.js
git commit -m "Add six Training Grounds lessons, each checked against its sources"
```

---

### Task 4: "Spot the fake message" from Reclaim City's phishing data

**Files:**
- Create: `desktop/renderer/game/lessons/spot-the-fake.js`
- Modify: `desktop/app-protocol.js` (`RC_ALLOW`), `desktop/package.json` (`build.files`)
- Test: `desktop/test/game-vendor-contract.test.js`, `desktop/test/app-protocol.test.js`, `desktop/test/game-training.test.js` (all extended)

**Interfaces:**
- Consumes: the vendored `desktop/vendor/reclaim-city/src/data/phishing.js`, which exports `CURATED_MESSAGES: [{id, type, from, subject, body, answer: 'pretext'|'genuine', tells: string[]}]`.
- Produces:
  - `PICKS = [1, 4, 5]`
  - `buildSpotTheFake(messages) -> Lesson`, with `type: 'phishing'`. It throws if none of the picks can be used.
  - `app://rescue/rc/data/phishing.js` is served.

- [ ] **Step 1: Write the failing tests**

Add to `desktop/test/game-vendor-contract.test.js`:

```js
test('Reclaim City’s phishing data is self-contained and has the messages the lesson uses', async () => {
  const file = need('data/phishing.js');
  assert.doesNotMatch(fs.readFileSync(file, 'utf8'), /^\s*import\s/m);
  const { CURATED_MESSAGES } = await import(file);
  for (const id of [1, 4, 5]) {
    const m = CURATED_MESSAGES.find((x) => x.id === id);
    assert.ok(m, `message ${id} gone upstream`);
    assert.ok(['pretext', 'genuine'].includes(m.answer));
    assert.ok(Array.isArray(m.tells) && m.tells.length > 0);
  }
});
```

Add to `desktop/test/app-protocol.test.js`, inside the `'rc/ serves only the allowlisted game sources'` test:

```js
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/data/phishing.js`, BASE).file, V('data/phishing.js'));
```

Add to `desktop/test/game-training.test.js`:

```js
test('buildSpotTheFake makes one real-or-fake question per picked message', async () => {
  const { buildSpotTheFake } = await import('../renderer/game/lessons/spot-the-fake.js');
  const msgs = [
    { id: 1, type: 'email', from: 'a@x', subject: 'S', body: 'B', answer: 'pretext', tells: ['Odd domain', 'Deadline.'] },
    { id: 4, type: 'call', from: '+1', subject: null, body: 'C', answer: 'pretext', tells: ['Asks for a code'] },
    { id: 5, type: 'email', from: 'n@g', subject: 'P', body: 'D', answer: 'genuine', tells: ['Real address'] },
    { id: 9, type: 'push', from: 'I', body: 'E', answer: 'genuine', tells: ['x'] },
  ];
  const l = buildSpotTheFake(msgs);
  assert.strictEqual(l.id, 'spot-the-fake');
  assert.strictEqual(l.type, 'phishing');
  assert.strictEqual(l.questions.length, 3);
  const [q1, , q3] = l.questions;
  assert.deepStrictEqual(q1.options.map((o) => [o.text, o.correct]), [['Fake', true], ['Real', false]]);
  assert.deepStrictEqual(q3.options.map((o) => [o.text, o.correct]), [['Fake', false], ['Real', true]]);
  assert.match(q1.options[0].feedback, /Odd domain\. Deadline\./);
  assert.deepStrictEqual(q1.message, { type: 'email', from: 'a@x', subject: 'S', body: 'B' });
  assert.throws(() => buildSpotTheFake([]));
  assert.throws(() => buildSpotTheFake([{ id: 1, answer: 'maybe', tells: ['x'] }]));
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-vendor-contract.test.js test/app-protocol.test.js test/game-training.test.js`
Expected: FAIL. `rc/data/phishing.js` resolves to `null`, and `spot-the-fake.js` isn't found.

- [ ] **Step 3: Implement it**

In `desktop/app-protocol.js`, change `RC_ALLOW` to:

```js
const RC_ALLOW = [/^components\/scout\.js$/, /^style\.css$/, /^data\/phishing\.js$/];
```

(If Plan B is already in, it has its own allowlist entries. Add `/^data\/phishing\.js$/` to that list instead of replacing it.)

In `desktop/package.json` `build.files`, add `"vendor/reclaim-city/src/data/phishing.js"`.

Create `desktop/renderer/game/lessons/spot-the-fake.js`:

```js
// "Spot the fake message", built from Reclaim City's own scam-defense quiz data
// (vendor/reclaim-city/src/data/phishing.js). The messages and their "tells" are
// Reclaim City's content; only the wrapper text here is Device Rescue's.
export const PICKS = [1, 4, 5];

function sentence(tells) {
  return `${tells.map((t) => String(t).replace(/[.\s]+$/, '')).join('. ')}.`;
}

export function buildSpotTheFake(messages) {
  const byId = new Map((Array.isArray(messages) ? messages : []).map((m) => [m && m.id, m]));
  const questions = PICKS.map((id) => byId.get(id))
    .filter((m) => m && (m.answer === 'pretext' || m.answer === 'genuine') && Array.isArray(m.tells) && m.tells.length)
    .map((m) => {
      const fake = m.answer === 'pretext';
      const why = sentence(m.tells);
      return {
        prompt: 'Real or fake?',
        message: { type: m.type, from: m.from, subject: m.subject || null, body: m.body },
        options: [
          { text: 'Fake', correct: fake, feedback: fake ? `Right, it’s fake. ${why}` : `This one is real. ${why}` },
          { text: 'Real', correct: !fake, feedback: fake ? `This one is fake. ${why}` : `Right, it’s real. ${why}` },
        ],
      };
    });
  if (!questions.length) throw new Error('Spot the fake message: no usable messages');
  return {
    id: 'spot-the-fake',
    type: 'phishing',
    title: 'Spot the fake message',
    recommendedFor: ['hacked', 'identity', 'helping'],
    modules: [],
    sources: ['desktop/vendor/reclaim-city/src/data/phishing.js'],
    briefing: 'Scammers copy the messages real companies send. These come from Reclaim City’s scam-defense quiz. For each one, decide whether it’s real or fake. Look at who sent it, whether it rushes you, and what it asks you to do.',
    whatTheScanLooksFor: 'The checkup can’t see your messages. It looks for what a scam can leave behind on the computer, like remote-access tools.',
    questions,
  };
}
```

Remove any `todo` left on the lesson-count test in `game-lessons.test.js`.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS. The lesson-count test now finds 8 lessons.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/spot-the-fake.js desktop/app-protocol.js desktop/package.json desktop/test/game-vendor-contract.test.js desktop/test/app-protocol.test.js desktop/test/game-training.test.js desktop/test/game-lessons.test.js
git commit -m "Add Spot the fake message, built from Reclaim City's phishing quiz data"
```

---

### Task 5: The boss's sweep state (`boss.js`)

**Files:**
- Modify: `desktop/renderer/game/findings-to-city.js` (Plan A Task 7): export `OUTSKIRTS`, and add `districtIdFor`.
- Create: `desktop/renderer/game/boss.js`
- Test: `desktop/test/game-boss.test.js`

**Interfaces:**
- Consumes (Plan A): `DISTRICTS`, and the private `districtFor(category)` in `findings-to-city.js`. The engine's progress events are `{type: 'progress', phase: 'start'|'done', index, total, module, category, findings, error}`.
- Produces:
  - `OUTSKIRTS` (exported), `districtIdFor(category) -> string`
  - `bossInit() -> Boss`, `bossApply(boss, ev) -> Boss`, `bossFinish(boss) -> Boss`
  - `bossDistricts(boss) -> [{id, name, state: 'waiting'|'sweeping'|'swept'}]`
  - `bossPercent(boss) -> 0..100`
  - `Boss = {index, total, found, current: string|null, seen: {[districtId]: number}, done: boolean}`

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-boss.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/boss.js');
const ev = (phase, index, total, category, findings = 0) => ({ type: 'progress', phase, index, total, module: 'm', category, findings });

test('districts go waiting → sweeping → swept as checks for their category run', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  let b = bossInit();
  assert.ok(bossDistricts(b).every((d) => d.state === 'waiting'));
  b = bossApply(b, ev('start', 1, 10, 'security'));
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'gatehouse').state, 'sweeping');
  b = bossApply(b, ev('done', 1, 10, 'security', 2));
  b = bossApply(b, ev('start', 2, 10, 'network'));
  const states = Object.fromEntries(bossDistricts(b).map((d) => [d.id, d.state]));
  assert.strictEqual(states.gatehouse, 'swept');
  assert.strictEqual(states.wires, 'sweeping');
  assert.strictEqual(states.junkyard, 'waiting');
  assert.strictEqual(b.found, 2);
});

test('no district state ever claims safe, clear or unsafe', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  const b = bossApply(bossInit(), ev('done', 1, 2, 'security', 9));
  for (const d of bossDistricts(b)) assert.ok(['waiting', 'sweeping', 'swept'].includes(d.state), d.state);
});

test('an unknown or missing category sweeps The Outskirts, which only appears once used', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  let b = bossInit();
  assert.ok(!bossDistricts(b).some((d) => d.id === 'outskirts'));
  b = bossApply(b, ev('start', 1, 3, 'test'));
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'outskirts').state, 'sweeping');
  b = bossApply(b, { type: 'progress', phase: 'start', index: 2, total: 3 });
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'outskirts').state, 'sweeping');
});

test('odd numbers are clamped; non-progress and late events are ignored', async () => {
  const { bossInit, bossApply, bossFinish, bossPercent } = await load();
  let b = bossApply(bossInit(), ev('done', 50, 10, 'security', -3));
  assert.strictEqual(b.index, 10);
  assert.strictEqual(b.found, 0);
  assert.strictEqual(bossPercent(b), 100);
  const before = b;
  assert.strictEqual(bossApply(b, { type: 'log', line: 'x' }), before);
  assert.strictEqual(bossApply(b, null), before);
  b = bossFinish(b);
  assert.strictEqual(bossApply(b, ev('done', 1, 10, 'network', 5)), b);
  assert.strictEqual(bossPercent(bossInit()), 0);
  assert.strictEqual(bossPercent(bossApply(bossInit(), ev('done', 3, 0, 'security'))), 0);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-boss.test.js`
Expected: FAIL with `Cannot find module …/boss.js`.

- [ ] **Step 3: Export the district helpers from `findings-to-city.js`**

Change `const OUTSKIRTS = {` to `export const OUTSKIRTS = {`, and add this directly under `function districtFor(category) { … }`:

```js
export function districtIdFor(category) {
  return districtFor(category).id;
}
```

- [ ] **Step 4: Write `desktop/renderer/game/boss.js`**

```js
// The final boss: the real scan, shown as Scout sweeping the city. Driven only by
// the engine's progress events. Until the scan finishes, a district is waiting,
// sweeping or swept — never safe or unsafe. That's decided by the results.
import { DISTRICTS, OUTSKIRTS, districtIdFor } from './findings-to-city.js';

export function bossInit() {
  return { index: 0, total: 0, found: 0, current: null, seen: {}, done: false };
}

const num = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);

export function bossApply(boss, ev) {
  if (!boss || boss.done || !ev || ev.type !== 'progress') return boss;
  const id = districtIdFor(ev.category);
  const total = num(ev.total) !== null && ev.total > 0 ? ev.total : boss.total;
  const rawIndex = num(ev.index) !== null ? Math.max(0, ev.index) : boss.index;
  const index = total ? Math.min(rawIndex, total) : rawIndex;
  const next = { ...boss, total, index, seen: { ...boss.seen } };
  if (ev.phase === 'start') {
    next.current = id;
    next.seen[id] = next.seen[id] || 0;
  } else if (ev.phase === 'done') {
    next.seen[id] = (next.seen[id] || 0) + 1;
    const f = num(ev.findings);
    next.found = boss.found + (f !== null && f > 0 ? f : 0);
  }
  return next;
}

export function bossFinish(boss) {
  return { ...(boss || bossInit()), done: true, current: null };
}

export function bossDistricts(boss) {
  const list = [...DISTRICTS, ...(boss && OUTSKIRTS.id in boss.seen ? [OUTSKIRTS] : [])];
  return list.map((d) => ({
    id: d.id,
    name: d.name,
    state: boss && boss.current === d.id ? 'sweeping' : (boss && d.id in boss.seen ? 'swept' : 'waiting'),
  }));
}

export function bossPercent(boss) {
  if (!boss || !boss.total) return 0;
  return Math.max(0, Math.min(100, Math.round((boss.index / boss.total) * 100)));
}
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS, including Plan A's `game-findings-to-city.test.js`.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/findings-to-city.js desktop/renderer/game/boss.js desktop/test/game-boss.test.js
git commit -m "Turn scan progress into the boss's district sweep"
```

---

### Task 6: The Training Grounds, lesson and boss views, and the briefing's "learned" link

**Files:**
- Create: `desktop/renderer/game/views/training.js`, `views/lesson.js`, `views/boss.js`
- Modify: `desktop/renderer/game/views/briefing.js` (Plan A Task 9): the optional `learned` param
- Modify: `desktop/renderer/game/game.css` (Plan A Task 11 Step 3): the training, lesson and boss rules
- Test: `desktop/test/game-training-views.test.js`

**Interfaces:**
- Consumes: `esc` (Plan A), `bossDistricts`/`bossPercent` (Task 5), `lessonDone` (Task 1), `Lesson` (Task 2).
- Produces:
  - `skipBar(scan) -> string`, `cityBanner() -> string`, `lessonText(s) -> string` (escapes, then turns `` `x` `` into `<code>x</code>`)
  - `renderTraining({ordered, progress, worryTitle, scan, scout, pendingCity}) -> string`
  - `renderLesson({lesson, qIndex, picked, scan, scout, pendingCity}) -> string`
  - `renderBoss({boss, scout, tips}) -> string`
  - `renderBriefing({…Plan A params, learned})`, where `learned` is `{id, title} | null`
  - `Scan = {running: boolean, index: number, total: number, error: string|null}`
  - New clickables: `data-go="training"|"boss"|"city"|"lesson:<id>"`, `data-act="start-checkup"|"answer:<n>"|"next-question"|"finish-lesson"|"leave"`

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-training-views.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/training.js')),
  ...(await import('../renderer/game/views/lesson.js')),
  ...(await import('../renderer/game/views/boss.js')),
  ...(await import('../renderer/game/views/briefing.js')),
  ...(await import('../renderer/game/boss.js')),
});
const LESSON = {
  id: 'l1', title: 'Lesson one', recommendedFor: [], modules: [], sources: ['README.md'],
  briefing: 'Open `chrome://extensions/` to see them.', whatTheScanLooksFor: 'Extensions.',
  questions: [
    { prompt: 'Q1?', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'Not quite.' }] },
    { prompt: 'Q2?', options: [{ text: 'A', correct: false, feedback: 'Nope.' }, { text: 'B', correct: true, feedback: 'Yes.' }] },
  ],
};
const idle = { running: false, index: 0, total: 0, error: null };
const running = { running: true, index: 12, total: 290, error: null };
const failed = { running: false, index: 0, total: 0, error: 'The engine stopped.' };
const ordered = { recommended: [LESSON], other: [] };

test('the way to the checkup is on every Training Grounds and lesson state', async () => {
  const v = await views();
  const states = [];
  for (const scan of [idle, running, failed]) {
    for (const pendingCity of [false, true]) {
      states.push(v.renderTraining({ ordered, progress: { lessons: {} }, worryTitle: 'x', scan, scout, pendingCity }));
      for (const [qIndex, picked] of [[0, null], [0, 1], [1, 1]]) {
        states.push(v.renderLesson({ lesson: LESSON, qIndex, picked, scan, scout, pendingCity }));
      }
    }
  }
  states.push(v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} }, scan: idle, scout }));
  for (const html of states) assert.match(html, /data-act="start-checkup"|data-go="boss"/);
});

test('while a scan runs, the button goes back to the checkup instead of starting another', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered, progress: { lessons: {} }, scan: running, scout });
  assert.match(html, /data-go="boss"/);
  assert.doesNotMatch(html, /data-act="start-checkup"/);
  assert.match(html, /12 of 290/);
});

test('a failed scan shows the error in plain words and offers to start again', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered, progress: { lessons: {} }, scan: failed, scout });
  assert.match(html, /didn’t finish/);
  assert.match(html, /The engine stopped\./);
  assert.match(html, /Nothing on your computer was changed/);
  assert.match(html, /START THE CHECKUP/);
});

test('mid-lesson, a finished scan shows a banner and keeps the picked answer', async () => {
  const v = await views();
  const html = v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 0, scan: idle, scout, pendingCity: true });
  assert.match(html, /Your checkup is done/);
  assert.match(html, /data-go="city"/);
  assert.match(html, /class="opt right"/);
  assert.match(html, /Right\./);
});

test('a lesson: briefing with code, feedback after answering, next then finish', async () => {
  const v = await views();
  const q1 = v.renderLesson({ lesson: LESSON, qIndex: 0, picked: null, scan: idle, scout });
  assert.match(q1, /<code>chrome:\/\/extensions\/<\/code>/);
  assert.doesNotMatch(q1, /class="feedback"/);
  assert.match(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 1, scan: idle, scout }), /data-act="next-question"/);
  const last = v.renderLesson({ lesson: LESSON, qIndex: 1, picked: 1, scan: idle, scout });
  assert.match(last, /data-act="finish-lesson"/);
  assert.match(last, /Extensions\./);
  assert.match(v.renderLesson({ lesson: LESSON, qIndex: 0, picked: 1, scan: idle, scout }), /class="opt wrong"/);
});

test('Reclaim City message text is escaped in the phishing lesson', async () => {
  const v = await views();
  const lesson = { ...LESSON, type: 'phishing', questions: [{ prompt: 'Real or fake?', message: { type: 'email', from: EVIL, subject: EVIL, body: EVIL },
    options: [{ text: 'Fake', correct: true, feedback: EVIL }, { text: 'Real', correct: false, feedback: 'x' }] }] };
  const html = v.renderLesson({ lesson, qIndex: 0, picked: 0, scan: idle, scout });
  assert.ok(!html.includes('<img src=x'));
  assert.match(html, /&lt;img src=x/);
});

test('the boss screen: sweep states, progress, a way to the lessons, escaped tips, and no verdicts', async () => {
  const v = await views();
  let b = v.bossInit();
  b = v.bossApply(b, { type: 'progress', phase: 'done', index: 1, total: 4, category: 'security', findings: 3 });
  b = v.bossApply(b, { type: 'progress', phase: 'start', index: 2, total: 4, category: 'network' });
  const html = v.renderBoss({ boss: b, scout, tips: [{ title: EVIL, body: 'Click Allow.' }] });
  assert.match(html, /SWEEPING/);
  assert.match(html, /SWEPT/);
  assert.match(html, /WAITING/);
  assert.match(html, /1 \/ 4 CHECKS/);
  assert.match(html, /3 THINGS NOTED SO FAR/);
  assert.match(html, /data-go="training"/);
  assert.match(html, /aria-valuenow="25"/);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html.replace(/<[^>]+>/g, ' '), /\b(safe|clear|nothing found|infected|hacked)\b/i);
});

test('the briefing links back to a finished lesson only when given one', async () => {
  const v = await views();
  const mission = { id: 'm1', districtId: 'gatehouse', severity: 'warning', title: 'T', description: 'D', steps: [{ number: 1, title: 'S', body: '' }],
    walkthroughTitle: null, safetyNote: null, findings: [{}], primary: {} };
  const base = { mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false };
  assert.doesNotMatch(v.renderBriefing(base), /Training Grounds/);
  const html = v.renderBriefing({ ...base, learned: { id: 'starts-on-its-own', title: EVIL } });
  assert.match(html, /data-go="lesson:starts-on-its-own"/);
  assert.match(html, /You learned about this in the Training Grounds/);
  assert.ok(!html.includes('<img src=x'));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-training-views.test.js`
Expected: FAIL with `Cannot find module …/views/training.js`.

- [ ] **Step 3: Write `desktop/renderer/game/views/training.js`**

```js
import { esc } from '../escape.js';
import { lessonDone } from '../progress.js';

// Lesson text may name a page in `backticks`; show it as code. Escape first.
export function lessonText(s) {
  return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
}

export function cityBanner() {
  return `<div class="banner" role="status"><span>Your checkup is done.</span>
    <button type="button" class="btn-p" data-go="city">SEE YOUR CITY ▶</button></div>`;
}

// On every Training Grounds and lesson screen: the way to the checkup.
export function skipBar(scan) {
  if (scan && scan.running) {
    return `<div class="skip-bar"><span>Your checkup is running: ${esc(scan.index)} of ${esc(scan.total || '…')} checks.</span>
      <button type="button" class="btn-s lime" data-go="boss">BACK TO THE CHECKUP ▶</button></div>`;
  }
  const label = scan && scan.error ? 'START THE CHECKUP ▶' : 'SKIP TO THE CHECKUP ▶';
  return `<div class="skip-bar"><span>You don’t need to finish any lessons first.</span>
    <button type="button" class="btn-s lime" data-act="start-checkup">${label}</button></div>`;
}

export function trainingHud(progress, lessons) {
  const done = lessons.filter((l) => lessonDone(progress, l.id)).length;
  return `<header class="hud"><span class="hud-title">THE TRAINING GROUNDS</span>
    ${lessons.length ? `<span class="stat lime"><b>${done}/${lessons.length}</b> <small>LESSONS</small></span>` : ''}
    <span class="switch"><button type="button" data-act="leave">PLAIN VIEW</button></span></header>`;
}

function lessonItem(l, progress) {
  const n = l.questions.length;
  return `<li><button type="button" class="lesson${lessonDone(progress, l.id) ? ' done' : ''}" data-go="lesson:${esc(l.id)}">
    <b>${esc(l.title)}</b><small>${n} question${n === 1 ? '' : 's'}</small>
    ${lessonDone(progress, l.id) ? '<span class="badge safe">DONE</span>' : ''}</button></li>`;
}

export function renderTraining({ ordered, progress, worryTitle, scan, scout, pendingCity }) {
  const all = [...ordered.recommended, ...ordered.other];
  const head = worryTitle ? `RECOMMENDED FOR “${esc(String(worryTitle).toUpperCase())}”` : 'START HERE';
  const failed = scan && scan.error ? `
    <div class="panel fogged" role="alert"><div class="label">THE CHECKUP DIDN’T FINISH</div>
      <p class="intel">${esc(scan.error)}</p>
      <p class="intel">Nothing on your computer was changed. You can start it again whenever you’re ready.</p></div>` : '';
  return `
  ${trainingHud(progress, all)}
  ${pendingCity ? cityBanner() : ''}
  ${failed}
  <section class="train">
    <div class="lessons">
      ${ordered.recommended.length ? `<span class="label">${head}</span><ul>${ordered.recommended.map((l) => lessonItem(l, progress)).join('')}</ul>` : ''}
      ${ordered.other.length ? `<span class="label faint">ALSO HERE</span><ul>${ordered.other.map((l) => lessonItem(l, progress)).join('')}</ul>` : ''}
      ${all.length ? '' : '<p class="intel">The lessons couldn’t load. The checkup still works.</p>'}
    </div>
    <div class="quiz">
      <div class="scout-row">${scout('happy', 72)}<p class="say">${esc('These are short. Pick any one, or go straight to the checkup.')}</p></div>
    </div>
  </section>
  ${skipBar(scan)}`;
}
```

- [ ] **Step 4: Write `desktop/renderer/game/views/lesson.js`**

```js
import { esc } from '../escape.js';
import { lessonText, skipBar, cityBanner, trainingHud } from './training.js';

export function renderLesson({ lesson: l, qIndex, picked, scan, scout, pendingCity }) {
  const i = Math.max(0, Math.min(qIndex, l.questions.length - 1));
  const q = l.questions[i];
  const last = i >= l.questions.length - 1;
  const answer = picked != null ? q.options[picked] : null;
  const options = q.options.map((o, n) => {
    const cls = answer ? (o.correct ? ' right' : (n === picked ? ' wrong' : '')) : '';
    return `<button type="button" class="opt${cls}" data-act="answer:${n}" data-k="${String.fromCharCode(65 + n)}"${answer ? ' aria-disabled="true"' : ''}>${lessonText(o.text)}</button>`;
  }).join('');
  const message = q.message ? `
    <div class="message-card"><span class="badge skip">${esc(String(q.message.type || '').toUpperCase())}</span>
      <p class="from">From: ${esc(q.message.from)}</p>
      ${q.message.subject ? `<p><strong>${esc(q.message.subject)}</strong></p>` : ''}
      <p>${esc(q.message.body)}</p></div>` : '';
  const after = answer ? `
    <div class="feedback" role="status">${lessonText(answer.feedback)}</div>
    ${last
      ? `<p class="intel"><strong>In the checkup:</strong> ${lessonText(l.whatTheScanLooksFor)}</p>
         <button type="button" class="btn-p" data-act="finish-lesson">FINISH LESSON</button>`
      : '<button type="button" class="btn-p" data-act="next-question">NEXT QUESTION</button>'}` : '';
  return `
  ${trainingHud({ lessons: {} }, [])}
  ${pendingCity ? cityBanner() : ''}
  <section class="quiz lesson-screen">
    <div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${l.questions.length}</div>
    ${i === 0 ? `<div class="panel"><div class="label">WHAT TO KNOW</div><p class="intel">${lessonText(l.briefing)}</p></div>` : ''}
    ${message}
    <p class="q">${lessonText(q.prompt)}</p>
    <div class="options">${options}</div>
    ${after}
    <div class="scout-row">${scout(answer && answer.correct ? 'happy' : 'thinkingA', 54)}</div>
  </section>
  ${skipBar(scan)}`;
}
```

- [ ] **Step 5: Write `desktop/renderer/game/views/boss.js`**

```js
import { esc } from '../escape.js';
import { bossDistricts, bossPercent } from '../boss.js';

const LABEL = { sweeping: 'SWEEPING', swept: 'SWEPT', waiting: 'WAITING' };

function skyline() {
  return '<div class="skyline" aria-hidden="true"><img src="assets/iso_occupied.png" alt=""><img class="tower" src="assets/iso_tower_occ.png" alt=""></div>';
}

export function renderBoss({ boss, scout, tips }) {
  const ds = bossDistricts(boss);
  const pct = bossPercent(boss);
  const current = ds.find((d) => d.state === 'sweeping');
  const line = current
    ? `Checking ${current.name} now. You don’t need to watch. I’ll call you when it’s done.`
    : 'Starting the checkup engine.';
  const tipList = Array.isArray(tips) && tips.length ? `
    <details class="panel" open><summary class="label">POP-UPS YOU MIGHT SEE</summary>
      <ul class="notes">${tips.map((t) => `<li><strong>${esc(t.title)}</strong> ${esc(t.body)}</li>`).join('')}</ul></details>` : '';
  return `
  <section class="boss" aria-label="Your checkup is running">
    <div class="boss-top">${scout('proud', 72)}
      <div class="boss-meter"><h2>THE SWEEP</h2>
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="--pct: ${pct}%"></i></div>
        <div class="bar-meta"><span>${boss.total ? `${esc(boss.index)} / ${esc(boss.total)} CHECKS` : 'GETTING READY'}</span>
          ${boss.found ? `<span>${esc(boss.found)} THING${boss.found === 1 ? '' : 'S'} NOTED SO FAR</span>` : ''}</div></div></div>
    <div class="districts sweep">${ds.map((d) => `
      <div class="district ${d.state}"><h4>${esc(d.name.toUpperCase())}</h4>${skyline()}
        <span class="d-foot"><span class="badge ${d.state === 'sweeping' ? 'cyan' : 'skip'}">${LABEL[d.state]}</span></span></div>`).join('')}</div>
    <div class="row"><p class="say">${esc(line)}</p>
      <button type="button" class="btn-s lime" data-go="training">PLAY A LESSON WHILE YOU WAIT</button>
      <button type="button" class="btn-t" data-act="leave">PLAIN VIEW</button></div>
    ${tipList}
  </section>`;
}
```

- [ ] **Step 6: Add the `learned` link to Plan A's `views/briefing.js`**

Change the signature to `export function renderBriefing({ mission: m, status, controlsHtml, scout, busy, wantsSafety, learned }) {`. In the returned template, add this right after the `WHAT IT IS` panel line:

```js
      ${learned ? `<p class="from"><button type="button" class="link" data-go="lesson:${esc(learned.id)}">You learned about this in the Training Grounds: ${esc(learned.title)} →</button></p>` : ''}
```

- [ ] **Step 6b: Give the city's HUD a way back to the Training Grounds**

Spec C §2 says people can come back from the city at any time. In Plan A's `views/hud.js`, change the switch line to:

```js
    <span class="switch"><button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
```

Add to `game-training-views.test.js`:

```js
test('the city HUD links back to the Training Grounds', async () => {
  const { renderHud } = await import('../renderer/game/views/hud.js');
  const html = renderHud({ title: 'T', city: { districts: [], totals: { critical: 0, warning: 0, fog: 0 } }, progress: { missions: {} } });
  assert.match(html, /data-go="training"/);
  assert.match(html, /data-act="list"/);
});
```

- [ ] **Step 7: Add the CSS to `game.css`**

From `docs/superpowers/specs/2026-10-16-game-mode-mockups.html`'s `<style>` block, copy these rule groups verbatim:
- `.train` and its `@media (max-width: 760px)` rule
- `.lessons` (and its `@media` rule), `.lesson`, `.lesson b`, `.lesson small`, `.lesson.cur`, `.lesson .badge`
- `.quiz`, `.q`, `.opt`, `.opt::before`, `.opt.right`, `.feedback`
- `.skip-bar`, `.skip-bar span`
- `.boss`, `.boss-top`, `.boss h4`, `.bar`, `.bar i`, `.bar-meta`, `.sweep .district`
- `.district.swept …`, `.district.sweeping …` (both rules), `.district.waiting …`, `@keyframes sweep`

Then make these changes:
- Change `.boss h4` to `.boss h2` with the same declarations.
- Replace `.bar i { position: absolute; inset: 0 51% 0 0; … }` with `.bar i { position: absolute; inset: 0 auto 0 0; width: var(--pct, 0%); background: linear-gradient(90deg, rgba(0,229,255,0.5), var(--cyan)); box-shadow: 0 0 14px rgba(0,229,255,0.5); }`.
- Add these rules:

```css
.lessons ul { list-style: none; margin: 0 0 12px; padding: 0; display: grid; gap: 8px; }
button.lesson { width: 100%; text-align: left; }
.lesson.done { border-color: rgba(198,255,0,0.3); }
.label.faint { color: var(--faint); }
.options { display: grid; gap: 8px; }
button.opt { width: 100%; text-align: left; }
.opt.wrong { border-color: rgba(255,45,155,0.55); background: rgba(255,45,155,0.06); }
.opt[aria-disabled="true"] { cursor: default; }
.message-card { border: 1px solid rgba(255,255,255,0.14); background: rgba(9,11,16,0.7); padding: 14px; display: grid; gap: 6px; }
.banner { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; padding: 12px 18px; border-bottom: 1px solid rgba(198,255,0,0.35); background: rgba(198,255,0,0.06); }
button.link { color: var(--cyan); text-decoration: underline; padding: 0; }
code { font-family: var(--font-mono); font-size: 0.92em; background: rgba(0,229,255,0.06); padding: 1px 5px; }
```

Plan A's `prefers-reduced-motion` rule already stops the sweep animation.

- [ ] **Step 8: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS, including Plan A's `game-views.test.js`.

- [ ] **Step 9: Commit**

```bash
git add desktop/renderer/game/views desktop/renderer/game/game.css desktop/test/game-training-views.test.js
git commit -m "Add the Training Grounds, lesson and boss screens, and a way back from the city"
```

---

### Task 7: Wire it in: the controller and `app.js`

**Files:**
- Modify: `desktop/renderer/game/controller.js` (Plan A Task 11 Step 4)
- Modify: `desktop/renderer/app.js` (Plan A Tasks 6 and 11): `trainingFirst`, `postScanView`, the worry click, `runCheckup`, `RescueHost`
- Test: `desktop/test/game-flow-gate.test.js`
- Manual: the steps in Step 7, also appended to `desktop/MANUAL-QA.md`

**Interfaces:**
- Consumes:
  - Everything in Tasks 1–6.
  - From Plan A: `gameOfferedFor`, `cityAvailable`, `showCity`, `renderCitySwitch`, `rememberView`/`rememberedView`, `wantsCity`, `onScanEvent`, `setScanBusy`, `resetProgress`, `showScanError`, `goToScan`, `loadPermissionsContent`, `duringScanTips`, `detectOS`, `lastKnownPlatform`, `lastScanDoc`, `situation` and `showScreen`.
- Produces:
  - Exported from `app.js` for Node: `trainingFirst({wantsCity, offered, ready}) -> boolean` and `postScanView({inGame, left, wantsCity, rememberedCity, offered, ready}) -> 'boss-city'|'city'|'results'`.
  - `window.RescueGame` gains `showTraining(situation)`, `showBoss()`, `scanEvent(ev)`, `scanDone(doc, situation)` and `scanFailed(message)`.
  - `window.RescueHost` gains `startCheckup()`, `scanTips() -> Promise<[{title, body}]>` and `leaveGame()`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-flow-gate.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { trainingFirst, postScanView, gameOfferedFor, SITUATIONS } = require('../renderer/app.js');
const byId = (id) => SITUATIONS.find((s) => s.id === id);

test('the Training Grounds only follows a worry the game is offered for', () => {
  for (const s of SITUATIONS) {
    const offered = gameOfferedFor(s, null);
    assert.strictEqual(trainingFirst({ wantsCity: true, offered, ready: true }), offered, s.id);
  }
  assert.strictEqual(trainingFirst({ wantsCity: true, offered: gameOfferedFor(byId('watched'), null), ready: true }), false);
  assert.strictEqual(trainingFirst({ wantsCity: false, offered: true, ready: true }), false);
  assert.strictEqual(trainingFirst({ wantsCity: true, offered: true, ready: false }), false);
});

test('after the boss scan: city only when still offered and the person stayed in the game', () => {
  const base = { inGame: true, left: false, wantsCity: true, rememberedCity: false, offered: true, ready: true };
  assert.strictEqual(postScanView(base), 'boss-city');
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'critical' }] }] };
  assert.strictEqual(postScanView({ ...base, offered: gameOfferedFor(byId('unsure'), monitoring) }), 'results');
  assert.strictEqual(postScanView({ ...base, left: true }), 'results');
  assert.strictEqual(postScanView({ ...base, ready: false }), 'results');
});

test('outside the game, Plan A’s rule is unchanged', () => {
  const base = { inGame: false, left: false, wantsCity: false, rememberedCity: false, offered: true, ready: true };
  assert.strictEqual(postScanView(base), 'results');
  assert.strictEqual(postScanView({ ...base, wantsCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true, offered: false }), 'results');
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-flow-gate.test.js`
Expected: FAIL with `trainingFirst is not a function`.

- [ ] **Step 3: Add the pure helpers to `app.js`**

Add these at top level, right after `gameOfferedFor`:

```js
/** After a worry is picked: straight into the Training Grounds, or the plain scan screen. */
function trainingFirst({ wantsCity, offered, ready }) {
  return !!(wantsCity && offered && ready);
}

/**
 * Where a finished scan lands. The gate is checked again with the real results:
 * if monitoring software turned up, nobody lands in the city.
 */
function postScanView({ inGame, left, wantsCity, rememberedCity, offered, ready }) {
  if (!offered || !ready || left) return 'results';
  if (inGame) return 'boss-city';
  return wantsCity || rememberedCity ? 'city' : 'results';
}
```

Add `trainingFirst, postScanView,` to `module.exports`. Run `node --test test/game-flow-gate.test.js` and expect PASS.

- [ ] **Step 4: Wire up the browser side of `app.js`**

In the worry click handler inside `renderSituations`, replace `goToScan();` with:

```js
          if (trainingFirst({ wantsCity, offered: gameOfferedFor(situation, null),
            ready: !!(window.RescueGame && window.RescueGame.isReady) })) {
            leftGame = false;
            window.RescueGame.showTraining(situation);
            showScreen('city');
            return;
          }
          goToScan();
```

Replace the whole `runCheckup` function (as Plan A Task 11 left it) with:

```js
    let scanRunning = false;
    let leftGame = false; // chose "Plain view" during game mode

    async function runCheckup(opts) {
      if (scanRunning) return; // one scan at a time, however many buttons are pressed
      scanRunning = true;
      // A click handler passes an Event here; only {game: true} from the game counts.
      const inGame = !!(opts && opts.game === true && window.RescueGame && window.RescueGame.isReady);
      if (inGame) leftGame = false;
      setScanBusy(true);
      resetProgress();
      if (inGame) window.RescueGame.showBoss();
      const unsubscribe = window.rescue.onScanEvent((ev) => {
        onScanEvent(ev);
        if (inGame && ev.type === 'progress') window.RescueGame.scanEvent(ev);
      });
      try {
        const doc = await window.rescue.runScan(situation ? situation.profile : null);
        if (doc && typeof doc.platform === 'string') lastKnownPlatform = doc.platform;
        lastScanDoc = doc;
        renderResults(doc);
        renderNextStep();
        renderLearnMore(doc);
        setScanBusy(false);
        renderCitySwitch(doc);
        const view = postScanView({
          inGame, left: leftGame, wantsCity, rememberedCity: rememberedView() === 'city',
          offered: gameOfferedFor(situation, doc), ready: !!(window.RescueGame && window.RescueGame.isReady),
        });
        if (view === 'boss-city') {
          window.RescueGame.scanDone(doc, situation);
          rememberView('city');
          showScreen('city');
        } else if (view === 'city') {
          showCity(doc);
        } else {
          showScreen('results');
        }
      } catch (err) {
        setScanBusy(false);
        const message = err && err.message ? err.message : String(err);
        if (inGame && !leftGame) {
          window.RescueGame.scanFailed(message);
          showScreen('city');
        } else {
          showScanError(message);
        }
      } finally {
        unsubscribe();
        scanRunning = false;
      }
    }
```

Add these three members to the `window.RescueHost` object from Plan A:

```js
      startCheckup() { runCheckup({ game: true }); },
      // The OS pop-ups the person may see during the scan, for the boss screen.
      async scanTips() {
        try {
          const content = await loadPermissionsContent();
          return duringScanTips(content, detectOS(lastKnownPlatform)).map((t) => ({ title: t.title, body: t.body }));
        } catch (_) {
          return [];
        }
      },
      // "Plain view": back to Device Rescue's own screens. A running scan carries on there.
      leaveGame() {
        leftGame = true;
        wantsCity = false;
        rememberView('list');
        if (lastScanDoc && !scanRunning) showScreen('results');
        else goToScan();
      },
```

`goToScan` during a running scan shows the scan screen with its live progress, because `setScanBusy(true)` already ran.

Also set `leftGame = false;` in the `btn-play-game` handler and in `resetToWelcome`.

- [ ] **Step 5: Add the new screens to `controller.js`**

At the top of `controller.js`, add these imports:

```js
import { loadLessons, orderLessons, lessonForModule, afterScanDone } from './training.js';
import { setLessonDone } from './progress.js';
import { bossInit, bossApply, bossFinish } from './boss.js';
import { renderTraining } from './views/training.js';
import { renderLesson } from './views/lesson.js';
import { renderBoss } from './views/boss.js';
```

Merge `setLessonDone` into the existing `./progress.js` import line rather than importing it twice.

Add these fields to the `s` state object:

```js
    lessons: [], lesson: null, pendingCity: false, tips: [],
    scan: { running: false, index: 0, total: 0, error: null }, boss: bossInit(),
```

Right after the `s` object, start loading lessons:

```js
  // Specifiers resolve against this file (app://rescue/game/controller.js).
  loadLessons((spec) => import(spec)).then((ls) => {
    s.lessons = ls;
    if (s.screen === 'training' || s.screen === 'lesson') render();
  });
```

At the top of `screenHtml()`, before the `district` branch, add:

```js
    if (s.screen === 'training') {
      return renderTraining({ ordered: orderLessons(s.lessons, s.situation && s.situation.id), progress: s.progress,
        worryTitle: s.situation && s.situation.title, scan: s.scan, scout, pendingCity: s.pendingCity });
    }
    if (s.screen === 'lesson') {
      const l = s.lesson && s.lessons.find((x) => x.id === s.lesson.id);
      if (l) return renderLesson({ lesson: l, qIndex: s.lesson.q, picked: s.lesson.picked, scan: s.scan, scout, pendingCity: s.pendingCity });
      s.screen = 'training';
      return screenHtml();
    }
    if (s.screen === 'boss') return renderBoss({ boss: s.boss, scout, tips: s.tips });
```

In the `mission` branch, pass `learned: lessonForModule(s.lessons, s.progress, m.module)` to `renderBriefing`.

Replace Plan A's `render()` with:

```js
  const TRAINING_SCREENS = new Set(['training', 'lesson', 'boss']);
  function render() {
    try {
      if (!s.city && !TRAINING_SCREENS.has(s.screen)) s.screen = 'training';
      const hud = TRAINING_SCREENS.has(s.screen) ? '' : renderHud({ title: 'YOUR COMPUTER', city: s.city, progress: s.progress });
      frame.innerHTML = hud + screenHtml();
    } catch (err) {
      console.error('City view failed:', err);
      frame.innerHTML = `<p class="say">${esc('The city view hit a problem. Here’s the same thing as a list.')}</p>`;
      win.RescueHost.leaveGame();
    }
  }
```

In the frame click handler, add these lines directly after `const act = el.getAttribute('data-act');`:

```js
    if (go === 'training') { s.lesson = null; s.screen = 'training'; render(); return; }
    if (go === 'boss') { s.screen = 'boss'; render(); return; }
    if (go === 'city') { s.pendingCity = false; s.lesson = null; s.screen = 'map'; render(); return; }
    if (go && go.startsWith('lesson:')) { s.lesson = { id: go.slice(7), q: 0, picked: null }; s.screen = 'lesson'; render(); return; }
    if (act === 'leave') { win.RescueHost.leaveGame(); return; }
    if (act === 'start-checkup') { if (!s.scan.running) win.RescueHost.startCheckup(); return; }
    if (act && act.startsWith('answer:')) {
      if (s.lesson && s.lesson.picked == null) { s.lesson.picked = Number(act.slice(7)); render(); }
      return;
    }
    if (act === 'next-question' && s.lesson) { s.lesson = { ...s.lesson, q: s.lesson.q + 1, picked: null }; render(); return; }
    if (act === 'finish-lesson' && s.lesson) {
      s.progress = setLessonDone(s.progress, s.lesson.id, now());
      saveProgress(storage, s.progress);
      s.lesson = null;
      s.screen = 'training';
      render();
      return;
    }
```

Leaving a lesson part-way (`data-go="training"`) records nothing. Only `finish-lesson` writes progress.

Add these methods to the object `createController` returns:

```js
    showTraining(situation) {
      s.situation = situation;
      s.scan = { running: false, index: 0, total: 0, error: null };
      s.pendingCity = false;
      s.lesson = null;
      s.screen = 'training';
      render();
    },
    showBoss() {
      s.boss = bossInit();
      s.scan = { running: true, index: 0, total: 0, error: null };
      s.pendingCity = false;
      s.screen = 'boss';
      render();
      Promise.resolve(win.RescueHost.scanTips()).then((t) => {
        s.tips = Array.isArray(t) ? t : [];
        if (s.screen === 'boss') render();
      }, () => {});
    },
    scanEvent(ev) {
      s.boss = bossApply(s.boss, ev);
      s.scan = { ...s.scan, index: s.boss.index, total: s.boss.total };
      if (s.screen === 'boss' || s.screen === 'training') render();
    },
    scanDone(doc, situation) {
      s.boss = bossFinish(s.boss);
      s.scan = { running: false, index: s.boss.total, total: s.boss.total, error: null };
      if (situation) s.situation = situation;
      rebuild(doc);
      s.outcome = null;
      if (afterScanDone(s.screen) === 'banner') s.pendingCity = true;
      else { s.lesson = null; s.screen = 'map'; }
      render();
    },
    scanFailed(message) {
      s.boss = bossFinish(s.boss);
      s.scan = { running: false, index: 0, total: 0, error: String(message || 'The checkup stopped.') };
      if (s.screen !== 'lesson') s.screen = 'training';
      render();
    },
```

- [ ] **Step 6: Run the whole desktop suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 7: Manual check on a Mac, also appended to `desktop/MANUAL-QA.md` as "Training Grounds and the final boss"**

Run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start`, with DevTools open.
1. Click **Play it as a game**, then **Someone is on my Wi-Fi…**. The Training Grounds opens. "The tool that asks for your password" is first, then "Who's on your Wi-Fi". **SKIP TO THE CHECKUP ▶** is visible.
2. Open "Who's on your Wi-Fi" and answer question 1 wrongly. The feedback shows, the option is marked, and **NEXT QUESTION** appears. Click **Training Grounds** in the breadcrumb. The lesson isn't marked done.
3. Finish "The tool that asks for your password". It shows **DONE**, and the HUD reads `1/8 LESSONS`.
4. Click **SKIP TO THE CHECKUP ▶**. The boss screen shows: the bar moves, districts change from WAITING to SWEEPING to SWEPT, and "POP-UPS YOU MIGHT SEE" is listed. No district says safe or clear.
5. Click **PLAY A LESSON WHILE YOU WAIT**, open a lesson, and answer one question. When the scan finishes, the banner "Your checkup is done." appears, and the answer you picked is still shown. Click **SEE YOUR CITY ▶** and the city appears.
6. Open the Gatehouse mission for a launch agent after finishing "Things that start on their own". The briefing shows "You learned about this in the Training Grounds" and links to the lesson.
7. Run the QA launch agent from Plan A Task 11 Step 9 again, start over, play, and click **PLAIN VIEW** on the boss screen mid-scan. The plain scan screen shows live progress. When it finishes, the list results show, not the city.
8. Simulate a failed scan: quit, run with `RESCUE_ENGINE=/usr/bin/false`, play, and start the checkup. You're back in the Training Grounds with "THE CHECKUP DIDN'T FINISH" and **START THE CHECKUP ▶**.
9. Pick **I think someone is watching me** after **Play it as a game**. The plain scan screen opens, with no Training Grounds.
10. DevTools → Network: every request is `app://rescue/…`, including `rc/data/phishing.js`.

- [ ] **Step 8: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/renderer/app.js desktop/test/game-flow-gate.test.js desktop/MANUAL-QA.md
git commit -m "Send game mode through the Training Grounds and run the checkup as the final boss"
```

---

### Task 8: Docs

**Files:**
- Modify: `README.md` (the game-mode paragraph Plan A Task 13 added)

- [ ] **Step 1: Extend the README paragraph**

After "…each fix still asks first.", add:

```markdown
Before the checkup you can play a few short lessons in the Training Grounds:
what a real security tool never asks you for, what starts on its own, what
"couldn't check" means. They're optional. "Skip to the checkup" is always
there, and the checkup itself is the final boss.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Mention the Training Grounds in the README"
```

---

## Self-Review Notes

- **Spec coverage:**

  | Spec section | Task |
  | --- | --- |
  | §1 rule 1, never locked | 6 (skip test on every state), 7 |
  | §1 rule 2, never diagnose | 2 (`DIAGNOSTIC_PHRASES` test) |
  | §1 rule 3, sourced | 2 (path, backtick and source test) |
  | §1 rule 4, no score | 1 (`completedAt` only) |
  | §2 flow, gate, recommendations, return from the city | 2 (`orderLessons`), 7 (`trainingFirst`, the worry click; the city returns to the Training Grounds through a lesson link or a `data-go="training"` link) |
  | §3 lessons | 2, 3, 4 |
  | §4 final boss | 5, 6, 7 |
  | §5 accuracy | 2 |
  | §6 progress | 1, 6 (`learned`) |
  | §7 errors | 2 (a broken lesson file), 6 and 7 (scan failure), Review Focus 1 (leaving mid-lesson) |
  | §8 tests | each task |
  | Spec C planning changes 1–8 | 3 (1), 3 (2), 2 (3), 2 and 6 (4), 1 (5), 4 (6), 2 (7), 6 and 7 (8) |

- **The way back from the city:** the HUD's TRAINING button (Task 6 Step 6b), plus the briefing's "learned" link.
- **Not covered by the lessons:** Windows paths for updates, encryption and the lock screen. The locked-door lesson is Mac-specific in its path question, because the cited guides only give Mac paths. A Windows question needs a Windows guide as its source first.
- **Defaults** for the spec's §9 are listed in the header.
