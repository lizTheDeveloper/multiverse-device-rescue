# Player Profile and IRT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One player profile per install that records what the person has learned, skipped or not yet met (measured with item response theory over banks of question variants), drill calibration, rank and missions; stored as recipe-like data in every display mode; shown in game style and plain view; and, only once the school side is ready, offered to MVProfile as a consented file.

**Architecture:** Pure ES modules under `desktop/renderer/game/profile/` hold the codec (`recipe-box.js`), the maths (`irt.js`), the concept map (`skills.js`), the item bank and adaptive draw (`item-bank.js`), the record itself (`player-profile.js`) and the publish payload (`publish.js`). `player-profile.js` is the only code that reads or writes the store. The game controller keeps working on the v3-shaped `progress` view that `progress.js` and `ledger.js` already understand; the profile derives that view (`toProgress`) and folds changes back (`withProgress`). Lesson files gain stable item keys, a concept per question, and variants; the lesson view renders a visit's items. Views (`views/profile.js`) are pure HTML builders used by both YOUR FILE (game) and "Your progress" (plain view).

**Tech Stack:** Plain JavaScript ES modules (no bundler), Electron renderer, `node:test` (Node 22.12 or later). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-18-player-profile-proposal.md` (the whole document, and its "Owner decisions (2026-10-18)") and `docs/superpowers/specs/2026-10-18-teach-once-and-checklists-proposal.md` (concepts C1-C23 in section 1.3; owner decisions 1 and 5). Executors read both.

## Global Constraints

- Code: plain JS ES modules for everything under `desktop/renderer/game/` (its `package.json` is `{ "type": "module" }`); no bundler; no new dependencies (`desktop/package.json` `devDependencies` stays `electron` and `electron-builder` only).
- Tests: `node:test` and `node:assert`, run from `desktop/` with `node --test test/<file>` or `npm test`. `desktop/test/profile-read.js` uses `require()` of an ES module, which needs Node 22.12 or later (CI pins `node-version: '22'`).
- No time estimates anywhere in code, docs or commit messages.
- Lesson text (title, briefing, whatTheScanLooksFor, teach, every prompt, option and feedback, variants included) never matches `TIME_WORDS` (`/\b(seconds?|minutes?|hours?|days?|weeks?)\b/i`, which also catches the ordinal "second") and never contains a `DIAGNOSTIC_PHRASES` entry (`desktop/renderer/game/training.js`), e.g. "your computer has", "someone is on your".
- Lesson accuracy gate (`desktop/test/game-lessons.test.js`): every UI path (`A > B` or `A → B`) and every backticked bit is word for word in one of the lesson's `sources`. `PATH_RE` runs a capitalised sentence start into a path ("The delay is in System Settings > Lock Screen" fails); start the path after a comma or a lowercase word ("For the delay, go to System Settings > Lock Screen").
- Nothing written to disk matches `FORBIDDEN_ON_DISK` = `/partner|safety|stealth|\bsafe\b|stalk|watch|abuse|violence|advocate|hotline|799-7233|88788|monitor|spy/i` (`desktop/test/disk-words.js`). Ids and keys that are stored (concept ids, skill ids, item keys) are checked against it too.
- Storage: the profile lives under `device-rescue.recipe-box.v1`, written only by `saveProfile` in `player-profile.js`, encoded by `recipe-box.js` in every mode. The old key `device-rescue.game.v1` is never written again; it stays frozen in standard mode and is removed in city mode once the box is written.
- No network code in any profile module. Publishing is a file the person saves or text they copy, never in city mode, never findings, paths, missions, lesson ids, answers or anything about the computer, and only behind `PUBLISH_READY` (false until the school-repo prerequisites below land).
- Monitoring checks (`stalkerware_scan`, `mvt_spyware_scan`, `keylogger_indicators`) never produce missions, evidence, gap signals or offers.
- Copy: plain and calm; sizes by question count ("2 questions"), never by time; nothing implies the person was hacked. After reclaim-city lands the product is called "Reclaim City" in lesson text.
- Tasks marked **after reclaim-city lands** start only once the `reclaim-city` branch is merged into `main`; they quote that branch's text at `6cf1130` (`git show reclaim-city:<path>`). If the branch moves before it lands, apply each replacement's rule to the new text and check the result with the task's tests. Everything else can start now.

## Review Focus

1. A box written by a newer build (unknown `version`) is moved to `device-rescue.recipe-box.v1.spare`, never overwritten, and the old key is read instead (test in Task 6).
2. Storage that refuses writes (quota) makes `saveProfile` return false without removing the old key or throwing (test in Task 6).
3. Evidence on an item key that a later lesson edit removed is ignored by the estimate and the lesson state, and an answer to an unknown key records nothing (test in Task 6).
4. The drill bank failing to load still leaves lesson visits drawn and measured (test in Task 18).
5. Long use stays bounded: evidence per concept is capped at 30 and the box stays far under storage limits after hundreds of answers (test in Task 6).

---

## What this plan resolves from the specs

- **"Signal-or-Noise calls feed the same estimates."** Drill calls (invented findings with a right answer) are graded evidence on the drill's concept. A call on a *real* finding has no right answer (Scout: "Your call stands"), so when Scout reads it differently it is a gap signal for the concepts behind the clues the person opened, never a graded response.
- **Key name.** `device-rescue.recipe-box.v1` (the proposal's `device-rescue.player.v1` names a game). The per-install seed travels inside the box, so losing `device-rescue.city-seed` loses nothing.
- **Mission titles stay** in both modes: everything on disk is encoded, so there is no need for the proposal's "Something that's gone now" fallback.
- **The old key** is a frozen backup in standard mode and removed in city mode after the box is written (the proposal's rule; the owner asked for a backup).
- **"Learned" versus the game's flow.** A lesson is DONE for the map once a visit has been answered to the end (keeps `0949c63`: a DONE district opens no quiz). "Learned" is the measured state shown on YOUR FILE.
- **The "cut someone off" question in Who's on your Wi-Fi** (C4 territory) is its own hidden concept `cut-off-order`: measured, counted toward its lesson, never listed, never in a skill, never published.
- **Spot the fake message** has no C-number; it measures `fake-messages`, and its variants are other curated messages of the same kind.
- **Publishing** ships dark (`PUBLISH_READY = false`) until all four school-repo prerequisites below are done.
- **Rank in plain view** reads "Points: 340 (level 3 of 5)" (proposal open question 6).
- **The re-opened "?" signal** has its API (`recordGap(p, concepts, 'reopen', now)`); wiring it belongs to the teach-once "?" control, which isn't built.
- **Item difficulty** moves per install with a small Elo step and a clamp, because one person's answers can't separate their ability from an item's difficulty for long.

## The maths

**Model: Rasch (1PL) with a fixed guessing floor.** For ability θ on a concept, and an item with difficulty b and k answer options:

    P(right | θ, b) = c + (1 − c) · σ(θ − b),   σ(z) = 1 / (1 + e^(−z)),   c = min(0.5, 1/k)

Only b is per item, and c is known from the item, so the model stays honest with a handful of answers. A 2PL would need each item's discrimination, which one person's answers can't estimate; a fixed discrimination of 1 is the 1PL's prior in effect.

> **Updated after review (Task 2, fix rounds 1–2):** the constants below supersede the original draft. Grid ±6 (121 points); weight w_k = max(0.35, 0.9^(n−1−k)); learned = θ̂ ≥ 0.4 AND posterior sd ≤ 0.89 AND n ≥ 4 answers on ≥ 2 items. Calibrated by seeded simulation: random guesser ever "learned" within 20 answers ≤ 2% (2- and 3-option); knower θ = 1.5 learned within 8 answers ≥ 80% on 3–4 options (2-option: ≥ 88% within 20); recovery after 3 early misses = 8 right answers on 3-option items. New bank items should have at least 3 options. Old-rule lessons: `isLearned(estimate([]), true)` is false by design, so Task 6 must migrate a lesson finished under the old rule as stored evidence that keeps it learned. Do not derive "learned" from an empty estimate.

**Ability: EAP on a grid.** θ_j ∈ {−6.0, −5.9, …, 6.0} (121 points), prior N(0, 1); N(0.5, 0.8²) for a concept whose lesson was finished under the old rule. The k-th of n answers on a concept (oldest first) has weight w_k = max(0.35, 0.9^(n−1−k)), so a person who learns can show it:

    log post(θ_j) = −(θ_j − μ0)² / (2σ0²) + Σ_k w_k · [x_k log P_k(θ_j) + (1 − x_k) log(1 − P_k(θ_j))]
    θ̂ = Σ θ_j post_j / Σ post_j,     sd = sqrt(Σ (θ_j − θ̂)² post_j / Σ post_j)

EAP rather than maximum likelihood because an all-right pattern has no finite MLE; the prior keeps three right answers from meaning "infinitely able".

**Learned.** Enough evidence (n ≥ 4 graded answers on ≥ 2 different items: "a few examples of each question"), posterior sd ≤ 0.89, and θ̂ ≥ 0.4. Once learned (`learnedAt` is stored), a concept stays learned until θ̂ < −0.25, so one slip doesn't take it away. A concept finished under the old rule stays learned through migrated evidence (Task 6) until it has 4 answers of its own; then the rule above decides, with the higher prior.

**Item difficulty.** Starts at its authored level (easy −1, medium 0, hard +1). After each answer, with θ̂ from just before it:

    b ← b + K(n) · (P(right | θ̂, b) − x),   K(n) = 0.1 / (1 + 0.2 n),   clamped to level ± 1

**Choosing items.** For the concepts not yet learned (all of them, as a review, when every one is): unseen items first, then the most informative at θ̂, I(θ) = P′² / (P(1 − P)) with P′ = (1 − c) σ(θ − b)(1 − σ(θ − b)), then bank order; one per family before a second variant of a family; never one of the concept's last 2 answers. A first visit (nothing answered on any of the lesson's concepts) is the lesson as written.

**Known values** (3-option medium items alternating between two items; these are the numbers `desktop/test/profile-irt.test.js` pins):

| Answers (oldest first) | θ̂ | sd | Learned? |
|---|---|---|---|
| (none) | 0 | 1 | no |
| 1 | 0.207 | 0.978 | no (too few) |
| 1 1 1 | 0.430 | 0.944 | yes |
| 0 1 1 1 | 0.261 | 0.921 | yes (older answers count less) |
| 1 1 0 | −0.191 | 0.898 | no |
| 1 1 1 0 | −0.129 | 0.893 | stays learned (above −0.25) |
| 1 1 1 0 0 | −0.441 | 0.858 | no longer (a refresher) |
| 0 0 0 | −0.750 | 0.836 | no |
| 1 1 1 on 2-option items | 0.295 | | yes |
| finished before, then 0 0 0 | −0.153 | | no (a refresher) |

**Re-asking a skipped concept.** "I know this" stores `self` (skipped, not learned). Gap signals add to `gaps` with a kind: `drill` (a wrong drill on the concept), `call` (Scout read a real finding differently, on a concept behind the opened clues), `reopen` (the second re-opened "?" in a sweep, counted by the caller). The concept is **worth a look** when a gap is newer than `self`, or it has ≥ 2 answers and θ̂ < 0. An offer ("Want the 2 questions on …?") shows at most once per sweep; "Still know it" counts a decline and clears the gaps; after two declines only a new wrong drill reopens it.

## Storage format

```text
localStorage["device-rescue.recipe-box.v1"] =
  {"kitchen":"<4 words: the seed>","cards":[{"dish":"<word> <word>","serves":2..6,"ingredients":[<up to 24 words>]}, ...]}
```

The profile's JSON is UTF-8 bytes, prefixed `rb1:` and XORed with a seeded keystream; each byte becomes one of 256 cooking words in an order shuffled by the per-install seed. Decoded, the record is:

```text
{ version: 4, since, migrations: [{ v, from, at, changes: [..] }],
  concepts: { <id>: { seen: [[itemKey, 1|0, at, 'lesson'|'drill'], ...<=30], self?, learnedAt?, gaps?: { n, at, drill, call, reopen }, offered?: { at, declined } } },
  items: { <itemKey>: { b, n } },
  lessons: { <lessonId>: { visited?, before?, self? } },
  drills: { right, tried, calls: { <truth>: { <picked>: n } }, recent: [1|0, ...<=10] },
  rank: { points, index }, deck: { tags, confirmed, once, sweep, sweeps }, missions: { ... } }
```

## School-repo prerequisites (not done in this repo)

Publishing stays off until all four are done in `~/src/themultiverse.school` (read-only from here). Each would otherwise make it unsafe:

1. **SHAPE additions** in `tools/shared/profile.js`: `security.city_lessons_learned`, `security.city_skills`, `play.city_drills_right`, `play.city_drills_tried`, `play.city_rank_level`. `set()` throws on unknown fields today, and `fromJSON` keeps whatever it's given.
2. **A merge import** in the Profile Viewer (`tools/profile_viewer/src/export.js` calls `MVProfile.fromJSON`, which replaces the whole profile): import through `MVSync.mergeProfiles` and refuse fields outside `SHAPE`. Without it, importing this app's file wipes the student's profile.
3. **Sharing classes enforced**: `tools/shared/profile.contract.yml` with these five fields as `derived` and everything else from `reclaim-city` as `never`, enforced in `tools/profile_viewer/src/sharing.js` and `profile_sharing.py` (today any field can be ticked and the server checks only the group).
4. **The relay address**: `tools/profile_viewer/src/pair.js:31` sets `RELAY_HOST = "192.168.0.159:8765"` over `ws://`; it must point at `sync.themultiverse.school` over `wss://` before anything of ours can ride a sync.
## File Structure

| File | Responsibility | Task |
|---|---|---|
| `desktop/test/disk-words.js` (create, identical to reclaim-city's) | `FORBIDDEN_ON_DISK`, `recordingStore`, `forbiddenWrites` | 1 |
| `desktop/renderer/game/profile/recipe-box.js` | Codec: any JSON value ↔ recipe cards, per-install word order | 1 |
| `desktop/renderer/game/profile/irt.js` | Response curve, EAP estimate, learned rule, difficulty step, information | 2 |
| `desktop/renderer/game/views/lesson.js` (modify) | Renders a visit's items; hides the what-to-know when told | 3 |
| `desktop/renderer/game/profile/skills.js` | Concepts (C-numbers), skills, drill→concept and clue→concept maps | 4 |
| `desktop/renderer/game/profile/item-bank.js` | Lessons + drills → items; adaptive draw for visits and "Learn this" | 5 |
| `desktop/test/game-lessons.test.js` (modify) | The accuracy gate reads variants; item keys and concepts checked; bank complete | 5, 17 |
| `desktop/renderer/game/profile/player-profile.js` | The record: salvage migration, load/save, derived states, writes, v3 view, summary | 6 |
| `desktop/test/profile-fixtures.js` | Made-up lessons, drills and a v3 store for profile tests | 6 |
| `desktop/renderer/game/lessons/*.js` (modify) | Keys, concepts and variants per question | 7-9, 12-16 |
| `desktop/renderer/game/profile/publish.js` | The MVProfile fragment builder (allow-list), `PUBLISH_READY` | 10 |
| `desktop/renderer/game/views/profile.js` | YOUR FILE / Your progress HTML, the consent sheet | 11 |
| `desktop/renderer/game/controller.js` (modify) | Store swap, visits, drills/calls/offers, YOUR FILE routes | 18-21 |
| `desktop/test/profile-read.js` | Test helper: decode the saved box | 18 |
| `desktop/renderer/game/clues.js`, `views/signal.js` (modify) | `scoutAgrees`; the offer line | 19 |
| `desktop/renderer/game/views/deck.js`, `views/training.js` (modify) | Rank chip and YOUR FILE entry points | 20 |
| `desktop/renderer/game/profile.css` | YOUR FILE and sheet styles (game) | 20 |
| `desktop/renderer/game/profile/plain-panel.js`, `desktop/renderer/profile.css`, `index.html` (modify) | "Your progress" dialog in plain view | 21 |
| `desktop/renderer/app.js` (modify) | Tells the game when the display mode changes | 18 |

## Batches and dependencies

| Batch | When | Tasks (files) | Needs |
|---|---|---|---|
| A | now, in parallel | 1 codec (`profile/recipe-box.js`, `test/disk-words.js`), 2 IRT (`profile/irt.js`), 3 lesson view (`views/lesson.js`) | nothing |
| B | now | 4 skills (`profile/skills.js`) | 1 |
| C | now | 5 item bank + gate (`profile/item-bank.js`, `test/game-lessons.test.js`) | 2, 4 |
| D | now, in parallel | 6 player profile (`profile/player-profile.js`); 7 `lessons/whos-on-wifi.js`; 8 `lessons/browser-add-ons.js`; 9 `lessons/poisoned-packages.js` | 6: 1, 2, 4, 5. 7-9: 5 |
| E | now, in order | 10 publish (`profile/publish.js`), then 11 views (`views/profile.js`) | 6; 10 |
| F | **after reclaim-city lands**, in parallel | 12 `lessons/password-asker.js`, 13 `lessons/starts-on-its-own.js`, 14 `lessons/locked-door.js`, 15 `lessons/couldnt-check.js`, 16 `lessons/spot-the-fake.js` | 5 |
| G | after F | 17 bank complete (`test/game-lessons.test.js`) | 7-9, 12-16 |
| H | **after reclaim-city lands**, in order (one file: `controller.js`) | 18 store + visits, 19 drills/calls/offers, 20 YOUR FILE + sheet, 21 plain view | 18: 3, 6. 19: 18. 20: 11, 19. 21: 20 |
| I | only after the school-repo prerequisites | 22 open publishing (`profile/publish.js`, `docs/trust-and-safety.md`) | 20, 21 |

Task 17 edits `game-lessons.test.js`, which Task 5 also edits: never run them at the same time.

---

### Task 1: The recipe-box codec

**Files:**

- Create: `desktop/test/disk-words.js` (byte-identical to `git show reclaim-city:desktop/test/disk-words.js`, so the merge is clean)
- Create: `desktop/renderer/game/profile/recipe-box.js`
- Test: `desktop/test/profile-recipe-box.test.js`

**Interfaces:**

- Consumes: nothing.
- Produces: `recipe-box.js`: `WORDS` (frozen array of 256 words), `CARD_SIZE = 24`, `mulberry32(seed) -> () => number`, `validSeed(seed) -> boolean` (integer 1..0x7fffffff), `wordOrder(seed) -> number[256]`, `encode(value, seed) -> string` (throws `recipe box: bad seed`), `decode(text) -> value | null`, `seedOf(text) -> number | null`. `disk-words.js`: `FORBIDDEN_ON_DISK`, `recordingStore(initial) -> { data, writes, removed, getItem, setItem, removeItem, clear }`, `forbiddenWrites(store) -> string[]`.

- [ ] **Step 1: Add the disk-word helper**

If `desktop/test/disk-words.js` doesn't exist yet on main, create it exactly as on reclaim-city:

```js
// Words that must never be written to disk by the app. A stored key or value
// containing one could tell whoever looks at this computer what the person
// was worried about. Used by the storage tests.
const FORBIDDEN_ON_DISK = /partner|safety|stealth|\bsafe\b|stalk|watch|abuse|violence|advocate|hotline|799-7233|88788|monitor|spy/i;

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

- [ ] **Step 2: Write the failing test**

Create `desktop/test/profile-recipe-box.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');
const load = () => import('../renderer/game/profile/recipe-box.js');

// A profile-shaped value full of words that must never reach disk.
const LITERAL = {
  version: 4,
  concepts: { 'who-made-it': { seen: [['update-where', 1, '2026-10-18T10:00:00.000Z', 'lesson']] } },
  lessons: { 'locked-door': { visited: '2026-10-18T10:00:00.000Z' } },
  missions: { 'stalkerware_scan|security.stalkerware_scan.found|/Users/ann/Library/mSpy': { status: 'open', title: 'Monitoring software: partner safety hotline 1-800-799-7233' } },
  deck: { tags: { 'launch_agent_audit|x|/tmp/.sys/run.sh': { tag: 'threat', at: 'now', fp: 'abc' } } },
  rank: { points: 88788, index: 3 },
  note: 'stealth watch spy abuse violence advocate 88788 safe',
  emoji: 'Ünïcødé ✓',
};
const STRUCTURE = new Set(['kitchen', 'cards', 'dish', 'serves', 'ingredients']);

// Every token in the stored text: JSON keys, string words and numbers.
function tokens(text) {
  return text.match(/[a-z]+|\d+/gi) || [];
}

test('the word list is 256 distinct lowercase cooking words, none of them a word that must stay off disk', async () => {
  const { WORDS } = await load();
  assert.strictEqual(WORDS.length, 256);
  assert.strictEqual(new Set(WORDS).size, 256);
  for (const w of WORDS) {
    assert.match(w, /^[a-z]+$/, w);
    assert.doesNotMatch(w, FORBIDDEN_ON_DISK, w);
  }
});

test('decode(encode(x)) gives back x, for several seeds and shapes', async () => {
  const { encode, decode } = await load();
  for (const seed of [1, 2, 12345, 0x7fffffff]) {
    for (const v of [LITERAL, {}, [], 'plain', 0, { deep: { a: [1, 2, { b: null, c: true }] } }]) {
      assert.deepStrictEqual(decode(encode(v, seed)), v, `seed ${seed}`);
    }
  }
});

test('nothing literal reaches disk: every token is a recipe word, a card field or a small number', async () => {
  const { encode, WORDS } = await load();
  const text = encode(LITERAL, 424242);
  assert.doesNotMatch(text, FORBIDDEN_ON_DISK);
  const words = new Set(WORDS);
  for (const t of tokens(text)) {
    assert.ok(words.has(t) || STRUCTURE.has(t) || /^[2-6]$/.test(t), `unexpected token "${t}"`);
  }
  for (const literal of ['locked-door', 'who-made-it', 'update-where', 'launch_agent_audit', 'threat', 'lesson', 'version']) {
    assert.ok(!text.includes(literal), literal);
  }
});

test('two installs write the same profile differently; one install writes it the same way each time', async () => {
  const { encode } = await load();
  assert.notStrictEqual(encode(LITERAL, 1001), encode(LITERAL, 1002));
  assert.strictEqual(encode(LITERAL, 1001), encode(LITERAL, 1001));
});

test('the seed travels with the box, so a lost seed key loses nothing', async () => {
  const { encode, seedOf } = await load();
  assert.strictEqual(seedOf(encode({ a: 1 }, 777)), 777);
  assert.strictEqual(seedOf('not json'), null);
});

test('anything that is not a box this code wrote decodes to null, never throws', async () => {
  const { encode, decode } = await load();
  const good = JSON.parse(encode({ a: 1 }, 99));
  const swapped = { ...good, cards: [{ ...good.cards[0], ingredients: ['granola', ...good.cards[0].ingredients.slice(1)] }] };
  const dropped = { ...good, cards: [{ ...good.cards[0], ingredients: good.cards[0].ingredients.slice(1) }] };
  for (const bad of ['', 'null', '{}', '{"kitchen":"basil basil basil basil","cards":[]}', JSON.stringify(swapped),
    JSON.stringify(dropped), JSON.stringify({ ...good, kitchen: 'basil' }), '{"cards":"x","kitchen":"basil thyme sage dill"}']) {
    assert.strictEqual(decode(bad), null, bad.slice(0, 40));
  }
});

test('encode refuses a bad seed instead of writing something unreadable', async () => {
  const { encode } = await load();
  for (const seed of [0, -1, 1.5, 0x80000000, '12', null]) assert.throws(() => encode({}, seed), /bad seed/);
});

test('cards look like recipe cards: a dish, servings and at most 24 ingredients', async () => {
  const { encode, CARD_SIZE } = await load();
  const box = JSON.parse(encode(LITERAL, 5150));
  assert.deepStrictEqual(Object.keys(box).sort(), ['cards', 'kitchen']);
  for (const c of box.cards) {
    assert.deepStrictEqual(Object.keys(c).sort(), ['dish', 'ingredients', 'serves']);
    assert.match(c.dish, /^[a-z]+ [a-z]+$/);
    assert.ok(c.serves >= 2 && c.serves <= 6);
    assert.ok(c.ingredients.length >= 1 && c.ingredients.length <= CARD_SIZE);
  }
});
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-recipe-box.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/recipe-box.js`.

- [ ] **Step 4: Write the codec**

Create `desktop/renderer/game/profile/recipe-box.js`:

```js
// The player profile on disk, disguised as a box of recipe cards. Every byte
// of the profile's JSON becomes one ingredient word, through a word order
// shuffled by a number made once per install, so two installs write the same
// profile differently and nothing literal ever reaches disk. Only this code
// maps the cards back. It hides; it doesn't lock: anyone with this file could
// decode it, which is fine, because the goal is that a glance at the disk (or
// a search for a word) finds recipes, not progress.
//
// Pure. No storage, no DOM. TextEncoder/TextDecoder exist in Electron and Node.
export const WORDS = Object.freeze([
  'basil', 'thyme', 'sage', 'rosemary', 'parsley', 'dill', 'oregano', 'tarragon', 'chive',
  'cilantro', 'fennel', 'cumin', 'coriander', 'paprika', 'saffron', 'turmeric', 'cardamom',
  'clove', 'nutmeg', 'cinnamon', 'ginger', 'garlic', 'shallot', 'vanilla', 'anise', 'caraway',
  'marjoram', 'sorrel', 'lovage', 'chervil', 'allspice', 'sumac', 'fenugreek', 'juniper', 'pepper',
  'mustard', 'horseradish', 'wasabi', 'leek', 'onion', 'carrot', 'celery', 'potato', 'tomato',
  'squash', 'pumpkin', 'zucchini', 'courgette', 'aubergine', 'eggplant', 'spinach', 'kale',
  'chard', 'cabbage', 'lettuce', 'arugula', 'radish', 'turnip', 'parsnip', 'beetroot', 'artichoke',
  'asparagus', 'broccoli', 'cauliflower', 'okra', 'pea', 'bean', 'lentil', 'chickpea', 'corn',
  'mushroom', 'truffle', 'olive', 'caper', 'cucumber', 'gherkin', 'endive', 'kohlrabi', 'yam',
  'cassava', 'taro', 'rhubarb', 'watercress', 'scallion', 'celeriac', 'apple', 'pear', 'plum',
  'peach', 'apricot', 'cherry', 'grape', 'fig', 'lemon', 'lime', 'orange', 'tangerine', 'mandarin',
  'grapefruit', 'melon', 'mango', 'papaya', 'guava', 'kiwi', 'banana', 'pineapple', 'coconut',
  'raspberry', 'strawberry', 'blueberry', 'blackberry', 'cranberry', 'gooseberry', 'currant',
  'raisin', 'sultana', 'prune', 'quince', 'lychee', 'pomegranate', 'persimmon', 'kumquat',
  'elderberry', 'mulberry', 'nectarine', 'flour', 'bread', 'toast', 'bagel', 'brioche', 'biscuit',
  'scone', 'muffin', 'crumpet', 'pancake', 'waffle', 'crepe', 'noodle', 'pasta', 'rice', 'barley',
  'oats', 'rye', 'wheat', 'millet', 'quinoa', 'polenta', 'couscous', 'bulgur', 'semolina',
  'dumpling', 'pretzel', 'cracker', 'oatcake', 'galette', 'tart', 'pie', 'crumble', 'cobbler',
  'pudding', 'custard', 'trifle', 'souffle', 'risotto', 'paella', 'pilaf', 'curry', 'stew', 'soup',
  'broth', 'chowder', 'gumbo', 'goulash', 'ragout', 'casserole', 'frittata', 'omelette', 'quiche',
  'tagine', 'korma', 'biryani', 'ramen', 'udon', 'soba', 'gnocchi', 'lasagne', 'ravioli',
  'tortilla', 'taco', 'burrito', 'empanada', 'pierogi', 'samosa', 'falafel', 'hummus', 'pesto',
  'salsa', 'chutney', 'relish', 'compote', 'jam', 'marmalade', 'jelly', 'syrup', 'honey',
  'caramel', 'toffee', 'fudge', 'praline', 'meringue', 'macaron', 'sorbet', 'gelato', 'granita',
  'parfait', 'fondue', 'gratin', 'terrine', 'butter', 'cream', 'cheese', 'yogurt', 'ricotta',
  'feta', 'brie', 'cheddar', 'gouda', 'parmesan', 'mozzarella', 'halloumi', 'paneer', 'ghee',
  'kefir', 'buttermilk', 'milk', 'egg', 'almond', 'walnut', 'pecan', 'hazelnut', 'cashew',
  'pistachio', 'peanut', 'chestnut', 'macadamia', 'sesame', 'poppy', 'flax', 'sugar', 'salt',
  'vinegar', 'molasses', 'treacle', 'cocoa', 'chocolate', 'coffee',
]);
export const CARD_SIZE = 24;
// The decoded text starts with this, so a wrong seed or a damaged card fails
// to decode instead of producing nonsense.
const MAGIC = 'rb1:';
const MAX_SEED = 0x7fffffff;

// A small, well-known 32-bit generator (mulberry32). Deterministic per seed.
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function validSeed(seed) {
  return Number.isInteger(seed) && seed >= 1 && seed <= MAX_SEED;
}

// byte -> word index, shuffled per seed (Fisher-Yates).
export function wordOrder(seed) {
  const order = Array.from({ length: 256 }, (_, i) => i);
  const rnd = mulberry32(seed);
  for (let i = 255; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

// The keystream that scrambles the bytes before they become words, so a run
// of the same character doesn't become a run of the same ingredient.
function keystream(seed) {
  const rnd = mulberry32((seed ^ 0x5bd1e995) >>> 0);
  return () => Math.floor(rnd() * 256);
}

// The seed itself, as four words in the unshuffled order, so a card box can
// always be read back even if the install's seed key is lost.
function seedWords(seed) {
  return [24, 16, 8, 0].map((s) => WORDS[(seed >>> s) & 0xff]).join(' ');
}

function seedFrom(kitchen) {
  const parts = typeof kitchen === 'string' ? kitchen.split(' ') : [];
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const i = WORDS.indexOf(p);
    if (i < 0) return null;
    n = (n * 256) + i;
  }
  return validSeed(n) ? n : null;
}

const dish = (order, i) => `${WORDS[order[(i * 7) % 256]]} ${WORDS[order[(i * 13 + 5) % 256]]}`;

// Any JSON value -> the stored text. Throws on a bad seed or a value that
// JSON can't hold (the caller then keeps what's on disk).
export function encode(value, seed) {
  if (!validSeed(seed)) throw new Error('recipe box: bad seed');
  const json = JSON.stringify(value);
  if (typeof json !== 'string') throw new Error('recipe box: nothing to store');
  const bytes = new TextEncoder().encode(MAGIC + json);
  const order = wordOrder(seed);
  const ks = keystream(seed);
  const words = Array.from(bytes, (b) => WORDS[order[b ^ ks()]]);
  const cards = [];
  for (let i = 0; i * CARD_SIZE < words.length; i += 1) {
    cards.push({ dish: dish(order, i), serves: 2 + (i % 5), ingredients: words.slice(i * CARD_SIZE, (i + 1) * CARD_SIZE) });
  }
  return JSON.stringify({ kitchen: seedWords(seed), cards });
}

// The stored text -> the value, or null when it isn't a card box this code wrote.
export function decode(text) {
  try {
    const box = JSON.parse(text);
    const seed = seedFrom(box && box.kitchen);
    if (seed === null || !Array.isArray(box.cards)) return null;
    const order = wordOrder(seed);
    const back = new Map(order.map((w, b) => [WORDS[w], b]));
    const ks = keystream(seed);
    const bytes = [];
    for (const card of box.cards) {
      if (!card || !Array.isArray(card.ingredients)) return null;
      for (const word of card.ingredients) {
        if (!back.has(word)) return null;
        bytes.push(back.get(word) ^ ks());
      }
    }
    const textOut = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    if (!textOut.startsWith(MAGIC)) return null;
    return JSON.parse(textOut.slice(MAGIC.length));
  } catch (_) {
    return null;
  }
}

// The seed a stored box was written with, or null.
export function seedOf(text) {
  try { return seedFrom(JSON.parse(text).kitchen); } catch (_) { return null; }
}
```

- [ ] **Step 5: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-recipe-box.test.js`

Expected: PASS, 8 tests.

- [ ] **Step 6: Commit**

```bash
git add desktop/test/disk-words.js desktop/renderer/game/profile/recipe-box.js desktop/test/profile-recipe-box.test.js
git commit -m "Profile: recipe-box codec, so nothing literal reaches disk"
```

---

### Task 2: IRT maths

**Files:**

- Create: `desktop/renderer/game/profile/irt.js`
- Test: `desktop/test/profile-irt.test.js`

**Interfaces:**

- Consumes: nothing.
- Produces: `GRID`, `PRIOR = {mean:0, sd:1}`, `BEFORE_PRIOR = {mean:0.5, sd:0.8}`, `DECAY = 0.9`, `WEIGHT_FLOOR = 0.35`, `LEVEL_B = {easy:-1, medium:0, hard:1}`, `LEARNED_AT = 0.4`, `LEARNED_SD_CAP = 0.89`, `SLIPPED_BELOW = -0.25`, `MIN_RESPONSES = 4`, `MIN_ITEMS = 2`; `guessFloor(k) -> number`, `levelB(level) -> number`, `pCorrect(theta, b, c) -> number`, `information(theta, b, c) -> number`, `estimate(responses: {key, x, b, c}[], prior?, decay?) -> {mean, sd, n, items}`, `enoughEvidence(est) -> boolean`, `isLearned(est, wasLearned?) -> boolean`, `updateDifficulty({b, n}, x, theta, c, level?) -> {b, n}`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-irt.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/profile/irt.js');

// Answers as a string of 1 (right) and 0 (wrong), oldest first, alternating
// between two items so the "different items" rule is met.
const seq = (s, c = 1 / 3, b = 0) => s.split('').map((ch, i) => ({ key: `k${i % 2}`, x: ch === '1' ? 1 : 0, b, c }));
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg}: ${a} vs ${b}`);

test('the response curve: known values', async () => {
  const { pCorrect, guessFloor } = await load();
  assert.strictEqual(pCorrect(0, 0, 0), 0.5);
  near(pCorrect(0, 0, 1 / 3), 2 / 3, 1e-12, 'guessing floor lifts the middle');
  near(pCorrect(1, 0, 0), 0.7310585786, 1e-9, 'σ(1)');
  assert.strictEqual(guessFloor(3), 1 / 3);
  assert.strictEqual(guessFloor(2), 0.5);
  assert.strictEqual(guessFloor(4), 0.25);
  assert.strictEqual(guessFloor(1), 0);
  assert.strictEqual(guessFloor(undefined), 0);
});

test('item information: known values', async () => {
  const { information } = await load();
  near(information(0, 0, 0), 0.25, 1e-12, 'Rasch at θ = b');
  near(information(0, 0, 1 / 3), 0.125, 1e-12, 'with a 1/3 guessing floor');
  assert.ok(information(0, 0, 0) > information(2, 0, 0), 'an item says most where θ is near b');
});

test('the estimate: known values for the model the plan fixes (prior N(0,1), decay 0.7, 3 options, medium items)', async () => {
  const { estimate } = await load();
  assert.deepStrictEqual(estimate([]), { mean: 0, sd: 1, n: 0, items: 0 });
  const cases = { 1: [0.207, 0.978], 111: [0.43, 0.944], '0111': [0.261, 0.921], 110: [-0.191, 0.898], 1110: [-0.129, 0.893], 11100: [-0.441, 0.858], '000': [-0.75, 0.836] };
  for (const [s, [mean, sd]] of Object.entries(cases)) {
    const e = estimate(seq(s));
    assert.strictEqual(e.mean, mean, `${s} mean`);
    assert.strictEqual(e.sd, sd, `${s} sd`);
    assert.strictEqual(e.n, s.length);
  }
  assert.strictEqual(estimate(seq('111', 0.5)).mean, 0.295, 'two options: right answers say less');
});

test('the estimate agrees with an independent, finer integration', async () => {
  const { estimate, pCorrect, DECAY } = await load();
  function fine(rs) {
    let num = 0; let den = 0;
    for (let t = -6; t <= 6; t += 0.001) {
      let lp = -(t * t) / 2;
      rs.forEach((r, k) => { const p = pCorrect(t, r.b, r.c); lp += DECAY ** (rs.length - 1 - k) * (r.x ? Math.log(p) : Math.log(1 - p)); });
      const w = Math.exp(lp); num += w * t; den += w;
    }
    return num / den;
  }
  for (const s of ['1', '111', '0111', '110', '000', '10101']) near(estimate(seq(s)).mean, fine(seq(s)), 0.01, s);
});

test('a prior from a lesson finished under the old rule starts the estimate higher', async () => {
  const { estimate, BEFORE_PRIOR } = await load();
  assert.deepStrictEqual(estimate([], BEFORE_PRIOR), { mean: 0.5, sd: 0.8, n: 0, items: 0 });
  assert.strictEqual(estimate(seq('0'), BEFORE_PRIOR).mean, 0.158);
  assert.strictEqual(estimate(seq('000'), BEFORE_PRIOR).mean, -0.153);
  assert.strictEqual(estimate(seq('111'), BEFORE_PRIOR).mean, 0.752);
});

test('learned: three right on two items is enough; two is not; a recovery counts; one slip does not take it away', async () => {
  const { estimate, isLearned, enoughEvidence } = await load();
  assert.strictEqual(isLearned(estimate(seq('11'))), false, 'too few answers');
  assert.strictEqual(isLearned(estimate(seq('111'))), true);
  assert.strictEqual(isLearned(estimate(seq('0111'))), true, 'older answers count less');
  assert.strictEqual(isLearned(estimate(seq('110'))), false);
  const sameItem = [1, 1, 1].map((x) => ({ key: 'only', x, b: 0, c: 1 / 3 }));
  assert.strictEqual(enoughEvidence(estimate(sameItem)), false, 'one item three times is one example');
  assert.strictEqual(isLearned(estimate(seq('1110')), true), true, 'a slip after learning');
  assert.strictEqual(isLearned(estimate(seq('11100')), true), false, 'two in a row takes it away');
});

test('responses that are not answers are ignored, never thrown on', async () => {
  const { estimate } = await load();
  const junk = [null, {}, { x: 2, b: 0, c: 0 }, { x: 1, b: NaN, c: 0 }, { x: 1, b: 0, c: 1 }, { key: 'a', x: 1, b: 0, c: 1 / 3 }];
  assert.deepStrictEqual(estimate(junk), estimate([{ key: 'a', x: 1, b: 0, c: 1 / 3 }]));
  assert.deepStrictEqual(estimate(undefined), estimate([]));
});

test('difficulty moves by an Elo step, shrinking with use, and stays within 1 of its level', async () => {
  const { updateDifficulty, levelB } = await load();
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 0 }, 1, 0, 0), { b: -0.05, n: 1 }, 'right when expected 50%: K = 0.1, so 0.1·(0.5 − 1)');
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 5 }, 0, 0, 1 / 3), { b: 0.0333, n: 6 }, 'K = 0.1/(1+0.2·5) = 0.05; 0.05·(2/3)');
  assert.deepStrictEqual(updateDifficulty({ b: -1.95, n: 0 }, 1, 3, 0, 'easy'), { b: -1.9507, n: 1 });
  assert.deepStrictEqual(updateDifficulty({ b: 1.99, n: 0 }, 0, 4, 0, 'hard'), { b: 2, n: 1 }, 'clamped at level + 1');
  assert.deepStrictEqual(updateDifficulty({}, 1, 0, 0), { b: -0.05, n: 1 }, 'no record yet: starts at the level');
  assert.strictEqual(levelB('easy'), -1);
  assert.strictEqual(levelB('nonsense'), 0);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-irt.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/irt.js`.

- [ ] **Step 3: Write the maths**

Create `desktop/renderer/game/profile/irt.js`:

```js
// Item response theory for one person on one computer. Pure maths, no storage.
//
// Model: a Rasch (one-parameter logistic) model with a fixed guessing floor.
// For a person with ability θ on a concept, and an item with difficulty b and
// k answer options,
//
//     P(right | θ, b) = c + (1 − c) · σ(θ − b),   σ(z) = 1 / (1 + e^(−z)),
//     c = min(0.5, 1/k)   (blind guessing on a k-option item).
//
// Nothing per item is estimated except b, and c is known from the item, so the
// model stays honest with a handful of answers. Discrimination is fixed at 1.
//
// Ability is the posterior mean (EAP) over a grid θ ∈ [−4, 4], step 0.1, with
// a normal prior N(μ0, σ0²): N(0, 1) normally, N(0.5, 0.8²) for a concept whose
// lesson was finished under the old rule ("before"). Older answers count less,
// so a person who learns can show it: the k-th of n answers on a concept has
// weight DECAY^(n−1−k) on its log-likelihood.
//
//     log post(θ) = −(θ − μ0)² / (2σ0²) + Σ_k w_k · [x_k log P_k(θ) + (1 − x_k) log(1 − P_k(θ))]
//     θ̂ = Σ θ_j post(θ_j) / Σ post(θ_j),   sd = sqrt(Σ (θ_j − θ̂)² post(θ_j) / Σ post(θ_j))
//
// Item difficulty starts at its authored level (easy −1, medium 0, hard +1)
// and moves by an Elo-style step after each answer, using θ̂ from before it:
//
//     b ← b + K(n) · (P(right | θ̂, b) − x),   K(n) = 0.1 / (1 + 0.2 n),
//
// clamped to within 1 of the authored level, so one person's answers can tune
// an item but never turn an easy one hard.
export const GRID = Object.freeze(Array.from({ length: 81 }, (_, i) => Math.round((-4 + i * 0.1) * 10) / 10));
export const PRIOR = Object.freeze({ mean: 0, sd: 1 });
export const BEFORE_PRIOR = Object.freeze({ mean: 0.5, sd: 0.8 });
export const DECAY = 0.7;
export const LEVEL_B = Object.freeze({ easy: -1, medium: 0, hard: 1 });
// "Learned": enough evidence, and the estimate above LEARNED_AT. Once learned,
// a concept stays learned until the estimate falls below SLIPPED_BELOW, so a
// single slip doesn't take it away.
export const LEARNED_AT = 0.25;
export const SLIPPED_BELOW = -0.25;
export const MIN_RESPONSES = 3;
export const MIN_ITEMS = 2;
const K0 = 0.1;
const K_SLOPE = 0.2;
const B_RANGE = 1;

const round = (v, d = 3) => Math.round(v * 10 ** d) / 10 ** d;
const sigmoid = (z) => 1 / (1 + Math.exp(-z));

export function guessFloor(k) {
  return Number.isInteger(k) && k >= 2 ? Math.min(0.5, 1 / k) : 0;
}

export function levelB(level) {
  return Object.prototype.hasOwnProperty.call(LEVEL_B, level) ? LEVEL_B[level] : LEVEL_B.medium;
}

export function pCorrect(theta, b, c) {
  return c + (1 - c) * sigmoid(theta - b);
}

// Fisher information of one item at θ, for choosing the next item.
export function information(theta, b, c) {
  const s = sigmoid(theta - b);
  const p = c + (1 - c) * s;
  const dp = (1 - c) * s * (1 - s);
  return (dp * dp) / (p * (1 - p));
}

// `responses`: oldest first, each { key, x: 1|0, b, c }. Returns the
// posterior mean and sd (3 decimals), how many answers counted, and how many
// different items they were on.
export function estimate(responses, prior = PRIOR, decay = DECAY) {
  const rs = (Array.isArray(responses) ? responses : [])
    .filter((r) => r && (r.x === 0 || r.x === 1) && Number.isFinite(r.b) && Number.isFinite(r.c) && r.c >= 0 && r.c < 1);
  const n = rs.length;
  const logPost = GRID.map((t) => -((t - prior.mean) ** 2) / (2 * prior.sd * prior.sd));
  rs.forEach((r, k) => {
    const w = decay ** (n - 1 - k);
    for (let j = 0; j < GRID.length; j += 1) {
      const p = pCorrect(GRID[j], r.b, r.c);
      logPost[j] += w * (r.x === 1 ? Math.log(p) : Math.log(1 - p));
    }
  });
  const top = Math.max(...logPost);
  const post = logPost.map((v) => Math.exp(v - top));
  const total = post.reduce((a, v) => a + v, 0);
  const mean = post.reduce((a, v, j) => a + v * GRID[j], 0) / total;
  const variance = post.reduce((a, v, j) => a + v * (GRID[j] - mean) ** 2, 0) / total;
  return { mean: round(mean), sd: round(Math.sqrt(variance)), n, items: new Set(rs.map((r) => r.key)).size };
}

export function enoughEvidence(est) {
  return !!est && est.n >= MIN_RESPONSES && est.items >= MIN_ITEMS;
}

// `wasLearned`: the concept has been learned before (or finished under the
// old rule). Then only a fall below SLIPPED_BELOW takes "learned" away.
export function isLearned(est, wasLearned = false) {
  if (wasLearned) return !!est && est.mean >= SLIPPED_BELOW;
  return enoughEvidence(est) && est.mean >= LEARNED_AT;
}

// One Elo-style step for an item's difficulty after an answer `x` given by
// someone whose estimate was `theta` just before. `n`: answers this item has
// had before this one. Returns the new { b, n }.
export function updateDifficulty({ b, n }, x, theta, c, level = 'medium') {
  const base = levelB(level);
  const start = Number.isFinite(b) ? b : base;
  const seen = Number.isInteger(n) && n >= 0 ? n : 0;
  const k = K0 / (1 + K_SLOPE * seen);
  const next = start + k * (pCorrect(theta, start, c) - (x === 1 ? 1 : 0));
  return { b: round(Math.min(base + B_RANGE, Math.max(base - B_RANGE, next)), 4), n: seen + 1 };
}
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-irt.test.js`

Expected: PASS, 8 tests, including the known values in the table above and agreement with the independent integration within 0.01.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/profile/irt.js desktop/test/profile-irt.test.js
git commit -m "Profile: IRT maths (Rasch with a guessing floor, EAP, Elo difficulty)"
```

---

### Task 3: The lesson view renders a visit's items

**Files:**

- Modify: `desktop/renderer/game/views/lesson.js` (the `renderLesson` head and the crumbs line)
- Test: `desktop/test/game-training-views.test.js` (append one test)

**Interfaces:**

- Consumes: nothing.
- Produces: `renderLesson({ lesson, items = null, qIndex, picked, showTeach = true, scan, scout, pendingCity, scanFinished, settingFor })`. With `items` (an array of bank items: `{ key, prompt, options, teach, setting, message }`) it renders those and counts them; without, `lesson.questions` as today. `showTeach: false` hides the item's what-to-know (the briefing still opens item 1).

- [ ] **Step 1: Write the failing test**

Append to `desktop/test/game-training-views.test.js`:

```js

test('a visit renders the items it was given, counts them, and hides the what-to-know when told to', async () => {
  const v = await import('../renderer/game/views/lesson.js');
  const lesson = { id: 'l', title: 'L', briefing: 'Intro here.', questions: [{ teach: 'Q teach', prompt: 'Q one', options: [{ text: 'A', correct: true, feedback: 'ok' }, { text: 'B', correct: false, feedback: 'no' }] }] };
  const items = [
    { key: 'x-2', teach: 'Family teach', prompt: 'Variant prompt', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'No.' }] },
    { key: 'y', teach: 'Other teach', prompt: 'Second item', options: [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'No.' }] },
  ];
  const scout = () => '';
  const idle = { running: false, index: 0, total: 0, error: null };
  const first = v.renderLesson({ lesson, items, qIndex: 0, picked: null, scan: idle, scout });
  assert.ok(first.includes('Variant prompt') && first.includes('QUESTION 1 OF 2') && first.includes('Family teach'));
  assert.ok(!first.includes('Q one'));
  const hidden = v.renderLesson({ lesson, items, qIndex: 1, picked: null, showTeach: false, scan: idle, scout });
  assert.ok(hidden.includes('Second item') && !hidden.includes('Other teach'));
  assert.match(v.renderLesson({ lesson, items, qIndex: 1, picked: 0, scan: idle, scout }), /data-act="finish-lesson"/);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-training-views.test.js`

Expected: FAIL in "a visit renders the items it was given…" (`QUESTION 1 OF 1` and `Q one` are shown, the items ignored).

- [ ] **Step 3: Take items and showTeach**

In `desktop/renderer/game/views/lesson.js`, replace:

```js
// `settingFor(key)` gives { key, hint } for a question's `setting` on a Mac, else null.
export function renderLesson({ lesson: l, qIndex, picked, scan, scout, pendingCity, scanFinished = false, settingFor = () => null }) {
  const i = Math.max(0, Math.min(qIndex, l.questions.length - 1));
  const q = l.questions[i];
  const last = i >= l.questions.length - 1;
  // The lesson's intro opens question 1; each question's own `teach` sits right above it.
  const know = [i === 0 && l.briefing, q.teach].filter(Boolean);
```

with:

```js
// `settingFor(key)` gives { key, hint } for a question's `setting` on a Mac, else null.
// `items`: this visit's items from the item bank (each with prompt, options,
// teach, setting, message); without it, the lesson's own questions.
// `showTeach`: whether this item's "what to know" shows (it hides once the
// person has got one item in its family right).
export function renderLesson({ lesson: l, items = null, qIndex, picked, showTeach = true, scan, scout, pendingCity, scanFinished = false, settingFor = () => null }) {
  const list = Array.isArray(items) && items.length ? items : l.questions;
  const i = Math.max(0, Math.min(qIndex, list.length - 1));
  const q = list[i];
  const last = i >= list.length - 1;
  // The lesson's intro opens question 1; each question's own `teach` sits right above it.
  const know = [i === 0 && l.briefing, showTeach && q.teach].filter(Boolean);
```

In `desktop/renderer/game/views/lesson.js`, replace:

```js
    <div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${l.questions.length}</div>
```

with:

```js
    <div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${list.length}</div>
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/game-training-views.test.js`

Expected: PASS, every test (the old ones pass because `items` defaults to the lesson's questions).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/views/lesson.js desktop/test/game-training-views.test.js
git commit -m "Game: the lesson view renders a visit's items"
```

---

### Task 4: Concepts, skills and the drill map

**Files:**

- Create: `desktop/renderer/game/profile/skills.js`
- Test: `desktop/test/profile-skills.test.js`

**Interfaces:**

- Consumes: `desktop/test/disk-words.js` (Task 1).
- Produces: `CONCEPTS: {id, ref, title, hidden?}[]` (15 concepts; ids `who-made-it`, `where-it-lives`, `fix-and-undo`, `couldnt-check`, `clean-isnt-certain`, `disk-encryption`, `auto-updates`, `lock-screen`, `browser-add-ons`, `remote-access-scams`, `password-prompts`, `wifi-and-mining`, `cut-off-order` (hidden), `poisoned-packages`, `fake-messages`), `SKILLS: {id, title, concepts}[]`, `DRILL_CONCEPTS: {[drillId]: conceptId | null}`, `CLUE_CONCEPTS = { maker: 'who-made-it', where: 'where-it-lives' }`, `conceptById(id) -> concept | null`, `isHidden(id) -> boolean`, `shownConcepts() -> concept[]`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-skills.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');

const GAME = path.join(__dirname, '..', 'renderer', 'game');
const imp = (rel) => import(pathToFileURL(path.join(GAME, rel)).href);

test('concept ids are unique, disk-safe slugs', async () => {
  const { CONCEPTS } = await imp('profile/skills.js');
  assert.strictEqual(new Set(CONCEPTS.map((c) => c.id)).size, CONCEPTS.length);
  for (const c of CONCEPTS) {
    assert.match(c.id, /^[a-z]+(?:-[a-z]+)*$/, c.id);
    assert.doesNotMatch(c.id, FORBIDDEN_ON_DISK, c.id);
    assert.ok(typeof c.title === 'string' && c.title.trim(), c.id);
  }
});

test('every skill names real, shown concepts; every shown concept is in exactly one skill', async () => {
  const { SKILLS, CONCEPTS, conceptById, isHidden } = await imp('profile/skills.js');
  const seen = new Map();
  for (const s of SKILLS) {
    assert.doesNotMatch(s.id, FORBIDDEN_ON_DISK, s.id);
    for (const c of s.concepts) {
      assert.ok(conceptById(c), `${s.id}: no concept ${c}`);
      assert.ok(!isHidden(c), `${s.id}: ${c} is hidden and may not be in a skill`);
      seen.set(c, (seen.get(c) || 0) + 1);
    }
  }
  for (const c of CONCEPTS.filter((x) => !x.hidden)) assert.strictEqual(seen.get(c.id), 1, c.id);
});

test('every drill in the bank is mapped (to a concept, or to null), and only to concepts that exist', async () => {
  const { DRILL_CONCEPTS, CLUE_CONCEPTS, conceptById } = await imp('profile/skills.js');
  const drills = await imp('drills.js');
  const bank = await drills.loadDrills((spec) => imp(spec));
  for (const d of bank) assert.ok(Object.prototype.hasOwnProperty.call(DRILL_CONCEPTS, d.id), `drill ${d.id} is not mapped`);
  for (const [id, c] of Object.entries(DRILL_CONCEPTS)) {
    assert.ok(bank.some((d) => d.id === id), `no drill ${id}`);
    if (c !== null) assert.ok(conceptById(c), `${id}: no concept ${c}`);
  }
  for (const c of Object.values(CLUE_CONCEPTS)) assert.ok(conceptById(c));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-skills.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/skills.js`.

- [ ] **Step 3: Write the map**

Create `desktop/renderer/game/profile/skills.js`:

```js
// What the profile measures: concepts (one skill each, for item response
// theory), and skills (a few concepts read together, MVProfile-style depth).
// `ref` is the concept's number in the teach-once proposal
// (docs/superpowers/specs/2026-10-18-teach-once-and-checklists-proposal.md,
// section 1.3); null where that list has no entry.
//
// Ids are stored (inside the recipe box), so each must pass FORBIDDEN_ON_DISK.
// `hidden`: measured, and counts toward its lesson, but never listed on the
// profile screen, in a skill, or in anything published.
export const CONCEPTS = Object.freeze([
  { id: 'who-made-it', ref: 'C1', title: 'Who made it' },
  { id: 'where-it-lives', ref: 'C2', title: 'Where it lives' },
  { id: 'fix-and-undo', ref: 'C8', title: 'Switching things off so you can undo it' },
  { id: 'couldnt-check', ref: 'C9', title: 'What “couldn’t check” means' },
  { id: 'clean-isnt-certain', ref: 'C10', title: 'What a clean result means' },
  { id: 'disk-encryption', ref: 'C12', title: 'Disk encryption and the recovery key' },
  { id: 'auto-updates', ref: 'C13', title: 'Automatic updates' },
  { id: 'lock-screen', ref: 'C14', title: 'The lock screen' },
  { id: 'browser-add-ons', ref: 'C15', title: 'Browser add-ons' },
  { id: 'remote-access-scams', ref: 'C17', title: 'Remote-access scams' },
  { id: 'password-prompts', ref: 'C19', title: 'Who asks for your password' },
  { id: 'wifi-and-mining', ref: 'C22', title: 'Your Wi-Fi and a hot, slow computer' },
  { id: 'cut-off-order', ref: 'C4', title: 'The order to do things in', hidden: true },
  { id: 'poisoned-packages', ref: 'C23', title: 'Poisoned packages' },
  { id: 'fake-messages', ref: null, title: 'Spotting a fake message' },
]);

export const SKILLS = Object.freeze([
  { id: 'reading-makers', title: 'Reading who made it and where it lives', concepts: ['who-made-it', 'where-it-lives'] },
  { id: 'starting-on-its-own', title: 'Things that start on their own', concepts: ['fix-and-undo'] },
  { id: 'locks-and-updates', title: 'Locks and updates', concepts: ['auto-updates', 'disk-encryption', 'lock-screen'] },
  { id: 'add-ons', title: 'Browser add-ons', concepts: ['browser-add-ons'] },
  { id: 'your-network', title: 'Your network', concepts: ['wifi-and-mining'] },
  { id: 'spotting-scams', title: 'Spotting a scam', concepts: ['remote-access-scams', 'password-prompts', 'fake-messages'] },
  { id: 'developer-packages', title: 'Developer packages', concepts: ['poisoned-packages'] },
  { id: 'honest-results', title: 'Honest results', concepts: ['couldnt-check', 'clean-isnt-certain'] },
]);

// Which concept a practice drill measures, by drill id. A drill not listed
// here (or listed as null) still counts toward drill accuracy, but toward no
// concept: its skill has no lesson to measure against yet.
export const DRILL_CONCEPTS = Object.freeze({
  'upd8r-hidden-cache': 'where-it-lives',
  'zoom-helper-signed': 'who-made-it',
  'tmp-script-agent': 'where-it-lives',
  'sync-keepalive': 'who-made-it',
  'small-app-helper': 'who-made-it',
  'own-backup-script': 'who-made-it',
  'hosts-bank-redirect': null,
  'dev-cert-app': 'who-made-it',
  'proxy-unknown': null,
  'proxy-work': null,
  'busy-miner': 'wifi-and-mining',
  'busy-video-export': 'wifi-and-mining',
  'preinstalled-trial': 'who-made-it',
  'signed-optimizer': 'who-made-it',
  'downloads-login-item': 'where-it-lives',
});

// A Signal or Noise call on a real finding has no right answer, so it is
// never graded. When Scout reads a call differently, it is a gap signal for
// the concepts behind the clues the person opened (or, with none opened, the
// concepts of the lessons that teach the finding's module).
export const CLUE_CONCEPTS = Object.freeze({ maker: 'who-made-it', where: 'where-it-lives' });

const BY_ID = new Map(CONCEPTS.map((c) => [c.id, c]));
export const conceptById = (id) => BY_ID.get(id) || null;
export const isHidden = (id) => !!(BY_ID.get(id) || {}).hidden;
export const shownConcepts = () => CONCEPTS.filter((c) => !c.hidden);
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-skills.test.js`

Expected: PASS, 3 tests (every one of the 15 drills in `renderer/game/drills/` is mapped).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/profile/skills.js desktop/test/profile-skills.test.js
git commit -m "Profile: concepts, skills and which concept each drill measures"
```

---

### Task 5: The item bank, and the gate reads variants

**Files:**

- Create: `desktop/renderer/game/profile/item-bank.js`
- Test: `desktop/test/profile-item-bank.test.js`; `desktop/test/profile-fixtures.js` (shared with Task 6)
- Modify: `desktop/test/game-lessons.test.js` (`ownText`, the options loop, two appended tests)

**Interfaces:**

- Consumes: `irt.js` (`guessFloor`, `levelB`, `information`) from Task 2; `skills.js` (`DRILL_CONCEPTS`, `conceptById`) from Task 4; `disk-words.js` from Task 1.
- Produces: `VISIT_MAX = 3`, `LEARN_THIS_MAX = 2`, `RECENT = 2`; `buildBank(lessons, drills) -> { items: Map<key, item>, lessons: Map<id, {id, title, concepts, families, keys, modules, recommendedFor}>, concepts: Map<conceptId, key[]> }` where an item is `{ key, family, concept, lessonId, kind: 'lesson'|'drill', first, prompt, options, teach, setting, message, level, c }` and a drill's key is `drill:<id>`; `emptyBank()`; `lessonsWithConcept(bank, conceptId) -> lessonId[]`; `drawLessonVisit(bank, lessonId, history, { max, bOf }) -> key[]`; `drawConcept(bank, conceptId, history, { max, bOf }) -> key[]`. `history[conceptId] = { mean, learned, recent: key[], seen: Set<key> }`. A lesson question may now carry `key`, `concept`, `level` and `variants: [{ key, prompt, options, message?, level? }]`.

- [ ] **Step 1: Add the fixtures**

Create `desktop/test/profile-fixtures.js`:

```js
// Small, made-up lessons and drills for the profile tests, so these tests
// don't move when the real lessons' wording does.
const o3 = () => [
  { text: 'Right one', correct: true, feedback: 'Right.' },
  { text: 'Wrong one', correct: false, feedback: 'No.' },
  { text: 'Other wrong', correct: false, feedback: 'No.' },
];
const o2 = () => [
  { text: 'Yes', correct: true, feedback: 'Right.' },
  { text: 'No', correct: false, feedback: 'No.' },
];
const family = (key, concept, options, teach = `Teach ${key}`) => ({
  key, concept, teach, prompt: `Prompt ${key}`, options: options(),
  variants: [{ key: `${key}-2`, prompt: `Prompt ${key}-2`, options: options() }, { key: `${key}-3`, prompt: `Prompt ${key}-3`, options: options() }],
});

const LESSONS = [
  { id: 'lesson-a', title: 'Lesson A', modules: ['launch_agent_audit'], recommendedFor: ['hacked'],
    questions: [family('a1', 'who-made-it', o3), family('a2', 'where-it-lives', o3)] },
  { id: 'lesson-b', title: 'Lesson B', modules: [], recommendedFor: ['unsure'],
    questions: [family('b1', 'couldnt-check', o2)] },
];
const DRILLS = [
  { id: 'upd8r-hidden-cache', answer: 'threat', district: 'gatehouse', clues: { what: 'x' } },
  { id: 'zoom-helper-signed', answer: 'mine', district: 'gatehouse', clues: { what: 'x' } },
  { id: 'proxy-work', answer: 'mine', district: 'wires', clues: { what: 'x' } },
];

// A version 3 store from the old key, as main writes it today.
const V3 = {
  version: 3,
  missions: {
    'launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x': { status: 'later', module: 'launch_agent_audit', districtId: 'gatehouse', title: 'A helper', updatedAt: '2026-10-10T09:00:00.000Z' },
    'stalkerware_scan|security.stalkerware_scan.found|x': { status: 'open', module: 'stalkerware_scan', updatedAt: '2026-10-11T09:00:00.000Z' },
    'broken': { status: 'weird' },
  },
  lessons: {
    'lesson-a': { completedAt: '2026-10-09T08:00:00.000Z' },
    'lesson-b': { completedAt: '2026-10-12T08:00:00.000Z', how: 'skipped' },
    'bad': { done: true },
  },
  deck: {
    points: 340, rank: 2, drills: { right: 9, tried: 12 },
    tags: { good: { tag: 'mine', at: 'now', fp: 'f' }, bad: { tag: 'nonsense', at: 'now', fp: 'f' } },
    confirmed: { 'a|b|c': '2026-10-10T09:00:00.000Z' }, once: { 'drill:x': true },
    sweep: { at: '2026-10-12T10:00:00.000Z', keys: { 'clue:x#maker': true } },
    sweeps: [{ at: '2026-10-12T10:00:00.000Z', checks: 9, critical: 0, warning: 2, info: 4, fog: 1, checked: 8, secured: 6 }, { at: 'x' }],
  },
};

const memStore = (init = {}) => {
  const s = { ...init };
  return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; }, raw: s };
};

module.exports = { LESSONS, DRILLS, V3, memStore };
```

- [ ] **Step 2: Write the failing bank test**

Create `desktop/test/profile-item-bank.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS } = require('./profile-fixtures.js');
const load = () => import('../renderer/game/profile/item-bank.js');

const fresh = () => ({});
const hist = (over) => ({ 'who-made-it': { mean: 0, learned: false, recent: [], seen: new Set() }, 'where-it-lives': { mean: 0, learned: false, recent: [], seen: new Set() }, 'couldnt-check': { mean: 0, learned: false, recent: [], seen: new Set() }, ...over });

test('the bank holds every question, every variant and every drill, with its guessing floor', async () => {
  const { buildBank } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.strictEqual(bank.items.size, 9 + 3);
  assert.strictEqual(bank.items.get('a1').first, true);
  assert.strictEqual(bank.items.get('a1-2').first, false);
  assert.strictEqual(bank.items.get('a1-2').teach, 'Teach a1', 'a variant shares its family’s what-to-know');
  assert.strictEqual(bank.items.get('a1').c, 1 / 3);
  assert.strictEqual(bank.items.get('b1-3').c, 0.5);
  assert.deepStrictEqual(bank.concepts.get('who-made-it'), ['a1', 'a1-2', 'a1-3', 'drill:zoom-helper-signed']);
  assert.strictEqual(bank.items.get('drill:upd8r-hidden-cache').concept, 'where-it-lives');
  assert.strictEqual(bank.items.get('drill:proxy-work').concept, null);
  assert.deepStrictEqual(bank.lessons.get('lesson-a').concepts, ['who-made-it', 'where-it-lives']);
  assert.deepStrictEqual(bank.lessons.get('lesson-a').modules, ['launch_agent_audit']);
});

test('a key used twice keeps the first item only', async () => {
  const { buildBank } = await load();
  const dup = [...LESSONS, { id: 'lesson-c', title: 'C', questions: [{ key: 'a1', concept: 'lock-screen', prompt: 'x', options: [] }] }];
  const bank = buildBank(dup, []);
  assert.strictEqual(bank.items.get('a1').concept, 'who-made-it');
  assert.deepStrictEqual(bank.lessons.get('lesson-c').keys, []);
});

test('the first visit is the lesson as written: each question’s own item, in order', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', hist()), ['a1', 'a2']);
  assert.deepStrictEqual(drawLessonVisit(bank, 'nope', hist()), []);
});

test('later visits: unseen variants first, concepts not learned only, never the item just asked', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const h = hist({ 'who-made-it': { mean: 0.2, learned: false, recent: ['a1'], seen: new Set(['a1']) } });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', h), ['a1-2', 'a2', 'a1-3']);
  const learned = hist({ 'who-made-it': { mean: 1, learned: true, recent: ['a1', 'a1-2', 'a1-3'], seen: new Set(['a1', 'a1-2', 'a1-3']) } });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', learned), ['a2', 'a2-2', 'a2-3'], 'only the concept still open');
});

test('when every concept is learned, a visit is a review over all of them', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const all = (keys) => ({ mean: 1, learned: true, recent: keys, seen: new Set(keys) });
  const h = hist({ 'who-made-it': all(['a1', 'a1-2', 'a1-3']), 'where-it-lives': all(['a2-3', 'a2', 'a2-2']) });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', h), ['a1', 'a2-3']);
});

test('the most informative item comes first among unseen ones', async () => {
  const { buildBank, drawConcept } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const b = (k) => ({ a1: 2, 'a1-2': 0.9, 'a1-3': -2 }[k]);
  const h = hist({ 'who-made-it': { mean: 1, learned: false, recent: [], seen: new Set() } });
  assert.deepStrictEqual(drawConcept(bank, 'who-made-it', h, { bOf: b }), ['a1-2', 'a1']);
});

test('Learn this draws at most two items on one concept, and never a drill', async () => {
  const { buildBank, drawConcept, LEARN_THIS_MAX } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.strictEqual(LEARN_THIS_MAX, 2);
  const keys = drawConcept(bank, 'who-made-it', hist());
  assert.strictEqual(keys.length, 2);
  assert.ok(keys.every((k) => !k.startsWith('drill:')));
  assert.deepStrictEqual(drawConcept(bank, 'lock-screen', hist()), []);
});
```

- [ ] **Step 3: Make the gate read variants and check keys**

In `desktop/test/game-lessons.test.js`, replace:

```js
function ownText(lesson) {
  // For the phishing lesson, the messages and their tells are Reclaim City's
  // content. Only Device Rescue's wrapper text is checked here.
  const qs = lesson.questions.flatMap((q) => (lesson.type === 'phishing'
    ? [q.prompt, q.teach]
    : [q.prompt, q.teach, ...q.options.flatMap((o) => [o.text, o.feedback])]));
  return [lesson.title, lesson.briefing, lesson.whatTheScanLooksFor, ...qs].filter((t) => t != null);
}
```

with:

```js
// A question and each of its variants: the items item response theory measures.
const itemsOf = (q) => [q, ...(Array.isArray(q.variants) ? q.variants : [])];

function ownText(lesson) {
  // For the phishing lesson, the messages and their tells are Reclaim City's
  // content. Only Device Rescue's wrapper text is checked here.
  const qs = lesson.questions.flatMap((q) => [q.teach, ...itemsOf(q).flatMap((it) => (lesson.type === 'phishing'
    ? [it.prompt]
    : [it.prompt, ...it.options.flatMap((o) => [o.text, o.feedback])]))]);
  return [lesson.title, lesson.briefing, lesson.whatTheScanLooksFor, ...qs].filter((t) => t != null);
}
```

In `desktop/test/game-lessons.test.js`, replace:

```js
    for (const q of l.questions) {
      assert.ok(q.options.length >= 2, `${l.id}: "${q.prompt}" needs options`);
      assert.strictEqual(q.options.filter((o) => o.correct === true).length, 1, `${l.id}: "${q.prompt}" needs exactly one right answer`);
      for (const o of q.options) assert.ok(typeof o.feedback === 'string' && o.feedback.trim(), `${l.id}: "${o.text}" has no feedback`);
    }
```

with:

```js
    for (const q of l.questions.flatMap(itemsOf)) {
      assert.ok(q.options.length >= 2, `${l.id}: "${q.prompt}" needs options`);
      assert.strictEqual(q.options.filter((o) => o.correct === true).length, 1, `${l.id}: "${q.prompt}" needs exactly one right answer`);
      for (const o of q.options) assert.ok(typeof o.feedback === 'string' && o.feedback.trim(), `${l.id}: "${o.text}" has no feedback`);
    }
```

Append to `desktop/test/game-lessons.test.js`:

```js

// The item bank (docs/superpowers/plans/2026-10-18-player-profile-and-irt.md):
// every item a lesson can ask has a stable key and the concept it measures.
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');
const KEY_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

test('item keys are stable slugs, unique across every lesson, and safe to store', async () => {
  const { lessons } = await loadAll();
  const seen = new Map();
  for (const l of lessons) {
    for (const q of l.questions) {
      for (const it of itemsOf(q).filter((x) => x.key !== undefined)) {
        assert.match(it.key, KEY_RE, `${l.id}: key "${it.key}"`);
        assert.doesNotMatch(it.key, FORBIDDEN_ON_DISK, `${l.id}: key "${it.key}"`);
        assert.ok(!seen.has(it.key), `${l.id}: key "${it.key}" is also used in ${seen.get(it.key)}`);
        seen.set(it.key, l.id);
      }
      if (Array.isArray(q.variants) && q.variants.length) {
        assert.ok(typeof q.key === 'string', `${l.id}: "${q.prompt}" has variants but no key`);
        for (const v of q.variants) assert.ok(typeof v.key === 'string', `${l.id}: a variant of "${q.prompt}" has no key`);
      }
    }
  }
});

test('every concept a question names exists, and variants share their question’s concept', async () => {
  const { lessons } = await loadAll();
  const { conceptById } = await import(pathToFileURL(path.join(GAME, 'profile', 'skills.js')).href);
  for (const l of lessons) {
    for (const q of l.questions.filter((x) => x.concept !== undefined)) {
      assert.ok(conceptById(q.concept), `${l.id}: no concept ${q.concept}`);
      for (const v of q.variants || []) assert.strictEqual(v.concept, undefined, `${l.id}: ${v.key} names its own concept; it takes its question’s`);
    }
  }
});
```

- [ ] **Step 4: Run them to make sure the bank test fails**

Run: `cd desktop && node --test test/profile-item-bank.test.js test/game-lessons.test.js`

Expected: `profile-item-bank.test.js` FAILS with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/item-bank.js`. `game-lessons.test.js` PASSES: no lesson has keys yet, so the new checks have nothing to reject.

- [ ] **Step 5: Write the bank**

Create `desktop/renderer/game/profile/item-bank.js`:

```js
// The item bank: every lesson question and every variant of it, plus every
// practice drill, as items that item response theory can measure. And the
// adaptive draw: which few items a lesson visit (or "Learn this") asks next.
// Pure.
//
// A lesson question is a *family*: its own prompt is the family's first item,
// and each entry in its `variants` is another item on the same skill, worded
// differently or set in a different scene. A family shares its `teach`,
// `setting`, `key` prefix and `concept`.
import { guessFloor, levelB, information } from './irt.js';
import { DRILL_CONCEPTS } from './skills.js';

export const VISIT_MAX = 3;
export const LEARN_THIS_MAX = 2;
// An item asked among a concept's last RECENT answers isn't asked again yet.
export const RECENT = 2;

function lessonItems(lesson) {
  const out = [];
  for (const q of Array.isArray(lesson.questions) ? lesson.questions : []) {
    if (!q || typeof q.key !== 'string' || typeof q.concept !== 'string') continue;
    const shared = { family: q.key, concept: q.concept, lessonId: lesson.id, kind: 'lesson', teach: q.teach || null, setting: q.setting || null };
    const all = [{ ...q, first: true }, ...(Array.isArray(q.variants) ? q.variants.map((v) => ({ ...v, first: false })) : [])];
    for (const v of all) {
      if (!v || typeof v.key !== 'string' || !Array.isArray(v.options)) continue;
      out.push({ ...shared, key: v.key, first: v.first, prompt: v.prompt, options: v.options, message: v.message || null,
        level: v.level || q.level || 'medium', c: guessFloor(v.options.length) });
    }
  }
  return out;
}

function drillItem(d) {
  const concept = Object.prototype.hasOwnProperty.call(DRILL_CONCEPTS, d.id) ? DRILL_CONCEPTS[d.id] : null;
  return { key: `drill:${d.id}`, family: `drill:${d.id}`, concept, lessonId: null, kind: 'drill', first: true, level: 'medium', c: guessFloor(3) };
}

// `lessons`: as training.loadLessons returns them. `drills`: as drills.loadDrills does.
// The first item with a key wins; a later duplicate is left out.
export function buildBank(lessons, drills) {
  const items = new Map();
  const byLesson = new Map();
  const byConcept = new Map();
  const add = (it) => {
    if (items.has(it.key)) return false;
    items.set(it.key, it);
    if (it.concept) {
      if (!byConcept.has(it.concept)) byConcept.set(it.concept, []);
      byConcept.get(it.concept).push(it.key);
    }
    return true;
  };
  for (const l of Array.isArray(lessons) ? lessons : []) {
    if (!l || typeof l.id !== 'string') continue;
    const keys = lessonItems(l).filter(add).map((it) => it.key);
    const concepts = [...new Set(keys.map((k) => items.get(k).concept))];
    const families = [...new Set(keys.map((k) => items.get(k).family))];
    byLesson.set(l.id, { id: l.id, title: l.title, concepts, families, keys, modules: l.modules || [], recommendedFor: l.recommendedFor || [] });
  }
  for (const d of Array.isArray(drills) ? drills : []) if (d && typeof d.id === 'string') add(drillItem(d));
  return { items, lessons: byLesson, concepts: byConcept };
}

export const emptyBank = () => buildBank([], []);

export function lessonsWithConcept(bank, conceptId) {
  return [...bank.lessons.values()].filter((l) => l.concepts.includes(conceptId)).map((l) => l.id);
}

// `history[conceptId]`: { mean, learned, recent: [itemKey, …] newest last, seen: Set<itemKey> }.
// `bOf(key)`: the item's current difficulty.
function pick(bank, conceptIds, history, max, bOf, only) {
  const out = [];
  const families = new Set();
  const lists = conceptIds.map((c) => {
    const h = history[c] || { mean: 0, recent: [], seen: new Set() };
    const recent = new Set((h.recent || []).slice(-RECENT));
    const keys = (bank.concepts.get(c) || []).filter((k) => {
      const it = bank.items.get(k);
      return it.kind === 'lesson' && (!only || only(it)) && !recent.has(k);
    });
    const seen = h.seen || new Set();
    // Unseen items first; then the most informative at the current estimate; then bank order.
    return keys.map((k, i) => ({ k, i, unseen: seen.has(k) ? 0 : 1, info: information(h.mean || 0, bOf(k), bank.items.get(k).c) }))
      .sort((a, b) => (b.unseen - a.unseen) || (b.info - a.info) || (a.i - b.i)).map((x) => x.k);
  });
  // One item per family first; then, if there is room, another variant of a family already asked.
  for (const oneEach of [true, false]) {
    while (out.length < max) {
      let added = false;
      for (const list of lists) {
        if (out.length >= max) break;
        const k = list.find((key) => !out.includes(key) && !(oneEach && families.has(bank.items.get(key).family)));
        if (k) { out.push(k); families.add(bank.items.get(k).family); added = true; }
      }
      if (!added) break;
    }
  }
  return out;
}

const defaultB = (bank) => (k) => levelB(bank.items.get(k).level);

// The items for one visit to a lesson. The first visit (nothing answered on
// any of its concepts yet) is the lesson as written: each question's own
// item, in order. After that: up to VISIT_MAX items, one per family, spread
// over the concepts not learned yet (or over all of them, as a review).
export function drawLessonVisit(bank, lessonId, history, { max = VISIT_MAX, bOf = defaultB(bank) } = {}) {
  const l = bank.lessons.get(lessonId);
  if (!l) return [];
  const answered = l.concepts.some((c) => history[c] && history[c].seen && history[c].seen.size);
  if (!answered) return l.families.map((f) => l.keys.find((k) => bank.items.get(k).family === f && bank.items.get(k).first)).filter(Boolean);
  const open = l.concepts.filter((c) => !(history[c] && history[c].learned));
  return pick(bank, open.length ? open : l.concepts, history, max, bOf, (it) => it.lessonId === lessonId);
}

// "Learn this (2 questions)": items on one concept, from any lesson.
export function drawConcept(bank, conceptId, history, { max = LEARN_THIS_MAX, bOf = defaultB(bank) } = {}) {
  return pick(bank, [conceptId], history, max, bOf, null);
}
```

- [ ] **Step 6: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/profile-item-bank.test.js test/game-lessons.test.js`

Expected: PASS, 7 bank tests and every gate test.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/profile/item-bank.js desktop/test/profile-item-bank.test.js desktop/test/profile-fixtures.js desktop/test/game-lessons.test.js
git commit -m "Profile: the item bank and adaptive draw; the lesson gate reads variants"
```

---

### Task 6: The player profile

**Files:**

- Create: `desktop/renderer/game/profile/player-profile.js`
- Test: `desktop/test/profile-player.test.js` (uses `desktop/test/profile-fixtures.js` from Task 5)

**Interfaces:**

- Consumes: `recipe-box.js` (`encode`, `decode`, `seedOf`, `validSeed`); `irt.js` (`estimate`, `isLearned`, `levelB`, `updateDifficulty`, `PRIOR`, `BEFORE_PRIOR`, `MIN_RESPONSES`); `item-bank.js` (`lessonsWithConcept`, and banks from `buildBank`); `skills.js` (`CONCEPTS`, `SKILLS`, `CLUE_CONCEPTS`, `isHidden`, `conceptById`); `progress.js` (`STORE_KEY`, `TAGS`, `SWEEP_FIELDS`); `ledger.js` (`MONITORING_MODULES`, `RANKS`, `rankOf`, `sweepPercent`, `MAX_SWEEPS`).
- Produces: `PROFILE_KEY = 'device-rescue.recipe-box.v1'`, `SPARE_KEY`, `OLD_KEY` (= `device-rescue.game.v1`), `SEED_KEY = 'device-rescue.city-seed'`, `VERSION = 4`, `MAX_SEEN = 30`; `emptyProfile(now)`, `salvage(raw, now) -> {profile, changes}`, `loadProfile(storage, now) -> profile`, `profileSeed(storage, displayMode, random?) -> number`, `saveProfile(storage, profile, {seed, mode}) -> boolean`; `conceptEstimate(p, bank, c)`, `conceptState(p, bank, c) -> 'learned'|'refresher'|'worth-a-look'|'skipped'|'started'|'not-yet'`, `lessonState(p, bank, id) -> {state: 'learned'|'refresher'|'worth-a-look'|'skipped'|'measuring'|'not-yet', done, answered, right, concepts}`, `historyFor(p, bank)`, `difficultyOf(p, bank) -> (key) => b`, `teachShown(p, bank, key)`; writes `recordAnswer(p, bank, key, right, now)`, `recordVisit(p, lessonId, now)`, `recordDrillCall(p, bank, drill, picked, now)`, `callConcepts(bank, module, openedKinds) -> conceptId[]`, `recordGap(p, concepts, 'call'|'reopen', now)`, `markKnown(p, concepts, now)`, `markLessonKnown(p, lessonId, now)`, `shouldOffer(p, bank, c, sweepAt)`, `noteOffered(p, c, now)`, `declineOffer(p, c, now)`; `toProgress(p, bank) -> {version: 3, missions, lessons, deck}`, `withProgress(p, progress) -> p`; `calibration(drills) -> {over, under, total}`; `summary(p, bank, lessonOrder?) -> {lessons, concepts, skills, lessonsLearned, drills, rank: {index, level, of, name, points, toNext, next}, city: {reclaimed, later, yours, lastSweep}, since, migrations}`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-player.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3, memStore } = require('./profile-fixtures.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const NOW = '2026-10-18T12:00:00.000Z';
const at = (n) => `2026-10-18T12:00:${String(n).padStart(2, '0')}.000Z`;
const load = async () => {
  const [pp, ib, rb, ledger] = await Promise.all([
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
    import('../renderer/game/profile/recipe-box.js'),
    import('../renderer/game/ledger.js'),
  ]);
  return { ...pp, bank: ib.buildBank(LESSONS, DRILLS), rb, ledger };
};
const answer = (m, p, bank, keys, rights) => keys.reduce((acc, k, i) => m.recordAnswer(acc, bank, k, rights[i], at(i)), p);

test('v3 migrates record by record: a bad tag or lesson costs only itself; points and rank survive', async () => {
  const { salvage } = await load();
  const { profile: p, changes } = salvage(V3, NOW);
  assert.strictEqual(p.version, 4);
  assert.deepStrictEqual(Object.keys(p.missions), ['launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x'], 'monitoring and broken missions dropped');
  assert.strictEqual(p.missions['launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x'].title, 'A helper');
  assert.deepStrictEqual(p.lessons['lesson-a'], { visited: '2026-10-09T08:00:00.000Z', before: '2026-10-09T08:00:00.000Z' });
  assert.deepStrictEqual(p.lessons['lesson-b'], { self: '2026-10-12T08:00:00.000Z' });
  assert.strictEqual(p.lessons.bad, undefined);
  assert.deepStrictEqual(p.rank, { points: 340, index: 2 });
  assert.deepStrictEqual([p.drills.right, p.drills.tried], [9, 12]);
  assert.deepStrictEqual(Object.keys(p.deck.tags), ['good']);
  assert.strictEqual(p.deck.sweeps.length, 1);
  assert.strictEqual(p.since, '2026-10-09T08:00:00.000Z');
  assert.ok(changes.includes('lessons: 2 kept'));
  assert.ok(changes.some((c) => /^deck: \d+ dropped$/.test(c)));
});

test('v1 and v2 documents migrate too; anything else starts fresh without throwing', async () => {
  const { salvage } = await load();
  const v1 = salvage({ version: 1, missions: { a: { status: 'open', module: 'm' } } }, NOW).profile;
  assert.deepStrictEqual(Object.keys(v1.missions), ['a']);
  const v2 = salvage({ version: 2, missions: {}, lessons: { 'lesson-a': { completedAt: 'x' } } }, NOW).profile;
  assert.strictEqual(v2.lessons['lesson-a'].before, 'x');
  for (const junk of [null, 'x', [], { version: 9 }]) assert.strictEqual(salvage(junk, NOW).profile.version, 4);
});

test('first load reads the old key, logs the migration, and leaves the old key exactly as it was', async () => {
  const { loadProfile, OLD_KEY } = await load();
  const text = JSON.stringify(V3);
  const store = memStore({ [OLD_KEY]: text });
  const p = loadProfile(store, NOW);
  assert.strictEqual(p.rank.points, 340);
  assert.strictEqual(p.migrations.length, 1);
  assert.strictEqual(p.migrations[0].from, 3);
  assert.strictEqual(store.raw[OLD_KEY], text);
});

test('save then load gives the same profile; nothing written names what must stay off disk', async () => {
  const { loadProfile, saveProfile, recordAnswer, bank, PROFILE_KEY, OLD_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: JSON.stringify(V3) });
  let p = loadProfile(store, NOW);
  p.missions['x|y|/Users/ann/partner-safety'] = { status: 'open', module: 'm', title: 'Monitor hotline stalkerware' };
  p = recordAnswer(p, bank, 'a1', true, NOW);
  assert.strictEqual(saveProfile(store, p, { seed: 4242, mode: 'standard' }), true);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.deepStrictEqual(loadProfile(store, NOW), p);
  assert.ok(store.data[PROFILE_KEY].startsWith('{"kitchen":'));
  assert.ok(store.data[OLD_KEY], 'standard mode keeps the old key as a backup');
});

test('in city mode the old literal document goes once the box is written', async () => {
  const { loadProfile, saveProfile, OLD_KEY, PROFILE_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: JSON.stringify(V3) });
  const p = loadProfile(store, NOW);
  assert.strictEqual(saveProfile(store, p, { seed: 4242, mode: 'city' }), true);
  assert.strictEqual(store.data[OLD_KEY], undefined);
  assert.ok(store.data[PROFILE_KEY]);
});

test('a save that cannot be encoded writes nothing and removes nothing', async () => {
  const { saveProfile, emptyProfile, OLD_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: '{}' });
  assert.strictEqual(saveProfile(store, emptyProfile(NOW), { seed: 0, mode: 'city' }), false);
  assert.deepStrictEqual(store.writes, []);
  assert.deepStrictEqual(store.removed, []);
});

test('a box that will not decode is kept aside, never overwritten, and the old key is read instead', async () => {
  const { loadProfile, PROFILE_KEY, SPARE_KEY, OLD_KEY } = await load();
  const store = memStore({ [PROFILE_KEY]: '{"kitchen":"basil basil basil basil","cards":[]}', [OLD_KEY]: JSON.stringify(V3) });
  const p = loadProfile(store, NOW);
  assert.strictEqual(p.rank.points, 340);
  assert.strictEqual(store.raw[SPARE_KEY], '{"kitchen":"basil basil basil basil","cards":[]}');
});

test('the seed comes from the box when there is one, else from the install', async () => {
  const { profileSeed, saveProfile, emptyProfile } = await load();
  const store = memStore();
  const dm = { ensureSeed: () => 99 };
  assert.strictEqual(profileSeed(store, dm), 99);
  saveProfile(store, emptyProfile(NOW), { seed: 1234 });
  assert.strictEqual(profileSeed(store, dm), 1234);
  const bare = memStore({ 'device-rescue.city-seed': '777' });
  assert.strictEqual(profileSeed(bare, null), 777, 'the install’s seed key, read the way DisplayMode reads it');
  const none = memStore();
  assert.strictEqual(profileSeed(none, null, () => 0.5), 1073741824);
  assert.strictEqual(none.raw['device-rescue.city-seed'], '1073741824', 'and kept, so the next session matches');
});

test('learned comes from the estimate: three right on two items; wrong answers are kept as evidence', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p = answer(m, p, m.bank, ['a1', 'a1-2'], [true, true]);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'started');
  p = m.recordAnswer(p, m.bank, 'a1-3', true, at(3));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned');
  assert.ok(p.concepts['who-made-it'].learnedAt);
  p = m.recordAnswer(p, m.bank, 'a1', false, at(4));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned', 'one slip keeps it');
  assert.deepStrictEqual(p.concepts['who-made-it'].seen.map((e) => e[1]), [1, 1, 1, 0]);
  p = m.recordAnswer(p, m.bank, 'a1-2', false, at(5));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'refresher');
});

test('each answer moves its item’s difficulty', async () => {
  const m = await load();
  const p = m.recordAnswer(m.emptyProfile(NOW), m.bank, 'a1', true, NOW);
  assert.deepStrictEqual(p.items.a1, { b: -0.0333, n: 1 }, 'b + 0.1·(2/3 − 1)');
});

test('answering every question once is evidence, not proof; the visit makes the lesson done for the game', async () => {
  const m = await load();
  let p = answer(m, m.emptyProfile(NOW), m.bank, ['a1', 'a2'], [true, true]);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'measuring');
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').done, false);
  p = m.recordVisit(p, 'lesson-a', NOW);
  const s = m.lessonState(p, m.bank, 'lesson-a');
  assert.deepStrictEqual([s.state, s.done, s.answered, s.right], ['measuring', true, 2, 2]);
  assert.ok(m.toProgress(p, m.bank).lessons['lesson-a'], 'the game’s lessonDone sees it');
});

test('a lesson finished under the old rule is learned until its own answers say otherwise', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'learned');
  p = answer(m, p, m.bank, ['a1', 'a1-2', 'a1-3'], [false, false, false]);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'refresher');
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'learned');
});

test('"I know this" is skipped, not learned; a wrong drill makes it worth a look, and an offer follows the rules', async () => {
  const m = await load();
  let p = m.markKnown(m.emptyProfile(NOW), ['where-it-lives'], at(1));
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'skipped');
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), false);
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'mine', at(2));
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'worth-a-look');
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), true);
  p = m.noteOffered(p, 'where-it-lives', at(3));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), false, 'once per sweep');
  p = m.declineOffer(p, 'where-it-lives', at(4));
  p = m.recordGap(p, ['where-it-lives'], 'call', at(5));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(5)), true, 'one decline: a new signal offers again');
  p = m.declineOffer(p, 'where-it-lives', at(6));
  p = m.recordGap(p, ['where-it-lives'], 'call', at(7));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(7)), false, 'two declines: only a wrong drill reopens it');
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'closer', at(8));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(8)), true);
});

test('a lesson skipped as a whole skips each of its concepts', async () => {
  const m = await load();
  const p = m.markLessonKnown(m.emptyProfile(NOW), 'lesson-a', NOW);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'skipped');
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'skipped');
});

test('drill calls fill the calls matrix and the last-10 row; calibration counts over- and under-calling', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p = m.recordDrillCall(p, m.bank, DRILLS[1], 'threat', at(1)); // mine called threat: over
  p = m.recordDrillCall(p, m.bank, DRILLS[2], 'threat', at(2)); // over, on a drill with no concept
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'mine', at(3)); // threat called mine: under
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'threat', at(4));
  assert.strictEqual(p.drills.calls.mine.threat, 2);
  assert.strictEqual(p.drills.calls.threat.mine, 1);
  assert.deepStrictEqual(p.drills.recent, [0, 0, 0, 1]);
  assert.deepStrictEqual(m.calibration(p.drills), { over: 2, under: 1, total: 4 });
  assert.strictEqual(p.concepts['who-made-it'].seen.length, 1);
  assert.strictEqual(m.recordDrillCall(p, m.bank, DRILLS[0], 'nonsense', NOW), p);
});

test('a real call maps to the clues opened, else to the lessons for its module; never to monitoring checks', async () => {
  const m = await load();
  assert.deepStrictEqual(m.callConcepts(m.bank, 'launch_agent_audit', ['where', 'what']), ['where-it-lives']);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'launch_agent_audit', []), ['who-made-it', 'where-it-lives']);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'stalkerware_scan', ['maker']), []);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'nothing_teaches_this', []), []);
});

test('the v3 view feeds the ledger unchanged, and folding it back never lowers the rank', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  const view = m.toProgress(p, m.bank);
  assert.strictEqual(view.deck.points, 340);
  const r = m.ledger.award(view.deck, 'fix', 'launch_agent_audit|x|y');
  p = m.withProgress(p, { ...view, deck: r.deck });
  assert.strictEqual(p.rank.points, 390);
  p = m.withProgress(p, { ...view, deck: { ...r.deck, rank: 0 } });
  assert.strictEqual(p.rank.index, 2, 'rank never drops');
  p = m.withProgress(p, { ...view, missions: { ...view.missions, 'stalkerware_scan|a|b': { status: 'open', module: 'stalkerware_scan' } } });
  assert.strictEqual(p.missions['stalkerware_scan|a|b'], undefined);
});

test('the what-to-know shows until one item in its family is answered right', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), true);
  p = m.recordAnswer(p, m.bank, 'a1', false, NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), true);
  p = m.recordAnswer(p, m.bank, 'a1-3', true, NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), false);
  assert.strictEqual(m.teachShown(p, m.bank, 'a2'), true);
});

test('the summary: lessons, shown concepts, skill depth, drills and rank', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  p = answer(m, p, m.bank, ['b1', 'b1-2', 'b1-3'], [true, true, true]);
  const s = m.summary(p, m.bank);
  assert.deepStrictEqual(s.lessons.map((l) => [l.id, l.state]), [['lesson-a', 'learned'], ['lesson-b', 'learned']]);
  assert.strictEqual(s.lessonsLearned, 2);
  const honest = s.skills.find((k) => k.id === 'honest-results');
  assert.deepStrictEqual([honest.depth, honest.learned, honest.of], ['practiced', 1, 1]);
  assert.strictEqual(s.skills.find((k) => k.id === 'locks-and-updates'), undefined, 'nothing in this bank measures it, so it isn’t listed');
  assert.strictEqual(s.skills.find((k) => k.id === 'reading-makers').depth, 'practiced');
  assert.deepStrictEqual([s.rank.name, s.rank.level, s.rank.of, s.rank.toNext], ['NETRUNNER', 3, 5, 360]);
  assert.deepStrictEqual(s.city, { reclaimed: 0, later: 1, yours: 0, lastSweep: 75 });
  assert.ok(s.concepts.every((c) => c.id !== 'cut-off-order'));
});

// Review focus: inputs the spec implies but the tests above don't reach.
test('a box from a newer build is kept aside, never overwritten, and the old key is read instead', async () => {
  const { loadProfile, PROFILE_KEY, SPARE_KEY, OLD_KEY } = await load();
  const { encode } = await import('../renderer/game/profile/recipe-box.js');
  const newer = encode({ version: 5, whatever: true }, 321);
  const store = memStore({ [PROFILE_KEY]: newer, [OLD_KEY]: JSON.stringify(V3) });
  assert.strictEqual(loadProfile(store, NOW).rank.points, 340);
  assert.strictEqual(store.raw[SPARE_KEY], newer);
});

test('storage that refuses writes: nothing is removed, the save says it failed, nothing throws', async () => {
  const { saveProfile, emptyProfile, OLD_KEY } = await load();
  let removed = 0;
  const full = { getItem: () => null, setItem: () => { throw new Error('QuotaExceededError'); }, removeItem: () => { removed += 1; } };
  assert.strictEqual(saveProfile(full, emptyProfile(NOW), { seed: 5, mode: 'city' }), false);
  assert.strictEqual(removed, 0, `the old ${OLD_KEY} stays when the box couldn’t be written`);
});

test('evidence on an item no longer in the bank is ignored, never thrown on', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p.concepts['who-made-it'] = { seen: [['gone-item', 1, NOW, 'lesson'], ['gone-item', 1, NOW, 'lesson'], ['a1', 1, NOW, 'lesson']] };
  p = m.salvage(p, NOW).profile;
  assert.strictEqual(m.conceptEstimate(p, m.bank, 'who-made-it').n, 1);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'started');
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').answered, 1);
  assert.strictEqual(m.recordAnswer(p, m.bank, 'gone-item', true, NOW), p, 'an answer to an unknown item records nothing');
});

test('long use stays small: evidence per concept is capped, and the box stays well under storage limits', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  for (let i = 0; i < 400; i += 1) p = m.recordAnswer(p, m.bank, ['a1', 'a1-2', 'a1-3', 'a2', 'b1'][i % 5], i % 3 !== 0, at(i % 60));
  assert.ok(Object.values(p.concepts).every((c) => (c.seen || []).length <= m.MAX_SEEN));
  const store = memStore();
  m.saveProfile(store, p, { seed: 11 });
  assert.ok(store.raw[m.PROFILE_KEY].length < 200000, `${store.raw[m.PROFILE_KEY].length} characters`);
});

test('a sweep’s carry flag survives the round trip, so held software going is never paid after a restart', async () => {
  const m = await load();
  const raw = { ...V3, deck: { ...V3.deck, sweep: { ...V3.deck.sweep, carry: true } } };
  const p = m.salvage(raw, NOW).profile;
  assert.strictEqual(p.deck.sweep.carry, true);
  assert.strictEqual(m.toProgress(p, m.bank).deck.sweep.carry, true);
  assert.strictEqual(m.withProgress(p, m.toProgress(p, m.bank)).deck.sweep.carry, true);
  assert.strictEqual(m.salvage(V3, NOW).profile.deck.sweep.carry, undefined, 'absent unless set');
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-player.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/player-profile.js`.

- [ ] **Step 3: Write the profile**

Create `desktop/renderer/game/profile/player-profile.js`:

```js
// The player profile: one record of what the person has learned, skipped or
// not yet met, the evidence behind it, drill calibration, rank, the deck and
// missions. The only code that reads or writes it on disk. Stored as a recipe
// box (recipe-box.js) in every display mode, so the disk looks the same
// whichever mode is used. No network code, ever.
//
// State shown on screen is derived from the record, never stored (MVProfile's
// rule): see conceptState and lessonState.
import { encode, decode, seedOf, validSeed } from './recipe-box.js';
import { estimate, isLearned, levelB, updateDifficulty, PRIOR, BEFORE_PRIOR, MIN_RESPONSES } from './irt.js';
import { lessonsWithConcept } from './item-bank.js';
import { CONCEPTS, SKILLS, CLUE_CONCEPTS, isHidden, conceptById } from './skills.js';
import { STORE_KEY as OLD_KEY, TAGS, SWEEP_FIELDS } from '../progress.js';
import { MONITORING_MODULES, RANKS, rankOf, sweepPercent, MAX_SWEEPS } from '../ledger.js';

export const PROFILE_KEY = 'device-rescue.recipe-box.v1';
// A box that wouldn't decode is moved here once, never thrown away.
export const SPARE_KEY = 'device-rescue.recipe-box.v1.spare';
export { OLD_KEY };
export const VERSION = 4;
export const MAX_SEEN = 30;
export const MAX_MIGRATIONS = 20;
const STATUSES = new Set(['open', 'later', 'yours', 'reclaimed']);
const SOURCES = new Set(['lesson', 'drill']);
const CALLS = ['threat', 'mine', 'closer'];
const GAP_KINDS = ['drill', 'call', 'reopen'];

const plainObject = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const count = (n) => Number.isInteger(n) && n >= 0;
const str = (s) => typeof s === 'string';
const entries = (o) => (plainObject(o) ? Object.entries(o) : []);
// Object.fromEntries keeps an id like "__proto__" a plain key.
const obj = (pairs) => Object.fromEntries(pairs);

const emptyCalls = () => obj(CALLS.map((t) => [t, obj(CALLS.map((p) => [p, 0]))]));
export function emptyDrills() {
  return { right: 0, tried: 0, calls: emptyCalls(), recent: [] };
}
export function emptyDeckPart() {
  return { tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] };
}
export function emptyProfile(now) {
  return { version: VERSION, since: String(now), migrations: [], concepts: {}, items: {}, lessons: {},
    drills: emptyDrills(), rank: { points: 0, index: 0 }, deck: emptyDeckPart(), missions: {} };
}

// --- salvage: each record on its own; a bad one is dropped, never its neighbours ---

function salvageMissions(m, changes) {
  const out = {};
  let dropped = 0;
  for (const [id, r] of entries(m)) {
    if (!plainObject(r) || !STATUSES.has(r.status) || MONITORING_MODULES.has(r.module)) { dropped += 1; continue; }
    const rec = { status: r.status };
    for (const k of ['module', 'districtId', 'title', 'updatedAt']) if (str(r[k])) rec[k] = r[k];
    out[id] = rec;
  }
  if (dropped) changes.push(`missions: ${dropped} dropped`);
  return out;
}

function salvageDeck(d, changes) {
  const out = emptyDeckPart();
  if (!plainObject(d)) return out;
  let dropped = 0;
  for (const [id, t] of entries(d.tags)) {
    if (plainObject(t) && TAGS.has(t.tag) && str(t.at) && str(t.fp)) out.tags[id] = { tag: t.tag, at: t.at, fp: t.fp }; else dropped += 1;
  }
  for (const [id, v] of entries(d.confirmed)) if (str(v)) out.confirmed[id] = v; else dropped += 1;
  for (const [id, v] of entries(d.once)) if (v === true) out.once[id] = true; else dropped += 1;
  if (plainObject(d.sweep) && (d.sweep.at === null || str(d.sweep.at))) {
    // `carry` (reclaim-city's held.js): a bare flag that this sweep held
    // something, so its going is never paid, even after a restart.
    out.sweep = { at: d.sweep.at, keys: obj(entries(d.sweep.keys).filter(([, v]) => v === true)), ...(d.sweep.carry === true ? { carry: true } : {}) };
  }
  for (const w of Array.isArray(d.sweeps) ? d.sweeps : []) {
    if (plainObject(w) && str(w.at) && SWEEP_FIELDS.every((k) => count(w[k]))) out.sweeps.push(obj([['at', w.at], ...SWEEP_FIELDS.map((k) => [k, w[k]])]));
    else dropped += 1;
  }
  out.sweeps = out.sweeps.slice(-MAX_SWEEPS);
  if (dropped) changes.push(`deck: ${dropped} dropped`);
  return out;
}

function salvageDrills(d) {
  const out = emptyDrills();
  if (!plainObject(d)) return out;
  if (count(d.right)) out.right = d.right;
  if (count(d.tried)) out.tried = Math.max(d.tried, out.right);
  for (const t of CALLS) for (const p of CALLS) if (plainObject(d.calls) && plainObject(d.calls[t]) && count(d.calls[t][p])) out.calls[t][p] = d.calls[t][p];
  if (Array.isArray(d.recent)) out.recent = d.recent.filter((x) => x === 0 || x === 1).slice(-10);
  return out;
}

function salvageConcept(r) {
  if (!plainObject(r)) return null;
  const out = {};
  const seen = (Array.isArray(r.seen) ? r.seen : []).filter((e) => Array.isArray(e) && e.length === 4 && str(e[0]) && (e[1] === 0 || e[1] === 1) && str(e[2]) && SOURCES.has(e[3]));
  if (seen.length) out.seen = seen.slice(-MAX_SEEN).map((e) => [e[0], e[1], e[2], e[3]]);
  if (str(r.self)) out.self = r.self;
  if (str(r.learnedAt)) out.learnedAt = r.learnedAt;
  if (plainObject(r.gaps) && count(r.gaps.n) && str(r.gaps.at)) out.gaps = { n: r.gaps.n, at: r.gaps.at, ...obj(GAP_KINDS.map((k) => [k, count(r.gaps[k]) ? r.gaps[k] : 0])) };
  if (plainObject(r.offered) && str(r.offered.at) && count(r.offered.declined)) out.offered = { at: r.offered.at, declined: r.offered.declined };
  return Object.keys(out).length ? out : null;
}

function salvageLessonRecord(r) {
  if (!plainObject(r)) return null;
  const out = {};
  for (const k of ['visited', 'before', 'self']) if (str(r[k])) out[k] = r[k];
  return Object.keys(out).length ? out : null;
}

// Any stored document (v1, v2, v3 from the old key, or v4 from the box) -> a
// clean v4 profile, plus a line per thing kept or dropped.
export function salvage(raw, now) {
  const changes = [];
  const p = emptyProfile(now);
  if (!plainObject(raw)) return { profile: p, changes: ['nothing readable: started fresh'] };
  p.missions = salvageMissions(raw.missions, changes);
  if (raw.version === VERSION) {
    if (str(raw.since)) p.since = raw.since;
    p.migrations = (Array.isArray(raw.migrations) ? raw.migrations : [])
      .filter((m) => plainObject(m) && count(m.v) && str(m.at) && Array.isArray(m.changes))
      .map((m) => ({ v: m.v, from: count(m.from) ? m.from : null, at: m.at, changes: m.changes.filter(str) })).slice(-MAX_MIGRATIONS);
    for (const [id, r] of entries(raw.concepts)) { const c = salvageConcept(r); if (c) p.concepts[id] = c; }
    for (const [k, r] of entries(raw.items)) if (plainObject(r) && Number.isFinite(r.b) && count(r.n)) p.items[k] = { b: r.b, n: r.n };
    for (const [id, r] of entries(raw.lessons)) { const l = salvageLessonRecord(r); if (l) p.lessons[id] = l; }
    p.drills = salvageDrills(raw.drills);
    if (plainObject(raw.rank) && count(raw.rank.points)) p.rank.points = raw.rank.points;
    if (plainObject(raw.rank) && count(raw.rank.index)) p.rank.index = Math.min(RANKS.length - 1, raw.rank.index);
    p.deck = salvageDeck(raw.deck, changes);
    return { profile: p, changes };
  }
  if (![1, 2, 3].includes(raw.version)) return { profile: p, changes: ['unknown version: started fresh'] };
  // v2 and v3: a finished lesson is kept as finished under the old rule.
  let kept = 0;
  if (raw.version >= 2) {
    for (const [id, r] of entries(raw.lessons)) {
      if (!plainObject(r) || !str(r.completedAt)) continue;
      p.lessons[id] = r.how === 'skipped' ? { self: r.completedAt } : { visited: r.completedAt, before: r.completedAt };
      kept += 1;
    }
  }
  if (raw.version === 3 && plainObject(raw.deck)) {
    const d = raw.deck;
    if (count(d.points)) p.rank.points = d.points;
    if (count(d.rank)) p.rank.index = Math.min(RANKS.length - 1, d.rank);
    p.drills = salvageDrills(d.drills);
    p.deck = salvageDeck(d, changes);
  }
  const times = [...Object.values(p.lessons).map((l) => l.visited || l.self), ...Object.values(p.missions).map((m) => m.updatedAt)].filter(str).sort();
  if (times.length) p.since = times[0];
  changes.unshift(`lessons: ${kept} kept`, `missions: ${Object.keys(p.missions).length} kept`);
  return { profile: p, changes };
}

// --- storage ---

function read(storage, key) {
  try { return storage ? storage.getItem(key) : null; } catch (_) { return null; }
}

// Never throws. A box that won't decode is moved to SPARE_KEY (once) so the
// next save can't destroy it; then the old key is read, as on a first run.
export function loadProfile(storage, now) {
  const box = read(storage, PROFILE_KEY);
  if (box) {
    const v = decode(box);
    if (plainObject(v) && v.version === VERSION) return salvage(v, now).profile;
    try { if (!read(storage, SPARE_KEY)) storage.setItem(SPARE_KEY, box); } catch (_) { /* keep going */ }
  }
  const old = read(storage, OLD_KEY);
  if (!old) return emptyProfile(now);
  let raw = null;
  try { raw = JSON.parse(old); } catch (_) { raw = null; }
  const { profile, changes } = salvage(raw, now);
  profile.migrations = [{ v: VERSION, from: plainObject(raw) && count(raw.version) ? raw.version : null, at: String(now), changes }];
  return profile;
}

// The seed the box was written with; else the install's own number
// (DisplayMode.ensureSeed, the same key and rule); else one made here under
// that key. Never null: a box can always be written.
export const SEED_KEY = 'device-rescue.city-seed';
export function profileSeed(storage, displayMode, random = Math.random) {
  const fromBox = seedOf(read(storage, PROFILE_KEY));
  if (fromBox !== null) return fromBox;
  if (displayMode && typeof displayMode.ensureSeed === 'function') {
    try { const s = displayMode.ensureSeed(storage); if (validSeed(s)) return s; } catch (_) { /* fall through */ }
  }
  const raw = read(storage, SEED_KEY);
  if (typeof raw === 'string' && /^\d+$/.test(raw) && validSeed(Number(raw))) return Number(raw);
  const seed = 1 + Math.floor(random() * 0x7ffffffe);
  try { storage.setItem(SEED_KEY, String(seed)); } catch (_) { /* this session only */ }
  return seed;
}

// Writes the box. In 'city' mode the old literal document is removed once
// the box is safely written; in 'standard' it stays, frozen, as a backup for
// an older build. Returns whether the box was written.
export function saveProfile(storage, profile, { seed, mode } = {}) {
  let text;
  try { text = encode(salvage(profile, profile && profile.since).profile, seed); } catch (_) { return false; }
  try { storage.setItem(PROFILE_KEY, text); } catch (_) { return false; }
  if (mode === 'city') { try { storage.removeItem(OLD_KEY); } catch (_) { /* nothing to remove */ } }
  return true;
}

// --- the evidence, and what it adds up to ---

const conceptRec = (p, id) => (p.concepts && p.concepts[id]) || {};
const bOf = (p, bank) => (key) => {
  const r = p.items && p.items[key];
  const it = bank.items.get(key);
  return r && Number.isFinite(r.b) ? r.b : levelB(it ? it.level : 'medium');
};

// The lessons, finished under the old rule or skipped as a lesson, that cover this concept.
function lessonFlag(p, bank, conceptId, flag) {
  return lessonsWithConcept(bank, conceptId).map((id) => p.lessons[id] && p.lessons[id][flag]).filter(str).sort()[0] || null;
}

export function conceptEstimate(p, bank, conceptId) {
  const b = bOf(p, bank);
  const responses = (conceptRec(p, conceptId).seen || [])
    .filter(([key]) => bank.items.has(key))
    .map(([key, x]) => ({ key, x, b: b(key), c: bank.items.get(key).c }));
  return estimate(responses, lessonFlag(p, bank, conceptId, 'before') ? BEFORE_PRIOR : PRIOR);
}

// learned | refresher | worth-a-look | skipped | started | not-yet
export function conceptState(p, bank, conceptId) {
  const rec = conceptRec(p, conceptId);
  const est = conceptEstimate(p, bank, conceptId);
  const before = lessonFlag(p, bank, conceptId, 'before');
  const self = rec.self || lessonFlag(p, bank, conceptId, 'self');
  if (before && est.n < MIN_RESPONSES) return 'learned';
  if (isLearned(est, !!rec.learnedAt)) return 'learned';
  if (rec.learnedAt || before) return 'refresher';
  if (self) {
    const gap = rec.gaps && rec.gaps.n > 0 && rec.gaps.at > self;
    return gap || (est.n >= 2 && est.mean < 0) ? 'worth-a-look' : 'skipped';
  }
  return est.n > 0 ? 'started' : 'not-yet';
}

const LESSON_ORDER = ['learned', 'refresher', 'worth-a-look', 'skipped', 'measuring', 'not-yet'];
// For one lesson: its state, whether the game counts it as done (learned, or
// a visit answered to the end), and the evidence to show.
export function lessonState(p, bank, lessonId) {
  const l = bank.lessons.get(lessonId);
  if (!l) return { state: 'not-yet', done: !!(p.lessons[lessonId] && p.lessons[lessonId].visited), answered: 0, right: 0, concepts: [] };
  const states = l.concepts.map((c) => conceptState(p, bank, c));
  let state;
  if (states.length && states.every((s) => s === 'learned')) state = 'learned';
  else if (states.includes('refresher')) state = 'refresher';
  else if (states.includes('worth-a-look')) state = 'worth-a-look';
  else if (states.length && states.every((s) => s === 'learned' || s === 'skipped') && states.includes('skipped')) state = 'skipped';
  else if (states.some((s) => s !== 'not-yet')) state = 'measuring';
  else state = 'not-yet';
  const mine = new Set(l.keys);
  const answers = l.concepts.flatMap((c) => (conceptRec(p, c).seen || []).filter(([key]) => mine.has(key)));
  return { state, done: state === 'learned' || !!(p.lessons[lessonId] && p.lessons[lessonId].visited),
    answered: new Set(answers.map(([key]) => key)).size, right: answers.filter(([, x]) => x === 1).length,
    concepts: l.concepts.map((c, i) => ({ id: c, state: states[i] })) };
}
export const LESSON_STATES = LESSON_ORDER;

// What the adaptive draw needs to know about each concept.
export function historyFor(p, bank) {
  const out = {};
  for (const c of bank.concepts.keys()) {
    const seen = conceptRec(p, c).seen || [];
    out[c] = { mean: conceptEstimate(p, bank, c).mean, learned: conceptState(p, bank, c) === 'learned',
      recent: seen.map(([key]) => key), seen: new Set(seen.map(([key]) => key)) };
  }
  return out;
}
export const difficultyOf = bOf;

// The family's "what to know" shows above an item until the person has got
// one item in that family right.
export function teachShown(p, bank, itemKey) {
  const it = bank.items.get(itemKey);
  if (!it || !it.teach) return false;
  return !(conceptRec(p, it.concept).seen || []).some(([key, x]) => x === 1 && bank.items.has(key) && bank.items.get(key).family === it.family);
}

// --- writes: each returns a new profile ---

function clone(p) {
  return salvage(p, p.since).profile;
}

function withEvidence(p, bank, itemKey, right, now, src) {
  const it = bank.items.get(itemKey);
  if (!it || !it.concept) return p;
  const before = conceptEstimate(p, bank, it.concept);
  const next = clone(p);
  const rec = { ...(next.concepts[it.concept] || {}) };
  rec.seen = [...(rec.seen || []), [itemKey, right ? 1 : 0, String(now), src]].slice(-MAX_SEEN);
  next.concepts[it.concept] = rec;
  const prev = next.items[itemKey] || {};
  next.items[itemKey] = updateDifficulty({ b: prev.b, n: prev.n }, right ? 1 : 0, before.mean, it.c, it.level);
  // Crossing into "learned" is remembered, so one slip later doesn't undo it.
  if (!rec.learnedAt && isLearned(conceptEstimate(next, bank, it.concept))) rec.learnedAt = String(now);
  return next;
}

// One answer to a lesson item (or a "Learn this" item). Wrong answers are kept: they are evidence too.
export function recordAnswer(p, bank, itemKey, right, now) {
  const it = bank.items.get(itemKey);
  if (!it || it.kind !== 'lesson') return p;
  return withEvidence(p, bank, itemKey, right, now, 'lesson');
}

// The last item of a visit was answered: the lesson counts as done for the
// game's flow (its district opens no quiz), whatever the estimate says.
export function recordVisit(p, lessonId, now) {
  if (!str(lessonId)) return p;
  const next = clone(p);
  next.lessons[lessonId] = { ...(next.lessons[lessonId] || {}), visited: String(now) };
  return next;
}

function addGap(p, conceptIds, kind, now) {
  const next = clone(p);
  for (const c of conceptIds) {
    if (!conceptById(c)) continue;
    const rec = { ...(next.concepts[c] || {}) };
    const g = rec.gaps || { n: 0, at: String(now), drill: 0, call: 0, reopen: 0 };
    rec.gaps = { ...g, n: g.n + 1, at: String(now), [kind]: (g[kind] || 0) + 1 };
    next.concepts[c] = rec;
  }
  return next;
}

// A drill answered in Signal or Noise or the DRILL RANGE: graded evidence on
// its concept, a cell in the calls matrix, the last-10 row, and, when wrong,
// a gap signal. Right/tried stay with the ledger (deck.drills, via withProgress).
export function recordDrillCall(p, bank, drill, picked, now) {
  if (!drill || !CALLS.includes(drill.answer) || !CALLS.includes(picked)) return p;
  const right = picked === drill.answer;
  let next = withEvidence(p, bank, `drill:${drill.id}`, right, now, 'drill');
  if (next === p) next = clone(p);
  next.drills.calls[drill.answer][picked] += 1;
  next.drills.recent = [...next.drills.recent, right ? 1 : 0].slice(-10);
  const it = bank.items.get(`drill:${drill.id}`);
  if (!right && it && it.concept) next = addGap(next, [it.concept], 'drill', now);
  return next;
}

// Which concepts a real Signal or Noise call is about. Never one from monitoring checks.
export function callConcepts(bank, module, openedKinds) {
  if (MONITORING_MODULES.has(module)) return [];
  const fromClues = [...new Set((openedKinds || []).map((k) => CLUE_CONCEPTS[k]).filter(Boolean))];
  if (fromClues.length) return fromClues;
  const out = [];
  for (const l of bank.lessons.values()) {
    if (!(l.modules || []).includes(module)) continue;
    for (const c of l.concepts) if (!out.includes(c) && !isHidden(c)) out.push(c);
  }
  return out;
}

// 'call' (Scout read a real finding differently) or 'reopen' (a "?" opened
// again; the caller counts and sends the second one in a sweep).
export function recordGap(p, conceptIds, kind, now) {
  if (!['call', 'reopen'].includes(kind) || !Array.isArray(conceptIds) || !conceptIds.length) return p;
  return addGap(p, conceptIds, kind, now);
}

// "I know this": skipped, not learned.
export function markKnown(p, conceptIds, now) {
  const next = clone(p);
  for (const c of conceptIds || []) {
    if (!conceptById(c)) continue;
    next.concepts[c] = { ...(next.concepts[c] || {}), self: String(now) };
  }
  return next;
}
export function markLessonKnown(p, lessonId, now) {
  if (!str(lessonId)) return p;
  const next = clone(p);
  next.lessons[lessonId] = { ...(next.lessons[lessonId] || {}), self: String(now) };
  return next;
}

// Offer the questions again for a skipped concept that signals say is worth a
// look: at most once per sweep, and after two "Still know it" answers only
// when a drill on it has gone wrong since.
export function shouldOffer(p, bank, conceptId, sweepAt) {
  if (isHidden(conceptId) || conceptState(p, bank, conceptId) !== 'worth-a-look') return false;
  const rec = conceptRec(p, conceptId);
  const o = rec.offered;
  if (o && sweepAt && o.at >= sweepAt) return false;
  if (o && o.declined >= 2 && !(rec.gaps && rec.gaps.drill > 0)) return false;
  return true;
}
export function noteOffered(p, conceptId, now) {
  const next = clone(p);
  const rec = { ...(next.concepts[conceptId] || {}) };
  rec.offered = { at: String(now), declined: (rec.offered && rec.offered.declined) || 0 };
  next.concepts[conceptId] = rec;
  return next;
}
// "Still know it": no more offers until new signals; the gap count starts again.
export function declineOffer(p, conceptId, now) {
  const next = clone(p);
  const rec = { ...(next.concepts[conceptId] || {}) };
  rec.offered = { at: String(now), declined: ((rec.offered && rec.offered.declined) || 0) + 1 };
  if (rec.gaps) rec.gaps = { n: 0, at: rec.gaps.at, drill: 0, call: 0, reopen: 0 };
  next.concepts[conceptId] = rec;
  return next;
}

// --- the v3 view the game's existing transforms work on ---

// { version: 3, missions, lessons, deck } as progress.js and ledger.js expect.
// lessons[id] is present when the lesson is done for the game's flow.
export function toProgress(p, bank) {
  const lessons = {};
  const ids = new Set([...Object.keys(p.lessons), ...bank.lessons.keys()]);
  for (const id of ids) {
    const s = lessonState(p, bank, id);
    if (s.done) lessons[id] = { completedAt: (p.lessons[id] && p.lessons[id].visited) || p.since };
  }
  return { version: 3, missions: { ...p.missions }, lessons,
    deck: { points: p.rank.points, rank: p.rank.index, drills: { right: p.drills.right, tried: p.drills.tried }, ...JSON.parse(JSON.stringify(p.deck)) } };
}

// Folds a v3 view (after reconcile, setStatus, setDeck, award…) back in.
// Rank never drops.
export function withProgress(p, progress) {
  const next = clone(p);
  if (!plainObject(progress)) return next;
  const changes = [];
  next.missions = salvageMissions(progress.missions, changes);
  const d = progress.deck;
  if (plainObject(d)) {
    next.deck = salvageDeck(d, changes);
    if (count(d.points)) next.rank.points = d.points;
    if (count(d.rank)) next.rank.index = Math.min(RANKS.length - 1, Math.max(next.rank.index, d.rank));
    if (plainObject(d.drills) && count(d.drills.right) && count(d.drills.tried)) { next.drills.right = d.drills.right; next.drills.tried = d.drills.tried; }
  }
  return next;
}

// --- what the profile screen and the publish sheet read ---

export function calibration(drills) {
  const c = (drills && drills.calls) || emptyCalls();
  const over = c.mine.threat + c.closer.threat;
  const under = c.threat.mine;
  const total = CALLS.reduce((a, t) => a + CALLS.reduce((b, q) => b + c[t][q], 0), 0);
  return { over, under, total };
}

export function summary(p, bank, lessonsInOrder = [...bank.lessons.keys()]) {
  const lessons = lessonsInOrder.filter((id) => bank.lessons.has(id)).map((id) => ({ id, title: bank.lessons.get(id).title, ...lessonState(p, bank, id) }));
  const concepts = CONCEPTS.filter((c) => !c.hidden && bank.concepts.has(c.id)).map((c) => {
    const est = conceptEstimate(p, bank, c.id);
    return { id: c.id, title: c.title, state: conceptState(p, bank, c.id), answers: est.n };
  });
  const stateOf = new Map(concepts.map((c) => [c.id, c.state]));
  const skills = SKILLS.map((s) => {
    const st = s.concepts.filter((c) => stateOf.has(c)).map((c) => stateOf.get(c));
    const learned = st.filter((x) => x === 'learned').length;
    const depth = st.length && learned === st.length ? 'practiced' : st.some((x) => x !== 'not-yet') ? 'introduced' : 'not-yet';
    return { id: s.id, title: s.title, depth, learned, of: st.length };
  }).filter((k) => k.of > 0);
  const r = rankOf({ points: p.rank.points, rank: p.rank.index, drills: { right: 0, tried: 0 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] });
  const missions = Object.values(p.missions);
  const last = p.deck.sweeps.length ? p.deck.sweeps[p.deck.sweeps.length - 1] : null;
  return {
    lessons, concepts, skills,
    lessonsLearned: lessons.filter((l) => l.state === 'learned').length,
    drills: { right: p.drills.right, tried: p.drills.tried, lastTen: { right: p.drills.recent.filter((x) => x === 1).length, of: p.drills.recent.length }, ...calibration(p.drills) },
    rank: { index: r.index, level: r.index + 1, of: RANKS.length, name: r.name, points: r.points, toNext: r.toNext, next: r.next ? r.next.name : null },
    city: { reclaimed: missions.filter((m) => m.status === 'reclaimed').length, later: missions.filter((m) => m.status === 'later').length,
      yours: missions.filter((m) => m.status === 'yours').length, lastSweep: last ? sweepPercent(last) : null },
    since: p.since, migrations: p.migrations,
  };
}
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-player.test.js`

Expected: PASS, 24 tests, the Review Focus ones included (newer box kept aside, refused writes, unknown item keys, capped evidence).

- [ ] **Step 5: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS. Nothing outside the profile imports it yet.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/profile/player-profile.js desktop/test/profile-player.test.js
git commit -m "Profile: one record with evidence, salvage migration from v3, derived states"
```

---

### Task 7: Item bank: whos-on-wifi

**Files:**

- Modify: `desktop/renderer/game/lessons/whos-on-wifi.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `whos-on-wifi` questions with `key`, `concept` and `variants` as in the table: 15 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `hot-and-slow` | `wifi-and-mining` | `hot-and-slow-2`: What does a hot, loud, slow computer usually turn out to be?<br>`hot-and-slow-3`: A miner was stopped, but it’s back after a restart. What do you look for next? |
| `more-devices` | `wifi-and-mining` | `more-devices-2`: There’s a device on the list you can’t name. What’s a simple way to find out what it is?<br>`more-devices-3`: Your phone doesn’t match the hardware address printed on its box. Why? |
| `full-device-list` | `wifi-and-mining` | `full-device-list-2`: Why can the checkup’s device list be incomplete?<br>`full-device-list-3`: On the router’s admin page, what might its list of connected devices be called? |
| `cut-off-order` | `cut-off-order` | `cut-off-order-2`: The person you’re worried about is an ex. Why can changing the Wi-Fi passphrase straight away be risky?<br>`cut-off-order-3`: The person you’re worried about is a stranger or a neighbour, not someone you know. What order do the steps go in? |
| `remove-everyone` | `wifi-and-mining` | `remove-everyone-2`: Before you set a new Wi-Fi passphrase, what should you do first on the router?<br>`remove-everyone-3`: You’ve set a strong new Wi-Fi passphrase. Why turn off WPS as well? |

Every new line is from `guides/home_network_intrusion/phase_0.md` (the order of steps; cutting off tells them), `phase_1.md` (recent devices only, randomised phone addresses, naming devices, the router's list names, MAC filtering), `phase_2.md` (firmware first, WPS PIN, don't restore a saved backup) and `phase_3.md` (mining is what a hot, slow machine usually is; a startup entry relaunches it). No new UI path or backticked text.

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/whos-on-wifi.js` with:

```js
export default {
  id: 'whos-on-wifi',
  title: 'Who’s on your Wi-Fi',
  recommendedFor: ['wifi'],
  modules: ['lan_device_inventory', 'arp_spoof_check', 'router_security_audit', 'wifi_security_audit', 'crypto_miner_detect', 'win_crypto_miner_detect'],
  districts: ['wires'],
  sources: [
    'guides/home_network_intrusion/phase_0.md',
    'guides/home_network_intrusion/phase_1.md',
    'guides/home_network_intrusion/phase_2.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'A slow computer, fans running all the time, a hot laptop doing nothing: these are some of the things that make people worry about their Wi-Fi.',
  whatTheScanLooksFor: 'The checkup lists devices that have recently talked to this computer, looks for signs that something is intercepting your traffic, and checks which admin services your router offers to the network. On a Mac or a Windows computer, it also looks for cryptocurrency mining running right now.',
  questions: [
    {
      key: 'hot-and-slow',
      concept: 'wifi-and-mining',
      teach: 'A hot, loud, slow computer usually turns out to be cryptocurrency mining: a program using the computer’s power to make money for someone else. On a Mac or a Windows computer, the checkup looks for mining running right now. Your network and your router are separate checks.',
      prompt: 'Your computer is hot and slow. What does the checkup do about that?',
      options: [
        { text: 'It looks for cryptocurrency mining running right now, and checks your network separately', correct: true,
          feedback: 'Right. On a Mac or a Windows computer, it looks for miner programs, mining commands and live connections to mining pools. The devices on your network and your router’s settings are separate checks.' },
        { text: 'It counts the devices on your Wi-Fi to find what’s slowing the computer down', correct: false,
          feedback: 'The device list shows what has recently talked to this computer. For a hot, slow computer, a separate check looks for mining running on the computer itself, on a Mac or a Windows computer.' },
        { text: 'It checks your router’s settings for the cause', correct: false,
          feedback: 'The router check looks at which admin services your router offers to the network, and whether UPnP is on. For a hot, slow computer, a separate check looks for mining running on the computer itself, on a Mac or a Windows computer.' },
      ],
      variants: [
        {
          key: 'hot-and-slow-2',
          prompt: 'What does a hot, loud, slow computer usually turn out to be?',
          options: [
            { text: 'Cryptocurrency mining: a program using its power to make money for someone else', correct: true,
              feedback: 'Right. Mining is what a hot, loud, slow machine usually turns out to be.' },
            { text: 'Too many devices on the Wi-Fi', correct: false,
              feedback: 'Other devices on the Wi-Fi don’t heat this computer up. Mining running on the computer itself usually does.' },
            { text: 'An old router', correct: false,
              feedback: 'The router is a separate check. A hot, loud, slow computer usually turns out to be mining running on it.' },
          ],
        },
        {
          key: 'hot-and-slow-3',
          prompt: 'A miner was stopped, but it’s back after a restart. What do you look for next?',
          options: [
            { text: 'What starts it again: a startup item, scheduled task or other startup entry', correct: true,
              feedback: 'Right. Stopping a miner achieves nothing if a startup entry launches it again, and that is the normal arrangement.' },
            { text: 'A faster computer', correct: false,
              feedback: 'Speed isn’t the problem. Something is starting the miner again, so look for the startup entry that launches it.' },
            { text: 'A new Wi-Fi passphrase', correct: false,
              feedback: 'The passphrase controls who joins the Wi-Fi. The miner comes back because a startup entry launches it again.' },
          ],
        },
      ],
    },
    {
      key: 'more-devices',
      concept: 'wifi-and-mining',
      teach: 'Phones, laptops, TVs, printers, doorbells and smart plugs all count as devices. Most households are surprised by the count, and twenty is normal now. Name each one. For anything you can’t name, unplug it or switch it off and look again. The one that disappears is that device.',
      prompt: 'The list shows more devices than you expected. What’s most likely?',
      options: [
        { text: 'Strangers have joined', correct: false,
          feedback: 'Maybe, but check first. Phones, laptops, TVs, printers, doorbells and smart plugs all count. Most households are surprised by the count, and twenty is normal now.' },
        { text: 'They’re your own things: phones, TV, printer, smart plugs', correct: true,
          feedback: 'Usually, yes. Name each one. For anything you can’t name, unplug it or switch it off and look again. The one that disappears is that device.' },
      ],
      variants: [
        {
          key: 'more-devices-2',
          prompt: 'There’s a device on the list you can’t name. What’s a simple way to find out what it is?',
          options: [
            { text: 'Unplug or switch things off one at a time and look again', correct: true,
              feedback: 'Right. The entry that disappears is that device.' },
            { text: 'Block its hardware address', correct: false,
              feedback: 'A hardware address is easy to change, so blocking one doesn’t help. Unplug or switch things off and look again; the one that disappears is that device.' },
            { text: 'Reset everything straight away', correct: false,
              feedback: 'Find out what it is first. Unplug or switch things off and look again; the one that disappears is that device.' },
          ],
        },
        {
          key: 'more-devices-3',
          prompt: 'Your phone doesn’t match the hardware address printed on its box. Why?',
          options: [
            { text: 'Modern phones use a different, randomly generated address on each network', correct: true,
              feedback: 'Right. That is privacy behaviour, not an intruder.' },
            { text: 'The phone has been swapped', correct: false,
              feedback: 'Modern phones deliberately use a different, randomly generated address on every network. That is privacy behaviour, not an intruder.' },
            { text: 'The checkup read it wrong', correct: false,
              feedback: 'It read what the phone used. Modern phones deliberately use a different, randomly generated address on every network.' },
          ],
        },
      ],
    },
    {
      key: 'full-device-list',
      concept: 'wifi-and-mining',
      teach: 'The checkup lists devices that have recently talked to this computer, so its list can be incomplete. The router’s own admin page is the full list, including devices this computer hasn’t spoken to.',
      prompt: 'Where is the full list of devices on your network?',
      options: [
        { text: 'The router’s own admin page', correct: true,
          feedback: 'Right. Compare it with the checkup’s list. Anything on the router’s list you can’t account for is the thing to focus on.' },
        { text: 'The checkup’s device list', correct: false,
          feedback: 'That list only shows devices that have recently talked to this computer. The router’s admin page is the full list.' },
      ],
      variants: [
        {
          key: 'full-device-list-2',
          prompt: 'Why can the checkup’s device list be incomplete?',
          options: [
            { text: 'It only shows devices that have recently talked to this computer', correct: true,
              feedback: 'Right. The router’s own admin page shows the devices this computer hasn’t spoken to.' },
            { text: 'It leaves out devices on purpose', correct: false,
              feedback: 'It shows what it can see: devices that have recently talked to this computer. The router’s admin page is the full list.' },
            { text: 'It only lists phones', correct: false,
              feedback: 'It lists any device that has recently talked to this computer. The router’s admin page is the full list.' },
          ],
        },
        {
          key: 'full-device-list-3',
          prompt: 'On the router’s admin page, what might its list of connected devices be called?',
          options: [
            { text: 'Attached Devices, Device List, Client List or DHCP Clients', correct: true,
              feedback: 'Right. Compare it with the checkup’s list.' },
            { text: 'Firmware Update', correct: false,
              feedback: 'That’s where the router’s own software is updated. The device list may be called Attached Devices, Device List, Client List or DHCP Clients.' },
            { text: 'Remote Management', correct: false,
              feedback: 'That setting should be off. The device list may be called Attached Devices, Device List, Client List or DHCP Clients.' },
          ],
        },
      ],
    },
    {
      key: 'cut-off-order',
      concept: 'cut-off-order',
      teach: 'If the person you’re worried about is someone you know, like a partner, an ex or a housemate, stop before you cut them off. Cutting off someone’s access tells them they’ve been found out. If they have ever frightened you, it’s worth getting help to plan the safest order.',
      prompt: 'You think a housemate who has frightened you is on your Wi-Fi. What comes first?',
      options: [
        { text: 'Get help planning the safest order before you cut them off', correct: true,
          feedback: 'Right. Cutting someone off tells them they’ve been found out, so the safe order matters more than speed.' },
        { text: 'Change the Wi-Fi passphrase straight away', correct: false,
          feedback: 'That tells them they’ve been found out. When it’s someone who has frightened you, get help planning the safest order first.' },
      ],
      variants: [
        {
          key: 'cut-off-order-2',
          prompt: 'The person you’re worried about is an ex. Why can changing the Wi-Fi passphrase straight away be risky?',
          options: [
            { text: 'Cutting off their access tells them they’ve been found out', correct: true,
              feedback: 'Right. If they have ever frightened you, get help planning the safest order first.' },
            { text: 'It isn’t risky. Always do it first.', correct: false,
              feedback: 'With someone you know, it can be. Cutting off their access tells them they’ve been found out, so plan the order first.' },
            { text: 'It deletes everyone’s files', correct: false,
              feedback: 'It doesn’t delete anything. The risk is that cutting off their access tells them they’ve been found out.' },
          ],
        },
        {
          key: 'cut-off-order-3',
          prompt: 'The person you’re worried about is a stranger or a neighbour, not someone you know. What order do the steps go in?',
          options: [
            { text: 'Reclaim the network, then clean the devices, then rebuild the accounts', correct: true,
              feedback: 'Right. Changing passwords first, on a computer that isn’t clean yet, can hand over the new ones.' },
            { text: 'Change every password first, from this computer', correct: false,
              feedback: 'Don’t change important passwords from a computer you haven’t cleaned yet. The order is the network, then the devices, then the accounts.' },
            { text: 'Clean the devices, then reconnect them and carry on', correct: false,
              feedback: 'Cleaning a laptop first and reconnecting it to a network someone else still controls means starting again. Reclaim the network first.' },
          ],
        },
      ],
    },
    {
      key: 'remove-everyone',
      concept: 'wifi-and-mining',
      teach: 'The Wi-Fi passphrase is what devices use to join. Update the router’s firmware (its built-in software) first, because if the router has a known weakness, a new passphrase doesn’t help. Turn off WPS too, or its PIN gets around the new passphrase.',
      prompt: 'What actually removes everyone you haven’t allowed onto your Wi-Fi?',
      options: [
        { text: 'A new Wi-Fi passphrase', correct: true,
          feedback: 'Right. The passphrase is what devices use to join. Update the router’s firmware first, because if the router has a known weakness, a new passphrase doesn’t help. Turn off WPS too, or its PIN gets around the new passphrase. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
        { text: 'Blocking devices by hardware address', correct: false,
          feedback: 'A hardware address is easy to change, so blocking one only tells an intruder which address to stop using. A new Wi-Fi passphrase is what works. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
        { text: 'Restarting the laptop', correct: false,
          feedback: 'That doesn’t change who can join. A new Wi-Fi passphrase does. If it’s someone you know, stop and read the safety note before you change it. Cutting someone off tells them they’ve been found out.' },
      ],
      variants: [
        {
          key: 'remove-everyone-2',
          prompt: 'Before you set a new Wi-Fi passphrase, what should you do first on the router?',
          options: [
            { text: 'Update its firmware', correct: true,
              feedback: 'Right. If the router has a known weakness, new passwords don’t help.' },
            { text: 'Turn WPS on', correct: false,
              feedback: 'WPS should be off: its PIN gets around the passphrase. Update the router’s firmware first.' },
            { text: 'Restore a saved settings backup', correct: false,
              feedback: 'A saved backup can bring back an intruder’s changes along with yours. Update the router’s firmware first.' },
          ],
        },
        {
          key: 'remove-everyone-3',
          prompt: 'You’ve set a strong new Wi-Fi passphrase. Why turn off WPS as well?',
          options: [
            { text: 'Its PIN can be broken, and it gets around the new passphrase', correct: true,
              feedback: 'Right. Leaving it on makes the strong passphrase you just set irrelevant.' },
            { text: 'WPS makes the Wi-Fi slower', correct: false,
              feedback: 'The problem is its PIN, which can be broken and gets around the passphrase.' },
            { text: 'WPS is the passphrase', correct: false,
              feedback: 'WPS lets a device join with a PIN instead of the passphrase, and that PIN can be broken. Turn it off.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/whos-on-wifi.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/whos-on-wifi.js
git commit -m "Lessons: whos-on-wifi gets item keys, a concept per question, and variants"
```

---

### Task 8: Item bank: browser-add-ons

**Files:**

- Modify: `desktop/renderer/game/lessons/browser-add-ons.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `browser-add-ons` questions with `key`, `concept` and `variants` as in the table: 12 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `permissions-fit` | `browser-add-ons` | `permissions-fit-2`: A password manager extension wants to work on every site. Is that a warning sign?<br>`permissions-fit-3`: The checkup points out an extension with a broad set of permissions. What does that mean on its own? |
| `unknown-extension` | `browser-add-ons` | `unknown-extension-2`: How might an extension you never chose have got into your browser?<br>`unknown-extension-3`: You looked up an unfamiliar extension, and its publisher doesn’t check out. What now? |
| `extensions-page` | `browser-add-ons` | `extensions-page-2`: Where do you see your add-ons in Firefox?<br>`extensions-page-3`: Where do you see your extensions in Safari? |
| `unused-extension` | `browser-add-ons` | `unused-extension-2`: You have three ad blockers installed. What does the guide suggest?<br>`unused-extension-3`: An extension is harmless, but you never use it. Why remove it? |

Every new line is from `guides/remediation/review_browser_extensions.md` ("a prompt to verify, not a verdict", password managers and ad blockers need broad access, bundled extensions, "If it doesn't check out, remove it", consolidating overlapping ad blockers, more code on every page). The only UI paths and backticks are the ones the lesson already uses: `chrome://extensions/`, `about:addons`, Safari > Settings > Extensions.

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/browser-add-ons.js` with:

```js
export default {
  id: 'browser-add-ons',
  title: 'Browser add-ons',
  recommendedFor: ['hacked', 'sketchy', 'helping'],
  modules: ['browser_extension_audit', 'chrome_extensions', 'safari_extensions'],
  districts: ['gatehouse'],
  sources: ['guides/remediation/review_browser_extensions.md'],
  briefing: 'Browser extensions (also called add-ons) run code on the pages you visit.',
  whatTheScanLooksFor: 'On a Mac, the checkup lists your extensions in Chrome, Firefox and Safari, flags names known to be harmful or adware, and points out ones asking for an unusually broad set of permissions.',
  questions: [
    {
      key: 'permissions-fit',
      concept: 'browser-add-ons',
      teach: 'Many good extensions, like ad blockers and password managers, need broad permissions to do their job. So a broad set of permissions is a prompt to look, not a verdict. What matters is whether the permissions fit what the extension is for.',
      prompt: 'Which extension’s permissions would you question?',
      options: [
        { text: 'A screenshot tool that wants to read your cookies and block web requests', correct: true,
          feedback: 'Right. A screenshot tool has no reason to need those.' },
        { text: 'A password manager that wants to work on every site', correct: false,
          feedback: 'That one’s expected. The guide names password managers as needing this kind of access.' },
        { text: 'An ad blocker that sees every page', correct: false,
          feedback: 'Also expected. The guide names ad blockers as needing this kind of access.' },
      ],
      variants: [
        {
          key: 'permissions-fit-2',
          prompt: 'A password manager extension wants to work on every site. Is that a warning sign?',
          options: [
            { text: 'No. A password manager needs that to do its job.', correct: true,
              feedback: 'Right. What matters is whether the permissions fit what the extension is for.' },
            { text: 'Yes. No extension should need every site.', correct: false,
              feedback: 'Some do. Ad blockers and password managers need that kind of access to work. What matters is whether it fits what the extension is for.' },
          ],
        },
        {
          key: 'permissions-fit-3',
          prompt: 'The checkup points out an extension with a broad set of permissions. What does that mean on its own?',
          options: [
            { text: 'It’s a prompt to look, not a verdict', correct: true,
              feedback: 'Right. Check whether the permissions fit what the extension is for, and who publishes it.' },
            { text: 'It’s harmful', correct: false,
              feedback: 'Not on its own. Many good extensions need broad permissions. It’s a prompt to look, not a verdict.' },
            { text: 'It’s fine', correct: false,
              feedback: 'Not necessarily either. It’s a prompt to look: do the permissions fit what the extension is for?' },
          ],
        },
      ],
    },
    {
      key: 'unknown-extension',
      concept: 'browser-add-ons',
      teach: 'It also matters who publishes an extension: a company or developer you recognise and trust. An extension you don’t remember installing may have come bundled with other software. Look it up by name in the browser’s extension store before deciding whether to keep it.',
      prompt: 'You find an extension you don’t remember installing. What’s a good first step?',
      options: [
        { text: 'Look it up in the extension store and check who publishes it', correct: true,
          feedback: 'Right. If it doesn’t check out, remove it. If it does, no action is needed.' },
        { text: 'Leave it. If it’s in the browser, it must be fine.', correct: false,
          feedback: 'Not always. It may have come bundled with other software. Check who publishes it first.' },
      ],
      variants: [
        {
          key: 'unknown-extension-2',
          prompt: 'How might an extension you never chose have got into your browser?',
          options: [
            { text: 'It came bundled with other software you installed', correct: true,
              feedback: 'Right. Look it up in the extension store and check who publishes it.' },
            { text: 'The checkup added it', correct: false,
              feedback: 'The checkup only looks; it never adds anything. An extension you don’t remember installing may have come bundled with other software.' },
          ],
        },
        {
          key: 'unknown-extension-3',
          prompt: 'You looked up an unfamiliar extension, and its publisher doesn’t check out. What now?',
          options: [
            { text: 'Remove it', correct: true,
              feedback: 'Right. If it doesn’t check out, remove it.' },
            { text: 'Keep it, but only use it on some sites', correct: false,
              feedback: 'An extension runs on the pages it has access to whether you use it or not. If it doesn’t check out, remove it.' },
          ],
        },
      ],
    },
    {
      key: 'extensions-page',
      concept: 'browser-add-ons',
      teach: 'Each browser has a page that lists its extensions. In Chrome it’s `chrome://extensions/`. In Firefox it’s `about:addons`. In Safari, go to Safari > Settings > Extensions.',
      prompt: 'Where do you see your extensions in Chrome?',
      options: [
        { text: '`chrome://extensions/`', correct: true,
          feedback: 'Right. Firefox uses `about:addons`. For Safari, it’s this: Safari > Settings > Extensions.' },
        { text: '`about:addons`', correct: false,
          feedback: 'That’s Firefox’s page. Chrome’s is `chrome://extensions/`.' },
        { text: 'Safari > Settings > Extensions', correct: false,
          feedback: 'That’s Safari. Chrome’s is `chrome://extensions/`.' },
      ],
      variants: [
        {
          key: 'extensions-page-2',
          prompt: 'Where do you see your add-ons in Firefox?',
          options: [
            { text: '`about:addons`', correct: true,
              feedback: 'Right. Chrome uses `chrome://extensions/`.' },
            { text: '`chrome://extensions/`', correct: false,
              feedback: 'That’s Chrome’s page. Firefox’s is `about:addons`.' },
            { text: 'Safari > Settings > Extensions', correct: false,
              feedback: 'That’s Safari. Firefox’s is `about:addons`.' },
          ],
        },
        {
          key: 'extensions-page-3',
          prompt: 'Where do you see your extensions in Safari?',
          options: [
            { text: 'Safari > Settings > Extensions', correct: true,
              feedback: 'Right. Find the extension there to uninstall it.' },
            { text: '`about:addons`', correct: false,
              feedback: 'That’s Firefox’s page. In Safari, it’s this: Safari > Settings > Extensions.' },
            { text: '`chrome://extensions/`', correct: false,
              feedback: 'That’s Chrome’s page. In Safari, it’s this: Safari > Settings > Extensions.' },
          ],
        },
      ],
    },
    {
      key: 'unused-extension',
      concept: 'browser-add-ons',
      teach: 'Every extension is more code running on every page you visit, even a harmless one. A simple test for each: have I used this in the last month?',
      prompt: 'You haven’t used an extension in the last month. What’s a good move?',
      options: [
        { text: 'Remove it. You can always reinstall it later.', correct: true,
          feedback: 'Right. Fewer extensions means less code running on every page you visit.' },
        { text: 'Keep every extension, just in case', correct: false,
          feedback: 'Each one is more code running on every page you visit. If you don’t use it, it can go.' },
      ],
      variants: [
        {
          key: 'unused-extension-2',
          prompt: 'You have three ad blockers installed. What does the guide suggest?',
          options: [
            { text: 'Keep one trusted one', correct: true,
              feedback: 'Right. Overlapping extensions are best brought down to one you trust.' },
            { text: 'Keep all three, for extra protection', correct: false,
              feedback: 'Each one is more code running on every page you visit. Keep one you trust.' },
          ],
        },
        {
          key: 'unused-extension-3',
          prompt: 'An extension is harmless, but you never use it. Why remove it?',
          options: [
            { text: 'It’s more code running on every page you visit', correct: true,
              feedback: 'Right. You can always reinstall it later if you need it.' },
            { text: 'There’s no reason to. Unused extensions do nothing.', correct: false,
              feedback: 'An installed extension still runs code on the pages you visit. If you don’t use it, it can go.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/browser-add-ons.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/browser-add-ons.js
git commit -m "Lessons: browser-add-ons gets item keys, a concept per question, and variants"
```

---

### Task 9: Item bank: poisoned-packages

**Files:**

- Modify: `desktop/renderer/game/lessons/poisoned-packages.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `poisoned-packages` questions with `key`, `concept` and `variants` as in the table: 9 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `worm-script` | `poisoned-packages` | `worm-script-2`: Why move a flagged worm file to a quarantine folder instead of deleting it?<br>`worm-script-3`: A flagged script downloads something and pipes it straight into a shell. Is it malware? |
| `worm-server` | `poisoned-packages` | `worm-server-2`: Before you stop a program that talks to a known worm server, what should you note down?<br>`worm-server-3`: A program keeps making the same connection again and again. Is that always a worm? |
| `git-hooks` | `poisoned-packages` | `git-hooks-2`: Your git hooks setting points at a folder you set up for husky. What should you do?<br>`git-hooks-3`: A hooks setting points somewhere you don’t recognise. What do the guides say to do before you unset it? |

Every new line is from `guides/remediation/clean_ai_worm_filesystem.md` (quarantine for later review; heuristic matches and legitimate install scripts), `cut_ai_worm_c2.md` (note the process and destination first; beaconing from sync clients, chat apps and package managers) and `secure_git_ssh_after_worm.md` (hook managers you set up; read hook scripts, don't run them). No backticks: the guide's own `curl | bash` is described in words.

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/poisoned-packages.js` with:

```js
export default {
  id: 'poisoned-packages',
  title: 'Poisoned packages',
  recommendedFor: ['sketchy'],
  modules: ['ai_worm_filesystem', 'ai_worm_git_ssh', 'ai_worm_persistence', 'ai_worm_network', 'ai_worm_lateral'],
  districts: ['gatehouse'],
  sources: [
    'README.md',
    'guides/remediation/clean_ai_worm_filesystem.md',
    'guides/remediation/cut_ai_worm_c2.md',
    'guides/remediation/secure_git_ssh_after_worm.md',
  ],
  briefing: 'This one is mostly for people who write code. Some “worm” attacks spread through developer tools like npm, PyPI and GitHub. If you don’t use developer tools, you can skip this lesson.',
  whatTheScanLooksFor: 'The checkup looks for files these worms are known to drop, connections to their known servers, changed git settings, and anything set to start them again.',
  questions: [
    {
      key: 'worm-script',
      concept: 'poisoned-packages',
      teach: 'These worms can drop scripts into hidden or temporary folders. If one is flagged, the guides say to read it first and never run it. Then move it to a quarantine folder (a folder set aside for it) instead of deleting it, so it can be looked at later.',
      prompt: 'The checkup flags a script a worm is known to drop. What do the guides say to do with it?',
      options: [
        { text: 'Read it first, then move it to a quarantine folder instead of deleting it', correct: true,
          feedback: 'Right. Inspect before moving anything, and quarantine rather than delete, so it can be looked at later.' },
        { text: 'Delete it straight away', correct: false,
          feedback: 'Read it first, then quarantine it rather than deleting it. What it does tells you which passwords and keys to change afterwards.' },
        { text: 'Run it to see what it does', correct: false,
          feedback: 'Never run it. Read it, don’t execute it.' },
      ],
      variants: [
        {
          key: 'worm-script-2',
          prompt: 'Why move a flagged worm file to a quarantine folder instead of deleting it?',
          options: [
            { text: 'So it can be looked at later, and what it does tells you which passwords and keys to change', correct: true,
              feedback: 'Right. Read it first, then quarantine it.' },
            { text: 'Deleting it would spread the worm', correct: false,
              feedback: 'That isn’t the reason. Quarantine keeps it for later review, and what it does tells you which passwords and keys to change.' },
            { text: 'Quarantine runs it safely', correct: false,
              feedback: 'Quarantine never runs it. It’s a folder set aside so the file can be looked at later.' },
          ],
        },
        {
          key: 'worm-script-3',
          prompt: 'A flagged script downloads something and pipes it straight into a shell. Is it malware?',
          options: [
            { text: 'Not always. Many real install scripts do that too, so read it and check whether you added it.', correct: true,
              feedback: 'Right. This kind of match isn’t confirmed. If you don’t recognise it, quarantine it rather than deleting it.' },
            { text: 'Yes. Delete it straight away.', correct: false,
              feedback: 'Many legitimate install scripts use similar patterns. Read it first, and quarantine it rather than deleting it if you don’t recognise it.' },
          ],
        },
      ],
    },
    {
      key: 'worm-server',
      concept: 'poisoned-packages',
      teach: 'Worms also talk to the attacker’s servers. The program making that connection is the real problem; the connection is only the part you happened to see.',
      prompt: 'A program is talking to a known worm server. Is blocking that address enough?',
      options: [
        { text: 'No. The program itself is the problem; the connection is only the symptom.', correct: true,
          feedback: 'Right. Stop the program and find what keeps starting it.' },
        { text: 'Yes. Block it and carry on.', correct: false,
          feedback: 'The program would still be running. The connection is only the part you happened to see.' },
      ],
      variants: [
        {
          key: 'worm-server-2',
          prompt: 'Before you stop a program that talks to a known worm server, what should you note down?',
          options: [
            { text: 'The program’s name and where it was connecting', correct: true,
              feedback: 'Right. You’ll need that to work out what else the program may have touched.' },
            { text: 'Nothing. Stop it and move on.', correct: false,
              feedback: 'Note the program’s name and where it was connecting first. You’ll need that to work out what else it may have touched.' },
          ],
        },
        {
          key: 'worm-server-3',
          prompt: 'A program keeps making the same connection again and again. Is that always a worm?',
          options: [
            { text: 'No. Sync clients, chat apps and package managers do it too.', correct: true,
              feedback: 'Right. Look up where it connects, and look at the program, before deciding.' },
            { text: 'Yes, always', correct: false,
              feedback: 'Many legitimate background services do it too, like sync clients, chat apps and package managers.' },
          ],
        },
      ],
    },
    {
      key: 'git-hooks',
      concept: 'poisoned-packages',
      teach: 'Some worms change your global git settings, so that every project you clone or create quietly picks up a malicious hook (a script git runs for you). A hook manager you set up yourself, like husky or pre-commit, uses the same settings on purpose.',
      prompt: 'Your global git settings point hooks at a folder. When is that a problem?',
      options: [
        { text: 'When it points somewhere you don’t recognise', correct: true,
          feedback: 'Right. Read what it points at first. If you set it up yourself for a hook manager, it’s fine.' },
        { text: 'Always. Remove any hook setting you find.', correct: false,
          feedback: 'Not always. A hook manager you set up yourself, like husky or pre-commit, uses it on purpose. Read what it points at first.' },
      ],
      variants: [
        {
          key: 'git-hooks-2',
          prompt: 'Your git hooks setting points at a folder you set up for husky. What should you do?',
          options: [
            { text: 'Nothing. A hook manager you set up yourself uses it on purpose.', correct: true,
              feedback: 'Right. It’s a problem only when it points somewhere you don’t recognise.' },
            { text: 'Remove it straight away', correct: false,
              feedback: 'You set it up yourself, so it’s fine. It’s a problem only when it points somewhere you don’t recognise.' },
          ],
        },
        {
          key: 'git-hooks-3',
          prompt: 'A hooks setting points somewhere you don’t recognise. What do the guides say to do before you unset it?',
          options: [
            { text: 'Read the hook scripts in that folder, without running them', correct: true,
              feedback: 'Right. What they do can tell you which passwords and keys to change.' },
            { text: 'Run them to see what they do', correct: false,
              feedback: 'Never run them. Read them first.' },
            { text: 'Nothing. Just unset it.', correct: false,
              feedback: 'Read the hook scripts first, without running them. What they do can tell you which passwords and keys to change.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/poisoned-packages.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/poisoned-packages.js
git commit -m "Lessons: poisoned-packages gets item keys, a concept per question, and variants"
```

---

### Task 10: The publish payload

**Files:**

- Create: `desktop/renderer/game/profile/publish.js`
- Test: `desktop/test/profile-publish.test.js`

**Interfaces:**

- Consumes: `skills.js` (`SKILLS`) from Task 4; in tests, `player-profile.js` (`salvage`, `recordAnswer`, `summary`) from Task 6 and `item-bank.js` from Task 5.
- Produces: `PUBLISH_READY = false`, `WORKBOOK = 'reclaim-city'`, `PUBLISH_FIELDS: {id, group, field, label, value(summary)}[]` with ids `lessons`, `drills-right`, `drills-tried`, `rank`, `skills`; `STAYS_HERE` (the line naming what can't be shared); `buildPayload(summary, tickedIds, { mode, now }) -> string | null` (an MVProfile fragment, pretty-printed; null in city mode, with nothing ticked, or with a value off the list); `publishOffered(mode, ready = PUBLISH_READY) -> boolean`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-publish.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const NOW = '2026-10-18T12:00:00.000Z';
const load = async () => {
  const [pub, pp, ib] = await Promise.all([
    import('../renderer/game/profile/publish.js'),
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
  ]);
  const bank = ib.buildBank(LESSONS, DRILLS);
  let p = pp.salvage(V3, NOW).profile;
  p = pp.recordAnswer(p, bank, 'b1', true, NOW);
  return { ...pub, summary: pp.summary(p, bank), profile: p };
};
const ALL = ['lessons', 'drills-right', 'drills-tried', 'rank', 'skills'];

test('the payload is an MVProfile fragment in its own provenance slot, with only the ticked fields', async () => {
  const { buildPayload, summary } = await load();
  const doc = JSON.parse(buildPayload(summary, ['lessons', 'rank'], { mode: 'standard', now: NOW }));
  assert.deepStrictEqual(doc, {
    security: { city_lessons_learned: { by: { 'reclaim-city': { value: 1, at: NOW, seq: 1 } } } },
    play: { city_rank_level: { by: { 'reclaim-city': { value: 3, at: NOW, seq: 2 } } } },
  });
});

test('nothing ticked, city mode, or no summary: no payload at all', async () => {
  const { buildPayload, summary } = await load();
  assert.strictEqual(buildPayload(summary, [], { mode: 'standard', now: NOW }), null);
  assert.strictEqual(buildPayload(summary, ALL, { mode: 'city', now: NOW }), null);
  assert.strictEqual(buildPayload(summary, ALL, { mode: null, now: NOW }), null);
  assert.strictEqual(buildPayload(null, ALL, { mode: 'standard', now: NOW }), null);
});

test('everything ticked still says nothing about the computer, the lessons or the answers', async () => {
  const { buildPayload, summary, profile } = await load();
  const text = buildPayload(summary, ALL, { mode: 'standard', now: NOW });
  const never = [
    ...Object.keys(profile.missions), ...Object.values(profile.missions).map((m) => m.title),
    ...Object.keys(profile.lessons), ...Object.keys(profile.concepts), 'a1', 'b1', 'launch_agent_audit', '/tmp', 'gatehouse',
    ...Object.keys(profile.deck.tags), ...Object.keys(profile.deck.confirmed), 'NETRUNNER', 'points',
  ];
  for (const s of never) assert.ok(!text.includes(s), `payload contains "${s}"`);
  const doc = JSON.parse(text);
  assert.deepStrictEqual(Object.keys(doc).sort(), ['play', 'security']);
  assert.deepStrictEqual(Object.keys(doc.security.city_skills.by['reclaim-city'].value).sort(), ['honest-results', 'reading-makers']);
});

test('a value that is not on the list refuses the whole payload', async () => {
  const { buildPayload, summary } = await load();
  assert.strictEqual(buildPayload({ ...summary, lessonsLearned: -1 }, ['lessons'], { mode: 'standard', now: NOW }), null);
  assert.strictEqual(buildPayload({ ...summary, skills: [{ id: 'made-up', depth: 'practiced' }] }, ['skills'], { mode: 'standard', now: NOW }), '{\n  "security": {\n    "city_skills": {\n      "by": {\n        "reclaim-city": {\n          "value": {},\n          "at": "2026-10-18T12:00:00.000Z",\n          "seq": 1\n        }\n      }\n    }\n  }\n}');
});

test('the control exists only in standard mode, and only once the school side is ready', async () => {
  const { publishOffered, PUBLISH_READY } = await load();
  assert.strictEqual(PUBLISH_READY, false, 'flip only after the school-repo prerequisites in the plan land');
  assert.strictEqual(publishOffered('standard'), false);
  assert.strictEqual(publishOffered('standard', true), true);
  assert.strictEqual(publishOffered('city', true), false);
  assert.strictEqual(publishOffered(null, true), false);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-publish.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/publish.js`.

- [ ] **Step 3: Write the builder**

Create `desktop/renderer/game/profile/publish.js`:

```js
// "Add to my school profile": the only thing that ever leaves, and only as a
// file the person saves or text they copy, then import themselves in The
// Multiverse School's Profile Viewer. No network call here, ever.
//
// The payload is an MVProfile fragment in the school's record shape,
// { <group>: { <field>: { by: { <workbook>: { value, at, seq } } } } }, so the
// viewer's merge import (MVSync.mergeProfiles) puts it in its own provenance
// slot without touching anything else. Allow-list only: activity counts,
// skill levels and the rank level. Never findings, paths, missions, lesson
// ids or answers, or anything about the computer.
//
// PUBLISH_READY stays false until the school repo has: the five fields in
// MVProfile's SHAPE; a merge import in the Profile Viewer (fromJSON replaces
// the whole profile today); sharing classes that enforce `never`
// (profile.contract.yml); and pair.js pointed at the real relay, not a LAN
// address. See docs/superpowers/plans/2026-10-18-player-profile-and-irt.md.
import { SKILLS } from './skills.js';

export const PUBLISH_READY = false;
export const WORKBOOK = 'reclaim-city';
const DEPTHS = new Set(['introduced', 'practiced']);
const SKILL_IDS = new Set(SKILLS.map((s) => s.id));

export const PUBLISH_FIELDS = Object.freeze([
  { id: 'lessons', group: 'security', field: 'city_lessons_learned', label: 'How many lessons you’ve learned', value: (s) => s.lessonsLearned },
  { id: 'drills-right', group: 'play', field: 'city_drills_right', label: 'Practice drills you got right', value: (s) => s.drills.right },
  { id: 'drills-tried', group: 'play', field: 'city_drills_tried', label: 'Practice drills you tried', value: (s) => s.drills.tried },
  { id: 'rank', group: 'play', field: 'city_rank_level', label: 'Your rank, as a level from 1 to 5', value: (s) => s.rank.level },
  { id: 'skills', group: 'security', field: 'city_skills', label: 'Your skill levels', value: (s) => skillLevels(s) },
]);
export const STAYS_HERE = 'Your checkup results, your missions and anything about this computer stay here.';

// Only skills the person has started, as { id: 'introduced' | 'practiced' }.
function skillLevels(summary) {
  return Object.fromEntries((summary.skills || []).filter((k) => SKILL_IDS.has(k.id) && DEPTHS.has(k.depth)).map((k) => [k.id, k.depth]));
}

function validValue(id, v) {
  if (id === 'skills') return !!v && typeof v === 'object' && !Array.isArray(v)
    && Object.entries(v).every(([k, d]) => SKILL_IDS.has(k) && DEPTHS.has(d));
  return Number.isInteger(v) && v >= 0;
}

// The exact text that would leave, for the ticked field ids, or null: in city
// mode, with nothing ticked, or with anything that isn't on the list.
export function buildPayload(summary, ticked, { mode, now }) {
  if (mode !== 'standard' || !summary) return null;
  const want = new Set(Array.isArray(ticked) ? ticked : []);
  const out = {};
  let seq = 0;
  for (const f of PUBLISH_FIELDS) {
    if (!want.has(f.id)) continue;
    const value = f.value(summary);
    if (!validValue(f.id, value)) return null;
    seq += 1;
    out[f.group] = out[f.group] || {};
    out[f.group][f.field] = { by: { [WORKBOOK]: { value, at: String(now), seq } } };
  }
  return seq ? JSON.stringify(out, null, 2) : null;
}

// Whether the "Add to my school profile" control exists at all.
export function publishOffered(mode, ready = PUBLISH_READY) {
  return ready === true && mode === 'standard';
}
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-publish.test.js`

Expected: PASS, 5 tests. ("a value that is not on the list…": a negative count refuses the whole payload; an unknown skill id is dropped from `city_skills`, which is then `{}`.)

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/profile/publish.js desktop/test/profile-publish.test.js
git commit -m "Profile: the MVProfile fragment builder, allow-list only, off until the school side is ready"
```

---

### Task 11: The profile screen views

**Files:**

- Create: `desktop/renderer/game/views/profile.js`
- Test: `desktop/test/profile-views.test.js`

**Interfaces:**

- Consumes: `summary(...)` output from Task 6; `PUBLISH_FIELDS`, `STAYS_HERE`, `buildPayload` from Task 10; `esc` from `desktop/renderer/game/escape.js`.
- Produces: `START_OVER` (the confirmation sentence); `renderProfile({ summary, theme: 'game'|'plain', publish: boolean, confirming: boolean }) -> string` (section labelled by `#profile-title`; game rows carry `data-go="lesson:<id>"`; acts `profile-publish`, `profile-start-over`, `profile-start-over-yes`, `profile-start-over-no`, `profile-close`); `renderPublishSheet({ summary, ticked: id[], payload: string | null, theme }) -> string` (checkboxes `id="pub-<id>" data-act="pub-toggle:<id>"`, acts `publish-save`, `publish-copy`, `publish-close`).

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-views.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const NOW = '2026-10-18T12:00:00.000Z';
const TIME_WORDS = /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i;
const load = async () => {
  const [views, pp, ib, pub] = await Promise.all([
    import('../renderer/game/views/profile.js'),
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
    import('../renderer/game/profile/publish.js'),
  ]);
  const bank = ib.buildBank(LESSONS, DRILLS);
  let p = pp.salvage(V3, NOW).profile;
  p = pp.recordAnswer(p, bank, 'b1', true, NOW);
  p = pp.markKnown(p, ['where-it-lives'], NOW);
  for (let i = 0; i < 3; i += 1) p = pp.recordDrillCall(p, bank, DRILLS[1], 'threat', `${NOW}${i}`);
  return { ...views, pub, summary: pp.summary(p, bank) };
};

test('both themes show rank, lessons, skills, drills and city counts, with a heading the section is named by', async () => {
  const { renderProfile, summary } = await load();
  for (const theme of ['game', 'plain']) {
    const html = renderProfile({ summary, theme });
    assert.match(html, /aria-labelledby="profile-title"/);
    assert.match(html, /<h2 id="profile-title">/);
    assert.ok(html.includes('Lesson A') && html.includes('Lesson B'));
    assert.ok(html.includes('Honest results'));
    assert.match(html, /<span>[^<]+ \(step [123] of 3\)<\/span>/, 'the meter has a text equivalent');
    assert.ok(!html.includes('Developer packages'), 'a skill with nothing to measure in this bank is left out');
    assert.ok(html.includes('1 set aside for later'));
    assert.doesNotMatch(html, TIME_WORDS);
  }
  assert.ok(renderProfile({ summary, theme: 'plain' }).includes('Points: 340 (level 3 of 5)'));
  assert.ok(renderProfile({ summary, theme: 'game' }).includes('NETRUNNER'));
});

test('calibration is said kindly, and only with enough calls behind it', async () => {
  const { renderProfile, summary } = await load();
  assert.ok(renderProfile({ summary }).includes('You flag things as threats more often than they are (3 times).'));
  const few = { ...summary, drills: { ...summary.drills, total: 2, over: 2, under: 0 } };
  assert.ok(!renderProfile({ summary: few }).includes('more often than they are'));
});

test('game rows open their lesson; plain rows have no button (no lesson host there yet)', async () => {
  const { renderProfile, summary } = await load();
  assert.match(renderProfile({ summary, theme: 'game' }), /data-go="lesson:lesson-a"/);
  assert.doesNotMatch(renderProfile({ summary, theme: 'plain' }), /data-go="lesson:/);
});

test('the publish control is absent unless offered', async () => {
  const { renderProfile, summary } = await load();
  assert.doesNotMatch(renderProfile({ summary }), /profile-publish/);
  assert.match(renderProfile({ summary, publish: true }), /data-act="profile-publish"/);
});

test('titles are escaped', async () => {
  const { renderProfile, summary } = await load();
  const evil = { ...summary, lessons: [{ ...summary.lessons[0], title: '<img src=x onerror=alert(1)>' }] };
  assert.ok(!renderProfile({ summary: evil }).includes('<img src=x'));
});

test('the consent sheet: every box unticked to start, the exact payload previewed, nothing to save until one is ticked', async () => {
  const { renderPublishSheet, summary, pub } = await load();
  const empty = renderPublishSheet({ summary });
  assert.doesNotMatch(empty, /checked/);
  assert.match(empty, /data-act="publish-save" disabled/);
  assert.ok(empty.includes(pub.STAYS_HERE));
  assert.strictEqual((empty.match(/type="checkbox"/g) || []).length, pub.PUBLISH_FIELDS.length);
  assert.strictEqual((empty.match(/<label for="pub-/g) || []).length, pub.PUBLISH_FIELDS.length, 'every box has a label');
  const payload = pub.buildPayload(summary, ['lessons'], { mode: 'standard', now: NOW });
  const one = renderPublishSheet({ summary, ticked: ['lessons'], payload });
  assert.match(one, /id="pub-lessons" data-act="pub-toggle:lessons" checked/);
  assert.ok(one.includes('city_lessons_learned'));
  assert.doesNotMatch(one, /data-act="publish-save" disabled/);
});

test('Start over asks first, and says nothing on the computer changes', async () => {
  const { renderProfile, summary, START_OVER } = await load();
  assert.doesNotMatch(renderProfile({ summary }), /profile-start-over-yes/);
  const html = renderProfile({ summary, confirming: true });
  assert.ok(html.includes(START_OVER));
  assert.match(html, /role="alertdialog"/);
  assert.match(html, /data-act="profile-start-over-yes"/);
  assert.match(html, /data-act="profile-start-over-no"/);
});

test('the consent sheet speaks plain view’s words in plain view', async () => {
  const { renderPublishSheet, summary } = await load();
  assert.ok(renderPublishSheet({ summary, theme: 'plain' }).includes('>Save a file<'));
  assert.ok(renderPublishSheet({ summary }).includes('>SAVE A FILE<'));
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-views.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/views/profile.js`.

- [ ] **Step 3: Write the views**

Create `desktop/renderer/game/views/profile.js`:

```js
// The profile screen: YOUR FILE in game style, "Your progress" in plain view.
// Same content, two sets of words. Pure: takes PlayerProfile.summary(…) and
// returns HTML. Counts only for the city: never a finding's name.
import { esc } from '../escape.js';
import { PUBLISH_FIELDS, STAYS_HERE } from '../profile/publish.js';

const WORDS = {
  game: {
    title: 'YOUR FILE', rank: 'RANK', training: 'TRAINING', skills: 'SKILLS', drills: 'DRILLS', city: 'CITY',
    history: 'DATA HISTORY', startOver: 'START OVER', publish: 'ADD TO MY SCHOOL PROFILE', back: 'BACK TO THE DECK',
    stamp: { learned: 'LEARNED', measuring: 'IN PROGRESS', skipped: 'YOU KNEW THIS', 'worth-a-look': 'YOU KNEW THIS', refresher: 'REFRESHER', 'not-yet': 'NOT YET' },
    depth: { 'not-yet': 'NOT YET', introduced: 'INTRODUCED', practiced: 'PRACTICED' },
  },
  plain: {
    title: 'Your progress', rank: 'Points', training: 'Lessons', skills: 'Skills', drills: 'Practice drills', city: 'Your checkups',
    history: 'Data history', startOver: 'Start over', publish: 'Add to my school profile', back: 'Close',
    stamp: { learned: 'Learned', measuring: 'In progress', skipped: 'You said you know this', 'worth-a-look': 'You said you know this', refresher: 'Worth a refresher', 'not-yet': 'Not started' },
    depth: { 'not-yet': 'Not yet', introduced: 'Introduced', practiced: 'Practiced' },
  },
};
const STEP = { 'not-yet': 1, introduced: 2, practiced: 3 };

function lessonNote(l) {
  const n = l.answered;
  const answered = n ? `${n} answered, ${l.right} right` : '';
  if (l.state === 'learned') return answered;
  if (l.state === 'measuring') return `${answered}. A few more questions will show whether it’s learned.`;
  if (l.state === 'worth-a-look') return 'A drill suggests a refresher.';
  if (l.state === 'refresher') return `${answered}. Some recent answers missed, so a refresher could help.`;
  return '';
}

// Game rows get the button that opens the lesson; plain view has no lesson host yet.
function lessonAction(l, theme) {
  if (theme !== 'game') return '';
  const label = { learned: 'REVIEW ONE', measuring: 'CONTINUE', skipped: 'TAKE IT', 'worth-a-look': '2 QUESTIONS', refresher: '2 QUESTIONS', 'not-yet': 'START' }[l.state] || 'START';
  return `<button type="button" class="btn-s" data-go="lesson:${esc(l.id)}" aria-label="${esc(label.toLowerCase())}: ${esc(l.title)}">${esc(label)} ▶</button>`;
}

function rankHtml(s, w, theme) {
  const r = s.rank;
  if (theme === 'game') {
    return `<p class="rank-name"><b>${esc(r.name)}</b> <small>${esc(r.points)} POINTS</small></p>
      <p class="intel">${r.next ? `${esc(r.toNext)} to ${esc(r.next)}.` : 'Top rank.'} Rank never drops.</p>`;
  }
  return `<p>${esc(w.rank)}: ${esc(r.points)} (level ${esc(r.level)} of ${esc(r.of)})</p>`;
}

function drillsHtml(d) {
  if (!d.tried) return '<p>No practice drills yet.</p>';
  const lines = [`<p>${esc(d.right)} of ${esc(d.tried)} right${d.lastTen.of ? ` · last ${esc(d.lastTen.of)}: ${esc(d.lastTen.right)} right` : ''}</p>`];
  if (d.total >= 3 && d.over >= 2 && d.over > d.under) lines.push(`<p>You flag things as threats more often than they are (${esc(d.over)} times).</p>`);
  else if (d.total >= 3 && d.under >= 2 && d.under >= d.over) lines.push(`<p>A few threats got past you as “mine” (${esc(d.under)}).</p>`);
  if (!d.total) lines.push('<p>Which way your calls lean is counted from now on.</p>');
  return lines.join('');
}

function historyHtml(s, w) {
  const rows = (s.migrations || []).map((m) => `<li>Moved to this version${m.from ? ` from version ${esc(m.from)}` : ''}: ${esc((m.changes || []).join('; '))}</li>`).join('');
  return `<details><summary>${esc(w.history)}</summary>${rows ? `<ul>${rows}</ul>` : '<p>Nothing has been moved or changed.</p>'}</details>`;
}

export const START_OVER = 'Start over? This clears your lessons, drills, rank and missions here. Nothing on your computer changes.';

// `publish`: whether the "Add to my school profile" control exists (publishOffered).
// `confirming`: the person pressed Start over and is being asked to be sure.
export function renderProfile({ summary: s, theme = 'game', publish = false, confirming = false }) {
  const w = WORDS[theme === 'plain' ? 'plain' : 'game'];
  const lessons = s.lessons.map((l) => `
      <li class="profile-lesson ${esc(l.state)}"><span class="stamp">${esc(w.stamp[l.state] || w.stamp['not-yet'])}</span>
        <b>${esc(l.title)}</b>${lessonNote(l) ? `<small>${esc(lessonNote(l))}</small>` : ''}${lessonAction(l, theme)}</li>`).join('');
  const skills = s.skills.map((k) => `
      <li><b>${esc(k.title)}</b> <span class="meter" aria-hidden="true">${[1, 2, 3].map((i) => `<i class="${i <= STEP[k.depth] ? 'on' : ''}"></i>`).join('')}</span>
        <span>${esc(w.depth[k.depth])} (step ${esc(STEP[k.depth])} of 3)</span></li>`).join('');
  const c = s.city;
  return `
  <section class="profile ${theme === 'plain' ? 'profile-plain' : 'profile-game'}" aria-labelledby="profile-title">
    <h2 id="profile-title">${esc(w.title)}</h2>
    <div class="panel"><h3 class="label">${esc(w.rank)}</h3>${rankHtml(s, w, theme)}</div>
    <div class="panel"><h3 class="label">${esc(w.training)}</h3><ul class="profile-lessons">${lessons}</ul></div>
    <div class="panel"><h3 class="label">${esc(w.skills)}</h3><ul class="profile-skills">${skills}</ul></div>
    <div class="panel"><h3 class="label">${esc(w.drills)}</h3>${drillsHtml(s.drills)}</div>
    <div class="panel"><h3 class="label">${esc(w.city)}</h3>
      <p>${esc(c.reclaimed)} fixed and confirmed · ${esc(c.later)} set aside for later · ${esc(c.yours)} marked as yours${c.lastSweep === null ? '' : ` · last checkup ${esc(c.lastSweep)}% secured`}</p></div>
    ${confirming ? `<div class="panel" role="alertdialog" aria-labelledby="start-over-q"><p id="start-over-q">${esc(START_OVER)}</p>
      <div class="row"><button type="button" class="btn-s" data-act="profile-start-over-yes">${esc(theme === 'plain' ? 'Yes, start over' : 'YES, START OVER')}</button>
        <button type="button" class="btn-t" data-act="profile-start-over-no">${esc(theme === 'plain' ? 'Keep my progress' : 'KEEP MY PROGRESS')}</button></div></div>` : ''}
    <footer class="row">${historyHtml(s, w)}
      ${publish ? `<button type="button" class="btn-s" data-act="profile-publish">${esc(w.publish)}</button>` : ''}
      <button type="button" class="btn-t" data-act="profile-start-over">${esc(w.startOver)}</button>
      <button type="button" class="btn-t" data-act="profile-close">${esc(w.back)}</button></footer>
  </section>`;
}

// The consent sheet. Every box starts unticked; the preview is the exact text
// that would leave. `payload`: buildPayload(…) for the ticked boxes, or null.
export function renderPublishSheet({ summary: s, ticked = [], payload = null, theme = 'game' }) {
  const plain = theme === 'plain';
  const want = new Set(ticked);
  const shown = (f) => (f.id === 'skills'
    ? s.skills.filter((k) => k.depth !== 'not-yet').map((k) => `${k.title}: ${k.depth}`).join(', ') || 'none started yet'
    : String(f.value(s)));
  const boxes = PUBLISH_FIELDS.map((f) => `
      <li><input type="checkbox" id="pub-${esc(f.id)}" data-act="pub-toggle:${esc(f.id)}"${want.has(f.id) ? ' checked' : ''}>
        <label for="pub-${esc(f.id)}">${esc(f.label)}: <b>${esc(shown(f))}</b></label></li>`).join('');
  return `
  <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="pub-title">
    <h2 id="pub-title">Add to my school profile</h2>
    <p>Tick what you want to add. Nothing is sent: you save a file or copy the text, and add it in the school’s Profile Viewer yourself.</p>
    <p><strong>${esc(STAYS_HERE)}</strong></p>
    <fieldset><legend>What to add</legend><ul class="pub-fields">${boxes}</ul></fieldset>
    <h3>Exactly what would leave</h3>
    <pre class="pub-preview" aria-live="polite">${payload ? esc(payload) : 'Nothing ticked yet.'}</pre>
    <div class="row">
      <button type="button" class="btn-p" data-act="publish-save"${payload ? '' : ' disabled'}>${plain ? 'Save a file' : 'SAVE A FILE'}</button>
      <button type="button" class="btn-s" data-act="publish-copy"${payload ? '' : ' disabled'}>${plain ? 'Copy' : 'COPY'}</button>
      <button type="button" class="btn-t" data-act="publish-close">${plain ? 'Close' : 'CLOSE'}</button></div>
  </div>`;
}
```

- [ ] **Step 4: Run the test and make sure it passes**

Run: `cd desktop && node --test test/profile-views.test.js`

Expected: PASS, 8 tests (both themes, calibration lines, escaping, Start over, unticked boxes with labels, plain words in plain view).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/views/profile.js desktop/test/profile-views.test.js
git commit -m "Profile: YOUR FILE and Your progress views, and the consent sheet"
```

---

### Task 12: Item bank: password-asker (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/lessons/password-asker.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `password-asker` questions with `key`, `concept` and `variants` as in the table: 6 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

**After reclaim-city lands.** This file is one reclaim-city renamed (Device Rescue → Reclaim City); the text below is written against that version. Check first: `git diff reclaim-city -- desktop/renderer/game/lessons/password-asker.js` must show only the additions below (keys, concepts, variants).

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `scam-popup` | `remote-access-scams` | `scam-popup-2`: Someone phones, says they’re from tech support, and asks you to install a program so they can fix your computer. What should you do?<br>`scam-popup-3`: The checkup finds two different remote-access tools on a Windows computer, and nobody knows why either is there. What does that pattern often mean? |
| `fake-prompt` | `password-prompts` | `fake-prompt-2`: During the checkup, a window from macOS itself asks for your Mac’s administrator password. What is that?<br>`fake-prompt-3`: Which of these will Reclaim City ask you to type into it? |

New lines come from `guides/remediation/review_windows_remote_access.md` ("Legitimate support … does not cold-call you", several tools together as the scam's hallmark), `desktop/renderer/permissions-content.json` (macOS's own administrator prompt, in its own window) and `docs/trust-and-safety.md` (no prompt for an account password, a one-time code, a recovery code, a seed phrase or a password-manager master password).

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/password-asker.js` with:

```js
export default {
  id: 'password-asker',
  title: 'The tool that asks for your password',
  recommendedFor: ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'],
  modules: ['win_remote_access_audit'],
  districts: ['gatehouse'],
  sources: [
    'docs/trust-and-safety.md',
    'desktop/renderer/permissions-content.json',
    'guides/remediation/review_windows_remote_access.md',
    'guides/home_network_intrusion/phase_3.md',
  ],
  briefing: 'Reclaim City never asks for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password. There is no prompt for any of them anywhere in the tool.',
  whatTheScanLooksFor: 'On Windows, the checkup looks for remote-access tools like TeamViewer, AnyDesk and VNC, which are common leftovers from “tech support” phone scams.',
  questions: [
    {
      key: 'scam-popup',
      concept: 'remote-access-scams',
      teach: 'Be wary of an unexpected call or pop-up telling you to install remote-access software (a tool that lets someone else control your computer). Scammers use that to take over your screen.',
      prompt: 'A pop-up claims a virus was found and gives you a number to call for help. What should you do?',
      options: [
        { text: 'Call the number so they can fix it', correct: false,
          feedback: 'That’s how the scam starts. The caller may walk you through installing remote-access software, which gives them access to your computer.' },
        { text: 'Don’t call. Close it, and run a checkup you started yourself.', correct: true,
          feedback: 'Right. A checkup you started yourself doesn’t come from a stranger, and Reclaim City never asks for your passwords or codes.' },
        { text: 'Read them the code your phone just got, to prove it’s you', correct: false,
          feedback: 'Never read a code to anyone who contacted you. Reclaim City never asks for a one-time code.' },
      ],
      variants: [
        {
          key: 'scam-popup-2',
          prompt: 'Someone phones, says they’re from tech support, and asks you to install a program so they can fix your computer. What should you do?',
          options: [
            { text: 'Hang up', correct: true,
              feedback: 'Right. Legitimate support (your bank, Microsoft, your ISP) does not cold-call you asking you to install remote-access software.' },
            { text: 'Install it, because they sound official', correct: false,
              feedback: 'Sounding official is part of the scam. Legitimate support does not cold-call you asking you to install remote-access software.' },
            { text: 'Install it, then uninstall it when they hang up', correct: false,
              feedback: 'Once it’s in, they can control your screen, and scammers often add another tool to keep access. Hang up instead.' },
          ],
        },
        {
          key: 'scam-popup-3',
          prompt: 'The checkup finds two different remote-access tools on a Windows computer, and nobody knows why either is there. What does that pattern often mean?',
          options: [
            { text: 'A tech-support scam: another tool keeps access if the first is removed', correct: true,
              feedback: 'Right. Several remote-access tools installed together is a well-known sign of a tech-support scam. Check each one with anyone else who uses the computer.' },
            { text: 'Nothing. Windows comes with several of them.', correct: false,
              feedback: 'These are separate programs someone installed. Two or more together is a well-known sign of a tech-support scam.' },
            { text: 'The Wi-Fi is too slow for one tool', correct: false,
              feedback: 'Speed isn’t the reason. A scammer layers on more tools to keep access even if the first is removed.' },
          ],
        },
      ],
    },
    {
      key: 'fake-prompt',
      concept: 'password-prompts',
      teach: 'Your computer may ask for its own administrator password, in its own window. Reclaim City never sees what you type there, and it never asks you to type a password into it. If something claiming to be Reclaim City asks you to type a password into it, it is not Reclaim City.',
      prompt: 'A box that says it’s from Reclaim City asks for your email password to “finish the scan”. What is it?',
      options: [
        { text: 'A normal part of the checkup', correct: false,
          feedback: 'Reclaim City has no prompt like that anywhere. Its checks never need your email password.' },
        { text: 'Something pretending to be Reclaim City. Don’t type anything, and close it.', correct: true,
          feedback: 'Right. Your computer may ask for its own administrator password in its own window, but Reclaim City never asks you to type a password into it.' },
      ],
      variants: [
        {
          key: 'fake-prompt-2',
          prompt: 'During the checkup, a window from macOS itself asks for your Mac’s administrator password. What is that?',
          options: [
            { text: 'Your Mac asking, in its own window. Reclaim City never sees what you type there.', correct: true,
              feedback: 'Right. Some checks or fixes need it, and macOS asks for it in its own window.' },
            { text: 'Reclaim City asking for your email password', correct: false,
              feedback: 'Reclaim City never asks for your email password. This is macOS asking for its own administrator password, in its own window.' },
            { text: 'A sign the checkup has gone wrong', correct: false,
              feedback: 'It’s expected for some checks or fixes. macOS asks, in its own window, and Reclaim City never sees what you type.' },
          ],
        },
        {
          key: 'fake-prompt-3',
          prompt: 'Which of these will Reclaim City ask you to type into it?',
          options: [
            { text: 'None of them', correct: true,
              feedback: 'Right. There is no prompt in the tool for an account password, a one-time code, a recovery code, a seed phrase, or a password-manager master password.' },
            { text: 'A one-time code from your phone', correct: false,
              feedback: 'Never. There is no prompt in the tool for a one-time code.' },
            { text: 'Your password-manager master password', correct: false,
              feedback: 'Never. There is no prompt in the tool for a password-manager master password.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/password-asker.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/password-asker.js
git commit -m "Lessons: password-asker gets item keys, a concept per question, and variants"
```

---

### Task 13: Item bank: starts-on-its-own (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/lessons/starts-on-its-own.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `starts-on-its-own` questions with `key`, `concept` and `variants` as in the table: 9 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

**After reclaim-city lands.** This file is one reclaim-city renamed (Device Rescue → Reclaim City); the text below is written against that version. Check first: `git diff reclaim-city -- desktop/renderer/game/lessons/starts-on-its-own.js` must show only the additions below (keys, concepts, variants).

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `startup-warning-sign` | `where-it-lives` | `startup-warning-sign-2`: On Windows, a startup entry runs a program from the Downloads folder. Why is that worth a closer look?<br>`startup-warning-sign-3`: On a Mac, which of these places would worry you most for a program that starts every time you log in? |
| `signed-maker` | `who-made-it` | `signed-maker-2`: A finding says a program is “not signed”. What does that tell you on its own?<br>`signed-maker-3`: A program you never chose has a real, verified signature from a company. Did you want it? |
| `unknown-item-first-move` | `fix-and-undo` | `unknown-item-first-move-2`: On a Mac, what does Reclaim City’s “Fix it for me” do with a flagged background job?<br>`unknown-item-first-move-3`: Why move a background item’s file aside instead of deleting it? |

New lines come from `guides/remediation/audit_windows_autoruns.md` (Program Files versus Temp or Downloads), `review_launch_persistence.md` (`/tmp`, `/var/tmp` or a hidden folder; quarantine rather than delete), `desktop/renderer/app.js` ("not proof of anything bad, but nobody has vouched for it"; "part of macOS") and `rescue/app_fixes.json` ("moves its settings file to … quarantine folder. Nothing is deleted.").

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/starts-on-its-own.js` with:

```js
export default {
  id: 'starts-on-its-own',
  title: 'Things that start on their own',
  recommendedFor: ['hacked', 'sketchy', 'helping', 'unsure'],
  modules: ['launch_agent_audit', 'launchd_persistence_audit', 'win_autoruns_audit'],
  districts: ['gatehouse'],
  sources: [
    'guides/remediation/review_launch_persistence.md',
    'guides/remediation/audit_windows_autoruns.md',
    'rescue/app_fixes.json',
    'desktop/renderer/app.js',
    'desktop/renderer/fix-flow.js',
  ],
  briefing: 'Some programs set themselves up to start every time you log in. On a Mac these include launch agents. On Windows they sit in Run keys and the Startup folders.',
  whatTheScanLooksFor: 'On a Mac, the checkup lists background items that aren’t part of macOS, and flags ones that run from /tmp, /var/tmp or a hidden folder. On Windows, it lists every startup entry, and flags ones that run from a Temp or Downloads folder.',
  questions: [
    {
      key: 'startup-warning-sign',
      concept: 'where-it-lives',
      teach: 'Lots of ordinary apps do this, like sync clients and VPN helpers. Unwanted software does it too, so it keeps coming back. One strong warning sign is a program that runs from a temporary or hidden folder. Installed software normally runs from its own install folder, like Program Files on Windows.',
      prompt: 'Which of these is a warning sign in something that starts on its own?',
      options: [
        { text: 'It’s made by a company you know, with a verified signature', correct: false,
          feedback: 'That’s the less worrying case. A verified signature tells you who made it, not that you wanted it.' },
        { text: 'It runs a program from a hidden folder or a temporary folder', correct: true,
          feedback: 'Right. On Windows, installed software runs from Program Files or its own install folder, not a temporary or download folder. On a Mac, a program in a temporary or hidden folder is one of the strongest warning signs the checkup looks for.' },
        { text: 'It’s a sync app you use all the time', correct: false,
          feedback: 'Sync clients and VPN helpers start on their own on purpose. That’s a normal pattern.' },
      ],
      variants: [
        {
          key: 'startup-warning-sign-2',
          prompt: 'On Windows, a startup entry runs a program from the Downloads folder. Why is that worth a closer look?',
          options: [
            { text: 'Installed software runs from Program Files or its own install folder, not a download folder', correct: true,
              feedback: 'Right. A startup entry pointing at Temp or Downloads is a strong warning sign.' },
            { text: 'Downloads is where Windows keeps its own startup programs', correct: false,
              feedback: 'It isn’t. Installed software runs from Program Files or its own install folder, so a startup entry in Downloads is a strong warning sign.' },
            { text: 'It isn’t. Most startup programs run from Downloads.', correct: false,
              feedback: 'Installed software runs from Program Files or its own install folder. A startup entry in Downloads is a strong warning sign.' },
          ],
        },
        {
          key: 'startup-warning-sign-3',
          prompt: 'On a Mac, which of these places would worry you most for a program that starts every time you log in?',
          options: [
            { text: '/tmp, a temporary folder', correct: true,
              feedback: 'Right. A program in /tmp, /var/tmp or a hidden folder is one of the strongest warning signs the checkup looks for.' },
            { text: '/Applications, where Mac apps are installed', correct: false,
              feedback: 'That’s where installed apps normally live. A temporary or hidden folder is the stronger warning sign.' },
          ],
        },
      ],
    },
    {
      key: 'signed-maker',
      concept: 'who-made-it',
      teach: 'When a finding names a program, Reclaim City says who made it and whether that could be checked: for example a “verified signature”, or “not signed”. A verified signature tells you who made it, not that you wanted it.',
      prompt: 'A finding says a program has a “verified signature”. What does that tell you?',
      options: [
        { text: 'Who made it', correct: true,
          feedback: 'Right. It tells you who made it. Whether you want it running is still your call.' },
        { text: 'That you installed it and want it', correct: false,
          feedback: 'A signature can’t tell that. It tells you who made it, not that you wanted it.' },
      ],
      variants: [
        {
          key: 'signed-maker-2',
          prompt: 'A finding says a program is “not signed”. What does that tell you on its own?',
          options: [
            { text: 'Nobody has vouched for who made it, so look at where it lives too', correct: true,
              feedback: 'Right. It is not proof of anything bad, but nobody has vouched for it.' },
            { text: 'It’s harmful', correct: false,
              feedback: 'Not on its own. It is not proof of anything bad, but nobody has vouched for it, so look at where it lives too.' },
            { text: 'It comes with macOS', correct: false,
              feedback: 'Files that come with macOS are shown as part of macOS. “Not signed” means nobody has vouched for who made it.' },
          ],
        },
        {
          key: 'signed-maker-3',
          prompt: 'A program you never chose has a real, verified signature from a company. Did you want it?',
          options: [
            { text: 'Not necessarily. The signature says who made it, not that you wanted it.', correct: true,
              feedback: 'Right. Whether you want it running is still your call.' },
            { text: 'Yes. A signed program is one you installed.', correct: false,
              feedback: 'A signature can’t tell that. It tells you who made it, not that you wanted it.' },
          ],
        },
      ],
    },
    {
      key: 'unknown-item-first-move',
      concept: 'fix-and-undo',
      teach: 'If you don’t recognise one, look before you remove anything. Switching it off and moving its file aside, rather than deleting it, means it can be looked at again or put back.',
      prompt: 'You don’t recognise a background item. What’s the safest first move?',
      options: [
        { text: 'Delete it straight away', correct: false,
          feedback: 'Look before you remove anything, and move it aside rather than deleting it, so it can be looked at again or put back.' },
        { text: 'Check who made it, then switch it off in a way you can undo', correct: true,
          feedback: 'Right. On a Mac, for a flagged background job, Reclaim City’s “Fix it for me” stops the job and moves its settings file to a quarantine folder. Nothing is deleted, and you can undo it.' },
        { text: 'Leave it. Everything on a computer starts on its own.', correct: false,
          feedback: 'Some things do, on purpose. It’s still worth knowing what each one is, because unwanted software uses the same trick.' },
      ],
      variants: [
        {
          key: 'unknown-item-first-move-2',
          prompt: 'On a Mac, what does Reclaim City’s “Fix it for me” do with a flagged background job?',
          options: [
            { text: 'Stops the job and moves its settings file to a quarantine folder', correct: true,
              feedback: 'Right. Nothing is deleted, and you can undo it.' },
            { text: 'Deletes the job and its program', correct: false,
              feedback: 'Nothing is deleted. It stops the job and moves its settings file to Reclaim City’s quarantine folder, and you can undo it.' },
            { text: 'Restarts the computer', correct: false,
              feedback: 'It stops the job and moves its settings file to Reclaim City’s quarantine folder. Nothing is deleted, and you can undo it.' },
          ],
        },
        {
          key: 'unknown-item-first-move-3',
          prompt: 'Why move a background item’s file aside instead of deleting it?',
          options: [
            { text: 'So it can be looked at again or put back', correct: true,
              feedback: 'Right. If it turns out to be something you need, nothing is lost.' },
            { text: 'Because moving it makes it safe to run', correct: false,
              feedback: 'Moving it doesn’t change what it does. It’s moved aside so it can be looked at again or put back.' },
            { text: 'There’s no difference', correct: false,
              feedback: 'A deleted file is gone. A file moved aside can be looked at again or put back.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/starts-on-its-own.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/starts-on-its-own.js
git commit -m "Lessons: starts-on-its-own gets item keys, a concept per question, and variants"
```

---

### Task 14: Item bank: locked-door (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/lessons/locked-door.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `locked-door` questions with `key`, `concept` and `variants` as in the table: 15 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

**After reclaim-city lands.** This file is one reclaim-city renamed (Device Rescue → Reclaim City); the text below is written against that version. Check first: `git diff reclaim-city -- desktop/renderer/game/lessons/locked-door.js` must show only the additions below (keys, concepts, variants).

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `update-where` | `auto-updates` | `update-where-2`: You’ve opened System Settings > General > Software Update. To see each automatic update switch, what do you click?<br>`update-where-3`: On a work Mac, the update switches are greyed out. What’s the likely reason? |
| `update-switch` | `auto-updates` | `update-switch-2`: Which switch covers the rapid-response security patches that come out between full macOS updates?<br>`update-switch-3`: “Check for updates” is on, and nothing else is. Is that enough? |
| `filevault-what` | `disk-encryption` | `filevault-what-2`: Someone takes the disk out of a Mac that has FileVault on. Can they read it?<br>`filevault-what-3`: On Windows, what does the job FileVault does on a Mac? |
| `recovery-key-where` | `disk-encryption` | `recovery-key-where-2`: Windows shows you a BitLocker recovery key. Which is a good place for it?<br>`recovery-key-where-3`: Why treat a FileVault recovery key like a master password? |
| `lock-delay` | `lock-screen` | `lock-delay-2`: Your Mac waits a while after the screen locks before it asks for the password. What’s the risk?<br>`lock-delay-3`: Where do you set how soon a Mac asks for the password after the screen locks? |

New lines come from `guides/remediation/enable_automatic_updates.md` (the "i" next to "Automatic updates"; greyed-out switches on a managed Mac; the names of the switches), `enable_disk_encryption.md` (unreadable even if the disk is removed; treat the key like a master password), `enable_bitlocker.md` (Microsoft account or a printed copy kept physically secure; never a plain text file on the same drive) and `enforce_lock_screen.md` (a delay gives a window during a brief absence). UI paths reused: System Settings > General > Software Update, System Settings > Lock Screen, System Settings > Privacy & Security > FileVault.

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/locked-door.js` with:

```js
export default {
  id: 'locked-door',
  title: 'Updates and the locked door',
  recommendedFor: ['identity', 'helping', 'unsure'],
  modules: ['automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'win_bitlocker_check', 'lock_screen_check', 'screen_lock_check'],
  districts: ['gatehouse', 'foundations'],
  sources: [
    'guides/remediation/enable_automatic_updates.md',
    'guides/remediation/enable_disk_encryption.md',
    'guides/remediation/enforce_lock_screen.md',
    'guides/remediation/enable_bitlocker.md',
  ],
  briefing: 'Three settings do a lot of quiet work: automatic updates, FileVault and the lock screen. This lesson takes them one at a time.',
  whatTheScanLooksFor: 'On a Mac, the checkup looks at your update settings, whether FileVault is on, and how soon the screen asks for a password. On Windows, it checks whether BitLocker is encrypting your drives.',
  questions: [
    {
      key: 'update-where',
      concept: 'auto-updates',
      teach: 'Automatic updates install security fixes for you. On a Mac, they’re in System Settings > General > Software Update. Click the “i” next to “Automatic updates” to see each switch.',
      setting: 'softwareUpdate',
      prompt: 'On a Mac, where do you turn on automatic updates?',
      options: [
        { text: 'System Settings > General > Software Update', correct: true,
          feedback: 'Right. Click the “i” next to “Automatic updates” to see each switch.' },
        { text: 'System Settings > Privacy & Security > FileVault', correct: false,
          feedback: 'That’s disk encryption. Updates are under General.' },
        { text: 'System Settings > Lock Screen', correct: false,
          feedback: 'That’s where the lock screen settings live. Updates are under General.' },
      ],
      variants: [
        {
          key: 'update-where-2',
          prompt: 'You’ve opened System Settings > General > Software Update. To see each automatic update switch, what do you click?',
          options: [
            { text: 'The “i” next to “Automatic updates”', correct: true,
              feedback: 'Right. That shows each switch, and each one can be turned on there.' },
            { text: 'FileVault', correct: false,
              feedback: 'FileVault is disk encryption, under Privacy & Security. The update switches are behind the “i” next to “Automatic updates”.' },
            { text: 'Lock Screen', correct: false,
              feedback: 'That’s a different setting. The update switches are behind the “i” next to “Automatic updates”.' },
          ],
        },
        {
          key: 'update-where-3',
          prompt: 'On a work Mac, the update switches are greyed out. What’s the likely reason?',
          options: [
            { text: 'The organisation manages updates centrally, so check with IT', correct: true,
              feedback: 'Right. Updates are likely still being applied on a schedule set by IT. Check with them rather than fighting the settings.' },
            { text: 'The updates are broken and macOS needs reinstalling', correct: false,
              feedback: 'Greyed-out switches usually mean the organisation controls updates. Check with your IT team.' },
            { text: 'FileVault is turned off', correct: false,
              feedback: 'FileVault doesn’t lock the update switches. On a managed Mac, the organisation may control them. Check with IT.' },
          ],
        },
      ],
    },
    {
      key: 'update-switch',
      concept: 'auto-updates',
      teach: 'Of those switches, “Install Security Responses and system files” is the most important one. It covers rapid-response security patches that come out between full macOS updates.',
      setting: 'softwareUpdate',
      prompt: 'Which update switch matters most for security?',
      options: [
        { text: '“Install Security Responses and system files”', correct: true,
          feedback: 'Right. It covers the rapid-response security patches.' },
        { text: '“Automatically update apps from the App Store”', correct: false,
          feedback: 'That one is worth having too, but “Install Security Responses and system files” is the most important, because it covers rapid-response security patches.' },
        { text: '“Check for updates”', correct: false,
          feedback: 'Checking is a start, but on its own it doesn’t install anything. “Install Security Responses and system files” is the most important switch.' },
      ],
      variants: [
        {
          key: 'update-switch-2',
          prompt: 'Which switch covers the rapid-response security patches that come out between full macOS updates?',
          options: [
            { text: '“Install Security Responses and system files”', correct: true,
              feedback: 'Right. It’s the most important switch to have on.' },
            { text: '“Download new updates when available”', correct: false,
              feedback: 'That downloads updates. The rapid-response patches are covered by “Install Security Responses and system files”.' },
            { text: '“Install macOS updates”', correct: false,
              feedback: 'That installs full macOS updates. The rapid-response patches are covered by “Install Security Responses and system files”.' },
          ],
        },
        {
          key: 'update-switch-3',
          prompt: '“Check for updates” is on, and nothing else is. Is that enough?',
          options: [
            { text: 'No. Checking doesn’t install anything; turn on “Install Security Responses and system files” too.', correct: true,
              feedback: 'Right. That’s the most important switch, because it covers rapid-response security patches.' },
            { text: 'Yes. Checking for updates installs them.', correct: false,
              feedback: 'Checking on its own doesn’t install anything. Turn on “Install Security Responses and system files” too.' },
          ],
        },
      ],
    },
    {
      key: 'filevault-what',
      concept: 'disk-encryption',
      teach: 'FileVault, on a Mac, encrypts (scrambles) the whole startup disk, so its contents can’t be read without your password or recovery key, even if the disk is taken out. It’s in System Settings > Privacy & Security > FileVault. On Windows, BitLocker does this job.',
      setting: 'fileVault',
      prompt: 'What does FileVault do?',
      options: [
        { text: 'Encrypts the whole startup disk, so it can’t be read without your password or recovery key', correct: true,
          feedback: 'Right. Even if someone takes the disk out, they can’t read it.' },
        { text: 'Makes the screen ask for a password after it locks', correct: false,
          feedback: 'That’s the lock screen setting. FileVault encrypts the disk.' },
        { text: 'Installs security fixes', correct: false,
          feedback: 'That’s automatic updates. FileVault encrypts the disk.' },
      ],
      variants: [
        {
          key: 'filevault-what-2',
          prompt: 'Someone takes the disk out of a Mac that has FileVault on. Can they read it?',
          options: [
            { text: 'Not without the password or the recovery key', correct: true,
              feedback: 'Right. FileVault encrypts the whole startup disk, even if the disk is taken out.' },
            { text: 'Yes. FileVault only locks the screen.', correct: false,
              feedback: 'That’s the lock screen. FileVault encrypts the whole disk, so it can’t be read without the password or recovery key.' },
            { text: 'Yes, if they plug it into another Mac', correct: false,
              feedback: 'Another Mac can’t read it either. Without the password or recovery key, the disk stays scrambled.' },
          ],
        },
        {
          key: 'filevault-what-3',
          prompt: 'On Windows, what does the job FileVault does on a Mac?',
          options: [
            { text: 'BitLocker', correct: true,
              feedback: 'Right. BitLocker encrypts the drive, so it can’t be read if the computer is lost or stolen.' },
            { text: 'The lock screen', correct: false,
              feedback: 'The lock screen asks for a password when you come back. BitLocker is what encrypts the drive.' },
            { text: 'Automatic updates', correct: false,
              feedback: 'Updates install security fixes. BitLocker is what encrypts the drive.' },
          ],
        },
      ],
    },
    {
      key: 'recovery-key-where',
      concept: 'disk-encryption',
      teach: 'When you turn FileVault on, you choose how to keep the recovery key: store it with your Apple ID, or get a key to keep yourself. Anyone who has that key can unlock the whole disk, so treat it like a master password.',
      setting: 'fileVault',
      prompt: 'You turn on FileVault and it shows you a recovery key. Where should it go?',
      options: [
        { text: 'Paste it into Reclaim City so it’s kept safe', correct: false,
          feedback: 'Don’t paste it into this tool or into a chat. Anyone who has it can unlock the whole disk.' },
        { text: 'Write it down, or save it in a password manager', correct: true,
          feedback: 'Right. Treat it like a master password.' },
        { text: 'In a note that syncs to an account someone else can get into', correct: false,
          feedback: 'Keep it where nobody else can read it. Anyone who has it can unlock the whole disk.' },
      ],
      variants: [
        {
          key: 'recovery-key-where-2',
          prompt: 'Windows shows you a BitLocker recovery key. Which is a good place for it?',
          options: [
            { text: 'Your Microsoft account, or a printed copy kept somewhere physically secure', correct: true,
              feedback: 'Right. And never paste it into this tool or into a chat.' },
            { text: 'A plain text file on the same drive', correct: false,
              feedback: 'Don’t save it as a plain text file on the same drive. Use your Microsoft account or a printed copy kept somewhere physically secure.' },
            { text: 'Paste it into Reclaim City', correct: false,
              feedback: 'Never paste a recovery key into this tool or a chat. Use your Microsoft account or a printed copy kept somewhere physically secure.' },
          ],
        },
        {
          key: 'recovery-key-where-3',
          prompt: 'Why treat a FileVault recovery key like a master password?',
          options: [
            { text: 'Anyone who has it can unlock the whole disk', correct: true,
              feedback: 'Right. Write it down or keep it in a password manager, where nobody else can read it.' },
            { text: 'It changes your Apple ID password', correct: false,
              feedback: 'It doesn’t. It unlocks the whole disk, which is why anyone who has it matters.' },
            { text: 'It turns FileVault off for good', correct: false,
              feedback: 'It doesn’t turn anything off. It unlocks the whole disk, so keep it where nobody else can read it.' },
          ],
        },
      ],
    },
    {
      key: 'lock-delay',
      concept: 'lock-screen',
      teach: 'When the screen locks, your Mac can ask for the password straight away, or after a delay. A long delay gives someone a chance to use it while you step away. It’s in System Settings > Lock Screen.',
      setting: 'lockScreen',
      prompt: 'How soon after the screen locks should your Mac ask for the password?',
      options: [
        { text: 'Immediately', correct: true,
          feedback: 'Right. A long delay gives someone a chance to use it while you’re away.' },
        { text: 'Only after a restart', correct: false,
          feedback: 'That leaves it open whenever you step away. Choose “Immediately” in the Lock Screen settings.' },
      ],
      variants: [
        {
          key: 'lock-delay-2',
          prompt: 'Your Mac waits a while after the screen locks before it asks for the password. What’s the risk?',
          options: [
            { text: 'Someone could use it while you’ve stepped away', correct: true,
              feedback: 'Right. Set it to “Immediately” in the Lock Screen settings.' },
            { text: 'None, as long as FileVault is on', correct: false,
              feedback: 'FileVault protects the disk if it’s taken out. While the Mac is running, the lock screen is what keeps someone out, so set it to “Immediately”.' },
            { text: 'It runs the battery down', correct: false,
              feedback: 'The risk is someone using it while you’ve stepped away. Set it to “Immediately” in the Lock Screen settings.' },
          ],
        },
        {
          key: 'lock-delay-3',
          prompt: 'Where do you set how soon a Mac asks for the password after the screen locks?',
          options: [
            { text: 'System Settings > Lock Screen', correct: true,
              feedback: 'Right. Choose “Immediately”.' },
            { text: 'System Settings > General > Software Update', correct: false,
              feedback: 'That’s updates. For the password delay, go to System Settings > Lock Screen.' },
            { text: 'System Settings > Privacy & Security > FileVault', correct: false,
              feedback: 'That’s disk encryption. For the password delay, go to System Settings > Lock Screen.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/locked-door.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/locked-door.js
git commit -m "Lessons: locked-door gets item keys, a concept per question, and variants"
```

---

### Task 15: Item bank: couldnt-check (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/lessons/couldnt-check.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `couldnt-check` questions with `key`, `concept` and `variants` as in the table: 6 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

**After reclaim-city lands.** This file is one reclaim-city renamed (Device Rescue → Reclaim City); the text below is written against that version. Check first: `git diff reclaim-city -- desktop/renderer/game/lessons/couldnt-check.js` must show only the additions below (keys, concepts, variants).

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `fog-means` | `couldnt-check` | `fog-means-2`: After the checkup, one check is listed as one that couldn’t run. Is that part of the computer clean?<br>`fog-means-3`: Why does a check often fail to run? |
| `nothing-found` | `clean-isnt-certain` | `nothing-found-2`: A friend says a clean checkup proves their laptop is fine. What would you tell them?<br>`nothing-found-3`: The checkup found nothing, but a few checks couldn’t run. What can you say? |

New lines come from `desktop/renderer/index.html` ("Often it just means a permission or tool is missing"; not a clean bill of health) and `AGENTS.md` ("a clean scan lowers the odds of a problem without ruling one out").

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/couldnt-check.js` with:

```js
export default {
  id: 'couldnt-check',
  title: 'What “couldn’t check” means',
  recommendedFor: ['unsure'],
  modules: [],
  districts: [],
  sources: [
    'README.md',
    'AGENTS.md',
    'desktop/renderer/index.html',
    'desktop/renderer/app.js',
    'desktop/renderer/game/findings-to-city.js',
    'desktop/renderer/game/views/map.js',
  ],
  briefing: 'Not every check can run on every computer. When one can’t, it’s often because a permission or a tool is missing.',
  whatTheScanLooksFor: 'After the checkup, anything that couldn’t run is listed by name, so you know exactly what wasn’t looked at.',
  questions: [
    {
      key: 'fog-means',
      concept: 'couldnt-check',
      teach: 'A check that couldn’t run checked nothing, so it isn’t a clean bill of health. Reclaim City says so instead of pretending everything is fine. In the city, those places show as fog, or are marked COULDN’T CHECK.',
      prompt: 'A district on your map is covered in fog. What does that mean?',
      options: [
        { text: 'Those checks couldn’t run, so nothing there was looked at', correct: true,
          feedback: 'Right. Often it just means a permission or a tool is missing.' },
        { text: 'Everything there is safe', correct: false,
          feedback: 'No. Fog means nothing was checked there, so it isn’t a clean bill of health.' },
        { text: 'Something bad is hiding there', correct: false,
          feedback: 'Fog doesn’t mean danger either. It means a check couldn’t look.' },
      ],
      variants: [
        {
          key: 'fog-means-2',
          prompt: 'After the checkup, one check is listed as one that couldn’t run. Is that part of the computer clean?',
          options: [
            { text: 'Nobody knows: that check looked at nothing', correct: true,
              feedback: 'Right. A check that couldn’t run isn’t a clean bill of health.' },
            { text: 'Yes. Nothing was found there.', correct: false,
              feedback: 'Nothing was found because nothing was looked at. A check that couldn’t run isn’t a clean bill of health.' },
            { text: 'No. Something is wrong there.', correct: false,
              feedback: 'It doesn’t mean that either. It means the check couldn’t look.' },
          ],
        },
        {
          key: 'fog-means-3',
          prompt: 'Why does a check often fail to run?',
          options: [
            { text: 'A permission or a tool is missing', correct: true,
              feedback: 'Right. Reclaim City lists each one by name, so you know exactly what wasn’t looked at.' },
            { text: 'Something is hiding from it', correct: false,
              feedback: 'Usually it’s simpler: a permission or a tool is missing.' },
          ],
        },
      ],
    },
    {
      key: 'nothing-found',
      concept: 'clean-isnt-certain',
      teach: 'Even a checkup that finds nothing lowers the odds of a problem without ruling one out.',
      prompt: 'The checkup found nothing at all. What can you say?',
      options: [
        { text: 'The odds of a problem are lower, but it isn’t a guarantee', correct: true,
          feedback: 'Right. A clean checkup lowers the odds without ruling a problem out.' },
        { text: 'This computer is definitely clean', correct: false,
          feedback: 'A checkup can’t promise that. It lowers the odds; it doesn’t rule a problem out.' },
      ],
      variants: [
        {
          key: 'nothing-found-2',
          prompt: 'A friend says a clean checkup proves their laptop is fine. What would you tell them?',
          options: [
            { text: 'It lowers the odds of a problem, but it can’t rule one out', correct: true,
              feedback: 'Right. That’s true of any checkup.' },
            { text: 'They’re right. It’s a guarantee.', correct: false,
              feedback: 'A checkup can’t promise that. It lowers the odds without ruling a problem out.' },
          ],
        },
        {
          key: 'nothing-found-3',
          prompt: 'The checkup found nothing, but a few checks couldn’t run. What can you say?',
          options: [
            { text: 'Only the checks that ran looked at anything, and even they lower the odds rather than rule a problem out', correct: true,
              feedback: 'Right. The ones that couldn’t run are listed by name, so you know what wasn’t looked at.' },
            { text: 'Everything is clean', correct: false,
              feedback: 'The checks that couldn’t run looked at nothing, and the ones that ran lower the odds without ruling a problem out.' },
          ],
        },
      ],
    },
  ],
};
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/couldnt-check.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

Expected: every family prints 3.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/couldnt-check.js
git commit -m "Lessons: couldnt-check gets item keys, a concept per question, and variants"
```

---

### Task 16: Item bank: spot-the-fake (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/lessons/spot-the-fake.js` (replace the whole file)
- Test: `desktop/test/game-lessons.test.js` (the gate, unchanged here)

**Interfaces:**

- Consumes: the gate from Task 5 (`itemsOf`, key and concept checks) and `skills.js` concept ids from Task 4.
- Produces: `spot-the-fake` questions with `key`, `concept` and `variants` as in the table: 12 items in all.

- [ ] **Step 1: Read the variants this lesson needs**

**After reclaim-city lands.** This file is one reclaim-city renamed (Device Rescue → Reclaim City); the text below is written against that version. Check first: `git diff reclaim-city -- desktop/renderer/game/lessons/spot-the-fake.js` must show only the additions below (keys, concepts, variants, and the families).

| Question (family key) | Concept | New variants (key: scenario) |
|---|---|---|
| `msg-1` | `fake-messages` | `msg-8`: email from security@paypa1.com<br>`msg-10`: email from verify@chase.com<br>`msg-6`: chat from IT-Support-Desk (via Slack) |
| `msg-4` | `fake-messages` | `msg-3`: sms from 72255<br>`msg-11`: sms from 346-23<br>`msg-12`: call from +1 (555) 012-3456 |
| `msg-5` | `fake-messages` | `msg-2`: email from account-security-noreply@accountprotection.microsoft.com<br>`msg-7`: sms from T-Mobile<br>`msg-9`: push from Instagram |

No new text: the variants are Reclaim City's own curated messages (`desktop/vendor/reclaim-city/src/data/phishing.js`), grouped by kind. Family `msg-1` (a pretext email) adds messages 8, 10 and 6; `msg-4` (a pretext call) adds 3, 11 and 12; `msg-5` (a genuine notice) adds 2, 7 and 9.

- [ ] **Step 2: Replace the lesson file**

Replace the whole of `desktop/renderer/game/lessons/spot-the-fake.js` with:

```js
// "Spot the fake message", built from Reclaim City's own scam-defense quiz data
// (vendor/reclaim-city/src/data/phishing.js). The messages and their "tells" are
// Reclaim City's content; only the wrapper text here is Reclaim City's.
//
// Each of PICKS is a question (a family); FAMILY_VARIANTS lists the other
// messages of the same kind, so item response theory has several of each.
export const PICKS = [1, 4, 5];
export const FAMILY_VARIANTS = { 1: [8, 10, 6], 4: [3, 11, 12], 5: [2, 7, 9] };

function sentence(tells) {
  return `${tells.map((t) => String(t).replace(/[.\s]+$/, '')).join('. ')}.`;
}

const usable = (m) => m && (m.answer === 'pretext' || m.answer === 'genuine') && Array.isArray(m.tells) && m.tells.length;

function item(m) {
  const fake = m.answer === 'pretext';
  const why = sentence(m.tells);
  return {
    key: `msg-${m.id}`,
    prompt: 'Real or fake?',
    message: { type: m.type, from: m.from, subject: m.subject || null, body: m.body },
    options: [
      { text: 'Fake', correct: fake, feedback: fake ? `Right, it’s fake. ${why}` : `This one is real. ${why}` },
      { text: 'Real', correct: !fake, feedback: fake ? `This one is fake. ${why}` : `Right, it’s real. ${why}` },
    ],
  };
}

export function buildSpotTheFake(messages) {
  const byId = new Map((Array.isArray(messages) ? messages : []).map((m) => [m && m.id, m]));
  const questions = PICKS.map((id) => byId.get(id)).filter(usable).map((m) => ({
    ...item(m),
    concept: 'fake-messages',
    variants: (FAMILY_VARIANTS[m.id] || []).map((v) => byId.get(v)).filter(usable).map(item),
  }));
  if (questions.length) questions[0].teach = 'Look at who sent it, whether it rushes you, and what it asks you to do. Even when a message looks real, type the company’s address into the address bar yourself, and don’t call a number from the message.';
  if (!questions.length) throw new Error('Spot the fake message: no usable messages');
  return {
    id: 'spot-the-fake',
    type: 'phishing',
    title: 'Spot the fake message',
    recommendedFor: ['hacked', 'identity', 'helping'],
    modules: [],
    districts: [],
    sources: ['desktop/vendor/reclaim-city/src/data/phishing.js', 'guides/identity_theft_recovery/phase_6.md'],
    briefing: 'Scammers copy the messages real companies send. These come from Reclaim City’s scam-defense quiz. For each one, decide whether it’s real or fake.',
    whatTheScanLooksFor: 'The checkup can’t see your messages. It looks for what a scam can leave behind on the computer, like remote-access tools.',
    questions,
  };
}
```

- [ ] **Step 3: Run the gate**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. A failure names the lesson and the text: a UI path or backtick not word for word in a source, a time word (watch for the ordinal "second"), or a key that clashes.

- [ ] **Step 4: Count the items**

Run:

```bash
cd desktop && node -e "import('./renderer/game/lessons/spot-the-fake.js').then((m) => { const l = m.default || m.buildSpotTheFake; console.log(l.questions ? l.questions.map((q) => [q.key, 1 + q.variants.length]) : 'see spot-the-fake') })"
```

For spot-the-fake the lesson is built from data, so the gate's "bank is complete" test in Task 17 does the count (4 items per family).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/lessons/spot-the-fake.js
git commit -m "Lessons: spot-the-fake gets item keys, a concept per question, and variants"
```

---

### Task 17: The bank is complete

**Files:**

- Modify: `desktop/test/game-lessons.test.js` (append two tests)

**Interfaces:**

- Consumes: every lesson converted (Tasks 7-9, 12-16); `buildBank` from Task 5.
- Produces: a gate that fails if any lesson question lacks a key, a concept or two variants, or if a duplicate key drops an item.

- [ ] **Step 1: Write the test**

Append to `desktop/test/game-lessons.test.js`:

```js

test('the bank is complete: every question has a key, a concept and at least two variants', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    for (const q of l.questions) {
      assert.ok(typeof q.key === 'string', `${l.id}: "${q.prompt}" has no key`);
      assert.ok(typeof q.concept === 'string', `${l.id}: ${q.key} has no concept`);
      assert.ok(itemsOf(q).length >= 3, `${l.id}: ${q.key} has ${itemsOf(q).length} items; item response theory needs at least 3`);
    }
  }
});

test('the item bank builds every item, and every shown concept a lesson teaches has three or more', async () => {
  const { lessons } = await loadAll();
  const { buildBank } = await import(pathToFileURL(path.join(GAME, 'profile', 'item-bank.js')).href);
  const bank = buildBank(lessons, []);
  const total = lessons.reduce((n, l) => n + l.questions.flatMap(itemsOf).length, 0);
  assert.strictEqual(bank.items.size, total, 'no item lost to a duplicate key');
  for (const [c, keys] of bank.concepts) assert.ok(keys.length >= 3, `${c}: ${keys.length} items`);
});
```

- [ ] **Step 2: Run it**

Run: `cd desktop && node --test test/game-lessons.test.js`

Expected: PASS. (Before Tasks 7-9 and 12-16 it FAILS naming the first question without a key.) The bank then holds 84 lesson items: `remote-access-scams` 3, `password-prompts` 3, `where-it-lives` 3, `who-made-it` 3, `fix-and-undo` 3, `auto-updates` 6, `disk-encryption` 6, `lock-screen` 3, `wifi-and-mining` 12, `cut-off-order` 3, `browser-add-ons` 12, `couldnt-check` 3, `clean-isnt-certain` 3, `poisoned-packages` 9, `fake-messages` 12.

- [ ] **Step 3: Commit**

```bash
git add desktop/test/game-lessons.test.js
git commit -m "Lessons: the gate requires a complete item bank"
```

---

### Task 18: The game keeps its progress in the profile, and lessons are visits (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/controller.js` (imports, state, `persist`/`keep`/`keepProfile`/`refreshBank`, `rebuild`, `commitDeck`, visit helpers, the lesson screen, the `lesson:`/`learn:`/`review:`/`answer:`/`next-question`/`finish-lesson`/`later` routes, `profileModeChanged`)
- Modify: `desktop/renderer/app.js` (`setMode`)
- Create: `desktop/test/profile-read.js`
- Create: `desktop/test/game-profile-controller.test.js`
- Modify: `desktop/test/game-controller.test.js`, `game-deck-controller.test.js`, `game-held-followups.test.js`, `game-side-district-controller.test.js` (read the box, not the old key)

**Interfaces:**

- Consumes: `player-profile.js` (Task 6): `loadProfile`, `saveProfile`, `profileSeed`, `toProgress`, `withProgress`, `recordAnswer`, `recordVisit`, `historyFor`, `difficultyOf`, `teachShown`; `item-bank.js` (Task 5): `buildBank`, `drawLessonVisit`; `renderLesson({ items, showTeach })` (Task 3); reclaim-city's `win.RescueHost.mode()` and `win.DisplayMode`.
- Produces: Controller state `s.profile`, `s.bank`, `s.progress` (the v3 view); functions `persist()`, `keep(nextProgress)`, `keepProfile(nextProfile)`, `refreshBank()`, `itemsOf(keys)`, `teachAt(keys, i)`, `openVisit(lessonId, keys, extra)`, `startVisit(lessonId, extra)`; `s.lesson = { id, keys, q, picked, showTeach, fromSweep?, back?, concept? }`; API `RescueGame.profileModeChanged()`. Test helper `profile-read.js`: `PROFILE_KEY`, `savedProfile(storage)`, `savedAsV3(storage)`.

- [ ] **Step 1: Add the test helper**

Create `desktop/test/profile-read.js`:

```js
// What the game saved, read back the way the app reads it: the recipe box,
// decoded. `savedAsV3` gives it in the old v3 shape the controller tests were
// written against. (require() of an ES module: Node 22.12 and later.)
const { decode } = require('../renderer/game/profile/recipe-box.js');

const PROFILE_KEY = 'device-rescue.recipe-box.v1';

function savedProfile(storage) {
  const text = storage.getItem(PROFILE_KEY);
  return text ? decode(text) : null;
}

function savedAsV3(storage) {
  const p = savedProfile(storage);
  if (!p) return null;
  const lessons = Object.fromEntries(Object.entries(p.lessons || {}).filter(([, l]) => l.visited).map(([id, l]) => [id, { completedAt: l.visited }]));
  return { version: 3, missions: p.missions, lessons,
    deck: { points: p.rank.points, rank: p.rank.index, drills: { right: p.drills.right, tried: p.drills.tried }, ...p.deck } };
}

module.exports = { PROFILE_KEY, savedProfile, savedAsV3 };
```

- [ ] **Step 2: Write the failing controller test**

Create `desktop/test/game-profile-controller.test.js`:

```js
// The player profile wired into game mode: the recipe box on disk, adaptive
// lesson visits, drills and calls as evidence, offers, YOUR FILE, and the
// publish sheet that never exists in city mode. Stubbed window, as in
// game-deck-controller.test.js.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { PROFILE_KEY, savedProfile } = require('./profile-read.js');

const OLD_KEY = 'device-rescue.game.v1';
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, category: 'security', data, ...extra });
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const drill = (id, answer) => ({ id, district: 'gatehouse', severity: 'warning', modules: [], title: `Drill ${id}`, setup: '',
  clues: { maker: { name: 'Unknown maker', verified: false, how: 'unsigned' }, path: '/tmp/d', what: 'Practice only.', when: null },
  answer, why: `Why ${id}.`, sources: [] });
const DRILLS = [drill('upd8r-hidden-cache', 'threat'), drill('zoom-helper-signed', 'mine')];
const DOC = scan(mod('launch_agent_audit', [f('Unsigned helper', 'critical', { program: '/tmp/x' },
  { code: 'security.launch_agent_audit.tmp', made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] })]));

function stub(mode) {
  const listeners = [];
  const keyListeners = [];
  const calls = { clipboard: [], objectUrls: 0, downloads: [] };
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); if (type === 'keydown') keyListeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }),
      createElement: () => ({ click() { calls.downloads.push(this.download); } }) },
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode.now, showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    navigator: { clipboard: { writeText: async (t) => { calls.clipboard.push(t); } } },
    URL: { createObjectURL: () => { calls.objectUrls += 1; return 'blob:x'; }, revokeObjectURL: () => {} },
    Blob: function Blob(parts) { this.parts = parts; },
    setTimeout: (fn) => fn(),
    rescue: {},
  };
  const click = (attrs, checked = false) => {
    const el = { checked, getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const key = (k) => { const ev = { key: k, target: { closest: () => null }, preventDefault() {} }; keyListeners.forEach((fn) => fn(ev)); };
  return { win, frame, calls, click, key };
}

async function setup({ storage = recordingStore(), mode = 'standard', publishReady = false, doc = DOC } = {}) {
  const [{ createController }, training] = await Promise.all([import('../renderer/game/controller.js'), import('../renderer/game/training.js')]);
  const lessons = await training.loadLessons(importModule);
  const m = { now: mode };
  const t = stub(m);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank: async () => DRILLS, publishReady });
  await tick();
  if (doc) ctl.show(doc, { id: 'unsure' });
  return { ...t, ctl, storage, lessons, mode: m, html: () => t.frame.innerHTML, lesson: (id) => lessons.find((l) => l.id === id) };
}
const correctIndex = (q) => q.options.findIndex((o) => o.correct);

test('the profile is a recipe box from the first run: nothing literal written; city mode retires the old store, standard keeps it', async () => {
  const v3 = JSON.stringify({ version: 3, missions: {}, lessons: { 'locked-door': { completedAt: '2026-10-01T00:00:00.000Z' } },
    deck: { points: 120, rank: 1, drills: { right: 1, tried: 2 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] } });
  const city = await setup({ storage: recordingStore({ [OLD_KEY]: v3 }), mode: 'city' });
  assert.strictEqual(city.storage.data[OLD_KEY], undefined);
  assert.strictEqual(savedProfile(city.storage).rank.points, 120);
  assert.deepStrictEqual(forbiddenWrites(city.storage), []);
  const std = await setup({ storage: recordingStore({ [OLD_KEY]: v3 }), mode: 'standard' });
  assert.strictEqual(std.storage.data[OLD_KEY], v3, 'kept, frozen, for an older build');
  assert.deepStrictEqual(forbiddenWrites(std.storage), []);
  assert.ok(std.storage.data[PROFILE_KEY].startsWith('{"kitchen":'));
});

test('a first visit is the lesson as written; the next asks variants; every answer is saved as evidence', async () => {
  const t = await setup();
  const l = t.lesson('couldnt-check');
  t.click({ 'data-go': 'lesson:couldnt-check' });
  assert.ok(t.html().includes(`QUESTION 1 OF ${l.questions.length}`));
  l.questions.forEach((q, n) => {
    assert.ok(t.html().includes(q.prompt.replace(/’/g, '’')), `asks ${q.key} as written`);
    t.click({ 'data-act': `answer:${correctIndex(q)}` });
    t.click({ 'data-act': n === l.questions.length - 1 ? 'finish-lesson' : 'next-question' });
  });
  const p = savedProfile(t.storage);
  assert.deepStrictEqual(p.concepts['couldnt-check'].seen.map((e) => e[0]), ['fog-means']);
  assert.ok(p.lessons['couldnt-check'].visited, 'the visit makes it done for the game');
  t.click({ 'data-go': 'lesson:couldnt-check' });
  const variants = l.questions.flatMap((q) => q.variants.map((v) => v.prompt));
  assert.ok(variants.some((v) => t.html().includes(v)), 'the second visit asks a variant');
});

test('the drill bank failing to load still leaves lesson visits measured', async () => {
  const [{ createController }, training] = await Promise.all([import('../renderer/game/controller.js'), import('../renderer/game/training.js')]);
  const lessons = await training.loadLessons(importModule);
  const t = stub({ now: 'standard' });
  const storage = recordingStore();
  createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank: () => Promise.reject(new Error('no drills')) });
  await tick();
  t.click({ 'data-go': 'lesson:locked-door' });
  t.click({ 'data-act': 'answer:0' });
  assert.deepStrictEqual(savedProfile(storage).concepts['auto-updates'].seen.map((e) => e[0]), ['update-where']);
});
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-profile-controller.test.js`

Expected: FAIL: nothing is written under `device-rescue.recipe-box.v1` (`savedProfile` returns null), and the old key is still present in city mode.

- [ ] **Step 4: Point the existing tests at the box**

In `desktop/test/game-held-followups.test.js`, replace:

```js
const assert = require('node:assert');
```

with:

```js
const assert = require('node:assert');
const { PROFILE_KEY, savedProfile, savedAsV3 } = require('./profile-read.js');
```

In `desktop/test/game-held-followups.test.js`, replace:

```js
saved: () => JSON.parse(storage.getItem('device-rescue.game.v1') || 'null') };
```

with:

```js
saved: () => savedAsV3(storage) };
```

In `desktop/test/game-side-district-controller.test.js`, replace:

```js
const assert = require('node:assert');
```

with:

```js
const assert = require('node:assert');
const { PROFILE_KEY, savedProfile, savedAsV3 } = require('./profile-read.js');
```

In `desktop/test/game-side-district-controller.test.js`, replace:

```js
const saved = JSON.parse(t.storage.getItem('device-rescue.game.v1'));
```

with:

```js
const saved = savedAsV3(t.storage);
```

In `desktop/test/game-deck-controller.test.js`, replace:

```js
const assert = require('node:assert');
```

with:

```js
const assert = require('node:assert');
const { PROFILE_KEY, savedProfile, savedAsV3 } = require('./profile-read.js');
```

In `desktop/test/game-deck-controller.test.js`, replace:

```js
saved: () => JSON.parse(storage.getItem(STORE) || 'null') };
```

with:

```js
saved: () => savedAsV3(storage) };
```

In `desktop/test/game-deck-controller.test.js`, replace:

```js
assert.doesNotMatch(t.storage.getItem(STORE), /stalkerware|monitoringSeen/);
```

with:

```js
assert.doesNotMatch(JSON.stringify(savedProfile(t.storage)), /stalkerware|monitoringSeen/);
```

In `desktop/test/game-controller.test.js`, replace:

```js
const assert = require('node:assert');
```

with:

```js
const assert = require('node:assert');
const { PROFILE_KEY, savedProfile, savedAsV3 } = require('./profile-read.js');
```

In `desktop/test/game-controller.test.js`, replace:

```js
assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 20);
```

with:

```js
assert.strictEqual(savedAsV3(t.storage).deck.points, 20);
```

In `desktop/test/game-controller.test.js`, replace:

```js
assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.points, 50);
```

with:

```js
assert.strictEqual(savedAsV3(t.storage).deck.points, 50);
```

In `desktop/test/game-controller.test.js`, replace:

```js
test('a wrong answer gets feedback; leaving part-way records nothing; finishing marks DONE', async () => {
```

with:

```js
test('a wrong answer gets feedback; leaving part-way keeps the answer but marks nothing DONE; finishing marks DONE', async () => {
```

In `desktop/test/game-controller.test.js`, replace:

```js
  assert.doesNotMatch(String(t.storage.getItem('device-rescue.game.v1') || ''), /whos-on-wifi/);
```

with:

```js
  assert.strictEqual((savedAsV3(t.storage).lessons || {})['whos-on-wifi'], undefined);
  assert.deepStrictEqual(savedProfile(t.storage).concepts['wifi-and-mining'].seen.map((e) => [e[0], e[1]]), [['hot-and-slow', 0]],
    'the first pick is kept as evidence, wrong and all');
```

In `desktop/test/game-controller.test.js`, replace:

```js
  const saved = JSON.parse(t.storage.getItem('device-rescue.game.v1'));
  assert.ok(saved.lessons['password-asker'].completedAt);
```

with:

```js
  const saved = savedAsV3(t.storage);
  assert.ok(saved.lessons['password-asker'].completedAt);
```

In `desktop/test/game-controller.test.js`, replace:

```js
const before = storage.getItem('device-rescue.game.v1');
```

with:

```js
const before = storage.getItem(PROFILE_KEY);
```

In `desktop/test/game-controller.test.js`, replace:

```js
assert.strictEqual(storage.getItem('device-rescue.game.v1'), before, 'nothing saved');
```

with:

```js
assert.strictEqual(storage.getItem(PROFILE_KEY), before, 'nothing saved');
```

In `desktop/test/game-controller.test.js`, replace:

```js
assert.ok(JSON.parse(storage.getItem('device-rescue.game.v1')).lessons['whos-on-wifi'].completedAt);
```

with:

```js
assert.ok(savedAsV3(storage).lessons['whos-on-wifi'].completedAt);
```

In `desktop/test/game-controller.test.js`, replace:

```js
  const saved = JSON.parse(storage.getItem('device-rescue.game.v1'));
  assert.deepStrictEqual(Object.keys(saved.lessons).sort(), ['password-asker', 'whos-on-wifi']);
```

with:

```js
  const saved = savedAsV3(storage);
  assert.deepStrictEqual(Object.keys(saved.lessons).sort(), ['password-asker', 'whos-on-wifi']);
```

- [ ] **Step 5: Swap the store and make lessons visits**

The rule: every `s.progress = X; saveProgress(storage, s.progress);` becomes `keep(X);`, and every lesson record goes through the profile. The exact edits against reclaim-city `6cf1130`:

In `desktop/renderer/game/controller.js`, replace:

```js
import { loadProgress, saveProgress, reconcile, setStatus, setLessonDone, lessonDone, ranOkModules, recheckOutcome, setDeck } from './progress.js';
```

with:

```js
import { reconcile, setStatus, ranOkModules, recheckOutcome, setDeck } from './progress.js';
import { buildBank, drawLessonVisit } from './profile/item-bank.js';
import { loadProfile, saveProfile, profileSeed, toProgress, withProgress, recordAnswer, recordVisit,
  historyFor, difficultyOf, teachShown } from './profile/player-profile.js';
```

In `desktop/renderer/game/controller.js`, replace:

```js
  const s = { doc: null, held: [], heldCity: null, situation: null, city: null, progress: loadProgress(storage), cameBack: [],
```

with:

```js
  // The player profile (profile/player-profile.js) is the record; `progress`
  // is the v3-shaped view of it that progress.js and ledger.js work on.
  const profile0 = loadProfile(storage, now());
  const bank0 = buildBank([], []);
  const s = { doc: null, held: [], heldCity: null, situation: null, city: null, profile: profile0, bank: bank0, progress: toProgress(profile0, bank0), cameBack: [],
```

In `desktop/renderer/game/controller.js`, replace:

```js
    s.lessons = Array.isArray(ls) ? ls : [];
    s.lessonsLoaded = true;
```

with:

```js
    s.lessons = Array.isArray(ls) ? ls : [];
    s.lessonsLoaded = true;
    refreshBank();
```

In `desktop/renderer/game/controller.js`, replace:

```js
    s.drillBank = Array.isArray(ds) ? ds : [];
    s.drillsLoaded = true;
```

with:

```js
    s.drillBank = Array.isArray(ds) ? ds : [];
    s.drillsLoaded = true;
    refreshBank();
```

In `desktop/renderer/game/controller.js`, replace:

```js
  const hostMode = () => (win.RescueHost && typeof win.RescueHost.mode === 'function' ? win.RescueHost.mode() : 'city');
```

with:

```js
  const hostMode = () => (win.RescueHost && typeof win.RescueHost.mode === 'function' ? win.RescueHost.mode() : 'city');

  // The one place the profile is written: a recipe box in every mode. In city
  // mode the old literal store goes once the box is written (player-profile.js).
  function persist() {
    saveProfile(storage, s.profile, { seed: profileSeed(storage, win.DisplayMode), mode: hostMode() });
  }
  // A v3 view changed by progress.js or ledger.js: folded into the profile,
  // saved, and the view drawn again from the profile.
  function keep(nextProgress) {
    s.profile = withProgress(s.profile, nextProgress);
    persist();
    s.progress = toProgress(s.profile, s.bank);
  }
  function keepProfile(next) {
    s.profile = next;
    persist();
    s.progress = toProgress(s.profile, s.bank);
  }
  function refreshBank() {
    s.bank = buildBank(s.lessons, s.drillBank);
    s.progress = toProgress(s.profile, s.bank);
  }
  // A first run moves the old store into the box straight away.
  persist();
```

In `desktop/renderer/game/controller.js`, replace:

```js
    s.progress = setDeck(r.progress, carrying && rd.deck.sweep.carry !== true ? { ...rd.deck, sweep: { ...rd.deck.sweep, carry: true } } : rd.deck);
    saveProgress(storage, s.progress);
```

with:

```js
    keep(setDeck(r.progress, carrying && rd.deck.sweep.carry !== true ? { ...rd.deck, sweep: { ...rd.deck.sweep, carry: true } } : rd.deck));
```

In `desktop/renderer/game/controller.js`, replace:

```js
  function commitDeck(deck) {
    s.progress = setDeck(s.progress, deck);
    saveProgress(storage, s.progress);
  }
```

with:

```js
  function commitDeck(deck) {
    keep(setDeck(s.progress, deck));
  }

  // Lesson visits: a few items from the bank (profile/item-bank.js).
  const itemsOf = (keys) => (keys || []).map((k) => s.bank.items.get(k)).filter(Boolean);
  const teachAt = (keys, i) => (keys && keys.length ? teachShown(s.profile, s.bank, keys[i]) : true);
  function openVisit(lessonId, keys, extra = {}) {
    s.lesson = { id: lessonId, keys, q: 0, picked: null, showTeach: teachAt(keys, 0), ...extra };
    s.screen = 'lesson';
    render();
  }
  // With no items for it in the bank, a lesson is asked as written.
  function startVisit(lessonId, extra = {}) {
    openVisit(lessonId, drawLessonVisit(s.bank, lessonId, historyFor(s.profile, s.bank), { bOf: difficultyOf(s.profile, s.bank) }), extra);
  }
```

In `desktop/renderer/game/controller.js`, replace:

```js
      if (l) return renderLesson({ lesson: l, qIndex: s.lesson.q, picked: s.lesson.picked, scan: s.scan, scout, pendingCity: cityWaiting(), scanFinished: !!s.city, settingFor });
```

with:

```js
      const items = itemsOf(s.lesson.keys);
      if (l) return renderLesson({ lesson: l, items: items.length ? items : null, qIndex: s.lesson.q, picked: s.lesson.picked, showTeach: s.lesson.showTeach !== false,
        scan: s.scan, scout, pendingCity: cityWaiting(), scanFinished: !!s.city, settingFor });
```

In `desktop/renderer/game/controller.js`, replace:

```js
    if (go && go.startsWith('lesson:')) { s.lesson = { id: go.slice(7), q: 0, picked: null }; s.screen = 'lesson'; render(); return; }
```

with:

```js
    if (go && go.startsWith('lesson:')) { startVisit(go.slice(7)); return; }
```

In `desktop/renderer/game/controller.js`, replace:

```js
      if (l && !l.done) { s.lesson = { id: l.lesson.id, q: 0, picked: null, fromSweep: true }; s.screen = 'lesson'; render(); }
```

with:

```js
      if (l && !l.done) startVisit(l.lesson.id, { fromSweep: true });
```

In `desktop/renderer/game/controller.js`, replace:

```js
      if (l) { s.lesson = { id: nextReview(l.list || [l.lesson]).id, q: 0, picked: null, fromSweep: true }; s.screen = 'lesson'; render(); }
```

with:

```js
      if (l) startVisit(nextReview(l.list || [l.lesson]).id, { fromSweep: true });
```

In `desktop/renderer/game/controller.js`, replace:

```js
      if (s.lesson && s.lesson.picked == null) {
        s.lesson.picked = Number(act.slice(7));
        // Answering the last question is finishing: it counts even if the
        // person then leaves (SEE YOUR CITY, BACK TO THE CHECKUP) without FINISH.
        const l = s.lessons.find((x) => x.id === s.lesson.id);
        if (l && s.lesson.q >= l.questions.length - 1 && !lessonDone(s.progress, l.id)) {
          s.progress = setLessonDone(s.progress, l.id, now());
          saveProgress(storage, s.progress);
        }
        render();
      }
```

with:

```js
      if (s.lesson && s.lesson.picked == null) {
        const l = s.lessons.find((x) => x.id === s.lesson.id);
        const items = itemsOf(s.lesson.keys);
        const list = items.length ? items : (l ? l.questions : []);
        const n = Number(act.slice(7));
        const q = list[s.lesson.q];
        if (!q || !Array.isArray(q.options) || !q.options[n]) return;
        s.lesson.picked = n;
        // Every answer is evidence, right or wrong. Answering the last item
        // finishes the visit: it counts even if the person then leaves (SEE
        // YOUR CITY, BACK TO THE CHECKUP) without FINISH.
        let next = items.length ? recordAnswer(s.profile, s.bank, q.key, q.options[n].correct === true, now()) : s.profile;
        if (s.lesson.q >= list.length - 1 && !s.lesson.concept) next = recordVisit(next, s.lesson.id, now());
        keepProfile(next);
        render();
      }
```

In `desktop/renderer/game/controller.js`, replace:

```js
    if (act === 'next-question' && s.lesson) { s.lesson = { ...s.lesson, q: s.lesson.q + 1, picked: null }; render(); return; }
    // Only finishing a lesson records anything; leaving part-way records nothing.
    if (act === 'finish-lesson' && s.lesson) {
      if (!lessonDone(s.progress, s.lesson.id)) {
        s.progress = setLessonDone(s.progress, s.lesson.id, now());
        saveProgress(storage, s.progress);
      }
      // A lesson opened from the sweep goes back to the sweep, or, once the
      // checkup has finished, to the city: never the Training Grounds' list.
      const fromSweep = s.lesson.fromSweep;
      s.screen = !fromSweep ? 'training' : s.scan.running ? 'boss' : s.city ? 'map' : 'training';
```

with:

```js
    if (act === 'next-question' && s.lesson) {
      s.lesson = { ...s.lesson, q: s.lesson.q + 1, picked: null, showTeach: teachAt(s.lesson.keys, s.lesson.q + 1) };
      render();
      return;
    }
    // Each answer was saved as it was given; leaving part-way keeps those.
    if (act === 'finish-lesson' && s.lesson) {
      const rec = s.profile.lessons[s.lesson.id];
      if (!s.lesson.concept && !(rec && rec.visited)) keepProfile(recordVisit(s.profile, s.lesson.id, now()));
      // A lesson opened from the sweep goes back to the sweep, or, once the
      // checkup has finished, to the city: never the Training Grounds' list.
      // One opened from YOUR FILE or a signal's offer goes back there.
      const fromSweep = s.lesson.fromSweep;
      s.screen = s.lesson.back ? s.lesson.back : !fromSweep ? 'training' : s.scan.running ? 'boss' : s.city ? 'map' : 'training';
      if (s.screen === 'range' && !s.range) s.screen = s.city ? 'map' : 'training';
```

In `desktop/renderer/game/controller.js`, replace:

```js
        s.progress = setStatus(s.progress, m.id, 'later', m.module, now(), { districtId: m.districtId, title: m.title });
        saveProgress(storage, s.progress); s.screen = 'district'; s.districtId = m.districtId;
```

with:

```js
        keep(setStatus(s.progress, m.id, 'later', m.module, now(), { districtId: m.districtId, title: m.title }));
        s.screen = 'district'; s.districtId = m.districtId;
```

In `desktop/renderer/game/controller.js`, replace:

```js
  return {
    isReady: true,
```

with:

```js
  return {
    isReady: true,
    // The display mode changed: save once now, so city mode retires the old store at once.
    profileModeChanged() { persist(); },
```

In `desktop/renderer/app.js`, replace:

```js
      mode = next;
      DisplayMode.writeMode(store, next);
      if (changed && lastScanDoc) renderResults(lastScanDoc);
```

with:

```js
      mode = next;
      DisplayMode.writeMode(store, next);
      // The game saves its profile once in the new mode (city mode retires the old store).
      if (changed && window.RescueGame && typeof window.RescueGame.profileModeChanged === 'function') window.RescueGame.profileModeChanged();
      if (changed && lastScanDoc) renderResults(lastScanDoc);
```

Then check nothing of the old store is left: `grep -n "saveProgress\|loadProgress\|setLessonDone\|lessonDone(" desktop/renderer/game/controller.js` prints nothing.

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS. In particular `game-controller.test.js` "answering every question counts as done…", "REVIEW rotates…" (nothing saved by opening reviews) and "a DONE ✓ district mid-scan opens no quiz" pass unchanged in substance: a first visit is the lesson as written, and answering its last item records the visit.

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/renderer/app.js desktop/test/profile-read.js desktop/test/game-profile-controller.test.js desktop/test/game-controller.test.js desktop/test/game-deck-controller.test.js desktop/test/game-held-followups.test.js desktop/test/game-side-district-controller.test.js
git commit -m "Game: progress lives in the player profile; lessons are measured visits"
```

---

### Task 19: Drills and calls are evidence; a skipped concept is offered again (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/controller.js` (imports, `sessionStart`, `offerFor`, `tagSignal`, `answerDrill`, `signalPanelHtml`, the `offer-yes:`/`offer-no:` routes)
- Modify: `desktop/renderer/game/clues.js` (add `scoutAgrees`)
- Modify: `desktop/renderer/game/views/signal.js` (`offer` parameter and line)
- Test: `desktop/test/game-profile-controller.test.js`, `desktop/test/game-signal-view.test.js`, `desktop/test/game-clues.test.js` (append)

**Interfaces:**

- Consumes: Task 18's controller (`keepProfile`, `openVisit`, `startVisit`); `player-profile.js`: `recordDrillCall`, `recordGap`, `callConcepts`, `shouldOffer`, `noteOffered`, `declineOffer`, `historyFor`, `difficultyOf`; `item-bank.js`: `drawConcept`; `skills.js`: `conceptById`.
- Produces: `scoutAgrees(sig, tag) -> boolean` in `clues.js`; `renderSignalPanel({ …, offer: { id, title } | null })`; controller `offerFor(conceptIds) -> { id, title } | null`, `s.signal.offer`; acts `offer-yes:<conceptId>` (opens a 2-question visit that returns to the deck or the range) and `offer-no:<conceptId>`.

- [ ] **Step 1: Write the failing tests**

Append to `desktop/test/game-profile-controller.test.js`:

```js

test('a wrong drill on a concept the person said they knew offers 2 questions; YES opens them; STILL KNOW IT declines', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage });
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  assert.match(t.html(), /Want the 2 questions on where it lives\?/);
  assert.match(t.html(), /data-act="offer-yes:where-it-lives"/);
  t.click({ 'data-act': 'offer-yes:where-it-lives' });
  assert.match(t.html(), /QUESTION 1 OF 2/);
  const p = savedProfile(t.storage);
  assert.ok(p.concepts['where-it-lives'].offered, 'the offer is remembered, so it isn’t made again this sweep');
  assert.strictEqual(p.drills.calls.threat.mine, 1);
});

test('STILL KNOW IT records the decline and the offer goes', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage });
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'offer-no:where-it-lives' });
  assert.doesNotMatch(t.html(), /Want the 2 questions/);
  assert.strictEqual(savedProfile(t.storage).concepts['where-it-lives'].offered.declined, 1);
});

test('when Scout reads a real finding differently, the profile notes a gap for its concepts', async () => {
  const t = await setup();
  const { buildSignals } = await import('../renderer/game/signals.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = buildSignals(findingsToCity(DOC), null).find((x) => x.kind === 'real').id;
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'tag:mine' }); // the scan marked it critical: Scout reads THREAT
  const p = savedProfile(t.storage);
  assert.strictEqual(p.concepts['who-made-it'].gaps.call, 1);
  assert.ok(!JSON.stringify(p.concepts).includes('/tmp/x'), 'only the concept, never the finding');
});
```

Append to `desktop/test/game-signal-view.test.js`:

```js

test('an offer is one line with two answers, after Scout’s read', async () => {
  const { renderSignalPanel } = await import('../renderer/game/views/signal.js');
  const sig = { id: 'drill:x', kind: 'drill', severity: 'warning', title: 'A drill', districtId: 'gatehouse', drill: { setup: '' } };
  const html = renderSignalPanel({ signal: sig, tagged: 'mine', read: 'Not this time.', scout: () => '', offer: { id: 'where-it-lives', title: 'Where it lives' } });
  assert.match(html, /Want the 2 questions on where it lives\?/);
  assert.match(html, /data-act="offer-yes:where-it-lives"/);
  assert.match(html, /data-act="offer-no:where-it-lives"[^>]*>STILL KNOW IT/);
  assert.ok(html.indexOf('Not this time.') < html.indexOf('Want the 2 questions'));
  assert.doesNotMatch(renderSignalPanel({ signal: sig, tagged: 'mine', read: 'r', scout: () => '' }), /offer-yes/);
});
```

Append to `desktop/test/game-clues.test.js`:

```js

test('scoutAgrees: the scan’s view in tag terms, and a mark reads as MINE', async () => {
  const { scoutAgrees } = await import('../renderer/game/clues.js');
  assert.strictEqual(scoutAgrees({ severity: 'critical' }, 'threat'), true);
  assert.strictEqual(scoutAgrees({ severity: 'critical' }, 'mine'), false);
  assert.strictEqual(scoutAgrees({ severity: 'warning' }, 'closer'), true);
  assert.strictEqual(scoutAgrees({ severity: 'info' }, 'mine'), true);
  assert.strictEqual(scoutAgrees({ severity: 'critical', marked: true }, 'mine'), true);
  assert.strictEqual(scoutAgrees({ severity: 'nonsense' }, 'closer'), true);
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-profile-controller.test.js test/game-signal-view.test.js test/game-clues.test.js`

Expected: FAIL: no "Want the 2 questions" line; `scoutAgrees` is not a function; `concepts['who-made-it']` has no `gaps`.

- [ ] **Step 3: Add scoutAgrees and the offer line**

In `desktop/renderer/game/clues.js`, replace:

```js
// Never "wrong": the person's call stands, and a tag only sorts the game.
export function scoutRead(sig, tag) {
```

with:

```js
// Whether Scout reads a real signal the way the person tagged it. A
// disagreement is never "wrong" (the call stands); the profile only notes it
// as a sign a lesson might help.
export function scoutAgrees(sig, tag) {
  return tag === (sig.marked ? 'mine' : VIEW[sig.severity] || 'closer');
}

// Never "wrong": the person's call stands, and a tag only sorts the game.
export function scoutRead(sig, tag) {
```

In `desktop/renderer/game/views/signal.js`, replace:

```js
export function renderSignalPanel({ signal: sig, districtName = '', clues = [], opened = [], tagged = null, right = false, read = '',
  points = 0, scout, mineHtml = '', range = null }) {
```

with:

```js
// `offer`: { id, title } of a concept the person said they knew, when a
// signal suggests a refresher (PlayerProfile.shouldOffer). One line, two answers.
export function renderSignalPanel({ signal: sig, districtName = '', clues = [], opened = [], tagged = null, right = false, read = '',
  points = 0, scout, mineHtml = '', range = null, offer = null }) {
```

In `desktop/renderer/game/views/signal.js`, replace:

```js
    <div class="scout-row">${scout(drill && !right ? 'thinkingA' : 'happy', 54)}<p class="say">${esc(read)}</p></div>
```

with:

```js
    <div class="scout-row">${scout(drill && !right ? 'thinkingA' : 'happy', 54)}<p class="say">${esc(read)}</p></div>
    ${offer ? `<div class="panel offer" role="note"><p class="intel">Want the 2 questions on ${esc(offer.title.toLowerCase())}?</p>
      <div class="row"><button type="button" class="btn-s" data-act="offer-yes:${esc(offer.id)}">YES</button>
        <button type="button" class="btn-t" data-act="offer-no:${esc(offer.id)}">STILL KNOW IT</button></div></div>` : ''}
```

- [ ] **Step 4: Wire drills, calls and offers in the controller**

In `desktop/renderer/game/controller.js`, replace:

```js
import { buildBank, drawLessonVisit } from './profile/item-bank.js';
import { loadProfile, saveProfile, profileSeed, toProgress, withProgress, recordAnswer, recordVisit,
  historyFor, difficultyOf, teachShown } from './profile/player-profile.js';
```

with:

```js
import { buildBank, drawLessonVisit, drawConcept } from './profile/item-bank.js';
import { loadProfile, saveProfile, profileSeed, toProgress, withProgress, recordAnswer, recordVisit, recordDrillCall, recordGap,
  callConcepts, shouldOffer, noteOffered, declineOffer, historyFor, difficultyOf, teachShown } from './profile/player-profile.js';
import { conceptById } from './profile/skills.js';
```

In `desktop/renderer/game/controller.js`, replace:

```js
import { cluesFor, drillClues, scoutRead, drillRead, COULDNT_READ } from './clues.js';
```

with:

```js
import { cluesFor, drillClues, scoutRead, scoutAgrees, drillRead, COULDNT_READ } from './clues.js';
```

In `desktop/renderer/game/controller.js`, replace:

```js
  const bank0 = buildBank([], []);
```

with:

```js
  const bank0 = buildBank([], []);
  // Offers are once per sweep; before the first sweep, once per session.
  const sessionStart = now();
```

In `desktop/renderer/game/controller.js`, replace:

```js
  function startVisit(lessonId, extra = {}) {
    openVisit(lessonId, drawLessonVisit(s.bank, lessonId, historyFor(s.profile, s.bank), { bOf: difficultyOf(s.profile, s.bank) }), extra);
  }
```

with:

```js
  function startVisit(lessonId, extra = {}) {
    openVisit(lessonId, drawLessonVisit(s.bank, lessonId, historyFor(s.profile, s.bank), { bOf: difficultyOf(s.profile, s.bank) }), extra);
  }
  // "Want the 2 questions on this?": for a concept the person said they knew,
  // once per sweep (or per session before any sweep), by the profile's rules.
  function offerFor(concepts) {
    const sweepAt = s.progress.deck.sweep.at || sessionStart;
    const c = (concepts || []).find((x) => shouldOffer(s.profile, s.bank, x, sweepAt));
    if (!c) return null;
    keepProfile(noteOffered(s.profile, c, now()));
    return { id: c, title: conceptById(c).title };
  }
```

In `desktop/renderer/game/controller.js`, replace:

```js
    s.signal = { ...s.signal, tagged: tag, read: sig.kind === 'couldnt' ? COULDNT_READ : scoutRead(sig, tag) };
    logEntry('TAG', `${TAG_WORD[tag]}: ${sig.title}`);
```

with:

```js
    s.signal = { ...s.signal, tagged: tag, read: sig.kind === 'couldnt' ? COULDNT_READ : scoutRead(sig, tag) };
    // Scout reading it another way is a sign a lesson might help (never "wrong").
    if (sig.kind === 'real' && !scoutAgrees(sig, tag)) {
      const cs = callConcepts(s.bank, sig.module, openedFor(sig.id));
      if (cs.length) { keepProfile(recordGap(s.profile, cs, 'call', now())); s.signal.offer = offerFor(cs); }
    }
    logEntry('TAG', `${TAG_WORD[tag]}: ${sig.title}`);
```

In `desktop/renderer/game/controller.js`, replace:

```js
    commitDeck(recordDrill(s.progress.deck, right));
    const points = right ? commitAward(award(s.progress.deck, 'drill', d.id, openedFor(sig.id).length >= 2 ? POINTS.drillClueBonus : 0)) : 0;
    if (!range) s.drillAnswers[d.id] = { tag, right };
    s.signal = { ...s.signal, tagged: tag, right, points, read: drillRead(d, right) };
```

with:

```js
    commitDeck(recordDrill(s.progress.deck, right));
    const points = right ? commitAward(award(s.progress.deck, 'drill', d.id, openedFor(sig.id).length >= 2 ? POINTS.drillClueBonus : 0)) : 0;
    // The same answer is evidence on the drill's concept, and a cell in the calls matrix.
    keepProfile(recordDrillCall(s.profile, s.bank, d, tag, now()));
    const it = s.bank.items.get(`drill:${d.id}`);
    const offer = !right && it && it.concept ? offerFor([it.concept]) : null;
    if (!range) s.drillAnswers[d.id] = { tag, right };
    s.signal = { ...s.signal, tagged: tag, right, points, read: drillRead(d, right), offer };
```

In `desktop/renderer/game/controller.js`, replace:

```js
      tagged: s.signal.tagged, right: s.signal.right, read: s.signal.read, points: s.signal.points, scout, mineHtml: mine,
      range: s.screen === 'range' ? { hasCity: !!s.city } : null });
```

with:

```js
      tagged: s.signal.tagged, right: s.signal.right, read: s.signal.read, points: s.signal.points, scout, mineHtml: mine,
      range: s.screen === 'range' ? { hasCity: !!s.city } : null, offer: s.signal.offer || null });
```

In `desktop/renderer/game/controller.js`, replace:

```js
    if (go === 'training') { s.lesson = null; s.screen = 'training'; render(); return; }
```

with:

```js
    // A signal's offer: the 2 questions on that concept, or "still know it".
    if (act && act.startsWith('offer-yes:')) {
      const keys = drawConcept(s.bank, act.slice(10), historyFor(s.profile, s.bank), { bOf: difficultyOf(s.profile, s.bank) });
      const first = keys.length ? s.bank.items.get(keys[0]) : null;
      if (first) { const back = s.screen === 'range' ? 'range' : 'map'; s.signal = null; openVisit(first.lessonId, keys, { concept: act.slice(10), back }); }
      return;
    }
    if (act && act.startsWith('offer-no:')) {
      keepProfile(declineOffer(s.profile, act.slice(9), now()));
      if (s.signal) s.signal = { ...s.signal, offer: null };
      render(); return;
    }
    if (go === 'training') { s.lesson = null; s.screen = 'training'; render(); return; }
```

- [ ] **Step 5: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/renderer/game/clues.js desktop/renderer/game/views/signal.js desktop/test/game-profile-controller.test.js desktop/test/game-signal-view.test.js desktop/test/game-clues.test.js
git commit -m "Game: drills and Scout disagreements feed the profile; skipped concepts are offered again"
```

---

### Task 20: YOUR FILE in game mode, with the consent sheet (after reclaim-city lands)

**Files:**

- Modify: `desktop/renderer/game/controller.js` (imports, screen sets, `publishReady` option, shadow-root stylesheet, `profileHtml`/`exportPayload`/`closeProfile`, the `profile` routes, Escape on YOUR FILE)
- Modify: `desktop/renderer/game/views/deck.js` (rank chip), `desktop/renderer/game/views/training.js` (YOUR FILE button)
- Create: `desktop/renderer/game/profile.css`
- Test: `desktop/test/game-profile-controller.test.js` (append)

**Interfaces:**

- Consumes: Task 19's controller; `summary`, `emptyProfile` (Task 6); `buildPayload`, `publishOffered`, `PUBLISH_READY` (Task 10); `renderProfile`, `renderPublishSheet` (Task 11).
- Produces: Screen `'profile'` (in `NO_CITY_SCREENS` and `KEEP_FOCUS`); `createController({ …, publishReady = PUBLISH_READY })`; `s.profileView = { confirming, publish: { ticked, at } | null, from }`; routes `data-go="profile"`, acts `profile-close`, `profile-start-over`, `profile-start-over-yes`, `profile-start-over-no`, `profile-publish`, `pub-toggle:<id>`, `publish-close`, `publish-save` (a download named `school-profile.json`), `publish-copy` (the clipboard).

- [ ] **Step 1: Write the failing tests**

Append to `desktop/test/game-profile-controller.test.js`:

```js

test('YOUR FILE opens from the rank chip and the Training Grounds, and Escape closes it', async () => {
  const t = await setup();
  assert.match(t.html(), /data-go="profile"/);
  t.click({ 'data-go': 'profile' });
  assert.match(t.html(), /<h2 id="profile-title">YOUR FILE<\/h2>/);
  assert.ok(t.html().includes('Updates and the locked door'));
  t.key('Escape');
  assert.doesNotMatch(t.html(), /profile-title/);
});

test('Start over asks first, then clears the game’s record and nothing else', async () => {
  const t = await setup();
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-act': 'profile-start-over' });
  assert.match(t.html(), /role="alertdialog"/);
  t.click({ 'data-act': 'profile-start-over-no' });
  assert.doesNotMatch(t.html(), /role="alertdialog"/);
  t.click({ 'data-act': 'profile-start-over' });
  t.click({ 'data-act': 'profile-start-over-yes' });
  assert.deepStrictEqual(savedProfile(t.storage).missions, {});
});

test('city mode: no route builds or hands over a payload, even with the school side ready', async () => {
  const t = await setup({ mode: 'city', publishReady: true });
  t.click({ 'data-go': 'profile' });
  assert.doesNotMatch(t.html(), /profile-publish|Add to my school profile|school-profile/i);
  for (const act of ['profile-publish', 'pub-toggle:lessons', 'publish-save', 'publish-copy']) t.click({ 'data-act': act }, true);
  assert.doesNotMatch(t.html(), /pub-preview|role="dialog"/);
  assert.deepStrictEqual([t.calls.clipboard, t.calls.objectUrls, t.calls.downloads], [[], 0, []]);
});

test('standard mode, before the school side is ready: the control is absent', async () => {
  const t = await setup({ mode: 'standard' });
  t.click({ 'data-go': 'profile' });
  assert.doesNotMatch(t.html(), /profile-publish/);
  t.click({ 'data-act': 'profile-publish' });
  assert.doesNotMatch(t.html(), /pub-preview/);
});

test('standard mode, school side ready: every box unticked, the preview is the payload, Save and Copy hand it over; city mode closes the sheet', async () => {
  const t = await setup({ mode: 'standard', publishReady: true });
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-act': 'profile-publish' });
  assert.match(t.html(), /Nothing ticked yet\./);
  t.click({ 'data-act': 'pub-toggle:drills-tried' }, true);
  assert.match(t.html(), /city_drills_tried/);
  t.click({ 'data-act': 'publish-copy' });
  await tick();
  assert.strictEqual(t.calls.clipboard.length, 1);
  assert.deepStrictEqual(Object.keys(JSON.parse(t.calls.clipboard[0]).play), ['city_drills_tried']);
  t.click({ 'data-act': 'publish-save' });
  assert.deepStrictEqual(t.calls.downloads, ['school-profile.json']);
  t.mode.now = 'city';
  t.click({ 'data-act': 'pub-toggle:lessons' }, true);
  assert.doesNotMatch(t.html(), /pub-preview|profile-publish/);
});

test('both modes: every write in a session (lesson answers, a drill, a later, the file) is recipe words only', async () => {
  const loud = scan(mod('launch_agent_audit', [f('Partner safety monitor watch', 'warning', { program: '/Users/ann/stalk/spy.sh' },
    { code: 'security.launch_agent_audit.tmp' })]));
  for (const mode of ['standard', 'city']) {
    const t = await setup({ mode, doc: loud });
    t.click({ 'data-go': 'lesson:whos-on-wifi' });
    t.click({ 'data-act': `answer:${correctIndex(t.lesson('whos-on-wifi').questions[0])}` });
    t.click({ 'data-go': 'range' });
    await tick();
    t.click({ 'data-go': 'signal:drill:zoom-helper-signed' });
    t.click({ 'data-act': 'tag:threat' });
    t.click({ 'data-go': 'profile' });
    assert.ok(t.storage.writes.length >= 3, `${mode}: something was saved`);
    assert.deepStrictEqual(forbiddenWrites(t.storage), [], mode);
    assert.ok(t.storage.writes.every(([k]) => k === PROFILE_KEY || k === 'device-rescue.city-seed'), `${mode}: only the box (and the seed)`);
    assert.strictEqual(savedProfile(t.storage).missions[Object.keys(savedProfile(t.storage).missions)[0]].title, 'Partner safety monitor watch',
      `${mode}: the title is kept, disguised`);
  }
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/game-profile-controller.test.js`

Expected: FAIL: there is no `data-go="profile"` and no `profile-title` heading.

- [ ] **Step 3: Add the entry points**

In `desktop/renderer/game/views/deck.js`, replace:

```js
    <span class="stat lime"><small>RANK</small> ${esc(rank.name)}</span>
```

with:

```js
    <button type="button" class="stat lime rank-chip" data-go="profile" aria-label="Your file: ${esc(rank.name)}, ${esc(rank.points)} points"><small>RANK</small> ${esc(rank.name)} · ${esc(rank.points)}</button>
```

In `desktop/renderer/game/views/training.js`, replace:

```js
    <span class="switch"><button type="button" data-act="leave">PLAIN VIEW</button></span></header>`;
```

with:

```js
    <span class="switch"><button type="button" data-go="profile">YOUR FILE</button><button type="button" data-act="leave">PLAIN VIEW</button></span></header>`;
```

- [ ] **Step 4: Add the styles**

Create `desktop/renderer/game/profile.css`:

```css
/* YOUR FILE (views/profile.js), game style, and the publish sheet. */
.profile { display: grid; gap: 12px; padding: 16px; max-width: 1100px; margin: 0 auto; }
@media (min-width: 900px) {
  .profile { grid-template-columns: 1fr 1fr; }
  .profile > h2, .profile > footer, .profile > [role="alertdialog"] { grid-column: 1 / -1; }
}
.profile h2 { font-family: var(--font-display); color: var(--cyan); letter-spacing: 2px; margin: 0; }
.profile-lessons, .profile-skills { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.profile-lesson { display: grid; grid-template-columns: auto 1fr auto; gap: 4px 10px; align-items: center; }
.profile-lesson small { grid-column: 2 / 3; color: var(--dim); }
.profile-lesson .stamp { font-family: var(--font-display); font-size: 10px; letter-spacing: 1px; padding: 2px 6px; border: 1px solid var(--line); }
.profile-lesson.learned .stamp { color: var(--lime); border-color: rgba(198,255,0,0.4); }
.profile-lesson.refresher .stamp, .profile-lesson.worth-a-look .stamp { color: var(--amber); border-color: rgba(255,159,0,0.4); }
.meter { display: inline-flex; gap: 3px; vertical-align: middle; }
.meter i { width: 14px; height: 6px; border: 1px solid var(--line); }
.meter i.on { background: var(--cyan); }
.rank-chip { cursor: pointer; }
.sheet { position: fixed; inset: 5% 10%; overflow: auto; background: var(--charcoal); border: 1px solid var(--line); padding: 20px; z-index: 10; }
.pub-fields { list-style: none; padding: 0; display: grid; gap: 6px; }
.pub-preview { white-space: pre-wrap; font-family: var(--font-mono); font-size: 12px; background: var(--midnight); padding: 10px; max-height: 240px; overflow: auto; }
.panel.offer { margin-top: 8px; }
```

- [ ] **Step 5: Wire YOUR FILE in the controller**

In `desktop/renderer/game/controller.js`, replace:

```js
import { conceptById } from './profile/skills.js';
```

with:

```js
import { conceptById } from './profile/skills.js';
import { summary, emptyProfile } from './profile/player-profile.js';
import { buildPayload, publishOffered, PUBLISH_READY } from './profile/publish.js';
import { renderProfile, renderPublishSheet } from './views/profile.js';
```

In `desktop/renderer/game/controller.js`, replace:

```js
const NO_CITY_SCREENS = new Set([...TRAINING_SCREENS, 'range']);
const KEEP_FOCUS = new Set([...TRAINING_SCREENS, 'map', 'range']);
```

with:

```js
const NO_CITY_SCREENS = new Set([...TRAINING_SCREENS, 'range', 'profile']);
const KEEP_FOCUS = new Set([...TRAINING_SCREENS, 'map', 'range', 'profile']);
```

In `desktop/renderer/game/controller.js`, replace:

```js
export function createController({ win, storage, scoutSprite, loadGame = loadRc, loadTraining = loadLessonsHere, loadDrillBank = loadDrillsHere }) {
```

with:

```js
// `publishReady` is for tests; the app always uses PUBLISH_READY (publish.js).
export function createController({ win, storage, scoutSprite, loadGame = loadRc, loadTraining = loadLessonsHere, loadDrillBank = loadDrillsHere, publishReady = PUBLISH_READY }) {
```

In `desktop/renderer/game/controller.js`, replace:

```js
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><div class="frame" id="frame"></div>';
```

with:

```js
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><link rel="stylesheet" href="game/profile.css"><div class="frame" id="frame"></div>';
```

In `desktop/renderer/game/controller.js`, replace:

```js
    if (s.screen === 'range') return rangeHtml();
    if (s.screen === 'training') {
```

with:

```js
    if (s.screen === 'range') return rangeHtml();
    if (s.screen === 'profile') return profileHtml();
    if (s.screen === 'training') {
```

In `desktop/renderer/game/controller.js`, replace:

```js
  function screenHtml() {
```

with:

```js
  // YOUR FILE. The publish sheet exists only in standard mode, once the school
  // side is ready; if the mode turns to city while it's open, it closes.
  const canPublish = () => publishOffered(hostMode(), publishReady);
  function profileSummary() {
    const o = orderLessons(s.lessons, s.situation && s.situation.id);
    return summary(s.profile, s.bank, [...o.recommended, ...o.other].map((l) => l.id));
  }
  function profileHtml() {
    const pv = s.profileView || {};
    if (pv.publish && !canPublish()) s.profileView = { ...pv, publish: null };
    const view = s.profileView || {};
    const sum = profileSummary();
    const sheet = view.publish ? renderPublishSheet({ summary: sum, ticked: view.publish.ticked,
      payload: buildPayload(sum, view.publish.ticked, { mode: hostMode(), now: view.publish.at }) }) : '';
    return renderProfile({ summary: sum, theme: 'game', publish: canPublish(), confirming: !!view.confirming }) + sheet;
  }
  // Save a file or Copy: the person hands it over themselves. No network call.
  function exportPayload(kind) {
    const view = s.profileView;
    if (!view || !view.publish || !canPublish()) return;
    const text = buildPayload(profileSummary(), view.publish.ticked, { mode: hostMode(), now: view.publish.at });
    if (!text) return;
    if (kind === 'copy') { Promise.resolve().then(() => win.navigator.clipboard.writeText(text)).catch(() => {}); return; }
    const url = win.URL.createObjectURL(new win.Blob([text], { type: 'application/json' }));
    const a = doc0.createElement('a');
    a.href = url;
    a.download = 'school-profile.json';
    a.click();
    win.setTimeout(() => win.URL.revokeObjectURL(url), 0);
  }
  function closeProfile() {
    const from = (s.profileView && s.profileView.from) || 'map';
    s.profileView = null;
    s.screen = from === 'lesson' && !s.lesson ? 'training' : from;
    render();
  }

  function screenHtml() {
```

In `desktop/renderer/game/controller.js`, replace:

```js
    if (go && go.startsWith('lesson:')) { startVisit(go.slice(7)); return; }
```

with:

```js
    if (go && go.startsWith('lesson:')) { startVisit(go.slice(7), s.screen === 'profile' ? { back: 'profile' } : {}); return; }
```

In `desktop/renderer/game/controller.js`, replace:

```js
    // A signal's offer: the 2 questions on that concept, or "still know it".
```

with:

```js
    // YOUR FILE, its Start over, and its publish sheet.
    if (go === 'profile') {
      s.profileView = { confirming: false, publish: null, from: s.screen === 'profile' ? 'map' : s.screen };
      s.signal = null; s.screen = 'profile'; render(); return;
    }
    if (act === 'profile-close') { closeProfile(); return; }
    if (act === 'profile-start-over') { s.profileView = { ...(s.profileView || {}), confirming: true }; render(); return; }
    if (act === 'profile-start-over-no') { s.profileView = { ...(s.profileView || {}), confirming: false }; render(); return; }
    if (act === 'profile-start-over-yes') {
      keepProfile(emptyProfile(now()));
      s.profileView = { ...(s.profileView || {}), confirming: false };
      render(); return;
    }
    if (act === 'profile-publish') {
      if (canPublish()) { s.profileView = { ...(s.profileView || {}), publish: { ticked: [], at: now() } }; render(); }
      return;
    }
    if (act && act.startsWith('pub-toggle:')) {
      const view = s.profileView;
      if (!view || !view.publish) return;
      const id = act.slice(11);
      const rest = view.publish.ticked.filter((x) => x !== id);
      s.profileView = { ...view, publish: { ...view.publish, ticked: el.checked ? [...rest, id] : rest } };
      render(); return;
    }
    if (act === 'publish-close') { if (s.profileView) s.profileView = { ...s.profileView, publish: null }; render(); return; }
    if (act === 'publish-save') { exportPayload('file'); return; }
    if (act === 'publish-copy') { exportPayload('copy'); return; }
    // A signal's offer: the 2 questions on that concept, or "still know it".
```

In `desktop/renderer/game/controller.js`, replace:

```js
  // Escape closes the Signal or Noise panel, like BACK TO THE DECK. Inside a
```

with:

```js
  // Escape on YOUR FILE closes what's on top: the publish sheet, the Start
  // over question, then the screen itself.
  frame.addEventListener('keydown', (e) => {
    if (!e || e.key !== 'Escape' || s.screen !== 'profile') return;
    if (typeof e.preventDefault === 'function') e.preventDefault();
    const view = s.profileView || {};
    if (view.publish) { s.profileView = { ...view, publish: null }; render(); return; }
    if (view.confirming) { s.profileView = { ...view, confirming: false }; render(); return; }
    closeProfile();
  });
  // Escape closes the Signal or Noise panel, like BACK TO THE DECK. Inside a
```

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS, including "city mode: no route builds or hands over a payload…" and "both modes: every write in a session … is recipe words only".

- [ ] **Step 7: Commit**

```bash
git add desktop/renderer/game/controller.js desktop/renderer/game/views/deck.js desktop/renderer/game/views/training.js desktop/renderer/game/profile.css desktop/test/game-profile-controller.test.js
git commit -m "Game: YOUR FILE, with Start over and a consent sheet that never exists in city mode"
```

---

### Task 21: "Your progress" in plain view (after reclaim-city lands)

**Files:**

- Create: `desktop/renderer/game/profile/plain-panel.js`
- Create: `desktop/renderer/profile.css`
- Modify: `desktop/renderer/index.html` (stylesheet, button and dialog on the results screen, module script)
- Modify: `desktop/renderer/game/controller.js` (API `reloadProfile`)
- Modify: `desktop/test/stylesheets.test.js` (the two new sheets)
- Test: `desktop/test/profile-plain-panel.test.js`

**Interfaces:**

- Consumes: `loadLessons` (`training.js`), `loadDrills` (`drills.js`), `buildBank` (Task 5); `loadProfile`, `saveProfile`, `profileSeed`, `summary`, `emptyProfile` (Task 6); `buildPayload`, `publishOffered`, `PUBLISH_READY` (Task 10); `renderProfile`, `renderPublishSheet` (Task 11); `win.RescueHost.mode()`, `win.DisplayMode`, `win.RescueGame.reloadProfile()`.
- Produces: `attachPlainPanel({ win, storage, loadBank?, publishReady? }) -> { open } | null`, auto-attached in the browser when `#btn-your-progress` exists; elements `#btn-your-progress`, `<dialog id="progress-dialog">`, `#progress-dialog-body`; `RescueGame.reloadProfile()`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/profile-plain-panel.test.js`:

```js
// "Your progress" in plain view, against stub elements (no DOM library).
const test = require('node:test');
const assert = require('node:assert');
const { recordingStore } = require('./disk-words.js');
const { savedProfile } = require('./profile-read.js');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
function el(id) {
  const listeners = {};
  return { id, innerHTML: '', open: false, focused: 0, attrs: {},
    addEventListener: (t, fn) => { (listeners[t] = listeners[t] || []).push(fn); },
    fire: (t, ev = {}) => (listeners[t] || []).forEach((fn) => fn(ev)),
    showModal() { this.open = true; }, close() { this.open = false; this.fire('close'); },
    focus() { this.focused += 1; }, setAttribute(k, v) { this.attrs[k] = v; } };
}
async function setup({ mode = 'standard', publishReady = false, storage = recordingStore({ 'device-rescue.game.v1': JSON.stringify(V3) }) } = {}) {
  const [{ attachPlainPanel }, { buildBank }] = await Promise.all([
    import('../renderer/game/profile/plain-panel.js'), import('../renderer/game/profile/item-bank.js')]);
  const els = { 'btn-your-progress': el('b'), 'progress-dialog': el('d'), 'progress-dialog-body': el('body'), 'profile-title': el('h') };
  const calls = { reload: 0, clipboard: [] };
  const win = { document: { getElementById: (id) => els[id] || null, createElement: () => ({ click() {} }) },
    RescueHost: { mode: () => mode }, RescueGame: { reloadProfile: () => { calls.reload += 1; } },
    navigator: { clipboard: { writeText: async (t) => { calls.clipboard.push(t); } } } };
  const panel = attachPlainPanel({ win, storage, loadBank: async () => buildBank(LESSONS, DRILLS), publishReady });
  const click = (act, checked = false) => els['progress-dialog-body'].fire('click', { target: { closest: () => ({ checked, getAttribute: () => act }) } });
  return { els, calls, panel, click, storage, body: () => els['progress-dialog-body'].innerHTML };
}

test('the button opens a modal dialog with the plain view of the profile, its heading focused', async () => {
  const t = await setup();
  t.els['btn-your-progress'].fire('click');
  await tick(); await tick();
  assert.strictEqual(t.els['progress-dialog'].open, true);
  assert.match(t.body(), /<h2 id="profile-title">Your progress<\/h2>/);
  assert.ok(t.body().includes('Points: 340 (level 3 of 5)'));
  assert.strictEqual(t.els['profile-title'].focused, 1);
  t.click('profile-close');
  assert.strictEqual(t.els['progress-dialog'].open, false);
  assert.strictEqual(t.els['btn-your-progress'].focused, 1, 'focus goes back to the button');
});

test('Start over in plain view asks first, saves through the profile, and tells the game to read it again', async () => {
  const t = await setup();
  t.els['btn-your-progress'].fire('click');
  await tick(); await tick();
  t.click('profile-start-over');
  assert.match(t.body(), /role="alertdialog"/);
  t.click('profile-start-over-yes');
  assert.strictEqual(savedProfile(t.storage).rank.points, 0);
  assert.strictEqual(t.calls.reload, 1);
});

test('city mode: no publish control, and its actions do nothing', async () => {
  const t = await setup({ mode: 'city', publishReady: true });
  t.els['btn-your-progress'].fire('click');
  await tick(); await tick();
  assert.doesNotMatch(t.body(), /profile-publish/);
  t.click('profile-publish'); t.click('pub-toggle:lessons', true); t.click('publish-copy');
  await tick();
  assert.doesNotMatch(t.body(), /pub-preview/);
  assert.deepStrictEqual(t.calls.clipboard, []);
});

test('missing elements: nothing is attached and nothing throws', async () => {
  const { attachPlainPanel } = await import('../renderer/game/profile/plain-panel.js');
  assert.strictEqual(attachPlainPanel({ win: { document: { getElementById: () => null } }, storage: recordingStore() }), null);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-plain-panel.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `renderer/game/profile/plain-panel.js`.

- [ ] **Step 3: Write the panel**

Create `desktop/renderer/game/profile/plain-panel.js`:

```js
// "Your progress" in plain view: the same profile as YOUR FILE, in a dialog
// opened from the results screen, with plain words. Reads the profile fresh
// each time it opens (the game may have written since); writes only through
// PlayerProfile.saveProfile, and tells the game to read it again.
import { loadLessons } from '../training.js';
import { loadDrills } from '../drills.js';
import { buildBank } from './item-bank.js';
import { loadProfile, saveProfile, profileSeed, summary, emptyProfile } from './player-profile.js';
import { buildPayload, publishOffered, PUBLISH_READY } from './publish.js';
import { renderProfile, renderPublishSheet } from '../views/profile.js';

// Specifiers resolve the way the game's own loaders expect: lessons against
// training.js, drills against drills.js.
async function defaultLoadBank() {
  const lessonBase = new URL('../training.js', import.meta.url).href;
  const drillBase = new URL('../drills.js', import.meta.url).href;
  const [lessons, drills] = await Promise.all([
    loadLessons((spec) => import(new URL(spec, lessonBase).href)),
    loadDrills((spec) => import(new URL(spec, drillBase).href)),
  ]);
  return buildBank(lessons, drills);
}

export function attachPlainPanel({ win, storage, loadBank = defaultLoadBank, publishReady = PUBLISH_READY }) {
  const doc = win.document;
  const button = doc.getElementById('btn-your-progress');
  const dialog = doc.getElementById('progress-dialog');
  const body = doc.getElementById('progress-dialog-body');
  if (!button || !dialog || !body) return null;
  const now = () => new Date().toISOString();
  const mode = () => (win.RescueHost && typeof win.RescueHost.mode === 'function' ? win.RescueHost.mode() : 'city');
  let bankP = null;
  const bank = () => (bankP = bankP || Promise.resolve().then(loadBank).catch(() => buildBank([], [])));
  const st = { profile: null, bank: null, confirming: false, publish: null };

  function draw() {
    const sum = summary(st.profile, st.bank);
    const offered = publishOffered(mode(), publishReady);
    if (!offered) st.publish = null;
    const sheet = st.publish ? renderPublishSheet({ summary: sum, ticked: st.publish.ticked, theme: 'plain',
      payload: buildPayload(sum, st.publish.ticked, { mode: mode(), now: st.publish.at }) }) : '';
    body.innerHTML = renderProfile({ summary: sum, theme: 'plain', publish: offered, confirming: st.confirming }) + sheet;
  }

  async function open() {
    st.bank = await bank();
    st.profile = loadProfile(storage, now());
    st.confirming = false;
    st.publish = null;
    draw();
    if (!dialog.open) dialog.showModal();
    const h = doc.getElementById('profile-title');
    if (h) { h.setAttribute('tabindex', '-1'); h.focus(); }
  }

  function handOver(kind) {
    if (!st.publish || !publishOffered(mode(), publishReady)) return;
    const text = buildPayload(summary(st.profile, st.bank), st.publish.ticked, { mode: mode(), now: st.publish.at });
    if (!text) return;
    if (kind === 'copy') { Promise.resolve().then(() => win.navigator.clipboard.writeText(text)).catch(() => {}); return; }
    const url = win.URL.createObjectURL(new win.Blob([text], { type: 'application/json' }));
    const a = doc.createElement('a');
    a.href = url;
    a.download = 'school-profile.json';
    a.click();
    win.setTimeout(() => win.URL.revokeObjectURL(url), 0);
  }

  button.addEventListener('click', () => { open(); });
  // Closing (the Close button, or Escape) puts focus back where it came from.
  dialog.addEventListener('close', () => { if (typeof button.focus === 'function') button.focus(); });
  body.addEventListener('click', (e) => {
    const el = e.target && typeof e.target.closest === 'function' ? e.target.closest('[data-act]') : null;
    if (!el || !st.profile) return;
    const act = el.getAttribute('data-act');
    if (act === 'profile-close') { dialog.close(); return; }
    if (act === 'profile-start-over') { st.confirming = true; draw(); return; }
    if (act === 'profile-start-over-no') { st.confirming = false; draw(); return; }
    if (act === 'profile-start-over-yes') {
      st.profile = emptyProfile(now());
      saveProfile(storage, st.profile, { seed: profileSeed(storage, win.DisplayMode), mode: mode() });
      if (win.RescueGame && typeof win.RescueGame.reloadProfile === 'function') win.RescueGame.reloadProfile();
      st.confirming = false;
      draw();
      return;
    }
    if (act === 'profile-publish') { if (publishOffered(mode(), publishReady)) { st.publish = { ticked: [], at: now() }; draw(); } return; }
    if (act.startsWith('pub-toggle:') && st.publish) {
      const id = act.slice(11);
      const rest = st.publish.ticked.filter((x) => x !== id);
      st.publish = { ...st.publish, ticked: el.checked ? [...rest, id] : rest };
      draw();
      return;
    }
    if (act === 'publish-close') { st.publish = null; draw(); return; }
    if (act === 'publish-save') { handOver('file'); return; }
    if (act === 'publish-copy') { handOver('copy'); }
  });
  return { open };
}

function safeStorage() {
  try { return window.localStorage; } catch (_) { return null; }
}

if (typeof window !== 'undefined' && window.document && window.document.getElementById('btn-your-progress')) {
  attachPlainPanel({ win: window, storage: safeStorage() });
}
```

- [ ] **Step 4: Add the styles**

Create `desktop/renderer/profile.css`:

```css
/* "Your progress" (views/profile.js, plain theme) in its dialog on the results screen. */
.results-progress-link { margin: 8px 0; }
.progress-dialog { max-width: 760px; width: calc(100% - 32px); border: 1px solid var(--border); border-radius: 12px; padding: 0; background: var(--surface); color: var(--text); }
.progress-dialog::backdrop { background: rgba(0, 0, 0, 0.35); }
.profile-plain { display: grid; gap: 12px; padding: 20px; }
.profile-plain h2 { margin: 0; }
.profile-plain .panel { border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: var(--surface-muted); }
.profile-plain .label { font-size: 1rem; margin: 0 0 6px; }
.profile-plain ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.profile-plain .stamp { display: inline-block; min-width: 9em; color: var(--text-muted); }
.profile-plain small { display: block; color: var(--text-muted); }
.profile-plain .meter { display: inline-flex; gap: 3px; vertical-align: middle; }
.profile-plain .meter i { width: 14px; height: 6px; border: 1px solid var(--border); }
.profile-plain .meter i.on { background: var(--brand); }
.profile-plain .row, .progress-dialog .sheet .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.profile-plain button, .progress-dialog .sheet button { font: inherit; padding: 6px 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; }
.profile-plain button:focus-visible, .progress-dialog .sheet button:focus-visible { outline: 3px solid var(--focus-ring); outline-offset: 2px; }
.progress-dialog .sheet { padding: 20px; border-top: 1px solid var(--border); }
.progress-dialog .pub-preview { white-space: pre-wrap; background: var(--surface-muted); padding: 10px; border-radius: 6px; max-height: 240px; overflow: auto; }
```

- [ ] **Step 5: Wire it into the page and the game**

In `desktop/renderer/game/controller.js`, replace:

```js
    // The display mode changed: save once now, so city mode retires the old store at once.
    profileModeChanged() { persist(); },
```

with:

```js
    // The display mode changed: save once now, so city mode retires the old store at once.
    profileModeChanged() { persist(); },
    // Plain view changed the profile (Start over): read it again before the next save.
    reloadProfile() {
      s.profile = loadProfile(storage, now());
      s.progress = toProgress(s.profile, s.bank);
      if (s.screen === 'profile') render();
    },
```

In `desktop/renderer/index.html`, replace:

```html
  <link rel="stylesheet" href="game-fonts.css" />
```

with:

```html
  <link rel="stylesheet" href="game-fonts.css" />
  <link rel="stylesheet" href="profile.css" />
```

In `desktop/renderer/index.html`, replace:

```html
            <button id="btn-see-city" class="btn btn--game" type="button">See it as a city</button>
          </p>
```

with:

```html
            <button id="btn-see-city" class="btn btn--game" type="button">See it as a city</button>
          </p>
          <p class="results-progress-link">
            <button id="btn-your-progress" class="btn btn--secondary" type="button">Your progress</button>
          </p>
          <dialog id="progress-dialog" class="progress-dialog" aria-labelledby="profile-title">
            <div id="progress-dialog-body"></div>
          </dialog>
```

In `desktop/renderer/index.html`, replace:

```html
  <script type="module" src="game/boot.js"></script>
```

with:

```html
  <script type="module" src="game/boot.js"></script>
  <script type="module" src="game/profile/plain-panel.js"></script>
```

In `desktop/test/stylesheets.test.js`, replace:

```js
const SHEETS = ['renderer/styles.css', 'renderer/game/game.css', 'renderer/game-fonts.css'];
```

with:

```js
const SHEETS = ['renderer/styles.css', 'renderer/game/game.css', 'renderer/game-fonts.css', 'renderer/profile.css', 'renderer/game/profile.css'];
```

- [ ] **Step 6: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS, including `app-identity.test.js` (the page still never says "Device Rescue") and `stylesheets.test.js` for both new sheets.

- [ ] **Step 7: Check it in the app**

Run: `cd desktop && npm start`. Finish a checkup in plain view, press **Your progress**: the dialog opens with its heading focused, Tab stays inside it, Escape closes it and focus returns to the button. Open game mode, press the rank chip: YOUR FILE shows the same lessons and counts.

- [ ] **Step 8: Commit**

```bash
git add desktop/renderer/game/profile/plain-panel.js desktop/renderer/profile.css desktop/renderer/index.html desktop/renderer/game/controller.js desktop/test/stylesheets.test.js desktop/test/profile-plain-panel.test.js
git commit -m "Plain view: Your progress, the same profile in plain words"
```

---

### Task 22: Open publishing (only after the school-repo prerequisites)

**Files:**

- Modify: `desktop/renderer/game/profile/publish.js` (`PUBLISH_READY`)
- Modify: `desktop/test/profile-publish.test.js`
- Modify: `docs/trust-and-safety.md` ("Nothing is sent anywhere unless you opt in")

**Interfaces:**

- Consumes: Tasks 20 and 21; the four school-repo prerequisites, done and released in `~/src/themultiverse.school`.
- Produces: `PUBLISH_READY = true`: the control appears in standard mode only.

- [ ] **Step 1: Confirm the prerequisites**

In `~/src/themultiverse.school` (read only from here), confirm all four: `grep -n "city_lessons_learned\|city_skills\|city_drills_right\|city_drills_tried\|city_rank_level" tools/shared/profile.js` shows the five fields in `SHAPE`; the Profile Viewer's import calls `MVSync.mergeProfiles` (not `MVProfile.fromJSON` alone); `tools/shared/profile.contract.yml` exists with the five fields `derived` and `sharing.js` refuses `never`; `grep -n RELAY_HOST tools/profile_viewer/src/pair.js` shows the `sync.themultiverse.school` host over `wss://`. If any is missing, stop here.

- [ ] **Step 2: Update the test first**

In `desktop/test/profile-publish.test.js`, replace:

```js
  assert.strictEqual(PUBLISH_READY, false, 'flip only after the school-repo prerequisites in the plan land');
  assert.strictEqual(publishOffered('standard'), false);
```

with:

```js
  assert.strictEqual(PUBLISH_READY, true, 'on: the school-repo prerequisites in the plan have landed');
  assert.strictEqual(publishOffered('standard'), true);
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `cd desktop && node --test test/profile-publish.test.js`

Expected: FAIL: `PUBLISH_READY` is still false.

- [ ] **Step 4: Flip the switch and say so in the docs**

In `desktop/renderer/game/profile/publish.js`, replace:

```js
export const PUBLISH_READY = false;
```

with:

```js
export const PUBLISH_READY = true;
```

In `docs/trust-and-safety.md`, replace:

```markdown
`[category/module] (severity) title: description` — and nothing else. See
[Privacy](privacy.md#what-the-ai-layer-sends) for the full payload.
```

with:

```markdown
`[category/module] (severity) title: description` — and nothing else. See
[Privacy](privacy.md#what-the-ai-layer-sends) for the full payload.

The game's progress record never leaves the computer by itself, and the app
makes no network call for it. In standard mode, **Add to my school profile**
opens a sheet listing five things that could be added to a Multiverse School
profile: how many lessons are learned, practice drills right, practice drills
tried, the rank as a level from 1 to 5, and skill levels. Every box starts
unticked, and the sheet shows the exact text. The person saves it as a file or
copies it, then adds it in the school's Profile Viewer themselves. It is never
offered in city mode, and it never includes checkup results, missions, paths,
answers, or anything about the computer.
```

- [ ] **Step 5: Run the whole suite**

Run: `cd desktop && npm test`

Expected: PASS. The controller and plain-panel tests pass `publishReady` explicitly, so their city-mode and not-ready cases still hold.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/profile/publish.js desktop/test/profile-publish.test.js docs/trust-and-safety.md
git commit -m "Profile: offer Add to my school profile in standard mode"
```

---

## Self-Review

**Spec coverage.**

| Requirement | Task |
|---|---|
| One record per concept: learned / skipped / not yet, with evidence (each item, right or wrong, when) | 6 (`concepts[*].seen`, `conceptState`) |
| Drill calibration, rank, missions in the same record | 6 (`drills.calls`, `recent`, `rank`, `missions`), 19 |
| Migrate from `device-rescue.game.v1` v1-v3 without losing progress; old key kept as backup | 6 (`salvage`, `loadProfile`), 18 |
| Disguised as recipe-like data in both modes; per-install seeded vocabulary; FORBIDDEN_ON_DISK; round-trip and nothing-literal tests | 1, 6, 18, 20 |
| IRT model for small data; online update; per-item difficulty with priors; learned = estimate above a threshold with minimum evidence; maths and known values | 2, "The maths" |
| SKIPPED re-asked on a wrong drill, a Scout disagreement, or repeated "?" | 6 (gaps, `shouldOffer`), 19 (drill, call); "?" API only (the "?" control is teach-once's) |
| Drills and Signal-or-Noise calls feed the same estimates where they map to a concept | 4 (`DRILL_CONCEPTS`), 6 (`recordDrillCall`), 19 |
| Every lesson question has ≥ 3 variants, gated for accuracy, no time words or diagnosis phrases | 5, 7-9, 12-17 |
| Lessons draw a few items adaptively; learned from the estimate; the lesson-done fix maps onto evidence | 5 (`drawLessonVisit`), 18 |
| Profile screen in game and plain view, accessible | 11, 20, 21 |
| MVProfile publishing: opt-in, consent screen naming the fields, school contract, never in stealth, never about the computer; school-side gaps as prerequisites | 10, 11, 20, 21, 22; "School-repo prerequisites" |

**Placeholder scan.** Every code step carries the full file or the exact before/after text; the content tasks carry each lesson file whole. No "TBD", no "similar to Task N".

**Type consistency.** `buildBank` items carry `{ key, family, concept, lessonId, kind, first, level, c }` everywhere they're read (`player-profile.js`, `controller.js`, `plain-panel.js`). `history[c] = { mean, learned, recent, seen }` is produced by `historyFor` and read by `drawLessonVisit`/`drawConcept`. Acts and routes match between `views/profile.js`, `views/signal.js` and the controller (`profile-*`, `pub-toggle:`, `publish-*`, `offer-yes:`/`offer-no:`). `PROFILE_KEY` is `device-rescue.recipe-box.v1` in `player-profile.js` and `profile-read.js`.

**Review Focus.** The five lines above each have a test in the task that owns the code (Tasks 6 and 18).

**Known limits, out of scope here.** `device-rescue.game.scan-confirmed.v1` (verified-missions) is another literal store this plan doesn't encode. Reclaim City's own account state (`rc.saveState`) is unchanged. The teach-once "?" and "I know this" controls aren't built; `markKnown`, `markLessonKnown` and `recordGap(…, 'reopen', …)` are ready for them.
