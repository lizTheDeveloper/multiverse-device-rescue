// The player profile: one record of what the person has learned, skipped or
// not yet met, the evidence behind it, drill calibration, rank, the deck and
// missions. The only code that reads or writes it on disk. Stored as a recipe
// box (recipe-box.js) in every display mode, so the disk looks the same
// whichever mode is used. No network code, ever.
//
// State shown on screen is derived from the record, never stored (MVProfile's
// rule): see conceptState and lessonState.
import { encode, decode, seedOf, validSeed, peek } from './recipe-box.js';
import { estimate, isLearned, levelB, updateDifficulty, PRIOR, BEFORE_PRIOR, MIN_RESPONSES } from './irt.js';
import { lessonsWithConcept } from './item-bank.js';
import { CONCEPTS, SKILLS, CLUE_CONCEPTS, isHidden, conceptById } from './skills.js';
import { STORE_KEY as OLD_KEY, TAGS, SWEEP_FIELDS } from '../progress.js';
import { MONITORING_MODULES, RANKS, rankOf, sweepPercent, MAX_SWEEPS } from '../ledger.js';

export const PROFILE_KEY = 'device-rescue.recipe-box.v1';
// Boxes that wouldn't decode are moved here (see the storage section).
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

// `older`: answers older than `seen`, in order, without their time or source:
// { keys: [itemKey, …], seq: [keyIndex * 2 + x, …] }. Written only when a box
// is over MAX_BOX_CHARS (see boxText). The estimate reads them exactly as it
// reads `seen`, so compacting never changes a concept's state.
function olderPairs(rec) {
  const o = rec && rec.older;
  return o ? o.seq.map((v) => [o.keys[v >> 1], v & 1]) : [];
}
function makeOlder(pairs) {
  if (!pairs.length) return null;
  const keys = [...new Set(pairs.map(([k]) => k))];
  const at = new Map(keys.map((k, i) => [k, i]));
  return { keys, seq: pairs.map(([k, x]) => at.get(k) * 2 + x) };
}
// Every answer on a concept, oldest first, as [itemKey, x].
const answersOf = (rec) => [...olderPairs(rec), ...((rec && rec.seen) || []).map(([k, x]) => [k, x])];

// Keeps at most MAX_SEEN answers in all, dropping the oldest (from `older` first).
function windowed(older, seen) {
  let over = older.length + seen.length - MAX_SEEN;
  const o = over > 0 ? older.slice(Math.min(over, older.length)) : older;
  over -= older.length - o.length;
  return { older: o, seen: over > 0 ? seen.slice(over) : seen };
}

function salvageOlder(o) {
  if (!plainObject(o) || !Array.isArray(o.keys) || !o.keys.every(str) || !Array.isArray(o.seq)) return [];
  return o.seq.filter((v) => count(v) && v >> 1 < o.keys.length).map((v) => [o.keys[v >> 1], v & 1]);
}

function salvageConcept(r) {
  if (!plainObject(r)) return null;
  const out = {};
  const seen = (Array.isArray(r.seen) ? r.seen : []).filter((e) => Array.isArray(e) && e.length === 4 && str(e[0]) && (e[1] === 0 || e[1] === 1) && str(e[2]) && SOURCES.has(e[3]));
  const w = windowed(salvageOlder(r.older), seen);
  const older = makeOlder(w.older);
  if (older) out.older = older;
  if (w.seen.length) out.seen = w.seen.map((e) => [e[0], e[1], e[2], e[3]]);
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
    let lost = 0;
    for (const [id, r] of entries(raw.concepts)) { const c = salvageConcept(r); if (c) p.concepts[id] = c; else lost += 1; }
    for (const [k, r] of entries(raw.items)) if (plainObject(r) && Number.isFinite(r.b) && count(r.n)) p.items[k] = { b: r.b, n: r.n }; else lost += 1;
    for (const [id, r] of entries(raw.lessons)) { const l = salvageLessonRecord(r); if (l) p.lessons[id] = l; else lost += 1; }
    if (lost) changes.push(`records: ${lost} dropped`);
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
//
// Nothing stored is dropped without a copy, or without saying so:
// - a box that won't decode (damaged, or from a newer build) is copied to a
//   spare slot before anything overwrites it. There are SPARE_KEYS.length
//   slots; when they are full the oldest is freed (and that is reported);
// - a box that decodes but had records it couldn't read gets one slot of its
//   own (SALVAGED_KEY), overwritten each time that happens;
// - the old literal document (OLD_KEY) is never changed. In standard mode it
//   stays where it is, for an older build. In city mode it is first copied,
//   disguised like the box, to BACKUP_KEY, and removed only once that copy
//   reads back exactly.
// Anything that goes wrong is passed, once, to the caller's `onProblem(code)`.
//
// Downgrades (for the release notes):
// - after city mode has saved, an older build finds no old document (only the
//   disguised backup, which it can't read) and starts fresh;
// - in standard mode an older build reads and writes the old document, frozen
//   at the upgrade. Back on this build, the box is read first, so progress
//   made in the older build meanwhile is outranked by the box and not merged.
export const SPARE_KEYS = Object.freeze([SPARE_KEY, `${SPARE_KEY}.2`]);
export const SALVAGED_KEY = 'device-rescue.recipe-box.v1.salvaged';
export const BACKUP_KEY = 'device-rescue.recipe-box.v1.backup';
// Each slot this code writes holds at most this many characters. The codec
// makes the text about 13 times the JSON; a box over it is written with older
// answers compacted (see boxText). Worst case for everything here: the box,
// the salvaged slot, the spares and the backup, each full, STORAGE_WORST in
// all, well under Chromium's ~5M characters per origin.
export const MAX_BOX_CHARS = 600000;
export const STORAGE_WORST = (3 + SPARE_KEYS.length) * MAX_BOX_CHARS;
// Answers kept with their time and source when a box is compacted.
const KEEP_LITERAL = 8;
const FAILURES = new Set(['encode', 'too-big', 'spare', 'write']);

function read(storage, key) {
  try { return storage ? storage.getItem(key) : null; } catch (_) { return null; }
}
function write(storage, key, text) {
  try { storage.setItem(key, text); } catch (_) { return false; }
  return read(storage, key) === text;
}

// Problems already reported, per storage, so each is said once.
const reported = new WeakMap();
function report(storage, onProblem, code) {
  if (typeof onProblem !== 'function') return;
  const key = storage && typeof storage === 'object' ? storage : report;
  if (!reported.has(key)) reported.set(key, new Set());
  const said = reported.get(key);
  if (said.has(code)) return;
  said.add(code);
  try { onProblem(code); } catch (_) { /* the caller's problem */ }
}
function clearFailures(storage) {
  const said = storage && typeof storage === 'object' ? reported.get(storage) : null;
  if (said) for (const c of FAILURES) said.delete(c);
}

// A cheap check that `text` is a box this version wrote: its head only.
const isOurBox = (text) => peek(text, 13) === `{"version":${VERSION},`;

// Copies an undecodable box to a spare slot, freeing the oldest when all are
// taken. { ok, problem }: ok is false only when nothing could be written.
function stash(storage, text) {
  if (SPARE_KEYS.some((k) => read(storage, k) === text)) return { ok: true, problem: null };
  if (text.length > MAX_BOX_CHARS) return { ok: true, problem: 'unreadable-too-big' };
  let slot = SPARE_KEYS.find((k) => read(storage, k) === null);
  let problem = null;
  if (!slot) {
    for (let i = 0; i + 1 < SPARE_KEYS.length; i += 1) {
      if (!write(storage, SPARE_KEYS[i], read(storage, SPARE_KEYS[i + 1]))) return { ok: false, problem: 'spare' };
    }
    slot = SPARE_KEYS[SPARE_KEYS.length - 1];
    problem = 'spare-full';
  }
  return write(storage, slot, text) ? { ok: true, problem } : { ok: false, problem: 'spare' };
}

// The old document's text: the literal key, else the disguised backup city mode made.
function oldText(storage) {
  const literal = read(storage, OLD_KEY);
  if (literal) return literal;
  const kept = decode(read(storage, BACKUP_KEY));
  return str(kept) && kept ? kept : null;
}

// Never throws. A box that won't decode is kept aside (see stash); then the
// old document is read, as on a first run. Records a v4 box held that could
// not be read are listed in a migration entry, and that box is kept in
// SALVAGED_KEY.
export function loadProfile(storage, now, { onProblem } = {}) {
  const say = (code) => report(storage, onProblem, code);
  const box = read(storage, PROFILE_KEY);
  if (box) {
    const v = decode(box);
    if (plainObject(v) && v.version === VERSION) {
      const { profile, changes } = salvage(v, now);
      if (changes.length) {
        if (box.length > MAX_BOX_CHARS || !write(storage, SALVAGED_KEY, box)) say('salvaged');
        profile.migrations = [...profile.migrations, { v: VERSION, from: VERSION, at: String(now), changes }].slice(-MAX_MIGRATIONS);
      }
      return profile;
    }
    const s = stash(storage, box);
    if (s.problem) say(s.problem);
  }
  // First run of this build (or the box was unreadable): migrate the old document.
  const old = oldText(storage);
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

// The box's text. Over MAX_BOX_CHARS, each concept keeps its newest
// KEEP_LITERAL answers as they are and the rest compacted into `older`
// (order and right/wrong kept, time and source dropped), so no estimate and
// no state changes; then migrations are cut to the last 5. Throws when it
// can't be encoded. May still be over the limit: the caller checks.
export function boxText(p, seed) {
  const text = encode(p, seed);
  if (text.length <= MAX_BOX_CHARS) return text;
  const concepts = obj(Object.entries(p.concepts).map(([id, c]) => {
    const seen = c.seen || [];
    const cut = Math.max(0, seen.length - KEEP_LITERAL);
    if (!cut) return [id, c];
    const rec = { ...c, older: makeOlder([...olderPairs(c), ...seen.slice(0, cut).map(([k, x]) => [k, x])]), seen: seen.slice(cut) };
    return [id, rec];
  }));
  return encode({ ...p, concepts, migrations: p.migrations.slice(-5) }, seed);
}

// In city mode: copy the old literal document, disguised, then remove it.
// Returns a problem code when the literal document had to stay.
function retireOld(storage, seed) {
  const old = read(storage, OLD_KEY);
  if (old === null) return null;
  let kept = decode(read(storage, BACKUP_KEY)) === old;
  if (!kept) {
    let text = null;
    try { text = encode(old, seed); } catch (_) { text = null; }
    kept = !!text && text.length <= MAX_BOX_CHARS && write(storage, BACKUP_KEY, text) && decode(read(storage, BACKUP_KEY)) === old;
  }
  if (!kept) return 'old-kept';
  try { storage.removeItem(OLD_KEY); } catch (_) { return 'old-kept'; }
  return null;
}

// Writes the box. Returns whether it was written; when it wasn't, nothing was
// removed, and `onProblem` hears why (once).
export function saveProfile(storage, profile, { seed, mode, onProblem } = {}) {
  const say = (code) => report(storage, onProblem, code);
  let text;
  try { text = boxText(salvage(profile, profile && profile.since).profile, seed); } catch (_) { say('encode'); return false; }
  if (text.length > MAX_BOX_CHARS) { say('too-big'); return false; }
  const current = read(storage, PROFILE_KEY);
  if (current && current !== text && !isOurBox(current)) {
    const s = stash(storage, current);
    if (s.problem) say(s.problem);
    if (!s.ok) return false;
  }
  try { storage.setItem(PROFILE_KEY, text); } catch (_) { say('write'); return false; }
  clearFailures(storage);
  if (mode === 'city') { const r = retireOld(storage, seed); if (r) say(r); }
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
  const responses = answersOf(conceptRec(p, conceptId))
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
  // A lesson finished under the old rule is stored evidence: it stays learned
  // until the concept has MIN_RESPONSES answers of its own. From then on the
  // IRT rule decides (BEFORE_PRIOR, and treated as learned before, as irt.js
  // defines wasLearned). Never "learned" from an empty estimate otherwise.
  if (before && est.n < MIN_RESPONSES) return 'learned';
  if (isLearned(est, !!rec.learnedAt || !!before)) return 'learned';
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
  const answers = l.concepts.flatMap((c) => answersOf(conceptRec(p, c)).filter(([key]) => mine.has(key)));
  return { state, done: state === 'learned' || !!(p.lessons[lessonId] && p.lessons[lessonId].visited),
    answered: new Set(answers.map(([key]) => key)).size, right: answers.filter(([, x]) => x === 1).length,
    concepts: l.concepts.map((c, i) => ({ id: c, state: states[i] })) };
}
export const LESSON_STATES = LESSON_ORDER;

// What the adaptive draw needs to know about each concept.
export function historyFor(p, bank) {
  const out = {};
  for (const c of bank.concepts.keys()) {
    const seen = answersOf(conceptRec(p, c));
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
  return !answersOf(conceptRec(p, it.concept)).some(([key, x]) => x === 1 && bank.items.has(key) && bank.items.get(key).family === it.family);
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
  const w = windowed(olderPairs(rec), [...(rec.seen || []), [itemKey, right ? 1 : 0, String(now), src]]);
  rec.seen = w.seen;
  const older = makeOlder(w.older);
  if (older) rec.older = older; else delete rec.older;
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
