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
import { validBloom, validHashes } from './folded.js';

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

// A stored sweep needs its date and every count; anything else on it is dropped by cleanDeck.
const sweepFieldsOk = (w) => plainObject(w) && typeof w.at === 'string' && SWEEP_FIELDS.every((k) => count(w[k]));

export function validDeck(d) {
  return plainObject(d) && count(d.points) && count(d.rank)
    && plainObject(d.drills) && count(d.drills.right) && count(d.drills.tried)
    && plainObject(d.tags) && Object.values(d.tags).every((t) => plainObject(t) && TAGS.has(t.tag) && typeof t.at === 'string' && typeof t.fp === 'string')
    && plainObject(d.confirmed) && Object.values(d.confirmed).every((v) => typeof v === 'string')
    && plainObject(d.once) && Object.values(d.once).every((v) => v === true)
    && plainObject(d.sweep) && (d.sweep.at === null || typeof d.sweep.at === 'string') && plainObject(d.sweep.keys)
    && (d.sweep.paid === undefined || validBloom(d.sweep.paid))
    && Array.isArray(d.sweeps) && d.sweeps.every(sweepFieldsOk)
    // Kept by the profile when it folds old records to stay small (folded.js):
    // `paid`, lifetime award keys folded out of `once` (and `sweep.paid`,
    // this sweep's keys folded out of `sweep.keys`); `confirmedEarlier`,
    // confirmed fixes folded out of `confirmed`, still counted, with their
    // ids as short hashes in `confirmedFolded`.
    && (d.paid === undefined || validBloom(d.paid))
    && (d.confirmedEarlier === undefined || count(d.confirmedEarlier))
    && (d.confirmedFolded === undefined || validHashes(d.confirmedFolded));
}

// The deck rebuilt from its known fields only, or null when it isn't a valid
// deck. A stray key anywhere (a name, a `monitoringSeen`) is dropped, never
// stored. Object.fromEntries keeps an id like "__proto__" a plain key.
export function cleanDeck(d) {
  if (!validDeck(d)) return null;
  const map = (o, f) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, f(v)]));
  return {
    points: d.points,
    rank: d.rank,
    drills: { right: d.drills.right, tried: d.drills.tried },
    tags: map(d.tags, (t) => ({ tag: t.tag, at: t.at, fp: t.fp })),
    confirmed: map(d.confirmed, (v) => v),
    once: map(d.once, () => true),
    sweep: { at: d.sweep.at, keys: Object.fromEntries(Object.entries(d.sweep.keys).filter(([, v]) => v === true)),
      ...(d.sweep.paid !== undefined ? { paid: d.sweep.paid } : {}) },
    sweeps: d.sweeps.map((w) => Object.fromEntries([['at', w.at], ...SWEEP_FIELDS.map((k) => [k, w[k]])])),
    ...(d.paid !== undefined ? { paid: d.paid } : {}),
    ...(d.confirmedEarlier !== undefined ? { confirmedEarlier: d.confirmedEarlier } : {}),
    ...(d.confirmedFolded !== undefined ? { confirmedFolded: d.confirmedFolded } : {}),
  };
}

// Reclaimed missions the profile folded into a count per district, to stay
// small: { districtId: n }. Counted by reclaimedIn and countReclaimed.
export function cleanEarlier(e) {
  return Object.fromEntries(Object.entries(plainObject(e) ? e : {}).filter(([, n]) => Number.isInteger(n) && n > 0));
}

// Accepts a stored version 1, 2 or 3 document. Missions are kept whenever they
// are valid; a bad lessons field only costs the lessons, and a bad deck only
// costs the deck.
export function migrate(raw) {
  if (!plainObject(raw) || !validMissions(raw.missions)) return emptyProgress();
  const lessons = validLessons(raw.lessons) ? raw.lessons : {};
  if (raw.version === 1) return { version: 3, missions: raw.missions, lessons: {}, deck: emptyDeck() };
  if (raw.version === 2) return { version: 3, missions: raw.missions, lessons, deck: emptyDeck() };
  if (raw.version === 3) return { version: 3, missions: raw.missions, lessons, deck: cleanDeck(raw.deck) || emptyDeck() };
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
  const earlier = cleanEarlier(progress && progress.reclaimedEarlierBy);
  return {
    version: 3,
    missions: { ...((progress && progress.missions) || {}) },
    lessons: { ...((progress && progress.lessons) || {}) },
    deck: (progress && cleanDeck(progress.deck)) || emptyDeck(),
    ...(Object.keys(earlier).length ? { reclaimedEarlierBy: earlier } : {}),
  };
}

// The deck changes only through the ledger (ledger.js); an invalid one is
// refused, and a valid one is rebuilt from its known fields.
export function setDeck(progress, deck) {
  const next = base(progress);
  const clean = cleanDeck(deck);
  if (clean) next.deck = clean;
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
// that status, the ones the scan no longer reports (kept in progress), and
// the ones folded into a count (`earlier: true`, no id; one row per mission
// so the count is right, which views may show as one line).
export const EARLIER_TITLE = 'Something that’s gone now';
export function reclaimedIn(progress, district) {
  const records = (progress && progress.missions) || {};
  const present = new Map((district.missions || []).map((m) => [m.id, m]));
  const listed = Object.entries(records)
    .filter(([id, r]) => r.status === 'reclaimed' && (present.has(id) || r.districtId === district.id))
    .map(([id, r]) => ({ id, title: (present.get(id) || {}).title || r.title || EARLIER_TITLE }));
  const earlier = cleanEarlier(progress && progress.reclaimedEarlierBy)[district.id] || 0;
  return [...listed, ...Array.from({ length: earlier }, () => ({ id: null, title: EARLIER_TITLE, earlier: true }))];
}

export function recheckOutcome(missionId, cityAfter, response) {
  if (!response || response.ok !== true || !response.module) return 'couldnt';
  if (response.module.status === 'error' || response.module.supported === false) return 'couldnt';
  const m = allMissions(cityAfter).find((x) => x.id === missionId);
  if (!m) return 'reclaimed';
  return m.marked ? 'yours' : 'not-yet';
}

export function countReclaimed(progress) {
  const earlier = Object.values(cleanEarlier(progress && progress.reclaimedEarlierBy)).reduce((a, n) => a + n, 0);
  return Object.values((progress && progress.missions) || {}).filter((r) => r.status === 'reclaimed').length + earlier;
}
