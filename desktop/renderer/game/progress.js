// Mission progress for game mode, plus finished lessons. The scan is the source
// of truth: progress only remembers what the person chose ("later"), what
// changed between scans, and which lessons they finished. "reclaimed" is only
// ever set by evidence: a re-check or a full scan where the finding's module ran
// and no longer reports it. Lessons never count toward fixes.
//
// The key keeps its v1 name so a saved Plan A store is found and migrated.
import { HELD_MODULES } from './held.js';

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

// Accepts a stored version 1 or 2 document. Missions are kept whenever they are
// valid; a bad lessons field only costs the lessons.
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
    version: 2,
    missions: { ...((progress && progress.missions) || {}) },
    lessons: { ...((progress && progress.lessons) || {}) },
  };
}

// Records keep a mission's title and id, which can name a program and a path.
// Monitoring software is never recorded: the controller already holds it out
// of the city (held.js), and this skips it again, and drops any older record
// of it, so nothing about it is ever written.
export function reconcile(progress, city, ranOk, now) {
  const next = base(progress);
  for (const [id, rec] of Object.entries(next.missions)) {
    if (HELD_MODULES.has(rec.module)) delete next.missions[id];
  }
  const cameBack = [];
  const present = new Set();
  for (const m of allMissions(city)) {
    if (HELD_MODULES.has(m.module)) continue;
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
  if (HELD_MODULES.has(module)) return base(progress); // never recorded (see reconcile)
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
