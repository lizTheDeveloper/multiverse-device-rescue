// Mission progress for game mode. The scan is the source of truth: progress only
// remembers what the person chose ("later") and what changed between scans.
// "reclaimed" is only ever set by evidence: a re-check or a full scan where the
// finding's module ran and no longer reports it.
export const STORE_KEY = 'device-rescue.game.v1';
const STATUSES = new Set(['open', 'later', 'yours', 'reclaimed']);

export function emptyProgress() {
  return { version: 1, missions: {} };
}

function valid(p) {
  return p && p.version === 1 && p.missions && typeof p.missions === 'object' && !Array.isArray(p.missions)
    && Object.values(p.missions).every((r) => r && STATUSES.has(r.status));
}

export function loadProgress(storage) {
  try {
    const raw = storage ? storage.getItem(STORE_KEY) : null;
    if (!raw) return emptyProgress();
    const p = JSON.parse(raw);
    return valid(p) ? p : emptyProgress();
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

export function reconcile(progress, city, ranOk, now) {
  const next = { version: 1, missions: { ...(progress && progress.missions) } };
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
    if (present.has(id) || rec.status === 'reclaimed' || rec.status === 'yours') continue;
    if (ranOk.has(rec.module)) next.missions[id] = { ...rec, status: 'reclaimed', updatedAt: now };
  }
  return { progress: next, cameBack };
}

export function setStatus(progress, id, status, module, now) {
  return { version: 1, missions: { ...progress.missions, [id]: { status, module, updatedAt: now } } };
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
