// The final boss: the real scan, shown as Scout sweeping the city. Driven only by
// the engine's progress events. Until the scan finishes, a district is waiting,
// sweeping or swept — never safe or unsafe. That's decided by the results.
// With the engine's plan (every check about to run), a district is SWEPT only
// once all its checks are done, and its finished checks' results (streamed
// entries) can be previewed; until then it is part-way.
import { DISTRICTS, OUTSKIRTS, districtIdFor } from './findings-to-city.js';

export function bossInit() {
  return { index: 0, total: 0, found: 0, current: null, seen: {}, done: false, planned: null, modules: [] };
}

const num = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);

export function bossApply(boss, ev) {
  if (!boss || boss.done || !ev) return boss;
  if (ev.type === 'plan') {
    if (!Array.isArray(ev.modules)) return boss;
    const planned = {};
    for (const m of ev.modules) {
      const id = districtIdFor(m && m.category);
      planned[id] = (planned[id] || 0) + 1;
    }
    const total = num(ev.total) !== null && ev.total > 0 ? ev.total : boss.total;
    return { ...boss, planned, total };
  }
  if (ev.type === 'module') {
    const r = ev.result;
    if (!r || typeof r !== 'object' || typeof r.name !== 'string') return boss;
    return { ...boss, modules: [...(boss.modules || []).filter((m) => m.name !== r.name), r] };
  }
  if (ev.type !== 'progress') return boss;
  const id = districtIdFor(ev.category);
  const total = num(ev.total) !== null && ev.total > 0 ? ev.total : boss.total;
  // The engine numbers checks from 1, and a 'start' event names the check now
  // starting, so only the ones before it are finished.
  const given = num(ev.index) !== null ? (ev.phase === 'start' ? ev.index - 1 : ev.index) : null;
  const rawIndex = given !== null ? Math.max(0, given) : boss.index;
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

// 'waiting' | 'sweeping' | 'part' (some of its checks done, with a plan) | 'swept'
// | 'skip' (with a plan: none of its checks are in this sweep).
// Without a plan (an older engine), a district is swept once any check in it ran.
function stateOf(boss, id) {
  if (!boss) return 'waiting';
  const want = boss.planned ? boss.planned[id] || 0 : 0;
  // With a plan, its last check finishing makes it swept straight away.
  if (boss.planned && want && (boss.seen[id] || 0) >= want) return 'swept';
  if (boss.current === id) return 'sweeping';
  // No check of this kind is in this sweep (a worry's checks, say): never "waiting".
  if (boss.planned && !want && !(id in boss.seen)) return 'skip';
  if (!(id in boss.seen)) return 'waiting';
  if (boss.planned && (boss.seen[id] || 0) < want) return 'part';
  return 'swept';
}

export function bossDistricts(boss) {
  const outskirts = boss && (OUTSKIRTS.id in boss.seen || (boss.planned && boss.planned[OUTSKIRTS.id]));
  const list = [...DISTRICTS, ...(outskirts ? [OUTSKIRTS] : [])];
  return list.map((d) => {
    const out = { id: d.id, name: d.name, state: stateOf(boss, d.id) };
    if (boss && boss.planned) out.checks = { done: boss.seen[d.id] || 0, of: boss.planned[d.id] || 0 };
    return out;
  });
}

// What the finished checks found so far, per SWEPT district, for the sweep
// screen. `toCity(doc)` is the controller's own path from a scan to a city
// (monitoring software held out, its words as the mode has them). A preview
// only: nothing here is a mission yet, nothing is stored or scored, and it is
// never an all-clear (the sweep isn't done). Only districts whose every
// check finished are previewed, so no district is shown part-read.
export function bossPreview(boss, toCity) {
  if (!boss || !boss.planned || !Array.isArray(boss.modules) || !boss.modules.length || typeof toCity !== 'function') return [];
  const swept = new Set(bossDistricts(boss).filter((d) => d.state === 'swept').map((d) => d.id));
  if (!swept.size) return [];
  const city = toCity({ schema_version: 1, modules: boss.modules });
  const districts = city && Array.isArray(city.districts) ? city.districts : [];
  return districts.filter((d) => swept.has(d.id)).map((d) => ({
    id: d.id,
    name: d.name,
    missions: d.missions.map((m) => ({ title: m.title, severity: m.severity })),
    fog: d.fog.length,
  }));
}

export function bossPercent(boss) {
  if (!boss || !boss.total) return 0;
  return Math.max(0, Math.min(100, Math.round((boss.index / boss.total) * 100)));
}
