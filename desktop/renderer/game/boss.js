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
