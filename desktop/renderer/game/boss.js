// The final boss: the real scan, shown as Scout sweeping the city. Driven only by
// the engine's progress events. Until the scan finishes, a district is waiting,
// sweeping or swept — never safe or unsafe. That's decided by the results.
// `now` is the check running right now; `log` holds the finished ones, oldest
// first, so long gaps between checks never look like nothing is happening.
import { DISTRICTS, OUTSKIRTS, districtIdFor } from './findings-to-city.js';

export const LOG_KEEP = 400;

export function bossInit() {
  return { index: 0, total: 0, found: 0, couldnt: 0, current: null, now: null, log: [], seen: {}, done: false };
}

const num = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);
// Module and category names are snake_case identifiers; anything else is dropped, never shown.
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const nameOrNull = (m) => (typeof m === 'string' && NAME_RE.test(m) ? m : null);

// 'couldnt': the check didn't run here, or crashed, so it checked nothing.
// An event with no `supported` (an older engine) counts as having run.
function outcomeOf(ev, findings) {
  if (ev.supported === false || (typeof ev.error === 'string' && ev.error)) return 'couldnt';
  return findings > 0 ? 'noted' : 'none';
}

export function bossApply(boss, ev) {
  if (!boss || boss.done || !ev || ev.type !== 'progress') return boss;
  const id = districtIdFor(ev.category);
  const total = num(ev.total) !== null && ev.total > 0 ? ev.total : boss.total;
  // The engine numbers checks from 1, and a 'start' event names the check now
  // starting, so only the ones before it are finished.
  const given = num(ev.index) !== null ? (ev.phase === 'start' ? ev.index - 1 : ev.index) : null;
  const rawIndex = given !== null ? Math.max(0, given) : boss.index;
  const index = total ? Math.min(rawIndex, total) : rawIndex;
  const next = { ...boss, total, index, seen: { ...boss.seen }, log: boss.log || [], couldnt: boss.couldnt || 0 };
  const module = nameOrNull(ev.module);
  const category = nameOrNull(ev.category);
  const at = num(ev.index);
  if (ev.phase === 'start') {
    next.current = id;
    next.seen[id] = next.seen[id] || 0;
    next.now = { module, category, index: at };
  } else if (ev.phase === 'done') {
    next.seen[id] = (next.seen[id] || 0) + 1;
    const f = num(ev.findings);
    const findings = f !== null && f > 0 ? f : 0;
    next.found = boss.found + findings;
    const outcome = outcomeOf(ev, findings);
    if (outcome === 'couldnt') next.couldnt += 1;
    next.log = [...next.log, { module, category, index: at, findings, outcome }].slice(-LOG_KEEP);
    next.now = null;
  }
  return next;
}

export function bossFinish(boss) {
  return { ...(boss || bossInit()), done: true, current: null, now: null };
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
