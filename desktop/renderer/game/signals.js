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
