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
    if (have && ORDER[sig.severity] >= ORDER[have.severity]) { have.count += 1; return; }
    const rec = tags[sig.id];
    const fits = !!rec && (sig.kind === 'couldnt' ? rec.tag === 'noted' : REAL_TAGS.has(rec.tag));
    const changed = (!!rec && rec.fp !== sig.fp) || !!(changedIds && changedIds.has(sig.id));
    const tag = sig.marked ? 'mine' : (fits && rec.fp === sig.fp ? rec.tag : null);
    const full = { ...sig, tag, changed: changed && !sig.marked };
    if (have) {
      // The same identity at a higher severity: the worse one is what shows.
      full.count = have.count + 1;
      out[out.indexOf(have)] = full;
    } else {
      out.push(full);
    }
    byId.set(sig.id, full);
  };
  for (const d of (city && city.districts) || []) {
    for (const m of d.missions || []) {
      if (MONITORING_MODULES.has(m.module)) continue;
      const f = m.primary || {};
      // Couldn't be checked this time (mark_unchecked) is never "changed".
      const unchecked = !!(f.data && f.data.mark_unchecked === true);
      const stale = !unchecked && !!(f.data && f.data.mark_stale === true);
      add({ id: m.id, kind: 'real', severity: m.severity, title: m.title, description: m.description || '', districtId: d.id,
        module: m.module, finding: f, missionId: m.id, fixable: !!m.fixable, marked: !!m.marked && !stale && !unchecked, stale, unchecked, fp: fingerprint(f), count: 1 });
    }
    for (const n of d.notes || []) {
      if (MONITORING_MODULES.has(n.module)) continue;
      add({ id: findingIdentity(n), kind: 'real', severity: 'info', title: n.title || 'Something the checkup noted',
        description: n.description || '', districtId: d.id, module: n.module, finding: n, missionId: null, fixable: false,
        marked: false, stale: false, fp: fingerprint(n), count: 1 });
    }
    for (const g of d.fog || []) {
      if (MONITORING_MODULES.has(g.module)) continue;
      add({ id: `couldnt|${g.module}`, kind: 'couldnt', severity: 'couldnt', title: couldntTitle(g),
        description: String(g.reason == null ? '' : g.reason), districtId: d.id, module: g.module, finding: null,
        missionId: null, fixable: false, marked: false, stale: false, fp: 'couldnt', count: 1 });
    }
  }
  return out;
}

// A check that couldn't run, named (monitoring checks never get here) with
// why, in a few words: "Code signature audit took too long".
export function couldntTitle(g) {
  const words = String((g && g.module) || '').replace(/_/g, ' ').trim();
  const name = words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check';
  const why = String((g && g.reason) || '');
  if (/timed?\s*out|took too long/i.test(why)) return `${name} took too long`;
  if (/permission|not permitted|full disk access|access denied/i.test(why)) return `${name} needed a permission`;
  return `${name} couldn’t run here`;
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

// Monitoring findings are never signals, but an open one still means its
// district isn't secure (and is hot), even while the game is withdrawn.
function openMonitoring(city) {
  const out = [];
  for (const d of (city && city.districts) || []) {
    for (const m of d.missions || []) {
      if (!MONITORING_MODULES.has(m.module) || !OPEN.has(m.severity)) continue;
      const stale = !!(m.primary && m.primary.data && m.primary.data.mark_stale === true);
      if (m.marked && !stale) continue;
      out.push({ districtId: d.id, severity: m.severity });
    }
  }
  return out;
}

// `held`: a city built from only the held monitoring findings (held.js), kept
// in memory. They're never signals, but they're still open.
export function cityIntegrity(city, signals, held = null) {
  const openIn = new Set([...(signals || []).filter(isOpen), ...openMonitoring(city), ...openMonitoring(held)].map((x) => x.districtId));
  const checkedIds = new Set();
  const securedIds = new Set();
  for (const d of (city && city.districts) || []) {
    if (!(d.checksRan > 0)) continue;
    checkedIds.add(d.id);
    // A check here that didn't finish may have missed something: not secured.
    if (!openIn.has(d.id) && !(d.unfinished && d.unfinished.length)) securedIds.add(d.id);
  }
  const checked = checkedIds.size;
  const secured = securedIds.size;
  return { percent: checked ? Math.round((secured / checked) * 100) : null, checked, secured, checkedIds, securedIds };
}

// The districts where a held monitoring finding is open. A change there is
// never "secured" and never a clean sweep: that would reward removing it.
export function heldDistrictIds(held) {
  return new Set(openMonitoring(held).map((x) => x.districtId));
}

export function districtHeat(city, signals, held = null) {
  const out = {};
  for (const x of [...(signals || []).filter(isOpen), ...openMonitoring(city), ...openMonitoring(held)]) {
    out[x.districtId] = out[x.districtId] === 'hot' || x.severity === 'critical' ? 'hot' : 'warn';
  }
  return out;
}

// What a sweep record holds: counts only (see progress.js SWEEP_FIELDS).
// `held`: the held city (held.js). Its criticals and warnings are counted too,
// as numbers only, so a sweep never reads as lighter than the scan was.
export function sweepCounts(doc, city, integrity, held = null) {
  const t = (city && city.totals) || {};
  const h = (held && held.totals) || {};
  const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
  return {
    checks: mods.filter((m) => m && m.status === 'ok' && m.supported !== false).length,
    critical: (t.critical || 0) + (h.critical || 0), warning: (t.warning || 0) + (h.warning || 0), info: t.info || 0, fog: t.fog || 0,
    checked: (integrity && integrity.checked) || 0, secured: (integrity && integrity.secured) || 0,
    // Ran, but stopped before the end ("complete": false): said in the log,
    // never stored (not one of SWEEP_FIELDS).
    unfinished: mods.filter((m) => m && m.status === 'ok' && m.supported !== false && m.complete === false).length,
  };
}

// The queue as rows: signals with the same title and severity in one row,
// with how many there are (`same`) and the first one's id to open. Order kept.
export function mergeSame(signals) {
  const out = [];
  const at = new Map();
  for (const x of signals || []) {
    const k = `${x.kind}|${x.severity}|${x.title}`;
    const row = at.get(k);
    if (row && x.kind !== 'drill') { row.same += 1; row.ids.push(x.id); continue; }
    const r = { ...x, same: 1, ids: [x.id] };
    at.set(k, r);
    out.push(r);
  }
  return out;
}

// How many signals of each kind the queue holds, for its filters.
export function severityCounts(signals) {
  const out = { critical: 0, warning: 0, couldnt: 0 };
  for (const x of signals || []) if (x.severity in out) out[x.severity] += 1;
  return out;
}

// A note that says part of a check couldn't look ("We couldn't list your USB
// devices", "Checked 16 of 110 app signatures"). The same rule as the list's
// (app.js isPartlyChecked), so both views count the same things.
const COULDNT_TITLE = /^(?:we\s+)?(?:couldn[’']t|could\s+not)\s+(?:check|list|read|see|tell|find\s+out)\b/i;
export function isPartlyChecked(f) {
  if (!f || f.severity !== 'info') return false;
  const title = String(f.title || '');
  if (COULDNT_TITLE.test(title)) return true;
  return !!(f.data && f.data.incomplete) && /^checked\s+\d+\s+of\s+\d+/i.test(title);
}

// One count of what wasn't fully checked, the same as the list's
// (app.js notCheckedSummary): checks that couldn't run or didn't finish, and
// notes that say part of a check couldn't look. `checks`: every check.
export function notCheckedSummary(doc) {
  const mods = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean) : [];
  const couldntRun = mods.filter((m) => m.status === 'error' || m.supported === false).length;
  const unfinished = mods.filter((m) => m.status !== 'error' && m.supported !== false && m.complete === false).length;
  const partly = mods.reduce((n, m) => n + (Array.isArray(m.findings) ? m.findings.filter(isPartlyChecked).length : 0), 0);
  return { checks: mods.length, couldntRun, unfinished, partly, count: couldntRun + unfinished + partly };
}

// The deck's top line when something wasn't fully checked. Never an all-clear.
export function notCheckedLine(sum) {
  const s = sum || {};
  const ran = (s.couldntRun || 0) + (s.unfinished || 0);
  const how = s.couldntRun && s.unfinished ? 'couldn’t run or didn’t finish' : s.couldntRun ? 'couldn’t run' : 'didn’t finish';
  const parts = [];
  if (ran) parts.push(`${ran} ${ran === 1 ? 'check' : 'checks'} ${how}`);
  if (s.partly) parts.push(`${s.partly} ${s.partly === 1 ? 'thing was' : 'things were'} only partly checked`);
  if (!parts.length) return '';
  return `${parts.join(', and ')}, so this isn’t a clean bill of health.`;
}

// The scan as the city reads it: a note saying part of a check couldn't look
// leaves the notes, and its check counts as not finished (never clear). The
// titles come back as `partly`, by module. A copy; the scan is unchanged.
export function foldPartly(doc) {
  if (!doc || !Array.isArray(doc.modules)) return { doc, partly: new Map() };
  const partly = new Map();
  const modules = doc.modules.map((m) => {
    if (!m || !Array.isArray(m.findings)) return m;
    const out = m.findings.filter(isPartlyChecked);
    if (!out.length) return m;
    partly.set(m.name, out.map((f) => String(f.title || '')));
    const failed = m.status === 'error' || m.supported === false;
    return { ...m, findings: m.findings.filter((f) => !isPartlyChecked(f)), ...(failed ? {} : { complete: false }) };
  });
  return { doc: { ...doc, modules }, partly };
}
