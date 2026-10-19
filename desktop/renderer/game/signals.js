// The command center's queue: every finding as a signal to sort. Pure.
// Warnings and criticals come first, and info is folded into one low-priority
// list. A check that couldn't run is a COULDN'T CHECK signal, tagged NOTED and
// never MINE or THREAT. A finding the person marked as theirs arrives
// pre-tagged MINE; one that changed since (data.mark_stale) is back in the
// queue. Monitoring checks are never signals: the game isn't offered when they
// find something, and nothing about them is scored.
import { findingIdentity, DISTRICTS, OUTSKIRTS, districtIdFor } from './findings-to-city.js';
import { MONITORING_MODULES } from './ledger.js';
// Sets globalThis.NotChecked (a plain script the list loads too).
import '../not-checked.js';

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

// An opt-in check waiting for the person's go-ahead (the iPhone backup's long
// scan): a calm optional mission, never "couldn't run" and never clean. City
// mode (`cover`) says it in game words and names no check.
export const WAITING_TITLE = { cover: 'A phone backup can get its own long sweep', plain: 'Your phone’s backup can be swept for spyware' };
export const WAITING_TEXT = {
  cover: 'There’s a phone backup on this computer. It can get its own long sweep. It only looks at the backup and changes nothing. It starts only if you say so.',
  plain: 'There’s an iPhone backup on this computer. It can be swept for spyware: a long sweep that only reads the backup and changes nothing. It starts only if you say so.',
};

// Its id never names the check (it is drawn into the page): the district, and
// a short number made from the check's id.
export function waitingId(districtId, module) {
  let h = 5381;
  for (const ch of String(module)) h = ((h * 33) ^ ch.charCodeAt(0)) >>> 0;
  return `waiting|${districtId}|${h.toString(36).slice(0, 4)}`;
}

// `changedIds`: tags the controller set aside this session, so the
// "changed since you tagged it" badge stays after reconcileDeck dropped them.
// `cover`: city mode's words (WAITING_TITLE).
export function buildSignals(city, deck, changedIds = null, { cover = true } = {}) {
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
      if (g.notStarted) {
        // Counted with COULDN'T CHECK (it wasn't checked), but offered, not noted.
        add({ id: waitingId(d.id, g.module), kind: 'waiting', severity: 'couldnt', title: cover ? WAITING_TITLE.cover : WAITING_TITLE.plain,
          description: cover ? WAITING_TEXT.cover : WAITING_TEXT.plain, districtId: d.id, module: g.module, finding: null, missionId: null,
          fixable: false, marked: false, stale: false, fp: 'waiting', count: 1, monitoring: MONITORING_MODULES.has(g.module) });
        continue;
      }
      // A monitoring check that couldn't run is still a COULDN'T CHECK row, so
      // the queue counts what the list counts (not-checked.js). It is never
      // named, never tagged and never stored (ledger.js refuses its id too).
      const monitoring = MONITORING_MODULES.has(g.module);
      add({ id: `couldnt|${g.module}`, kind: 'couldnt', severity: 'couldnt', title: couldntTitle(monitoring ? { reason: g.reason } : g),
        description: monitoring ? 'This check couldn’t run.' : String(g.reason == null ? '' : g.reason), districtId: d.id,
        module: g.module, finding: null, missionId: null, fixable: false, marked: false, stale: false, fp: 'couldnt', count: 1,
        ...(monitoring ? { monitoring: true } : {}) });
    }
    // A check that started but didn't finish: a NOT CHECKED row too, so the
    // filter shows every check the banner and NotChecked.scanCounts name
    // (`unfinished`). A check only partly checked (its titles) stays in its district.
    for (const u of d.unfinished || []) {
      if (Array.isArray(u.titles) && u.titles.length && u.stoppedEarly !== true) continue;
      const monitoring = MONITORING_MODULES.has(u.module);
      add({ id: `couldnt|${u.module}`, kind: 'couldnt', unfinished: true, severity: 'couldnt',
        title: unfinishedTitle(monitoring ? {} : u), description: UNFINISHED_TEXT, districtId: d.id,
        module: u.module, finding: null, missionId: null, fixable: false, marked: false, stale: false, fp: 'couldnt', count: 1,
        ...(monitoring ? { monitoring: true } : {}) });
    }
  }
  return out;
}

export const UNFINISHED_TEXT = 'This check started but stopped before the end, so it may have missed something.';
// "App signatures didn't finish": the check's own name for people, never its id.
export function unfinishedTitle(g) {
  const words = String((g && g.checkName) || '').trim();
  return `${words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check'} didn’t finish`;
}

// A check that couldn't run, named (monitoring checks never get here) with
// why, in a few words: "App signatures took too long". The check's own name
// for people (check_name, as the list says it); its id only as a last resort.
export function couldntTitle(g) {
  const words = String((g && (g.checkName || g.module)) || '').replace(/_/g, ' ').trim();
  const name = words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check';
  const why = String((g && g.reason) || '');
  // A checkup that stopped before this check (engine-runner stoppedDocOf): it never ran, nothing failed.
  if (/stopped before this check ran/i.test(why)) return `${name} didn’t get to run`;
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

// TO DO on the deck and every HUD: the list's number of items
// (NotChecked.scanCounts `items`, city mode), less the ones already sorted
// with a tag (MINE, THREAT). Never the couldn't-check rows: those are NOT
// CHECKED. Before any sorting it is exactly the list's count.
export function todoFrom(counts, signals) {
  const items = Number(counts && counts.items) || 0;
  const sorted = (signals || []).filter((x) => x.kind === 'real' && x.severity !== 'info' && !x.marked && x.tag && x.tag !== 'closer').length;
  return Math.max(0, items - sorted);
}

// The NOT CHECKED chip's parts, from NotChecked.scanCounts only:
// "4 DIDN'T FINISH · 1 NOT STARTED".
export function notCheckedChip(counts) {
  const c = counts || {};
  return [[c.couldntRun, 'COULDN’T RUN'], [c.unfinished, 'DIDN’T FINISH'], [c.notStarted, 'NOT STARTED']]
    .filter(([n]) => Number(n) > 0).map(([n, label]) => `${Number(n)} ${label}`).join(' · ');
}

// What's left to do: the rows still to sort in the deck's queue (critical,
// warning and couldn't-check, untagged or LOOK CLOSER), so it is the sum of
// the deck's CRITICAL, WARNING and COULDN'T CHECK chips. A tag (MINE, THREAT,
// NOTED) takes a row off it on the deck and on every HUD alike. Something the
// checkup reported more than once is one mission (findingsToCity), so this
// can be lower than the list's count of cards (see repeatsMerged).
export function todoCount(signals) {
  return queueOf(signals).urgent.length;
}

// How many critical and warning findings were folded into another mission
// with the same identity: why the city's count can be lower than the list's.
export function repeatsMerged(city) {
  const t = (city && city.totals) || {};
  const missions = ((city && city.districts) || []).reduce((n, d) => n + (d.missions || []).length, 0);
  return Math.max(0, (Number(t.critical) || 0) + (Number(t.warning) || 0) - missions);
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
    // Nor is a district with fog (a check that couldn't run, or one waiting
    // for the go-ahead): it wasn't all looked at. Nor is any district of a
    // checkup that stopped before its report was done.
    if (!openIn.has(d.id) && !(d.unfinished && d.unfinished.length) && !(d.fog && d.fog.length) && !d.stopped) securedIds.add(d.id);
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

// The scan's numbers as the city shows them: NotChecked.scanCounts in city
// mode (held findings left out of every number), by the city's districts.
export function cityCounts(doc) {
  return globalThis.NotChecked.scanCounts(doc, { mode: 'city', districtOf: districtIdFor });
}

// What a sweep record holds: counts only (see progress.js SWEEP_FIELDS), from
// cityCounts, so LAST SWEEP, the ops log, the chips and the list agree.
// `checks` + `fog` is every check; `fog` is what couldn't run or didn't
// finish. The rest is said in the log, never stored.
export function sweepCounts(doc, city, integrity) {
  const c = cityCounts(doc);
  return {
    checks: Math.max(0, c.checks - c.didntFinish), fog: c.didntFinish,
    critical: c.critical, warning: c.warning, info: c.info,
    checked: (integrity && integrity.checked) || 0, secured: (integrity && integrity.secured) || 0,
    total: c.checks, unfinished: c.unfinished, couldntRun: c.couldntRun, notStarted: c.notStarted, items: c.items,
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

// What wasn't fully checked: the list's own rule, one module for both
// (renderer/not-checked.js), so both views count the same things.
const NC = globalThis.NotChecked;
export const isPartlyChecked = NC.isPartlyChecked;
export const notCheckedSummary = NC.notCheckedSummary;
export const notCheckedLine = NC.notCheckedLine;
export const notCheckedParts = NC.notCheckedParts;

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
