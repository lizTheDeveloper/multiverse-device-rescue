// The technical level's triage queue: every case in one dense list, filled in
// as the sweep finishes each check, and sorted from the keyboard. Pure: the
// rows, the filters, the groups, the keys, and the safety plan for each
// action. The screen's state and drawing are triage-screen.js.
//
// Safety is decided here, never by the keys. Held findings (held.js:
// monitoring) are one locked row that only routes to their own help: never
// selected, tagged, categorised or paid. "Mine" on a critical waits for its
// own confirmation and is never part of a bulk action. A real mark (the
// engine's "This is mine") still goes through mark-desk.js, which asks first
// wherever yours.js says it must.
import { findingsToCity, DISTRICTS, OUTSKIRTS } from './findings-to-city.js';
import { splitHeld, HELD_MODULES } from './held.js';
import { MONITORING_MODULES } from './ledger.js';
import { kindsOf, PROGRAM_KINDS } from './program-kinds.js';
import { nameOf, makerOf } from './yours.js';
import { pathOf, homeRelative } from './clues.js';
import { evidenceRows } from './level.js';
import { caseOf, compareCases, mergeEchoes, verifiedMaker, CASE_TYPES } from './case-file.js';
import { suggestCategory, OWN_CATEGORIES } from './own-categories.js';

const monitoring = (name) => HELD_MODULES.has(name) || MONITORING_MODULES.has(name);
const DISTRICT_LIST = [...DISTRICTS, OUTSKIRTS];
export const districtLabel = (id) => (DISTRICT_LIST.find((d) => d.id === id) || OUTSKIRTS).name.replace(/^The /, '');

// --- The live sweep -----------------------------------------------------------
// The engine's "done" progress line carries that check's findings (rescue
// scan --json --progress: `result`), in the scan's own shape. Only a module
// entry that looks like one is kept, by name, so a re-run check replaces itself.
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
export function liveModuleOf(ev) {
  const m = ev && ev.type === 'progress' && ev.phase === 'done' ? ev.result : null;
  if (!m || typeof m !== 'object' || typeof m.name !== 'string' || !NAME_RE.test(m.name) || !Array.isArray(m.findings)) return null;
  return m;
}

// A city from the checks finished so far, the same way the controller builds
// one from a whole scan: held findings set aside first, then the same text
// as the list (`quiet`). Memory only; nothing about it is stored or reconciled.
export function liveCity(modules, platform = null, quiet = (d) => d) {
  const doc = { schema_version: 1, platform, modules: Array.isArray(modules) ? modules : [] };
  const split = splitHeld(doc);
  return { city: findingsToCity(quiet(split.doc)), held: split.held };
}

// --- Rows -------------------------------------------------------------------
const MAX_EVIDENCE = 140;
const SKIP_EVIDENCE = new Set(['program', 'path', 'plist', 'file', 'executable', 'target', 'signer', 'module', 'code']);

// One line of what the finding saw, after the path: pid, ports, command…
export function evidenceSummary(sig) {
  if (!sig || sig.kind !== 'real') return sig && sig.description ? String(sig.description).slice(0, MAX_EVIDENCE) : '';
  const rows = evidenceRows(sig.finding).filter(([k]) => !SKIP_EVIDENCE.has(k));
  const line = rows.slice(0, 4).map(([k, v]) => `${k} ${v}`).join(' · ');
  if (line) return line.length > MAX_EVIDENCE ? `${line.slice(0, MAX_EVIDENCE - 1)}…` : line;
  const what = String((sig.finding && sig.finding.description) || '').split(/\n\s*\n/)[0].split(/what to do:?/i)[0].trim();
  return what.length > MAX_EVIDENCE ? `${what.slice(0, MAX_EVIDENCE - 1)}…` : what;
}

// `qm`: mark-desk's quickMarkOf answer for this signal (the engine's real
// "This is mine"), or null. `closed`: its fix was confirmed (progress.js).
export function rowOf(sig, { ctx = null, qm = null, closed = false } = {}) {
  const real = sig.kind === 'real';
  const f = real ? sig.finding || {} : {};
  const kinds = real ? kindsOf(f, ctx).map((k) => k.id) : [];
  const c = caseOf(sig, { kinds, closed });
  const p = real ? pathOf(f) : null;
  return {
    id: sig.id, sig, case: c, title: sig.title, severity: sig.severity, district: sig.districtId, kinds,
    name: real ? nameOf(f) : sig.title, maker: real ? makerOf(f) : null, verified: real && verifiedMaker(f),
    path: p ? homeRelative(p) : '', evidence: evidenceSummary(sig), tag: sig.tag || null, marked: !!sig.marked,
    pending: !!sig.pending, changed: !!sig.changed || !!sig.stale,
    critical: sig.severity === 'critical', couldnt: sig.kind === 'couldnt',
    // The engine's own mark can be offered (after the sweep: main only marks what its last scan offered).
    markable: !!qm, confirm: !!(qm && qm.confirm),
    suggest: c.type === 'lead' ? suggestCategory(f, kinds) : null,
    held: false, also: [],
  };
}

// The one row for whatever the checkup holds. Its words come from the
// controller (city mode: the generated district's name, nothing about what
// was found), and its only control routes to that help.
export function heldRow({ label, go = null, act = null, count = 1 }) {
  return { id: 'held', held: true, case: caseOf({ kind: 'real' }, { held: true }), title: label, name: label, kinds: [], maker: null,
    verified: false, path: '', evidence: '', tag: null, marked: false, critical: false, couldnt: false, markable: false,
    confirm: false, suggest: null, also: [], district: null, go, act, count };
}

// Every signal as a row (drills aren't cases), with echoes folded together.
export function rowsOf(signals, { ctx = null, qmOf = () => null, closedIds = new Set() } = {}) {
  const rows = (signals || []).filter((x) => x && x.kind !== 'drill' && !monitoring(x.module) && !monitoring((x.finding || {}).module))
    .map((x) => rowOf(x, { ctx, qm: qmOf(x), closed: closedIds.has(x.id) }));
  return mergeEchoes(rows.sort(compareCases));
}

// --- Filters, sort, groups ----------------------------------------------------
export const TYPE_IDS = ['lead', 'door', 'upkeep', 'blind', 'note'];
// Upkeep (disk space, sleep settings) isn't an incident: off until asked for.
export const defaultFilters = () => ({ types: new Set(['lead', 'door', 'blind', 'note']), open: true, priority: null, kind: null,
  maker: null, district: null, text: '' });

function haystack(r) {
  if (r.hay === undefined) {
    r.hay = [r.name, r.title, r.path, r.maker && r.maker.name, r.sig && r.sig.module, r.evidence, CASE_TYPES[r.case.type].label,
      r.kinds.map((k) => PROGRAM_KINDS[k].label).join(' '), districtLabel(r.district)].filter(Boolean).join(' ').toLowerCase();
  }
  return r.hay;
}

// The held row always shows: safety first, whatever is filtered.
export function matches(r, f) {
  if (r.held) return true;
  if (!f) return true;
  if (f.types && !f.types.has(r.case.type)) return false;
  if (f.open && !r.case.open) return false;
  if (f.priority && r.case.priority !== f.priority) return false;
  if (f.kind && !r.kinds.includes(f.kind)) return false;
  if (f.maker === 'verified' && !r.verified) return false;
  if (f.maker === 'unverified' && r.verified) return false;
  if (f.district && r.district !== f.district) return false;
  const terms = String(f.text || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length) { const h = haystack(r); if (!terms.every((t) => h.includes(t))) return false; }
  return true;
}

export const SORTS = ['case', 'name', 'maker', 'district', 'kind'];
export const GROUPS = ['none', 'maker', 'kind', 'district'];
const by = (key) => (a, b) => String(key(a)).localeCompare(String(key(b))) || compareCases(a, b);
const SORTERS = {
  case: compareCases,
  name: by((r) => r.name.toLowerCase()),
  maker: by((r) => (r.maker ? `${r.verified ? 0 : 1}${r.maker.name.toLowerCase()}` : '~')),
  district: by((r) => DISTRICT_LIST.findIndex((d) => d.id === r.district)),
  kind: by((r) => (r.kinds[0] ? Object.keys(PROGRAM_KINDS).indexOf(r.kinds[0]) : 99)),
};

// {key, label, verified} for one row under a grouping.
export function groupOf(r, group) {
  if (group === 'maker') {
    if (!r.maker) return { key: 'none', label: 'No maker recorded', verified: false };
    return r.verified ? { key: `v|${r.maker.name}`, label: `${r.maker.name} · verified`, verified: true }
      : { key: `u|${r.maker.name}`, label: `Says ${r.maker.name} · couldn’t verify`, verified: false };
  }
  if (group === 'kind') {
    const k = r.kinds[0] ? PROGRAM_KINDS[r.kinds[0]] : null;
    return k ? { key: k.id, label: `${k.icon} ${k.label}` } : { key: 'other', label: 'No program kind' };
  }
  if (group === 'district') return { key: r.district || 'none', label: districtLabel(r.district) };
  return { key: 'all', label: '' };
}

// What the list shows, in order: rows, with a head before each group when
// grouped (biggest group first). The held row leads, ungrouped.
export function viewOf(rows, { filters = defaultFilters(), sort = 'case', group = 'none', held = null } = {}) {
  const shown = (rows || []).filter((r) => matches(r, filters)).sort(SORTERS[sort] || compareCases);
  const items = held ? [held] : [];
  if (group === 'none' || !GROUPS.includes(group)) return { items: items.concat(shown), count: shown.length };
  const groups = new Map();
  for (const r of shown) {
    const g = groupOf(r, group);
    if (!groups.has(g.key)) groups.set(g.key, { ...g, head: true, id: `group:${g.key}`, rows: [] });
    groups.get(g.key).rows.push(r);
  }
  // Verified makers first (the fast bulk), then by size; "no maker" and unverified claims after.
  const rank = (g) => (g.verified === true ? 0 : g.key === 'none' ? 2 : 1);
  const order = [...groups.values()].sort((a, b) => (rank(a) - rank(b)) || (b.rows.length - a.rows.length) || a.label.localeCompare(b.label));
  for (const g of order) items.push(g, ...g.rows);
  return { items, count: shown.length };
}

// --- Keys ---------------------------------------------------------------------
// One key, one action name. `inInput`: typing in the filter box, where only
// Enter and Escape leave it. Modifier chords belong to the app, not the queue.
const DIGIT_CAT = Object.fromEntries(OWN_CATEGORIES.map((c, i) => [String(i + 1), c.id]));
export function keyAction({ key, shiftKey = false, ctrlKey = false, metaKey = false, altKey = false, inInput = false } = {}) {
  if (inInput) return key === 'Escape' || key === 'Enter' ? 'filter-done' : null;
  if (ctrlKey || metaKey || altKey) return null;
  if (shiftKey && key === 'ArrowDown') return 'down-select';
  if (shiftKey && key === 'ArrowUp') return 'up-select';
  switch (key) {
    case 'j': case 'ArrowDown': return 'down';
    case 'J': return 'down-select';
    case 'k': case 'ArrowUp': return 'up';
    case 'K': return 'up-select';
    case 'Home': return 'top';
    case 'End': return 'bottom';
    case 'PageDown': return 'page-down';
    case 'PageUp': return 'page-up';
    case 'Enter': return 'expand';
    case 'm': return 'mine';
    case 't': return 'threat';
    case 'l': return 'closer';
    case 'n': return 'noted';
    case 'y': return 'yes';
    case 'u': return 'undo';
    case 'x': return 'select';
    case 'X': return 'select-range';
    case '/': return 'filter';
    case '?': return 'help';
    case 'c': return 'check';
    case 'g': return 'group';
    case 'o': return 'sort';
    case 'Escape': return 'escape';
    default: break;
  }
  if (DIGIT_CAT[key]) return `cat:${DIGIT_CAT[key]}`;
  return null;
}
export const categoryForDigit = (d) => DIGIT_CAT[String(d)] || null;

// Shift-x: everything between the anchor and here, in the order shown. Heads
// and the held row are never part of a selection.
export function rangeIds(items, fromId, toId) {
  const ids = items.map((x) => x.id);
  let a = ids.indexOf(fromId);
  const b = ids.indexOf(toId);
  if (b < 0) return [];
  if (a < 0) a = b;
  const [lo, hi] = a <= b ? [a, b] : [b, a];
  return items.slice(lo, hi + 1).filter(selectable).map((x) => x.id);
}
export const selectable = (x) => !!x && !x.head && !x.held;

// A group's own MINE ✓ N: only a maker the system verified vouches for a
// whole group. Kind and district groups are selected first, then sorted.
export const groupMineable = (g) => !!g && g.head === true && g.verified === true;

// --- The safety plan ------------------------------------------------------------
// What a tag would do to these rows: `go` now, `ask` (each needs its own
// question first), and `skip` with the reason. `bulk`: more than one row, or a
// group. A critical is never "mine" in bulk; held rows never move at all.
export const SKIP_WHY = {
  held: 'This one isn’t sorted here. Read it first.',
  critical: 'A critical needs its own confirmation, one at a time.',
  couldnt: 'This check couldn’t run: n notes it.',
  marked: 'Already in YOURS.',
  notblind: 'Only a check that couldn’t run is noted.',
  same: 'Already tagged that way.',
};
export function planTag(rows, tag, { bulk = false } = {}) {
  const go = [];
  const ask = [];
  const skip = [];
  for (const r of rows || []) {
    if (!r || r.head) continue;
    if (r.held || monitoring(r.sig && r.sig.module) || monitoring(r.sig && r.sig.finding && r.sig.finding.module)) { skip.push({ r, why: 'held' }); continue; }
    if (r.couldnt) { if (tag === 'noted') go.push(r); else skip.push({ r, why: 'couldnt' }); continue; }
    if (tag === 'noted') { skip.push({ r, why: 'notblind' }); continue; }
    if (r.marked) { skip.push({ r, why: 'marked' }); continue; }
    if (tag === 'mine' && r.critical) { if (bulk) skip.push({ r, why: 'critical' }); else ask.push(r); continue; }
    if (r.tag === tag && !(tag === 'mine' && r.markable)) { skip.push({ r, why: 'same' }); continue; }
    go.push(r);
  }
  return { go, ask, skip };
}

// The category a bulk "mine" lands with: the one most of its leads suggest
// (ties: the list's order), else "something else". Only ever pre-selected.
export function groupCategory(rows) {
  const n = new Map();
  for (const r of rows || []) if (r && r.case && r.case.type === 'lead' && r.suggest) n.set(r.suggest, (n.get(r.suggest) || 0) + 1);
  let best = null;
  for (const c of OWN_CATEGORIES) if (n.has(c.id) && (!best || n.get(c.id) > n.get(best))) best = c.id;
  return best || 'other';
}

// --- Undo -------------------------------------------------------------------------
// The tag records a change replaced, so Undo can put each one back (or remove
// it). Watch tags live in their own map (ledger sessionTag).
export function restoreTags(deck, prev) {
  const tags = { ...(deck && deck.tags) };
  for (const p of prev || []) {
    if (p.watch) continue;
    if (p.rec) tags[p.id] = p.rec; else delete tags[p.id];
  }
  return { ...deck, tags };
}
export function restoreWatchTags(session, prev) {
  const out = { ...(session || {}) };
  for (const p of prev || []) {
    if (!p.watch) continue;
    if (p.rec) out[p.id] = p.rec; else delete out[p.id];
  }
  return out;
}
export const UNDO_KEEP = 50;
