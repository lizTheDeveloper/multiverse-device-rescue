// "This is mine", the fast way, and the YOURS district. Pure.
//
// A mark is still the engine's (rescue known add, through main's mark policy,
// which re-checks the item before saving). What changes is the asking: one
// click, with an Undo, for a background task; one short inline question for
// anything that could be used to watch a computer, and for every mark in city
// mode or while the checkup holds monitoring software (held.js).
//
// Monitoring software is never quick-markable. Its findings never become
// signals (signals.js), MarkFlow refuses them, and this refuses them again by
// module and by the code the engine's block names.
//
// A marked item leaves the queue and the district's missions, and is listed
// in YOURS: what it is, who made it (and whether that was verified), and what
// it does (program-kinds.js). One that changed since it was marked
// (data.mark_stale) is back in the queue and flagged in YOURS.
import { HELD_MODULES } from './held.js';
import { MONITORING_MODULES } from './ledger.js';
import { kindsOf, PROGRAM_KINDS, KIND_ORDER } from './program-kinds.js';

const MARK_ID = /^[0-9a-f]{12}$/;
const monitoring = (name) => HELD_MODULES.has(name) || MONITORING_MODULES.has(name);
const moduleOfCode = (code) => (typeof code === 'string' ? code.split('.')[1] : '');
const dataOf = (f) => (f && f.data && typeof f.data === 'object' ? f.data : {});
const str = (v) => (typeof v === 'string' ? v : '');

// {id, kind, confirm} for a finding that may be marked from the game, or null.
// `watched`: city mode. `held`: this checkup holds monitoring software.
// `level` (level.js) changes only the asking, never what may be marked:
// "new" always asks the short question first; "technical" lets city mode's
// background tasks go in one click (with Undo), while anything held, and
// anything that could be used to watch a computer, still asks.
export function quickMarkOf(finding, { MarkFlow, watched = false, held = false, level = 'everyday' } = {}) {
  if (!finding || typeof finding !== 'object' || !MarkFlow || typeof MarkFlow.markableOf !== 'function') return null;
  if (monitoring(finding.module) || monitoring(moduleOfCode(finding.code))) return null;
  if (finding.severity === 'critical') return null;
  if (dataOf(finding).marked_by_user === true) return null;
  const m = MarkFlow.markableOf(finding);
  if (!m || monitoring(moduleOfCode(m.code))) return null;
  const watchKind = m.kind !== 'background_task' && m.monitoring !== false;
  const confirm = level === 'new' || held || watchKind || (watched && level !== 'technical');
  return { id: m.id, kind: m.kind, confirm };
}

// Signals with this session's marks laid over them: a mark the engine saved
// moves its signal to YOURS at once, before the re-check confirms it, and an
// unmark the engine saved ({back: true}) puts it straight back in the queue.
export function withPending(signals, pending) {
  if (!pending || !pending.size) return signals;
  return (signals || []).map((x) => {
    const p = pending.get(x.id);
    if (!p) return x;
    if (p.back) return x.marked ? { ...x, marked: false, tag: null, pending: true } : x;
    return x.marked ? x : { ...x, marked: true, stale: false, changed: false, tag: 'mine', pending: true };
  });
}

const SERVICE_NAMES = { screen_sharing: 'Screen Sharing', file_sharing: 'File Sharing', remote_login: 'Remote Login', remote_management: 'Remote Management' };

// What to call it: the thing's own name from the evidence, not the warning title.
export function nameOf(f) {
  const d = dataOf(f);
  const m = f.markable || {};
  if (str(d.extension)) return d.browser ? `${d.extension} (${d.browser})` : d.extension;
  if (str(d.service)) return SERVICE_NAMES[d.service] || d.service;
  return str(d.label) || str(m.label) || str(d.bundle_id) || str(d.name) || str(d.original_title) || str(f.title) || 'Something you marked';
}

function evidenceOf(f) {
  const d = dataOf(f);
  return str(d.program) || str(d.path) || str((f.markable || {}).program) || str(d.permissions) || '';
}

// The made_by entry for the program it names (or the first), as {name, verified}.
export function makerOf(f) {
  const list = Array.isArray(f.made_by) ? f.made_by.filter((e) => e && str(e.name) && e.name !== 'Unknown maker') : [];
  const prog = str(dataOf(f).program);
  const e = list.find((x) => x.subject === prog) || list[0];
  return e ? { name: e.name, verified: e.verified === true } : null;
}

function itemOf(sig, ctx) {
  const f = sig.finding || {};
  const d = dataOf(f);
  return { id: sig.id, missionId: sig.missionId || null, title: sig.title, name: nameOf(f), kinds: kindsOf(f, ctx), maker: makerOf(f),
    evidence: evidenceOf(f), markId: MARK_ID.test(str(d.known_item_id)) ? d.known_item_id : null, pending: !!sig.pending,
    stale: !!sig.stale, districtId: sig.districtId };
}

// {items, changed, groups, count}. `items`: marked (or marked this session),
// `changed`: marked once and changed since. Groups follow KIND_ORDER by each
// item's first kind; items with no known kind go last.
export function yoursInventory(signals, ctx = null) {
  const real = (signals || []).filter((x) => x && x.kind === 'real' && !monitoring(x.module) && !monitoring((x.finding || {}).module));
  const items = real.filter((x) => x.marked).map((x) => itemOf(x, ctx));
  const changed = real.filter((x) => x.stale && !x.marked).map((x) => itemOf(x, ctx));
  const OTHER = { id: 'other', icon: '·', label: 'Other' };
  const groups = [];
  for (const id of [...KIND_ORDER, 'other']) {
    const list = items.filter((it) => (it.kinds[0] ? it.kinds[0].id : 'other') === id);
    if (list.length) groups.push({ kind: PROGRAM_KINDS[id] || OTHER, items: list });
  }
  return { items, changed, groups, count: items.length };
}
