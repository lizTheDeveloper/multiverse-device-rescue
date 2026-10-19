// One mission, played: a pure state machine (spec: "Runner and screens").
//
// Games only return decisions with EFFECTS; the runner decides what an effect
// means and hands the controller an ACT to carry out through the existing
// paths (MarkFlow, FixFlow, the re-check, open-setting, allowlisted links).
// Nothing here touches the DOM, storage or the computer.
//
//   startRun(mission, { practiceDue, recalled }) -> run
//   decisionsFor(run, game, item, ctx) -> Decision[]   checked, safe default first, Look closer (id 'closer') dropped while looking closer
//   viewFor(run, game, ctx, research) -> view          what the screen draws (game.render gets the same view)
//   choose(run, id, game, ctx) -> { run, act }         act: null | { kind: mark|fix|settings|link|recheck|lesson|odd, … }
//   confirmPending(run, game, ctx) / cancelPending(run) the warning-before-acting step (R6)
//   openLink(run, game, ctx, act) -> { run, act }       a research link; behind the confirm when the item warns
//   proceed(run)                                       past an answered item whose steps are on screen
//   guideOf(item, decision, mode)                      steps, checklist, hint, focus, off a decision shows
//   settle(run, outcome)                               a mark/fix/recheck flow finished: 'done' | 'cancelled'
//   startPractice / choosePractice / skipPractice      the self-teaching round
//   practiceDue(record, conceptStates) -> boolean
//   fingerprint(item) -> string                        evidence that, when it changes, un-remembers an answer
//   remembers(result) -> boolean                       which answers are kept for the next scan
//   summaryResults(run) -> [{ item, decision, effect, points }]
//
// Phases: 'offer' (first time: practice or "I know this"), 'practice',
// 'item', 'confirm' (the removal warning before a fix or a warned settings
// pane), 'summary'.
import { EFFECT_KINDS, MIN_DECISIONS, MAX_DECISIONS, REMOVING_KINDS, checkDecisions, isAlertingItem } from './contract.js';
import { shortHash } from '../game/folded.js';

export const REMOVAL_WARNING = 'Removing this can alert whoever installed it.';

// contract.js's one rule: a monitoring check's own finding always warns, as
// does any finding carrying removal_alert or a safety note.
export const alerting = (item) => isAlertingItem(item);

// The fix confirm's options for FixFlow.fixControlsHtml: city mode's watched
// warning, else the removal line whenever the item warns. Games can't change it.
export function fixOptions(item, mode) {
  const watched = mode === 'city';
  return { watched, safety: !watched && alerting(item) ? REMOVAL_WARNING : '' };
}

const label = (standard, city) => ({ standard, city });
const FALLBACK = [
  { id: 'later', label: label('Later', 'Later'), effect: { kind: 'later' } },
  { id: 'did', label: label('I did this', 'Done it'), effect: { kind: 'recheck' } },
];

export function startRun(mission, { practiceDue = false, recalled = {} } = {}) {
  const items = (mission && Array.isArray(mission.items) ? mission.items : []);
  const results = [];
  for (const item of items) {
    const was = recalled && Object.prototype.hasOwnProperty.call(recalled, item.key) ? recalled[item.key] : null;
    if (was) results.push({ key: item.key, item, decision: was, effect: null, outcome: 'remembered', points: 0 });
  }
  const run = { missionId: mission ? mission.id : null, type: mission ? mission.type : 'simple', items, index: 0, results,
    phase: practiceDue ? 'offer' : 'item', closer: {}, opened: {}, pending: null, practice: null, skipped: false, practiced: false };
  return practiceDue ? run : advance(run, 0);
}

const answered = (run, key) => run.results.some((r) => r.key === key);

// The next unanswered item from `from`, else the summary.
function advance(run, from = run.index) {
  const fresh = { ...run, pending: null, showing: null, guide: null };
  for (let i = from; i < run.items.length; i += 1) if (!answered(run, run.items[i].key)) return { ...fresh, index: i, phase: 'item' };
  for (let i = 0; i < from && i < run.items.length; i += 1) if (!answered(run, run.items[i].key)) return { ...fresh, index: i, phase: 'item' };
  return { ...fresh, phase: 'summary' };
}

export const currentItem = (run) => (run && run.items[run.index]) || null;
export const doneCount = (run) => run.results.length;

// A game's decisions, made safe: a game that throws or breaks the rules gets
// Later / I did this; a removing decision never leads on an alerting item;
// while looking closer, the item stays open until another decision.
export function decisionsFor(run, game, item, ctx) {
  let d;
  try { d = game.decisions(item, ctx); } catch (_) { d = null; }
  const problems = checkDecisions(d, null).filter((p) => !/removal warning/.test(p));
  if (!Array.isArray(d) || problems.length) d = FALLBACK;
  d = d.filter((x) => x && x.effect && EFFECT_KINDS.includes(x.effect.kind));
  if (alerting(item) && d[0] && REMOVING_KINDS.has(d[0].effect.kind)) {
    const safe = d.findIndex((x) => !REMOVING_KINDS.has(x.effect.kind));
    if (safe > 0) d = [d[safe], ...d.filter((_, i) => i !== safe)];
  }
  // Only Look closer itself goes: a game's own acts that show steps
  // (Quarantine, Stop it, Not mine...) are 'closer' effects too and must stay.
  if (run && item && run.closer[item.key]) {
    const rest = d.filter((x) => x.id !== 'closer');
    if (rest.length >= MIN_DECISIONS - 1) d = rest;
  }
  return d.slice(0, MAX_DECISIONS);
}

export function viewFor(run, game, ctx, research) {
  if (run.phase === 'practice') {
    const step = game.practice.script[run.practice.step] || null;
    const item = step ? game.practice.items[step.item] : null;
    return { item, research, decisions: item ? decisionsFor(null, game, item, ctx) : [], index: run.practice.step,
      total: game.practice.script.length, practice: true, step, warning: item && alerting(item) ? REMOVAL_WARNING : '', siblings: [], results: [],
      answer: run.practice.answers[run.practice.step] || null };
  }
  const item = currentItem(run);
  const pending = run.pending;
  return { item, research, decisions: item ? decisionsFor(run, game, item, ctx) : [], index: run.index, total: run.items.length,
    practice: false, warning: item && (alerting(item) || (pending && pending.warning) || (run.guide && run.guide.key === item.key && run.guide.warning)) ? REMOVAL_WARNING : '',
    closer: !!(item && run.closer[item.key]), confirming: run.phase === 'confirm' ? pending : null, done: doneCount(run),
    // Answered, its steps on screen until NEXT.
    showing: !!(item && run.showing && run.showing.key === item.key),
    siblings: run.items.filter((x) => x !== item), results: summaryResults(run),
    // What the last state-only move asked to show (a checklist, steps, a focus).
    guide: item && run.guide && run.guide.key === item.key ? run.guide : null };
}

function record(run, item, d, outcome = 'done') {
  const results = [...run.results.filter((r) => r.key !== item.key), { key: item.key, item, decision: d.id, effect: d.effect, outcome, points: 0 }];
  return { ...run, results };
}

const modulesOf = (effect, item) => {
  const list = [...(Array.isArray(effect.modules) ? effect.modules : []), ...(typeof effect.module === 'string' ? [effect.module] : [])];
  return (list.length ? list : (item.seen_in || [item.finding && item.finding.module])).filter(Boolean).filter((x, i, a) => a.indexOf(x) === i);
};

// Text lists an effect carries: string[] or { standard: string[], city: string[] }
// (the person's mode). Only strings; the screen escapes them.
export function textList(v, mode) {
  const list = Array.isArray(v) ? v : v && typeof v === 'object' ? v[mode === 'city' ? 'city' : 'standard'] : null;
  return Array.isArray(list) ? list.filter((x) => typeof x === 'string' && x.trim()) : [];
}
const textOf = (v, mode) => (typeof v === 'string' ? v : v && typeof v === 'object' && typeof v[mode === 'city' ? 'city' : 'standard'] === 'string' ? v[mode === 'city' ? 'city' : 'standard'] : '');

// What a decision asks to show with it (R9, R10): steps, a checklist, a hint,
// a focus (which part of the job the steps are for) and `off` (switch-off steps).
export function guideOf(item, d, mode) {
  const e = d.effect || {};
  const steps = textList(e.steps, mode);
  const checklist = textList(e.checklist, mode);
  const hint = textOf(e.hint, mode) || textOf(d.hint, mode);
  const focus = typeof e.focus === 'string' && /^[a-z][a-z-]{0,30}$/.test(e.focus) ? e.focus : '';
  const off = e.off === true;
  if (!steps.length && !checklist.length && !hint) return null;
  return { key: item.key, decision: d.id, steps, checklist, hint, focus, off, warning: e.warning === true };
}

// Effects that answer the item without the computer being touched. With
// something to show (steps, a checklist), the item stays on screen, answered,
// until NEXT (proceed); otherwise the next item comes straight away.
const ANSWERS = new Set(['later', 'keep', 'note', 'odd']);
const confirmed = (run, item, d) => !!(run.pending && run.pending.confirmed && run.pending.key === item.key && run.pending.decision.id === d.id);

// `ctx.resolve(intent)`: research.js resolveLink with the mode and platform.
export function choose(run, id, game, ctx) {
  if (run.phase !== 'item' && run.phase !== 'confirm') return { run, act: null };
  if (run.showing) return { run, act: null };
  const item = currentItem(run);
  if (!item) return { run, act: null };
  const d = decisionsFor(run, game, item, ctx).find((x) => x.id === id);
  if (!d) return { run, act: null };
  const e = d.effect;
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const guide = guideOf(item, d, mode);
  const steps = guide ? guide.steps : [];
  // Keeping ("Mine") an item that warns is one click the person may regret:
  // a one-line "only if it's yours" confirm first (MarkFlow's own mark has one).
  if (e.kind === 'keep' && alerting(item) && !confirmed(run, item, d)) {
    return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: d, warning: true, deferred: d.id, ask: 'keep' } }, act: null };
  }
  // R6: a warned effect shows the removal warning first and acts only after
  // the person has read it (a fix's own confirm is FixFlow's panel).
  if (e.warning === true && e.kind !== 'fix' && !confirmed(run, item, d)) {
    return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: d, warning: true, deferred: d.id } }, act: null };
  }
  const base = { ...run, phase: 'item', pending: null };
  switch (e.kind) {
    case 'later': case 'keep': case 'note': case 'odd': {
      const odd = e.kind === 'odd' ? { kind: 'odd', item, module: e.module || item.finding.module, code: e.code || item.finding.code || null, key: e.key || item.key } : null;
      const answered = record(base, item, d);
      if (guide && (guide.steps.length || guide.checklist.length)) {
        return { run: { ...answered, guide, showing: { key: item.key } }, act: odd || { kind: 'steps', ...guide } };
      }
      return { run: advance(answered), act: odd };
    }
    case 'closer': {
      // A game's own act shown as steps the person carries out (Quarantine,
      // Stop it, Not mine, Hand back): that is the decision, so it is answered
      // and its steps stay on screen until NEXT. Unless the game offers a
      // re-check for it (a lock's "Done"): then the item stays open for that.
      const all = decisionsFor(run, game, item, ctx);
      if (d.id !== 'closer' && guide && (guide.steps.length || guide.checklist.length) && !all.some((x) => x.effect.kind === 'recheck')) {
        return { run: { ...record(base, item, d), guide, showing: { key: item.key } }, act: { kind: 'steps', ...guide } };
      }
      return { run: { ...base, closer: { ...run.closer, [item.key]: true }, guide }, act: guide ? { kind: 'steps', ...guide } : null };
    }
    case 'mark':
      return { run: { ...base, guide, pending: { key: item.key, decision: d } }, act: { kind: 'mark', item, steps } };
    case 'fix':
      // Always a confirm with the warning first (FixFlow's own panel is that confirm).
      return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: d, warning: alerting(item) } },
        act: { kind: 'fix', item, options: fixOptions(item, ctx.mode) } };
    case 'settings': case 'link': {
      const intent = e.kind === 'settings' ? { kind: 'settings', pane: e.pane, permission: e.permission } : e.link || e;
      const resolved = ctx.resolve ? ctx.resolve(intent) : null;
      const act = { kind: e.kind === 'settings' || (resolved && resolved.kind === 'settings') ? 'settings' : 'link', item,
        url: resolved ? resolved.url : null, text: resolved ? resolved.text : '', steps };
      return { run: { ...base, guide, opened: { ...run.opened, [item.key]: d.id } }, act };
    }
    case 'recheck':
      return { run: { ...base, guide, pending: { key: item.key, decision: d } }, act: { kind: 'recheck', item, modules: modulesOf(e, item), steps } };
    default:
      return { run, act: null };
  }
}

// A link under "Check it yourself" (a settings page or a look-up). On an item
// that warns, or whose decisions are warned (R6), it waits behind the same
// confirm as a warned decision; otherwise it opens straight away.
export function openLink(run, game, ctx, act) {
  const item = currentItem(run);
  if (!item || !act) return { run, act: null };
  const warned = alerting(item) || act.warning === true
    || decisionsFor(run, game, item, ctx).some((x) => x.effect && x.effect.warning === true);
  if (!warned) return { run, act };
  return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: { id: 'link' }, warning: true, act } }, act: null };
}

// After an answered item's steps: on to the next one.
export function proceed(run) {
  if (!run || !run.showing) return run;
  return advance({ ...run, showing: null, guide: null }, run.index + 1);
}

// The warning was read: carry the decision out (`game`, `ctx` as for choose).
export function confirmPending(run, game = null, ctx = {}) {
  const p = run.pending;
  if (run.phase !== 'confirm' || !p) return { run, act: null };
  if (p.act) return { run: { ...run, phase: 'item', pending: null, opened: { ...run.opened, [p.key]: p.decision.id } }, act: p.act };
  if (p.deferred && game) return choose({ ...run, pending: { ...p, confirmed: true } }, p.deferred, game, ctx);
  return { run, act: null };
}
export function cancelPending(run) {
  return { ...run, phase: run.phase === 'confirm' ? 'item' : run.phase, pending: null };
}

// A mark, fix or re-check came back. 'done' answers the item; anything else
// leaves it open.
// `item`: the item itself, when a re-check has already taken it off the
// mission's list (a fix that worked).
export function settle(run, outcome, item0 = null) {
  const p = run.pending;
  if (!p) return run;
  const item = run.items.find((i) => i.key === p.key) || (item0 && item0.key === p.key ? item0 : null);
  const cleared = { ...run, pending: null, phase: run.phase === 'confirm' ? 'item' : run.phase };
  if (!item || outcome !== 'done') return cleared;
  return advance(record(cleared, item, p.decision, 'done'));
}

export function addPoints(run, key, n) {
  return { ...run, results: run.results.map((r) => (r.key === key ? { ...r, points: (r.points || 0) + (Number(n) || 0) } : r)) };
}

// Skip an item for now without answering (NEXT): it stays unanswered.
export function skip(run) {
  return advance({ ...run, pending: null }, run.index + 1);
}

// --- practice ---
export function startPractice(run, game) {
  if (!game || !game.practice || !Array.isArray(game.practice.script) || !game.practice.script.length) return advance({ ...run, phase: 'item' }, 0);
  return { ...run, phase: 'practice', practice: { step: 0, answers: [], back: run.phase === 'offer' ? 'item' : run.phase } };
}
export function skipPractice(run) {
  if (run.phase !== 'offer' && run.phase !== 'practice') return run;
  return advance({ ...run, practice: null, skipped: run.phase === 'offer' ? true : run.skipped }, run.index);
}
// One move in the practice round. `right` is null for a step with no expected move.
export function choosePractice(run, game, id) {
  if (run.phase !== 'practice') return { run, answer: null };
  const step = game.practice.script[run.practice.step];
  if (!step || run.practice.answers[run.practice.step]) return { run, answer: null };
  const right = typeof step.expect === 'string' ? id === step.expect : null;
  const answers = [...run.practice.answers];
  answers[run.practice.step] = { id, right };
  return { run: { ...run, practice: { ...run.practice, answers } }, answer: { step: run.practice.step, right, expect: step.expect || null } };
}
export function nextPracticeStep(run, game) {
  if (run.phase !== 'practice') return run;
  const n = run.practice.step + 1;
  if (n < game.practice.script.length) return { ...run, practice: { ...run.practice, step: n } };
  return advance({ ...run, practice: null, practiced: true }, run.index);
}

// Due the first time a type is met; after "I know this", again when a gap
// shows on one of its concepts; never again after it was played, unless asked.
// `record`: { how: 'played'|'skipped', at } or null. `conceptStates`: player-profile conceptState per concept.
export function practiceDue(record, conceptStates = []) {
  if (!record) return true;
  if (record.how === 'skipped') return conceptStates.includes('worth-a-look');
  return false;
}

// --- remembering ---
// Keys that change for reasons other than the evidence (counts, timing, sizes
// that drift) are left out, so a remembered answer isn't lost to noise.
const VOLATILE = new Set(['pid', 'cpu', 'cpu_percent', 'memory', 'memory_mb', 'mem', 'rss', 'elapsed', 'seconds', 'uptime', 'timestamp',
  'checked_at', 'scanned_at', 'last_seen', 'seen', 'age_days', 'count', 'marked_by_user', 'mark_stale', 'mark_unchecked', 'known_item_id',
  'original_severity', 'original_title']);
function stable(v, depth = 0) {
  if (v == null || typeof v !== 'object') return v;
  if (depth > 3) return null;
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => stable(x, depth + 1));
  const out = {};
  for (const k of Object.keys(v).sort()) if (!VOLATILE.has(k)) out[k] = stable(v[k], depth + 1);
  return out;
}
export function fingerprint(item) {
  const fs = [item && item.finding, ...((item && item.findings) || [])].filter(Boolean);
  const parts = fs.map((f) => ({ code: f.code || f.title || '', data: stable(f.data || {}),
    signer: (Array.isArray(f.made_by) ? f.made_by : []).filter(Boolean).map((m) => [m.subject || '', m.name || '', m.verified === true]) }));
  const uniq = [...new Set(parts.map((p) => JSON.stringify(p)))].sort();
  return shortHash(uniq.join('\n'));
}

const KEPT_KINDS = new Set(['keep', 'note', 'mark', 'fix', 'recheck']);
export function remembers(result) {
  return !!result && result.outcome !== 'remembered' && !!result.effect && KEPT_KINDS.has(result.effect.kind);
}

export function summaryResults(run) {
  return run.results.map((r) => ({ item: r.item, decision: r.decision, effect: r.effect, points: r.points || 0 }));
}
