// One mission, played: a pure state machine (spec: "Runner and screens").
//
// Games only return decisions with EFFECTS; the runner decides what an effect
// means and hands the controller an ACT to carry out through the existing
// paths (MarkFlow, FixFlow, the re-check, open-setting, allowlisted links).
// Nothing here touches the DOM, storage or the computer.
//
//   startRun(mission, { practiceDue, recalled }) -> run
//   decisionsFor(run, game, item, ctx) -> Decision[]   checked, safe default first, closer dropped while looking closer
//   viewFor(run, game, ctx, research) -> view          what the screen draws (game.render gets the same view)
//   choose(run, id, game, ctx) -> { run, act }         act: null | { kind: mark|fix|settings|link|recheck|lesson|odd, … }
//   confirmPending(run) / cancelPending(run)           the warning-before-acting step (R6)
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
import { EFFECT_KINDS, MIN_DECISIONS, MAX_DECISIONS, REMOVING_KINDS, checkDecisions } from './contract.js';
import { shortHash } from '../game/folded.js';

export const REMOVAL_WARNING = 'Removing this can alert whoever installed it.';

export function alerting(item) {
  if (!item) return false;
  const fs = [item.finding, ...(Array.isArray(item.findings) ? item.findings : [])].filter(Boolean);
  return item.removal_alert === true || fs.some((f) => f.removal_alert === true || !!(f.remediation && f.remediation.safety_note));
}

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
  for (let i = from; i < run.items.length; i += 1) if (!answered(run, run.items[i].key)) return { ...run, index: i, phase: 'item', pending: null };
  for (let i = 0; i < from && i < run.items.length; i += 1) if (!answered(run, run.items[i].key)) return { ...run, index: i, phase: 'item', pending: null };
  return { ...run, phase: 'summary', pending: null };
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
  if (run && item && run.closer[item.key]) {
    const rest = d.filter((x) => x.effect.kind !== 'closer');
    if (rest.length >= MIN_DECISIONS - 1) d = rest;
  }
  return d.slice(0, MAX_DECISIONS);
}

export function viewFor(run, game, ctx, research) {
  if (run.phase === 'practice') {
    const step = game.practice.script[run.practice.step] || null;
    const item = step ? game.practice.items[step.item] : null;
    return { item, research, decisions: item ? decisionsFor(null, game, item, ctx) : [], index: run.practice.step,
      total: game.practice.script.length, practice: true, step, warning: item && alerting(item) ? REMOVAL_WARNING : '',
      answer: run.practice.answers[run.practice.step] || null };
  }
  const item = currentItem(run);
  const pending = run.pending;
  return { item, research, decisions: item ? decisionsFor(run, game, item, ctx) : [], index: run.index, total: run.items.length,
    practice: false, warning: item && (alerting(item) || (pending && pending.warning)) ? REMOVAL_WARNING : '',
    closer: !!(item && run.closer[item.key]), confirming: run.phase === 'confirm' ? pending : null, done: doneCount(run) };
}

function record(run, item, d, outcome = 'done') {
  const results = [...run.results.filter((r) => r.key !== item.key), { key: item.key, item, decision: d.id, effect: d.effect, outcome, points: 0 }];
  return { ...run, results };
}

const modulesOf = (effect, item) => {
  const list = [...(Array.isArray(effect.modules) ? effect.modules : []), ...(typeof effect.module === 'string' ? [effect.module] : [])];
  return (list.length ? list : (item.seen_in || [item.finding && item.finding.module])).filter(Boolean).filter((x, i, a) => a.indexOf(x) === i);
};

// `ctx.resolve(intent)`: research.js resolveLink with the mode and platform.
export function choose(run, id, game, ctx) {
  if (run.phase !== 'item' && run.phase !== 'confirm') return { run, act: null };
  const item = currentItem(run);
  if (!item) return { run, act: null };
  const d = decisionsFor(run, game, item, ctx).find((x) => x.id === id);
  if (!d) return { run, act: null };
  const e = d.effect;
  const steps = Array.isArray(e.steps) ? e.steps.filter((x) => typeof x === 'string') : [];
  switch (e.kind) {
    case 'later': case 'keep': case 'note':
      return { run: advance(record(run, item, d)), act: null };
    case 'odd':
      return { run: advance(record(run, item, d)), act: { kind: 'odd', item, module: e.module || item.finding.module, code: e.code || item.finding.code || null, key: e.key || item.key } };
    case 'closer':
      return { run: { ...run, closer: { ...run.closer, [item.key]: true } }, act: steps.length ? { kind: 'steps', steps } : null };
    case 'mark':
      return { run: { ...run, pending: { key: item.key, decision: d } }, act: { kind: 'mark', item } };
    case 'fix':
      // Always a confirm with the warning first (FixFlow's own panel is that confirm).
      return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: d, warning: alerting(item) } },
        act: { kind: 'fix', item, options: fixOptions(item, ctx.mode) } };
    case 'settings': case 'link': {
      const resolved = ctx.resolve ? ctx.resolve(e.kind === 'settings' ? { kind: 'settings', pane: e.pane, permission: e.permission } : e.link || e) : null;
      const act = { kind: e.kind === 'settings' ? 'settings' : 'link', item, url: resolved ? resolved.url : null, text: resolved ? resolved.text : '', steps };
      if (e.warning === true && !(run.pending && run.pending.confirmed && run.pending.key === item.key && run.pending.decision.id === d.id)) {
        return { run: { ...run, phase: 'confirm', pending: { key: item.key, decision: d, warning: true, act } }, act: null };
      }
      return { run: { ...run, phase: 'item', pending: null, opened: { ...run.opened, [item.key]: d.id } }, act };
    }
    case 'recheck':
      return { run: { ...run, pending: { key: item.key, decision: d } }, act: { kind: 'recheck', item, modules: modulesOf(e, item) } };
    default:
      return { run, act: null };
  }
}

// The warning was read: carry the act out.
export function confirmPending(run) {
  const p = run.pending;
  if (run.phase !== 'confirm' || !p || !p.act) return { run, act: null };
  return { run: { ...run, phase: 'item', pending: null, opened: { ...run.opened, [p.key]: p.decision.id } }, act: p.act };
}
export function cancelPending(run) {
  return { ...run, phase: run.phase === 'confirm' ? 'item' : run.phase, pending: null };
}

// A mark, fix or re-check came back. 'done' answers the item; anything else
// leaves it open.
export function settle(run, outcome) {
  const p = run.pending;
  if (!p) return run;
  const item = run.items.find((i) => i.key === p.key);
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
