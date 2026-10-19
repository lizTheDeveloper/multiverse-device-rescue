// The command center's points, ranks, game tags and sweep history. Pure.
//
// Real findings score the investigation, never the verdict: opening clues, and
// tagging after looking. A drill (invented, clearly marked) scores right or
// wrong. A confirmed fix (a re-check proved it) scores most; a reported step
// scores less and is labelled YOU REPORTED. Nothing scores for deleting
// anything, for speed, or for anything touching monitoring software.
//
// Every award has a key, and a key pays once: lifetime keys (fix, report,
// drill) or keys for the current sweep (clue, tag bonus, clean sweep). So
// re-tagging, re-opening or re-sweeping can't farm points.
import { emptyDeck, TAGS, SWEEP_FIELDS, validDeck } from './progress.js';
import { bloomHas, takeHash } from './folded.js';

export const POINTS = { clue: 5, tagBonus: 10, drill: 15, drillClueBonus: 5, fix: 50, report: 20, clean: 40 };
export const RANKS = [
  { name: 'ROOKIE', min: 0 },
  { name: 'SIGNAL ANALYST', min: 100 },
  { name: 'NETRUNNER', min: 300 },
  { name: 'SYSOP', min: 700 },
  { name: 'CITY WARDEN', min: 1500 },
];
// The same three checks app.js's gate watches (ALWAYS_SAFETY_MODULES). A test keeps them equal.
export const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
export const MAX_SWEEPS = 20;
const LIFETIME = new Set(['fix', 'report', 'drill']);
const PER_SWEEP = new Set(['clue', 'tagBonus', 'clean']);

const deckOf = (deck) => (validDeck(deck) ? deck : emptyDeck());
const none = (deck) => ({ deck, points: 0, rankUp: false });

// The module an award key or an identity belongs to:
// "module|code|…", "couldnt|module", or "identity#clue".
export function moduleOfKey(key) {
  const k = String(key == null ? '' : key).split('#')[0];
  return k.startsWith('couldnt|') ? k.slice(8) : k.split('|')[0];
}

export function rankIndexFor(points) {
  let i = 0;
  RANKS.forEach((r, n) => { if (points >= r.min) i = n; });
  return i;
}

// Rank never drops: the stored rank is the highest one reached.
export function rankOf(deck) {
  const d = deckOf(deck);
  const index = Math.min(RANKS.length - 1, Math.max(d.rank, rankIndexFor(d.points)));
  const next = RANKS[index + 1] || null;
  return { index, name: RANKS[index].name, points: d.points, min: RANKS[index].min, next,
    toNext: next ? Math.max(0, next.min - d.points) : 0 };
}

// `extra` adds points to this award (the drill clue bonus).
export function award(deck, kind, key, extra = 0) {
  const d = deckOf(deck);
  if (!LIFETIME.has(kind) && !PER_SWEEP.has(kind)) return none(d);
  if (typeof key !== 'string' || key === '' || MONITORING_MODULES.has(moduleOfKey(key))) return none(d);
  const k = `${kind}:${key}`;
  const lifetime = LIFETIME.has(kind);
  // A key folded into `paid` (folded.js) has paid too. Drill keys are never folded.
  const folded = kind !== 'drill' && bloomHas(lifetime ? d.paid : d.sweep.paid, k);
  if (folded || (lifetime ? d.once[k] : d.sweep.keys[k])) return none(d);
  const points = POINTS[kind] + (Number.isInteger(extra) && extra > 0 ? extra : 0);
  const total = d.points + points;
  const rank = Math.max(d.rank, rankIndexFor(total));
  return {
    deck: { ...d, points: total, rank,
      once: lifetime ? { ...d.once, [k]: true } : d.once,
      sweep: lifetime ? d.sweep : { ...d.sweep, keys: { ...d.sweep.keys, [k]: true } } },
    points,
    rankUp: rank > d.rank,
  };
}

// Game sorting only: a tag changes nothing on the computer. `fp` is the
// finding's fingerprint (signals.js): when it changes, the tag stops applying.
export function setTag(deck, id, tag, fp, now) {
  const d = deckOf(deck);
  if (typeof id !== 'string' || id === '' || !TAGS.has(tag) || MONITORING_MODULES.has(moduleOfKey(id))) return d;
  return { ...d, tags: { ...d.tags, [id]: { tag, at: String(now), fp: String(fp == null ? '' : fp) } } };
}

export function recordDrill(deck, right) {
  const d = deckOf(deck);
  return { ...d, drills: { right: d.drills.right + (right ? 1 : 0), tried: d.drills.tried + 1 } };
}

// A re-check proved the fix: it counts as CONFIRMED, and the fix points pay
// once per finding, ever.
export function confirmFix(deck, id, now) {
  const d = deckOf(deck);
  if (typeof id !== 'string' || id === '' || MONITORING_MODULES.has(moduleOfKey(id))) return none(d);
  return award({ ...d, confirmed: { ...d.confirmed, [id]: String(now) } }, 'fix', id);
}

export const sweepPercent = (w) => (w && w.checked > 0 ? Math.round((w.secured / w.checked) * 100) : null);
const isClean = (w) => !!w && w.checked > 0 && w.secured === w.checked;

// A finished scan, recorded as a date and counts only. It starts a new sweep,
// so clue and tag bonuses can be earned again. The clean-sweep bonus pays when
// a re-sweep is the one that made the board clean, not on every clean re-sweep.
// `carry`: this sweep holds monitoring software (held.js). A sweep that
// carries it, or follows one that did (deck.sweep.carry, stored, so a restart
// changes nothing), is recorded but never paid or called clean: its going is
// not a win.
export function recordSweep(deck, counts, now, { carry = false } = {}) {
  const d = deckOf(deck);
  const entry = { at: String(now) };
  for (const k of SWEEP_FIELDS) {
    const n = Math.floor(Number(counts && counts[k]));
    entry[k] = Number.isFinite(n) && n > 0 ? n : 0;
  }
  if (entry.secured > entry.checked) entry.secured = entry.checked;
  const prev = d.sweeps.length ? d.sweeps[d.sweeps.length - 1] : null;
  const next = { ...d, sweep: { at: entry.at, keys: {}, ...(carry ? { carry: true } : {}) }, sweeps: [...d.sweeps, entry].slice(-MAX_SWEEPS) };
  if (carry || d.sweep.carry === true || !(prev && isClean(entry) && !isClean(prev))) return { deck: next, points: 0, rankUp: false, clean: false };
  return { ...award(next, 'clean', entry.at), clean: true };
}

// After any scan or re-check, with buildSignals(…) for the new city. A tag
// whose finding changed is set aside (changed). A tag whose finding is gone
// from a check that ran is dropped (gone). A confirmed fix that shows up again
// is no longer counted as confirmed. Points are never taken back.
export function reconcileDeck(deck, signals, ranOk) {
  const d = deckOf(deck);
  const byId = new Map((signals || []).filter((x) => x && x.kind !== 'drill').map((x) => [x.id, x]));
  const tags = {};
  const changed = [];
  const gone = [];
  for (const [id, rec] of Object.entries(d.tags)) {
    const sig = byId.get(id);
    if (sig) {
      if (sig.fp === rec.fp) tags[id] = rec; else changed.push(id);
      continue;
    }
    if (ranOk && ranOk.has(moduleOfKey(id))) gone.push(id); else tags[id] = rec;
  }
  const confirmed = {};
  for (const [id, at] of Object.entries(d.confirmed)) if (!byId.has(id)) confirmed[id] = at;
  // A confirmed fix folded into a count (confirmedEarlier, with its id as a
  // short hash in confirmedFolded) that shows up again leaves the count too.
  const extra = {};
  if (d.confirmedFolded) {
    let hashes = d.confirmedFolded;
    let earlier = d.confirmedEarlier || 0;
    for (const id of byId.keys()) {
      const rest = takeHash(hashes, id);
      if (rest === null) continue;
      hashes = rest;
      earlier = Math.max(0, earlier - 1);
    }
    extra.confirmedFolded = hashes;
    extra.confirmedEarlier = earlier;
  }
  return { deck: { ...d, tags, confirmed, ...extra }, changed, gone };
}
