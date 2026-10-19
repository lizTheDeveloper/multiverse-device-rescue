// "Add to my school profile": the only thing that ever leaves, and only as a
// file the person saves or text they copy, then import themselves in The
// Multiverse School's Profile Viewer. No network call here, ever.
//
// The payload is an MVProfile fragment in the school's record shape,
// { <group>: { <field>: { by: { <workbook>: { value, at, seq } } } } }, so the
// viewer's merge import (MVSync.mergeProfiles) puts it in its own provenance
// slot without touching anything else. Allow-list only: activity counts,
// skill levels and the rank level. Never findings, paths, missions, lesson
// ids or answers, or anything about the computer.
//
// PUBLISH_READY stays false until the school repo has: the five fields in
// MVProfile's SHAPE; a merge import in the Profile Viewer (fromJSON replaces
// the whole profile today); sharing classes that enforce `never`
// (profile.contract.yml); and pair.js pointed at the real relay, not a LAN
// address. See docs/superpowers/plans/2026-10-18-player-profile-and-irt.md.
import { SKILLS, isHidden } from './skills.js';

export const PUBLISH_READY = false;
export const WORKBOOK = 'reclaim-city';
const DEPTHS = new Set(['introduced', 'practiced']);
// A skill made only of hidden concepts is never published (none is today).
const SKILL_IDS = new Set(SKILLS.filter((s) => s.concepts.some((c) => !isHidden(c))).map((s) => s.id));

export const PUBLISH_FIELDS = Object.freeze([
  { id: 'lessons', group: 'security', field: 'city_lessons_learned', label: 'How many lessons you’ve learned', value: (s) => lessonsLearned(s) },
  { id: 'drills-right', group: 'play', field: 'city_drills_right', label: 'Practice drills you got right', value: (s) => s.drills.right },
  { id: 'drills-tried', group: 'play', field: 'city_drills_tried', label: 'Practice drills you tried', value: (s) => s.drills.tried },
  { id: 'rank', group: 'play', field: 'city_rank_level', label: 'Your rank, as a level from 1 to 5', value: (s) => s.rank.level },
  { id: 'skills', group: 'security', field: 'city_skills', label: 'Your skill levels', value: (s) => skillLevels(s) },
]);
export const STAYS_HERE = 'Your checkup results, your missions and anything about this computer stay here.';

// Lessons learned, judged on their shown concepts only: a hidden concept's
// evidence never moves a published total either way. A lesson with no shown
// concept never counts. Without per-lesson concepts, nothing is counted.
export function lessonsLearned(summary) {
  if (!Array.isArray(summary.lessons)) return null;
  return summary.lessons.filter((l) => {
    const shown = (Array.isArray(l && l.concepts) ? l.concepts : []).filter((c) => c && !isHidden(c.id));
    return shown.length > 0 && shown.every((c) => c.state === 'learned');
  }).length;
}

// Only skills the person has started, as { id: 'introduced' | 'practiced' }.
function skillLevels(summary) {
  return Object.fromEntries((summary.skills || []).filter((k) => SKILL_IDS.has(k.id) && DEPTHS.has(k.depth)).map((k) => [k.id, k.depth]));
}

function validValue(id, v) {
  if (id === 'skills') return !!v && typeof v === 'object' && !Array.isArray(v)
    && Object.entries(v).every(([k, d]) => SKILL_IDS.has(k) && DEPTHS.has(d));
  return Number.isInteger(v) && v >= 0;
}

// The day only (UTC, YYYY-MM-DD), so the payload can't tell when someone
// plays. A Date or a date string; anything else, or an invalid date, is null.
function dayOf(now) {
  if (!(now instanceof Date) && typeof now !== 'string') return null;
  const d = new Date(now);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

// PREVIEW ONLY: builds the exact text that would leave, and never sends it.
// Sending goes through `deliver`, which is gated on PUBLISH_READY and consent.
// Null in city mode, with nothing ticked, without a valid date, or with
// anything that isn't on the list.
export function buildPayload(summary, ticked, { mode, now } = {}) {
  if (mode !== 'standard' || !summary) return null;
  const at = dayOf(now);
  if (!at) return null;
  const want = new Set(Array.isArray(ticked) ? ticked : []);
  const out = {};
  let seq = 0;
  for (const f of PUBLISH_FIELDS) {
    if (!want.has(f.id)) continue;
    const value = f.value(summary);
    if (!validValue(f.id, value)) return null;
    seq += 1;
    out[f.group] = out[f.group] || {};
    out[f.group][f.field] = { by: { [WORKBOOK]: { value, at, seq } } };
  }
  return seq ? JSON.stringify(out, null, 2) : null;
}

// Whether the "Add to my school profile" control exists at all.
export function publishOffered(mode, ready = PUBLISH_READY) {
  return ready === true && mode === 'standard';
}

// TEST SEAM ONLY: production code uses `deliver` below, which is bound to
// PUBLISH_READY. A source-scan test fails if anything outside this file and
// the tests mentions createPublisher.
export function createPublisher({ ready }) {
  // Hand the payload over, only with the person's consent: { fields: [ids] },
  // naming exactly the fields to send, each once, all on the list. `send` is
  // injected (save a file, copy to the clipboard); this module never touches
  // the network. Refuses before building anything unless the control is
  // offered (school side ready, standard mode). Resolves { sent: true, text }
  // or { sent: false, reason }.
  return async function deliver(summary, consent, { mode, now, send } = {}) {
    if (!publishOffered(mode, ready)) return { sent: false, reason: 'not-offered' };
    if (!consent || typeof consent !== 'object' || Array.isArray(consent)
      || !Array.isArray(consent.fields) || consent.fields.length === 0) return { sent: false, reason: 'no-consent' };
    const known = new Set(PUBLISH_FIELDS.map((f) => f.id));
    if (Object.keys(consent).length !== 1 || new Set(consent.fields).size !== consent.fields.length
      || consent.fields.some((id) => !known.has(id))) return { sent: false, reason: 'consent-mismatch' };
    if (typeof send !== 'function') return { sent: false, reason: 'no-transport' };
    // buildPayload emits exactly the ticked fields or nothing at all.
    const text = buildPayload(summary, consent.fields, { mode, now });
    if (!text) return { sent: false, reason: 'refused' };
    try {
      await send(text);
    } catch {
      return { sent: false, reason: 'send-failed' };
    }
    return { sent: true, text };
  };
}

// The only sender production code may use. There is no option to override
// PUBLISH_READY.
export const deliver = createPublisher({ ready: PUBLISH_READY });
