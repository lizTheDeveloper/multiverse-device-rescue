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
const SKILL_IDS = new Set(SKILLS.map((s) => s.id).filter((id) => !isHidden(id)));

export const PUBLISH_FIELDS = Object.freeze([
  { id: 'lessons', group: 'security', field: 'city_lessons_learned', label: 'How many lessons you’ve learned', value: (s) => s.lessonsLearned },
  { id: 'drills-right', group: 'play', field: 'city_drills_right', label: 'Practice drills you got right', value: (s) => s.drills.right },
  { id: 'drills-tried', group: 'play', field: 'city_drills_tried', label: 'Practice drills you tried', value: (s) => s.drills.tried },
  { id: 'rank', group: 'play', field: 'city_rank_level', label: 'Your rank, as a level from 1 to 5', value: (s) => s.rank.level },
  { id: 'skills', group: 'security', field: 'city_skills', label: 'Your skill levels', value: (s) => skillLevels(s) },
]);
export const STAYS_HERE = 'Your checkup results, your missions and anything about this computer stay here.';

// Only skills the person has started, as { id: 'introduced' | 'practiced' }.
function skillLevels(summary) {
  return Object.fromEntries((summary.skills || []).filter((k) => SKILL_IDS.has(k.id) && DEPTHS.has(k.depth)).map((k) => [k.id, k.depth]));
}

function validValue(id, v) {
  if (id === 'skills') return !!v && typeof v === 'object' && !Array.isArray(v)
    && Object.entries(v).every(([k, d]) => SKILL_IDS.has(k) && DEPTHS.has(d));
  return Number.isInteger(v) && v >= 0;
}

// The exact text that would leave, for the ticked field ids, or null: in city
// mode, with nothing ticked, or with anything that isn't on the list.
export function buildPayload(summary, ticked, { mode, now }) {
  if (mode !== 'standard' || !summary) return null;
  const want = new Set(Array.isArray(ticked) ? ticked : []);
  const out = {};
  let seq = 0;
  for (const f of PUBLISH_FIELDS) {
    if (!want.has(f.id)) continue;
    const value = f.value(summary);
    if (!validValue(f.id, value)) return null;
    seq += 1;
    out[f.group] = out[f.group] || {};
    out[f.group][f.field] = { by: { [WORKBOOK]: { value, at: String(now), seq } } };
  }
  return seq ? JSON.stringify(out, null, 2) : null;
}

// Whether the "Add to my school profile" control exists at all.
export function publishOffered(mode, ready = PUBLISH_READY) {
  return ready === true && mode === 'standard';
}

// Hand the payload over, only with the person's consent: { fields: [ids] },
// naming exactly the fields to send, each once, all on the list. `send` is
// injected (save a file, copy to the clipboard); this module never touches the
// network. Refuses before building anything unless the control is offered
// (school side ready, standard mode). Resolves { sent: true, text } or
// { sent: false, reason }.
export async function deliver(summary, consent, { mode, now, ready = PUBLISH_READY, send } = {}) {
  if (!publishOffered(mode, ready)) return { sent: false, reason: 'not-offered' };
  if (!consent || typeof consent !== 'object' || Array.isArray(consent)
    || !Array.isArray(consent.fields) || consent.fields.length === 0) return { sent: false, reason: 'no-consent' };
  const known = new Set(PUBLISH_FIELDS.map((f) => f.id));
  const named = new Set(consent.fields);
  if (Object.keys(consent).length !== 1 || named.size !== consent.fields.length
    || consent.fields.some((id) => !known.has(id))) return { sent: false, reason: 'consent-mismatch' };
  if (typeof send !== 'function') return { sent: false, reason: 'no-transport' };
  const text = buildPayload(summary, consent.fields, { mode, now });
  if (!text) return { sent: false, reason: 'refused' };
  // The built text must carry exactly the consented fields, no more, no fewer.
  const doc = JSON.parse(text);
  const sent = new Set(Object.entries(doc).flatMap(([g, fs]) => Object.keys(fs).map((f) => `${g}.${f}`)));
  const want = new Set(PUBLISH_FIELDS.filter((f) => named.has(f.id)).map((f) => `${f.group}.${f.field}`));
  if (sent.size !== want.size || [...want].some((k) => !sent.has(k))) return { sent: false, reason: 'consent-mismatch' };
  try {
    await send(text);
  } catch {
    return { sent: false, reason: 'send-failed' };
  }
  return { sent: true, text };
}
