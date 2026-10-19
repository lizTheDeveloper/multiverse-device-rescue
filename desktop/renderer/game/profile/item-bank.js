// The item bank: every lesson question and every variant of it, plus every
// practice drill, as items that item response theory can measure. And the
// adaptive draw: which few items a lesson visit (or "Learn this") asks next.
// Pure.
//
// A lesson question is a *family*: its own prompt is the family's first item,
// and each entry in its `variants` is another item on the same skill, worded
// differently or set in a different scene. A family shares its `teach`,
// `setting`, `key` prefix and `concept`.
import { guessFloor, levelB, information } from './irt.js';
import { DRILL_CONCEPTS } from './skills.js';

export const VISIT_MAX = 3;
export const LEARN_THIS_MAX = 2;
// An item asked among a concept's last RECENT answers isn't asked again yet.
export const RECENT = 2;

function lessonItems(lesson) {
  const out = [];
  for (const q of Array.isArray(lesson.questions) ? lesson.questions : []) {
    if (!q || typeof q.key !== 'string' || typeof q.concept !== 'string') continue;
    const shared = { family: q.key, concept: q.concept, lessonId: lesson.id, kind: 'lesson', teach: q.teach || null, setting: q.setting || null };
    const all = [{ ...q, first: true }, ...(Array.isArray(q.variants) ? q.variants.map((v) => ({ ...v, first: false })) : [])];
    for (const v of all) {
      if (!v || typeof v.key !== 'string' || !Array.isArray(v.options)) continue;
      out.push({ ...shared, key: v.key, first: v.first, prompt: v.prompt, options: v.options, message: v.message || null,
        level: v.level || q.level || 'medium', c: guessFloor(v.options.length) });
    }
  }
  return out;
}

function drillItem(d) {
  const concept = Object.prototype.hasOwnProperty.call(DRILL_CONCEPTS, d.id) ? DRILL_CONCEPTS[d.id] : null;
  return { key: `drill:${d.id}`, family: `drill:${d.id}`, concept, lessonId: null, kind: 'drill', first: true, level: 'medium', c: guessFloor(3) };
}

// `lessons`: as training.loadLessons returns them. `drills`: as drills.loadDrills does.
// The first item with a key wins; a later duplicate is left out.
export function buildBank(lessons, drills) {
  const items = new Map();
  const byLesson = new Map();
  const byConcept = new Map();
  const add = (it) => {
    if (items.has(it.key)) return false;
    items.set(it.key, it);
    if (it.concept) {
      if (!byConcept.has(it.concept)) byConcept.set(it.concept, []);
      byConcept.get(it.concept).push(it.key);
    }
    return true;
  };
  for (const l of Array.isArray(lessons) ? lessons : []) {
    if (!l || typeof l.id !== 'string') continue;
    const keys = lessonItems(l).filter(add).map((it) => it.key);
    const concepts = [...new Set(keys.map((k) => items.get(k).concept))];
    const families = [...new Set(keys.map((k) => items.get(k).family))];
    byLesson.set(l.id, { id: l.id, title: l.title, concepts, families, keys, modules: l.modules || [], recommendedFor: l.recommendedFor || [] });
  }
  for (const d of Array.isArray(drills) ? drills : []) if (d && typeof d.id === 'string') add(drillItem(d));
  return { items, lessons: byLesson, concepts: byConcept };
}

export const emptyBank = () => buildBank([], []);

export function lessonsWithConcept(bank, conceptId) {
  return [...bank.lessons.values()].filter((l) => l.concepts.includes(conceptId)).map((l) => l.id);
}

// `history[conceptId]`: { mean, learned, recent: [itemKey, …] newest last, seen: Set<itemKey> }.
// `seen` may also be an array (as it comes back from storage).
// `bOf(key)`: the item's current difficulty.
const seenSet = (h) => (h && h.seen instanceof Set ? h.seen : new Set(h && Array.isArray(h.seen) ? h.seen : []));

function fill(bank, lists, max) {
  const out = [];
  const families = new Set();
  // One item per family first; then, if there is room, another variant of a family already asked.
  for (const oneEach of [true, false]) {
    while (out.length < max) {
      let added = false;
      for (const list of lists) {
        if (out.length >= max) break;
        const k = list.find((key) => !out.includes(key) && !(oneEach && families.has(bank.items.get(key).family)));
        if (k) { out.push(k); families.add(bank.items.get(k).family); added = true; }
      }
      if (!added) break;
    }
  }
  return out;
}

function pick(bank, conceptIds, history, max, bOf, only) {
  const candidates = conceptIds.map((c) => {
    const h = history[c] || { mean: 0, recent: [], seen: [] };
    const keys = (bank.concepts.get(c) || []).filter((k) => {
      const it = bank.items.get(k);
      return it.kind === 'lesson' && (!only || only(it));
    });
    return { h, keys, recentList: Array.isArray(h.recent) ? h.recent : [] };
  });
  const lists = candidates.map(({ h, keys, recentList }) => {
    const recent = new Set(recentList.slice(-RECENT));
    const seen = seenSet(h);
    // Unseen items first; then the most informative at the current estimate; then bank order.
    return keys.filter((k) => !recent.has(k))
      .map((k, i) => ({ k, i, unseen: seen.has(k) ? 0 : 1, info: information(h.mean || 0, bOf(k), bank.items.get(k).c) }))
      .sort((a, b) => (b.unseen - a.unseen) || (b.info - a.info) || (a.i - b.i)).map((x) => x.k);
  });
  const out = fill(bank, lists, max);
  if (out.length || max < 1) return out;
  // Every item was asked just now: rather than an empty visit, ask the one
  // asked least recently on each concept (the earliest last appearance in `recent`).
  const oldest = candidates.map(({ keys, recentList }) => {
    const last = (k) => recentList.lastIndexOf(k);
    const sorted = keys.map((k, i) => ({ k, i, at: last(k) })).sort((a, b) => (a.at - b.at) || (a.i - b.i));
    return sorted.length ? [sorted[0].k] : [];
  });
  return fill(bank, oldest, max);
}

const defaultB = (bank) => (k) => levelB(bank.items.get(k).level);

// The items for one visit to a lesson. The first visit (nothing answered on
// any of its concepts yet) is the lesson as written: each question's own
// item, in order. After that: up to VISIT_MAX items, one per family, spread
// over the concepts not learned yet (or over all of them, as a review).
export function drawLessonVisit(bank, lessonId, history, { max = VISIT_MAX, bOf = defaultB(bank) } = {}) {
  const l = bank.lessons.get(lessonId);
  if (!l) return [];
  const answered = l.concepts.some((c) => history[c] && seenSet(history[c]).size > 0);
  if (!answered) return l.families.map((f) => l.keys.find((k) => bank.items.get(k).family === f && bank.items.get(k).first)).filter(Boolean);
  const open = l.concepts.filter((c) => !(history[c] && history[c].learned));
  return pick(bank, open.length ? open : l.concepts, history, max, bOf, (it) => it.lessonId === lessonId);
}

// "Learn this (2 questions)": items on one concept, from any lesson.
export function drawConcept(bank, conceptId, history, { max = LEARN_THIS_MAX, bOf = defaultB(bank) } = {}) {
  return pick(bank, [conceptId], history, max, bOf, null);
}
