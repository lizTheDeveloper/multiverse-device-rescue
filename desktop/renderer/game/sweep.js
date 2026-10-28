// The sweep's logic, apart from drawing it. Pure.
// - noteFor: what a check looks at, why, and where (check-notes.js, generated).
// - logLine: one finished check, in plain words, for the sweep log.
// - sweepPick: the lesson to offer next while the scan runs.
// - lessonItems: which item of each question's bank to show this time.
import { CHECK_NOTES } from './check-notes.js';
import { districtIdFor } from './findings-to-city.js';
import { orderLessons } from './training.js';
import { lessonDone } from './progress.js';

const humanize = (m) => {
  const words = String(m).replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
};

export function noteFor(module) {
  if (!module) return null;
  const n = Object.prototype.hasOwnProperty.call(CHECK_NOTES, module) ? CHECK_NOTES[module] : null;
  if (!n) return { module, what: humanize(module), why: '', where: '' };
  return { module, what: n.what, why: n.why, where: n.where };
}

export function logLine(entry) {
  const e = entry || {};
  const note = noteFor(e.module);
  const result = e.outcome === 'couldnt' ? 'couldn’t check'
    : e.findings > 0 ? `${e.findings} noted` : 'nothing to note';
  return { module: e.module || null, what: note ? note.what : 'A check', result, tone: e.outcome || 'none' };
}

// The lesson to offer while the scan runs: about the check running now, else
// about the district being swept, else the next unfinished one in the worry's
// order. `passed`: ids the person passed over this sweep; once every
// unfinished lesson has been passed over, they come round again.
// null: every lesson is finished.
export function sweepPick(lessons, progress, now, worryId, passed = []) {
  const { recommended, other } = orderLessons(lessons, worryId);
  const open = [...recommended, ...other].filter((l) => !lessonDone(progress, l.id));
  if (!open.length) return null;
  const skip = new Set(passed);
  const fresh = open.filter((l) => !skip.has(l.id));
  const pool = fresh.length ? fresh : open;
  const module = now && now.module;
  const district = now ? districtIdFor(now.category) : null;
  const byModule = module && pool.find((l) => (l.modules || []).includes(module));
  if (byModule) return { lesson: byModule, reason: 'module' };
  const byDistrict = district && pool.find((l) => (l.districts || []).includes(district));
  if (byDistrict) return { lesson: byDistrict, reason: 'district' };
  return { lesson: pool[0], reason: 'next' };
}

// Each question is one concept with a bank of items: the question as written,
// then its `variants`. Round 0 shows the question as written (the lesson
// itself); each later round shows the next item, keeping the question's
// teach unless the variant has its own.
export function lessonItems(lesson, round = 0) {
  const r = Number.isInteger(round) && round > 0 ? round : 0;
  if (!lesson || !r || !Array.isArray(lesson.questions)) return lesson;
  const questions = lesson.questions.map((q) => {
    const bank = [q, ...(Array.isArray(q.variants) ? q.variants : [])];
    const item = bank[r % bank.length];
    if (item === q) return q;
    return { ...item, concept: q.concept, teach: item.teach || q.teach, variants: q.variants };
  });
  return { ...lesson, questions };
}
