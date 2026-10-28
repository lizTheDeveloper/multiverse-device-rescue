// The Training Grounds: which lessons exist, in what order, and how they load.
// Pure, except loadLessons, which takes the import function it should use.
import { lessonDone } from './progress.js';

export const WORRY_IDS = ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'android', 'helping', 'unsure'];
export const FIRST_LESSON = 'password-asker';

// Specifiers relative to this file. Order is the order shown under "ALSO HERE".
export const LESSON_FILES = [
  './lessons/password-asker.js',
  './lessons/starts-on-its-own.js',
  './lessons/locked-door.js',
  './lessons/whos-on-wifi.js',
  './lessons/browser-add-ons.js',
  './lessons/couldnt-check.js',
  './lessons/poisoned-packages.js',
];

// Lessons teach; the scan diagnoses. None of these may appear in lesson text.
export const DIAGNOSTIC_PHRASES = [
  'your computer has', 'your mac has', 'your pc has', 'your computer is infected',
  'your computer is compromised', 'you are infected', 'you’re infected', "you're infected",
  'you have been hacked', 'you’ve been hacked', "you've been hacked", 'someone is on your',
];
export const TIME_WORDS = /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i;

export function orderLessons(lessons, worryId) {
  const list = Array.isArray(lessons) ? lessons : [];
  const first = list.filter((l) => l.id === FIRST_LESSON);
  const rest = list.filter((l) => l.id !== FIRST_LESSON);
  const fits = (l) => (l.recommendedFor || []).includes(worryId);
  return { recommended: [...first, ...rest.filter(fits)], other: rest.filter((l) => !fits(l)) };
}

async function loadSpotTheFake(importModule) {
  const [{ buildSpotTheFake }, { CURATED_MESSAGES }] = await Promise.all([
    importModule('./lessons/spot-the-fake.js'),
    importModule('../rc/data/phishing.js'),
  ]);
  return buildSpotTheFake(CURATED_MESSAGES);
}

// One file at a time: a broken lesson is left out, never the whole Training Grounds.
export async function loadLessons(importModule) {
  const tries = [
    ...LESSON_FILES.map((f) => Promise.resolve().then(() => importModule(f)).then((m) => m && m.default)),
    Promise.resolve().then(() => loadSpotTheFake(importModule)),
  ];
  const results = await Promise.allSettled(tries);
  return results
    .filter((r) => r.status === 'fulfilled' && r.value && typeof r.value.id === 'string')
    .map((r) => r.value);
}

export function lessonForModule(lessons, progress, module) {
  return (lessons || []).find((l) => (l.modules || []).includes(module) && lessonDone(progress, l.id)) || null;
}

// Each lesson names the districts it teaches (`districts`): the renderer only
// learns a module's category from the scan, and a district must be clickable
// before its checks run. A lesson with none is in the Training Grounds list.
export function lessonsByDistrict(lessons, worryId) {
  const { recommended, other } = orderLessons(lessons, worryId);
  const out = {};
  for (const l of [...recommended, ...other]) for (const d of l.districts || []) (out[d] = out[d] || []).push(l);
  return out;
}

// What a district on the sweep opens: its first unfinished lesson, else its
// first. `done`: every lesson for it is finished. null: no lesson teaches it.
export function districtLesson(byDistrict, progress, districtId) {
  const list = (byDistrict && byDistrict[districtId]) || [];
  if (!list.length) return null;
  const next = list.find((l) => !lessonDone(progress, l.id));
  return { lesson: next || list[0], done: !next, count: list.length,
    finished: list.filter((l) => lessonDone(progress, l.id)).length, list };
}

export function afterScanDone(screen) {
  return screen === 'lesson' ? 'banner' : 'city';
}
