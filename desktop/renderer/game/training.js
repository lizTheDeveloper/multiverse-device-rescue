// The Training Grounds: which lessons exist, in what order, and how they load.
// Pure, except loadLessons, which takes the import function it should use.
import { lessonDone } from './progress.js';

export const WORRY_IDS = ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'phone', 'helping', 'unsure'];
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

export function afterScanDone(screen) {
  return screen === 'lesson' ? 'banner' : 'city';
}
