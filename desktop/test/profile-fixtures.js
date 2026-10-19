// Small, made-up lessons and drills for the profile tests, so these tests
// don't move when the real lessons' wording does.
const o3 = () => [
  { text: 'Right one', correct: true, feedback: 'Right.' },
  { text: 'Wrong one', correct: false, feedback: 'No.' },
  { text: 'Other wrong', correct: false, feedback: 'No.' },
];
const o2 = () => [
  { text: 'Yes', correct: true, feedback: 'Right.' },
  { text: 'No', correct: false, feedback: 'No.' },
];
const family = (key, concept, options, teach = `Teach ${key}`) => ({
  key, concept, teach, prompt: `Prompt ${key}`, options: options(),
  variants: [{ key: `${key}-2`, prompt: `Prompt ${key}-2`, options: options() }, { key: `${key}-3`, prompt: `Prompt ${key}-3`, options: options() }],
});

const LESSONS = [
  { id: 'lesson-a', title: 'Lesson A', modules: ['launch_agent_audit'], recommendedFor: ['hacked'],
    questions: [family('a1', 'who-made-it', o3), family('a2', 'where-it-lives', o3)] },
  { id: 'lesson-b', title: 'Lesson B', modules: [], recommendedFor: ['unsure'],
    questions: [family('b1', 'couldnt-check', o2)] },
];
const DRILLS = [
  { id: 'upd8r-hidden-cache', answer: 'threat', district: 'gatehouse', clues: { what: 'x' } },
  { id: 'zoom-helper-signed', answer: 'mine', district: 'gatehouse', clues: { what: 'x' } },
  { id: 'proxy-work', answer: 'mine', district: 'wires', clues: { what: 'x' } },
];

// A version 3 store from the old key, as main writes it today.
const V3 = {
  version: 3,
  missions: {
    'launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x': { status: 'later', module: 'launch_agent_audit', districtId: 'gatehouse', title: 'A helper', updatedAt: '2026-10-10T09:00:00.000Z' },
    'stalkerware_scan|security.stalkerware_scan.found|x': { status: 'open', module: 'stalkerware_scan', updatedAt: '2026-10-11T09:00:00.000Z' },
    'broken': { status: 'weird' },
  },
  lessons: {
    'lesson-a': { completedAt: '2026-10-09T08:00:00.000Z' },
    'lesson-b': { completedAt: '2026-10-12T08:00:00.000Z', how: 'skipped' },
    'bad': { done: true },
  },
  deck: {
    points: 340, rank: 2, drills: { right: 9, tried: 12 },
    tags: { good: { tag: 'mine', at: 'now', fp: 'f' }, bad: { tag: 'nonsense', at: 'now', fp: 'f' } },
    confirmed: { 'a|b|c': '2026-10-10T09:00:00.000Z' }, once: { 'drill:x': true },
    sweep: { at: '2026-10-12T10:00:00.000Z', keys: { 'clue:x#maker': true } },
    sweeps: [{ at: '2026-10-12T10:00:00.000Z', checks: 9, critical: 0, warning: 2, info: 4, fog: 1, checked: 8, secured: 6 }, { at: 'x' }],
  },
};

const memStore = (init = {}) => {
  const s = { ...init };
  return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; }, raw: s };
};

module.exports = { LESSONS, DRILLS, V3, memStore };
