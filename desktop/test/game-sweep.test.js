// The sweep's own logic: which lesson to offer while the scan runs, and which
// item of a question's bank to show.
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/sweep.js');

const L = (id, extra = {}) => ({ id, title: id, modules: [], districts: [], recommendedFor: [], questions: [], ...extra });
const LESSONS = [
  L('password-asker', { districts: ['gatehouse'], modules: ['win_remote_access_audit'] }),
  L('starts-on-its-own', { districts: ['gatehouse'], modules: ['launch_agent_audit'] }),
  L('whos-on-wifi', { districts: ['wires'], modules: ['lan_device_inventory'], recommendedFor: ['wifi'] }),
  L('what-a-checkup-sees', { recommendedFor: ['unsure'] }),
];
const none = { lessons: {} };
const doneFor = (...ids) => ({ lessons: Object.fromEntries(ids.map((id) => [id, { completedAt: 'x' }])) });

test('a lesson about the check running now comes first', async () => {
  const { sweepPick } = await load();
  const p = sweepPick(LESSONS, none, { module: 'launch_agent_audit', category: 'security' }, 'unsure', []);
  assert.deepStrictEqual([p.lesson.id, p.reason], ['starts-on-its-own', 'module']);
});

test('then one about the district being swept, then the next unfinished one in the worry’s order', async () => {
  const { sweepPick } = await load();
  let p = sweepPick(LESSONS, none, { module: 'arp_spoof_check', category: 'network' }, 'unsure', []);
  assert.deepStrictEqual([p.lesson.id, p.reason], ['whos-on-wifi', 'district']);
  p = sweepPick(LESSONS, doneFor('password-asker'), { module: 'disk_space', category: 'performance' }, 'unsure', []);
  assert.deepStrictEqual([p.lesson.id, p.reason], ['what-a-checkup-sees', 'next']);
  p = sweepPick(LESSONS, doneFor('password-asker'), null, 'wifi', []);
  assert.strictEqual(p.lesson.id, 'whos-on-wifi');
});

test('finished and passed-over lessons are skipped; when every one is passed over, they come round again', async () => {
  const { sweepPick } = await load();
  const p = sweepPick(LESSONS, doneFor('starts-on-its-own'), { module: 'launch_agent_audit', category: 'security' }, 'unsure', ['password-asker']);
  assert.notStrictEqual(p.lesson.id, 'starts-on-its-own');
  assert.notStrictEqual(p.lesson.id, 'password-asker');
  const all = LESSONS.map((l) => l.id);
  const again = sweepPick(LESSONS, none, null, 'unsure', all);
  assert.ok(again && all.includes(again.lesson.id));
});

test('when every lesson is finished there is nothing to offer', async () => {
  const { sweepPick } = await load();
  assert.strictEqual(sweepPick(LESSONS, doneFor(...LESSONS.map((l) => l.id)), null, 'unsure', []), null);
  assert.strictEqual(sweepPick([], none, null, 'unsure', []), null);
});

test('lessonItems: round 0 is the question as written; later rounds rotate through its variants, keeping the teach', async () => {
  const { lessonItems } = await load();
  const opt = (t) => [{ text: t, correct: true, feedback: 'f' }, { text: 'no', correct: false, feedback: 'f' }];
  const lesson = L('x', { questions: [
    { concept: 'c1', teach: 'T1', prompt: 'P1', options: opt('a'), variants: [{ prompt: 'P1b', options: opt('b') }, { prompt: 'P1c', teach: 'T1c', options: opt('c') }] },
    { teach: 'T2', prompt: 'P2', options: opt('d') },
  ] });
  assert.deepStrictEqual(lessonItems(lesson, 0).questions.map((q) => q.prompt), ['P1', 'P2']);
  const r1 = lessonItems(lesson, 1).questions;
  assert.deepStrictEqual(r1.map((q) => [q.prompt, q.teach, q.concept]), [['P1b', 'T1', 'c1'], ['P2', 'T2', undefined]]);
  assert.deepStrictEqual(lessonItems(lesson, 2).questions[0].teach, 'T1c');
  assert.deepStrictEqual(lessonItems(lesson, 3).questions[0].prompt, 'P1');
  assert.strictEqual(lessonItems(lesson, 0), lesson, 'round 0 is the lesson itself');
});

test('logLine: a finished check in plain words, with what it noted', async () => {
  const { logLine } = await load();
  assert.deepStrictEqual(logLine({ module: 'launch_agent_audit', category: 'security', findings: 2, outcome: 'noted' }),
    { module: 'launch_agent_audit', what: 'Programs set to start on their own', result: '2 noted', tone: 'noted' });
  assert.strictEqual(logLine({ module: 'launch_agent_audit', findings: 1, outcome: 'noted' }).result, '1 noted');
  assert.strictEqual(logLine({ module: 'launch_agent_audit', findings: 0, outcome: 'none' }).result, 'nothing to note');
  assert.strictEqual(logLine({ module: 'launch_agent_audit', findings: 0, outcome: 'couldnt' }).result, 'couldn’t check');
  assert.strictEqual(logLine({ module: null, findings: 0, outcome: 'none' }).what, 'A check');
});
