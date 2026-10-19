const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/training.js');

const L = (id, recommendedFor = [], modules = []) => ({ id, title: id, recommendedFor, modules, questions: [] });

test('the password lesson comes first for every worry, then the recommended ones, then the rest', async () => {
  const { orderLessons, WORRY_IDS } = await load();
  const lessons = [L('a', ['wifi']), L('password-asker', []), L('b', ['wifi', 'hacked']), L('c', [])];
  for (const w of WORRY_IDS) {
    const { recommended } = orderLessons(lessons, w);
    assert.strictEqual(recommended[0].id, 'password-asker', w);
  }
  const wifi = orderLessons(lessons, 'wifi');
  assert.deepStrictEqual(wifi.recommended.map((l) => l.id), ['password-asker', 'a', 'b']);
  assert.deepStrictEqual(wifi.other.map((l) => l.id), ['c']);
  assert.deepStrictEqual(orderLessons(lessons, undefined).recommended.map((l) => l.id), ['password-asker']);
});

test('a lesson file that fails to load is left out; the rest still load', async () => {
  const { loadLessons, LESSON_FILES } = await load();
  const lessons = await loadLessons(async (spec) => {
    if (spec === LESSON_FILES[1]) throw new Error('broken file');
    if (spec === '../rc/data/phishing.js') throw new Error('no vendor');
    return { default: L(spec) };
  });
  assert.strictEqual(lessons.length, LESSON_FILES.length - 1);
  assert.ok(!lessons.some((l) => l.id === LESSON_FILES[1]));
});

test('lessonForModule links a mission to a lesson only once that lesson is done', async () => {
  const { lessonForModule } = await load();
  const lessons = [L('x', [], ['launch_agent_audit'])];
  assert.strictEqual(lessonForModule(lessons, { lessons: {} }, 'launch_agent_audit'), null);
  assert.strictEqual(lessonForModule(lessons, { lessons: { x: { completedAt: 'now' } } }, 'launch_agent_audit').id, 'x');
  assert.strictEqual(lessonForModule(lessons, { lessons: { x: { completedAt: 'now' } } }, 'disk_space'), null);
});

test('a scan that finishes mid-lesson shows a banner instead of pulling the person out', async () => {
  const { afterScanDone } = await load();
  assert.strictEqual(afterScanDone('lesson'), 'banner');
  for (const s of ['training', 'boss', 'map', undefined]) assert.strictEqual(afterScanDone(s), 'city');
});

test('buildSpotTheFake makes one real-or-fake question per picked message', async () => {
  const { buildSpotTheFake } = await import('../renderer/game/lessons/spot-the-fake.js');
  const msgs = [
    { id: 1, type: 'email', from: 'a@x', subject: 'S', body: 'B', answer: 'pretext', tells: ['Odd domain', 'Deadline.'] },
    { id: 4, type: 'call', from: '+1', subject: null, body: 'C', answer: 'pretext', tells: ['Asks for a code'] },
    { id: 5, type: 'email', from: 'n@g', subject: 'P', body: 'D', answer: 'genuine', tells: ['Real address'] },
    { id: 9, type: 'push', from: 'I', body: 'E', answer: 'genuine', tells: ['x'] },
  ];
  const l = buildSpotTheFake(msgs);
  assert.strictEqual(l.id, 'spot-the-fake');
  assert.strictEqual(l.type, 'phishing');
  assert.strictEqual(l.questions.length, 3);
  const [q1, , q3] = l.questions;
  assert.deepStrictEqual(q1.options.map((o) => [o.text, o.correct]), [['Fake', true], ['Real', false]]);
  assert.deepStrictEqual(q3.options.map((o) => [o.text, o.correct]), [['Fake', false], ['Real', true]]);
  assert.match(q1.options[0].feedback, /Odd domain\. Deadline\./);
  assert.deepStrictEqual(q1.message, { type: 'email', from: 'a@x', subject: 'S', body: 'B' });
  assert.throws(() => buildSpotTheFake([]));
  assert.throws(() => buildSpotTheFake([{ id: 1, answer: 'maybe', tells: ['x'] }]));
});

test('spot-the-fake items are honest two-option real-or-fake items with a guessing floor of 1/2', async () => {
  const { buildSpotTheFake } = await import('../renderer/game/lessons/spot-the-fake.js');
  const { buildBank } = await import('../renderer/game/profile/item-bank.js');
  const msgs = [1, 4, 5, 8, 3, 2].map((id, i) => ({ id, type: 'email', from: 'a', subject: 'S', body: 'B', answer: i % 2 ? 'genuine' : 'pretext', tells: ['t'] }));
  const l = buildSpotTheFake(msgs);
  const bank = buildBank([l], []);
  const items = [...bank.items.values()].filter((it) => it.lessonId === 'spot-the-fake');
  assert.ok(items.length > 3);
  for (const it of items) {
    assert.strictEqual(it.options.length, 2, it.key);
    assert.strictEqual(it.c, 0.5, it.key);
    assert.strictEqual(it.options.filter((o) => o.correct).length, 1, it.key);
  }
});

test('lessonsByDistrict groups lessons by their districts, in the worry’s order; districtLesson picks the next unfinished', async () => {
  const { lessonsByDistrict, districtLesson } = await load();
  const a = { ...L('a', ['wifi']), districts: ['gatehouse'] };
  const b = { ...L('b'), districts: ['gatehouse', 'wires'] };
  const c = L('c');
  const by = lessonsByDistrict([b, a, c], 'wifi');
  assert.deepStrictEqual(by.gatehouse.map((l) => l.id), ['a', 'b'], 'recommended first');
  assert.deepStrictEqual(by.wires.map((l) => l.id), ['b']);
  assert.strictEqual(districtLesson(by, { lessons: {} }, 'junkyard'), null);
  const none = districtLesson(by, { lessons: {} }, 'gatehouse');
  assert.strictEqual(none.lesson.id, 'a');
  assert.deepStrictEqual([none.done, none.count, none.finished], [false, 2, 0]);
  const one = districtLesson(by, { lessons: { a: { completedAt: 'x' } } }, 'gatehouse');
  assert.deepStrictEqual([one.lesson.id, one.done, one.finished], ['b', false, 1]);
  const all = districtLesson(by, { lessons: { a: { completedAt: 'x' }, b: { completedAt: 'y' } } }, 'gatehouse');
  assert.deepStrictEqual([all.lesson.id, all.done], ['a', true], 'all done: the first again');
});
