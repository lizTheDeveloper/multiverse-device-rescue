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
