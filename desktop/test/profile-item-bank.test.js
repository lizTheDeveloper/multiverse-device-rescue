const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS } = require('./profile-fixtures.js');
const load = () => import('../renderer/game/profile/item-bank.js');

const fresh = () => ({});
const hist = (over) => ({ 'who-made-it': { mean: 0, learned: false, recent: [], seen: new Set() }, 'where-it-lives': { mean: 0, learned: false, recent: [], seen: new Set() }, 'couldnt-check': { mean: 0, learned: false, recent: [], seen: new Set() }, ...over });

test('the bank holds every question, every variant and every drill, with its guessing floor', async () => {
  const { buildBank } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.strictEqual(bank.items.size, 9 + 3);
  assert.strictEqual(bank.items.get('a1').first, true);
  assert.strictEqual(bank.items.get('a1-2').first, false);
  assert.strictEqual(bank.items.get('a1-2').teach, 'Teach a1', 'a variant shares its family’s what-to-know');
  assert.strictEqual(bank.items.get('a1').c, 1 / 3);
  assert.strictEqual(bank.items.get('b1-3').c, 0.5);
  assert.deepStrictEqual(bank.concepts.get('who-made-it'), ['a1', 'a1-2', 'a1-3', 'drill:zoom-helper-signed']);
  assert.strictEqual(bank.items.get('drill:upd8r-hidden-cache').concept, 'where-it-lives');
  assert.strictEqual(bank.items.get('drill:proxy-work').concept, null);
  assert.deepStrictEqual(bank.lessons.get('lesson-a').concepts, ['who-made-it', 'where-it-lives']);
  assert.deepStrictEqual(bank.lessons.get('lesson-a').modules, ['launch_agent_audit']);
});

test('a key used twice keeps the first item only', async () => {
  const { buildBank } = await load();
  const dup = [...LESSONS, { id: 'lesson-c', title: 'C', questions: [{ key: 'a1', concept: 'lock-screen', prompt: 'x', options: [] }] }];
  const bank = buildBank(dup, []);
  assert.strictEqual(bank.items.get('a1').concept, 'who-made-it');
  assert.deepStrictEqual(bank.lessons.get('lesson-c').keys, []);
});

test('the first visit is the lesson as written: each question’s own item, in order', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', hist()), ['a1', 'a2']);
  assert.deepStrictEqual(drawLessonVisit(bank, 'nope', hist()), []);
});

test('later visits: unseen variants first, concepts not learned only, never the item just asked', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const h = hist({ 'who-made-it': { mean: 0.2, learned: false, recent: ['a1'], seen: new Set(['a1']) } });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', h), ['a1-2', 'a2', 'a1-3']);
  const learned = hist({ 'who-made-it': { mean: 1, learned: true, recent: ['a1', 'a1-2', 'a1-3'], seen: new Set(['a1', 'a1-2', 'a1-3']) } });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', learned), ['a2', 'a2-2', 'a2-3'], 'only the concept still open');
});

test('when every concept is learned, a visit is a review over all of them', async () => {
  const { buildBank, drawLessonVisit } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const all = (keys) => ({ mean: 1, learned: true, recent: keys, seen: new Set(keys) });
  const h = hist({ 'who-made-it': all(['a1', 'a1-2', 'a1-3']), 'where-it-lives': all(['a2-3', 'a2', 'a2-2']) });
  assert.deepStrictEqual(drawLessonVisit(bank, 'lesson-a', h), ['a1', 'a2-3']);
});

test('the most informative item comes first among unseen ones', async () => {
  const { buildBank, drawConcept } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  const b = (k) => ({ a1: 2, 'a1-2': 0.9, 'a1-3': -2 }[k]);
  const h = hist({ 'who-made-it': { mean: 1, learned: false, recent: [], seen: new Set() } });
  assert.deepStrictEqual(drawConcept(bank, 'who-made-it', h, { bOf: b }), ['a1-2', 'a1']);
});

test('Learn this draws at most two items on one concept, and never a drill', async () => {
  const { buildBank, drawConcept, LEARN_THIS_MAX } = await load();
  const bank = buildBank(LESSONS, DRILLS);
  assert.strictEqual(LEARN_THIS_MAX, 2);
  const keys = drawConcept(bank, 'who-made-it', hist());
  assert.strictEqual(keys.length, 2);
  assert.ok(keys.every((k) => !k.startsWith('drill:')));
  assert.deepStrictEqual(drawConcept(bank, 'lock-screen', hist()), []);
});
