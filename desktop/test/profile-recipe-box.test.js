const test = require('node:test');
const assert = require('node:assert');
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');
const load = () => import('../renderer/game/profile/recipe-box.js');

// A profile-shaped value full of words that must never reach disk.
const LITERAL = {
  version: 4,
  concepts: { 'who-made-it': { seen: [['update-where', 1, '2026-10-18T10:00:00.000Z', 'lesson']] } },
  lessons: { 'locked-door': { visited: '2026-10-18T10:00:00.000Z' } },
  missions: { 'stalkerware_scan|security.stalkerware_scan.found|/Users/ann/Library/mSpy': { status: 'open', title: 'Monitoring software: partner safety hotline 1-800-799-7233' } },
  deck: { tags: { 'launch_agent_audit|x|/tmp/.sys/run.sh': { tag: 'threat', at: 'now', fp: 'abc' } } },
  rank: { points: 88788, index: 3 },
  note: 'stealth watch spy abuse violence advocate 88788 safe',
  emoji: 'Ünïcødé ✓',
};
const STRUCTURE = new Set(['kitchen', 'cards', 'dish', 'serves', 'ingredients']);

// Every token in the stored text: JSON keys, string words and numbers.
function tokens(text) {
  return text.match(/[a-z]+|\d+/gi) || [];
}

test('the word list is 256 distinct lowercase cooking words, none of them a word that must stay off disk', async () => {
  const { WORDS } = await load();
  assert.strictEqual(WORDS.length, 256);
  assert.strictEqual(new Set(WORDS).size, 256);
  for (const w of WORDS) {
    assert.match(w, /^[a-z]+$/, w);
    assert.doesNotMatch(w, FORBIDDEN_ON_DISK, w);
  }
});

test('decode(encode(x)) gives back x, for several seeds and shapes', async () => {
  const { encode, decode } = await load();
  for (const seed of [1, 2, 12345, 0x7fffffff]) {
    for (const v of [LITERAL, {}, [], 'plain', 0, { deep: { a: [1, 2, { b: null, c: true }] } }]) {
      assert.deepStrictEqual(decode(encode(v, seed)), v, `seed ${seed}`);
    }
  }
});

test('nothing literal reaches disk: every token is a recipe word, a card field or a small number', async () => {
  const { encode, WORDS } = await load();
  const text = encode(LITERAL, 424242);
  assert.doesNotMatch(text, FORBIDDEN_ON_DISK);
  const words = new Set(WORDS);
  for (const t of tokens(text)) {
    assert.ok(words.has(t) || STRUCTURE.has(t) || /^[2-6]$/.test(t), `unexpected token "${t}"`);
  }
  for (const literal of ['locked-door', 'who-made-it', 'update-where', 'launch_agent_audit', 'threat', 'lesson', 'version']) {
    assert.ok(!text.includes(literal), literal);
  }
});

test('two installs write the same profile differently; one install writes it the same way each time', async () => {
  const { encode } = await load();
  assert.notStrictEqual(encode(LITERAL, 1001), encode(LITERAL, 1002));
  assert.strictEqual(encode(LITERAL, 1001), encode(LITERAL, 1001));
});

test('the seed travels with the box, so a lost seed key loses nothing', async () => {
  const { encode, seedOf } = await load();
  assert.strictEqual(seedOf(encode({ a: 1 }, 777)), 777);
  assert.strictEqual(seedOf('not json'), null);
});

test('anything that is not a box this code wrote decodes to null, never throws', async () => {
  const { encode, decode } = await load();
  const good = JSON.parse(encode({ a: 1 }, 99));
  const swapped = { ...good, cards: [{ ...good.cards[0], ingredients: ['granola', ...good.cards[0].ingredients.slice(1)] }] };
  const dropped = { ...good, cards: [{ ...good.cards[0], ingredients: good.cards[0].ingredients.slice(1) }] };
  for (const bad of ['', 'null', '{}', '{"kitchen":"basil basil basil basil","cards":[]}', JSON.stringify(swapped),
    JSON.stringify(dropped), JSON.stringify({ ...good, kitchen: 'basil' }), '{"cards":"x","kitchen":"basil thyme sage dill"}']) {
    assert.strictEqual(decode(bad), null, bad.slice(0, 40));
  }
});

test('encode refuses a bad seed instead of writing something unreadable', async () => {
  const { encode } = await load();
  for (const seed of [0, -1, 1.5, 0x80000000, '12', null]) assert.throws(() => encode({}, seed), /bad seed/);
});

test('cards look like recipe cards: a dish, servings and at most 24 ingredients', async () => {
  const { encode, CARD_SIZE } = await load();
  const box = JSON.parse(encode(LITERAL, 5150));
  assert.deepStrictEqual(Object.keys(box).sort(), ['cards', 'kitchen']);
  for (const c of box.cards) {
    assert.deepStrictEqual(Object.keys(c).sort(), ['dish', 'ingredients', 'serves']);
    assert.match(c.dish, /^[a-z]+ [a-z]+$/);
    assert.ok(c.serves >= 2 && c.serves <= 6);
    assert.ok(c.ingredients.length >= 1 && c.ingredients.length <= CARD_SIZE);
  }
});
