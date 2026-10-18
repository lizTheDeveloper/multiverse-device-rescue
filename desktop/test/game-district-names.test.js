const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const load = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

test('a large pool of names that fit the city, all different', async () => {
  const { NAMES } = await load('district-names.js');
  assert.ok(NAMES.length >= 40, `${NAMES.length} names`);
  assert.strictEqual(new Set(NAMES).size, NAMES.length);
  for (const n of NAMES) {
    assert.match(n, /^[A-Z0-9][\w’' ]*$/, n);
    assert.ok(n.length <= 24, n);
  }
});

test('nothing in a name, a look or a voice hints at what the district holds', async () => {
  const { NAMES, LOOKS, VOICES, GIVEAWAY } = await load('district-names.js');
  for (const text of [...NAMES, ...LOOKS, ...VOICES.flatMap((v) => [v.id, v.hello, v.bye])]) {
    assert.doesNotMatch(text, GIVEAWAY, text);
  }
  for (const bad of ['Safe Harbor', 'The Help Desk', 'Haven Street', 'Hope Lane', 'Shelter Point', 'Watchtower', 'Sanctuary Row']) {
    assert.match(bad, GIVEAWAY, `the check must catch ${bad}`);
  }
});

test('no name clashes with a district the game already has', async () => {
  const { NAMES } = await load('district-names.js');
  const { DISTRICTS, OUTSKIRTS } = await load('findings-to-city.js');
  const taken = new Set([...DISTRICTS, OUTSKIRTS].map((d) => d.name.toLowerCase()));
  for (const n of NAMES) assert.ok(!taken.has(n.toLowerCase()), n);
});

test('the same install always gets the same district', async () => {
  const { pickDistrict } = await load('district-names.js');
  for (const seed of [1, 7, 424242, 0x7fffffff]) assert.deepStrictEqual(pickDistrict(seed), pickDistrict(seed));
});

test('different installs get different districts', async () => {
  const { pickDistrict, LOOKS, VOICES } = await load('district-names.js');
  const names = new Set();
  const looks = new Set();
  const voices = new Set();
  for (let seed = 1; seed <= 500; seed += 1) {
    const d = pickDistrict(seed);
    names.add(d.name); looks.add(d.look); voices.add(d.voice.id);
  }
  assert.ok(names.size >= 30, `${names.size} names from 500 installs`);
  assert.strictEqual(looks.size, LOOKS.length);
  assert.strictEqual(voices.size, VOICES.length);
});

test('a bad seed still gives a district from the pools', async () => {
  const { pickDistrict, NAMES, LOOKS, VOICES } = await load('district-names.js');
  for (const seed of [0, -1, 1.5, NaN, null, undefined, '12']) {
    const d = pickDistrict(seed);
    assert.ok(NAMES.includes(d.name) && LOOKS.includes(d.look) && VOICES.includes(d.voice), String(seed));
  }
});
