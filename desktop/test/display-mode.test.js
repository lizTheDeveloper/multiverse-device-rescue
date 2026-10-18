const test = require('node:test');
const assert = require('node:assert');
const DisplayMode = require('../renderer/display-mode.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };

test('only two values are ever written: city and standard', () => {
  const store = recordingStore();
  assert.strictEqual(DisplayMode.writeMode(store, 'city'), true);
  assert.strictEqual(DisplayMode.writeMode(store, 'standard'), true);
  for (const bad of ['stealth', 'watched', 'safety', '', null, undefined, 'CITY', ' city', 1, {}]) {
    assert.strictEqual(DisplayMode.writeMode(store, bad), false, String(bad));
  }
  assert.deepStrictEqual(store.writes, [[DisplayMode.MODE_KEY, 'city'], [DisplayMode.MODE_KEY, 'standard']]);
});

test('reading: a stored value, or null for anything else', () => {
  assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: 'city' })), 'city');
  assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: 'standard' })), 'standard');
  for (const raw of ['stealth', '', '{"mode":"city"}', 'City']) {
    assert.strictEqual(DisplayMode.readMode(recordingStore({ [DisplayMode.MODE_KEY]: raw })), null, raw);
  }
  assert.strictEqual(DisplayMode.readMode(recordingStore()), null);
  assert.strictEqual(DisplayMode.readMode(null), null);
  assert.strictEqual(DisplayMode.readMode(throwing), null);
  assert.strictEqual(DisplayMode.writeMode(throwing, 'city'), false);
});

test('the keys and everything written say nothing about why', () => {
  const store = recordingStore();
  DisplayMode.writeMode(store, 'city');
  DisplayMode.writeMode(store, 'standard');
  DisplayMode.ensureSeed(store, () => 0.5);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.deepStrictEqual([...new Set(store.writes.map(([k]) => k))].sort(), [DisplayMode.MODE_KEY, DisplayMode.SEED_KEY].sort());
  assert.match(DisplayMode.MODE_KEY, /^device-rescue\./);
  assert.match(DisplayMode.SEED_KEY, /^device-rescue\./);
});

test('an existing install keeps everything it saved: nothing is removed or rewritten', () => {
  const saved = {
    'device-rescue.game.v1': JSON.stringify({ version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: '2026-10-01T00:00:00Z' } }, lessons: {} }),
    'device-rescue.view': 'city',
    'device-rescue.game.scan-confirmed.v1': '{"version":1,"missions":{}}',
    'reclaim-city.analytics-off': '1',
  };
  const store = recordingStore(saved);
  assert.strictEqual(DisplayMode.readMode(store), null, 'no mode yet: the question is asked once');
  DisplayMode.writeMode(store, 'standard');
  DisplayMode.ensureSeed(store, () => 0.25);
  for (const [k, v] of Object.entries(saved)) assert.strictEqual(store.getItem(k), v, k);
  assert.deepStrictEqual(store.removed, []);
  assert.ok(store.writes.every(([k]) => k === DisplayMode.MODE_KEY || k === DisplayMode.SEED_KEY));
});

test('the seed is made once and then kept', () => {
  const store = recordingStore();
  const a = DisplayMode.ensureSeed(store, () => 0.5);
  const b = DisplayMode.ensureSeed(store, () => 0.9);
  assert.strictEqual(a, b);
  assert.strictEqual(store.writes.length, 1);
  assert.ok(Number.isInteger(a) && a >= 1 && a <= 0x7fffffff);
  assert.strictEqual(DisplayMode.ensureSeed(store), a);
});

test('a seed that is missing or damaged is replaced; the extremes stay in range', () => {
  for (const raw of ['abc', '0', '-5', '1.5', '99999999999', '', ' 12']) {
    const store = recordingStore({ [DisplayMode.SEED_KEY]: raw });
    const n = DisplayMode.ensureSeed(store, () => 0.5);
    assert.ok(Number.isInteger(n) && n >= 1 && n <= 0x7fffffff, raw);
    assert.strictEqual(store.getItem(DisplayMode.SEED_KEY), String(n), raw);
  }
  assert.strictEqual(DisplayMode.ensureSeed(recordingStore(), () => 0), 1);
  assert.ok(DisplayMode.ensureSeed(recordingStore(), () => 0.9999999999) <= 0x7fffffff);
  assert.strictEqual(DisplayMode.ensureSeed(recordingStore({ [DisplayMode.SEED_KEY]: '424242' })), 424242);
});

test('blocked storage still gives a usable seed, without throwing', () => {
  const n = DisplayMode.ensureSeed(throwing, () => 0.5);
  assert.ok(Number.isInteger(n) && n >= 1);
  assert.ok(Number.isInteger(DisplayMode.ensureSeed(null, () => 0.5)));
});
