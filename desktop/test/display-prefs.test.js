const test = require('node:test');
const assert = require('node:assert');
const DisplayPrefs = require('../renderer/display-prefs.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };

test('the text size is stored under device-rescue.text-size, as normal, large or larger', () => {
  assert.strictEqual(DisplayPrefs.TEXT_KEY, 'device-rescue.text-size');
  const store = recordingStore();
  for (const v of ['normal', 'large', 'larger']) assert.strictEqual(DisplayPrefs.write(store, 'textSize', v), true, v);
  for (const bad of ['huge', '', null, undefined, 'Large', ' large', 2, {}]) {
    assert.strictEqual(DisplayPrefs.write(store, 'textSize', bad), false, String(bad));
  }
  assert.deepStrictEqual(store.writes, [['device-rescue.text-size', 'normal'], ['device-rescue.text-size', 'large'], ['device-rescue.text-size', 'larger']]);
});

test('only the three preferences, and only their own words, are ever written', () => {
  const store = recordingStore();
  assert.strictEqual(DisplayPrefs.write(store, 'font', 'plain'), true);
  assert.strictEqual(DisplayPrefs.write(store, 'font', 'city'), true);
  assert.strictEqual(DisplayPrefs.write(store, 'motion', 'less'), true);
  assert.strictEqual(DisplayPrefs.write(store, 'motion', 'system'), true);
  assert.strictEqual(DisplayPrefs.write(store, 'font', 'larger'), false);
  assert.strictEqual(DisplayPrefs.write(store, 'motion', 'reduce'), false);
  for (const name of ['display', 'toString', '__proto__', 'constructor', '']) {
    assert.strictEqual(DisplayPrefs.write(store, name, 'normal'), false, name);
  }
  assert.deepStrictEqual([...new Set(store.writes.map(([k]) => k))].sort(), [DisplayPrefs.FONT_KEY, DisplayPrefs.MOTION_KEY].sort());
  assert.deepStrictEqual(forbiddenWrites(store), []);
  for (const k of [DisplayPrefs.TEXT_KEY, DisplayPrefs.FONT_KEY, DisplayPrefs.MOTION_KEY]) assert.match(k, /^device-rescue\./);
});

test('reading: stored values, or the defaults for anything missing, garbled or blocked', () => {
  const defaults = { textSize: 'normal', font: 'city', motion: 'system' };
  assert.deepStrictEqual(DisplayPrefs.read(recordingStore()), defaults);
  assert.deepStrictEqual(DisplayPrefs.read(null), defaults);
  assert.deepStrictEqual(DisplayPrefs.read(throwing), defaults);
  assert.strictEqual(DisplayPrefs.write(throwing, 'textSize', 'large'), false);
  assert.deepStrictEqual(DisplayPrefs.read(recordingStore({
    'device-rescue.text-size': 'larger', 'device-rescue.font': 'plain', 'device-rescue.motion': 'less',
  })), { textSize: 'larger', font: 'plain', motion: 'less' });
  assert.deepStrictEqual(DisplayPrefs.read(recordingStore({
    'device-rescue.text-size': 'LARGE', 'device-rescue.font': '{"f":1}', 'device-rescue.motion': 'reduce',
  })), defaults);
});

test('zoom: 1 for normal or anything unknown, more for large and larger', () => {
  assert.strictEqual(DisplayPrefs.zoomFor('normal'), 1);
  assert.ok(DisplayPrefs.zoomFor('large') > 1);
  assert.ok(DisplayPrefs.zoomFor('larger') > DisplayPrefs.zoomFor('large'));
  for (const bad of ['huge', undefined, 'constructor', '__proto__']) assert.strictEqual(DisplayPrefs.zoomFor(bad), 1, String(bad));
});

test('less motion: asked for here, or asked for by the computer', () => {
  const sys = (reduce) => (q) => ({ matches: reduce && q === '(prefers-reduced-motion: reduce)' });
  assert.strictEqual(DisplayPrefs.lessMotion({ motion: 'less' }, sys(false)), true);
  assert.strictEqual(DisplayPrefs.lessMotion({ motion: 'system' }, sys(true)), true);
  assert.strictEqual(DisplayPrefs.lessMotion({ motion: 'system' }, sys(false)), false);
  assert.strictEqual(DisplayPrefs.lessMotion({ motion: 'system' }, undefined), false);
  assert.strictEqual(DisplayPrefs.lessMotion({ motion: 'system' }, () => { throw new Error('no'); }), false);
});
