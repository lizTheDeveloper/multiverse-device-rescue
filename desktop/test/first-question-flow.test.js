const test = require('node:test');
const assert = require('node:assert');
const { page, monitoring } = require('./page-harness.js');

const KEY = 'device-rescue.display';
const modeWrites = (p) => p.storage.writes.filter(([k]) => k === KEY);

test('the question comes once, after the worry, before any scan', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.deepStrictEqual(p.calls.scans, []);
  assert.deepStrictEqual(modeWrites(p), []);
  p.answer('no');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['home_network_intrusion']);
});

test('each answer stores its mode, and only the mode', () => {
  for (const [answer, mode] of [['no', 'standard'], ['yes', 'city'], ['rather-not', 'standard']]) {
    const p = page({ store: {} });
    p.byId('btn-get-started').click();
    p.pick('hacked');
    p.answer(answer);
    assert.deepStrictEqual(modeWrites(p), [[KEY, mode]], answer);
  }
});

test('once answered, the question isn’t asked again', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), []);
});

test('"I think someone is watching me" never asks: it is city', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
});

test('"Something changed?" opens the question again, then back to the worry screen', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('yes');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
  assert.deepStrictEqual(p.shown(), ['worry']);
});

test('monitoring software in a standard-mode scan: the follow-up, once a session', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.match(p.byId('question-card').innerHTML, /We found something that can be used to watch a computer\. Is that something you know about\?/);
  p.answer('known');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  await p.finish(monitoring);
  assert.ok(!p.shown().includes('question'), 'asked once a session');
});

test('the follow-up never comes in city mode', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(monitoring);
  assert.ok(!p.shown().includes('question'));
});

test('the seed is written for every install, so it says nothing about anyone', () => {
  for (const store of [{}, { [KEY]: 'standard' }, { [KEY]: 'city' }]) {
    const p = page({ store });
    assert.ok(/^\d+$/.test(p.storage.getItem('device-rescue.city-seed')), JSON.stringify(store));
  }
});

// Handed over from the display-preference store (Task 1).

test('blocked storage: "Yes" stays city for the whole session, though nothing could be saved', async () => {
  const p = page({ blocked: true });
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.shown(), ['question'], 'nothing could be read, so ask');
  p.answer('yes');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']], 'the write was tried');
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'city', 'kept in memory');
  // The next worry doesn't ask again and doesn't fall back to standard.
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  assert.ok(!p.shown().includes('question'));
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'city');
  // Nor does a scan with monitoring software in it bring the standard follow-up.
  p.byId('btn-run-scan').click();
  await p.finish(monitoring);
  assert.ok(!p.shown().includes('question'));
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'city');
});

test('no answer yet (first run or blocked storage): neither mode is assumed; the question is asked', () => {
  for (const opts of [{ store: {} }, { blocked: true }, { store: { [KEY]: 'stealth' } }, { store: { [KEY]: '' } }]) {
    const p = page(opts);
    assert.strictEqual(p.sandbox.RescueHost.mode(), null, JSON.stringify(opts));
    p.byId('btn-get-started').click();
    p.pick('wifi');
    assert.deepStrictEqual(p.shown(), ['question'], JSON.stringify(opts));
    assert.deepStrictEqual(p.calls.scans, []);
    assert.deepStrictEqual(modeWrites(p), [], 'nothing written before an answer');
  }
});

test('the seed is made once a session: with blocked storage it still never changes', () => {
  const p = page({ blocked: true });
  const seed = p.sandbox.RescueHost.citySeed();
  assert.ok(Number.isInteger(seed) && seed >= 1, String(seed));
  p.byId('btn-get-started').click();
  p.pick('wifi');
  p.answer('yes');
  for (let i = 0; i < 5; i++) assert.strictEqual(p.sandbox.RescueHost.citySeed(), seed);
  const seedWrites = p.storage.writes.filter(([k]) => k === 'device-rescue.city-seed');
  assert.strictEqual(seedWrites.length, 1, 'one attempt to save it, at start-up');
});

test('the old game-view setting is not an answer: it is never moved into the mode', () => {
  for (const view of ['city', 'list']) {
    const p = page({ store: { 'device-rescue.view': view } });
    assert.strictEqual(p.sandbox.RescueHost.mode(), null, view);
    p.byId('btn-get-started').click();
    p.pick('wifi');
    assert.deepStrictEqual(p.shown(), ['question'], view);
    assert.deepStrictEqual(modeWrites(p), [], view);
  }
});

test('nothing written during the question, its follow-up or "Something changed?" names why', async () => {
  const { forbiddenWrites, FORBIDDEN_ON_DISK } = require('./disk-words.js');
  assert.ok(FORBIDDEN_ON_DISK.test('stealth'), '"stealth" is never written either');
  for (const first of ['no', 'yes', 'rather-not']) {
    const p = page({ store: {} });
    p.byId('btn-get-started').click();
    p.pick('unsure');
    p.answer(first);
    await p.finish(monitoring);
    if (p.shown().includes('question')) p.answer('unknown');
    p.byId('btn-start-over').click();
    p.byId('btn-get-started').click();
    p.byId('btn-something-changed').click();
    p.answer('rather-not');
    p.pick('watched');
    assert.deepStrictEqual(forbiddenWrites(p.storage), [], first);
    for (const [k, v] of p.storage.writes) {
      assert.ok(['device-rescue.display', 'device-rescue.city-seed', 'device-rescue.view'].includes(k), k);
      if (k === KEY) assert.ok(['city', 'standard'].includes(v), v);
    }
  }
});

test('the follow-up "No, I don’t" turns on city', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('unknown');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'city');
});

// Fix round 1: focus, a way back from the re-ask, and the step dot.

test('focus moves to the question, so a screen reader reads it: first ask and the follow-up', async () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('unsure');
  assert.match(p.byId('question-card').innerHTML, /id="question-title" tabindex="-1"/);
  assert.strictEqual(p.sandbox.document.activeElement, p.byId('question-title'), 'first ask');
  p.answer('no');
  p.sandbox.document.activeElement = null;
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.match(p.byId('question-card').innerHTML, /id="question-title" tabindex="-1"/);
  assert.strictEqual(p.sandbox.document.activeElement, p.byId('question-title'), 'the follow-up');
});

test('the re-ask: Back changes nothing, writes nothing, and returns to the worry screen', () => {
  for (const m of ['city', 'standard']) {
    const p = page({ store: { [KEY]: m } });
    p.byId('btn-get-started').click();
    p.byId('btn-something-changed').click();
    assert.deepStrictEqual(p.shown(), ['question']);
    const before = p.storage.writes.length;
    p.answer('back');
    assert.strictEqual(p.storage.writes.length, before, 'nothing written');
    assert.strictEqual(p.storage.getItem(KEY), m);
    assert.strictEqual(p.sandbox.RescueHost.mode(), m);
    assert.deepStrictEqual(p.shown(), ['worry']);
  }
});

test('the re-ask: "I’d rather not say" keeps city as city', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  p.answer('rather-not');
  assert.deepStrictEqual(modeWrites(p), []);
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'city');
  assert.deepStrictEqual(p.shown(), ['worry']);
});

test('the re-ask: only an explicit "No" turns city into standard', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  p.answer('no');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
  assert.strictEqual(p.sandbox.RescueHost.mode(), 'standard');
});

test('"Something changed?" before any answer is the first ask: "rather not say" there is standard', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  assert.ok(!p.byId('question-card').innerHTML.includes('data-answer="back"'));
  p.answer('rather-not');
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'standard']]);
});

test('the step dot stays where the person is: worry for the first ask, the city for the follow-up', async () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('unsure');
  assert.deepStrictEqual(p.activeDot(), ['worry']);
  p.answer('no');
  assert.deepStrictEqual(p.shown(), ['city'], 'the scan runs on the city\'s sweep screen');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.deepStrictEqual(p.activeDot(), ['results'], 'the city\'s step, not back to "worry"');
  p.answer('known');
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the game can\'t draw: the step dot stays where the person is, and the scan screen runs the checkup', async () => {
  const p = page({ store: {}, ready: false });
  p.byId('btn-get-started').click();
  p.pick('unsure');
  assert.deepStrictEqual(p.activeDot(), ['worry']);
  p.answer('no');
  assert.deepStrictEqual(p.activeDot(), ['scan']);
  p.byId('btn-run-scan').click();
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.deepStrictEqual(p.activeDot(), ['scan'], 'not back to "worry"');
  p.answer('known');
  assert.deepStrictEqual(p.activeDot(), ['results']);
});
