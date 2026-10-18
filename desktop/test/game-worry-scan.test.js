// app.js's own wiring, in a stubbed page: picking a worry in game mode starts
// the same read-only scan the plain route runs, straight onto the sweep screen.
const test = require('node:test');
const assert = require('node:assert');
const { SITUATIONS } = require('../renderer/app.js');
const { page, clean, monitoring } = require('./page-harness.js');

const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('in game mode, a worry starts its scan at once on the sweep screen: no Training Grounds first', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')], 'the same scan and profile as the plain route');
  assert.deepStrictEqual(p.shown(), ['city']);
  await p.finish(clean);
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanDone']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the plain route is unchanged: the scan screen, and no scan until Run', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.calls.scans, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')]);
  assert.deepStrictEqual(p.calls.game, [], 'never the sweep outside game mode');
});

test('worries where someone may be watching never start the game, even from "Play it as a game"', () => {
  for (const id of ['watched', 'phone']) {
    const p = page();
    p.byId('btn-play-game').click();
    p.pick(id);
    assert.deepStrictEqual(p.calls.game, [], id);
    assert.deepStrictEqual(p.calls.scans, [], `${id}: the plain scan screen, waiting for Run`);
    assert.deepStrictEqual(p.shown(), ['scan'], id);
  }
});

test('once a scan found monitoring software, the follow-up comes first; then the next worry gets the plain screen', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('known');
  assert.ok(!p.calls.game.includes('scanDone'), 'nobody lands in the city');
  assert.deepStrictEqual(p.shown(), ['results']);
  p.calls.game.length = 0;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
});

test('PLAIN VIEW mid-scan: the plain scan screen, then the list when it finishes', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-progress').hidden, false, 'live progress');
  await p.finish(clean);
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.ok(!p.calls.game.includes('scanDone'));
});
