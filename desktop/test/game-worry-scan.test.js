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

test('the iPhone check stays on its own plain screen, even from "Play it as a game"', () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('phone');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.calls.scans, [], 'the plain scan screen, waiting for Run');
  assert.deepStrictEqual(p.shown(), ['scan']);
});

test('monitoring software in standard mode: the follow-up first, and "Yes, I know about it" keeps the game', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.ok(!p.calls.game.includes('scanDone'), 'nothing lands before the answer');
  p.answer('known');
  assert.ok(p.calls.game.includes('scanDone'));
  assert.deepStrictEqual(p.shown(), ['city']);
  p.calls.game.length = 0;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss'], 'the next worry plays too');
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

// "Plain view" from the game, then "Back to the city" in the plain header.
const cityStore = { 'device-rescue.display': 'city' };

test('"Back to the city" is hidden until the city has been on screen', () => {
  const p = page();
  assert.strictEqual(p.byId('btn-back-to-city').hidden, true);
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.strictEqual(p.byId('btn-back-to-city').hidden, true, 'plain all the way: nothing to go back to');
});

test('Plain view from the Training Grounds, then back: the Training Grounds again', () => {
  const p = page({ store: cityStore });
  assert.deepStrictEqual(p.shown(), ['city']);
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('btn-back-to-city').hidden, false);
  p.calls.game.length = 0;
  p.byId('btn-back-to-city').click();
  assert.deepStrictEqual(p.calls.game, ['showTraining']);
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.deepStrictEqual(p.calls.scans, [], 'going back starts no scan');
});

test('Plain view after a sweep, then back: the same city, no new scan', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  await p.finish(clean);
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['results']);
  p.byId('btn-back-to-city').click();
  assert.strictEqual(p.calls.last.name, 'show');
  assert.strictEqual(p.calls.last.args[0], clean);
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(p.calls.scans.length, 1);
});

test('Plain view during a sweep, then back: the sweep screen, and the scan lands in the city', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-back-to-city').click();
  assert.strictEqual(p.calls.last.name, 'showBoss');
  assert.deepStrictEqual(p.shown(), ['city']);
  await p.finish(clean);
  assert.strictEqual(p.calls.last.name, 'scanDone');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(p.calls.scans.length, 1);
});

test('a scan started in plain view can still be watched from the city', async () => {
  const p = page({ store: cityStore });
  p.sandbox.RescueHost.leaveGame();
  p.byId('btn-run-scan').click();
  p.byId('btn-back-to-city').click();
  assert.strictEqual(p.calls.last.name, 'showBoss');
  await p.finish(clean);
  assert.strictEqual(p.calls.last.name, 'scanDone');
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('no "Back to the city" for the iPhone check, which has no city', () => {
  const p = page({ store: cityStore });
  p.sandbox.RescueHost.leaveGame();
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('phone');
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('btn-back-to-city').hidden, true);
});
