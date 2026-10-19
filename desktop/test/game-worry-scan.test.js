// app.js's own wiring, in a stubbed page: picking a worry starts its
// read-only scan straight onto the city's sweep screen (Plain view is retired).
const test = require('node:test');
const assert = require('node:assert');
const { SITUATIONS } = require('../renderer/app.js');
const { page, clean, monitoring } = require('./page-harness.js');

const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('a worry starts its scan at once on the sweep screen: no Training Grounds first', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')], 'the same scan and profile as the plain route');
  assert.deepStrictEqual(p.shown(), ['city']);
  await p.finish(clean);
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanDone']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the game can\'t draw (not ready): the scan screen, no scan until Run, then the LIST', async () => {
  const p = page({ ready: false });
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.calls.scans, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')]);
  await p.finish(clean);
  assert.deepStrictEqual(p.shown(), ['results'], 'the LIST, which has the same results');
  assert.deepStrictEqual(p.calls.game, [], 'never the sweep when the game can\'t draw');
});

test('the iPhone check plays in the city too: its sweep starts at once', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('phone');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, [profileOf('phone')]);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the welcome screen has one way in: no Plain view route or toggle', () => {
  const fs = require('fs');
  const path = require('path');
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  assert.match(html, /id="btn-get-started"/);
  assert.doesNotMatch(html, /btn-play-game|route-choice|Plain view/i);
});

test('monitoring software in standard mode: the follow-up first, and "Yes, I know about it" keeps the game', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.ok(!p.calls.game.includes('scanDone'), 'nothing lands before the answer');
  p.answer('known');
  assert.ok(p.calls.game.includes('scanDone'));
  assert.deepStrictEqual(p.shown(), ['city']);
  p.calls.game.length = 0;
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss'], 'the next worry plays too');
});

test('the city leaves mid-scan (it couldn\'t draw): the scan screen with live progress, then the LIST', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-progress').hidden, false, 'live progress');
  await p.finish(clean);
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.ok(!p.calls.game.includes('scanDone'));
});
