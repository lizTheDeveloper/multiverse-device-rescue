const test = require('node:test');
const assert = require('node:assert');
const { trainingFirst, postScanView, gameOfferedFor, worryOpensTraining, gameStillOffered, noteMonitoring, SITUATIONS } = require('../renderer/app.js');
const byId = (id) => SITUATIONS.find((s) => s.id === id);

test('the Training Grounds only follows a worry the game is offered for', () => {
  for (const s of SITUATIONS) {
    const offered = gameOfferedFor(s, null);
    assert.strictEqual(trainingFirst({ wantsCity: true, offered, ready: true }), offered, s.id);
  }
  assert.strictEqual(trainingFirst({ wantsCity: true, offered: gameOfferedFor(byId('watched'), null), ready: true }), false);
  assert.strictEqual(trainingFirst({ wantsCity: true, offered: gameOfferedFor(byId('phone'), null), ready: true }), false);
  assert.strictEqual(trainingFirst({ wantsCity: false, offered: true, ready: true }), false);
  assert.strictEqual(trainingFirst({ wantsCity: true, offered: true, ready: false }), false);
});

test('after the boss scan: city only when still offered and the person stayed in the game', () => {
  const base = { inGame: true, left: false, wantsCity: true, rememberedCity: false, offered: true, ready: true };
  assert.strictEqual(postScanView(base), 'boss-city');
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'critical' }] }] };
  assert.strictEqual(postScanView({ ...base, offered: gameOfferedFor(byId('unsure'), monitoring) }), 'results');
  assert.strictEqual(postScanView({ ...base, left: true }), 'results');
  assert.strictEqual(postScanView({ ...base, left: true, rememberedCity: true }), 'results');
  assert.strictEqual(postScanView({ ...base, ready: false }), 'results');
});

test('outside the game, Plan A’s rule is unchanged', () => {
  const base = { inGame: false, left: false, wantsCity: false, rememberedCity: false, offered: true, ready: true };
  assert.strictEqual(postScanView(base), 'results');
  assert.strictEqual(postScanView({ ...base, wantsCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true, offered: false }), 'results');
  assert.strictEqual(postScanView({ ...base, wantsCity: true, ready: false }), 'results');
});

test('a worry never opens the Training Grounds on a machine whose last scan found monitoring software', () => {
  const ready = { wantsCity: true, ready: true };
  const warned = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'warning' }] }] };
  const critical = { modules: [{ name: 'keylogger_indicators', findings: [{ severity: 'critical' }] }] };
  const infoOnly = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'info' }] }] };
  for (const id of ['unsure', 'wifi', 'hacked', 'helping']) {
    assert.strictEqual(worryOpensTraining({ ...ready, situation: byId(id), lastScanDoc: warned }), false, id);
    assert.strictEqual(worryOpensTraining({ ...ready, situation: byId(id), lastScanDoc: critical }), false, id);
    assert.strictEqual(worryOpensTraining({ ...ready, situation: byId(id), lastScanDoc: infoOnly }), true, id);
    assert.strictEqual(worryOpensTraining({ ...ready, situation: byId(id), lastScanDoc: null }), true, id);
  }
  assert.strictEqual(worryOpensTraining({ ...ready, situation: byId('watched'), lastScanDoc: null }), false);
  assert.strictEqual(worryOpensTraining({ ...ready, situation: byId('phone'), lastScanDoc: null }), false);
  assert.strictEqual(worryOpensTraining({ wantsCity: false, ready: true, situation: byId('unsure'), lastScanDoc: null }), false);
});

test('monitoring software seen once this session keeps the game closed, even after a narrower clean scan', () => {
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'warning' }] }] };
  // home_for_the_holidays (`helping`) runs none of the safety modules.
  const narrowClean = { modules: [{ name: 'disk_space', findings: [] }] };
  let seen = false;
  seen = noteMonitoring(seen, monitoring);
  seen = noteMonitoring(seen, narrowClean);
  seen = noteMonitoring(seen, null);
  assert.strictEqual(seen, true, 'sticky for the session');
  const unsure = byId('unsure');
  assert.strictEqual(worryOpensTraining({ situation: unsure, lastScanDoc: narrowClean, monitoringSeen: seen, wantsCity: true, ready: true }), false);
  assert.strictEqual(gameStillOffered(unsure, narrowClean, seen), false, 'no city view either');
  // Without it, the narrow clean scan alone would have reopened the game.
  assert.strictEqual(worryOpensTraining({ situation: unsure, lastScanDoc: narrowClean, monitoringSeen: false, wantsCity: true, ready: true }), true);
  assert.strictEqual(gameStillOffered(unsure, narrowClean, false), true);
  // The per-doc check still applies on its own.
  assert.strictEqual(gameStillOffered(unsure, monitoring, false), false);
  assert.strictEqual(gameStillOffered(byId('watched'), narrowClean, false), false);
  assert.strictEqual(noteMonitoring(false, narrowClean), false);
  assert.strictEqual(noteMonitoring(false, { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'info' }] }] }), false);
});
