const test = require('node:test');
const assert = require('node:assert');
const { mayBeWatched, gameOfferedFor, learnMoreFor, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const withFinding = (module, severity) => ({ modules: [{ name: module, findings: [{ severity }] }] });

test('closed for the worries where someone may be watching', () => {
  assert.strictEqual(gameOfferedFor(byId('watched'), { modules: [] }), false);
  assert.strictEqual(gameOfferedFor(byId('phone'), { modules: [] }), false);
});

test('closed when monitoring software is found, whatever the worry', () => {
  for (const mod of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    for (const sev of ['critical', 'warning']) {
      assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding(mod, sev)), false, `${mod} ${sev}`);
    }
  }
});

test('an info finding from a monitoring module does not close it', () => {
  assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding('stalkerware_scan', 'info')), true);
});

test('open for every other worry, including ones with no matching chapter', () => {
  for (const id of ['hacked', 'wifi', 'identity', 'sketchy', 'helping', 'unsure']) {
    assert.strictEqual(gameOfferedFor(byId(id), { modules: [] }), true, id);
    assert.strictEqual(gameOfferedFor(byId(id), null), true, `${id} before any scan`);
  }
});

test('closed with no worry picked', () => {
  assert.strictEqual(gameOfferedFor(null, { modules: [] }), false);
});

test('learnMoreFor still hides the game link exactly when mayBeWatched says so', () => {
  for (const s of SITUATIONS) {
    if (mayBeWatched(s, { modules: [] })) assert.strictEqual(learnMoreFor(s, { modules: [] }), null, s.id);
  }
  assert.strictEqual(learnMoreFor(byId('hacked'), withFinding('stalkerware_scan', 'warning')), null);
});
