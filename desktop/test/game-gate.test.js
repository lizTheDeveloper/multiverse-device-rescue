const test = require('node:test');
const assert = require('node:assert');
const { mayBeWatched, gameOfferedFor, learnMoreFor, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const withFinding = (module, severity) => ({ modules: [{ name: module, findings: [{ severity }] }] });

test('open for every worry but the iPhone check, which keeps its own plain screen', () => {
  for (const id of ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping', 'unsure']) {
    assert.strictEqual(gameOfferedFor(byId(id)), true, id);
  }
  assert.strictEqual(gameOfferedFor(byId('phone')), false);
});

test('monitoring software found no longer closes it: the follow-up question decides', () => {
  for (const mod of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    for (const sev of ['critical', 'warning']) {
      assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding(mod, sev)), true, `${mod} ${sev}`);
    }
  }
});

test('closed with no worry picked', () => {
  assert.strictEqual(gameOfferedFor(null), false);
});

test('learnMoreFor still hides the web game link exactly when mayBeWatched says so', () => {
  for (const s of SITUATIONS) {
    if (mayBeWatched(s, { modules: [] })) assert.strictEqual(learnMoreFor(s, { modules: [] }), null, s.id);
  }
  assert.strictEqual(learnMoreFor(byId('hacked'), withFinding('stalkerware_scan', 'warning')), null);
});

test('no worry promises how long anything takes', () => {
  for (const s of SITUATIONS) {
    assert.doesNotMatch(`${s.title} ${s.sub}`, /\b(seconds?|minutes?|hours?)\b/i, s.id);
  }
});
