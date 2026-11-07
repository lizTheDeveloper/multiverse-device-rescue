const test = require('node:test');
const assert = require('node:assert');
const { learnMoreFor, RECLAIM_CITY_URL, SITUATIONS } = require('../renderer/app.js');
const { isAllowedGuideUrl, GAME_URL_PREFIX } = require('../setting-urls');

const byId = (id) => SITUATIONS.find((s) => s.id === id);

test('the game link is allowed through the open-guide channel', () => {
  assert.strictEqual(RECLAIM_CITY_URL, GAME_URL_PREFIX);
  assert.ok(isAllowedGuideUrl(RECLAIM_CITY_URL));
  assert.ok(isAllowedGuideUrl(`${RECLAIM_CITY_URL}#/district/master-keys`));
});

test('the allowlist does not open up the rest of the game host or look-alikes', () => {
  for (const url of [
    'https://play.multiversegames.ai/',
    'https://play.multiversegames.ai/other-game/',
    'https://play.multiversegames.ai/reclaim-city-evil/',
    'https://play.multiversegames.ai.evil.example/reclaim-city/',
    'http://play.multiversegames.ai/reclaim-city/',
    ' https://play.multiversegames.ai/reclaim-city/',
    'https://evil.example/?https://play.multiversegames.ai/reclaim-city/',
  ]) {
    assert.strictEqual(isAllowedGuideUrl(url), false, `should reject ${url}`);
  }
});

test('every suggestion is an allowed link', () => {
  for (const s of SITUATIONS) {
    const learn = learnMoreFor(s, { modules: [] });
    if (learn) assert.ok(isAllowedGuideUrl(learn.url), learn.url);
  }
});

test('worries with a matching chapter deep-link to it', () => {
  assert.strictEqual(learnMoreFor(byId('hacked'), {}).url, `${RECLAIM_CITY_URL}#/district/master-keys`);
  assert.strictEqual(learnMoreFor(byId('identity'), {}).url, `${RECLAIM_CITY_URL}#/district/reclamation`);
  assert.strictEqual(learnMoreFor(byId('unsure'), {}).url, RECLAIM_CITY_URL);
});

test('not offered to someone who may be watched, or with no real match', () => {
  assert.strictEqual(learnMoreFor(byId('watched'), {}), null);
  assert.strictEqual(learnMoreFor(byId('phone'), {}), null);
  assert.strictEqual(learnMoreFor(byId('android'), {}), null);
  assert.strictEqual(learnMoreFor(byId('sketchy'), {}), null);
  assert.strictEqual(learnMoreFor(byId('wifi'), {}), null);
  assert.strictEqual(learnMoreFor(null, {}), null);
});

test('the break-in suggestion names passwords and two-step sign-in', () => {
  const { text } = learnMoreFor(byId('hacked'), {});
  assert.match(text, /passwords/);
  assert.match(text, /two-step sign-in/);
  assert.match(text, /free game/);
});

test('not offered when the scan found monitoring software', () => {
  const doc = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'critical' }] }] };
  assert.strictEqual(learnMoreFor(byId('hacked'), doc), null);
  const quiet = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'info' }] }] };
  assert.ok(learnMoreFor(byId('hacked'), quiet));
});
