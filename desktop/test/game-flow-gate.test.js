// The gate, rewritten on purpose. Monitoring software no longer takes anyone
// out of the game. In 'city' the game is the cover: it never prompts removal,
// never offers a fix or a mark for monitoring software, and never makes a
// mission of it. In 'standard' the person is asked first (first-question.js).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { gameScanFirst, postScanView, gameOfferedFor, worryStartsGameScan, noteMonitoring, opensInGame,
  CITY_SITUATION, ALWAYS_SAFETY_MODULES, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

test('the game is offered for every worry but the iPhone check, monitoring software or not', () => {
  for (const s of SITUATIONS) assert.strictEqual(gameOfferedFor(s), s.id !== 'phone', s.id);
  assert.strictEqual(gameOfferedFor(CITY_SITUATION), true);
  assert.strictEqual(gameOfferedFor(null), false);
});

test('city always plays: a worry starts its scan in the game, even from Get started', () => {
  for (const s of SITUATIONS) {
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: false, mode: 'city', ready: true }), s.id !== 'phone', s.id);
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: false, mode: 'standard', ready: true }), false, s.id);
    assert.strictEqual(worryStartsGameScan({ situation: s, wantsCity: true, mode: 'standard', ready: true }), s.id !== 'phone', s.id);
  }
  assert.strictEqual(worryStartsGameScan({ situation: byId('unsure'), wantsCity: true, mode: 'city', ready: false }), false);
  assert.strictEqual(gameScanFirst({ wantsCity: true, offered: true, ready: true }), true);
  assert.strictEqual(opensInGame('city'), true);
  assert.strictEqual(opensInGame('standard'), false);
  assert.strictEqual(opensInGame(null), false);
});

test('after a game scan: the city, whatever it found; Plain view stays plain', () => {
  const base = { inGame: true, left: false, wantsCity: true, rememberedCity: false, offered: gameOfferedFor(byId('unsure')), ready: true };
  assert.strictEqual(postScanView({ ...base, mode: 'standard' }), 'boss-city');
  assert.strictEqual(postScanView({ ...base, mode: 'city' }), 'boss-city');
  assert.strictEqual(postScanView({ ...base, left: true, mode: 'city' }), 'results');
  assert.strictEqual(postScanView({ ...base, ready: false, mode: 'city' }), 'results');
});

test('outside the game: the city when chosen, remembered, or in city mode', () => {
  const base = { inGame: false, left: false, wantsCity: false, rememberedCity: false, offered: true, ready: true, mode: 'standard' };
  assert.strictEqual(postScanView(base), 'results');
  assert.strictEqual(postScanView({ ...base, wantsCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, rememberedCity: true }), 'city');
  assert.strictEqual(postScanView({ ...base, mode: 'city' }), 'city');
  assert.strictEqual(postScanView({ ...base, mode: 'city', offered: false }), 'results', 'the iPhone check');
});

test('monitoring software seen once is remembered for the session; it decides the follow-up', () => {
  const monitoring = { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'warning' }] }] };
  const narrowClean = { modules: [{ name: 'disk_space', findings: [] }] };
  let seen = false;
  seen = noteMonitoring(seen, monitoring);
  seen = noteMonitoring(seen, narrowClean);
  seen = noteMonitoring(seen, null);
  assert.strictEqual(seen, true);
  assert.strictEqual(noteMonitoring(false, narrowClean), false);
  assert.strictEqual(noteMonitoring(false, { modules: [{ name: 'stalkerware_scan', findings: [{ severity: 'info' }] }] }), false);
});

test('city mode never prompts removal: monitoring software gets the hold line, no steps, no fix, no mark', () => {
  for (const module of ALWAYS_SAFETY_MODULES) {
    const f = { module, description: 'An app that records what you type.', remediation: { steps: [{ number: 1, title: 'Remove it', body: 'Uninstall it.' }] } };
    const card = Q.cardText('city', f);
    assert.strictEqual(card.note, 'held');
    assert.deepStrictEqual(card.steps, []);
    const html = Q.heldHtml(card, String);
    assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
    assert.doesNotMatch(html, /uninstall|delete|fix it|turn it off/i);
    assert.strictEqual(Q.lineHtml(card, String), '');
  }
  assert.strictEqual(Q.noteFor('city', { module: 'remote_login_check' }), 'none');
  assert.strictEqual(Q.heldHtml(Q.cardText('standard', { module: 'stalkerware_scan' }), String), '');
});

test('one list of monitoring checks, everywhere', async () => {
  const { HELD_MODULES } = await game('held.js');
  assert.deepStrictEqual([...HELD_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
  assert.deepStrictEqual([...Q.MONITORING_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
});

test('the game never makes a mission of monitoring software, so nothing about it is saved', async () => {
  const { splitHeld } = await game('held.js');
  const { findingsToCity } = await game('findings-to-city.js');
  const { reconcile, saveProgress, emptyProgress, ranOkModules } = await game('progress.js');
  const doc = { modules: [
    { name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true, findings: [
      { severity: 'critical', title: 'Stalkerware found: mSpy', description: 'd' }, { severity: 'info', title: 'Checked for monitoring apps' }] },
    { name: 'remote_login_check', category: 'security', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 'Remote Login is on', description: 'd' }] },
  ] };
  const split = splitHeld(doc);
  assert.deepStrictEqual(split.held, [{ module: 'stalkerware_scan', title: 'Stalkerware found: mSpy' }]);
  assert.strictEqual(doc.modules[0].findings.length, 2, 'the scan itself is untouched');
  const city = findingsToCity(split.doc);
  assert.deepStrictEqual(city.districts.flatMap((d) => d.missions).map((m) => m.module), ['remote_login_check']);
  assert.ok(city.districts.find((d) => d.id === 'gatehouse').checksRan >= 2, 'the check still counts as having run');
  const store = recordingStore();
  saveProgress(store, reconcile(emptyProgress(), city, ranOkModules(doc), '2026-10-18T00:00:00Z').progress);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.doesNotMatch(JSON.stringify(store.data), /mSpy|stalkerware/i);
  assert.deepStrictEqual(splitHeld(null), { doc: null, held: [] });
});
