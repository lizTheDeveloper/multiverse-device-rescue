// The held-software guard across a restart through the player profile: the
// game's deck goes into the recipe box (disguised, city mode), comes back out
// on the next run, and the sweep where the software is gone still pays nothing.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { LESSONS, DRILLS } = require('./profile-fixtures.js');
const { savedAsV3 } = require('./profile-read.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const SPY = () => mod('stalkerware_scan', [{ title: 'Monitoring app', description: 'Monitoring app.', severity: 'critical', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found', data: { path: '/m' } }]);
const NONE = () => mod('stalkerware_scan', []);
const OLD = 'device-rescue.game.v1';
const LATER = '2026-10-19T09:00:00.000Z';

function stub() {
  let html = '';
  const frame = {
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; },
    addEventListener() {},
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const host = { attachShadow: () => shadow, closest: () => null };
  const win = {
    document: { getElementById: () => host },
    addEventListener() {},
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => 'city', citySeed: () => 424242, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: async () => true },
  };
  return { win, html: () => html };
}

async function run(storage, doc) {
  const { createController } = await game('controller.js');
  const t = stub();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, saved: () => savedAsV3(storage) };
}

test('city mode: held software, a restart through the recipe box, then a sweep without it: no CLEAN SWEEP, no points, carry kept', async () => {
  const pp = await game('profile/player-profile.js');
  const { buildBank } = await game('profile/item-bank.js');
  const bank = buildBank(LESSONS, DRILLS);
  const remote = () => mod('remote_login_check', []);

  // First run: the held finding is there. The game's deck marks the sweep.
  const first = recordingStore();
  const a = await run(first, scan(SPY(), remote()));
  assert.strictEqual(a.saved().deck.points, 0);
  assert.strictEqual(a.saved().deck.sweep.carry, true, 'the sweep is marked');
  assert.doesNotMatch(a.html(), /CLEAN SWEEP|DISTRICT SECURED/);

  // The controller keeps it in the recipe box (city mode: no literal document left).
  const disk = first;
  assert.strictEqual(disk.data[OLD], undefined, 'city mode leaves no literal document');
  const box = disk.data[pp.PROFILE_KEY];
  assert.ok(box.startsWith('{"kitchen":'), 'stored as a recipe box');
  assert.doesNotMatch(box, /carry|Monitoring app|stalkerware|"\/m"/, 'the box names nothing');
  assert.deepStrictEqual(forbiddenWrites(disk), []);

  // Restart: the profile is read back from the box, and the game runs on its view.
  const back = pp.loadProfile(disk, LATER);
  assert.strictEqual(back.deck.sweep.carry, true, 'carry intact after the disguised round-trip');
  assert.strictEqual(back.rank.points, 0);
  assert.strictEqual(pp.toProgress(back, bank).deck.sweep.carry, true);
  const b = await run(disk, scan(NONE(), remote()));
  assert.match(b.html(), /<b>100%<\/b>/, 'the board reads secured');
  assert.doesNotMatch(b.html(), /CLEAN SWEEP|DISTRICT SECURED/, 'its going is not a win');
  assert.strictEqual(b.saved().deck.points, 0, 'no points');
  assert.strictEqual(b.saved().deck.sweep.carry, undefined, 'this sweep holds nothing');
  assert.strictEqual(pp.loadProfile(disk, LATER).rank.points, 0, 'the box, read again, still pays nothing');
  assert.deepStrictEqual(forbiddenWrites(disk), []);
});
