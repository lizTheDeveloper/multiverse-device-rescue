'use strict';
// The photo record in the help district (game/controller.js, game/views/side-district.js): offered there only,
// in the spec's four cases; Next / Back / arrow keys; Done back to the district; Esc leaves at once; nothing
// saved, copied or scored. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { savedAsV3 } = require('./profile-read.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 6) => { for (let i = 0; i < n; i += 1) await tick(); };
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const SHARE = { title: 'Screen Sharing is on', description: 'd', severity: 'warning', category: 'security', data: { service: 'Screen Sharing' } };
const WATCH = { title: 'ExampleWatch is on this computer', description: 'd', severity: 'critical', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found',
  data: { check: 'monitoring_software_found', stalkerware_name: 'ExampleWatch', stalkerware_category: 'parental_control', location: '/Applications/ExampleWatch.app' } };
const PLAIN = scan(mod('sharing_services', [SHARE]));
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

function stub({ mode, dualUse = {} }) {
  const clicks = [];
  const keys = [];
  const clipboard = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: () => ({ focus() {} }), querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const calls = [];
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    navigator: { clipboard: { writeText: async (t) => { clipboard.push(t); } } },
    addEventListener: (type, fn) => { if (type === 'keydown') keys.push(fn); },
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => 424242, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {}, dualUseAnswers: () => dualUse },
    rescue: new Proxy({}, { get: (_t, k) => (...a) => { calls.push([k, a]); return Promise.resolve(null); } }),
  };
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; clicks.forEach((fn) => fn({ target: { closest: () => el } })); };
  const press = (key) => { const ev = { key, prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} }; keys.forEach((fn) => fn(ev)); return ev; };
  return { win, frame, click, press, clipboard, calls, html: () => frame.innerHTML };
}

async function setup({ mode = 'city', doc = PLAIN, situation = { id: mode === 'city' ? 'city' : 'unsure' }, dualUse = {} } = {}) {
  const { createController } = await game('controller.js');
  const t = stub({ mode, dualUse });
  const storage = recordingStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  ctl.show(doc, situation);
  return { ...t, ctl, storage };
}
const BUTTON = /data-act="record-open"[^>]*>MAKE A PHOTO RECORD</;

test('offered in the help district only, in the four cases, and not otherwise', async () => {
  const cases = [
    [{ mode: 'city' }, true],
    [{ mode: 'standard' }, false],
    [{ mode: 'standard', situation: { id: 'watched', safety: true } }, true],
    [{ mode: 'standard', doc: scan(mod('stalkerware_scan', [WATCH])) }, true],
    [{ mode: 'standard', dualUse: { parental_control: 'someone' } }, true],
    [{ mode: 'standard', dualUse: { employee_monitoring: 'employer' } }, false],
  ];
  for (const [opts, offered] of cases) {
    const t = await setup(opts);
    assert.doesNotMatch(t.html(), /record-open/, `${JSON.stringify(opts)}: never on the map`);
    t.click({ 'data-go': 'side' });
    assert.match(t.html(), /side-title/);
    if (offered) assert.match(t.html(), BUTTON, JSON.stringify(opts));
    else assert.doesNotMatch(t.html(), /record-open/, JSON.stringify(opts));
  }
});

test('pages: Next, Back and the arrow keys move; Done returns to the district; Esc leaves at once', async () => {
  const t = await setup({ mode: 'city', doc: scan(mod('stalkerware_scan', [WATCH]), mod('sharing_services', [SHARE])) });
  t.click({ 'data-go': 'side' });
  t.click({ 'data-act': 'record-open' });
  await ticks();
  const page = () => (/Page (\d+) of (\d+)/.exec(t.html()) || [])[1];
  assert.strictEqual(page(), '1');
  assert.match(t.html(), /How to use these pages/);
  t.click({ 'data-act': 'record-next' });
  assert.strictEqual(page(), '2');
  assert.match(t.html(), /ExampleWatch/);
  t.press('ArrowRight');
  assert.strictEqual(page(), '3');
  t.press('ArrowLeft');
  assert.strictEqual(page(), '2');
  t.click({ 'data-act': 'record-back' });
  assert.strictEqual(page(), '1');
  t.press('ArrowLeft');
  assert.strictEqual(page(), '1', 'nothing before the first page');
  t.click({ 'data-act': 'record-done' });
  assert.match(t.html(), /side-title/);
  assert.doesNotMatch(t.html(), /pr-page/);
  // Esc, from a page: straight to the game.
  t.click({ 'data-act': 'record-open' });
  await ticks();
  assert.match(t.html(), /pr-page/);
  assert.strictEqual(t.press('Escape').prevented, true);
  assert.doesNotMatch(t.html(), /pr-page|side-title/);
});

test('it saves, copies, exports and scores nothing', async () => {
  const t = await setup({ mode: 'city', doc: scan(mod('stalkerware_scan', [WATCH]), mod('sharing_services', [SHARE])) });
  t.click({ 'data-go': 'side' });
  await ticks();
  const writes = t.storage.writes.length;
  const asked = t.calls.length;
  const points = savedAsV3(t.storage).deck.points;
  t.click({ 'data-act': 'record-open' });
  await ticks();
  for (let i = 0; i < 6; i += 1) t.click({ 'data-act': 'record-next' });
  t.press('ArrowLeft');
  t.click({ 'data-act': 'record-done' });
  await ticks();
  assert.strictEqual(t.storage.writes.length, writes, `no writes: ${JSON.stringify(t.storage.writes.slice(writes))}`);
  assert.deepStrictEqual(t.storage.removed, []);
  assert.deepStrictEqual(t.clipboard, [], 'nothing on the clipboard');
  assert.deepStrictEqual(t.calls.slice(asked), [], 'nothing asked of the main process (no export, no file, no network)');
  assert.strictEqual(savedAsV3(t.storage).deck.points, points, 'no points');
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});
