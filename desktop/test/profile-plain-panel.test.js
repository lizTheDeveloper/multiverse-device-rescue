// "Your progress" in plain view, against stub elements (no DOM library).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { recordingStore } = require('./disk-words.js');
const { savedProfile } = require('./profile-read.js');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const NOW = '2026-10-18T12:00:00.000Z';

function el(id) {
  const listeners = {};
  return { id, innerHTML: '', open: false, focused: 0, attrs: {},
    addEventListener: (t, fn) => { (listeners[t] = listeners[t] || []).push(fn); },
    fire: (t, ev = {}) => (listeners[t] || []).forEach((fn) => fn(ev)),
    showModal() { this.open = true; }, close() { this.open = false; this.fire('close'); },
    focus() { this.focused += 1; }, setAttribute(k, v) { this.attrs[k] = v; } };
}
async function setup({ mode = 'standard', publishReady = false, storage = recordingStore({ 'device-rescue.game.v1': JSON.stringify(V3) }),
  loadBank = null, host = true } = {}) {
  const [{ attachPlainPanel }, { buildBank }] = await Promise.all([
    import('../renderer/game/profile/plain-panel.js'), import('../renderer/game/profile/item-bank.js')]);
  const els = { 'btn-your-progress': el('b'), 'progress-dialog': el('d'), 'progress-dialog-body': el('body'), 'profile-title': el('h') };
  const calls = { reload: 0, clipboard: [] };
  const m = { now: mode };
  const winListeners = {};
  const seeds = [];
  const win = { document: { getElementById: (id) => els[id] || null, createElement: () => ({ click() {} }) },
    addEventListener: (t, fn) => { (winListeners[t] = winListeners[t] || []).push(fn); },
    DisplayMode: { ensureSeed: () => { seeds.push(1); return 4242; } },
    RescueGame: { reloadProfile: () => { calls.reload += 1; } },
    navigator: { clipboard: { writeText: async (t) => { calls.clipboard.push(t); } } } };
  if (host) win.RescueHost = { mode: () => m.now };
  const panel = attachPlainPanel({ win, storage, loadBank: loadBank || (async () => buildBank(LESSONS, DRILLS)), publishReady });
  const click = (act, checked = false) => els['progress-dialog-body'].fire('click', { target: { closest: () => ({ checked, getAttribute: () => act }) } });
  const openIt = async () => { els['btn-your-progress'].fire('click'); await tick(); await tick(); };
  const setMode = (next) => { m.now = next; (winListeners['rescue-mode-changed'] || []).forEach((fn) => fn({})); };
  return { els, calls, panel, click, storage, mode: m, setMode, seeds, openIt, body: () => els['progress-dialog-body'].innerHTML };
}

test('the button opens a modal dialog with the plain view of the profile, its heading focused', async () => {
  const t = await setup();
  await t.openIt();
  assert.strictEqual(t.els['progress-dialog'].open, true);
  assert.match(t.body(), /<h2 id="profile-title" tabindex="-1">Your progress<\/h2>/);
  assert.ok(t.body().includes('Points: 340 (level 3 of 5)'));
  assert.strictEqual(t.els['profile-title'].focused, 1);
  t.click('profile-close');
  assert.strictEqual(t.els['progress-dialog'].open, false);
  assert.strictEqual(t.els['btn-your-progress'].focused, 1, 'focus goes back to the button');
});

test('Clear my progress in plain view asks first, saves through the profile, and tells the game to read it again', async () => {
  const t = await setup();
  await t.openIt();
  assert.match(t.body(), />Clear my progress<\/button>/);
  assert.doesNotMatch(t.body(), /Start over/, 'the results screen has its own Start over');
  t.click('profile-start-over-yes');
  assert.strictEqual(t.calls.reload, 0, 'not without being asked first');
  t.click('profile-start-over');
  assert.match(t.body(), /role="alertdialog"/);
  assert.ok(t.body().includes('Clear your progress? This clears your lessons, drills, rank and missions here. Nothing on your computer changes.'));
  assert.match(t.body(), />Yes, clear it<\/button>/);
  assert.doesNotMatch(t.body(), /Start over/);
  t.click('profile-start-over-yes');
  assert.strictEqual(t.seeds.length, 1, 'the seed comes from window.DisplayMode when there is no box yet');
  assert.strictEqual(savedProfile(t.storage).rank.points, 0);
  assert.strictEqual(t.calls.reload, 1);
  assert.ok(t.body().includes('Points: 0 (level 1 of 5)'));
  assert.doesNotMatch(t.body(), /role="alertdialog"/);
});

test('Escape while asking to start over closes the question, not the dialog; then it closes the dialog', async () => {
  const t = await setup();
  await t.openIt();
  t.click('profile-start-over');
  let prevented = 0;
  t.els['progress-dialog'].fire('cancel', { preventDefault: () => { prevented += 1; } });
  assert.strictEqual(prevented, 1);
  assert.strictEqual(t.els['progress-dialog'].open, true);
  assert.doesNotMatch(t.body(), /role="alertdialog"/);
  t.els['progress-dialog'].fire('cancel', { preventDefault: () => { prevented += 1; } });
  assert.strictEqual(prevented, 1, 'the browser closes the dialog itself');
});

test('the dialog reads the profile fresh each time it opens', async () => {
  const t = await setup();
  await t.openIt();
  t.click('profile-close');
  const pp = await import('../renderer/game/profile/player-profile.js');
  const p = pp.loadProfile(t.storage, NOW);
  pp.saveProfile(t.storage, { ...p, rank: { points: 1000, index: 3 } }, { seed: 7, mode: 'standard' });
  await t.openIt();
  assert.ok(t.body().includes('Points: 1000'), t.body());
});

test('city mode: no publish control, and its actions do nothing', async () => {
  const t = await setup({ mode: 'city', publishReady: true });
  await t.openIt();
  assert.doesNotMatch(t.body(), /profile-publish/);
  t.click('profile-publish'); t.click('pub-toggle:lessons', true); t.click('publish-copy');
  await tick();
  assert.doesNotMatch(t.body(), /pub-preview/);
  assert.deepStrictEqual(t.calls.clipboard, []);
});

test('any mode but standard (city, not chosen yet, a host that can\'t say): the dialog never opens and nothing is written', async () => {
  for (const opts of [{ mode: 'city' }, { mode: null }, { host: false }]) {
    const t = await setup(opts);
    await t.openIt();
    assert.strictEqual(t.els['progress-dialog'].open, false, JSON.stringify(opts));
    assert.strictEqual(t.body(), '');
    t.click('profile-start-over'); t.click('profile-start-over-yes');
    assert.strictEqual(t.storage.writes.length, 0);
    assert.strictEqual(t.calls.reload, 0);
  }
});

test('the mode turning to city while the dialog is open: the next action closes it and does nothing else', async () => {
  const t = await setup();
  await t.openIt();
  t.click('profile-start-over');
  t.mode.now = 'city';
  t.click('profile-start-over-yes');
  assert.strictEqual(t.els['progress-dialog'].open, false);
  assert.strictEqual(t.body(), '');
  assert.strictEqual(t.storage.writes.length, 0);
  assert.strictEqual(t.calls.reload, 0);
});

test('the headline count is the game\'s rule (publish.js lessonsLearned): a hidden concept never holds a lesson back', async () => {
  const [pp, ib, training, pub] = await Promise.all([import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'), import('../renderer/game/training.js'), import('../renderer/game/profile/publish.js')]);
  const gameDrills = [{ id: 'upd8r-hidden-cache', answer: 'threat', district: 'gatehouse', clues: {} }];
  const lessons = await training.loadLessons(importModule);
  const bank = ib.buildBank(lessons, gameDrills);
  let p = pp.emptyProfile(NOW);
  for (let pass = 0; pass < 2; pass += 1) {
    for (const [key, it] of bank.items) if (it.kind === 'lesson') p = pp.recordAnswer(p, bank, key, it.concept !== 'cut-off-order', NOW);
  }
  const full = pp.summary(p, bank);
  const shown = pub.lessonsLearned(full);
  assert.ok(shown > full.lessonsLearned, 'the fixture has a lesson held back only by the hidden concept');
  const storage = recordingStore();
  pp.saveProfile(storage, p, { seed: 4242, mode: 'standard' });
  const t = await setup({ storage, loadBank: async () => ib.buildBank(lessons, gameDrills) });
  await t.openIt();
  const m = /<p>(\d+) of \d+ learned<\/p>/.exec(t.body());
  assert.ok(m, 'a headline count');
  assert.strictEqual(Number(m[1]), shown);
});

test('publishing (test seam only): a tick for anything not on the list is ignored', async () => {
  const t = await setup({ publishReady: true });
  await t.openIt();
  t.click('profile-publish');
  t.click('pub-toggle:bogus', true);
  t.click('publish-copy');
  await tick();
  assert.deepStrictEqual(t.calls.clipboard, [], 'nothing on the list ticked: nothing to copy');
  t.click('pub-toggle:lessons', true);
  t.click('publish-copy');
  await tick();
  assert.strictEqual(t.calls.clipboard.length, 1);
  assert.deepStrictEqual(Object.keys(JSON.parse(t.calls.clipboard[0])), ['security']);
});

test('missing elements: nothing is attached and nothing throws', async () => {
  const { attachPlainPanel } = await import('../renderer/game/profile/plain-panel.js');
  assert.strictEqual(attachPlainPanel({ win: { document: { getElementById: () => null } }, storage: recordingStore() }), null);
});

// The test seams (createController's `publishing`, attachPlainPanel's
// `publishReady`) are never used by the app itself.
test('no app code passes a publishing seam: only controller.js and the tests name them', () => {
  const root = path.join(__dirname, '..');
  const files = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (['node_modules', 'vendor', 'test', 'dist'].includes(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(m?js|html)$/.test(e.name)) files.push(p);
    }
  };
  walk(root);
  assert.ok(files.some((f) => f.endsWith(path.join('game', 'boot-core.js'))), 'the scan reaches the code that makes the controller');
  const rel = (f) => path.relative(root, f).split(path.sep).join('/');
  const offenders = files.filter((f) => {
    const src = fs.readFileSync(f, 'utf8');
    const r = rel(f);
    return (r !== 'renderer/game/controller.js' && /\bpublishing\b/.test(src))
      || (r !== 'renderer/game/profile/plain-panel.js' && /\bpublishReady\b/.test(src));
  }).map(rel);
  assert.deepStrictEqual(offenders, []);
  // And plain-panel.js attaches itself without the seam.
  const auto = /attachPlainPanel\(\{ win: window, storage: safeStorage\(\) \}\)/;
  assert.match(fs.readFileSync(path.join(root, 'renderer/game/profile/plain-panel.js'), 'utf8'), auto);
});

test('the button is hidden in any mode but standard, and follows the mode as it changes', async () => {
  const t = await setup({ mode: 'city' });
  assert.strictEqual(t.els['btn-your-progress'].hidden, true);
  t.setMode('standard');
  assert.strictEqual(t.els['btn-your-progress'].hidden, false);
  await t.openIt();
  assert.strictEqual(t.els['progress-dialog'].open, true);
  t.setMode('city');
  assert.strictEqual(t.els['btn-your-progress'].hidden, true);
  assert.strictEqual(t.els['progress-dialog'].open, false, 'an open dialog closes');
  assert.strictEqual(t.body(), '');
  const none = await setup({ host: false });
  assert.strictEqual(none.els['btn-your-progress'].hidden, true, 'a host that can\'t say');
});

test('app.js tells the panel when the mode changes', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'app.js'), 'utf8');
  const setMode = /function setMode\(next\) \{[\s\S]*?\n {4}\}/.exec(src);
  assert.ok(setMode, 'setMode found');
  assert.match(setMode[0], /dispatchEvent\(new Event\('rescue-mode-changed'\)\)/);
});

test('display-mode.js puts DisplayMode on window, where the game\'s modules (controller, panel) read it', () => {
  const vm = require('node:vm');
  const window = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'renderer', 'display-mode.js'), 'utf8'), { window });
  assert.ok(window.DisplayMode, 'window.DisplayMode');
  assert.strictEqual(typeof window.DisplayMode.ensureSeed, 'function');
  for (const f of ['renderer/game/controller.js', 'renderer/game/profile/plain-panel.js']) {
    assert.match(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), /profileSeed\(storage, win\.DisplayMode\)/, f);
  }
});
