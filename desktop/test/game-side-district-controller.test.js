const test = require('node:test');
const assert = require('node:assert');
const { savedAsV3 } = require('./profile-read.js');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 4) => { for (let i = 0; i < n; i += 1) await tick(); };
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const finding = (title, severity) => ({ title, description: 'd', severity, category: 'security', data: {} });
const DOC = scan(mod('remote_login_check', [finding('Remote Login is on', 'warning')]), mod('stalkerware_scan', [finding('Stalkerware found: mSpy', 'critical')]));
const CLEAN = scan(mod('remote_login_check', [finding('Remote Login is on', 'warning')]));
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

function stub({ mode = 'city', seed = 424242, openGuide = async () => true } = {}) {
  const clicks = [];
  const keys = [];
  const focused = [];
  const calls = { guides: [] };
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: (sel) => {
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      return m && frame.innerHTML.includes(`${m[1]}="${m[2]}"`) ? { focus: () => focused.push(sel) } : null;
    },
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: (type, fn) => { if (type === 'keydown') keys.push(fn); },
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => seed, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: (url) => { calls.guides.push(url); return openGuide(url); } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const press = (key) => {
    const ev = { key, prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} };
    keys.forEach((fn) => fn(ev));
    return ev;
  };
  return { win, frame, calls, click, press, focused, html: () => frame.innerHTML };
}

async function setup(opts = {}, doc = DOC) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = recordingStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl, storage };
}

test('city mode: the district is on the deck and on the Training Grounds, under its generated name', async () => {
  const { pickDistrict } = await game('district-names.js');
  const name = pickDistrict(424242).name.toUpperCase();
  const t = await setup({}, CLEAN);
  assert.match(t.html(), /data-go="side"/);
  assert.ok(t.html().includes(name) || t.html().includes(name.replace(/’/g, '&#39;')));
  t.ctl.showTraining({ id: 'city', title: 'Take back the city' });
  assert.match(t.html(), /data-go="side"/, 'before any sweep too');
});

test('standard mode: no district anywhere, and its routes and Esc do nothing', async () => {
  const t = await setup({ mode: 'standard' });
  assert.doesNotMatch(t.html(), /data-go="side"/);
  t.click({ 'data-go': 'side' });
  assert.doesNotMatch(t.html(), /side-title/);
  assert.strictEqual(t.press('Escape').prevented, false);
});

test('monitoring software waits in the district: not on the deck, no mission, no points, nothing saved', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await setup();
  const deck = t.html();
  assert.doesNotMatch(deck, /mSpy/);
  assert.ok(deck.includes(`Something new in ${pickDistrict(424242).name}`.replace(/’/g, '&#39;')) || deck.includes(`Something new in ${pickDistrict(424242).name}`));
  t.click({ 'data-go': 'side' });
  assert.match(t.html(), /mSpy/);
  assert.match(t.html(), /Don’t remove it yet\. Talk to an advocate first\./);
  assert.doesNotMatch(t.html(), /data-fix-module|data-mark-card|data-act="tag:/);
  const saved = savedAsV3(t.storage);
  assert.strictEqual(saved.deck.points, 0);
  assert.doesNotMatch(JSON.stringify(saved), /mSpy|stalkerware/i);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('Esc, or BACK TO THE GAME, swaps straight to the deck with focus on the map', async () => {
  for (const leave of ['esc', 'button']) {
    const t = await setup();
    t.click({ 'data-go': 'side' });
    assert.match(t.html(), /side-title/);
    if (leave === 'esc') assert.strictEqual(t.press('Escape').prevented, true);
    else t.click({ 'data-act': 'side-back' });
    assert.doesNotMatch(t.html(), /side-title/, leave);
    assert.match(t.html(), /INCOMING SIGNALS/, leave);
    assert.ok(t.focused.includes('[data-go="filter:gatehouse"]'), `${leave}: ${t.focused.join(', ')}`);
  }
});

test('Esc mid-transition: a guide still opening says nothing afterwards, and a second Esc does nothing', async () => {
  let resolveOpen;
  const t = await setup({ openGuide: () => new Promise((r) => { resolveOpen = r; }) });
  t.click({ 'data-go': 'side' });
  t.click({ 'data-act': 'side-open-guide' });
  await tick();
  t.press('Escape');
  resolveOpen(false);
  await ticks();
  assert.doesNotMatch(t.html(), /side-title|couldn’t be opened|six-roses/);
  const before = t.html();
  assert.strictEqual(t.press('Escape').prevented, false);
  assert.strictEqual(t.html(), before);
});

test('a sweep that finishes in the district stays there; Esc then lands on the new deck', async () => {
  const t = await setup();
  t.click({ 'data-go': 'side' });
  t.ctl.scanDone(CLEAN, { id: 'city', title: 'Take back the city' });
  assert.match(t.html(), /side-title/);
  t.press('Escape');
  assert.match(t.html(), /INCOMING SIGNALS/);
  assert.doesNotMatch(t.html(), /Something new in/, 'the new sweep held nothing');
});

test('Esc on any other screen is left alone', async () => {
  const t = await setup();
  assert.strictEqual(t.press('Escape').prevented, false);
  t.ctl.showTraining({ id: 'city', title: 'x' });
  assert.strictEqual(t.press('Escape').prevented, false);
});

test('the ops log says only where they went', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await setup();
  t.click({ 'data-go': 'side' });
  t.press('Escape');
  const log = t.html().split('OPS LOG')[1] || '';
  assert.ok(log.includes(`Visited ${pickDistrict(424242).name}`) || log.includes(`Visited ${pickDistrict(424242).name.replace(/’/g, '&#39;')}`));
  assert.doesNotMatch(log, /advocate|hotline|799|watch|remove|guide|roses/i);
});

test('opening the guide goes through openGuide with the one exact address; a refusal shows in the district only', async () => {
  const t = await setup({ openGuide: async () => false });
  t.click({ 'data-go': 'side' });
  t.click({ 'data-act': 'side-open-guide' });
  await ticks();
  assert.deepStrictEqual(t.calls.guides, ['https://themultiverse.school/x/six-roses']);
  assert.match(t.html(), /It couldn’t be opened from here\./);
  t.press('Escape');
  assert.doesNotMatch(t.html(), /couldn’t be opened/);
});

test('the same install gets the same district after a restart', async () => {
  const a = await setup({ seed: 99 }, CLEAN);
  const b = await setup({ seed: 99 }, CLEAN);
  const tile = (h) => /data-go="side">([^<]*)</.exec(h)[1];
  assert.strictEqual(tile(a.html()), tile(b.html()));
});
