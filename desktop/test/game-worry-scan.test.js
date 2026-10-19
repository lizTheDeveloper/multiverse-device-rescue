// app.js's own wiring, in a stubbed page: picking a worry in game mode starts
// the same read-only scan the plain route runs, straight onto the sweep screen.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// The classic scripts index.html loads before app.js, in one global scope.
const SRC = ['ask.js', 'copy-ai.js', 'setting-panes.js', 'router-link.js', 'app.js'].map((f) => fs.readFileSync(path.join(__dirname, '..', 'renderer', f), 'utf8')).join('\n;\n');
const { SITUATIONS } = require('../renderer/app.js');
const tick = () => new Promise((r) => setTimeout(r, 0));

class El {
  constructor() {
    this.hidden = false; this.disabled = false; this.textContent = ''; this.dataset = {}; this.style = {};
    this.listeners = {}; this.kids = []; this._html = '';
    this.classList = { toggle() {}, add() {}, remove() {}, contains: () => false };
  }
  set innerHTML(html) {
    this._html = html;
    // The worry list: one button per data-situation, as the browser would make.
    this.kids = [...String(html).matchAll(/data-situation="([^"]+)"/g)].map((m) => {
      const b = new El(); b.dataset.situation = m[1]; return b;
    });
  }
  // escapeHtml sets textContent and reads innerHTML back.
  get innerHTML() { return this._html || String(this.textContent).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() { (this.listeners.click || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  querySelectorAll(sel) { return sel === '[data-situation]' ? this.kids : []; }
  querySelector() { return null; }
  getAttribute() { return null; }
  setAttribute() {}
  appendChild() {}
  focus() {}
  scrollIntoView() {}
}

const helper = () => new Proxy(() => '', { get: (_t, k) => (k === 'attach' ? () => helper() : () => '') });

function page() {
  const els = {};
  const byId = (id) => (els[id] = els[id] || new El());
  const calls = { game: [], scans: [] };
  let finishScan;
  const sandbox = {
    console, setTimeout, Promise, JSON,
    document: { getElementById: byId, querySelectorAll: () => [], createElement: () => new El(), addEventListener() {} },
    localStorage: { getItem: () => null, setItem() {} },
    fetch: () => Promise.reject(new Error('no network in tests')),
    navigator: { userAgent: 'Macintosh' },
    // The list's helper scripts: any call returns '' (or another of these).
    ClearList: helper(), FixFlow: helper(), MarkFlow: helper(),
  };
  sandbox.window = sandbox;
  sandbox.scrollTo = () => {};
  sandbox.addEventListener = () => {};
  sandbox.rescue = {
    onScanEvent: () => () => {},
    // Read-only: the scan IPC, with the worry's profile. Nothing else is called.
    runScan: (profile) => { calls.scans.push(profile); return new Promise((r) => { finishScan = r; }); },
  };
  const rec = (name, ret) => (...args) => { calls.game.push(name); return typeof ret === 'function' ? ret(...args) : ret; };
  sandbox.RescueGame = { isReady: true, newWorry: rec('newWorry'), showBoss: rec('showBoss', true),
    scanEvent() {}, scanDone: rec('scanDone', true), scanFailed: rec('scanFailed', true), show: rec('show', true) };
  vm.runInNewContext(SRC, sandbox);
  const shown = () => ['welcome', 'worry', 'scan', 'results', 'city'].filter((k) => !byId(`screen-${k}`).hidden);
  const pick = (id) => byId('situations').kids.find((b) => b.dataset.situation === id).click();
  return { byId, calls, sandbox, shown, pick, finish: async (doc) => { finishScan(doc); await tick(); await tick(); } };
}
const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;
const clean = { schema_version: 1, platform: 'darwin', modules: [] };
const monitoring = { schema_version: 1, platform: 'darwin', modules: [{ name: 'stalkerware_scan', status: 'ok', supported: true, findings: [{ severity: 'warning', title: 't' }] }] };

test('in game mode, a worry starts its scan at once on the sweep screen: no Training Grounds first', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')], 'the same scan and profile as the plain route');
  assert.deepStrictEqual(p.shown(), ['city']);
  await p.finish(clean);
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanDone']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the plain route is unchanged: the scan screen, and no scan until Run', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.calls.scans, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [profileOf('wifi')]);
  assert.deepStrictEqual(p.calls.game, [], 'never the sweep outside game mode');
});

test('worries where someone may be watching never start the game, even from "Play it as a game"', () => {
  for (const id of ['watched', 'phone']) {
    const p = page();
    p.byId('btn-play-game').click();
    p.pick(id);
    assert.deepStrictEqual(p.calls.game, [], id);
    assert.deepStrictEqual(p.calls.scans, [], `${id}: the plain scan screen, waiting for Run`);
    assert.deepStrictEqual(p.shown(), ['scan'], id);
  }
});

test('once a scan found monitoring software, the next worry gets the plain screen, not the game', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('unsure');
  await p.finish(monitoring);
  assert.ok(!p.calls.game.includes('scanDone'), 'nobody lands in the city');
  assert.deepStrictEqual(p.shown(), ['results']);
  p.calls.game.length = 0;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  assert.deepStrictEqual(p.calls.game, []);
  assert.deepStrictEqual(p.shown(), ['scan']);
});

test('PLAIN VIEW mid-scan: the plain scan screen, then the list when it finishes', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-progress').hidden, false, 'live progress');
  await p.finish(clean);
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.ok(!p.calls.game.includes('scanDone'));
});
