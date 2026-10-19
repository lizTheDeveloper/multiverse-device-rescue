// app.js's own wiring in a stubbed page, for the flow tests. Every classic
// script index.html loads runs in one global scope, in index.html's order, so
// a new script there is picked up here by itself. FixFlow, MarkFlow and
// ClearList are stand-ins: a card's fix and mark controls leave a marker, so a
// test can see whether a card offered them.
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { recordingStore } = require('./disk-words.js');

const RENDERER = path.join(__dirname, '..', 'renderer');
const STUBBED = new Set(['fix-flow.js', 'mark-flow.js', 'clear-list.js']);
const INDEX = fs.readFileSync(path.join(RENDERER, 'index.html'), 'utf8');
const SCRIPTS = [...INDEX.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]).filter((f) => !STUBBED.has(f));
const SRC = SCRIPTS.map((f) => fs.readFileSync(path.join(RENDERER, f), 'utf8')).join('\n;\n');
const tick = () => new Promise((r) => setTimeout(r, 0));

class El {
  constructor(doc) {
    this.doc = doc;
    this._hidden = false; this.disabled = false; this.textContent = ''; this.dataset = {}; this.style = {};
    this.listeners = {}; this.kids = []; this._html = '';
    const classes = new Set();
    this.classList = { toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)), add: (c) => classes.add(c),
      remove: (c) => classes.delete(c), contains: (c) => classes.has(c) };
  }
  // Every time the page shows an element, in order (doc.revealed), so a test can see a flash.
  get hidden() { return this._hidden; }
  set hidden(v) {
    if (!v && this.id && this.doc && this.doc.revealed) this.doc.revealed.push(this.id);
    this._hidden = !!v;
  }
  // The controls the page makes from HTML: one per data-situation or
  // data-answer button, per worry checkbox (data-cl-key) and per checklist
  // button (data-cl-action).
  set innerHTML(html) {
    this._html = String(html);
    this.kids = [...this._html.matchAll(/data-(situation|answer|cl-key|cl-action)="([^"]+)"/g)].map((m) => {
      const b = new El(this.doc); b.dataset[m[1]] = m[2]; b.attrs = { [`data-${m[1]}`]: m[2] }; return b;
    });
  }
  // escapeHtml sets textContent and reads innerHTML back.
  get innerHTML() { return this._html || String(this.textContent).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  click() { (this.listeners.click || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  querySelectorAll(sel) {
    const m = /^\[data-(situation|answer|cl-key|cl-action)\]$/.exec(sel);
    return m ? this.kids.filter((k) => m[1] in k.dataset) : [];
  }
  querySelector() { return null; }
  getAttribute(name) { return this.attrs && name in this.attrs ? this.attrs[name] : null; }
  setAttribute() {}
  appendChild() {}
  focus() { if (this.doc) this.doc.activeElement = this; }
  scrollIntoView() {}
}

const helper = () => new Proxy(() => '', { get: (_t, k) => (k === 'attach' ? () => helper() : () => '') });

// `blocked: true` is storage that throws on every call (a locked-down or
// private profile); the attempted writes are still recorded in `storage.writes`.
function blockedStore() {
  const writes = [];
  const fail = () => { throw new Error('storage blocked'); };
  return { data: {}, writes, removed: [], getItem: fail, removeItem: fail, clear: fail,
    setItem: (k, v) => { writes.push([String(k), String(v)]); fail(); } };
}

function page({ store = { 'device-rescue.display': 'standard' }, ready = true, blocked = false } = {}) {
  const els = {};
  const doc = { activeElement: null, revealed: [] };
  // Screens start as index.html has them: only the welcome screen showing.
  const byId = (id) => {
    if (!els[id]) { els[id] = new El(doc); els[id].id = id; if (/^screen-/.test(id) && id !== 'screen-welcome') els[id]._hidden = true; }
    return els[id];
  };
  // The progress dots at the top of the page, one per step.
  const dots = ['welcome', 'worry', 'scan', 'results'].map((d) => { const e = new El(doc); e.dataset.stepDot = d; return e; });
  const calls = { game: [], scans: [], guides: [], last: null };
  const winListeners = {};
  const storage = blocked ? blockedStore() : recordingStore(store || {});
  let finishScan = () => {};
  let failScan = () => {};
  // The page's scan-event listener, so a test can play the engine's stderr events.
  let scanListener = null;
  const sandbox = {
    console, setTimeout, clearTimeout, Promise, JSON,
    document: Object.assign(doc, { getElementById: byId, querySelectorAll: (sel) => (sel === '[data-step-dot]' ? dots : []),
      createElement: () => new El(doc), addEventListener() {} }),
    localStorage: storage,
    fetch: () => Promise.reject(new Error('no network in tests')),
    navigator: { userAgent: 'Macintosh' },
    ClearList: helper(),
    FixFlow: { attach: () => helper(), fixControlsHtml: () => '[FIX IT]' },
    MarkFlow: { attach: () => helper(), markControlsHtml: () => '[IT IS MINE]' },
  };
  sandbox.window = sandbox;
  sandbox.scrollTo = () => {};
  sandbox.addEventListener = (type, fn) => { (winListeners[type] = winListeners[type] || []).push(fn); };
  sandbox.dispatchEvent = () => true;
  sandbox.rescue = {
    platform: 'darwin',
    onScanEvent: (cb) => { scanListener = cb; return () => { if (scanListener === cb) scanListener = null; }; },
    // Read-only: the scan IPC, with the worry's profile. Nothing else is called.
    runScan: (profile) => { calls.scans.push(profile); return new Promise((r, j) => { finishScan = r; failScan = j; }); },
    openGuide: (url) => { calls.guides.push(url); return Promise.resolve(true); },
  };
  const rec = (name, ret) => (...args) => {
    calls.game.push(name);
    calls.last = { name, args };
    return typeof ret === 'function' ? ret(...args) : ret;
  };
  sandbox.RescueGame = { isReady: ready, newWorry: rec('newWorry'), showBoss: rec('showBoss', true),
    showTraining: rec('showTraining', true), showHome: rec('showHome', true), scanEvent() {}, scanDone: rec('scanDone', true),
    scanFailed: rec('scanFailed', true), show: rec('show', true) };
  vm.runInNewContext(SRC, sandbox);
  const shown = () => ['welcome', 'worry', 'question', 'scan', 'results', 'city'].filter((k) => !byId(`screen-${k}`).hidden);
  // "Check everything" and the iPhone check are buttons of their own; the
  // other worries are ticked, then "Start the checkup" is pressed.
  const pick = (...ids) => {
    const alone = ids.length === 1 ? byId('situations-alone').kids.find((b) => b.dataset.situation === ids[0]) : null;
    if (alone) return alone.click();
    const kids = byId('situations').kids;
    for (const id of ids) {
      const box = kids.find((b) => b.dataset['cl-key'] === id);
      box.checked = true;
      (box.listeners.change || []).forEach((fn) => fn({ target: box }));
    }
    return kids.find((b) => 'cl-action' in b.dataset).click();
  };
  const answer = (id) => byId('question-card').kids.find((b) => b.dataset.answer === id).click();
  const fire = (type) => (winListeners[type] || []).forEach((fn) => fn({ type }));
  const finish = async (d) => { finishScan(d); await tick(); await tick(); };
  const fail = async (message) => { failScan(new Error(message)); await tick(); await tick(); };
  const emit = (ev) => { if (scanListener) scanListener(ev); };
  const activeDot = () => dots.filter((e) => e.classList.contains('step-dot--active')).map((e) => e.dataset.stepDot);
  // Reads a top-level name from the page's scripts (a const isn't on window).
  const run = (code) => vm.runInContext(code, sandbox);
  const revealed = () => doc.revealed.slice();
  return { byId, calls, sandbox, storage, shown, pick, answer, fire, finish, fail, emit, activeDot, run, revealed };
}

const clean = { schema_version: 1, platform: 'darwin', modules: [] };
const monitoring = { schema_version: 1, platform: 'darwin', modules: [{ name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true,
  findings: [{ severity: 'warning', title: 'Monitoring app found', description: 'An app that can record what you type.', category: 'security', data: {} }] }] };

module.exports = { page, clean, monitoring, tick };
