// The controller against a stubbed window (no DOM library): just enough of
// document, the shadow root and the frame to drive clicks and FixFlow results.
const test = require('node:test');
const assert = require('node:assert');

const QID = '20261016T120000Z-com.example.a';
const finding = (title) => ({ title, description: 'd', severity: 'critical', category: 'security', data: {} });
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));

function stubWin(recheckDocs) {
  const listeners = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); }, querySelector: () => null };
  const shadow = { innerHTML: '', getElementById: () => frame };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: {
      attach: (_root, _api, h) => { hooks.fix = h; },
      fixControlsHtml: () => '',
      resultHtml: (r) => `<button data-fix-undo data-quarantine-id="${r.quarantine_id}">Undo</button>`,
    },
    MarkFlow: { attach: (_root, _api, h) => { hooks.mark = h; }, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false },
    rescue: { recheckModule: async (name) => {
      const doc = recheckDocs.shift();
      return { ok: true, doc, module: doc.modules.find((m) => m.name === name) };
    } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, hooks, click };
}

async function setup(recheckDocs) {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const before = scan(mod('mod_a', [finding('A')]), mod('mod_b', [finding('B')]));
  const ids = findingsToCity(before).districts[0].missions.map((m) => m.id);
  const stub = stubWin(recheckDocs);
  const ctl = createController({ win: stub.win, storage: memStore(), scoutSprite: () => '' });
  ctl.show(before, { id: 'unsure' });
  return { ...stub, ctl, before, idA: ids.find((i) => i.startsWith('mod_a')), idB: ids.find((i) => i.startsWith('mod_b')) };
}

test('Undo for a fix shows on that mission’s RECLAIMED screen only', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const afterB = scan(mod('mod_a', []), mod('mod_b', []));
  const t = await setup([afterA, afterB]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(t.frame.innerHTML.includes(QID), 'A’s own RECLAIMED screen offers its Undo');

  t.click({ 'data-go': `mission:${t.idB}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(!t.frame.innerHTML.includes(QID), 'B’s RECLAIMED screen must not offer A’s Undo');
});

test('a fresh show() forgets the last fix', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const t = await setup([afterA, afterA]);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.ok(t.frame.innerHTML.includes(QID));

  t.ctl.show(t.before, { id: 'unsure' });
  t.click({ 'data-go': `mission:${t.idA}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);
  assert.ok(!t.frame.innerHTML.includes(QID), 'a new city doesn’t carry an old Undo');
});
