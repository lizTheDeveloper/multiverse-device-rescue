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
  const choices = { outerHTML: '' };
  const calls = { recheck: [], showList: 0 };
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: (sel) => (sel === '.choices' ? choices : null) };
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
    RescueHost: { showList() { calls.showList += 1; }, docChanged: () => true, wantsSafety: () => false },
    // Each entry is a scan doc, or a function returning one (or a promise of one).
    rescue: { recheckModule: async (name) => {
      calls.recheck.push(name);
      const next = recheckDocs.shift();
      const doc = typeof next === 'function' ? await next(name) : next;
      return { ok: true, doc, module: doc.modules.find((m) => m.name === name) };
    } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, hooks, click, choices, calls };
}

async function setup(recheckDocs, before = scan(mod('mod_a', [finding('A')]), mod('mod_b', [finding('B')]))) {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
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

test('fixing every mission in a district leads to its milestone, which lists them', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const afterB = scan(mod('mod_a', []), mod('mod_b', []));
  const t = await setup([afterA, afterB]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  t.click({ 'data-act': 'debrief:easy' });
  assert.match(t.choices.outerHTML, /BACK TO THE DISTRICT/, 'B is still open: no milestone yet');

  // The district still shows A, lit and RECLAIMED, though the scan no longer reports it.
  t.click({ 'data-go': 'district:gatehouse' });
  assert.match(t.frame.innerHTML, /mission-row lit[\s\S]*RECLAIMED[\s\S]*>A</);

  t.click({ 'data-go': `mission:${t.idB}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  t.click({ 'data-act': 'debrief:easy' });
  assert.match(t.choices.outerHTML, /data-go="milestone:gatehouse"/);

  t.click({ 'data-go': 'milestone:gatehouse' });
  const html = t.frame.innerHTML;
  assert.match(html, /DISTRICT TAKEN BACK/);
  assert.match(html, /FIXED AND CHECKED[\s\S]*<li>A<\/li>[\s\S]*<li>B<\/li>/);

  t.click({ 'data-go': 'map' });
  assert.match(t.frame.innerHTML, /2 RECLAIMED/);
  assert.doesNotMatch(t.frame.innerHTML, /NOTHING FOUND/);
});

test('Undo: a neutral "put back" line, never "came back", and the checking screen while it runs', async () => {
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const before = scan(mod('mod_a', [finding('A')]), mod('mod_b', [finding('B')]));
  let release;
  const held = () => new Promise((r) => { release = () => r(before); });
  const t = await setup([afterA, held]);

  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'mod_a', result: { quarantine_id: QID }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /RECLAIMED/);

  t.hooks.fix.onResult({ kind: 'undo', module: 'mod_a', result: { restored: true }, described: { restored: true } });
  await tick();
  assert.match(t.frame.innerHTML, /Checking again/, 'the reclaimed mission still shows its checking screen');
  assert.doesNotMatch(t.frame.innerHTML, /aria-label="Your computer as a city"/);

  release();
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /PUT BACK/);
  assert.match(t.frame.innerHTML, /Put back\. It’s showing again\./);
  assert.doesNotMatch(t.frame.innerHTML, /NOT YET|put themselves back/);

  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.frame.innerHTML, /came back/);
});

test('"Stop treating this as mine" gets the same neutral line', async () => {
  const marked = { ...finding('A'), severity: 'info', code: 'security.mod_a.x', data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k1', original_severity: 'critical' } };
  const open = { ...finding('A'), code: 'security.mod_a.x', data: { plist: '/a.plist' } };
  const before = scan(mod('mod_a', [marked]), mod('mod_b', [finding('B')]));
  const after = scan(mod('mod_a', [open]), mod('mod_b', [finding('B')]));
  const t = await setup([after], before);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.mark.onResult({ kind: 'removed', result: { status: 'removed', ids: ['k1'] }, described: { done: true } });
  await tick(); await tick();
  assert.match(t.frame.innerHTML, /Put back\. It’s showing again\./);
  assert.doesNotMatch(t.frame.innerHTML, /NOT YET/);
});

test('a mark that covers findings in two checks re-checks both', async () => {
  const fa = { ...finding('A'), code: 'security.mod_a.x', markable: { id: 'k1' }, data: { plist: '/a.plist' } };
  const fc = { ...finding('A too'), code: 'security.mod_c.x', markable: { id: 'k2' }, data: { plist: '/a.plist' } };
  const ma = { ...fa, severity: 'info', markable: undefined, data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k1', original_severity: 'critical' } };
  const mc = { ...fc, severity: 'info', markable: undefined, data: { plist: '/a.plist', marked_by_user: true, known_item_id: 'k2', original_severity: 'critical' } };
  const before = scan(mod('mod_a', [fa]), mod('mod_b', [finding('B')]), mod('mod_c', [fc]));
  const after = scan(mod('mod_a', [ma]), mod('mod_b', [finding('B')]), mod('mod_c', [mc]));
  const t = await setup([after, after], before);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.hooks.mark.onResult({ kind: 'marked', result: { status: 'marked', ids: ['k1', 'k2'] }, described: { done: true } });
  await tick(); await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, ['mod_a', 'mod_c']);
  assert.match(t.frame.innerHTML, /MARKED AS YOURS/);
});

test('LIST works while a re-check is running', async () => {
  let release;
  const afterA = scan(mod('mod_a', []), mod('mod_b', [finding('B')]));
  const t = await setup([() => new Promise((r) => { release = () => r(afterA); })]);
  t.click({ 'data-go': `mission:${t.idA}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick();
  assert.match(t.frame.innerHTML, /Checking again/);
  t.click({ 'data-act': 'list' });
  assert.strictEqual(t.calls.showList, 1);
  t.click({ 'data-go': 'map' });
  assert.match(t.frame.innerHTML, /Checking again/, 'other clicks still wait for the re-check');
  release();
  await tick(); await tick();
});
