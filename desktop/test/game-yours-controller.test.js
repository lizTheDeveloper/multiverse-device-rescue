const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const MarkFlow = require('../renderer/mark-flow.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 10) => { for (let i = 0; i < n; i += 1) await tick(); };
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const UNDO = ['Choose “Stop treating this as mine”'];
const mod = (name, findings, category = 'security') => ({ name, category, status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });

function taskFinding(n, marked = false) {
  const data = { check: 'suspicious_path', label: `com.example.t${n}`, program: `/Users/me/.x/t${n}`, plist: `/Users/me/Library/LaunchAgents/t${n}.plist` };
  const made_by = [{ subject: data.program, name: 'Example LLC', verified: true }];
  if (marked) {
    return { title: `Background task you marked as yours: com.example.t${n}`, severity: 'info', category: 'security', code: 'security.launch_agent_audit.suspicious_path',
      description: 'd', made_by, data: { ...data, marked_by_user: true, known_item_id: `00000000000${n}`, original_severity: 'warning' } };
  }
  return { title: `Background task runs from a hidden folder: com.example.t${n}`, severity: 'warning', category: 'security', description: 'd',
    code: 'security.launch_agent_audit.suspicious_path', made_by, data,
    markable: { kind: 'background_task', id: `00000000000${n}`, code: 'security.launch_agent_audit.suspicious_path', label: data.label,
      program: data.program, plist: data.plist, will_change: 'Stops warning.', how_to_undo: UNDO } };
}
const SPY = mod('stalkerware_scan', [{ title: 'Stalkerware found: mSpy', description: 'd', severity: 'critical', category: 'security', data: {} }]);
const startup = mod('startup_optimizer', [{ title: 'Startup report', severity: 'info', category: 'performance', description: 'd',
  data: { items: [{ label: 'com.example.t1', plist: '/Users/me/Library/LaunchAgents/t1.plist', when: ['at login'], running: true, pid: 4 }] } }], 'performance');
const docWith = (marked = new Set(), extra = []) => scan(mod('launch_agent_audit', [1, 2].map((n) => taskFinding(n, marked.has(`00000000000${n}`)))), startup, ...extra);

function stub({ mode = 'standard', extra = [] } = {}) {
  const clicks = [];
  const saved = new Set();
  const calls = { mark: [], unmark: [], recheck: [] };
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: () => {},
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { ...MarkFlow, attach() {} },
    RescueHost: { mode: () => mode, citySeed: () => 1, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: {
      markMine: async (id) => { calls.mark.push(id); saved.add(id); return { status: 'marked', ids: [id] }; },
      unmarkMine: async (id) => { calls.unmark.push(id); saved.delete(id); return { status: 'removed', ids: [id] }; },
      recheckModule: async (name) => { calls.recheck.push(name); return { ok: true, doc: docWith(saved, extra), module: { name, status: 'ok' } }; },
    },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, calls, click, html: () => frame.innerHTML };
}

async function setup(opts = {}) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = recordingStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  ctl.show(docWith(new Set(), opts.extra || []), { id: 'unsure', title: 'Not sure' });
  const { findingIdentity } = await game('findings-to-city.js');
  const idOf = (n) => findingIdentity({ ...taskFinding(n), module: 'launch_agent_audit' });
  return { ...t, ctl, storage, idOf };
}
const attr = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const points = (storage) => JSON.parse(storage.getItem('device-rescue.game.v1')).deck.points;

test('the queue offers MINE ✓ on each markable row, with an unticked checkbox, and labels what each one does', async () => {
  const t = await setup();
  const html = t.html();
  assert.ok(html.includes(`data-act="mine:${attr(t.idOf(1))}"`));
  assert.ok(html.includes(`data-act="pick:${attr(t.idOf(1))}"`));
  assert.doesNotMatch(html, /data-act="pick:[^"]*" checked/, 'checkboxes start unticked');
  assert.match(html, /Starts on its own/);
  assert.match(html, /Running now/);
});

test('one click: out of the queue, into YOURS, no screen change, no points; Undo puts it back', async () => {
  const t = await setup();
  const before = points(t.storage);
  t.click({ 'data-act': `mine:${t.idOf(1)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.mark, ['000000000001']);
  const html = t.html();
  assert.ok(!html.includes(`data-act="mine:${attr(t.idOf(1))}"`), 'gone from the queue');
  assert.match(html, /INCOMING SIGNALS/, 'still on the deck');
  assert.doesNotMatch(html, /o-yours|BACK TO THE DISTRICT/, 'no outcome screen');
  assert.match(html, /data-go="yours"[^>]*>YOURS <b class="yours-count[^"]*">1<\/b>/);
  assert.match(html, /Sorted into YOURS: com\.example\.t1/);
  assert.deepStrictEqual(t.calls.recheck, ['launch_agent_audit'], 'a quiet re-check');
  assert.strictEqual(points(t.storage), before, 'marking pays nothing');
  assert.strictEqual(JSON.parse(t.storage.getItem('device-rescue.game.v1')).deck.sweep.marked, true);
  t.click({ 'data-act': 'mine-undo' });
  await ticks();
  assert.deepStrictEqual(t.calls.unmark, ['000000000001']);
  assert.ok(t.html().includes(`data-act="mine:${attr(t.idOf(1))}"`), 'back in the queue');
});

test('the YOURS district lists it with what it does and who made it, and NOT MINE sends it back', async () => {
  const t = await setup();
  t.click({ 'data-act': `mine:${t.idOf(1)}` });
  await ticks();
  t.click({ 'data-go': 'yours' });
  const html = t.html();
  assert.match(html, /id="yours-title"/);
  assert.match(html, /com\.example\.t1/);
  assert.match(html, /Starts on its own/);
  assert.match(html, /Made by Example LLC <small>\(verified\)<\/small>/);
  assert.match(html, /data-go="lesson:what-kind-of-program"/);
  t.click({ 'data-act': `unmine:${t.idOf(1)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.unmark, ['000000000001']);
  t.click({ 'data-act': 'yours-back' });
  assert.ok(t.html().includes(`data-act="mine:${attr(t.idOf(1))}"`));
});

test('bulk: tick two, one action marks both', async () => {
  const t = await setup();
  t.click({ 'data-act': `pick:${t.idOf(1)}` });
  t.click({ 'data-act': `pick:${t.idOf(2)}` });
  assert.match(t.html(), /MARK 2 AS MINE/);
  t.click({ 'data-act': 'mine-picked' });
  await ticks();
  assert.deepStrictEqual(t.calls.mark.sort(), ['000000000001', '000000000002']);
  assert.match(t.html(), /2 sorted into YOURS/);
});

test('the district’s missions drop what’s marked, and point to YOURS', async () => {
  const t = await setup();
  t.click({ 'data-act': `mine:${t.idOf(1)}` });
  await ticks();
  t.click({ 'data-go': 'district:gatehouse' });
  const html = t.html();
  assert.doesNotMatch(html, /hidden folder: com\.example\.t1/);
  assert.match(html, /hidden folder: com\.example\.t2/);
  assert.match(html, /1 MARKED AS YOURS/);
});

test('an open case has one MINE (the verdict); the briefing offers the one-step mark, with no long confirmation panel', async () => {
  const t = await setup();
  t.click({ 'data-go': `signal:${t.idOf(2)}` });
  // A first signal opens guided (guided.js); its call is the game's MINE.
  const open = t.html().split('class="sig-panel')[1].split('</section>\n  </li>')[0];
  t.click({ 'data-act': 'guide-call' });
  assert.match(t.html().split('class="sig-panel')[1], /data-act="tag:mine"/);
  assert.ok(!open.includes(`data-act="mine:${attr(t.idOf(2))}"`), 'never two MINE buttons on one case');
  assert.doesNotMatch(t.html(), /data-mark-panel/);
  t.click({ 'data-go': `mission:${t.idOf(2)}` });
  assert.ok(t.html().includes(`data-act="mine:${attr(t.idOf(2))}"`));
  assert.doesNotMatch(t.html(), /data-mark-panel/);
  t.click({ 'data-act': `mine:${t.idOf(2)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.mark, ['000000000002']);
  assert.match(t.html(), /INCOMING SIGNALS/, 'back to the deck, where it is gone');
});

test('SAFETY: with monitoring software held, it is in no queue, no YOURS, no MINE; every quick mark asks first', async () => {
  const t = await setup({ extra: [SPY] });
  const html = t.html();
  assert.doesNotMatch(html, /mSpy/);
  t.click({ 'data-act': `mine:${t.idOf(1)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.mark, [], 'asked first, nothing marked yet');
  assert.match(t.html(), /Only do this if you set this up yourself/);
  assert.ok(t.html().includes(`data-act="mine-yes:${attr(t.idOf(1))}"`));
  t.click({ 'data-act': 'mine-no' });
  t.click({ 'data-act': 'mine:stalkerware_scan|' });
  t.click({ 'data-go': 'yours' });
  assert.doesNotMatch(t.html(), /mSpy/);
  await ticks();
  assert.deepStrictEqual(t.calls.mark, []);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
  assert.doesNotMatch(t.storage.getItem('device-rescue.game.v1'), /mSpy|stalkerware/i);
});

test('SAFETY: city mode asks once for every mark', async () => {
  const t = await setup({ mode: 'city' });
  t.click({ 'data-act': `mine:${t.idOf(1)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.mark, []);
  t.click({ 'data-act': `mine-yes:${t.idOf(1)}` });
  await ticks();
  assert.deepStrictEqual(t.calls.mark, ['000000000001']);
});
