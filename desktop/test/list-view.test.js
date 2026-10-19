// The city's LIST tab (Plain view is retired): a read-only, literal list of
// everything the checkup found, built from NotChecked.displayItems, with a
// way back to the city. Synthetic findings only.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const app = require('../renderer/app.js');
const NC = require('../renderer/not-checked.js');
const { page, clean } = require('./page-harness.js');

const RENDERER = path.join(__dirname, '..', 'renderer');
const read = (f) => fs.readFileSync(path.join(RENDERER, f), 'utf8');
const mod = (name, findings, extra = {}) => Object.assign({ name, category: 'security', status: 'ok', supported: true, findings }, extra);
const warning = (title, extra = {}) => Object.assign({ title, description: 'What to do: look at it.', severity: 'warning', category: 'security', data: {} }, extra);
const SPY = { title: 'Monitoring app found: ExampleSpy', severity: 'critical', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found', description: 'ExampleSpy can record what you type.',
  data: { stalkerware_name: 'ExampleSpy', location: '/Library/Application Support/ExampleSpyAgent' },
  remediation: { steps: [{ title: 'Remove it', body: 'Uninstall it.' }] } };

async function listAfterSweep(doc, mode = 'standard') {
  const p = page({ store: { 'device-rescue.display': mode } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  p.sandbox.RescueHost.showList();
  assert.deepStrictEqual(p.shown(), ['results']);
  return p;
}

test('every element app.js reads is on the page (or drawn by it)', () => {
  const src = read('app.js');
  const html = read('index.html');
  const drawn = new Set(['question-title', 'results-safety']);
  const ids = [...new Set([...src.matchAll(/getElementById\('([^']+)'\)/g)].map((m) => m[1]))];
  assert.deepStrictEqual(ids.filter((id) => !drawn.has(id) && !html.includes(`id="${id}"`)), []);
});

test('the Plain-only pieces are gone: clear list, Your-progress dialog, the route choice, the phone Start', () => {
  const html = read('index.html');
  for (const gone of ['clear-list.js', 'plain-panel.js', 'progress-dialog', 'btn-your-progress', 'btn-play-game', 'btn-phone-start', 'results-progress"']) {
    assert.ok(!html.includes(gone), gone);
  }
  assert.ok(!fs.existsSync(path.join(RENDERER, 'clear-list.js')));
  assert.ok(!fs.existsSync(path.join(RENDERER, 'game', 'profile', 'plain-panel.js')));
  // The flows stay: the city's missions use them.
  for (const kept of ['fix-flow.js', 'mark-flow.js', 'checklist.js']) assert.match(html, new RegExp(`<script src="${kept}"></script>`));
  assert.doesNotMatch(read('app.js'), /ClearList|FixFlow\.attach|MarkFlow\.attach|listCounts/);
});

test('the LIST is literal: one card per item of displayItems, all on show, nothing to tick or act on', async () => {
  const many = Array.from({ length: 14 }, (_, i) => warning(`Warning ${i}`, { fixable: { will_change: 'x' }, markable: { kind: 'background_task', id: `id${i}` } }));
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('a', many), mod('b', [{ title: 'A note', severity: 'info', category: 'integrity', description: 'n', data: {} }])] };
  const p = await listAfterSweep(doc);
  const html = p.byId('results-groups').innerHTML;
  const list = NC.displayItems(doc, { mode: 'standard' });
  const cards = html.match(/<li class="finding-card /g) || [];
  assert.strictEqual(cards.length, list.critical.length + list.warning.length + list.info.length + list.marked.length + list.held.length);
  assert.doesNotMatch(html, /\[FIX IT\]|\[IT IS MINE\]|data-clear-did|data-card-pick|data-bulk|data-show-more|data-card-more|Cleared/);
  assert.match(html, /data-evidence/, 'evidence blocks');
  assert.match(p.byId('results-summary').innerHTML, /14 things to look at, and 1 good-to-know note further down\./);
});

test('an item marked as yours on an earlier checkup stays listed and says so', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('a', [warning('A helper starts at login', { data: { marked_by_user: true } })])] };
  const p = await listAfterSweep(doc);
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /A helper starts at login/);
  assert.ok(html.includes(app.MARKED_BEFORE_LINE));
});

test('city mode: a held item is drawn as the help district draws it; standard mode lists it with its warning', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('stalkerware_scan', [SPY]), mod('remote_login_check', [warning('Remote Login is on')])] };
  const c = await listAfterSweep(doc, 'city');
  const card = c.byId('results-groups').innerHTML.split('<li class="finding-card').find((x) => x.includes('ExampleSpy'));
  assert.match(card, /data-held/);
  assert.match(card, /evidence--held/);
  assert.match(card, /Write this down/);
  assert.doesNotMatch(card, /data-evidence-copy|data-copy-ai|data-ask-id|Show me how|Uninstall|tech-log/);
  assert.match(card, /Don’t remove it yet\. Talk to an advocate first\./);
  const s = await listAfterSweep(doc, 'standard');
  const std = s.byId('results-groups').innerHTML.split('<li class="finding-card').find((x) => x.includes('ExampleSpy'));
  assert.doesNotMatch(std, /data-held/, 'standard mode holds nothing');
  assert.match(std, /Removing this can alert whoever installed it\./);
});

test('the not-checked box is honest on the LIST: never an all-clear while a check didn’t run', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('a', []), mod('b', [], { status: 'error', error: 'timed out after 60s' })] };
  const p = await listAfterSweep(doc);
  assert.strictEqual(p.byId('results-errors').hidden, false);
  assert.match(p.byId('results-errors-line').textContent, /1 check couldn’t run/);
  assert.doesNotMatch(p.byId('results-summary').innerHTML, /Nothing stood out|all clear|tidy/i);
});

test('the LIST before any sweep says nothing was checked, never clean', () => {
  const p = page({ store: { 'device-rescue.display': 'city' } });
  assert.deepStrictEqual(p.shown(), ['city'], 'city mode opens into the city');
  p.sandbox.RescueHost.showList();
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.ok(p.byId('results-summary').innerHTML.includes(app.NO_SCAN_LINE));
  assert.doesNotMatch(app.NO_SCAN_LINE, /clean|clear|tidy|safe/i);
  assert.strictEqual(p.byId('results-groups').innerHTML, '');
  assert.strictEqual(p.byId('results-city-switch').hidden, true, 'nothing to go back to yet');
});

test('leaveGame (the city couldn’t draw): the LIST after a sweep, the scan screen mid-sweep or before one', async () => {
  const before = page();
  before.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(before.shown(), ['scan']);

  const mid = page();
  mid.byId('btn-get-started').click();
  mid.pick('wifi');
  mid.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(mid.shown(), ['scan']);
  assert.strictEqual(mid.byId('scan-progress').hidden, false);

  const after = page();
  after.byId('btn-get-started').click();
  after.pick('wifi');
  await after.finish(clean);
  assert.deepStrictEqual(after.shown(), ['city']);
  after.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(after.shown(), ['results']);
  // Back to the city from there draws it again from the finished scan.
  after.byId('btn-back-city').click();
  assert.deepStrictEqual(after.shown(), ['city']);
  assert.strictEqual(after.calls.last.name, 'show');
});

test('the city can’t be drawn on the way back: the LIST stays', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  await p.finish(clean);
  p.sandbox.RescueHost.showList();
  p.sandbox.RescueGame.show = () => false;
  p.key('Escape');
  assert.deepStrictEqual(p.shown(), ['results']);
});

test('a mode change redraws the LIST: monitoring software becomes held at once', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('stalkerware_scan', [SPY])] };
  const p = await listAfterSweep(doc, 'standard');
  assert.doesNotMatch(p.byId('results-groups').innerHTML, /data-held/);
  // "Something changed?" → "Yes": city mode.
  p.byId('btn-something-changed').click();
  p.answer('yes');
  assert.match(p.byId('results-groups').innerHTML, /data-held/);
});

test('the welcome screen copy has no time words and no Plain view', () => {
  const html = read('index.html');
  const welcome = html.slice(html.indexOf('id="screen-welcome"'), html.indexOf('id="screen-worry"'));
  assert.doesNotMatch(welcome, /minute|second|hour|quick|Plain view/i);
  assert.match(welcome, /city to take back/);
});

// Moved from profile-plain-panel.test.js (the Your-progress dialog is gone):
// the publishing test seam is never used by the app itself.
test('no app code passes a publishing seam: only controller.js and the tests name it', () => {
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
    return (r !== 'renderer/game/controller.js' && /\bpublishing\b/.test(src)) || /\bpublishReady\b/.test(src);
  }).map(rel);
  assert.deepStrictEqual(offenders, []);
});

// Moved from profile-plain-panel.test.js.
test('display-mode.js puts DisplayMode on window, where the game\'s modules read it', () => {
  const vm = require('node:vm');
  const window = {};
  vm.runInNewContext(read('display-mode.js'), { window });
  assert.ok(window.DisplayMode, 'window.DisplayMode');
  assert.strictEqual(typeof window.DisplayMode.ensureSeed, 'function');
  assert.match(read('game/controller.js'), /profileSeed\(storage, win\.DisplayMode\)/);
});

test('city mode: a removal warning in the description stays on the card’s face when there is no safety note to show it', async () => {
  const doc = { schema_version: 1, platform: 'darwin', modules: [mod('launch_agent_audit', [warning('A helper starts at login', {
    description: 'A helper starts at login.\n\nIf you think someone close to you set this up to monitor you, removing it can alert them.' })])] };
  const p = await listAfterSweep(doc, 'city');
  const face = p.byId('results-groups').innerHTML.split('<details class="tech-details">')[0];
  assert.match(face, /removing it can alert them/);
});
