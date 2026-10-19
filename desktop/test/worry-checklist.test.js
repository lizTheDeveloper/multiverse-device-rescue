// The worry screen is a checklist: tick everything that sounds close, and the
// checkup runs every check any of them would run. "Watching me" among them
// means city mode, without asking. Nothing is ticked to start with.
const test = require('node:test');
const assert = require('node:assert');
const { SITUATIONS } = require('../renderer/app.js');
const { page } = require('./page-harness.js');

const KEY = 'device-rescue.display';
const modeWrites = (p) => p.storage.writes.filter(([k]) => k === KEY);
const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('the worry screen is a checklist of worries, with two on their own', () => {
  const p = page();
  const html = p.byId('situations').innerHTML;
  assert.match(html, /<fieldset class="checklist checklist--plain" data-cl-list="worries" aria-labelledby="worry-title">/);
  assert.ok(!html.includes('<legend'), 'the heading names the list; no second legend');
  for (const id of ['hacked', 'watched', 'wifi', 'identity', 'sketchy', 'helping']) {
    assert.match(html, new RegExp(`data-cl-key="${id}"`), id);
  }
  assert.ok(!/\bchecked\b/.test(html), 'nothing is ticked to start with');
  assert.match(html, /Select at least one/);
  const alone = p.byId('situations-alone').innerHTML;
  assert.match(alone, /data-situation="unsure"/);
  assert.match(alone, /data-situation="phone"/);
});

test('two worries run the union of their profiles in one scan', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked', 'wifi');
  assert.deepStrictEqual(p.shown(), ['scan']);
  p.byId('btn-run-scan').click();
  // The page runs in its own realm: copy its array to compare it here.
  const scans = p.calls.scans.map((x) => (Array.isArray(x) ? [...x] : x));
  assert.deepStrictEqual(scans, [[profileOf('hacked'), profileOf('wifi')]]);
});

test('"watching me" among several worries goes straight to city mode, without asking', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('hacked', 'watched');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(modeWrites(p), [[KEY, 'city']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['digital_security_reset'], 'one profile, run once');
});

test('nothing ticked starts nothing', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.byId('situations').kids.find((b) => 'cl-action' in b.dataset).click();
  assert.deepStrictEqual(p.shown(), ['worry']);
  assert.deepStrictEqual(p.calls.scans, []);
});

test('"check everything" is a button of its own and runs every check', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('unsure');
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, [null]);
});

test('each visit to the worry screen starts with nothing ticked', () => {
  const p = page();
  p.byId('btn-get-started').click();
  const first = p.byId('situations').kids.find((b) => b.dataset['cl-key'] === 'hacked');
  first.checked = true;
  p.byId('btn-get-started').click();
  const again = p.byId('situations').kids.find((b) => b.dataset['cl-key'] === 'hacked');
  assert.notStrictEqual(again, first, 'the list is drawn again');
  assert.ok(!again.checked);
});

test('"Something changed?" comes back to the worry screen with focus on its link', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('back');
  assert.deepStrictEqual(p.shown(), ['worry']);
  assert.strictEqual(p.sandbox.document.activeElement, p.byId('btn-something-changed'));
});

test('redrawing the worry list adds no listeners to its container', () => {
  const p = page();
  const root = p.byId('situations');
  const counts = () => ['change', 'click', 'keydown'].map((t) => (root.listeners[t] || []).length);
  const before = counts();
  assert.deepStrictEqual(before, [1, 1, 1], 'the checklist is attached once');
  for (let i = 0; i < 3; i += 1) { p.byId('btn-get-started').click(); p.byId('btn-play-game').click(); }
  assert.deepStrictEqual(counts(), before);
});

// Copy for any AI goes to the clipboard, which a clipboard-history app can
// save to disk: under the city cover it never names "watching me".
const { copyAiSituation } = require('../renderer/app.js');
const Worries = require('../renderer/worries.js');
const ONE_FINDING = { schema_version: 1, platform: 'darwin', modules: [{ name: 'x', category: 'security', status: 'ok', supported: true,
  findings: [{ severity: 'warning', title: 'T', description: 'd', category: 'security', data: {} }] }] };

test('copy for any AI: no worry title in city mode when "watching me" is among the worries', () => {
  const watched = Worries.combine(['hacked', 'watched'], SITUATIONS);
  const alone = Worries.combine(['watched'], SITUATIONS);
  const hacked = Worries.combine(['hacked', 'wifi'], SITUATIONS);
  assert.strictEqual(copyAiSituation(watched, 'city'), undefined);
  assert.strictEqual(copyAiSituation(alone, 'city'), undefined);
  assert.strictEqual(copyAiSituation(hacked, 'city'), hacked.title);
  assert.strictEqual(copyAiSituation(watched, 'standard'), watched.title);
  assert.strictEqual(copyAiSituation(null, 'city'), undefined);
});

test('copy for any AI, on the page: the city results carry no "watching me" title', async () => {
  const p = page({ store: { [KEY]: 'city' }, ready: false });
  p.byId('btn-get-started').click();
  p.pick('hacked', 'watched');
  if (p.shown().includes('scan')) p.byId('btn-run-scan').click();
  await p.finish(ONE_FINDING);
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.strictEqual(p.run('copyAiReport.findings.length'), 1, 'the report was built');
  assert.strictEqual(p.run('copyAiReport.situation'), undefined);
  const q = page({ store: { [KEY]: 'standard' } });
  q.byId('btn-get-started').click();
  q.pick('hacked', 'wifi');
  q.byId('btn-run-scan').click();
  await q.finish(ONE_FINDING);
  assert.match(q.run('copyAiReport.situation'), /hacked/);
});
