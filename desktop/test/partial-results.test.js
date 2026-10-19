// Results while the checkup runs (Plain view). The engine streams each
// finished check's entry; the results screen shows them as partial: "N of M
// checks done", never an all-clear, and nothing on a card that changes the
// computer until the scan is done.
const test = require('node:test');
const assert = require('node:assert');
const {
  partialScanState, applyPartialEvent, partialDocOf, isPartialDoc,
  partialCountText, partialSummaryText, PARTIAL_ACTIONS_TEXT,
} = require('../renderer/app.js');
const { page } = require('./page-harness.js');

const ALL_CLEAR = /Nothing stood out|Nice and tidy|all clear|clean bill/i;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const warning = { title: 'Unknown helper starts at login', description: 'A program starts by itself.', severity: 'warning',
  category: 'security', code: 'security.launch_agents_audit.unsigned', data: { path: '/tmp/helper' },
  fixable: { will_change: 'Stops it.', how_to_undo: ['Turn it back on.'] } };
const info = { title: '12 apps installed', description: 'An inventory.', severity: 'info', category: 'bloatware', data: {} };
const entry = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true,
  unsupported_reason: null, findings, ...extra });
const done = (index, total, name, findings = 0) => ({ type: 'progress', phase: 'done', index, total, module: name, category: 'security', findings, error: null });

test('partial state: plan, done lines and streamed entries; a repeated entry replaces the old one', () => {
  const s = partialScanState();
  assert.strictEqual(applyPartialEvent(s, { type: 'plan', total: 3, modules: [] }), false);
  assert.strictEqual(applyPartialEvent(s, done(1, 3, 'a')), false);
  assert.strictEqual(applyPartialEvent(s, { type: 'module', result: entry('a', []) }), true);
  assert.strictEqual(applyPartialEvent(s, { type: 'module', result: entry('a', [warning]) }), true);
  assert.strictEqual(applyPartialEvent(s, { type: 'log', line: 'x' }), false);
  assert.strictEqual(applyPartialEvent(s, { type: 'module', result: { findings: [] } }), false, 'no name: ignored');
  const doc = partialDocOf(s, 'darwin');
  assert.deepStrictEqual(doc.partial, { done: 1, total: 3 });
  assert.strictEqual(doc.modules.length, 1);
  assert.strictEqual(doc.modules[0].findings.length, 1);
  assert.ok(isPartialDoc(doc));
  assert.ok(!isPartialDoc({ schema_version: 1, modules: [] }));
});

test('partial words say how far along, and never read as an all-clear', () => {
  assert.strictEqual(partialCountText({ done: 34, total: 120 }), 'The checkup is still running: 34 of 120 checks done.');
  assert.strictEqual(partialCountText({ done: 0, total: 0 }), 'The checkup is still running.');
  for (const counts of [{}, { worth: 0, other: 0 }, { worth: 0, other: 5 }, { worth: 2, other: 1 }]) {
    const said = partialSummaryText(counts);
    assert.doesNotMatch(said, ALL_CLEAR, said);
  }
  assert.match(partialSummaryText({ worth: 1 }), /So far, 1 thing worth a look/);
  assert.match(partialSummaryText({ worth: 0, other: 3 }), /isn’t finished/);
  assert.match(partialSummaryText({}), /isn’t finished/);
  assert.doesNotMatch(PARTIAL_ACTIONS_TEXT + partialCountText({ done: 1, total: 2 }), /minute|second|hour|soon/i, 'no time estimates');
});

async function running(mode = 'standard') {
  const p = page({ store: { 'device-rescue.display': mode }, ready: false });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.shown(), ['scan']);
  return p;
}

test('mid-scan: "See results so far" appears once a check is in, and shows partial cards with nothing to act on', async () => {
  const p = await running();
  assert.strictEqual(p.byId('scan-partial').hidden, true, 'nothing finished yet');
  p.emit({ type: 'plan', total: 3, modules: [] });
  p.emit({ type: 'progress', phase: 'start', index: 1, total: 3, module: 'launch_agents_audit', category: 'security' });
  p.emit(done(1, 3, 'launch_agents_audit', 1));
  p.emit({ type: 'module', result: entry('launch_agents_audit', [warning]) });
  assert.strictEqual(p.byId('scan-partial').hidden, false);

  p.byId('btn-see-partial').click();
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.strictEqual(p.byId('results-running').hidden, false);
  assert.strictEqual(p.byId('results-running-text').textContent, 'The checkup is still running: 1 of 3 checks done.');
  assert.strictEqual(p.byId('results-running-actions').textContent, PARTIAL_ACTIONS_TEXT);
  assert.match(p.byId('results-title').textContent, /so far/);
  const summary = p.byId('results-summary').innerHTML;
  assert.match(summary, /So far, 1 thing worth a look/);
  assert.doesNotMatch(summary, ALL_CLEAR);
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /Unknown helper starts at login/);
  assert.ok(!html.includes('[FIX IT]') && !html.includes('[IT IS MINE]'), 'no fix or mark mid-scan');
  assert.strictEqual(p.byId('results-copy-all').hidden, true, 'no whole-report copy of a partial scan');
  assert.strictEqual(p.byId('results-tech').hidden, true);

  // More checks finish while the person reads: the count moves at once, the cards shortly.
  p.emit(done(2, 3, 'apps', 1));
  p.emit({ type: 'module', result: entry('apps', [info], { category: 'bloatware' }) });
  assert.strictEqual(p.byId('results-running-text').textContent, 'The checkup is still running: 2 of 3 checks done.');
  await sleep(450);
  assert.match(p.byId('results-groups').innerHTML, /12 apps installed/);

  // Back to the progress, then the scan finishes: the full list, with its controls.
  p.byId('btn-back-to-scan').click();
  assert.deepStrictEqual(p.shown(), ['scan']);
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [entry('launch_agents_audit', [warning]), entry('apps', [info]), entry('c', [])] });
  assert.deepStrictEqual(p.shown(), ['results']);
  assert.strictEqual(p.byId('results-running').hidden, true);
  assert.strictEqual(p.byId('results-copy-all').hidden, false);
  assert.doesNotMatch(p.byId('results-title').textContent, /so far/);
  assert.ok(p.byId('results-groups').innerHTML.includes('[FIX IT]'), 'fixes once the checkup is done');
  assert.strictEqual(p.byId('scan-partial').hidden, true);
});

test('never all-clear while running: finished checks with nothing found still say the checkup isn’t done', async () => {
  const p = await running();
  p.emit({ type: 'plan', total: 120, modules: [] });
  p.emit(done(1, 120, 'disk_space'));
  p.emit({ type: 'module', result: entry('disk_space', []) });
  p.byId('btn-see-partial').click();
  const summary = p.byId('results-summary').innerHTML;
  assert.match(summary, /Nothing to show yet\. The checkup isn’t finished\./);
  assert.doesNotMatch(summary, ALL_CLEAR);
  assert.match(p.byId('results-running-text').textContent, /1 of 120 checks done/);
  // Only info so far: still not "nothing stood out".
  p.emit(done(2, 120, 'apps', 1));
  p.emit({ type: 'module', result: entry('apps', [info]) });
  await sleep(450);
  assert.doesNotMatch(p.byId('results-summary').innerHTML, ALL_CLEAR);
  assert.match(p.byId('results-summary').innerHTML, /more may turn up/);
});

test('a check that couldn’t run shows under "Couldn’t check these" mid-scan, not as clean', async () => {
  const p = await running();
  p.emit({ type: 'plan', total: 2, modules: [] });
  p.emit(done(1, 2, 'x'));
  p.emit({ type: 'module', result: entry('x', [], { status: 'error', error: 'timed out' }) });
  p.byId('btn-see-partial').click();
  assert.strictEqual(p.byId('results-errors').hidden, false);
  assert.doesNotMatch(p.byId('results-summary').innerHTML, ALL_CLEAR);
});

test('city mode mid-scan: monitoring software gets its hold line and nothing to act on', async () => {
  const p = await running('city');
  p.emit({ type: 'plan', total: 2, modules: [] });
  p.emit(done(1, 2, 'stalkerware_scan', 1));
  p.emit({ type: 'module', result: entry('stalkerware_scan', [{ severity: 'warning', title: 'Monitoring app found',
    description: 'An app that can record what you type.', category: 'security', data: {} }]) });
  p.byId('btn-see-partial').click();
  const html = p.byId('results-groups').innerHTML;
  assert.match(html, /Monitoring app found/);
  assert.ok(!html.includes('[FIX IT]') && !html.includes('[IT IS MINE]'));
  assert.ok(!html.includes('data-clear-did'), 'no "I did this" either');
});

test('a scan that fails mid-way drops its partial results and shows the error where the progress was', async () => {
  const p = await running();
  p.emit({ type: 'plan', total: 2, modules: [] });
  p.emit(done(1, 2, 'launch_agents_audit', 1));
  p.emit({ type: 'module', result: entry('launch_agents_audit', [warning]) });
  p.byId('btn-see-partial').click();
  assert.deepStrictEqual(p.shown(), ['results']);
  await p.fail('engine exited 1: boom');
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-error').hidden, false);
  assert.strictEqual(p.byId('results-running').hidden, true);
  assert.strictEqual(p.byId('scan-partial').hidden, true);
});
