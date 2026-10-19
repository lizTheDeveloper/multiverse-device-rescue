// Fixes, undos and marks never race a scan (scan-gate.js, used by main.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { createScanGate, fixRefusal, markRefusal } = require('../scan-gate');

const later = () => { let resolve; const p = new Promise((r) => { resolve = r; }); return { p, resolve }; };

test('a change asked for while a scan runs is refused, and runs normally once it is done', async () => {
  const gate = createScanGate();
  const scan = later();
  const scanning = gate.runScan(() => scan.p);
  assert.strictEqual(gate.scanning(), true);
  let ran = 0;
  const refused = fixRefusal('launch_agents_audit');
  assert.strictEqual(await gate.runChange(() => { ran += 1; return 'fixed'; }, refused), refused);
  assert.strictEqual(ran, 0, 'the engine was never asked to change anything');
  scan.resolve('doc');
  assert.strictEqual(await scanning, 'doc');
  assert.strictEqual(gate.scanning(), false);
  assert.strictEqual(await gate.runChange(() => { ran += 1; return 'fixed'; }, refused), 'fixed');
  assert.strictEqual(ran, 1);
});

test('a scan asked for while a change is running starts only after it', async () => {
  const gate = createScanGate();
  const change = later();
  const order = [];
  const changing = gate.runChange(() => change.p.then(() => order.push('change done')), null);
  const scanning = gate.runScan(() => { order.push('scan started'); return 'doc'; });
  await new Promise((r) => setTimeout(r, 5));
  assert.deepStrictEqual(order, []);
  change.resolve();
  await changing;
  assert.strictEqual(await scanning, 'doc');
  assert.deepStrictEqual(order, ['change done', 'scan started']);
});

test('a failed scan or change still reopens the gate', async () => {
  const gate = createScanGate();
  await assert.rejects(gate.runScan(() => Promise.reject(new Error('boom'))));
  assert.strictEqual(gate.scanning(), false);
  await assert.rejects(gate.runChange(() => { throw new Error('nope'); }, null));
  assert.strictEqual(await gate.runScan(() => 'ok'), 'ok');
});

test('the refusals use each flow’s own shape, say nothing was changed, and give no time estimate', () => {
  const f = fixRefusal('x');
  assert.strictEqual(f.status, 'refused');
  assert.strictEqual(f.applied, false);
  assert.strictEqual(f.error, 'scan_running');
  const m = markRefusal();
  assert.strictEqual(m.status, 'refused');
  for (const r of [f, m]) {
    assert.match(r.message, /Nothing was changed\./);
    assert.doesNotMatch(r.message, /minute|second|hour|soon/i);
  }
});

test('main.js routes every change through the gate, and the gate ships', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  for (const channel of ['run-fix', 'run-fix-action', 'undo-fix', 'mark-mine', 'unmark-mine', 'recheck-module']) {
    const at = main.indexOf(`ipcMain.handle('${channel}'`);
    assert.ok(at > 0, channel);
    assert.match(main.slice(at, at + 160), /gate\.runChange\(/, channel);
  }
  assert.match(main, /ipcMain\.handle\('run-scan', \(e, profile\) => gate\.runScan\(/);
  // A re-check waits for the scan like a change, with its own plain refusal.
  assert.match(main, /recheckRefusal\(\)\)\);/);
  // Quitting mid-scan stops the engine (SIGTERM, so it stops its commands too).
  assert.match(main, /app\.on\('before-quit', \(\) => stopRunningScans\(\)\)/);
  const pkg = require('../package.json');
  assert.ok(pkg.build.files.includes('scan-gate.js'));
});

test('the window hears about the wait, and the fix and mark cards word the refusal plainly, once', async () => {
  const gate = createScanGate();
  const change = later();
  const changing = gate.runChange(() => change.p, null);
  let waited = 0;
  const scanning = gate.runScan(() => 'doc', () => { waited += 1; });
  assert.strictEqual(waited, 1);
  change.resolve(); await changing; await scanning;
  await gate.runScan(() => 'doc', () => { waited += 1; });
  assert.strictEqual(waited, 1, 'no wait, no message');
  assert.match(fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8'), /send\('scan-event', \{ type: 'wait'/);

  const FixFlow = require('../renderer/fix-flow.js');
  const MarkFlow = require('../renderer/mark-flow.js');
  const f = FixFlow.describeFixResult(fixRefusal('x'));
  assert.strictEqual(f.headline, 'The checkup is still running.');
  assert.doesNotMatch(f.headline + f.detail, /didn’t go through|Run the checkup again/);
  const m = MarkFlow.describeMarkResult(markRefusal());
  assert.strictEqual(m.headline, 'The checkup is still running.');
  for (const d of [f, m]) assert.strictEqual(d.detail.match(/Nothing was changed\./g).length, 1);
  // Any refusal that already says it doesn't get it twice.
  const other = MarkFlow.describeMarkResult({ status: 'refused', error: 'not_allowed', message: 'This item can’t be marked from the app. Nothing was changed.' });
  assert.strictEqual(other.detail.match(/Nothing was changed\./g).length, 1);
  assert.match(MarkFlow.describeMarkResult({ status: 'refused', message: 'No.' }).detail, /^No\. Nothing was changed\.$/);
});


test('a re-check asked for while a scan runs is refused plainly, and starts nothing', async () => {
  const { recheckRefusal } = require('../scan-gate.js');
  const gate = createScanGate();
  const scan = later();
  const scanning = gate.runScan(() => scan.p);
  let ran = 0;
  const r = await gate.runChange(() => { ran += 1; return { ok: true }; }, recheckRefusal());
  assert.strictEqual(ran, 0);
  assert.deepStrictEqual([r.ok, r.error], [false, 'scan_running']);
  assert.match(r.message, /Nothing was changed\./);
  assert.doesNotMatch(r.message, /minute|second|hour|soon/i);
  scan.resolve('doc'); await scanning;
});
