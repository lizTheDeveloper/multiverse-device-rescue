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
  for (const channel of ['run-fix', 'run-fix-action', 'undo-fix', 'mark-mine', 'unmark-mine']) {
    const at = main.indexOf(`ipcMain.handle('${channel}'`);
    assert.ok(at > 0, channel);
    assert.match(main.slice(at, at + 160), /gate\.runChange\(/, channel);
  }
  assert.match(main, /ipcMain\.handle\('run-scan', \(e, profile\) => gate\.runScan\(/);
  const pkg = require('../package.json');
  assert.ok(pkg.build.files.includes('scan-gate.js'));
});
