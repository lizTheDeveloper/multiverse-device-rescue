const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { createFixPolicy, handleRunFix, isValidFixModuleName } = require('../fix-policy');
const { fixArgs, runFix } = require('../engine-runner');

const FIXABLE = { will_change: 'Turns on the firewall.', how_to_undo: ['Open Settings.'] };
const doc = (mods) => ({ modules: mods });

test('only module names made of lowercase letters, digits and underscores are valid', () => {
  assert.ok(isValidFixModuleName('firewall_audit'));
  assert.ok(!isValidFixModuleName('../etc/passwd'));
  assert.ok(!isValidFixModuleName('a b'));
  assert.ok(!isValidFixModuleName('--help'));
  assert.ok(!isValidFixModuleName(''));
  assert.ok(!isValidFixModuleName(null));
  assert.ok(!isValidFixModuleName({ toString: () => 'firewall_audit' }));
});

test('nothing is allowed before a scan has been seen', () => {
  assert.strictEqual(createFixPolicy().isAllowed('firewall_audit'), false);
});

test('a module is allowed only if a finding in the last scan carried a fixable block', () => {
  const policy = createFixPolicy();
  policy.remember(doc([
    { name: 'firewall_audit', findings: [{ title: 'x', fixable: FIXABLE }] },
    { name: 'disk_space', findings: [{ title: 'y' }] },
    { name: 'empty', findings: [] },
  ]));
  assert.strictEqual(policy.isAllowed('firewall_audit'), true);
  assert.strictEqual(policy.isAllowed('disk_space'), false);
  assert.strictEqual(policy.isAllowed('empty'), false);
  assert.strictEqual(policy.isAllowed('never_scanned'), false);
});

test('a malformed fixable block does not count', () => {
  const policy = createFixPolicy();
  policy.remember(doc([
    { name: 'a', findings: [{ fixable: {} }] },
    { name: 'b', findings: [{ fixable: 'yes' }] },
    { name: 'c', findings: [{ fixable: true }] },
    { name: 'd', findings: [{ fixable: { will_change: 'x', how_to_undo: [] } }] },
  ]));
  for (const n of ['a', 'b', 'c', 'd']) assert.strictEqual(policy.isAllowed(n), false, n);
});

test('a new scan replaces the previous allowance', () => {
  const policy = createFixPolicy();
  policy.remember(doc([{ name: 'firewall_audit', findings: [{ fixable: FIXABLE }] }]));
  policy.remember(doc([{ name: 'firewall_audit', findings: [] }]));
  assert.strictEqual(policy.isAllowed('firewall_audit'), false);
});

test('remember tolerates junk input', () => {
  const policy = createFixPolicy();
  for (const junk of [null, undefined, 3, 'x', {}, { modules: 'no' }, { modules: [null, 4] }]) {
    assert.doesNotThrow(() => policy.remember(junk));
  }
  assert.strictEqual(policy.isAllowed('anything'), false);
});

test('handleRunFix refuses an unlisted module without starting the engine', async () => {
  let started = 0;
  const policy = createFixPolicy();
  const res = await handleRunFix('firewall_audit', { policy, runFix: async () => { started++; return {}; } });
  assert.strictEqual(started, 0);
  assert.strictEqual(res.applied, false);
  assert.strictEqual(res.error, 'not_allowed');
});

test('handleRunFix refuses a badly shaped name even if somehow listed', async () => {
  let started = 0;
  const policy = { isAllowed: () => true };
  for (const bad of ['../x', '--yes', 'a;b', 42, null, undefined, ['firewall_audit']]) {
    const res = await handleRunFix(bad, { policy, runFix: async () => { started++; return {}; } });
    assert.strictEqual(res.error, 'not_allowed');
  }
  assert.strictEqual(started, 0);
});

test('handleRunFix runs exactly the allowed module and returns the engine result', async () => {
  const policy = createFixPolicy();
  policy.remember(doc([{ name: 'firewall_audit', findings: [{ fixable: FIXABLE }] }]));
  const calls = [];
  const engine = { module: 'firewall_audit', applied: true, verified: true, status: 'fixed' };
  const res = await handleRunFix('firewall_audit', { policy, runFix: async (n) => { calls.push(n); return engine; } });
  assert.deepStrictEqual(calls, ['firewall_audit']);
  assert.deepStrictEqual(res, engine);
});

test('handleRunFix turns a crash into a plain error object, never a throw', async () => {
  const policy = createFixPolicy();
  policy.remember(doc([{ name: 'firewall_audit', findings: [{ fixable: FIXABLE }] }]));
  const res = await handleRunFix('firewall_audit', { policy, runFix: async () => { throw new Error('spawn ENOENT'); } });
  assert.strictEqual(res.applied, false);
  assert.strictEqual(res.error, 'engine_error');
  assert.match(res.message, /spawn ENOENT/);
});

test('fixArgs always passes the acknowledgement flag and rejects bad names', () => {
  assert.deepStrictEqual(fixArgs('firewall_audit'), ['fix', 'firewall_audit', '--json', '--i-understand']);
  assert.throws(() => fixArgs('../x'));
  assert.throws(() => fixArgs('--yes'));
  assert.throws(() => fixArgs(undefined));
});

function fakeSpawn({ stdout = '', stderr = '', code = 0, hang = false }) {
  const calls = [];
  const fn = (bin, args) => {
    calls.push({ bin, args });
    const p = new EventEmitter();
    p.stdout = new EventEmitter();
    p.stderr = new EventEmitter();
    p.killed = false;
    p.kill = () => { p.killed = true; p.emit('close', null); };
    if (!hang) setImmediate(() => {
      if (stdout) p.stdout.emit('data', stdout);
      if (stderr) p.stderr.emit('data', stderr);
      p.emit('close', code);
    });
    return p;
  };
  fn.calls = calls;
  return fn;
}

test('runFix parses the engine JSON even when the engine exits non-zero', async () => {
  const body = { module: 'm', applied: false, error: 'not_allowed', message: 'no' };
  const spawn = fakeSpawn({ stdout: JSON.stringify(body), code: 2 });
  const res = await runFix('m', spawn);
  assert.deepStrictEqual(res, body);
  assert.deepStrictEqual(spawn.calls[0].args, ['fix', 'm', '--json', '--i-understand']);
});

test('runFix reports garbage output as an error object', async () => {
  const res = await runFix('m', fakeSpawn({ stdout: 'boom', stderr: 'trace', code: 1 }));
  assert.strictEqual(res.applied, false);
  assert.strictEqual(res.error, 'engine_error');
});

test('runFix gives up on a hung engine', async () => {
  const spawn = fakeSpawn({ hang: true });
  const res = await runFix('m', spawn, 20);
  assert.strictEqual(res.applied, false);
  assert.strictEqual(res.error, 'timeout');
});
