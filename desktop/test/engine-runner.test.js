const test = require('node:test');
const assert = require('node:assert');
const { parseEngineOutput, scanModuleArgs, runRecheck } = require('../engine-runner');

test('parseEngineOutput returns parsed JSON from stdout', () => {
  const out = JSON.stringify({ schema_version: 1, platform: 'darwin', modules: [] });
  assert.deepStrictEqual(parseEngineOutput(out).schema_version, 1);
});
test('parseEngineOutput throws on non-JSON', () => {
  assert.throws(() => parseEngineOutput('not json'));
});

test('scanModuleArgs builds a read-only single-module scan', () => {
  assert.deepStrictEqual(scanModuleArgs('launch_agent_audit'), ['scan', '--json', '--module', 'launch_agent_audit']);
  for (const bad of ['../x', 'a b', '', null, 'X']) assert.throws(() => scanModuleArgs(bad));
});

test('runRecheck resolves with the parsed scan, and with engine_error on garbage', async () => {
  const { EventEmitter } = require('events');
  const fakeSpawn = (stdout, code) => () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter(); p.kill = () => {};
    setImmediate(() => { p.stdout.emit('data', stdout); p.emit('close', code); });
    return p;
  };
  const ok = await runRecheck('a_mod', fakeSpawn('{"schema_version":1,"modules":[]}', 0));
  assert.deepStrictEqual(ok, { schema_version: 1, modules: [] });
  const bad = await runRecheck('a_mod', fakeSpawn('not json', 1));
  assert.strictEqual(bad.engine_error, 'engine_error');
  const refused = await runRecheck('../x', fakeSpawn('', 0));
  assert.strictEqual(refused.engine_error, 'engine_error');
});

test('runRecheck timeout and failures use re-check wording, not fix wording', async () => {
  const { EventEmitter } = require('events');
  let killed = false;
  const hangSpawn = () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter(); p.kill = () => { killed = true; };
    return p;
  };
  const timedOut = await runRecheck('a_mod', hangSpawn, 10);
  assert.strictEqual(timedOut.engine_error, 'timeout');
  assert.strictEqual(killed, true);
  assert.match(timedOut.message, /couldn’t re-check this just now/);
  assert.match(timedOut.message, /Nothing was changed/);
  assert.doesNotMatch(timedOut.message, /fix|checkup/i);
  const refused = await runRecheck('../x', hangSpawn, 10);
  assert.strictEqual(refused.message, timedOut.message);
});
