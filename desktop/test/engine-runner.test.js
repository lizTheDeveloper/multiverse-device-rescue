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

test('runScan streams plan and finished-check entries as events, and keeps them out of the error text', async () => {
  const { EventEmitter } = require('events');
  const { runScan, parseStderrLine } = require('../engine-runner');
  const entry = { name: 'disk_space', category: 'performance', status: 'ok', error: null, supported: true, findings: [{ title: 'x' }] };
  assert.deepStrictEqual(parseStderrLine(JSON.stringify({ module: entry })), { type: 'module', result: entry });
  assert.deepStrictEqual(parseStderrLine('{"plan": {"total": 2, "modules": []}}'), { type: 'plan', total: 2, modules: [] });
  assert.strictEqual(parseStderrLine('{"module": [1]}').type, 'log', 'not an entry: a log line');

  const fake = (code, stdout) => () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter();
    setImmediate(() => {
      const line = JSON.stringify({ module: entry });
      // Split mid-line: the runner joins chunks before it parses.
      p.stderr.emit('data', '{"plan": {"total": 1, "modules": []}}\n' + line.slice(0, 10));
      p.stderr.emit('data', line.slice(10) + '\nModule check timed out: x\n');
      if (stdout) p.stdout.emit('data', stdout);
      p.emit('close', code);
    });
    return p;
  };
  const events = [];
  const doc = await runScan(fake(0, '{"schema_version":1,"modules":[]}'), null, (ev) => events.push(ev));
  assert.deepStrictEqual(doc, { schema_version: 1, modules: [] });
  assert.deepStrictEqual(events.map((e) => e.type), ['plan', 'module', 'log']);
  assert.deepStrictEqual(events[1].result, entry);
  await assert.rejects(runScan(fake(1, ''), null, () => {}), (err) => {
    assert.match(err.message, /engine exited 1: Module check timed out: x/);
    assert.doesNotMatch(err.message, /"module"|"plan"|disk_space/);
    return true;
  });
});
