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
  assert.match(timedOut.message, /couldn’t check again just now/);
  // A fix may already have been made: never "Nothing was changed".
  assert.doesNotMatch(timedOut.message, /Nothing was changed/);
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
  // Exit 1 with no document, after one check reported: what it found is kept.
  const stoppedEvents = [];
  const stopped = await runScan(fake(1, ''), null, (ev) => stoppedEvents.push(ev));
  assert.deepStrictEqual(stopped.modules, [entry]);
  assert.strictEqual(stopped.stopped.reason, 'exit');
  assert.strictEqual(stopped.stopped.exit_code, 1);
  assert.strictEqual(stoppedEvents.at(-1).type, 'stopped');
});

test('runScan: an engine that stops leaves what it found; tracebacks never reach an error message', async () => {
  const { EventEmitter } = require('events');
  const { runScan, SCAN_STOPPED_MESSAGE, isStoppedDoc } = require('../engine-runner');
  const entry = (name) => ({ name, check_name: name, category: 'security', status: 'ok', error: null, supported: true, complete: true, error_kind: null, findings: [{ title: `t ${name}`, severity: 'warning' }] });
  const traceback = 'Traceback (most recent call last):\n  File "/Users/someone/src/rescue/serialize.py", line 109\nTypeError: unhashable type: \'dict\'';
  const fake = ({ code, stdout = '', modules = [], plan = null }) => () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter();
    setImmediate(() => {
      if (plan) p.stderr.emit('data', JSON.stringify({ plan }) + '\n');
      for (const m of modules) p.stderr.emit('data', JSON.stringify({ module: m }) + '\n');
      p.stderr.emit('data', traceback + '\n');
      if (stdout) p.stdout.emit('data', stdout);
      p.emit('close', code);
    });
    return p;
  };
  const plan = { total: 3, modules: ['a_check', 'b_check', 'c_check'].map((m) => ({ module: m, check_name: `Check ${m}`, category: 'security' })) };
  const events = [];
  const doc = await runScan(fake({ code: 1, modules: [entry('b_check'), entry('a_check')], plan }), null, (ev) => events.push(ev));
  assert.ok(isStoppedDoc(doc));
  assert.deepStrictEqual(doc.modules.map((m) => m.name), ['a_check', 'b_check', 'c_check'], 'in plan order');
  assert.deepStrictEqual(doc.stopped, { reason: 'exit', exit_code: 1, done: 2, total: 3 });
  const never = doc.modules[2];
  assert.strictEqual(never.status, 'error');
  assert.strictEqual(never.complete, false);
  assert.strictEqual(never.error_kind, 'stopped');
  assert.strictEqual(never.check_name, 'Check c_check');
  assert.ok(!('partial' in doc), 'stopped is not "still running"');
  assert.ok(!JSON.stringify(doc).includes('Traceback'), 'the traceback is not in the document');
  assert.ok(events.some((e) => e.type === 'log' && /Traceback/.test(e.line)), 'the traceback goes to the technical log');

  // Exit 0 but stdout cut short: the same partial document.
  const cut = await runScan(fake({ code: 0, stdout: '{"schema_version":1,"modu', modules: [entry('a_check')] }), null, () => {});
  assert.strictEqual(cut.stopped.reason, 'unreadable');
  assert.deepStrictEqual(cut.modules.map((m) => m.name), ['a_check']);

  // A whole document with a non-zero exit is still the whole document.
  const whole = await runScan(fake({ code: 2, stdout: '{"schema_version":1,"modules":[]}', modules: [entry('a_check')] }), null, () => {});
  assert.deepStrictEqual(whole, { schema_version: 1, modules: [] });

  // Nothing streamed: a plain rejection, no traceback, no home paths.
  await assert.rejects(runScan(fake({ code: 1 }), null, () => {}), (err) => {
    assert.strictEqual(err.message, SCAN_STOPPED_MESSAGE);
    assert.doesNotMatch(err.message, /Traceback|\/Users\/|engine exited/);
    return true;
  });
});

test('stopRunningScans sends SIGTERM to a running scan, and forgets finished ones', async () => {
  const { EventEmitter } = require('events');
  const { runScan, stopRunningScans } = require('../engine-runner');
  const signals = [];
  const spawned = [];
  const fake = () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter();
    p.kill = (sig) => { signals.push(sig); setImmediate(() => p.emit('close', 143)); };
    spawned.push(p);
    return p;
  };
  // A finished scan isn't signalled.
  const first = runScan(fake, null, () => {});
  spawned[0].stdout.emit('data', '{"schema_version":1,"modules":[]}');
  spawned[0].emit('close', 0);
  await first;
  const running = runScan(fake, null, () => {});
  stopRunningScans();
  assert.deepStrictEqual(signals, ['SIGTERM']);
  await assert.rejects(running, /The checkup stopped before it finished/);
  stopRunningScans();
  assert.deepStrictEqual(signals, ['SIGTERM'], 'nothing left to stop');
});

// The commands each check ran, kept per check for the Evidence block.
const { createExecLog, EXEC_LIMITS } = require('../engine-runner');

test('exec log: per check, repeats counted, copies handed out, reset per scan', () => {
  const log = createExecLog();
  const ev = (module, argv, extra = {}) => ({ type: 'exec', module, argv, returncode: 0, seconds: 0.1, ...extra });
  assert.strictEqual(log.add(ev('code_signature_audit', ['codesign', '--verify', '/Applications/A.app'])), true);
  log.add(ev('code_signature_audit', ['codesign', '--verify', '/Applications/A.app']));
  log.add(ev('code_signature_audit', ['codesign', '-dv', '/Applications/A.app'], { returncode: 1 }));
  log.add(ev('launch_agent_audit', ['plutil', '-p', 'x.plist']));
  const got = log.get('code_signature_audit');
  assert.deepStrictEqual(got, [
    { argv: ['codesign', '--verify', '/Applications/A.app'], returncode: 0, seconds: 0.1, times: 2 },
    { argv: ['codesign', '-dv', '/Applications/A.app'], returncode: 1, seconds: 0.1, times: 1 },
  ]);
  got[0].argv.push('changed');
  assert.strictEqual(log.get('code_signature_audit')[0].argv.length, 3, 'a copy');
  assert.strictEqual(log.get('launch_agent_audit').length, 1);
  assert.deepStrictEqual(log.get('nope'), []);
  log.reset();
  assert.deepStrictEqual(log.get('code_signature_audit'), []);
});

test('exec log: refuses odd events and stays bounded', () => {
  const log = createExecLog();
  for (const bad of [null, {}, { type: 'progress', module: 'x', argv: ['a'] }, { type: 'exec', module: null, argv: ['a'] },
    { type: 'exec', module: '../x', argv: ['a'] }, { type: 'exec', module: 'x', argv: [] }, { type: 'exec', module: 'x', argv: 'ls' }]) {
    assert.strictEqual(log.add(bad), false, JSON.stringify(bad));
  }
  for (let i = 0; i < 50; i += 1) log.add({ type: 'exec', module: 'busy', argv: ['cmd', String(i)] });
  assert.strictEqual(log.get('busy').length, EXEC_LIMITS.perModule);
  log.add({ type: 'exec', module: 'long', argv: [...Array(100).keys()].map((i) => 'x'.repeat(1000 + i)) });
  const [c] = log.get('long');
  assert.strictEqual(c.argv.length, EXEC_LIMITS.argv);
  assert.ok(c.argv.every((a) => a.length === EXEC_LIMITS.arg));
  const small = createExecLog({ modules: 2, perModule: 1, argv: 2, arg: 5 });
  for (const m of ['a', 'b', 'c']) small.add({ type: 'exec', module: m, argv: ['ls'] });
  assert.deepStrictEqual(small.get('c'), []);
  assert.deepStrictEqual(log.get(42), []);
});

test('main keeps the exec lines per check and the window can ask for one check', () => {
  const fs = require('fs');
  const path = require('path');
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8');
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  assert.match(main, /execLog\.reset\(\);\s*const doc = await runScan/);
  assert.match(main, /if \(ev\.type === 'exec'\) execLog\.add\(ev\);/);
  // A stopped checkup is shown, never acted on.
  assert.match(main, /fixPolicy\.remember\(isStoppedDoc\(doc\) \? null : doc\)/);
  assert.match(main, /markPolicy\.remember\(isStoppedDoc\(doc\) \? null : doc\)/);
  assert.match(main, /ipcMain\.handle\('module-commands', \(_e, name\) => execLog\.get\(name\)\)/);
  assert.match(preload, /moduleCommands: \(name\) => ipcRenderer\.invoke\('module-commands', name\)/);
});
