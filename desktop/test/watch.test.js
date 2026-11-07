const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { WATCH_MINUTES, handleWatch, stopActiveWatch, quitActiveWatch, SCAN_BUSY_MESSAGE, STOP_GRACE_MS,
  QUIT_GRACE_MS } = require('../watch');
const { runWatch } = require('../engine-runner');
const { MONITORING_MODULES } = require('../mark-policy');

const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

const mod = (name, findings = []) => ({ name, category: 'network', status: 'ok', supported: true, findings });
const LAST = { schema_version: 1, platform: 'darwin', modules: [mod('a_mod', [{ title: 'a', severity: 'info' }]), mod('b_mod')] };
const watchFinding = { title: 'Talks to example.com', severity: 'info', code: 'network.connection_watch.destinations' };
const WATCH_DOC = { schema_version: 1, platform: 'darwin', modules: [mod('connection_watch', [watchFinding])] };

function deps(over = {}) {
  let last = LAST;
  const remembered = [];
  const ran = [];
  return {
    remembered,
    ran,
    get last() { return last; },
    d: {
      getLastDoc: () => last,
      setLastDoc: (d) => { last = d; },
      runWatch: async (minutes, onEvent) => { ran.push(minutes); onEvent({ progress: { phase: 'watch' } }); return WATCH_DOC; },
      policies: [{ remember: (d) => remembered.push(['fix', d]) }, { remember: (d) => remembered.push(['mark', d]) }],
      isBusy: () => false,
      onEvent: () => {},
      ...over,
    },
  };
}

test('only the listed durations are accepted', async () => {
  assert.deepStrictEqual(WATCH_MINUTES, [1, 2, 5, 10, 15, 30]);
  for (const bad of [0, 3, 31, -1, 1.5, '5', null, undefined, NaN, [5], { minutes: 5 }]) {
    const t = deps();
    const r = await handleWatch(bad, t.d);
    assert.strictEqual(r.ok, false, JSON.stringify(bad));
    assert.strictEqual(r.reason, 'bad_minutes');
    assert.strictEqual(t.ran.length, 0);
  }
  for (const m of WATCH_MINUTES) {
    const t = deps();
    assert.strictEqual((await handleWatch(m, t.d)).ok, true, String(m));
    assert.deepStrictEqual(t.ran, [m]);
  }
});

test('lookups: on unless false; anything but a boolean is refused before the watch starts', async () => {
  const seen = [];
  const run = async (minutes, onEvent, lookups) => { seen.push(lookups); return WATCH_DOC; };
  assert.strictEqual((await handleWatch(5, { ...deps({ runWatch: run }).d })).ok, true);
  assert.strictEqual((await handleWatch(5, { ...deps({ runWatch: run }).d, lookups: true })).ok, true);
  assert.strictEqual((await handleWatch(5, { ...deps({ runWatch: run }).d, lookups: false })).ok, true);
  assert.deepStrictEqual(seen, [true, true, false]);
  for (const bad of ['false', 0, 1, null, 'yes', [], {}, NaN]) {
    const t = deps({ runWatch: run });
    const r = await handleWatch(5, { ...t.d, lookups: bad });
    assert.strictEqual(r.ok, false, JSON.stringify(bad));
    assert.strictEqual(r.reason, 'bad_lookups');
  }
  assert.strictEqual(seen.length, 3, 'a refused flag starts nothing');
});

test('no scan, no watch', async () => {
  for (const last of [null, {}, { modules: 'x' }]) {
    const t = deps({ getLastDoc: () => last });
    const r = await handleWatch(5, t.d);
    assert.deepStrictEqual(r, { ok: false, reason: 'no_scan', message: 'Run the checkup first.' });
    assert.strictEqual(t.ran.length, 0);
  }
});

test('refused while the checkup has found possible monitoring software', async () => {
  for (const name of MONITORING_MODULES) {
    for (const severity of ['critical', 'warning']) {
      const last = { modules: [...LAST.modules, mod(name, [{ title: 'x', severity }])] };
      const t = deps({ getLastDoc: () => last });
      const r = await handleWatch(5, t.d);
      assert.deepStrictEqual(r, {
        ok: false, reason: 'monitoring',
        message: 'The connection watch is off while this checkup has found possible monitoring software.',
      });
      assert.strictEqual(t.ran.length, 0, `${name} ${severity}`);
    }
  }
});

test('an info note from a monitoring check ("no backups found") does not turn the watch off', async () => {
  const last = { modules: [...LAST.modules, mod('mvt_spyware_scan', [{ title: 'No device backups found', severity: 'info' }]), mod('stalkerware_scan')] };
  const t = deps({ getLastDoc: () => last });
  assert.strictEqual((await handleWatch(5, t.d)).ok, true);
});

test('refused while something else is running', async () => {
  const t = deps({ isBusy: () => true });
  const r = await handleWatch(5, t.d);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'busy');
  assert.ok(r.message);
  assert.strictEqual(t.ran.length, 0);
});

test('the result is merged into the checkup, and both policies re-armed', async () => {
  const events = [];
  const t = deps({ onEvent: (ev) => events.push(ev) });
  const r = await handleWatch(5, t.d);
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.doc.modules.map((m) => m.name), ['a_mod', 'b_mod', 'connection_watch']);
  assert.strictEqual(r.doc.modules[0], LAST.modules[0]);
  assert.strictEqual(t.last, r.doc);
  assert.deepStrictEqual(t.remembered, [['fix', r.doc], ['mark', r.doc]]);
  assert.deepStrictEqual(events, [{ progress: { phase: 'watch' } }], 'progress reaches onEvent');
});

test('a second watch replaces the first and keeps the other modules', async () => {
  const older = { modules: [mod('a_mod'), mod('connection_watch', [{ title: 'old' }]), mod('b_mod')] };
  const t = deps({ getLastDoc: () => older, setLastDoc: () => {} });
  const r = await handleWatch(1, t.d);
  assert.deepStrictEqual(r.doc.modules.map((m) => m.name), ['a_mod', 'connection_watch', 'b_mod']);
  assert.deepStrictEqual(r.doc.modules[1].findings, [watchFinding]);
  assert.strictEqual(older.modules[1].findings[0].title, 'old', 'input not mutated');
});

test('a re-check that lands during the watch is kept', async () => {
  const t = deps();
  const rechecked = { modules: [mod('a_mod'), mod('b_mod', [{ title: 'new b' }])] };
  t.d.runWatch = async () => { t.d.setLastDoc(rechecked); return WATCH_DOC; };
  const r = await handleWatch(5, t.d);
  assert.deepStrictEqual(r.doc.modules[1].findings, [{ title: 'new b' }]);
});

test('a watch that fails or comes back without the module changes nothing', async () => {
  for (const runWatchFn of [async () => { throw new Error('engine exited 2'); }, async () => ({ modules: [] }), async () => null]) {
    const t = deps({ runWatch: runWatchFn, logError: () => {} });
    const r = await handleWatch(5, t.d);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.reason, 'failed');
    assert.ok(r.message);
    assert.strictEqual(t.last, LAST);
    assert.deepStrictEqual(t.remembered, []);
  }
});

// A fake `rescue watch` child: records stdin writes and kills.
function fakeChild() {
  const p = new EventEmitter();
  p.stdout = new EventEmitter();
  p.stderr = new EventEmitter();
  p.stdin = new EventEmitter();
  p.written = [];
  p.killed = 0;
  p.stdin.write = (s) => { p.written.push(s); return true; };
  p.kill = () => { p.killed += 1; };
  return p;
}
const DOC_TEXT = JSON.stringify(WATCH_DOC);

test('runWatch spawns the engine read-only with the minutes and forwards progress lines', async () => {
  let child, args;
  const events = [];
  const h = runWatch(5, (ev) => events.push(ev), (_bin, a) => { args = a; child = fakeChild(); return child; });
  assert.deepStrictEqual(args, ['watch', '--minutes', '5', '--json', '--progress']);
  child.stderr.emit('data', '{"progress": {"phase": "watch", "elapsed": 1, "total": 300, "snapshots": 1}}\nsome log li');
  child.stderr.emit('data', 'ne\n{"progress": not json\n');
  child.stdout.emit('data', DOC_TEXT);
  child.emit('close', 0);
  assert.deepStrictEqual(await h.promise, WATCH_DOC);
  assert.deepStrictEqual(events, [{ progress: { phase: 'watch', elapsed: 1, total: 300, snapshots: 1 } }]);
});

test('runWatch adds --no-lookups only when lookups is false', () => {
  const argsFor = (opts) => {
    let args;
    runWatch(2, () => {}, (_bin, a) => { args = a; const c = fakeChild(); setImmediate(() => c.emit('close', 1)); return c; }, opts)
      .promise.catch(() => {});
    return args;
  };
  assert.deepStrictEqual(argsFor({ lookups: false }), ['watch', '--minutes', '2', '--json', '--progress', '--no-lookups']);
  for (const opts of [undefined, {}, { lookups: true }, { lookups: 'false' }, { lookups: 0 }]) {
    assert.deepStrictEqual(argsFor(opts), ['watch', '--minutes', '2', '--json', '--progress'], JSON.stringify(opts));
  }
});

test('main passes the checkbox’s flag through as it came; preload sends it', () => {
  const main = read('main.js');
  const handler = main.slice(main.indexOf("ipcMain.handle('run-watch'"), main.indexOf("ipcMain.handle('stop-watch'"));
  assert.match(handler, /\(e, minutes, lookups\) =>/);
  assert.match(handler, /handleWatch\(minutes, \{\s*lookups,/);
  assert.match(handler, /runWatch\(m, onEvent, undefined, \{ lookups: on \}\)/);
  assert.ok(read('preload.js').includes("runWatch: (minutes, lookups) => ipcRenderer.invoke('run-watch', minutes, lookups)"));
});

test('runWatch stop() writes "stop\\n" to stdin and still resolves with the document', async () => {
  let child;
  const h = runWatch(10, () => {}, () => (child = fakeChild()));
  h.stop();
  assert.deepStrictEqual(child.written, ['stop\n']);
  child.stdout.emit('data', DOC_TEXT);
  child.emit('close', 0);
  assert.deepStrictEqual(await h.promise, WATCH_DOC);
  h.stop();
  assert.deepStrictEqual(child.written, ['stop\n'], 'nothing written after it exited');
});

test('runWatch rejects on a bad exit, garbage, a spawn error or bad minutes', async () => {
  let child;
  let h = runWatch(1, () => {}, () => (child = fakeChild()));
  child.stdout.emit('data', 'not json');
  child.emit('close', 0);
  await assert.rejects(h.promise);
  h = runWatch(1, () => {}, () => (child = fakeChild()));
  child.emit('error', new Error('ENOENT'));
  await assert.rejects(h.promise, /ENOENT/);
  h = runWatch(1, () => {}, () => { throw new Error('spawn failed'); });
  await assert.rejects(h.promise, /spawn failed/);
  h.stop(); // harmless
  let spawned = false;
  h = runWatch(31, () => {}, () => { spawned = true; return fakeChild(); });
  await assert.rejects(h.promise);
  assert.strictEqual(spawned, false);
});

test('runWatch timeout: asks the engine to stop, then kills it if it does not exit', async () => {
  let child;
  const h = runWatch(1, () => {}, () => (child = fakeChild()), { timeoutMs: 10, killAfterMs: 10 });
  await new Promise((r) => setTimeout(r, 15));
  assert.deepStrictEqual(child.written, ['stop\n']);
  assert.strictEqual(child.killed, 0);
  await new Promise((r) => setTimeout(r, 20));
  assert.strictEqual(child.killed, 1);
  child.emit('close', null);
  await assert.rejects(h.promise);
});

test('runWatch default timeout is the watch plus two minutes', () => {
  const src = read('engine-runner.js');
  assert.match(src, /minutes \* 60_?000 \+ 120_?000/);
});

test('a stopped watch gets 75 seconds: a snapshot already under way can take up to 30 s a command', () => {
  assert.strictEqual(STOP_GRACE_MS, 75000);
});

test('stopActiveWatch: stop, and kill only if it has not exited within the grace period', async () => {
  let child;
  let h = runWatch(5, () => {}, () => (child = fakeChild()));
  const done = stopActiveWatch(h, { graceMs: 50 });
  assert.deepStrictEqual(child.written, ['stop\n']);
  child.stdout.emit('data', DOC_TEXT);
  child.emit('close', 0);
  await done;
  assert.strictEqual(child.killed, 0, 'exited in time: not killed');

  h = runWatch(5, () => {}, () => (child = fakeChild()));
  h.promise.catch(() => {});
  await stopActiveWatch(h, { graceMs: 10 });
  assert.strictEqual(child.killed, 1, 'ignored stop: killed');
  child.emit('close', null);

  await stopActiveWatch(null); // nothing running
});

test('quitActiveWatch: on quit nobody reads the result, so stop twice and kill after 5 s', async () => {
  assert.strictEqual(QUIT_GRACE_MS, 5000);
  let child;
  let h = runWatch(5, () => {}, () => (child = fakeChild()));
  const done = quitActiveWatch(h, { graceMs: 50 });
  assert.deepStrictEqual(child.written, ['stop\n', 'stop\n'], 'the second stop ends the lookups too');
  child.stdout.emit('data', DOC_TEXT);
  child.emit('close', 0);
  await done;
  assert.strictEqual(child.killed, 0, 'exited in time: not killed');

  h = runWatch(5, () => {}, () => (child = fakeChild()));
  h.promise.catch(() => {});
  await quitActiveWatch(h, { graceMs: 10 });
  assert.strictEqual(child.killed, 1, 'still running: killed');
  child.emit('close', null);

  await quitActiveWatch(null); // nothing running
});

test('stops the watch when the app quits, and when the window goes away', () => {
  const main = read('main.js');
  const quit = main.slice(main.indexOf("app.on('before-quit'"));
  assert.ok(main.includes("app.on('before-quit'"), 'before-quit is handled');
  assert.match(quit.slice(0, 600), /quitActiveWatch\(/);
  assert.doesNotMatch(quit.slice(0, 600), /stopActiveWatch\(/);
  assert.match(quit.slice(0, 600), /preventDefault\(\)/);
  assert.match(main, /'destroyed'/);
  assert.match(main, /const onGone = \(\) => quitActiveWatch\(watch\)/, 'the window going away is a quit too');
  // Only STOP pressed in the panel gets the long grace.
  const stopHandler = main.slice(main.indexOf("ipcMain.handle('stop-watch'"), main.indexOf("ipcMain.handle('run-fix'"));
  assert.match(stopHandler, /stopActiveWatch\(activeWatch\)/);
});

test('one flag covers the checkup and the watch', () => {
  const main = read('main.js');
  const scan = main.slice(main.indexOf("ipcMain.handle('run-scan'"), main.indexOf("ipcMain.handle('run-fix'"));
  assert.match(scan, /if \(busy\) throw new Error\(SCAN_BUSY_MESSAGE\)/);
  assert.match(scan, /busy = false/);
  assert.match(main, /isBusy: \(\) => busy/);
  assert.match(main, /'watch-event'/);
  assert.match(main, /ipcMain\.handle\('stop-watch'/);
  assert.ok(SCAN_BUSY_MESSAGE.length > 10);
});

test('preload exposes the watch', () => {
  const preload = read('preload.js');
  for (const s of ["ipcRenderer.invoke('run-watch'", "ipcRenderer.invoke('stop-watch'", "ipcRenderer.on('watch-event'"]) {
    assert.ok(preload.includes(s), s);
  }
});

test('watch.js is packaged', () => {
  assert.ok(JSON.parse(read('package.json')).build.files.includes('watch.js'));
});

test('a failed watch logs the engine’s error; the person gets the plain message', async () => {
  const logged = [];
  const err = new Error('rescue exited with code 2: Traceback (most recent call last)');
  const t = deps({ runWatch: async () => { throw err; }, logError: (...a) => logged.push(a) });
  const r = await handleWatch(5, t.d);
  assert.strictEqual(r.reason, 'failed');
  assert.doesNotMatch(r.message, /Traceback|code 2/);
  assert.deepStrictEqual(logged, [['The connection watch failed:', err]]);
  // A document without the module isn't an engine error: nothing is logged.
  const quiet = [];
  await handleWatch(5, deps({ runWatch: async () => ({ modules: [] }), logError: (...a) => quiet.push(a) }).d);
  assert.deepStrictEqual(quiet, []);
});

test('main, its engine runner and the game ledger agree on the monitoring modules', () => {
  const copies = [
    ['renderer/game/ledger.js', /export const MONITORING_MODULES = new Set\(\[([^\]]*)\]\)/],
    ['engine-runner.js', /const NEVER_MARKABLE_MODULES = new Set\(\[([^\]]*)\]\)/],
  ];
  for (const [file, re] of copies) {
    const m = read(file).match(re);
    assert.ok(m, `${file} declares its monitoring list`);
    const names = [...m[1].matchAll(/'([a-z0-9_]+)'/g)].map((x) => x[1]).sort();
    assert.ok(names.length > 0, file);
    assert.deepStrictEqual([...MONITORING_MODULES].sort(), names, file);
  }
});

test('a failed watch says why in one plain line, never the engine’s stderr', async () => {
  const { whyFailed } = require('../watch');
  const enoent = Object.assign(new Error('spawn rescue ENOENT'), { code: 'ENOENT' });
  assert.match(whyFailed(enoent), /couldn’t be found/);
  assert.match(whyFailed(new SyntaxError('Unexpected token')), /couldn’t be read/);
  assert.match(whyFailed(new Error('engine exited null Traceback /Users/me/x')), /time limit/);
  assert.strictEqual(whyFailed(new Error('engine exited 2 Traceback /Users/me/x')), 'The engine stopped with an error (code 2).');
  const r = await handleWatch(5, deps({ runWatch: async () => { throw new Error('engine exited 1 /Users/me/secret'); }, logError: () => {} }).d);
  assert.strictEqual(r.why, 'The engine stopped with an error (code 1).');
  const empty = await handleWatch(5, deps({ runWatch: async () => ({ modules: [] }), logError: () => {} }).d);
  assert.match(empty.why, /no watch in it/);
});
