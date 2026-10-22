const path = require('path');
const { spawn } = require('child_process');

function resolveEnginePath() {
  // Development: point at any engine, e.g. a source checkout's .venv/bin/rescue.
  if (process.env.RESCUE_ENGINE) return process.env.RESCUE_ENGINE;
  const bin = process.platform === 'win32' ? 'rescue.exe' : 'rescue';
  // Packaged: process.resourcesPath/engine/<bin>; dev: ./engine/<bin>
  const base = process.resourcesPath && require('fs').existsSync(path.join(process.resourcesPath, 'engine'))
    ? path.join(process.resourcesPath, 'engine')
    : path.join(__dirname, 'engine');
  return path.join(base, bin);
}
function parseEngineOutput(stdout) { return JSON.parse(stdout); }
// Profile names are file stems in profiles/. Anything else is refused rather
// than passed to the engine, since the value arrives over IPC.
const PROFILE_NAME = /^[a-z0-9_]+$/;

// Several worries run the union of their profiles: one --profile each.
const MAX_PROFILES = 8;

function scanArgs(profile) {
  const args = ['scan', '--json'];
  if (profile == null) return args;
  const names = Array.isArray(profile) ? profile : [profile];
  if (names.length === 0 || names.length > MAX_PROFILES) throw new Error('invalid profile list');
  for (const name of names) {
    if (typeof name !== 'string' || !PROFILE_NAME.test(name)) {
      throw new Error(`invalid profile name: ${name}`);
    }
  }
  return args.concat(...[...new Set(names)].map((name) => ['--profile', name]));
}

// With --trace, stderr carries one {"plan": {...}} line (every check about to
// run), one {"progress": {...}} JSON line per check start and finish, one
// {"module": {...}} line per finished check (its entry of the final document,
// so results can show while the rest run), one {"exec": {...}} line per
// external command, and ordinary log lines. Each complete line becomes an
// event for the window. The final document on stdout is still the one acted on.
const EVENT_TYPES = ['progress', 'exec', 'plan', 'module'];

function parseStderrLine(line) {
  for (const type of EVENT_TYPES) {
    if (line.startsWith(`{"${type}"`)) {
      try {
        const body = JSON.parse(line)[type];
        if (body && typeof body === 'object' && !Array.isArray(body)) {
          // A finished check's entry keeps its own shape under `result`.
          return type === 'module' ? { type, result: body } : { type, ...body };
        }
      } catch (_) {
        // fall through: show it as a log line rather than lose it
      }
    }
  }
  return { type: 'log', line };
}

// The commands each check ran, from the {"exec"} trace lines, so a finding's
// Evidence block can say "checked with: codesign --verify …". Kept in memory
// only, for the last scan, and bounded: so many checks, so many distinct
// commands per check (repeats are counted, not kept), so many words per
// command, so many characters per word.
const EXEC_LIMITS = { modules: 400, perModule: 12, argv: 24, arg: 240 };
const EXEC_MODULE = /^[a-z0-9_]+$/;

function createExecLog(limits = EXEC_LIMITS) {
  let byModule = new Map();
  return {
    reset() { byModule = new Map(); },
    // One check's commands, before it is run again on its own.
    resetModule(name) { if (typeof name === 'string') byModule.delete(name); },
    add(ev) {
      if (!ev || ev.type !== 'exec' || typeof ev.module !== 'string' || !EXEC_MODULE.test(ev.module)) return false;
      if (!Array.isArray(ev.argv) || !ev.argv.length) return false;
      let list = byModule.get(ev.module);
      if (!list) {
        if (byModule.size >= limits.modules) return false;
        list = [];
        byModule.set(ev.module, list);
      }
      const argv = ev.argv.slice(0, limits.argv).map((a) => String(a).slice(0, limits.arg));
      const key = argv.join('\0');
      const seen = list.find((c) => c.key === key);
      if (seen) { seen.times += 1; return true; }
      if (list.length >= limits.perModule) return false;
      list.push({
        key, argv,
        returncode: Number.isInteger(ev.returncode) ? ev.returncode : null,
        seconds: typeof ev.seconds === 'number' ? ev.seconds : null,
        times: 1,
      });
      return true;
    },
    // Copies, so nothing the window does changes what main holds.
    get(name) {
      if (typeof name !== 'string' || !EXEC_MODULE.test(name)) return [];
      return (byModule.get(name) || []).map(({ argv, returncode, seconds, times }) => ({ argv: [...argv], returncode, seconds, times }));
    },
  };
}

// Scans still running, so quitting the app can stop them (stopRunningScans).
const runningScans = new Set();

// SIGTERM every running scan (main.js calls it on before-quit). On macOS and
// Linux the engine's SIGTERM handler stops the commands its checks started,
// then exits. On Windows kill() ends the engine outright (TerminateProcess),
// so commands it had started finish or hit their own timeouts.
function stopRunningScans(signal = 'SIGTERM') {
  for (const p of runningScans) {
    try { p.kill(signal); } catch (_) { /* already gone */ }
  }
  runningScans.clear();
}

// What the person is told when the engine stops before it writes its final
// document. The engine's own words (often a Python traceback with home-folder
// paths) went to the technical log as {type:'log'} events and are never put
// in an error message the screen could show.
const SCAN_STOPPED_MESSAGE = 'The checkup stopped before it finished. Nothing on your computer was changed.';

/**
 * The checks that did finish, as a scan document, when the engine stopped
 * before writing its own: the {"module"} entries it streamed, in the order
 * planned, plus one entry for every planned check that never reported, so
 * nothing reads as checked that wasn't. Marked `stopped` (never `partial`,
 * which means "still running"): the views say "The checkup stopped before it
 * finished", count it as not a clean bill of health, and offer no fixes or
 * marks from it (the fix and mark policies ignore it: actionableDoc).
 *
 *   stopped: { stage, reason: 'exit' | 'unreadable', exit_code, done, total }
 *   partial: { done, total, stopped: stage }   (the Plain list's partial frame)
 *
 * `stage` is 'assembly' when every planned check reported and only the final
 * report couldn't be put together ("All 196 checks ran, but the report
 * couldn't be put together"), and 'early' when some checks never ran.
 */
function stoppedDocOf(streamed, plan, info = {}) {
  const got = new Map();
  for (const m of streamed) if (m && typeof m.name === 'string') got.set(m.name, m);
  const planned = plan && Array.isArray(plan.modules) ? plan.modules : [];
  const modules = [];
  const seen = new Set();
  for (const p of planned) {
    const name = p && typeof p.module === 'string' ? p.module : null;
    if (!name || seen.has(name)) continue;
    seen.add(name);
    modules.push(got.get(name) || {
      name,
      check_name: typeof p.check_name === 'string' ? p.check_name : null,
      category: typeof p.category === 'string' ? p.category : null,
      status: 'error',
      error: 'The checkup stopped before this check ran.',
      supported: true,
      unsupported_reason: null,
      complete: false,
      error_kind: 'stopped',
      findings: [],
    });
  }
  for (const [name, m] of got) if (!seen.has(name)) modules.push(m);
  const total = Math.max(planned.length, modules.length);
  const done = got.size;
  // Without a plan we can't know what didn't run: never claim all of it did.
  const stage = planned.length > 0 && done >= total ? 'assembly' : 'early';
  return {
    schema_version: 1,
    platform: info.platform || process.platform,
    modules,
    stopped: {
      stage,
      reason: info.reason === 'unreadable' ? 'unreadable' : 'exit',
      exit_code: Number.isInteger(info.code) ? info.code : null,
      done,
      total,
    },
    partial: { done, total, stopped: stage },
  };
}

function isStoppedDoc(doc) {
  return !!(doc && doc.stopped && typeof doc.stopped === 'object');
}

function runScan(spawnFn = spawn, profile = null, onEvent = () => {}) {
  return new Promise((resolve, reject) => {
    const p = spawnFn(resolveEnginePath(), scanArgs(profile).concat(['--trace']));
    runningScans.add(p);
    // The finished checks' entries and the plan, so a stopped engine still
    // leaves the person what it found (stoppedDocOf).
    const streamed = [];
    let plan = null, out = '', pending = '';
    const take = (line) => {
      if (!line.trim()) return;
      const ev = parseStderrLine(line);
      if (ev.type === 'module' && ev.result && typeof ev.result.name === 'string') streamed.push(ev.result);
      if (ev.type === 'plan' && !plan) plan = ev;
      onEvent(ev);
    };
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => {
      pending += d;
      const lines = pending.split(/\r?\n/);
      pending = lines.pop();
      for (const line of lines) take(line);
    });
    p.on('error', (err) => { runningScans.delete(p); reject(err); });
    p.on('close', (code, signal) => {
      // Stopped by stopRunningScans (the app is quitting): nothing to show.
      const stoppedByUs = !runningScans.has(p);
      runningScans.delete(p);
      take(pending);
      pending = '';
      let doc = null;
      try { doc = parseEngineOutput(out); } catch (_) { doc = null; }
      const whole = doc && typeof doc === 'object' && Array.isArray(doc.modules);
      if (code === 0 && whole) return resolve(doc);
      // For the technical log only: how it ended. The log lines are already there.
      onEvent({ type: 'stopped', exit_code: Number.isInteger(code) ? code : null, signal: signal || null,
        document: whole ? 'written' : 'missing' });
      // A non-zero exit after a whole document was written still has every
      // check's answer in that document.
      if (whole) return resolve(doc);
      if (streamed.length && !stoppedByUs) {
        return resolve(stoppedDocOf(streamed, plan, { code, reason: code === 0 ? 'unreadable' : 'exit' }));
      }
      reject(new Error(SCAN_STOPPED_MESSAGE));
    });
  });
}
// "Fix it for me". The module name arrives over IPC, so only plain identifiers are
// passed to the engine; the acknowledgement flag is always present because the
// person has already said yes in the app by the time this runs.
const FIX_MODULE_NAME = /^[a-z0-9_]+$/;
const FIX_TIMEOUT_MS = 120000;

function fixArgs(moduleName) {
  if (typeof moduleName !== 'string' || !FIX_MODULE_NAME.test(moduleName)) {
    throw new Error(`invalid module name: ${moduleName}`);
  }
  return ['fix', moduleName, '--json', '--i-understand'];
}

function failure(moduleName, error, message) {
  return { module: moduleName, applied: false, verified: false, changes: [], how_to_undo: [], status: 'failed', error, message };
}

const ACTION_NAME = /^[a-z0-9_]+$/;
const QUARANTINE_ID = /^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;

function actionArgs(action, target) {
  if (typeof action !== 'string' || !ACTION_NAME.test(action)) throw new Error(`invalid action: ${action}`);
  if (typeof target !== 'string' || !target.startsWith('/') || target.includes('\0')) throw new Error('invalid target');
  return ['fix', '--action', action, '--target', target, '--json', '--i-understand'];
}

function undoArgs(quarantineId) {
  if (typeof quarantineId !== 'string' || !QUARANTINE_ID.test(quarantineId)) throw new Error('invalid quarantine id');
  return ['undo', '--quarantine-id', quarantineId, '--json'];
}

// Resolves with the engine's JSON result. The engine reports refusals and failures
// as JSON with a non-zero exit code, so stdout is parsed whatever the exit code.
function runFix(moduleName, spawnFn = spawn, timeoutMs = FIX_TIMEOUT_MS) {
  return runEngineJson(() => fixArgs(moduleName), moduleName, spawnFn, timeoutMs);
}

function runAction(action, target, spawnFn = spawn, timeoutMs = FIX_TIMEOUT_MS) {
  return runEngineJson(() => actionArgs(action, target), action, spawnFn, timeoutMs);
}

function runUndo(quarantineId, spawnFn = spawn, timeoutMs = FIX_TIMEOUT_MS) {
  return runEngineJson(() => undoArgs(quarantineId), 'undo', spawnFn, timeoutMs);
}

// Re-check one module after a fix: the same read-only scan, limited to it.
const RECHECK_TIMEOUT_MS = 180000;
// Said whatever came before it, so it never claims nothing changed: a fix may
// already have been made (the views say so beside it).
const RECHECK_FAILED_MESSAGE = 'We couldn’t check again just now. You can try again.';

function scanModuleArgs(moduleName) {
  if (typeof moduleName !== 'string' || !FIX_MODULE_NAME.test(moduleName)) {
    throw new Error(`invalid module name: ${moduleName}`);
  }
  return ['scan', '--json', '--module', moduleName];
}

// Resolves with the engine's scan document, or {engine_error, message}. Never rejects.
function runRecheck(moduleName, spawnFn = spawn, timeoutMs = RECHECK_TIMEOUT_MS) {
  return runEngineJson(() => scanModuleArgs(moduleName), moduleName, spawnFn, timeoutMs,
    // The engine's own wording is about fixes; a re-check gets its own, whatever went wrong.
    (error) => ({ engine_error: error, message: RECHECK_FAILED_MESSAGE }));
}

// "This is mine". The target was already checked against the last scan by the
// main process; it is checked again here because it is passed to the engine.
const MARK_ID = /^[0-9a-f]{12}$/;
const MARK_CODE = /^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$/;
// Long enough for the engine to run one check again before it saves.
const MARK_TIMEOUT_MS = 90000;

function clean(s, max = 1024) {
  return typeof s === 'string' && s.length > 0 && s.length < max && !s.includes('\0');
}

// Settings and installed items: the engine runs the check again and matches the id.
const ITEM_KINDS = new Set([
  'sharing_service', 'network_proxy', 'dns_profile', 'system_extension', 'browser_extension',
  'app_permissions', 'ssh_authorized_keys', 'ai_tooling', 'remote_tool',
]);
const NEVER_MARKABLE_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

// Lists that can be marked entry by entry, and how many entries at most
// (rescue/known_items.py ENTRY_KIND_FOR and MAX_LIST_ENTRIES).
const ENTRY_LIST_KINDS = new Set(['app_permissions', 'ssh_authorized_keys']);
const MAX_ENTRIES = 60;

// Some entries of one list: the list's own code and id, then one --item each.
function entryMarkArgs(t) {
  if (!ENTRY_LIST_KINDS.has(t.kind)) throw new Error('not a list');
  if (typeof t.code !== 'string' || !MARK_CODE.test(t.code)) throw new Error('invalid code');
  if (NEVER_MARKABLE_MODULES.has(t.code.split('.')[1])) throw new Error('not markable');
  if (typeof t.id !== 'string' || !MARK_ID.test(t.id)) throw new Error('invalid id');
  const chosen = Array.isArray(t.chosen) ? t.chosen : [];
  if (!chosen.length || chosen.length > MAX_ENTRIES) throw new Error('invalid items');
  if (new Set(chosen).size !== chosen.length) throw new Error('invalid items');
  if (!chosen.every((x) => typeof x === 'string' && MARK_ID.test(x)) || chosen.includes(t.id)) throw new Error('invalid items');
  // The person confirmed in the app. The engine runs the check again and
  // saves none of them unless every entry is still there, unchanged.
  return ['known', 'add', '--code', t.code, '--expect-id', t.id,
    ...chosen.flatMap((x) => ['--item', x]), '--json', '--i-understand'];
}

function markArgs(target) {
  const t = target || {};
  if (t.chosen !== undefined) return entryMarkArgs(t);
  const item = ITEM_KINDS.has(t.kind);
  if (!item) {
    if (t.kind !== 'background_task') throw new Error('invalid kind');
    if (!clean(t.label, 256) || t.label.startsWith('-')) throw new Error('invalid label');
    if (!clean(t.program) || !(t.program.startsWith('/') || t.program.startsWith('~'))) throw new Error('invalid program');
    if (!clean(t.plist) || !t.plist.startsWith('/')) throw new Error('invalid plist');
  }
  const marks = Array.isArray(t.marks) && t.marks.length ? t.marks : [{ code: t.code, id: t.id }];
  if (!marks.some((m) => m && m.id === t.id)) throw new Error('invalid marks');
  const codes = new Set();
  const ids = new Set();
  const pairs = [];
  for (const m of marks) {
    if (!m || typeof m.code !== 'string' || !MARK_CODE.test(m.code)) throw new Error('invalid code');
    if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) throw new Error('invalid id');
    if (codes.has(m.code) || ids.has(m.id)) throw new Error('duplicate mark');
    if (NEVER_MARKABLE_MODULES.has(m.code.split('.')[1])) throw new Error('not markable');
    codes.add(m.code);
    ids.add(m.id);
    pairs.push('--code', m.code, '--expect-id', m.id);
  }
  // The person has already confirmed in the app, hence --i-understand. The
  // engine re-reads the task (or runs the check again) and refuses all of
  // them unless each code still hashes to its --expect-id.
  if (item) return ['known', 'add', ...pairs, '--json', '--i-understand'];
  return ['known', 'add', ...pairs, '--label', t.label, '--program', t.program,
    '--plist', t.plist, '--json', '--i-understand'];
}

function unmarkArgs(ids) {
  const list = Array.isArray(ids) ? ids : [ids];
  if (list.length === 0 || !list.every((id) => typeof id === 'string' && MARK_ID.test(id))) throw new Error('invalid id');
  return ['known', 'remove', ...new Set(list), '--json'];
}

function markFailure(error, message) {
  const said = error === 'timeout' ? 'That took too long, so we stopped waiting. Run the checkup again to see where things stand.' : message;
  return { status: 'failed', error, message: said, id: null, label: null, how_to_undo: [] };
}

function runMark(target, spawnFn = spawn, timeoutMs = MARK_TIMEOUT_MS) {
  return runEngineJson(() => markArgs(target), 'known', spawnFn, timeoutMs, markFailure);
}

function runUnmark(id, spawnFn = spawn, timeoutMs = MARK_TIMEOUT_MS) {
  return runEngineJson(() => unmarkArgs(id), 'known', spawnFn, timeoutMs, markFailure);
}

function runEngineJson(buildArgs, moduleName, spawnFn, timeoutMs, fail = (error, message) => failure(moduleName, error, message)) {
  return new Promise((resolve) => {
    let p;
    try {
      p = spawnFn(resolveEnginePath(), buildArgs());
    } catch (e) {
      return resolve(fail('engine_error', e.message));
    }
    let out = '', err = '', finished = false;
    const finish = (value) => { if (!finished) { finished = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => {
      // Answer first: killing the process makes 'close' fire, which must not win.
      const timedOut = fail('timeout', 'The fix took too long, so we stopped waiting. Run the checkup again to see where things stand.');
      finish(timedOut);
      try { p.kill(); } catch (_) { /* already gone */ }
    }, timeoutMs);
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => (err += d));
    p.on('error', e => finish(fail('engine_error', e.message)));
    p.on('close', code => {
      try {
        finish(parseEngineOutput(out));
      } catch (_) {
        const tail = err.trim().split('\n').slice(-3).join(' ');
        finish(fail('engine_error', `The checkup engine gave an unexpected answer (exit ${code}). ${tail}`.trim()));
      }
    });
  });
}

module.exports = { createExecLog, EXEC_LIMITS, resolveEnginePath, parseEngineOutput, runScan, stoppedDocOf, isStoppedDoc, SCAN_STOPPED_MESSAGE, RECHECK_FAILED_MESSAGE, stopRunningScans, scanArgs, parseStderrLine, fixArgs, runFix, actionArgs, undoArgs, runAction, runUndo, scanModuleArgs, runRecheck, markArgs, unmarkArgs, runMark, runUnmark };
