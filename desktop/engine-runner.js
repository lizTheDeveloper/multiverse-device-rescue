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

function scanArgs(profile) {
  const args = ['scan', '--json'];
  if (profile == null) return args;
  if (typeof profile !== 'string' || !PROFILE_NAME.test(profile)) {
    throw new Error(`invalid profile name: ${profile}`);
  }
  return args.concat(['--profile', profile]);
}

// With --trace, stderr carries one {"progress": {...}} JSON line per check,
// one {"exec": {...}} line per external command, and ordinary log lines.
// Each complete line becomes an event for the window.
function parseStderrLine(line) {
  for (const type of ['progress', 'exec']) {
    if (line.startsWith(`{"${type}"`)) {
      try {
        return { type, ...JSON.parse(line)[type] };
      } catch (_) {
        // fall through: show it as a log line rather than lose it
      }
    }
  }
  return { type: 'log', line };
}

function runScan(spawnFn = spawn, profile = null, onEvent = () => {}) {
  return new Promise((resolve, reject) => {
    const p = spawnFn(resolveEnginePath(), scanArgs(profile).concat(['--trace']));
    let out = '', err = '', pending = '';
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => {
      err += d;
      pending += d;
      const lines = pending.split(/\r?\n/);
      pending = lines.pop();
      for (const line of lines) if (line.trim()) onEvent(parseStderrLine(line));
    });
    p.on('error', reject);
    p.on('close', code => {
      if (pending.trim()) onEvent(parseStderrLine(pending));
      if (code !== 0) return reject(new Error(`engine exited ${code}: ${err.split('\n').filter(l => !l.startsWith('{"progress"') && !l.startsWith('{"exec"')).join('\n')}`));
      try { resolve(parseEngineOutput(out)); } catch (e) { reject(e); }
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

function runEngineJson(buildArgs, moduleName, spawnFn, timeoutMs) {
  return new Promise((resolve) => {
    let p;
    try {
      p = spawnFn(resolveEnginePath(), buildArgs());
    } catch (e) {
      return resolve(failure(moduleName, 'engine_error', e.message));
    }
    let out = '', err = '', finished = false;
    const finish = (value) => { if (!finished) { finished = true; clearTimeout(timer); resolve(value); } };
    const timer = setTimeout(() => {
      // Answer first: killing the process makes 'close' fire, which must not win.
      const timedOut = failure(moduleName, 'timeout', 'The fix took too long, so we stopped waiting. Run the checkup again to see where things stand.');
      finish(timedOut);
      try { p.kill(); } catch (_) { /* already gone */ }
    }, timeoutMs);
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => (err += d));
    p.on('error', e => finish(failure(moduleName, 'engine_error', e.message)));
    p.on('close', code => {
      try {
        finish(parseEngineOutput(out));
      } catch (_) {
        const tail = err.trim().split('\n').slice(-3).join(' ');
        finish(failure(moduleName, 'engine_error', `The checkup engine gave an unexpected answer (exit ${code}). ${tail}`.trim()));
      }
    });
  });
}

module.exports = { resolveEnginePath, parseEngineOutput, runScan, scanArgs, parseStderrLine, fixArgs, runFix, actionArgs, undoArgs, runAction, runUndo };
