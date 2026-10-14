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
module.exports = { resolveEnginePath, parseEngineOutput, runScan, scanArgs, parseStderrLine };
