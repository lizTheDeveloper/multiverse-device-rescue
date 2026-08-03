const path = require('path');
const { spawn } = require('child_process');

function resolveEnginePath() {
  const bin = process.platform === 'win32' ? 'rescue.exe' : 'rescue';
  // Packaged: process.resourcesPath/engine/<bin>; dev: ./engine/<bin>
  const base = process.resourcesPath && require('fs').existsSync(path.join(process.resourcesPath, 'engine'))
    ? path.join(process.resourcesPath, 'engine')
    : path.join(__dirname, 'engine');
  return path.join(base, bin);
}
function parseEngineOutput(stdout) { return JSON.parse(stdout); }
function runScan(spawnFn = spawn) {
  return new Promise((resolve, reject) => {
    const p = spawnFn(resolveEnginePath(), ['scan', '--json']);
    let out = '', err = '';
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => (err += d));
    p.on('error', reject);
    p.on('close', code => {
      if (code !== 0) return reject(new Error(`engine exited ${code}: ${err}`));
      try { resolve(parseEngineOutput(out)); } catch (e) { reject(e); }
    });
  });
}
module.exports = { resolveEnginePath, parseEngineOutput, runScan };
