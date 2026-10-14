const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SITUATIONS } = require('../renderer/app.js');
const { scanArgs } = require('../engine-runner');
const { isAllowedGuideUrl, GUIDE_URL_PREFIX } = require('../setting-urls');

const repo = path.join(__dirname, '..', '..');

test('every situation runs a profile that exists', () => {
  for (const s of SITUATIONS) {
    if (s.profile === null) continue; // "check everything"
    assert.ok(fs.existsSync(path.join(repo, 'profiles', `${s.profile}.yaml`)), s.profile);
  }
});

test('every situation guide is an allowed link to a page that exists', () => {
  for (const s of SITUATIONS) {
    assert.ok(isAllowedGuideUrl(s.guide), s.guide);
    const rel = s.guide.slice(GUIDE_URL_PREFIX.length).replace(/^docs\//, '');
    const base = rel.replace(/\/$/, '');
    const candidates = [`${base}.md`, path.join(base, 'index.md')];
    assert.ok(candidates.some((c) => fs.existsSync(path.join(repo, 'docs', c))), `docs/${base} for ${s.id}`);
  }
});

test('scanArgs passes a profile through and refuses anything else', () => {
  assert.deepStrictEqual(scanArgs(null), ['scan', '--json']);
  assert.deepStrictEqual(scanArgs('digital_security_reset'),
    ['scan', '--json', '--profile', 'digital_security_reset']);
  assert.throws(() => scanArgs('--yes'));
  assert.throws(() => scanArgs('../x'));
});

test('guide links are limited to the project site', () => {
  assert.ok(!isAllowedGuideUrl('https://evil.example/'));
  assert.ok(!isAllowedGuideUrl('file:///etc/passwd'));
});

test('progress reads as words and a percentage', () => {
  const { describeProgress } = require('../renderer/app.js');
  const start = describeProgress({ phase: 'start', index: 23, total: 120,
    module: 'launch_agent_audit', category: 'security' });
  assert.strictEqual(start.headline, 'Looking for security problems');
  assert.strictEqual(start.detail, 'Launch agent audit · check 23 of 120');
  assert.strictEqual(start.percent, 18);
  assert.strictEqual(describeProgress({ phase: 'done', index: 120, total: 120,
    module: 'x', category: 'odd' }).percent, 100);
});

test('stderr lines split into progress events and log lines', () => {
  const { parseStderrLine } = require('../engine-runner');
  assert.deepStrictEqual(parseStderrLine('{"progress": {"phase": "start", "index": 1}}'),
    { type: 'progress', phase: 'start', index: 1 });
  assert.deepStrictEqual(parseStderrLine('Module check timed out: x'),
    { type: 'log', line: 'Module check timed out: x' });
});

test('traced commands render like a shell line', () => {
  const { formatExec } = require('../renderer/app.js');
  assert.strictEqual(formatExec({ argv: ['launchctl', 'list'], returncode: 0, seconds: 0.04 }),
    '    $ launchctl list   (exit 0, 0.04s)');
  assert.strictEqual(formatExec({ argv: ['ls', 'a b'], returncode: null, seconds: 0, error: 'nope' }),
    "    $ ls 'a b'   (did not start: nope, 0s)");
  const { parseStderrLine } = require('../engine-runner');
  assert.strictEqual(parseStderrLine('{"exec": {"argv": ["x"]}}').type, 'exec');
});
