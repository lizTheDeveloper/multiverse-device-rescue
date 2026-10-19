// One rule for filling a walkthrough's placeholders (renderer/step-fill.js),
// used by the Plain list (app.js) and the game (game/views/steps.js). The
// strictest of the two rules they had: both their attack lists run here
// against both callers.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const StepFill = require('../renderer/step-fill.js');
const app = require('../renderer/app.js');

const steps = () => import('../renderer/game/views/steps.js');
const PLATFORMS = ['darwin', 'linux', 'win32', null, undefined, 'freebsd'];

test('the list and the game use the one rule', async () => {
  const s = await steps();
  assert.strictEqual(app.fillPlaceholders, StepFill.fillPlaceholders);
  assert.strictEqual(s.shellSafe, StepFill.shellSafe);
  const data = { plist: '/Users/a/Library/LaunchAgents/x y.plist', label: 'ai.x', pid: 7 };
  for (const p of PLATFORMS) {
    const t = 'launchctl bootout gui/501 "<path-to-plist>"; kill <pid>; grep <label>';
    assert.strictEqual(s.fillPlaceholders(t, data, p), app.fillPlaceholders(t, data, { platform: p }), String(p));
  }
  const index = fs.readFileSync(path.join(__dirname, '../renderer/index.html'), 'utf8');
  assert.ok(index.indexOf('src="step-fill.js"') > 0 && index.indexOf('src="step-fill.js"') < index.indexOf('src="app.js"'));
});

test('safe values: paths and names single-quoted, digits bare, template quotes replaced', () => {
  const f = (t, d) => StepFill.fillPlaceholders(t, d, 'darwin');
  const data = { label: 'ai.hermes.gateway', plist: '/Users/a/Library/LaunchAgents/ai.hermes.gateway.plist', pid: 61084, ports: [8765, 8766] };
  assert.strictEqual(f('cat <path-to-plist> | grep <label>', data),
    "cat '/Users/a/Library/LaunchAgents/ai.hermes.gateway.plist' | grep 'ai.hermes.gateway'");
  assert.strictEqual(f('kill <pid>; lsof -i :<port>', data), 'kill 61084; lsof -i :8765');
  for (const t of ['cat <path>', 'cat "<path>"', "cat '<path>'", 'cat “<path>”', 'cat ‘<path>’']) {
    assert.strictEqual(f(t, { path: '/Applications/Ö App.app' }), "cat '/Applications/Ö App.app'", t);
  }
  assert.strictEqual(StepFill.fillPlaceholders('<label>', { label: 'a.b' }, { platform: 'linux' }), "'a.b'", 'platform as an option');
});

test('a quote on one side only, or an unsafe first value, leaves the placeholder as written', () => {
  const f = (t, d) => StepFill.fillPlaceholders(t, d, 'darwin');
  assert.strictEqual(f('cat "<path>', { path: '/x' }), 'cat "<path>');
  assert.strictEqual(f("cat <path>'", { path: '/x' }), "cat <path>'");
  // The first field holding a value decides: never another field's value instead.
  assert.strictEqual(f('cat <path>', { path: '/tmp/$(id)', program: '/bin/ok' }), 'cat <path>');
  assert.strictEqual(f('cat <path>', { path: 'relative/x' }), 'cat <path>', 'paths are absolute');
  assert.strictEqual(f('cat <path>', { path: '~/x' }), 'cat <path>', 'no ~ (the shell expands it)');
  assert.strictEqual(f('kill <pid> <unknown>', {}), 'kill <pid> <unknown>');
});

test('nothing unsafe is ever filled, for either caller, on any platform (both attack lists)', async () => {
  const s = await steps();
  const BAD = [
    // the game's list
    '$(touch x)', '`id`', '"; rm -rf ~; "', "'; rm -rf ~; '", 'a\nrm -rf ~', 'a\rb', 'x\u0000y', '“; id; ”', '‘$(id)’',
    'a;b', 'a&b', 'a|b', 'a>b', 'a<b', 'a\\b', '*', '?', '-rf', ' lead', 'a{b}', 'a!b', 'a#b',
    // the list's list
    '/tmp/$(touch x).plist', '/tmp/`id`.plist', '/tmp/a"; rm -rf ~; ".plist', "/tmp/a'; rm -rf ~; '.plist",
    '/tmp/a\nrm -rf ~', '/tmp/[click](http://evil)', '/tmp/![x](http://evil/i.png)', '/tmp/<img src=x onerror=alert(1)>',
    '/tmp/**bold**', '/tmp/a\\b', '/tmp/a;b', '/tmp/a|b', '/tmp/a&b', 'relative/path',
    // and a few more
    '/tmp/trail ', '/tmp/a‮b', '/tmp/a\tb', '/tmp/~x', '/tmp/a*b', '/tmp/a?b', '/tmp/{a,b}', `/${'a'.repeat(1100)}`,
  ];
  const TEMPLATES = ['cat <path>', 'cat "<path>"', "cat '<path>'", 'cat “<path>”',
    'launchctl bootout gui/$(id -u) <path-to-plist>', 'grep <label>', 'open <app path>', 'id <username>', 'echo <name> <process> <bundle-id>',
    '<plist> <program> <path-to-binary>'];
  const data = (v) => ({ path: v, plist: v, plist_path: v, program: v, location: v, label: v, bundle_id: v, name: v, process: v, username: v, user: v });
  for (const v of BAD) {
    assert.strictEqual(StepFill.safeValue('path', v), null, JSON.stringify(v));
    assert.strictEqual(StepFill.safeValue('name', v), null, JSON.stringify(v));
    for (const t of TEMPLATES) {
      for (const p of PLATFORMS) {
        assert.strictEqual(s.fillPlaceholders(t, data(v), p), t, `game ${p} ${JSON.stringify(v)} in ${t}`);
        assert.strictEqual(app.fillPlaceholders(t, data(v), { platform: p }), t, `list ${p} ${JSON.stringify(v)} in ${t}`);
      }
    }
  }
  for (const pid of ['1; rm -rf ~', '$(id)', '12a', -1, 1.5, '', '1 2', NaN, '12345678901']) {
    assert.strictEqual(StepFill.fillPlaceholders('kill <pid> :<port>', { pid, port: pid }, 'darwin'), 'kill <pid> :<port>', JSON.stringify(pid));
  }
  for (const label of ['$(id)', 'a b', '`id`', '<img src=x onerror=alert(1)>', '[x](http://evil)', '-rf', 'a\nb', 'Ö', '/abs']) {
    assert.strictEqual(StepFill.fillPlaceholders('<label>', { label }, 'darwin'), '<label>', JSON.stringify(label));
  }
  // Windows (PowerShell) and an unknown platform fill nothing, even a safe value.
  for (const p of ['win32', null, undefined, 'freebsd', { platform: 'win32' }, {}]) {
    assert.strictEqual(StepFill.fillPlaceholders('Remove-Item "<path>"', { path: '/Apps/x.exe' }, p), 'Remove-Item "<path>"');
  }
});

test('what is filled is drawn as text by both renderers', async () => {
  const s = await steps();
  const mac = 'darwin';
  const listHtml = app.renderMiniMarkdown(app.fillPlaceholders('Run `launchctl bootout gui/501 <path-to-plist>`', { plist: '/Users/a/My App/x.plist' }, { platform: mac }));
  assert.strictEqual(listHtml, "<p>Run <code>launchctl bootout gui/501 '/Users/a/My App/x.plist'</code></p>");
  const gameHtml = s.stepsHtml([{ number: 1, title: 't', body: '`cat <path>`' }], { data: { path: '/a/b_c,d@e%f=g+h:i' }, platform: mac });
  assert.match(gameHtml, /cat &#39;\/a\/b_c,d@e%f=g\+h:i&#39;/);
  assert.match(s.stepsHtml([{ number: 1, title: 't', body: '`cat <path>`' }], { data: { path: '$(touch x)' }, platform: mac }), /cat &lt;path&gt;/);
});
