const test = require('node:test');
const assert = require('node:assert');
const FixFlow = require('../renderer/fix-flow.js');

const FIXABLE = {
  will_change: 'Turns on your Mac\'s firewall.',
  how_to_undo: ['Open System Settings.', 'Turn the firewall off.'],
};

test('fixableOf returns the block only when it is well formed', () => {
  assert.deepStrictEqual(FixFlow.fixableOf({ fixable: FIXABLE }), FIXABLE);
  assert.strictEqual(FixFlow.fixableOf({}), null);
  assert.strictEqual(FixFlow.fixableOf(null), null);
  assert.strictEqual(FixFlow.fixableOf({ fixable: { will_change: 'x' } }), null);
  assert.strictEqual(FixFlow.fixableOf({ fixable: { will_change: 'x', how_to_undo: [] } }), null);
  assert.strictEqual(FixFlow.fixableOf({ fixable: { will_change: '', how_to_undo: ['a'] } }), null);
});

test('no button for a finding that is not fixable, or has no module', () => {
  assert.strictEqual(FixFlow.fixControlsHtml({ module: 'm' }), '');
  assert.strictEqual(FixFlow.fixControlsHtml({ fixable: FIXABLE }), '');
  assert.strictEqual(FixFlow.fixControlsHtml({ module: '../x', fixable: FIXABLE }), '');
});

test('controls show the button and a hidden confirmation with will-change and undo', () => {
  const html = FixFlow.fixControlsHtml({ module: 'firewall_audit', fixable: FIXABLE });
  assert.match(html, /data-fix-module="firewall_audit"/);
  assert.match(html, /Fix it for me/);
  assert.match(html, /What changes:/);
  assert.match(html, /To undo later:/);
  assert.match(html, /Yes, fix it/);
  assert.match(html, /Cancel/);
  assert.match(html, /Turn the firewall off\./);
  // the confirmation starts hidden: nothing happens until the person opens it
  assert.match(html, /data-fix-panel hidden/);
});

test('everything from the engine is escaped', () => {
  const evil = {
    will_change: '<img src=x onerror=alert(1)>',
    how_to_undo: ['<script>alert(2)</script>', '"quoted" & <b>bold</b>'],
  };
  const html = FixFlow.fixControlsHtml({ module: 'm', fixable: evil });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script'));
  assert.ok(!html.includes('<b>'));
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /&quot;quoted&quot; &amp; &lt;b&gt;bold&lt;\/b&gt;/);
});

test('describeFixResult: fixed and verified', () => {
  const r = FixFlow.describeFixResult({ applied: true, verified: true, status: 'fixed', how_to_undo: ['Do x.'] });
  assert.strictEqual(r.tone, 'success');
  assert.match(r.headline, /Done, and checked again: fixed/);
  assert.match(r.headline, /✓/);
  assert.deepStrictEqual(r.undo, ['Do x.']);
});

test('describeFixResult: applied but still showing is never called fixed', () => {
  const r = FixFlow.describeFixResult({ applied: true, verified: false, status: 'not_fixed', how_to_undo: [] });
  assert.strictEqual(r.tone, 'warning');
  assert.ok(!/fixed ✓/.test(r.headline));
  assert.match(r.detail, /still/i);
});

test('describeFixResult: nothing to fix', () => {
  const r = FixFlow.describeFixResult({ applied: false, status: 'nothing_to_fix', verified: true });
  assert.strictEqual(r.tone, 'info');
  assert.match(r.headline, /nothing to fix/i);
});

test('describeFixResult: refusals and failures are in plain words, with the engine message', () => {
  const refused = FixFlow.describeFixResult({ applied: false, error: 'not_allowed', message: 'x' });
  assert.strictEqual(refused.tone, 'error');
  assert.match(refused.detail, /How to fix this/);
  const failed = FixFlow.describeFixResult({ applied: false, status: 'failed', message: 'The change did not go through: must be root' });
  assert.strictEqual(failed.tone, 'error');
  // The engine's words are kept for a tech helper, never run into the app's sentence.
  assert.match(failed.engine, /must be root/);
  assert.doesNotMatch(failed.detail, /must be root/);
  assert.match(FixFlow.resultHtml({ applied: false, status: 'failed', message: 'must be root' }), /For tech helpers<\/summary><p>must be root/);
  const crash = FixFlow.describeFixResult({ applied: false, error: 'engine_error', message: 'spawn ENOENT' });
  assert.strictEqual(crash.tone, 'error');
});

test('describeFixResult copes with junk and never claims success', () => {
  for (const junk of [null, undefined, 'x', 5, {}, { applied: true }, { verified: true }]) {
    const r = FixFlow.describeFixResult(junk);
    assert.notStrictEqual(r.tone, 'success', JSON.stringify(junk));
  }
});

test('resultHtml escapes the message and the undo steps', () => {
  const html = FixFlow.resultHtml({
    applied: true, verified: true, status: 'fixed',
    how_to_undo: ['<script>x</script>'], message: '<b>hi</b>',
  });
  assert.ok(!html.includes('<script'));
  assert.match(html, /&lt;script&gt;x&lt;\/script&gt;/);
});

test('failure detail from the engine is escaped in the result html', () => {
  const html = FixFlow.resultHtml({ applied: false, status: 'failed', message: '<img src=x onerror=1>' });
  assert.ok(!html.includes('<img'));
  assert.match(html, /&lt;img/);
});

// --- the click flow, against a tiny fake DOM -----------------------------------------

function fakeRoot() {
  const els = {};
  const mk = (name, attrs = {}) => {
    const el = {
      name, attrs, hidden: false, disabled: false, innerHTML: '',
      closest(sel) { return sel === '[data-fix-module]' ? els.card : null; },
      hasAttribute(a) { return a in attrs; },
      getAttribute(a) { return attrs[a]; },
      querySelector(sel) {
        if (sel === '[data-fix-panel]') return els.panel;
        if (sel === '[data-fix-status]') return els.status;
        if (sel === '[data-fix-open]') return els.open;
        return null;
      },
    };
    els[name] = el;
    return el;
  };
  mk('card', { 'data-fix-module': 'firewall_audit' });
  mk('panel', {}); els.panel.hidden = true;
  mk('status', {}); els.status.hidden = true;
  mk('open', { 'data-fix-open': '' });
  mk('confirm', { 'data-fix-confirm': '' });
  mk('cancel', { 'data-fix-cancel': '' });
  const listeners = {};
  const root = {
    addEventListener(type, fn) { listeners[type] = fn; },
    click(target) { return listeners.click({ target: { closest: (sel) => (sel === '[data-fix-open],[data-fix-confirm],[data-fix-cancel],[data-fix-undo]' ? target : null) } }); },
    key(key) { return listeners.keydown && listeners.keydown({ key, target: els.card }); },
  };
  return { root, els };
}

test('Fix it for me opens the confirmation and changes nothing', () => {
  const { root, els } = fakeRoot();
  let calls = 0;
  FixFlow.attach(root, { runFix: async () => { calls++; } });
  root.click(els.open);
  assert.strictEqual(els.panel.hidden, false);
  assert.strictEqual(calls, 0);
});

test('Cancel closes the panel and changes nothing', () => {
  const { root, els } = fakeRoot();
  let calls = 0;
  FixFlow.attach(root, { runFix: async () => { calls++; } });
  root.click(els.open);
  root.click(els.cancel);
  assert.strictEqual(els.panel.hidden, true);
  assert.strictEqual(calls, 0);
});

test('Escape closes an open confirmation and changes nothing', () => {
  const { root, els } = fakeRoot();
  let calls = 0;
  FixFlow.attach(root, { runFix: async () => { calls++; } });
  root.click(els.open);
  root.key('Escape');
  assert.strictEqual(els.panel.hidden, true);
  assert.strictEqual(calls, 0);
});

test('Yes, fix it calls run-fix once for that module and shows the result', async () => {
  const { root, els } = fakeRoot();
  const calls = [];
  const result = { applied: true, verified: true, status: 'fixed', how_to_undo: ['Undo it.'] };
  FixFlow.attach(root, { runFix: async (m) => { calls.push(m); return result; } });
  root.click(els.open);
  const done = root.click(els.confirm);
  // while running: the confirm controls are gone so it cannot be sent twice
  assert.strictEqual(els.panel.hidden, true);
  assert.match(els.status.innerHTML, /Fixing/);
  await done;
  assert.deepStrictEqual(calls, ['firewall_audit']);
  assert.match(els.status.innerHTML, /Done, and checked again: fixed/);
  assert.match(els.status.innerHTML, /Undo it\./);
});

test('a second click on Yes while running is ignored', async () => {
  const { root, els } = fakeRoot();
  let calls = 0;
  let release;
  FixFlow.attach(root, { runFix: () => { calls++; return new Promise((r) => { release = r; }); } });
  root.click(els.open);
  const first = root.click(els.confirm);
  root.click(els.confirm);
  release({ applied: true, verified: true, status: 'fixed', how_to_undo: [] });
  await first;
  assert.strictEqual(calls, 1);
});

test('Yes without opening the confirmation first does nothing', async () => {
  const { root, els } = fakeRoot();
  let calls = 0;
  FixFlow.attach(root, { runFix: async () => { calls++; } });
  await root.click(els.confirm);
  assert.strictEqual(calls, 0);
});

test('the page loads fix-flow.js before app.js, and the app packages fix-policy.js', () => {
  const read = (rel) => require('node:fs').readFileSync(require('node:path').join(__dirname, rel), 'utf8');
  const html = read('../renderer/index.html');
  assert.ok(html.indexOf('fix-flow.js') !== -1 && html.indexOf('fix-flow.js') < html.indexOf('app.js'));
  assert.ok(JSON.parse(read('../package.json')).build.files.includes('fix-policy.js'));
});

test('an IPC failure becomes a plain-words error, not a stuck spinner', async () => {
  const { root, els } = fakeRoot();
  FixFlow.attach(root, { runFix: async () => { throw new Error('ipc blew up'); } });
  root.click(els.open);
  await root.click(els.confirm);
  assert.match(els.status.innerHTML, /fix-status--error/);
  assert.ok(!/Fixing/.test(els.status.innerHTML));
});

test('onResult hears the engine answer after Yes, fix it', async () => {
  const { root, els } = fakeRoot();
  const heard = [];
  const result = { applied: true, verified: true, status: 'fixed', how_to_undo: ['Undo it.'] };
  FixFlow.attach(root, { runFix: async () => result }, { onResult: (e) => heard.push(e) });
  root.click(els.open);
  await root.click(els.confirm);
  assert.strictEqual(heard.length, 1);
  assert.strictEqual(heard[0].kind, 'fix');
  assert.strictEqual(heard[0].module, 'firewall_audit');
  assert.strictEqual(heard[0].result, result);
  assert.strictEqual(heard[0].described.tone, 'success');
});

test('a throwing onResult does not break the flow', async () => {
  const { root, els } = fakeRoot();
  FixFlow.attach(root, { runFix: async () => ({ applied: true, verified: true, status: 'fixed', how_to_undo: ['u'] }) },
    { onResult: () => { throw new Error('hook'); } });
  root.click(els.open);
  await root.click(els.confirm);
  assert.match(els.status.innerHTML, /fixed/);
});

test('onResult is not called when the person cancels', () => {
  const { root, els } = fakeRoot();
  let heard = 0;
  FixFlow.attach(root, { runFix: async () => ({}) }, { onResult: () => { heard++; } });
  root.click(els.open);
  root.click(els.cancel);
  assert.strictEqual(heard, 0);
});

test('onResult hears an Undo as kind "undo"', async () => {
  const { root, els } = fakeRoot();
  const heard = [];
  const undo = { name: 'undo', attrs: { 'data-fix-undo': '', 'data-quarantine-id': '20261016T120000Z-com.example.a' },
    hasAttribute(a) { return a in this.attrs; }, getAttribute(a) { return this.attrs[a]; },
    closest(sel) { return sel === '[data-fix-module]' ? els.card : null; } };
  const result = { restored: true, status: 'restored' };
  FixFlow.attach(root, { runFix: async () => ({}), undoFix: async () => result }, { onResult: (e) => heard.push(e) });
  await root.click(undo);
  assert.strictEqual(heard.length, 1);
  assert.strictEqual(heard[0].kind, 'undo');
  assert.strictEqual(heard[0].module, 'firewall_audit');
  assert.strictEqual(heard[0].result, result);
});

test('describeFixResult: a check afterwards that didn’t finish is “couldn’t confirm”, never fixed, and starts no re-check', () => {
  const r = FixFlow.describeFixResult({ applied: true, verified: false, status: 'unconfirmed', how_to_undo: ['Do x.'] });
  assert.strictEqual(r.tone, 'warning');
  assert.match(r.headline, /The fix ran, but the re-check couldn’t confirm it/);
  assert.doesNotMatch(r.headline + r.detail, /fixed|still shows/i);
  assert.deepStrictEqual(r.undo, ['Do x.']);
});

test('round 3: after a fix was applied, a re-check that fails never says "Nothing was changed"', () => {
  const after = FixFlow.recheckFailedText({ fixApplied: true });
  assert.doesNotMatch(after.headline + after.detail, /Nothing was changed/);
  assert.match(after.headline, /The change was made/);
  assert.match(after.detail, /can’t confirm/);
  const before = FixFlow.recheckFailedText({ fixApplied: false });
  assert.match(before.headline, /couldn’t check again/);
  // Every answer where the engine applied the change: never "Nothing was changed".
  for (const r of [{ applied: true, status: 'unconfirmed' }, { applied: true, verified: false, status: 'still_present' },
    { applied: true, status: 'unconfirmed', error: 'scan_running' }, { applied: true, error: 'not_allowed' }]) {
    const d = FixFlow.describeFixResult(r);
    assert.doesNotMatch(`${d.headline} ${d.detail}`, /Nothing was changed/, JSON.stringify(r));
  }
});

test('round 3: a fix with its own Undo says so in one line; the manual ways back are for a tech helper', () => {
  const html = FixFlow.fixControlsHtml({ module: 'launch_agent_audit', fixable: Object.assign({}, FIXABLE,
    { action: 'disable_launch_agent', target: '/Users/ann/Library/LaunchAgents/x.plist', how_to_undo: ['Open Reclaim City and choose Undo.', 'Move the file back.'] }) });
  assert.match(html, /<strong>To undo:<\/strong> Undo is on this item\./);
  assert.doesNotMatch(html, /To undo later/);
  assert.doesNotMatch(html, /<ol class="fix-undo">/, 'no numbered alternatives');
  assert.match(html, /For tech helpers: undo it by hand<\/summary><p>Open Reclaim City and choose Undo\.<\/p><p>Move the file back\./);
  const done = FixFlow.resultHtml({ action: 'disable_launch_agent', applied: true, verified: true, status: 'fixed',
    quarantine_id: '20261019T101010Z-x.plist', how_to_undo: ['Open Reclaim City and choose Undo.'] });
  assert.match(done, /data-fix-undo/);
  assert.doesNotMatch(done, /To undo later/, 'not beside an Undo button');
});
