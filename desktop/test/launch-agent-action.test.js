const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const {
  createFixPolicy, handleRunAction, handleRunUndo, handleRunFix,
} = require('../fix-policy');
const { actionArgs, undoArgs, runAction, runUndo } = require('../engine-runner');
const FixFlow = require('../renderer/fix-flow.js');

const TARGET = '/Users/x/Library/LaunchAgents/com.morgan.bluesky-poster.plist';
const QID = '20261014T120000Z-com.morgan.bluesky-poster';
const FIXABLE = {
  action: 'disable_launch_agent',
  target: TARGET,
  will_change: "Stops the background job 'com.morgan.bluesky-poster' and moves its settings file to Device Rescue's quarantine folder. Nothing is deleted.",
  how_to_undo: ['Open Device Rescue and choose Undo on this item', 'Or move the file back'],
};
const scan = (fixable = FIXABLE) => ({ modules: [{ name: 'launchd_persistence_audit', findings: [{ title: 't', fixable }] }] });

// ---- IPC policy ----

test('only the action+target pair the engine offered is allowed', () => {
  const policy = createFixPolicy();
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', TARGET), false);
  policy.remember(scan());
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', TARGET), true);
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', '/Users/x/Library/LaunchAgents/other.plist'), false);
  assert.strictEqual(policy.isActionAllowed('delete_everything', TARGET), false);
  for (const bad of [null, undefined, 5, '', 'relative.plist', ['a']]) {
    assert.strictEqual(policy.isActionAllowed('disable_launch_agent', bad), false);
  }
});

test('an action offer does not make the whole module fixable, and a new scan replaces it', () => {
  const policy = createFixPolicy();
  policy.remember(scan());
  assert.strictEqual(policy.isAllowed('launchd_persistence_audit'), false);
  policy.remember({ modules: [] });
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', TARGET), false);
});

test('malformed action offers are ignored', () => {
  const policy = createFixPolicy();
  policy.remember(scan({ ...FIXABLE, target: 'not/absolute' }));
  policy.remember(scan({ ...FIXABLE, action: '../x' }));
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', 'not/absolute'), false);
  policy.remember(scan({ ...FIXABLE, how_to_undo: [] }));
  assert.strictEqual(policy.isActionAllowed('disable_launch_agent', TARGET), false);
});

test('handleRunAction refuses unoffered pairs without starting the engine', async () => {
  let started = 0;
  const policy = createFixPolicy();
  policy.remember(scan());
  const runner = async () => { started++; return {}; };
  for (const [a, t] of [['disable_launch_agent', '/etc/passwd'], ['x', TARGET], [null, null]]) {
    const res = await handleRunAction(a, t, { policy, runAction: runner });
    assert.strictEqual(res.error, 'not_allowed');
    assert.strictEqual(res.applied, false);
  }
  assert.strictEqual(started, 0);
});

test('handleRunAction runs the offered pair and then allows undo of the returned id only', async () => {
  const policy = createFixPolicy();
  policy.remember(scan());
  const calls = [];
  const engine = { status: 'fixed', applied: true, verified: true, quarantine_id: QID };
  const res = await handleRunAction('disable_launch_agent', TARGET, { policy, runAction: async (a, t) => { calls.push([a, t]); return engine; } });
  assert.deepStrictEqual(calls, [['disable_launch_agent', TARGET]]);
  assert.deepStrictEqual(res, engine);
  assert.strictEqual(policy.isUndoAllowed(QID), true);
  assert.strictEqual(policy.isUndoAllowed('20261014T120000Z-other'), false);
});

test('handleRunAction turns a crash into an error object', async () => {
  const policy = createFixPolicy();
  policy.remember(scan());
  const res = await handleRunAction('disable_launch_agent', TARGET, { policy, runAction: async () => { throw new Error('boom'); } });
  assert.strictEqual(res.error, 'engine_error');
});

test('handleRunUndo refuses ids the engine did not return in this session', async () => {
  let started = 0;
  const policy = createFixPolicy();
  for (const id of [QID, '../../x', '', null, undefined, 7]) {
    const res = await handleRunUndo(id, { policy, runUndo: async () => { started++; return {}; } });
    assert.strictEqual(res.error, 'not_allowed');
  }
  assert.strictEqual(started, 0);
});

test('handleRunUndo runs once for a known id and forgets it after success', async () => {
  const policy = createFixPolicy();
  policy.noteUndo(QID);
  const calls = [];
  const res = await handleRunUndo(QID, { policy, runUndo: async (id) => { calls.push(id); return { status: 'restored' }; } });
  assert.deepStrictEqual(calls, [QID]);
  assert.strictEqual(res.status, 'restored');
  assert.strictEqual(policy.isUndoAllowed(QID), false);
});

test('module fixes still work and are unaffected', async () => {
  const policy = createFixPolicy();
  policy.remember({ modules: [{ name: 'firewall_audit', findings: [{ fixable: { will_change: 'x', how_to_undo: ['y'] } }] }] });
  const res = await handleRunFix('firewall_audit', { policy, runFix: async () => ({ ok: 1 }) });
  assert.deepStrictEqual(res, { ok: 1 });
});

// ---- engine arguments ----

test('actionArgs and undoArgs build exact argv and reject bad input', () => {
  assert.deepStrictEqual(actionArgs('disable_launch_agent', TARGET),
    ['fix', '--action', 'disable_launch_agent', '--target', TARGET, '--json', '--i-understand']);
  assert.deepStrictEqual(undoArgs(QID), ['undo', '--quarantine-id', QID, '--json']);
  assert.throws(() => actionArgs('--yes', TARGET));
  assert.throws(() => actionArgs('disable_launch_agent', '--help'));
  assert.throws(() => actionArgs('disable_launch_agent', undefined));
  assert.throws(() => undoArgs('../x'));
  assert.throws(() => undoArgs('--json'));
});

function fakeSpawn(stdout, code = 0) {
  const calls = [];
  const fn = (bin, args) => {
    calls.push(args);
    const p = new EventEmitter();
    p.stdout = new EventEmitter();
    p.stderr = new EventEmitter();
    p.kill = () => {};
    setImmediate(() => { p.stdout.emit('data', stdout); p.emit('close', code); });
    return p;
  };
  fn.calls = calls;
  return fn;
}

test('runAction and runUndo parse the engine JSON', async () => {
  const body = { status: 'fixed', quarantine_id: QID };
  const sp = fakeSpawn(JSON.stringify(body));
  assert.deepStrictEqual(await runAction('disable_launch_agent', TARGET, sp), body);
  assert.strictEqual(sp.calls[0][1], '--action');
  const sp2 = fakeSpawn(JSON.stringify({ status: 'restored' }));
  assert.strictEqual((await runUndo(QID, sp2)).status, 'restored');
  const bad = await runAction('--bad', TARGET, fakeSpawn('{}'));
  assert.strictEqual(bad.error, 'engine_error');
});

// ---- panel text and result ----

test('the confirmation panel for an action carries target attributes and no watched warning by default', () => {
  const html = FixFlow.fixControlsHtml({ module: 'launchd_persistence_audit', fixable: FIXABLE });
  assert.match(html, /data-fix-action="disable_launch_agent"/);
  assert.match(html, /data-fix-target="\/Users\/x\/Library\/LaunchAgents\/com\.morgan\.bluesky-poster\.plist"/);
  assert.match(html, /Nothing is deleted/);
  assert.ok(!html.includes('noticed by whoever set it up'));
});

test('the watched situation adds the advocate warning, verbatim', () => {
  const html = FixFlow.fixControlsHtml({ module: 'launchd_persistence_audit', fixable: FIXABLE }, { watched: true });
  assert.ok(html.includes('Turning this off may be noticed by whoever set it up. If you’re not sure that’s safe for you, talk to an advocate first.'));
  const plain = FixFlow.fixControlsHtml({ module: 'firewall_audit', fixable: { will_change: 'x', how_to_undo: ['y'] } }, { watched: true });
  assert.ok(!plain.includes('advocate'));
});

test('an action fixable with a bad target shows no button', () => {
  assert.strictEqual(FixFlow.fixControlsHtml({ module: 'm', fixable: { ...FIXABLE, target: 'rel' } }), '');
  assert.strictEqual(FixFlow.fixControlsHtml({ module: 'm', fixable: { ...FIXABLE, action: '../x' } }), '');
});

test('success shows Done. Nothing was deleted. and an Undo button', () => {
  const result = { action: 'disable_launch_agent', applied: true, verified: true, status: 'fixed', quarantine_id: QID, how_to_undo: ['a'] };
  const d = FixFlow.describeFixResult(result);
  assert.strictEqual(d.headline, 'Done. Nothing was deleted.');
  assert.strictEqual(d.undoId, QID);
  const html = FixFlow.resultHtml(result);
  assert.match(html, /data-fix-undo/);
  assert.ok(html.includes(`data-quarantine-id="${QID}"`));
  assert.ok(!FixFlow.resultHtml({ ...result, quarantine_id: '"><script>' }).includes('data-fix-undo'));
});

function fakeRoot() {
  const els = {};
  const mk = (name, attrs = {}) => {
    els[name] = {
      attrs, hidden: false, innerHTML: '',
      closest(sel) { return sel === '[data-fix-module]' ? els.card : null; },
      hasAttribute(a) { return a in attrs; },
      getAttribute(a) { return attrs[a] === undefined ? null : attrs[a]; },
      querySelector(sel) {
        return { '[data-fix-panel]': els.panel, '[data-fix-status]': els.status, '[data-fix-open]': els.open }[sel] || null;
      },
    };
    return els[name];
  };
  mk('card', { 'data-fix-module': 'launchd_persistence_audit', 'data-fix-action': 'disable_launch_agent', 'data-fix-target': TARGET });
  mk('panel'); els.panel.hidden = true;
  mk('status'); els.status.hidden = true;
  mk('open', { 'data-fix-open': '' });
  mk('confirm', { 'data-fix-confirm': '' });
  mk('undo', { 'data-fix-undo': '', 'data-quarantine-id': QID });
  let click;
  const root = {
    addEventListener(type, fn) { if (type === 'click') click = fn; },
    click(target) { return click({ target: { closest: () => target } }); },
  };
  return { root, els };
}

test('confirm runs the action with its target, then Undo restores by id', async () => {
  const { root, els } = fakeRoot();
  const log = [];
  FixFlow.attach(root, {
    runFix: async () => { log.push('module'); },
    runAction: async (a, t) => { log.push(['action', a, t]); return { action: a, applied: true, verified: true, status: 'fixed', quarantine_id: QID, how_to_undo: [] }; },
    undoFix: async (id) => { log.push(['undo', id]); return { action: 'undo_disable_launch_agent', applied: true, status: 'restored', message: 'Put back, and the background job is on again.' }; },
  });
  root.click(els.open);
  await root.click(els.confirm);
  assert.deepStrictEqual(log, [['action', 'disable_launch_agent', TARGET]]);
  assert.match(els.status.innerHTML, /Done\. Nothing was deleted\./);
  assert.match(els.status.innerHTML, /data-fix-undo/);
  await root.click(els.undo);
  assert.deepStrictEqual(log[1], ['undo', QID]);
  assert.match(els.status.innerHTML, /Put back the way it was/);
  assert.strictEqual(els.open.hidden, false);
});

test('Undo ignores a malformed id', async () => {
  const { root, els } = fakeRoot();
  els.undo.attrs['data-quarantine-id'] = '../../x';
  let calls = 0;
  FixFlow.attach(root, { undoFix: async () => { calls++; } });
  root.click(els.open);
  await root.click(els.undo);
  assert.strictEqual(calls, 0);
});
