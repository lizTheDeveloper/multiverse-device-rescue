// A checkup that stopped before the end (engine-runner.js stoppedDocOf), or is
// still running (`partial`), is shown but never acted on: both policies ignore
// it whoever calls remember (main's scan handler or a re-check merge), and a
// re-check of a stopped checkup is refused.
const test = require('node:test');
const assert = require('node:assert');
const { createFixPolicy } = require('../fix-policy');
const { createMarkPolicy } = require('../mark-policy');
const { handleRecheck } = require('../recheck');

const MARKABLE = {
  kind: 'background_task', code: 'security.launch_agent_audit.unsigned', id: 'aaaaaaaaaaaa',
  label: 'com.example.task', program: '/Users/x/bin/task', plist: '/Users/x/Library/LaunchAgents/com.example.task.plist',
  content_sha256: 'c'.repeat(64), arguments_sha256: 'a'.repeat(64),
};
const ACTION = { action: 'disable_launch_agent', target: '/Users/x/Library/LaunchAgents/com.example.task.plist', will_change: 'x', how_to_undo: ['Choose Undo.'] };
const scan = (extra = {}) => ({ schema_version: 1, modules: [
  { name: 'launch_agent_audit', status: 'ok', supported: true, findings: [{ title: 't', severity: 'warning', markable: MARKABLE, fixable: ACTION }] },
  { name: 'disk_cleanup', status: 'ok', supported: true, findings: [{ title: 'd', severity: 'warning', fixable: { will_change: 'x', how_to_undo: ['Choose Undo.'] } }] },
], ...extra });
const STOPPED = { stopped: { reason: 'exit', exit_code: 1, done: 2, total: 3 } };

test('fix and mark policies arm from a whole scan and never from a stopped or partial one', () => {
  for (const extra of [STOPPED, { partial: { done: 1, total: 3 } }]) {
    const fix = createFixPolicy();
    const mark = createMarkPolicy();
    fix.remember(scan());
    mark.remember(scan());
    assert.ok(fix.isAllowed('disk_cleanup') && fix.isActionAllowed(ACTION.action, ACTION.target));
    assert.ok(mark.targetFor(MARKABLE.id));
    fix.remember(scan(extra));
    mark.remember(scan(extra));
    assert.strictEqual(fix.isAllowed('disk_cleanup'), false, 'the old allowance is dropped too');
    assert.strictEqual(fix.isActionAllowed(ACTION.action, ACTION.target), false);
    assert.strictEqual(mark.targetFor(MARKABLE.id), null);
  }
});

test('a re-check never re-arms the policies from a stopped checkup', async () => {
  const fix = createFixPolicy();
  const mark = createMarkPolicy();
  let last = scan(STOPPED);
  let ran = false;
  const r = await handleRecheck('launch_agent_audit', {
    getLastDoc: () => last, setLastDoc: (d) => { last = d; },
    runRecheck: async () => { ran = true; return scan(); },
    policies: [fix, mark],
  });
  assert.strictEqual(r.ok, false);
  assert.strictEqual(ran, false, 'the engine is not run');
  assert.strictEqual(fix.isAllowed('disk_cleanup'), false);
  assert.strictEqual(mark.targetFor(MARKABLE.id), null);
  // Even if a stopped document reached remember() through a merge, it is ignored.
  fix.remember({ ...scan(STOPPED), modules: scan().modules });
  assert.strictEqual(fix.isAllowed('disk_cleanup'), false);
});
