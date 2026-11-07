// "It's mine" for settings and installed items (sharing services, proxies,
// extensions, app lists...): the same one mechanism as background tasks.
const test = require('node:test');
const assert = require('node:assert');
const { createMarkPolicy, handleMark, handleUnmark, markTarget } = require('../mark-policy');
const { markArgs } = require('../engine-runner');
const MarkFlow = require('../renderer/mark-flow.js');

const ID_A = 'aaaaaaaaaaaa';
const ID_B = 'bbbbbbbbbbbb';
const GROUP = '0123456789ab';
const RL = 'security.sharing_services.remote_login';
const SSH = 'security.remote_login_check.ssh_enabled';
const ITEM = {
  kind: 'sharing_service', id: ID_A, code: RL, group: GROUP, label: 'Remote Login', monitoring: true,
  shows: [['Setting', 'Remote Login'], ['Now', 'On']],
  will_change: 'Reclaim City will stop warning you about Remote Login being on.',
  how_to_undo: ['Choose "Stop treating this as mine"'],
};

const twoChecks = (a, b) => ({
  modules: [
    { name: 'sharing_services', findings: [{ title: 'x', markable: a }] },
    { name: 'remote_login_check', findings: [{ title: 'y', markable: b }] },
  ],
});

test('markTarget keeps only the id, code and group of an item', () => {
  assert.deepStrictEqual(markTarget(ITEM), { kind: 'sharing_service', id: ID_A, code: RL, group: GROUP });
  assert.strictEqual(markTarget({ ...ITEM, group: undefined }), null);
  assert.strictEqual(markTarget({ ...ITEM, group: '../x' }), null);
  assert.strictEqual(markTarget({ ...ITEM, kind: 'something_else' }), null);
  assert.strictEqual(markTarget({ ...ITEM, code: 'security.stalkerware_scan.monitoring_software_found' }), null);
  assert.strictEqual(markTarget({ ...ITEM, code: 'security.keylogger_indicators.x' }), null);
});

test('engine argv for an item: code and expected id pairs only, never evidence', () => {
  assert.deepStrictEqual(markArgs(markTarget(ITEM)), [
    'known', 'add', '--code', RL, '--expect-id', ID_A, '--json', '--i-understand',
  ]);
  assert.throws(() => markArgs({ ...markTarget(ITEM), marks: [{ code: 'security.mvt_spyware_scan.x', id: ID_A }] }));
  assert.throws(() => markArgs({ ...markTarget(ITEM), marks: [{ code: RL, id: ID_A }, { code: RL, id: ID_B }] }));
});

test('one item on two checks is marked with one answer; a different group never joins', async () => {
  const policy = createMarkPolicy();
  const ids = [ID_A, ID_B];
  policy.remember(twoChecks({ ...ITEM, ids }, { ...ITEM, id: ID_B, code: SSH, ids }));
  let got;
  await handleMark(ID_B, { policy, runMark: async (t) => { got = t; return { status: 'marked', ids }; } });
  assert.deepStrictEqual(got.marks, [{ code: SSH, id: ID_B }, { code: RL, id: ID_A }].sort((a, b) => (a.code < b.code ? -1 : 1)));
  assert.deepStrictEqual(markArgs(got).filter((a) => a === '--code').length, 2);

  policy.remember(twoChecks({ ...ITEM, ids }, { ...ITEM, id: ID_B, code: SSH, group: 'ffffffffffff', ids }));
  assert.deepStrictEqual(policy.targetFor(ID_A).marks, [{ code: RL, id: ID_A }]);
});

test('the monitoring-software checks are never remembered as markable', () => {
  const policy = createMarkPolicy();
  policy.remember({ modules: [{ name: 'stalkerware_scan', findings: [{ markable: ITEM }] }] });
  assert.strictEqual(policy.targetFor(ID_A), null);
});

test('after marking, Undo is allowed for exactly the ids the engine saved for that target', async () => {
  const policy = createMarkPolicy();
  policy.remember(twoChecks({ ...ITEM, ids: [ID_A, ID_B] }, { ...ITEM, id: ID_B, code: SSH, ids: [ID_A, ID_B] }));
  assert.strictEqual(policy.isUnmarkAllowed(ID_A), false);
  // The engine claiming an id nobody asked for gets nothing.
  await handleMark(ID_A, { policy, runMark: async () => ({ status: 'marked', ids: [ID_A, ID_B, 'cccccccccccc'] }) });
  assert.strictEqual(policy.isUnmarkAllowed(ID_A), true);
  assert.strictEqual(policy.isUnmarkAllowed('cccccccccccc'), false);
  let removed;
  await handleUnmark(ID_A, { policy, runUnmark: async (list) => { removed = list; return { status: 'removed' }; } });
  assert.deepStrictEqual(removed, [ID_A, ID_B]);
  // A refused mark allows nothing.
  const p2 = createMarkPolicy();
  p2.remember(twoChecks(ITEM, { ...ITEM, id: ID_B, code: SSH }));
  await handleMark(ID_A, { policy: p2, runMark: async () => ({ status: 'refused', ids: [ID_A] }) });
  assert.strictEqual(p2.isUnmarkAllowed(ID_A), false);
});

test('marked items group by kind and key for "Stop treating this as mine"', async () => {
  const policy = createMarkPolicy();
  const data = { marked_by_user: true, marked_kind: 'sharing_service', marked_key: GROUP };
  policy.remember({
    modules: [
      { name: 'sharing_services', findings: [{ data: { ...data, known_item_id: ID_A }, marked_ids: [ID_A, ID_B] }] },
      { name: 'remote_login_check', findings: [{ data: { ...data, known_item_id: ID_B }, marked_ids: [ID_A, ID_B] }] },
      { name: 'x', findings: [{ data: { ...data, marked_key: 'ffffffffffff', known_item_id: 'cccccccccccc' }, marked_ids: ['cccccccccccc', ID_A] }] },
    ],
  });
  let got;
  const runUnmark = async (list) => { got = list; return { status: 'removed' }; };
  await handleUnmark(ID_B, { policy, runUnmark });
  assert.deepStrictEqual(got, [ID_A, ID_B]);
  await handleUnmark('cccccccccccc', { policy, runUnmark });
  assert.deepStrictEqual(got, ['cccccccccccc']);
});

// --- the card -----------------------------------------------------------------------

test('each kind gets its own plain answer', () => {
  const label = (kind) => MarkFlow.markControlsHtml({ module: 'm', markable: { ...ITEM, kind } });
  assert.match(label('sharing_service'), /I turned this on — it’s mine/);
  assert.match(label('browser_extension'), /I installed this — it’s mine/);
  assert.match(label('app_permissions'), /I know these apps — they’re mine/);
  assert.match(label('ssh_authorized_keys'), /I added these keys — they’re mine/);
  assert.match(label('network_proxy'), /I set this up — it’s mine/);
});

test('"I back up another way" is an answer, not a claim on a thing', () => {
  const backup = {
    ...ITEM, kind: 'backup_elsewhere', code: 'integrity.time_machine_check.sync_only', monitoring: false,
    label: 'you back up another way', shows: [['Time Machine', 'Not set up'], ['Sync apps found', 'Dropbox']],
  };
  assert.deepStrictEqual(markTarget(backup), { kind: 'backup_elsewhere', id: ID_A, code: backup.code, group: GROUP });
  const html = MarkFlow.markControlsHtml({ module: 'time_machine_check', markable: backup });
  assert.match(html, /I back up another way/);
  assert.match(html, /Yes, I back up another way/);
  assert.match(html, /What the checkup found/);
  assert.doesNotMatch(html, /What you are saying is yours/);
  assert.ok(!html.includes(MarkFlow.ONLY_IF_YOURS));
});

test('anything that could be used to watch someone gets the stronger confirmation', () => {
  const strong = MarkFlow.markControlsHtml({ module: 'sharing_services', markable: ITEM });
  assert.ok(strong.includes(MarkFlow.ONLY_IF_YOURS));
  assert.ok(strong.includes(MarkFlow.COULD_WATCH));
  assert.match(strong, /data-mark-panel hidden/, 'the confirmation is a separate, deliberate click');
  assert.match(strong, /What you are saying is yours/);
  assert.match(strong, /Remote Login/);
  const printer = { ...ITEM, monitoring: false, label: 'Printer Sharing' };
  const light = MarkFlow.markControlsHtml({ module: 'sharing_services', markable: printer });
  assert.ok(!light.includes(MarkFlow.ONLY_IF_YOURS));
  assert.match(light, /Yes, it’s mine/, 'still a confirmation, just without the warning');
  // "Someone is watching me": always the stronger one.
  const watched = MarkFlow.markControlsHtml({ module: 'sharing_services', markable: printer }, { watched: true });
  assert.ok(watched.includes(MarkFlow.ONLY_IF_YOURS));
  // A missing flag counts as monitoring.
  const { monitoring, ...noFlag } = ITEM;
  assert.ok(MarkFlow.markControlsHtml({ module: 'm', markable: noFlag }).includes(MarkFlow.ONLY_IF_YOURS));
  void monitoring;
});

test('what the engine shows is escaped, and only the id is carried back', () => {
  const html = MarkFlow.markControlsHtml({
    module: 'm', markable: { ...ITEM, shows: [['<b>k</b>', '<img src=x onerror=1>'], ['bad']], will_change: '<i>w</i>' },
  });
  assert.ok(!html.includes('<img') && !html.includes('<b>k</b>') && !html.includes('<i>w</i>'));
  assert.match(html, /data-mark-id="aaaaaaaaaaaa"/);
  assert.ok(!/data-mark-code|data-mark-group="[^"]*\//.test(html));
});

test('the covers line counts the twin cards for an item too', () => {
  const html = MarkFlow.markControlsHtml({ module: 'm', markable: { ...ITEM, ids: [ID_A, ID_B] } });
  assert.match(html, /2 warnings about this on this checkup/);
});
