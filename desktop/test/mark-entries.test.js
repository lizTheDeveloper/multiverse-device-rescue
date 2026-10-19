// "It's mine" for some entries of one list: the main process sends the engine
// only entry ids its own last scan offered on that finding, never names.
const test = require('node:test');
const assert = require('node:assert');
const { createMarkPolicy, handleMark, handleUnmark } = require('../mark-policy');
const { markArgs, scanArgs } = require('../engine-runner');

const LIST = 'aaaaaaaaaaaa';
const OTHER_LIST = 'bbbbbbbbbbbb';
const E1 = '111111111111';
const E2 = '222222222222';
const E3 = '333333333333';
const DONE = '444444444444';
const ACC = 'security.app_permissions.accessibility_access';

const listMarkable = (id = LIST, items = [
  { key: 'com.example.one', label: 'One', detail: 'com.example.one', id: E1, monitoring: true },
  { key: 'com.example.two', label: 'Two', detail: 'com.example.two', id: E2, monitoring: true },
  { key: 'com.example.gone', label: 'Gone', detail: 'com.example.gone', id: null, monitoring: true },
  { key: 'com.example.done', label: 'Done', detail: 'com.example.done', id: DONE, marked: true, monitoring: true },
]) => ({
  kind: 'app_permissions', id, code: ACC, group: '0123456789ab', monitoring: true,
  shows: [['Apps', 'One, Two'], ['How many', String(items.length)]], items,
  will_change: 'w', how_to_undo: ['u'],
});

const scan = (...findings) => ({ modules: [{ name: 'app_permissions', findings }] });

test('only ids the scan offered on that finding, each once, can be sent', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable() }));
  assert.deepStrictEqual(policy.itemsFor(LIST, [E1, E2]), [E1, E2]);
  assert.strictEqual(policy.itemsFor(LIST, [E3]), null, 'a forged id');
  assert.strictEqual(policy.itemsFor(LIST, [E1, E1]), null, 'a repeat');
  assert.strictEqual(policy.itemsFor(LIST, []), null);
  assert.strictEqual(policy.itemsFor(LIST, [DONE]), null, 'already marked');
  assert.strictEqual(policy.itemsFor(LIST, ['"><x']), null);
  assert.strictEqual(policy.itemsFor(LIST, 'x'), null);
  assert.strictEqual(policy.itemsFor(OTHER_LIST, [E1]), null, 'another finding');
  assert.strictEqual(policy.itemsFor(LIST, Array.from({ length: 61 }, () => E1)), null);
});

test('handleMark with items sends only this finding, never the other checks', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: { ...listMarkable(), ids: [LIST, OTHER_LIST] } },
    { title: 'y', markable: { ...listMarkable(OTHER_LIST), code: 'security.privacy_permissions_audit.excessive_camera', ids: [LIST, OTHER_LIST] } }));
  let got;
  const result = await handleMark(LIST, { policy, runMark: async (t) => { got = t; return { status: 'marked', ids: [E2] }; } }, [E2]);
  assert.strictEqual(result.status, 'marked');
  assert.deepStrictEqual(got.chosen, [E2]);
  assert.deepStrictEqual(got.marks, [{ code: ACC, id: LIST }]);
  assert.deepStrictEqual(markArgs(got), ['known', 'add', '--code', ACC, '--expect-id', LIST, '--item', E2, '--json', '--i-understand']);
});

test('a forged item id over IPC is refused and nothing runs', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable() }));
  let ran = false;
  const result = await handleMark(LIST, { policy, runMark: async () => { ran = true; return {}; } }, [E1, E3]);
  assert.strictEqual(result.status, 'refused');
  assert.strictEqual(ran, false);
});

test('entries saved now, and entries marked on the scan, can be unmarked one by one', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', markable: listMarkable(), data: { marked_items: [{ id: DONE, entry: 'com.example.done', shown: 'Done' }] } }));
  assert.ok(policy.isUnmarkAllowed(DONE));
  assert.deepStrictEqual(policy.unmarkIdsFor(DONE), [DONE]);
  assert.ok(!policy.isUnmarkAllowed(E1));
  await handleMark(LIST, { policy, runMark: async () => ({ status: 'marked', ids: [E1, E3] }) }, [E1]);
  assert.ok(policy.isUnmarkAllowed(E1));
  assert.ok(!policy.isUnmarkAllowed(E3), 'only ids that were asked for');
  let sent;
  const r = await handleUnmark([E1, DONE, E1], { policy, runUnmark: async (ids) => { sent = ids; return { status: 'removed', ids } } });
  assert.strictEqual(r.status, 'removed');
  assert.deepStrictEqual(sent, [E1, DONE]);
  const refused = await handleUnmark([E1, E3], { policy, runUnmark: async () => { throw new Error('must not run'); } });
  assert.strictEqual(refused.status, 'refused');
});

test('a fully marked list from the scan can be unmarked all at once', async () => {
  const policy = createMarkPolicy();
  policy.remember(scan({ title: 'x', data: { marked_by_user: true, marked_items: [{ id: E1, entry: 'a', shown: 'a' }, { id: E2, entry: 'b', shown: 'b' }] } }));
  let sent;
  await handleUnmark([E1, E2], { policy, runUnmark: async (ids) => { sent = ids; return { status: 'removed' }; } });
  assert.deepStrictEqual(sent, [E1, E2]);
});

test('the monitoring-software checks never offer entries', () => {
  const policy = createMarkPolicy();
  policy.remember({ modules: [{ name: 'stalkerware_scan', findings: [{ markable: listMarkable(), data: { marked_items: [{ id: DONE }] } }] }] });
  assert.strictEqual(policy.itemsFor(LIST, [E1]), null);
  assert.ok(!policy.isUnmarkAllowed(DONE));
});

test('entry argv is checked again where it is built', () => {
  const t = { kind: 'app_permissions', id: LIST, code: ACC, chosen: [E1] };
  assert.deepStrictEqual(markArgs(t), ['known', 'add', '--code', ACC, '--expect-id', LIST, '--item', E1, '--json', '--i-understand']);
  assert.throws(() => markArgs({ ...t, kind: 'sharing_service' }));
  assert.throws(() => markArgs({ ...t, chosen: [] }));
  assert.throws(() => markArgs({ ...t, chosen: [E1, E1] }));
  assert.throws(() => markArgs({ ...t, chosen: ['--json'] }));
  assert.throws(() => markArgs({ ...t, chosen: [LIST] }));
  assert.throws(() => markArgs({ ...t, code: 'security.stalkerware_scan.x' }));
});

test('scanArgs takes one profile or several, and refuses anything else', () => {
  assert.deepStrictEqual(scanArgs(null), ['scan', '--json']);
  assert.deepStrictEqual(scanArgs('digital_security_reset'), ['scan', '--json', '--profile', 'digital_security_reset']);
  assert.deepStrictEqual(scanArgs(['digital_security_reset', 'home_network_intrusion', 'digital_security_reset']),
    ['scan', '--json', '--profile', 'digital_security_reset', '--profile', 'home_network_intrusion']);
  assert.throws(() => scanArgs([]));
  assert.throws(() => scanArgs(['ok_name', '--yes']));
  assert.throws(() => scanArgs(Array.from({ length: 9 }, (_, i) => `p${i}`)));
  assert.throws(() => scanArgs([null]));
});
