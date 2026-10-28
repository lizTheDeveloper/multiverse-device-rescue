const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const MarkFlow = require('../renderer/mark-flow.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const UNDO = ['Choose “Stop treating this as mine”'];
const task = (id = 'abcdef012345', extra = {}) => ({
  module: 'launch_agent_audit', code: 'security.launch_agent_audit.suspicious_path', title: 'Background task runs from a hidden folder: a.b',
  severity: 'warning', data: { label: 'a.b', program: '/Users/me/.x/run', plist: '/Users/me/Library/LaunchAgents/a.b.plist' },
  markable: { kind: 'background_task', id, code: 'security.launch_agent_audit.suspicious_path', label: 'a.b', program: '/Users/me/.x/run',
    plist: '/Users/me/Library/LaunchAgents/a.b.plist', will_change: 'Stops warning.', how_to_undo: UNDO }, ...extra });
const ext = (monitoring = true) => ({
  module: 'browser_extension_audit', code: 'security.browser_extension_audit.excessive_permissions', title: 'Extension: Grammar', severity: 'warning',
  data: { extension: 'Grammar', browser: 'Chrome' },
  markable: { kind: 'browser_extension', id: '0c0c0c0c0c01', group: '0d0d0d0d0d01', code: 'security.browser_extension_audit.excessive_permissions',
    monitoring, will_change: 'Stops warning.', how_to_undo: UNDO } });
const opts = (o = {}) => ({ MarkFlow, watched: false, held: false, ...o });

test('a background task is one click; anything that could watch a computer asks once, inline', async () => {
  const { quickMarkOf } = await game('yours.js');
  assert.deepStrictEqual(quickMarkOf(task(), opts()), { id: 'abcdef012345', kind: 'background_task', confirm: false });
  assert.strictEqual(quickMarkOf(ext(true), opts()).confirm, true);
  assert.strictEqual(quickMarkOf(ext(false), opts()).confirm, false);
});

test('city mode, or anything held this sweep, asks once for every mark', async () => {
  const { quickMarkOf } = await game('yours.js');
  assert.strictEqual(quickMarkOf(task(), opts({ watched: true })).confirm, true);
  assert.strictEqual(quickMarkOf(task(), opts({ held: true })).confirm, true);
  assert.strictEqual(quickMarkOf(ext(false), opts({ held: true })).confirm, true);
});

test('SAFETY: monitoring software is never quick-markable, whatever the engine or a forged block says', async () => {
  const { quickMarkOf } = await game('yours.js');
  for (const module of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    assert.strictEqual(quickMarkOf({ ...task(), module }, opts()), null, module);
    // A block whose code names a monitoring check, on any module.
    const forged = task();
    forged.markable = { ...forged.markable, code: `security.${module}.detected` };
    forged.code = `security.${module}.detected`;
    assert.strictEqual(quickMarkOf(forged, opts()), null, `${module} code`);
  }
});

test('SAFETY: nothing without a well-formed block, nothing critical, nothing already marked', async () => {
  const { quickMarkOf } = await game('yours.js');
  assert.strictEqual(quickMarkOf(null, opts()), null);
  assert.strictEqual(quickMarkOf({ ...task(), markable: undefined }, opts()), null);
  assert.strictEqual(quickMarkOf({ ...task(), markable: { ...task().markable, id: 'nope' } }, opts()), null);
  assert.strictEqual(quickMarkOf({ ...task(), severity: 'critical' }, opts()), null, 'the engine never quiets a critical');
  assert.strictEqual(quickMarkOf({ ...task(), data: { ...task().data, marked_by_user: true } }, opts()), null);
  assert.strictEqual(quickMarkOf(task(), { ...opts(), MarkFlow: null }), null, 'no MarkFlow: no quick mark');
});

const sig = (over) => ({ id: 's1', kind: 'real', severity: 'warning', title: 'Background task runs from a hidden folder: a.b', districtId: 'gatehouse',
  module: 'launch_agent_audit', finding: task(), missionId: 's1', marked: false, stale: false, tag: null, ...over });

test('pending marks move a signal out of the queue at once, as marked', async () => {
  const { withPending } = await game('yours.js');
  const [a, b] = withPending([sig(), sig({ id: 's2' })], new Map([['s1', { markIds: ['abcdef012345'], at: 'now' }]]));
  assert.strictEqual(a.marked, true);
  assert.strictEqual(a.tag, 'mine');
  assert.strictEqual(a.pending, true);
  assert.strictEqual(b.marked, false);
});

test('the YOURS inventory lists what is marked and what changed, grouped by what it does', async () => {
  const { yoursInventory } = await game('yours.js');
  const { programContext } = await game('program-kinds.js');
  const marked = sig({ id: 'm1', marked: true, finding: { ...task(), markable: undefined, made_by: [{ subject: '/Users/me/.x/run', name: 'Example LLC', verified: true }],
    data: { ...task().data, marked_by_user: true, known_item_id: 'aaaaaaaaaaaa', original_title: 'Background task runs from a hidden folder: a.b' } } });
  const stale = sig({ id: 'st', stale: true, finding: { ...task('bbbbbbbbbbbb'), data: { ...task().data, label: 'c.d', mark_stale: true, known_item_id: 'cccccccccccc' } } });
  const extMarked = sig({ id: 'e1', marked: true, module: 'browser_extension_audit', finding: { ...ext(), markable: undefined, data: { extension: 'Grammar', browser: 'Chrome', marked_by_user: true, known_item_id: 'dddddddddddd', marked_kind: 'browser_extension' } } });
  const open = sig({ id: 'o1' });
  const inv = yoursInventory([marked, stale, extMarked, open], programContext(null));
  assert.deepStrictEqual(inv.items.map((x) => x.id), ['m1', 'e1']);
  assert.deepStrictEqual(inv.changed.map((x) => x.id), ['st']);
  assert.strictEqual(inv.count, 2);
  const m1 = inv.items[0];
  assert.strictEqual(m1.name, 'a.b');
  assert.strictEqual(m1.markId, 'aaaaaaaaaaaa');
  assert.deepStrictEqual(m1.maker, { name: 'Example LLC', verified: true });
  assert.strictEqual(m1.evidence, '/Users/me/.x/run');
  assert.deepStrictEqual(inv.groups.map((g) => g.kind.id), ['background', 'extension']);
  assert.strictEqual(inv.items[1].name, 'Grammar (Chrome)');
});

test('SAFETY: the inventory never lists monitoring software, even if a finding claims to be marked', async () => {
  const { yoursInventory } = await game('yours.js');
  const forged = sig({ id: 'x', marked: true, module: 'stalkerware_scan', finding: { module: 'stalkerware_scan', title: 'mSpy', data: { marked_by_user: true, known_item_id: 'eeeeeeeeeeee' } } });
  const inv = yoursInventory([forged], null);
  assert.strictEqual(inv.count, 0);
  assert.deepStrictEqual(inv.changed, []);
});
