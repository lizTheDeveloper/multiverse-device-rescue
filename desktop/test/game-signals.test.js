const test = require('node:test');
const assert = require('node:assert');
const load = async () => ({
  ...(await import('../renderer/game/signals.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/ledger.js')),
  ...(await import('../renderer/game/progress.js')),
  ...(await import('../renderer/game/one-city.js')),
});
const NOW = '2026-10-18T12:00:00Z';
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title} d`, severity, category: 'security', data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const net = (name, findings, extra = {}) => ({ ...mod(name, findings, extra), category: 'network' });
const doc = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
async function build(d, deck) {
  const v = await load();
  const city = v.findingsToCity(d);
  return { v, city, sigs: v.buildSignals(city, deck || v.emptyDeck()) };
}

test('the queue: critical, then warning, then couldn’t check; info is folded apart', async () => {
  const { v, sigs } = await build(doc(
    mod('a_mod', [f('Warn A', 'warning', { plist: '/a' }), f('Crit', 'critical', { plist: '/c' }), f('Note', 'info', { name: 'n1' })]),
    net('b_mod', [f('Warn B', 'warning', { path: '/b' })]),
    mod('broken', [], { status: 'error', error: 'boom' }),
  ));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual(q.urgent.map((x) => x.title), ['Crit', 'Warn A', 'Warn B', 'Broken couldn’t run here']);
  assert.deepStrictEqual(q.low.map((x) => x.title), ['Note']);
  assert.deepStrictEqual([q.urgent[3].kind, q.urgent[3].id, q.urgent[3].description], ['couldnt', 'couldnt|broken', 'boom']);
  assert.deepStrictEqual(v.queueOf(sigs, 'wires').urgent.map((x) => x.title), ['Warn B'], 'a district filter');
});

test('a finding marked as yours arrives tagged MINE; one that changed since is back in the queue', async () => {
  const marked = f('Mine', 'info', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' });
  const stale = f('Stale', 'info', { plist: '/s', marked_by_user: true, mark_stale: true, original_severity: 'warning', known_item_id: 'k2' });
  const { v, sigs } = await build(doc(mod('a_mod', [marked, stale])));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual(q.known.map((x) => [x.title, x.marked, x.tag]), [['Mine', true, 'mine']]);
  assert.deepStrictEqual(q.urgent.map((x) => [x.title, x.stale, x.tag]), [['Stale', true, null]]);
  assert.strictEqual(v.sortedCount(sigs), 1);
});

test('tags carry over by identity; a changed finding with the same identity loses its tag and says so', async () => {
  const same = () => doc(mod('a_mod', [f('Helper', 'warning', { plist: '/h', program: '/Applications/H.app' })]));
  const { v, sigs } = await build(same());
  const deck = v.setTag(v.emptyDeck(), sigs[0].id, 'threat', sigs[0].fp, NOW);
  assert.strictEqual(v.buildSignals(v.findingsToCity(same()), deck)[0].tag, 'threat', 'same identity, same finding: same tag');
  const moved = v.buildSignals(v.findingsToCity(doc(mod('a_mod', [f('Helper', 'warning', { plist: '/h', program: '/tmp/h' })]))), deck)[0];
  assert.strictEqual(moved.id, sigs[0].id, 'the identity is the plist, so it collides');
  assert.deepStrictEqual([moved.tag, moved.changed], [null, true]);
  const later = v.buildSignals(v.findingsToCity(same()), v.emptyDeck(), new Set([sigs[0].id]))[0];
  assert.strictEqual(later.changed, true, 'after the tag was set aside, the controller’s set keeps the badge');
});

// Review Focus 3.
test('two info findings with the same identity are one signal, counted twice', async () => {
  const { v, sigs } = await build(doc(mod('a_mod', [f('Same', 'info'), f('Same', 'info')])));
  const q = v.queueOf(sigs);
  assert.strictEqual(q.low.length, 1);
  assert.strictEqual(q.low[0].count, 2);
  assert.strictEqual(new Set(sigs.map((x) => x.id)).size, sigs.length, 'no two signals share a key');
});

test('integrity: checked districts with nothing open; fog excluded; game tags change nothing', async () => {
  const { v, city, sigs } = await build(doc(
    mod('a_mod', [f('Crit', 'critical', { plist: '/c' })]),
    net('b_mod', [f('Note', 'info')]),
    { ...mod('c_mod', []), category: 'integrity' },
    { ...mod('d_mod', [], { status: 'error', error: 'x' }), category: 'performance' },
  ));
  const i = v.cityIntegrity(city, sigs);
  assert.deepStrictEqual([i.checked, i.secured, i.percent], [3, 2, 67]);
  assert.ok(!i.checkedIds.has('engine-room'), 'a district nothing ran in is never counted');
  const crit = sigs.find((x) => x.title === 'Crit');
  const tagged = v.buildSignals(city, v.setTag(v.emptyDeck(), crit.id, 'mine', crit.fp, NOW));
  assert.strictEqual(tagged.find((x) => x.id === crit.id).tag, 'mine');
  assert.strictEqual(v.cityIntegrity(city, tagged).percent, 67, 'a game tag changes nothing');
  assert.deepStrictEqual(v.districtHeat(city, sigs), { gatehouse: 'hot' });
});

// Review Focus 1.
test('every check errored: no reading, nothing checked, only COULDN’T CHECK signals', async () => {
  const d = doc(mod('a', [], { status: 'error', error: 'x' }), net('b', [], { supported: false, unsupported_reason: 'Windows only' }));
  const { v, city, sigs } = await build(d);
  const i = v.cityIntegrity(city, sigs);
  assert.deepStrictEqual([i.percent, i.checked], [null, 0]);
  assert.ok(sigs.length === 2 && sigs.every((x) => x.kind === 'couldnt'));
  assert.deepStrictEqual(v.sweepCounts(d, city, i), { checks: 0, critical: 0, warning: 0, info: 0, fog: 2, checked: 0, secured: 0, unfinished: 0 });
});

test('monitoring checks’ findings never become signals; one that couldn’t run is an unnamed COULDN’T CHECK row', async () => {
  const { sigs } = await build(doc(mod('stalkerware_scan', [f('No monitoring apps found', 'info')]),
    mod('keylogger_indicators', [], { status: 'error', error: 'timed out looking for keyloggers' }), mod('a_mod', [f('Other', 'info')])));
  assert.deepStrictEqual(sigs.map((x) => x.title), ['Other', 'A check took too long']);
  // Counted as the list counts it (not-checked.js), but never named, explained, tagged or stored.
  const c = sigs.find((x) => x.kind === 'couldnt');
  assert.strictEqual(c.monitoring, true);
  assert.doesNotMatch(JSON.stringify([c.title, c.description]), /keylogger|Keylogger/);
  const { setTag } = await import('../renderer/game/ledger.js');
  const { emptyDeck } = await import('../renderer/game/progress.js');
  assert.deepStrictEqual(setTag(emptyDeck(), c.id, 'noted', c.fp, '2026-10-19T00:00:00Z').tags, {});
  const { renderSignalPanel } = await import('../renderer/game/views/signal.js');
  assert.doesNotMatch(renderSignalPanel({ signal: c, scout: () => '' }), /data-act="tag:noted"/);
});

// Review Focus 5.
test('hundreds of info findings stay in the one low-priority list', async () => {
  const { v, sigs } = await build(doc(mod('a_mod', Array.from({ length: 500 }, (_, i) => f(`Note ${i}`, 'info', { name: `n${i}` })))));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual([q.urgent.length, q.low.length], [0, 500]);
});

test('sweep counts are counts', async () => {
  const d = doc(mod('a_mod', [f('C', 'critical', { plist: '/c' }), f('W', 'warning', { plist: '/w' }), f('I', 'info')]), mod('gone', [], { status: 'error', error: 'x' }));
  const { v, city, sigs } = await build(d);
  assert.deepStrictEqual(v.sweepCounts(d, city, v.cityIntegrity(city, sigs)), { checks: 1, critical: 1, warning: 1, info: 1, fog: 1, checked: 1, secured: 0, unfinished: 0 });
});

test('sweep counts say how many checks ran but didn’t finish', async () => {
  const d = doc(mod('a_mod', [], { complete: false }), mod('b_mod', []));
  const { v, city, sigs } = await build(d);
  const c = v.sweepCounts(d, city, v.cityIntegrity(city, sigs));
  assert.strictEqual(c.checks, 2);
  assert.strictEqual(c.unfinished, 1);
});

test('the deck’s bars: confirmed fixes plus account missions the checkup confirmed; reported apart, never summed', async () => {
  const { countDeckBars } = await load();
  const deck = { confirmed: { a: NOW, b: NOW } };
  assert.deepStrictEqual(countDeckBars({ rc: null, deck }), { confirmed: 2, reported: 0 });
  const r = countDeckBars({ rc: { MISSIONS: [] }, deck, rcState: { missions: { x: { status: 'completed' } } }, scanConfirmed: { missions: {} }, doc: null });
  assert.deepStrictEqual(r, { confirmed: 2, reported: 1 });
});

test('the same identity at two severities shows the worse one, counted twice', async () => {
  const { v, city, sigs } = await build(doc(mod('a_mod', [f('Same', 'info', { plist: '/x' }), f('Same', 'warning', { plist: '/x' })])));
  assert.deepStrictEqual(sigs.map((x) => [x.severity, x.count]), [['warning', 2]]);
  assert.strictEqual(v.cityIntegrity(city, sigs).secured, 0, 'the warning is not hidden under the info');
});

test('a monitoring critical is never a signal, but its district is never secured', async () => {
  const { v, city, sigs } = await build(doc(mod('stalkerware_scan', [f('Monitoring app', 'critical', { plist: '/m' })]), net('b_mod', [f('Note', 'info')])));
  assert.ok(!sigs.some((x) => x.module === 'stalkerware_scan'));
  const i = v.cityIntegrity(city, sigs);
  assert.deepStrictEqual([i.checked, i.secured, i.percent], [2, 1, 50]);
  assert.deepStrictEqual(Object.values(v.districtHeat(city, sigs)), ['hot']);
});

test('a marked critical or warning is not open', async () => {
  const marked = f('Mine', 'warning', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' });
  const { v, city, sigs } = await build(doc(mod('a_mod', [marked])));
  assert.deepStrictEqual(sigs.map((x) => [x.marked, x.tag]), [[true, 'mine']]);
  assert.deepStrictEqual([v.cityIntegrity(city, sigs).percent, v.districtHeat(city, sigs)], [100, {}]);
});

test('bars with both counts non-zero are reported apart, never summed', async () => {
  const { countDeckBars } = await load();
  const FC = 'device_security-fortify-computer';
  const okm = (name, findings = []) => ({ name, status: 'ok', supported: true, findings });
  const d = { platform: 'darwin', modules: [okm('encryption_check'), okm('lock_screen_check'),
    okm('filevault_recovery', [{ severity: 'info', data: { check: 'fv_status' } }]),
    okm('screen_lock_check', [{ severity: 'info', data: { check: 'screen_lock_required', value: 'enabled' } }]),
    okm('find_my_mac_check', [{ severity: 'info', code: 'security.find_my_mac_check.configured_ok', data: {} }])] };
  const rc = { MISSIONS: [{ id: FC, steps: [0, 1, 2, 3, 4, 5] }] };
  const r = countDeckBars({ rc, deck: { confirmed: { a: NOW } },
    rcState: { missions: { [FC]: { status: 'completed' }, other: { status: 'completed' } } },
    scanConfirmed: { missions: { [FC]: true } }, doc: d });
  assert.deepStrictEqual(r, { confirmed: 2, reported: 1 });
});

test('a mark that couldn’t be checked this time is back in the queue, never “changed”', async () => {
  const unchecked = f('Unchecked', 'warning', { plist: '/u', mark_stale: true, mark_unchecked: true, known_item_id: 'k3' });
  const { v, sigs } = await build(doc(mod('a_mod', [unchecked])));
  const q = v.queueOf(sigs);
  assert.deepStrictEqual(q.urgent.map((x) => [x.title, x.stale, x.unchecked, x.marked]), [['Unchecked', false, true, false]]);
  const { signalRow } = await import('../renderer/game/views/deck.js');
  const row = signalRow(q.urgent[0]);
  assert.match(row, /NOT CHECKED THIS TIME/);
  assert.doesNotMatch(row, /CHANGED SINCE/);
});
