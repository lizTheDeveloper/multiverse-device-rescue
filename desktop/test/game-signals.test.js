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
  assert.deepStrictEqual(q.urgent.map((x) => x.title), ['Crit', 'Warn A', 'Warn B', 'A check couldn’t run here']);
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
  assert.deepStrictEqual(v.sweepCounts(d, city, i), { checks: 0, critical: 0, warning: 0, info: 0, fog: 2, checked: 0, secured: 0 });
});

test('monitoring checks never become signals, even their info findings or a check that couldn’t run', async () => {
  const { sigs } = await build(doc(mod('stalkerware_scan', [f('No monitoring apps found', 'info')]),
    mod('keylogger_indicators', [], { status: 'error', error: 'x' }), mod('a_mod', [f('Other', 'info')])));
  assert.deepStrictEqual(sigs.map((x) => x.title), ['Other']);
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
  assert.deepStrictEqual(v.sweepCounts(d, city, v.cityIntegrity(city, sigs)), { checks: 1, critical: 1, warning: 1, info: 1, fog: 1, checked: 1, secured: 0 });
});

test('the deck’s bars: confirmed fixes plus account missions the checkup confirmed; reported apart, never summed', async () => {
  const { countDeckBars } = await load();
  const deck = { confirmed: { a: NOW, b: NOW } };
  assert.deepStrictEqual(countDeckBars({ rc: null, deck }), { confirmed: 2, reported: 0 });
  const r = countDeckBars({ rc: { MISSIONS: [] }, deck, rcState: { missions: { x: { status: 'completed' } } }, scanConfirmed: { missions: {} }, doc: null });
  assert.deepStrictEqual(r, { confirmed: 2, reported: 1 });
});
