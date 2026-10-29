const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

const finding = (n, over = {}) => ({ module: 'launch_agents_audit', code: 'security.launch_agents_audit.third_party', title: `Starts on its own: t${n}`,
  severity: 'warning', data: { label: `t${n}`, program: `/Users/me/.x/t${n}`, plist: `/Users/me/Library/LaunchAgents/t${n}.plist` }, ...over });
const sig = (n, over = {}) => ({ id: `s${n}`, kind: 'real', severity: 'warning', title: `Starts on its own: t${n}`, districtId: 'gatehouse',
  module: 'launch_agents_audit', finding: finding(n, over.finding), missionId: `s${n}`, marked: false, stale: false, tag: null, fp: `fp${n}`, ...over, ...(over.finding ? { finding: finding(n, over.finding) } : {}) });

test('keys: one key, one action; typing in the search box only leaves it', async () => {
  const { keyAction } = await game('triage.js');
  assert.strictEqual(keyAction({ key: 'j' }), 'down');
  assert.strictEqual(keyAction({ key: 'ArrowUp' }), 'up');
  assert.strictEqual(keyAction({ key: 'ArrowDown', shiftKey: true }), 'down-select');
  assert.strictEqual(keyAction({ key: 'Enter' }), 'expand');
  assert.strictEqual(keyAction({ key: 'm' }), 'mine');
  assert.strictEqual(keyAction({ key: 't' }), 'threat');
  assert.strictEqual(keyAction({ key: 'l' }), 'closer');
  assert.strictEqual(keyAction({ key: 'u' }), 'undo');
  assert.strictEqual(keyAction({ key: 'x' }), 'select');
  assert.strictEqual(keyAction({ key: 'X', shiftKey: true }), 'select-range');
  assert.strictEqual(keyAction({ key: '/' }), 'filter');
  assert.strictEqual(keyAction({ key: '?' }), 'help');
  assert.strictEqual(keyAction({ key: '2' }), 'cat:dev');
  assert.strictEqual(keyAction({ key: 'm', metaKey: true }), null);
  assert.strictEqual(keyAction({ key: 'm', inInput: true }), null);
  assert.strictEqual(keyAction({ key: 'Escape', inInput: true }), 'filter-done');
});

test('safety plan: held rows never move, a critical is never mine in bulk, and asks on its own', async () => {
  const { planTag, rowOf, heldRow } = await game('triage.js');
  const held = heldRow({ label: 'Something new somewhere', go: 'side' });
  const crit = rowOf(sig(1, { severity: 'critical' }));
  const ok = rowOf(sig(2));
  const spy = { ...rowOf(sig(3)), sig: { ...sig(3), module: 'stalkerware_scan' } };
  for (const tag of ['mine', 'threat', 'closer', 'noted']) {
    const p = planTag([held, spy], tag, { bulk: true });
    assert.deepStrictEqual(p.go, []);
    assert.deepStrictEqual(p.skip.map((x) => x.why), ['held', 'held']);
  }
  const bulk = planTag([crit, ok], 'mine', { bulk: true });
  assert.deepStrictEqual(bulk.go.map((r) => r.id), ['s2']);
  assert.deepStrictEqual(bulk.skip.map((x) => x.why), ['critical']);
  const one = planTag([crit], 'mine', { bulk: false });
  assert.deepStrictEqual(one.ask.map((r) => r.id), ['s1']);
  assert.deepStrictEqual(one.go, []);
  assert.deepStrictEqual(planTag([crit], 'threat', { bulk: true }).go.map((r) => r.id), ['s1']);
});

test('view: the held row leads whatever the filters, and only a verified maker group is mineable at once', async () => {
  const { rowsOf, viewOf, heldRow, groupMineable, defaultFilters } = await game('triage.js');
  const mb = (name, verified) => ({ made_by: [{ subject: '/x', name, verified }] });
  const rows = rowsOf([sig(1, { finding: mb('Google LLC', true) }), sig(2, { finding: mb('Google LLC', true) }), sig(3, { finding: mb('Helper Co', false) }), sig(4)]);
  const held = heldRow({ label: 'Held', act: 'list' });
  const f = { ...defaultFilters(), text: 'nothing matches this' };
  assert.deepStrictEqual(viewOf(rows, { filters: f, held }).items.map((x) => x.id), ['held']);
  const v = viewOf(rows, { group: 'maker', held });
  const heads = v.items.filter((x) => x.head);
  assert.strictEqual(v.items[0].id, 'held');
  assert.strictEqual(heads[0].label, 'Google LLC · verified');
  assert.deepStrictEqual(heads.map(groupMineable), [true, false, false]);
});

test('range select skips heads and the held row; undo puts tags back or removes them', async () => {
  const { rangeIds, restoreTags, restoreWatchTags } = await game('triage.js');
  const items = [{ id: 'held', held: true }, { id: 'g', head: true }, { id: 'a' }, { id: 'b' }, { id: 'c' }];
  assert.deepStrictEqual(rangeIds(items, 'c', 'held'), ['a', 'b', 'c']);
  const deck = { tags: { a: { tag: 'mine', at: '2', fp: 'x' }, b: { tag: 'threat', at: '2', fp: 'y' } } };
  const back = restoreTags(deck, [{ id: 'a', rec: null }, { id: 'b', rec: { tag: 'closer', at: '1', fp: 'y' } }, { id: 'w', watch: true, rec: null }]);
  assert.deepStrictEqual(back.tags, { b: { tag: 'closer', at: '1', fp: 'y' } });
  assert.deepStrictEqual(restoreWatchTags({ w: { tag: 'mine' } }, [{ id: 'w', watch: true, rec: null }]), {});
});

test('live sweep: held findings never become rows', async () => {
  const { liveCity } = await game('triage.js');
  const m = { name: 'launch_agents_audit', category: 'security', status: 'ok', supported: true, findings: [finding(1)] };
  const spy = { name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true,
    findings: [{ title: 'Found', severity: 'critical', code: 'security.stalkerware_scan.found', data: {} }] };
  const { city, held } = liveCity([m, spy]);
  assert.strictEqual(held.length, 1);
  assert.ok(!city.districts.some((d) => d.missions.some((x) => x.module === 'stalkerware_scan')));
});

// The screen, with its controller-side pieces faked.
function screen(game0, { signals, held = [] }) {
  const store = { deck: { points: 0, rank: 0, drills: { right: 0, tried: 0 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] },
    watch: {}, awards: [], opened: {}, marks: [], unmarks: [] };
  const desk = { qmOf: () => null, isWatch: () => false, pickNone() {}, pick() {}, overlay: (s) => s, confirm: null,
    ask: async (id) => { store.marks.push(id); }, askPicked: async () => {}, yes: async () => {}, unmine: async (ids) => { store.unmarks.push(...ids); } };
  const { createTriageScreen } = game0;
  const t = createTriageScreen({ frame: null, now: () => 'now', scanning: () => false, boss: () => ({ index: 1, total: 1 }),
    signals: () => signals.map((x) => ({ ...x, tag: (store.deck.tags[x.id] || {}).tag || null })),
    quiet: (d) => d, platform: () => 'darwin', tagsDeck: () => store.deck, changed: () => new Set(), ctx: () => null, desk, held: () => held,
    heldSpec: () => ({ label: 'Held', act: 'list' }), closedIds: () => new Set(), deck: () => store.deck, commitDeck: (d) => { store.deck = d; },
    watchTags: () => store.watch, setWatchTags: (m) => { store.watch = m; }, clearChanged: () => {},
    award: (kind, key) => { store.awards.push(`${kind}:${key}`); return 1; }, opened: (id) => { store.opened[id] = store.opened[id] || []; return store.opened[id]; },
    cluesOf: () => [{ kind: 'where' }, { kind: 'what' }], log: () => {}, evidence: () => '', recheck: async () => ({ ran: true, still: true, paid: 0 }), render: () => {}, back: () => {},
    timer: () => 0 });
  return { t, store };
}

test('screen: m asks what a lead is; Enter takes the suggestion; XP only after looking; u undoes', async () => {
  const g = await game('triage-screen.js');
  const { t, store } = screen(g, { signals: [sig(1, { finding: { made_by: [{ subject: '/x', name: 'Docker Inc', verified: true }] } }),
    sig(2, { finding: { made_by: [{ subject: '/y', name: 'Example Ltd', verified: true }] } })] });
  t.html();
  t.act('mine');
  assert.strictEqual(t.state.ask.kind, 'identify');
  assert.strictEqual(t.state.ask.cat, 'dev');
  t.act('expand'); // Enter answers the question
  await new Promise((r) => setTimeout(r, 0));
  assert.deepStrictEqual(store.deck.tags.s1 && [store.deck.tags.s1.tag, store.deck.tags.s1.cat], ['mine', 'dev']);
  assert.deepStrictEqual(store.awards, [], 'nothing was looked at, so nothing pays');
  // The next row moved up under the cursor. Look first, then a digit: XP.
  t.act('expand');
  assert.deepStrictEqual(store.awards, ['clue:s2#where', 'clue:s2#what']);
  t.act('cat:work');
  await new Promise((r) => setTimeout(r, 0));
  assert.ok(store.awards.includes('identify:s2') && store.awards.includes('tagBonus:s2'));
  t.act('undo');
  await new Promise((r) => setTimeout(r, 0));
  assert.strictEqual(store.deck.tags.s2, undefined);
  assert.strictEqual(store.deck.tags.s1.tag, 'mine');
});

test('screen: a critical needs its own y; bulk mine leaves it out; the held row never moves', async () => {
  const g = await game('triage-screen.js');
  const { t, store } = screen(g, { signals: [sig(1, { severity: 'critical' }), sig(2), sig(3)], held: [{ module: 'stalkerware_scan', title: 'x' }] });
  t.html();
  // The cursor starts on the held row: every verdict key leaves it alone.
  for (const a of ['mine', 'threat', 'closer', 'noted', 'select', 'cat:dev']) t.act(a);
  assert.deepStrictEqual(store.deck.tags, {});
  assert.strictEqual(t.state.selected.size, 0);
  t.act('down'); // the critical
  t.act('cat:other');
  assert.strictEqual(t.state.ask.kind, 'critical');
  t.act('expand'); // Enter isn't yes for a critical
  assert.deepStrictEqual(store.deck.tags, {});
  t.act('down'); // moving on drops the question
  assert.strictEqual(t.state.ask, null);
  t.act('top');
  t.act('select'); // held: not selectable
  t.act('down'); t.act('select'); t.act('down-select'); t.act('down-select');
  assert.strictEqual(t.state.selected.size, 3);
  t.act('mine');
  assert.strictEqual(t.state.ask.kind, 'bulk');
  assert.strictEqual(t.state.ask.count, 2);
  assert.strictEqual(t.state.ask.skipped, 1);
  t.act('yes');
  await new Promise((r) => setTimeout(r, 0));
  assert.deepStrictEqual(Object.keys(store.deck.tags).sort(), ['s2', 's3']);
  assert.deepStrictEqual(store.awards, [], 'bulk pays only rows that were opened');
});
