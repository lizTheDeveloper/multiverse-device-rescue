const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/progress.js');

const NOW = '2026-10-16T12:00:00Z';
const mission = (id, module = 'm', extra = {}) => ({ id, module, marked: false, ...extra });
const cityWith = (...ms) => ({ districts: [{ id: 'gatehouse', missions: ms, notes: [], fog: [] }] });
const memStore = (init = {}) => { const s = { ...init }; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, raw: s }; };

test('a new finding opens a mission', async () => {
  const { reconcile, emptyProgress } = await load();
  const { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'open');
  assert.strictEqual(progress.missions.a.module, 'm');
});

test('gone after a scan where its module ran: reclaimed', async () => {
  const { reconcile, emptyProgress } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  ({ progress } = reconcile(progress, cityWith(), new Set(['m']), NOW));
  assert.strictEqual(progress.missions.a.status, 'reclaimed');
});

test('gone because its module could not run: status kept, never credited', async () => {
  const { reconcile, emptyProgress } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  ({ progress } = reconcile(progress, cityWith(), new Set([]), NOW));
  assert.strictEqual(progress.missions.a.status, 'open');
});

test('reclaimed and back again: open, and reported as came back', async () => {
  const { reconcile } = await load();
  const start = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', updatedAt: NOW } } };
  const { progress, cameBack } = reconcile(start, cityWith(mission('a')), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'open');
  assert.deepStrictEqual(cameBack, ['a']);
});

test('marked by the person: yours, and never counted as fixed', async () => {
  const { reconcile, emptyProgress, countReclaimed } = await load();
  const { progress } = reconcile(emptyProgress(), cityWith(mission('a', 'm', { marked: true })), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'yours');
  assert.strictEqual(countReclaimed(progress), 0);
});

test('later survives a rescan while the finding is still there', async () => {
  const { reconcile, setStatus, emptyProgress } = await load();
  let p = setStatus(emptyProgress(), 'a', 'later', 'm', NOW);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  assert.strictEqual(p.missions.a.status, 'later');
});

test('recheckOutcome', async () => {
  const { recheckOutcome } = await load();
  const okModule = { ok: true, module: { name: 'm', status: 'ok', supported: true } };
  assert.strictEqual(recheckOutcome('a', cityWith(), okModule), 'reclaimed');
  assert.strictEqual(recheckOutcome('a', cityWith(mission('a')), okModule), 'not-yet');
  assert.strictEqual(recheckOutcome('a', cityWith(mission('a', 'm', { marked: true })), okModule), 'yours');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: false, error: 'engine_error' }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: false, error: 'not_rechecked' }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: true, module: { name: 'm', status: 'error' } }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: true, module: { name: 'm', status: 'ok', supported: false } }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), null), 'couldnt');
});

test('storage: round trip, corrupt JSON, wrong version, and storage that throws', async () => {
  const { loadProgress, saveProgress, STORE_KEY, emptyProgress, emptyDeck } = await load();
  const s = memStore();
  const p = { version: 3, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: {}, deck: emptyDeck() };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{not json' })), emptyProgress());
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{"version":9,"missions":{}}' })), emptyProgress());
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{"version":1,"missions":{"a":{"status":"bogus"}}}' })), emptyProgress());
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.deepStrictEqual(loadProgress(throwing), emptyProgress());
  assert.strictEqual(saveProgress(throwing, p), false);
  assert.deepStrictEqual(loadProgress(null), emptyProgress());
});

test('ranOkModules lists only modules that ran cleanly', async () => {
  const { ranOkModules } = await load();
  const s = ranOkModules({ modules: [
    { name: 'a', status: 'ok', supported: true }, { name: 'b', status: 'error' },
    { name: 'c', status: 'ok', supported: false }, null,
    { name: 'd' }, { name: 'e', supported: true }, { name: 'f', status: 'skipped', supported: true },
  ] });
  assert.deepStrictEqual([...s], ['a']);
});

test('a yours mission that vanishes is never credited as reclaimed', async () => {
  const { reconcile, emptyProgress, countReclaimed } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a', 'm', { marked: true })), new Set(['m']), NOW);
  ({ progress } = reconcile(progress, cityWith(), new Set(['m']), NOW));
  assert.strictEqual(progress.missions.a.status, 'yours');
  assert.strictEqual(countReclaimed(progress), 0);
});

test('records keep the district and title, so a reclaimed mission can still be shown', async () => {
  const { reconcile, emptyProgress } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a', 'm', { districtId: 'gatehouse', title: 'A' })), new Set(['m']), NOW);
  assert.deepStrictEqual([progress.missions.a.districtId, progress.missions.a.title], ['gatehouse', 'A']);
  ({ progress } = reconcile(progress, cityWith(), new Set(['m']), NOW));
  assert.deepStrictEqual([progress.missions.a.status, progress.missions.a.districtId, progress.missions.a.title], ['reclaimed', 'gatehouse', 'A']);
});

test('an older record without district or title still loads and is filled in from the scan', async () => {
  const { loadProgress, reconcile, STORE_KEY, emptyDeck } = await load();
  const old = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(old) }));
  assert.deepStrictEqual(p, { version: 3, missions: old.missions, lessons: {}, deck: emptyDeck() });
  const { progress } = reconcile(p, cityWith(mission('a', 'm', { districtId: 'gatehouse', title: 'A' })), new Set(['m']), '2026-10-17T00:00:00Z');
  assert.deepStrictEqual(progress.missions.a, { status: 'later', module: 'm', districtId: 'gatehouse', title: 'A', updatedAt: NOW });
});

test('setStatus keeps what it knew about the mission', async () => {
  const { setStatus } = await load();
  const p = { version: 2, missions: { a: { status: 'open', module: 'm', districtId: 'gatehouse', title: 'A', updatedAt: NOW } }, lessons: {} };
  const next = setStatus(p, 'a', 'later', 'm', NOW);
  assert.deepStrictEqual([next.missions.a.status, next.missions.a.districtId, next.missions.a.title], ['later', 'gatehouse', 'A']);
});

test('a saved version 1 store from Plan A migrates to version 3 and keeps every mission', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const v1 = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', updatedAt: NOW }, b: { status: 'later', module: 'n', updatedAt: NOW } } };
  const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify(v1) }));
  assert.deepStrictEqual(p, { version: 3, missions: v1.missions, lessons: {}, deck: emptyDeck() });
});

test('a corrupt lessons field is dropped but the missions survive', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const missions = { a: { status: 'open', module: 'm', updatedAt: NOW } };
  for (const lessons of [null, [], 'x', { l: { completedAt: 5 } }, { l: null }]) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 2, missions, lessons }) }));
    assert.deepStrictEqual(p, { version: 3, missions, lessons: {}, deck: emptyDeck() }, JSON.stringify(lessons));
  }
});

test('setLessonDone records completion only, and lessons never count as fixes', async () => {
  const { emptyProgress, setLessonDone, lessonDone, countReclaimed } = await load();
  const p = setLessonDone(emptyProgress(), 'password-asker', NOW);
  assert.deepStrictEqual(p.lessons, { 'password-asker': { completedAt: NOW } });
  assert.strictEqual(lessonDone(p, 'password-asker'), true);
  assert.strictEqual(lessonDone(p, 'other'), false);
  assert.strictEqual(countReclaimed(p), 0);
});

test('reconcile and setStatus keep finished lessons', async () => {
  const { emptyProgress, setLessonDone, reconcile, setStatus } = await load();
  let p = setLessonDone(emptyProgress(), 'locked-door', NOW);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  p = setStatus(p, 'a', 'later', 'm', NOW);
  assert.deepStrictEqual(p.lessons, { 'locked-door': { completedAt: NOW } });
  assert.strictEqual(p.version, 3);
});

test('a version 2 store migrates to version 3: missions and lessons kept, the deck starts empty', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const v2 = { version: 2, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } }, lessons: { 'locked-door': { completedAt: NOW } } };
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: JSON.stringify(v2) })),
    { version: 3, missions: v2.missions, lessons: v2.lessons, deck: emptyDeck() });
});

// Review Focus 4: old "yours" records stay as they were; MINE comes from the scan's own mark.
test('a version 1 or 2 store with missions marked as yours keeps them, and no game tag is made up from them', async () => {
  const { loadProgress, STORE_KEY } = await load();
  const missions = { 'launch_agent_audit|security.launch_agent_audit.agent_info|plist=/Users/a/Library/LaunchAgents/x.plist':
    { status: 'yours', module: 'launch_agent_audit', updatedAt: NOW } };
  for (const version of [1, 2]) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version, missions, lessons: {} }) }));
    assert.deepStrictEqual(p.missions, missions, `v${version}`);
    assert.deepStrictEqual(p.deck.tags, {}, `v${version}: MINE comes from data.marked_by_user, not old records`);
    assert.strictEqual(p.deck.points, 0);
  }
});

test('a version 3 store with a bad deck keeps its missions and lessons and starts the deck empty', async () => {
  const { loadProgress, STORE_KEY, emptyDeck } = await load();
  const missions = { a: { status: 'open', module: 'm', updatedAt: NOW } };
  const lessons = { l: { completedAt: NOW } };
  const good = emptyDeck();
  const sweep = { at: NOW, checks: 1, critical: 0, warning: 0, info: 0, fog: 0, checked: 1, secured: 1 };
  const bad = [null, [], 'x', { ...good, points: -1 }, { ...good, rank: 1.5 }, { ...good, drills: null },
    { ...good, tags: { a: { tag: 'delete', at: NOW, fp: 'f' } } }, { ...good, tags: { a: { tag: 'mine', at: NOW } } },
    { ...good, confirmed: { a: 5 } }, { ...good, once: { k: 1 } }, { ...good, sweep: { at: 5, keys: {} } },
    { ...good, sweeps: {} }, { ...good, sweeps: [{ at: NOW, checks: 1 }] }, { ...good, sweeps: [{ ...sweep, title: 'x', checks: -1 }] }];
  for (const deck of bad) {
    const p = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 3, missions, lessons, deck }) }));
    assert.deepStrictEqual(p, { version: 3, missions, lessons, deck: emptyDeck() }, JSON.stringify(deck));
  }
});

// Final review (deferred a): unknown keys are dropped, never stored; the rest survives.
test('a version 3 deck with unknown keys keeps its known fields and drops the rest, on load and on setDeck', async () => {
  const { loadProgress, setDeck, emptyProgress, STORE_KEY } = await load();
  const sweep = { at: NOW, checks: 1, critical: 0, warning: 0, info: 0, fog: 0, checked: 1, secured: 1 };
  const deck = { points: 35, rank: 0, drills: { right: 1, tried: 2, name: 'Ann' },
    tags: { 'm|c|plist=/a': { tag: 'threat', at: NOW, fp: 'abc', title: 'Unsigned helper' } },
    confirmed: { 'm|c|plist=/b': NOW }, once: { 'fix:m|c|plist=/b': true },
    sweep: { at: NOW, keys: { 'clue:m|c|plist=/a#maker': true }, path: '/Users/ann' },
    sweeps: [{ ...sweep, title: 'Unsigned helper' }], monitoringSeen: true, name: 'Ann' };
  const want = { points: 35, rank: 0, drills: { right: 1, tried: 2 },
    tags: { 'm|c|plist=/a': { tag: 'threat', at: NOW, fp: 'abc' } },
    confirmed: { 'm|c|plist=/b': NOW }, once: { 'fix:m|c|plist=/b': true },
    sweep: { at: NOW, keys: { 'clue:m|c|plist=/a#maker': true } }, sweeps: [sweep] };
  const loaded = loadProgress(memStore({ [STORE_KEY]: JSON.stringify({ version: 3, missions: {}, lessons: {}, deck }) }));
  assert.deepStrictEqual(loaded.deck, want);
  const set = setDeck(emptyProgress(), deck);
  assert.deepStrictEqual(set.deck, want);
  assert.doesNotMatch(JSON.stringify(set), /monitoringSeen|Ann|Unsigned helper/);
});

test('a version 3 store round-trips with its deck', async () => {
  const { loadProgress, saveProgress, emptyDeck } = await load();
  const s = memStore();
  const deck = { ...emptyDeck(), points: 35, drills: { right: 1, tried: 2 },
    tags: { 'm|c|plist=/a': { tag: 'threat', at: NOW, fp: 'abc' } }, confirmed: { 'm|c|plist=/b': NOW },
    once: { 'fix:m|c|plist=/b': true }, sweep: { at: NOW, keys: { 'clue:m|c|plist=/a#maker': true } },
    sweeps: [{ at: NOW, checks: 290, critical: 1, warning: 2, info: 30, fog: 3, checked: 4, secured: 3 }] };
  const p = { version: 3, missions: {}, lessons: {}, deck };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
});

test('setDeck changes only the deck; reconcile, setStatus and setLessonDone keep it', async () => {
  const { emptyProgress, emptyDeck, setDeck, reconcile, setStatus, setLessonDone } = await load();
  const deck = { ...emptyDeck(), points: 10 };
  let p = setLessonDone(emptyProgress(), 'l', NOW);
  p = setDeck(p, deck);
  assert.deepStrictEqual([p.deck, p.lessons.l.completedAt], [deck, NOW]);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  p = setStatus(p, 'a', 'later', 'm', NOW);
  p = setLessonDone(p, 'k', NOW);
  assert.strictEqual(p.deck.points, 10);
  assert.strictEqual(p.version, 3);
  assert.strictEqual(setDeck(p, { points: 'lots' }).deck.points, 10, 'a bad deck is refused');
});
