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
  const { loadProgress, saveProgress, STORE_KEY, emptyProgress } = await load();
  const s = memStore();
  const p = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
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
