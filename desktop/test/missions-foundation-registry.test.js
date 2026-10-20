'use strict';
// Little missions: the game registry, the Odd Jobs fallback game, and the contract's covers checks.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const dir = path.join(__dirname, '..', 'renderer', 'missions');
const url = (rel) => pathToFileURL(path.join(dir, rel)).href;
const load = () => Promise.all([import(url('contract.js')), import(url('games/index.js')), import(url('games/simple.js')), import(url('types.js'))]);

test('Odd Jobs passes every contract check, on real-shaped items too', async () => {
  const [C, , S] = await load();
  const items = [
    C.makeItem({ module: 'battery_health', title: 'Battery is worn', data: { cycles: 900 } }),
    C.makeItem({ module: 'login_items', title: 'Helper', data: { label: 'com.example.h' }, markable: { id: 'm1', kind: 'background_task' } }),
    // The engine's real stalkerware finding (no removal_alert of its own), made fixable.
    C.makeItem({ ...require('./fixtures/monitoring-findings.json').stalkerware_scan.findings[0], module: 'stalkerware_scan', fixable: { will_change: 'x', how_to_undo: ['y'] } }),
  ];
  assert.ok(!items[2].finding.removal_alert && C.isAlertingItem(items[2]), 'warns through the module set alone');
  assert.deepStrictEqual(C.runContractChecks(S.default, items), []);
  const d = S.default.decisions(items[2], C.testContext());
  assert.strictEqual(d[0].effect.kind, 'later', 'the safe default leads');
  assert.ok(d.some((x) => x.effect.kind === 'fix'));
});

test('the registry works with only Odd Jobs present: every type falls back', async () => {
  const [C, I] = await load();
  const reg = await I.loadGames({ importer: async () => { throw new Error('missing'); } });
  for (const t of C.TYPE_IDS) assert.strictEqual(I.gameFor(reg, t).type, 'simple', t);
  assert.deepStrictEqual([...reg.own], ['simple']);
  assert.deepStrictEqual(reg.problems, []);
});

test('the real loader finds whichever games exist and falls back for the rest', async () => {
  const [C, I] = await load();
  const reg = await I.loadGames();
  for (const t of C.TYPE_IDS) {
    const exists = fs.existsSync(path.join(dir, 'games', `${t}.js`));
    const g = I.gameFor(reg, t);
    if (!exists) assert.strictEqual(g.type, 'simple', `${t} falls back`);
    if (reg.own.has(t)) assert.strictEqual(g.type, t);
  }
});

test('a game that breaks the shape, or says it is another type, falls back and is reported', async () => {
  const [, I] = await load();
  const reg = await I.loadGames({ importer: async (spec) => {
    if (spec.endsWith('/door.js')) return { default: { type: 'door' } };
    if (spec.endsWith('/seal.js')) return { default: { type: 'locks' } };
    throw new Error('missing');
  } });
  assert.strictEqual(I.gameFor(reg, 'door').type, 'simple');
  assert.strictEqual(I.gameFor(reg, 'seal').type, 'simple');
  assert.ok(reg.problems.some((p) => p.startsWith('door:')));
  assert.ok(reg.problems.some((p) => p.startsWith('seal:')));
});

test('covers: validated when present; two games claiming one finding are caught', async () => {
  const [C, I, S] = await load();
  assert.deepStrictEqual(C.checkCovers({ covers: [{ module: 'launch_agent_audit' }, { module: 'firewall_audit', codes: ['security.firewall_audit.global_state'] }] }), []);
  assert.ok(C.checkCovers({ covers: [{ module: '' }] }).length);
  assert.ok(C.checkCovers({ covers: [{ module: 'x', codes: [] }] }).length);
  assert.ok(C.checkCovers({ covers: 'x' }).length);
  assert.ok(C.validateGame({ ...S.default, covers: [{ module: 'Bad Name' }] }).some((p) => /covers/.test(p)));
  const a = { ...S.default, type: 'door', covers: [{ module: 'login_items' }] };
  const b = { ...S.default, type: 'keyring', covers: [{ module: 'login_items' }] };
  assert.ok(C.noDoubleClaims([a, b]).length);
  const reg = await I.loadGames({ importer: async (spec) => {
    if (spec.endsWith('/door.js')) return { default: a };
    if (spec.endsWith('/keyring.js')) return { default: b };
    throw new Error('missing');
  } });
  assert.ok(reg.problems.some((p) => /login_items/.test(p)));
});

// Every game that exists in this branch: the contract holds and no two claim one finding.
test('every registered game passes the contract, and no two games claim the same (module, code)', async () => {
  const [C, I, , T] = await load();
  const reg = await I.loadGames();
  for (const g of I.ownGames(reg)) assert.deepStrictEqual(C.runContractChecks(g, []), [], g.type);
  assert.deepStrictEqual(reg.problems, []);
  assert.deepStrictEqual(T.doubleClaims(T.buildTable(I.ownGames(reg))), []);
});

test('gameFor hands the Windows practice round on Windows, the default round elsewhere', async () => {
  const I = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'games', 'index.js')).href);
  const reg = await I.loadGames();
  const locks = I.gameFor(reg, 'locks');
  assert.ok(locks.practiceByPlatform && locks.practiceByPlatform.win32, 'Lock Run has a Windows round');
  const onWin = I.gameFor(reg, 'locks', 'win32');
  assert.strictEqual(onWin.practice, locks.practiceByPlatform.win32);
  assert.strictEqual(onWin.decisions, locks.decisions);
  assert.strictEqual(I.gameFor(reg, 'locks', 'win32'), onWin, 'the same object each time');
  assert.strictEqual(I.gameFor(reg, 'locks', 'darwin'), locks);
  assert.strictEqual(I.gameFor(reg, 'simple', 'win32'), I.gameFor(reg, 'simple'), 'no Windows round: the game itself');
});
