const test = require('node:test');
const assert = require('node:assert');

test('boot sets both opt-out keys before importing any game code', async () => {
  const { boot } = await import('../renderer/game/boot-core.js');
  const store = {}; const storage = { setItem: (k, v) => { store[k] = v; }, getItem: (k) => store[k] ?? null };
  const seenAtImport = [];
  const events = [];
  const win = { dispatchEvent: (e) => events.push(e.type), localStorage: storage };
  const controller = { show() {} };
  await boot({
    storage, win,
    importModule: async (spec) => {
      seenAtImport.push([spec, store['reclaim-city.analytics-off'], store['umami.disabled']]);
      if (spec.endsWith('controller.js')) return { createController: () => controller };
      return { scoutSprite: () => '' };
    },
  });
  assert.ok(seenAtImport.length >= 2);
  for (const [spec, a, u] of seenAtImport) assert.deepStrictEqual([a, u], ['1', '1'], spec);
  assert.strictEqual(win.RescueGame, controller);
  assert.deepStrictEqual(events, ['rescue-game-ready']);
});

test('applyOptOut survives storage that throws', async () => {
  const { applyOptOut } = await import('../renderer/game/opt-out.js');
  assert.strictEqual(applyOptOut({ setItem() { throw new Error('denied'); } }), false);
  assert.strictEqual(applyOptOut(null), false);
});
