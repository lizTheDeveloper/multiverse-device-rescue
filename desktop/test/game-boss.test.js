const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/boss.js');
const ev = (phase, index, total, category, findings = 0) => ({ type: 'progress', phase, index, total, module: 'm', category, findings });

test('districts go waiting → sweeping → swept as checks for their category run', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  let b = bossInit();
  assert.ok(bossDistricts(b).every((d) => d.state === 'waiting'));
  b = bossApply(b, ev('start', 1, 10, 'security'));
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'gatehouse').state, 'sweeping');
  b = bossApply(b, ev('done', 1, 10, 'security', 2));
  b = bossApply(b, ev('start', 2, 10, 'network'));
  const states = Object.fromEntries(bossDistricts(b).map((d) => [d.id, d.state]));
  assert.strictEqual(states.gatehouse, 'swept');
  assert.strictEqual(states.wires, 'sweeping');
  assert.strictEqual(states.junkyard, 'waiting');
  assert.strictEqual(b.found, 2);
});

test('no district state ever claims safe, clear or unsafe', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  const b = bossApply(bossInit(), ev('done', 1, 2, 'security', 9));
  for (const d of bossDistricts(b)) assert.ok(['waiting', 'sweeping', 'swept'].includes(d.state), d.state);
});

test('an unknown or missing category sweeps The Outskirts, which only appears once used', async () => {
  const { bossInit, bossApply, bossDistricts } = await load();
  let b = bossInit();
  assert.ok(!bossDistricts(b).some((d) => d.id === 'outskirts'));
  b = bossApply(b, ev('start', 1, 3, 'test'));
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'outskirts').state, 'sweeping');
  b = bossApply(b, { type: 'progress', phase: 'start', index: 2, total: 3 });
  assert.strictEqual(bossDistricts(b).find((d) => d.id === 'outskirts').state, 'sweeping');
});

test('odd numbers are clamped; non-progress and late events are ignored', async () => {
  const { bossInit, bossApply, bossFinish, bossPercent } = await load();
  let b = bossApply(bossInit(), ev('done', 50, 10, 'security', -3));
  assert.strictEqual(b.index, 10);
  assert.strictEqual(b.found, 0);
  assert.strictEqual(bossPercent(b), 100);
  const before = b;
  assert.strictEqual(bossApply(b, { type: 'log', line: 'x' }), before);
  assert.strictEqual(bossApply(b, null), before);
  b = bossFinish(b);
  assert.strictEqual(bossApply(b, ev('done', 1, 10, 'network', 5)), b);
  assert.strictEqual(bossPercent(bossInit()), 0);
  assert.strictEqual(bossPercent(bossApply(bossInit(), ev('done', 3, 0, 'security'))), 0);
});
