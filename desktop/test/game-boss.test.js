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

test('the count is of finished checks: a start event names the check now running', async () => {
  const { bossInit, bossApply, bossPercent } = await load();
  let b = bossApply(bossInit(), ev('start', 1, 4, 'security'));
  assert.strictEqual(b.index, 0);
  b = bossApply(b, ev('done', 1, 4, 'security'));
  assert.strictEqual(b.index, 1);
  b = bossApply(b, ev('start', 2, 4, 'network'));
  assert.strictEqual(b.index, 1);
  assert.strictEqual(bossPercent(b), 25);
});

// The sweep shows what is being checked right now, and a running log of
// finished checks, so long gaps never look like nothing is happening.
test('the check running now is named; a done event moves it into the log', async () => {
  const { bossInit, bossApply } = await load();
  let b = bossApply(bossInit(), { type: 'progress', phase: 'start', index: 1, total: 3, module: 'launch_agent_audit', category: 'security' });
  assert.deepStrictEqual(b.now, { module: 'launch_agent_audit', category: 'security', index: 1 });
  assert.deepStrictEqual(b.log, []);
  b = bossApply(b, { type: 'progress', phase: 'done', index: 1, total: 3, module: 'launch_agent_audit', category: 'security', findings: 2, error: null, supported: true });
  assert.strictEqual(b.now, null);
  assert.deepStrictEqual(b.log, [{ module: 'launch_agent_audit', category: 'security', index: 1, findings: 2, outcome: 'noted' }]);
});

test('the log tells a check that couldn’t run or crashed apart from one that noted nothing', async () => {
  const { bossInit, bossApply } = await load();
  const done = (module, extra) => ({ type: 'progress', phase: 'done', index: 1, total: 3, module, category: 'security', findings: 0, ...extra });
  let b = bossInit();
  b = bossApply(b, done('a', { supported: true, error: null }));
  b = bossApply(b, done('b', { supported: false, error: null }));
  b = bossApply(b, done('c', { supported: true, error: 'Module check timed out: c' }));
  b = bossApply(b, done('d', {}));
  assert.deepStrictEqual(b.log.map((e) => e.outcome), ['none', 'couldnt', 'couldnt', 'none']);
  assert.strictEqual(b.couldnt, 2);
});

test('a module name from the engine is kept only when it looks like one; the log is capped', async () => {
  const { bossInit, bossApply, LOG_KEEP } = await load();
  let b = bossApply(bossInit(), { type: 'progress', phase: 'start', index: 1, total: 3, module: '<img src=x>', category: 'security' });
  assert.strictEqual(b.now.module, null);
  for (let i = 1; i <= LOG_KEEP + 5; i += 1) b = bossApply(b, { type: 'progress', phase: 'done', index: i, total: LOG_KEEP + 5, module: 'm', category: 'network', findings: 0 });
  assert.strictEqual(b.log.length, LOG_KEEP);
  assert.strictEqual(b.log[b.log.length - 1].index, LOG_KEEP + 5);
});
