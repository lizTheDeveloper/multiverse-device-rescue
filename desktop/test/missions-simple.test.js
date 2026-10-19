'use strict';
// Odd Jobs (missions/games/simple.js): settings and readings aren't "something
// you did", and only a program shows who made it (audit P2-11).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const R = path.join(__dirname, '..', 'renderer', 'missions');
const load = async () => ({
  C: await import(pathToFileURL(path.join(R, 'contract.js')).href),
  S: await import(pathToFileURL(path.join(R, 'games', 'simple.js')).href),
});
const ids = (d) => d.map((x) => x.id);

test('a setting or a reading: Later / That’s fine / I changed it; never "I did this", never a maker line', async () => {
  const { C, S } = await load();
  const game = S.default;
  const volume = C.makeItem({ module: 'audio_check', severity: 'warning', title: 'Your volume is set very low (0%)', description: 'Your system volume is at 0%.', data: { volume_percent: 0 } });
  const battery = C.makeItem({ module: 'battery_health', severity: 'warning', title: 'Your battery is worn', description: 'It holds less charge than new.', data: { condition: 'Service Recommended' } });
  for (const item of [volume, battery]) {
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode });
      const d = game.decisions(item, ctx);
      assert.deepStrictEqual(ids(d), ['later', 'fine', 'did']);
      assert.strictEqual(d[1].effect.kind, 'keep');
      assert.strictEqual(d[2].effect.kind, 'recheck');
      assert.ok(!d.some((x) => /I did this|Done it/.test(x.label[mode])), 'no "I did this" on a setting');
      // The runner's research fills "Unknown maker" when a game gives no what: the card doesn't show it.
      const html = game.render({ item, research: { rows: [{ label: 'Volume percent', value: '0' }], what: 'Unknown maker', links: [] }, index: 0, total: 1 }, ctx);
      assert.doesNotMatch(html, /Unknown maker/);
      assert.doesNotMatch(html, /Volume percent/, 'evidence rows are the runner’s, not the card’s');
    }
  }
  assert.deepStrictEqual(C.runContractChecks(game, [volume, battery]), []);
});

test('a program keeps "I did this" and shows who made it', async () => {
  const { C, S } = await load();
  const game = S.default;
  const helper = C.makeItem({ module: 'some_audit', severity: 'warning', title: 'A helper', description: 'x', data: { label: 'com.example.helper' },
    made_by: [{ subject: 'com.example.helper', name: 'Example Ltd', verified: false }] });
  const d = game.decisions(helper, C.testContext());
  assert.deepStrictEqual(ids(d), ['later', 'did']);
  assert.strictEqual(d[1].label.standard, 'I did this');
  const html = game.render({ item: helper, research: { rows: [], what: 'Unknown maker', links: [] }, index: 0, total: 1 }, C.testContext());
  assert.match(html, /Unknown maker/);
  assert.ok(S.isProgram(helper.finding));
  assert.ok(!S.isProgram({ data: { path: '/usr/local' } }), 'a folder is not a program');
});
