// UX round 5, Plain view (group A5): the stopped checkup reaches the city,
// the removal warning once above the list, Good to know by area, one next
// step after the list, the stopped screens, and counts only from NotChecked.
const test = require('node:test');
const assert = require('node:assert');
const { page, tick } = require('./page-harness.js');

const mod = (name, findings, extra = {}) => Object.assign({ name, category: 'security', status: 'ok', supported: true, findings }, extra);

// ---------------------------------------------------------------------------
// (1) A stopped checkup in the city: the city gets what it found.
// ---------------------------------------------------------------------------
function stoppedDoc(stage) {
  return { schema_version: 1, platform: 'darwin',
    modules: [mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }])],
    stopped: { stage, reason: 'exit', exit_code: 1, done: 1, total: 3 }, partial: { done: 1, total: 3, stopped: stage } };
}

for (const stage of ['assembly', 'early']) {
  test(`a game checkup that stopped (${stage}) hands the city its results, not a bare error`, async () => {
    const p = page();
    p.byId('btn-play-game').click();
    p.pick('wifi');
    assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
    const doc = stoppedDoc(stage);
    await p.finish(doc);
    assert.deepStrictEqual(p.calls.game.slice(2), ['scanDone'], 'never scanFailed while there are results');
    assert.strictEqual(p.calls.last.args[0], doc, 'the stopped document itself, with its stopped stage');
    assert.deepStrictEqual(p.shown(), ['city']);
    // The list behind the city shows the same stopped results, with nothing to act on.
    assert.match(p.byId('results-title').textContent, /before it stopped/);
    const html = p.byId('results-groups').innerHTML;
    assert.match(html, /Remote Login is on/);
    assert.ok(!html.includes('[FIX IT]') && !html.includes('[IT IS MINE]'));
    await tick();
  });
}

test('a game checkup that stopped streamed results first: the city gets them too', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  p.emit({ type: 'plan', total: 3, modules: [] });
  p.emit({ type: 'module', result: mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }]) });
  await p.fail('engine exited 1');
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanDone']);
  const sent = p.calls.last.args[0];
  assert.ok(sent.stopped && sent.modules.some((m) => m.name === 'remote_login_check'));
  assert.deepStrictEqual(p.shown(), ['city']);
  await tick();
});

test('a game checkup that stopped before any check reported still says so in the city', async () => {
  const p = page();
  p.byId('btn-play-game').click();
  p.pick('wifi');
  await p.fail('The checkup stopped before it finished. Nothing on your computer was changed.');
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanFailed']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('if the city can’t draw the stopped checkup, Plain shows the stopped screen with what it found', async () => {
  const p = page();
  p.sandbox.RescueGame.scanDone = () => false;
  p.byId('btn-play-game').click();
  p.pick('wifi');
  await p.finish(stoppedDoc('early'));
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-error').hidden, false);
  assert.strictEqual(p.byId('btn-scan-sofar').hidden, false);
  await tick();
});

module.exports = { mod };
