// The sweep screen while the checkup runs: with the engine's plan, a district
// is SWEPT only once every check in it is done, and a swept district's
// finished checks can be previewed (read-only: nothing to start, store or
// score, and never "all clear" mid-sweep). Monitoring software stays held.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const boss = () => import('../renderer/game/boss.js');
const view = () => import('../renderer/game/views/boss.js');
const prog = (phase, index, total, category) => ({ type: 'progress', phase, index, total, module: 'm', category, findings: 0 });
const plan = (...cats) => ({ type: 'plan', total: cats.length, modules: cats.map((c, i) => ({ module: `m${i}`, category: c })) });
const entry = (name, category, findings, extra = {}) => ({ type: 'module', result: { name, category, status: 'ok', error: null,
  supported: true, unsupported_reason: null, findings, ...extra } });
const warn = (title) => ({ title, description: 'd', severity: 'warning', category: 'security', data: {} });
const scout = () => '';
const VERDICT = /\b(safe|clear|all clear|nothing found|nothing to (do|fix)|infected|hacked)\b/i;

async function toCity() {
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const { splitHeld } = await import('../renderer/game/held.js');
  // The controller's path, in city mode (quietDoc changes nothing there).
  return (d) => findingsToCity(splitHeld(d).doc);
}

test('with a plan: part-way until every check of a district is done, then SWEPT; unplanned districts are not waiting', async () => {
  const { bossInit, bossApply, bossDistricts } = await boss();
  let b = bossApply(bossInit(), plan('security', 'security', 'network'));
  const state = () => Object.fromEntries(bossDistricts(b).map((d) => [d.id, d.state]));
  assert.strictEqual(state().gatehouse, 'waiting');
  assert.strictEqual(state().junkyard, 'skip');
  b = bossApply(b, prog('start', 1, 3, 'security'));
  b = bossApply(b, prog('done', 1, 3, 'security'));
  b = bossApply(b, prog('start', 2, 3, 'network'));
  assert.strictEqual(state().gatehouse, 'part', 'one of its two checks done');
  assert.deepStrictEqual(bossDistricts(b).find((d) => d.id === 'gatehouse').checks, { done: 1, of: 2 });
  b = bossApply(b, prog('done', 2, 3, 'network'));
  assert.strictEqual(state().wires, 'swept');
  b = bossApply(b, prog('start', 3, 3, 'security'));
  b = bossApply(b, prog('done', 3, 3, 'security'));
  assert.strictEqual(state().gatehouse, 'swept');
});

test('the preview covers only swept districts and holds monitoring software out', async () => {
  const { bossInit, bossApply, bossPreview } = await boss();
  const city = await toCity();
  let b = bossApply(bossInit(), plan('security', 'security', 'network'));
  b = bossApply(b, prog('done', 1, 3, 'security'));
  b = bossApply(b, entry('stalkerware_scan', 'security', [warn('Monitoring app found')]));
  assert.deepStrictEqual(bossPreview(b, city), [], 'the Gatehouse is only part-way: nothing previewed');
  b = bossApply(b, prog('done', 2, 3, 'security'));
  b = bossApply(b, entry('launch_agents_audit', 'security', [warn('Unknown helper starts at login')]));
  const p = bossPreview(b, city);
  assert.strictEqual(p.length, 1);
  assert.strictEqual(p[0].id, 'gatehouse');
  assert.deepStrictEqual(p[0].missions.map((m) => m.title), ['Unknown helper starts at login']);
  assert.ok(!JSON.stringify(p).includes('Monitoring app found'), 'held: never a mission, even in a preview');
  // An older engine (no plan): no preview, as before.
  assert.deepStrictEqual(bossPreview(bossApply(bossInit(), entry('a', 'security', [warn('x')])), city), []);
});

test('the sweep screen shows SWEPT SO FAR read-only, with counts, never a verdict or a time', async () => {
  const { bossInit, bossApply } = await boss();
  const { renderBoss } = await view();
  const city = await toCity();
  let b = bossApply(bossInit(), plan('security', 'network', 'performance'));
  b = bossApply(b, prog('done', 1, 3, 'security'));
  b = bossApply(b, entry('launch_agents_audit', 'security', [warn('Unknown <b>helper</b>')]));
  b = bossApply(b, prog('done', 2, 3, 'network'));
  b = bossApply(b, entry('wifi', 'network', [], { status: 'error', error: 'timed out' }));
  b = bossApply(b, prog('start', 3, 3, 'performance'));
  const html = renderBoss({ boss: b, scout, tips: [], toCity: city });
  assert.match(html, /SWEPT SO FAR/);
  assert.match(html, /Missions open when the sweep is done\./);
  assert.match(html, /THE GATEHOUSE[\s\S]*1 MISSION WAITING[\s\S]*Unknown &lt;b&gt;helper&lt;\/b&gt;/);
  assert.match(html, /THE WIRES[\s\S]*1 COULDN’T CHECK/);
  assert.match(html, /NOT IN THIS SWEEP/);
  assert.match(html, /2 \/ 3 CHECKS/);
  const preview = /<section class="panel sweep-so-far"[\s\S]*?<\/section>/.exec(html)[0];
  assert.doesNotMatch(preview, /data-go="mission|data-go="district|data-fix|data-mark|<button/, 'nothing to start from the preview');
  const text = html.replace(/<[^>]+>/g, ' ');
  assert.doesNotMatch(text, VERDICT);
  assert.doesNotMatch(text, /\b(seconds?|minutes?|hours?|days?|weeks?)\b/i);
  // Without a toCity (or before anything is swept), no panel.
  assert.doesNotMatch(renderBoss({ boss: b, scout, tips: [] }), /SWEPT SO FAR/);
});

test('a swept district with nothing to do says only SWEPT: no "clear" mid-sweep', async () => {
  const { bossInit, bossApply } = await boss();
  const { renderBoss } = await view();
  let b = bossApply(bossInit(), plan('security', 'network'));
  b = bossApply(b, prog('done', 1, 2, 'security'));
  b = bossApply(b, entry('a', 'security', [{ title: 'note', severity: 'info', category: 'security', data: {} }]));
  const html = renderBoss({ boss: b, scout, tips: [], toCity: await toCity() });
  assert.match(html, /THE GATEHOUSE/);
  assert.doesNotMatch(html.replace(/<[^>]+>/g, ' '), VERDICT);
});

test('the controller previews through its own scan-to-city path, and app.js forwards the stream to the game', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'controller.js'), 'utf8');
  assert.match(src, /renderBoss\(\{[^}]*toCity: \(d\) => findingsToCity\(quietDoc\(splitHeld\(d\)\.doc\)\)/);
  const { GAME_SCAN_EVENTS } = require('../renderer/app.js');
  for (const t of ['progress', 'plan', 'module']) assert.ok(GAME_SCAN_EVENTS.has(t), t);
});
