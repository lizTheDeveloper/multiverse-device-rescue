// UX round 5, Plain view (group A5): the stopped checkup reaches the city,
// the removal warning once above the list, Good to know by area, one next
// step after the list, the stopped screens, and counts only from NotChecked.
const test = require('node:test');
const assert = require('node:assert');
const { page, tick } = require('./page-harness.js');
const FixFlow = require('../renderer/fix-flow.js');
const Q = require('../renderer/quiet-notes.js');

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


// ---------------------------------------------------------------------------
// (2) The removal warning: once above the list in standard mode, one bold line per card.
// ---------------------------------------------------------------------------
const SN = 'Before you remove or turn anything off: if you think someone close to you set this up to watch you, removing it can alert them. Talk to an advocate first. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.';
const watchy = (title, i) => ({ title, severity: 'warning', category: 'security', description: 'Starts by itself.',
  data: { label: `com.x.${i}`, path: `/Users/u/Library/LaunchAgents/com.x.${i}.plist` }, remediation: { safety_note: SN, steps: [] } });
async function listOf(mode, findings) {
  const p = page({ store: { 'device-rescue.display': mode }, ready: false });
  p.sandbox.FixFlow.fixControlsHtml = FixFlow.fixControlsHtml;
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish({ schema_version: 1, platform: 'darwin', modules: [mod('launch_agent_audit', findings)] });
  if (p.shown().includes('question')) p.answer('known');
  return p.byId('results-groups').innerHTML;
}

test('standard mode: three cards with the removal warning get one banner above the list and one bold line each', async () => {
  const html = await listOf('standard', [watchy('Task A', 1), watchy('Task B', 2), watchy('Task C', 3),
    { title: 'Disk nearly full', severity: 'warning', category: 'storage', description: 'Low space.', data: {} }]);
  assert.strictEqual(html.split('id="results-safety"').length, 2, 'one banner');
  assert.ok(html.indexOf('id="results-safety"') < html.indexOf('data-card-key'), 'above the list');
  assert.strictEqual(html.split(SN).length, 2, 'the note itself once, in the banner');
  assert.strictEqual(html.split('data-safety-line').length, 4, 'one bold line on each of the three cards');
  const disk = html.split('<li class="finding-card').find((c) => /Disk nearly full/.test(c));
  assert.doesNotMatch(disk, /data-safety-line/, 'not on a card that doesn’t carry it');
});

test('standard mode: no card carries the warning, so no banner', async () => {
  const html = await listOf('standard', [{ title: 'Disk nearly full', severity: 'warning', category: 'storage', description: 'Low space.', data: {} }]);
  assert.doesNotMatch(html, /results-safety/);
});

test('city mode (the Plain list): no banner; every card keeps its note in full', async () => {
  const html = await listOf('city', [watchy('Task A', 1), watchy('Task B', 2)]);
  assert.doesNotMatch(html, /results-safety|data-safety-line/);
  assert.strictEqual(html.split(SN).length, 3);
});

test('the banner helpers: notes said once, nothing without a line card', () => {
  const card = { note: 'line', full: ['A.', 'B.'] };
  assert.deepStrictEqual(Q.bannerNotes([card, { note: 'line', full: ['A.'] }, { note: 'none', full: ['C.'] }]), ['A.', 'B.']);
  assert.strictEqual(Q.bannerHtml([], String), '');
  assert.match(Q.bannerHtml(['A.'], String), /<details data-safety-details><summary>Read this first<\/summary><p>A\.<\/p><\/details>/);
});

test('the fix confirm says the warning, and the card’s own line hides meanwhile (not said twice)', async () => {
  const els = {};
  const mk = (name, attrs = {}) => {
    const el = { name, attrs, hidden: false, innerHTML: '',
      closest(sel) { return sel === '[data-fix-module]' ? els.card : null; },
      hasAttribute(a) { return a in attrs; }, getAttribute(a) { return attrs[a]; }, setAttribute() {}, focus() {},
      querySelector(sel) {
        if (name === 'panel') return sel === '[data-fix-safety]' ? els.safety : null;
        return { '[data-fix-panel]': els.panel, '[data-fix-status]': els.status, '[data-fix-open]': els.open, '[data-safety-line]': els.line }[sel] || null;
      } };
    els[name] = el;
    return el;
  };
  mk('card', { 'data-fix-module': 'launch_agent_audit' });
  mk('panel'); els.panel.hidden = true;
  mk('safety', { 'data-fix-safety': '' });
  mk('status'); mk('open', { 'data-fix-open': '' }); mk('cancel', { 'data-fix-cancel': '' }); mk('line', { 'data-safety-line': '' });
  const listeners = {};
  const root = { addEventListener(t, fn) { listeners[t] = fn; } };
  const click = (target) => listeners.click({ target: { closest: () => target } });
  FixFlow.attach(root, { runFix: async () => ({}) });
  click(els.open);
  assert.strictEqual(els.panel.hidden, false);
  assert.strictEqual(els.line.hidden, true, 'one warning on screen: the confirm’s');
  click(els.cancel);
  assert.strictEqual(els.line.hidden, false, 'back on the card once the confirm closes');
});
