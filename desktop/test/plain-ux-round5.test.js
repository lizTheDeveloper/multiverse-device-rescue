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
  test(`a game checkup that stopped (${stage}) hands the city its results with the error`, async () => {
    const p = page();
    p.byId('btn-play-game').click();
    p.pick('wifi');
    assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
    const doc = stoppedDoc(stage);
    await p.finish(doc);
    assert.deepStrictEqual(p.calls.game.slice(2), ['scanFailed']);
    assert.strictEqual(p.calls.last.args[1], doc, 'the stopped document itself, with its stopped stage');
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
  assert.deepStrictEqual(p.calls.game.slice(2), ['scanFailed']);
  const sent = p.calls.last.args[1];
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
  assert.strictEqual(p.calls.last.args[1], undefined, 'no doc: Training with the error');
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('if the city can’t draw the stopped checkup, Plain shows the stopped screen with what it found', async () => {
  const p = page();
  p.sandbox.RescueGame.scanFailed = () => false;
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

// The engine decides the warning (rescue/safety_scope.py: removal_alert and
// safety_note, by finding code); the text inference never takes it away.
async function listOfDoc(modules) {
  const p = page({ store: { 'device-rescue.display': 'standard' }, ready: false });
  p.sandbox.FixFlow.fixControlsHtml = FixFlow.fixControlsHtml;
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish({ schema_version: 1, platform: 'darwin', modules });
  if (p.shown().includes('question')) p.answer('known');
  return p.byId('results-groups').innerHTML;
}
test('the engine’s removal_alert drives the banner and the card’s line, on any check, with no note or warning text', async () => {
  const flagged = { title: 'Screen Sharing is on', severity: 'warning', category: 'security', description: 'Others can see your screen.',
    code: 'security.sharing_services.screen_sharing', removal_alert: true, data: {} };
  const html = await listOfDoc([mod('some_check_nobody_lists', [flagged,
    { title: 'Disk nearly full', severity: 'warning', category: 'storage', description: 'Low space.', data: {} }])]);
  assert.strictEqual(html.split('id="results-safety"').length, 2, 'one banner');
  const card = html.split('<li class="finding-card').find((c) => /Screen Sharing is on/.test(c));
  assert.match(card, /data-safety-line/);
  assert.strictEqual(Q.noteFor('standard', { ...flagged, module: 'some_check_nobody_lists' }), 'line', 'never inferred away');
});
test('a merged card carries the warning when any of its findings has the engine’s flag', async () => {
  const a = { title: 'Remote access is on', severity: 'warning', category: 'security', description: 'On.', same_key: 'remote:on', data: {} };
  const html = await listOfDoc([mod('first_check', [a]), mod('second_check', [{ ...a, removal_alert: true }])]);
  const cards = html.split('<li class="finding-card').slice(1);
  assert.strictEqual(cards.length, 1, 'one item');
  assert.match(cards[0], /data-safety-line/);
  assert.match(html, /id="results-safety"/);
});
test('a warning only inferred from text on a check that can’t monitor and offers no removal stays off', async () => {
  const html = await listOfDoc([mod('disk_space', [{ title: 'Old crash logs', severity: 'warning', category: 'storage',
    description: 'Removing them can alert nobody, but deleting them can notify the reporter.', data: {} }], { category: 'performance' })]);
  assert.doesNotMatch(html, /results-safety|data-safety-line/);
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
      closest(sel) { return sel === '[data-fix-module]' ? els.card : sel === '[data-card-key]' ? els.outer : null; },
      hasAttribute(a) { return a in attrs; }, getAttribute(a) { return attrs[a]; }, setAttribute() {}, focus() {},
      querySelector(sel) {
        if (name === 'panel') return sel === '[data-fix-safety]' ? els.safety : null;
        // The line is on the finding card, outside the fix control's own box.
        if (name === 'outer') return sel === '[data-safety-line]' ? els.line : null;
        if (sel === '[data-safety-line]') return null;
        return { '[data-fix-panel]': els.panel, '[data-fix-status]': els.status, '[data-fix-open]': els.open, '[data-safety-line]': els.line }[sel] || null;
      } };
    els[name] = el;
    return el;
  };
  mk('outer', { 'data-card-key': '0' });
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

// ---------------------------------------------------------------------------
// (7) Every number on the list comes from NotChecked.scanCounts.
// ---------------------------------------------------------------------------
const fs = require('node:fs');
const path = require('node:path');
const NC = require('../renderer/not-checked.js');
const fixture = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));

for (const file of ['replay-full.json', 'replay-errors.json', 'replay-held.json']) {
  test(`the list’s numbers are scanCounts’ (${file}): the sentence, the cards and the not-checked line`, async () => {
    const doc = fixture(file);
    const p = page();
    // The real sentence (the harness stubs ClearList's page wiring, not its words).
    const stub = p.sandbox.ClearList;
    const real = require('../renderer/clear-list.js');
    p.sandbox.ClearList = new Proxy(stub, { get: (t, k) => (k === 'summaryText' ? real.summaryText : t[k]) });
    p.byId('btn-get-started').click();
    p.pick('hacked');
    p.byId('btn-run-scan').click();
    await p.finish(doc);
    if (p.shown().includes('question')) p.answer('known');
    const c = NC.scanCounts(doc, { mode: 'standard' });
    const summary = p.byId('results-summary').innerHTML;
    if (c.todo) assert.match(summary, new RegExp(`\\b${c.todo} things? on your list`));
    if (c.notes) assert.match(summary, new RegExp(`\\b${c.notes} good-to-know notes?`));
    const html = p.byId('results-groups').innerHTML;
    const counted = (html.match(/data-card-counts="1"/g) || []).length;
    assert.strictEqual(counted, c.todo + c.markedItems + (html.match(/finding-card--note"[^>]*data-card-counts="1"/g) || []).length,
      'one card on the list per item');
    if (c.didntFinish || c.partly) assert.strictEqual(p.byId('results-errors-line').textContent, NC.notCheckedLine(c));
    await tick();
  });
}

// ---------------------------------------------------------------------------
// (3) Good to know: a few areas, not one box per check.
// ---------------------------------------------------------------------------
test('Good to know on the full replay: a handful of areas, each counted, all closed', async () => {
  const doc = fixture('replay-full.json');
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  const info = p.byId('results-groups').innerHTML.split('data-results-group="info"')[1];
  const areas = [...info.matchAll(/<span class="info-area__name">([^<]+)<\/span> <span class="results-group__count">(\d+)<\/span>/g)];
  assert.ok(areas.length >= 2 && areas.length <= 6, `${areas.length} areas`);
  const c = NC.scanCounts(doc);
  assert.strictEqual(areas.reduce((n, a) => n + Number(a[2]), 0), c.notes, 'the areas add up to the notes count');
  assert.doesNotMatch(info, /<details[^>]* open/, 'everything starts closed');
  await tick();
});

test('a note’s area is its check’s category; anything unknown goes to “Everything else”', () => {
  const app = require('../renderer/app.js');
  const doc = { modules: [{ name: 'a', category: 'network' }, { name: 'b', category: 'weird' }, { name: 'c', category: 'security' }] };
  const areas = app.groupByArea([{ module: 'a' }, { module: 'b' }, { module: 'c' }, { module: 'c' }], 'standard', doc);
  assert.deepStrictEqual(areas.map((a) => [a.name, a.checks.map((x) => x.findings.length)]),
    [['Security', [2]], ['Network', [1]], ['Everything else', [1]]]);
});

// ---------------------------------------------------------------------------
// (4) After the list: one next step, the rest in one closed box.
// ---------------------------------------------------------------------------
test('after the list: the guide is the one next step; lessons, progress, AI copy, the web game and the report are in one closed box', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  const after = html.slice(html.indexOf('<div id="results-groups">'), html.indexOf('id="btn-start-over"'));
  const more = /<details id="results-more"[^>]*>([\s\S]*)<\/details>\s*<dialog/.exec(after);
  assert.ok(more, 'one closed box');
  assert.doesNotMatch(/<details id="results-more"[^>]*>/.exec(after)[0], /\bopen\b/);
  for (const id of ['results-lessons', 'progress-link', 'results-copy-all', 'results-learn', 'results-tech']) {
    assert.ok(more[1].includes(`id="${id}"`), `${id} is inside it`);
  }
  const outside = after.replace(more[0], '');
  assert.match(outside, /id="results-next"/);
  assert.match(outside, /id="btn-open-guide" class="btn btn--primary"/, 'the one primary button after the list');
  assert.strictEqual((outside.match(/btn--primary/g) || []).length, 1);
  assert.doesNotMatch(more[1], /<dialog/, 'the progress dialog isn’t inside a closed box');
});

// ---------------------------------------------------------------------------
// (5) The stopped scan screen: the line by how it stopped; tech helpers get what it doesn't say.
// ---------------------------------------------------------------------------
async function stoppedScreen(stage, { log } = {}) {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  if (log) p.emit({ type: 'log', line: log });
  await p.finish(stoppedDoc(stage));
  return p;
}
test('the stopped scan screen: an assembly stop says every check ran; tech helpers don’t get the line again', async () => {
  const p = await stoppedScreen('assembly');
  const line = p.byId('scan-error-line').innerHTML;
  assert.match(line, /All 3 checks ran, but the report couldn’t be put together/);
  assert.doesNotMatch(line, /stopped before it finished/);
  assert.doesNotMatch(p.byId('scan-error-text').textContent, /stopped before it finished/);
  assert.strictEqual(p.byId('scan-error-tech').hidden, true, 'nothing more to say, so no fold');
  await tick();
});
test('the stopped scan screen: an early stop says how far it got; tech helpers get the end of the log', async () => {
  const p = await stoppedScreen('early', { log: 'Traceback (most recent call last): KeyError: apps' });
  assert.match(p.byId('scan-error-line').innerHTML, /stopped before it finished<\/strong> \(1 of 3 checks done\)/);
  const tech = p.byId('scan-error-text').textContent;
  assert.match(tech, /KeyError: apps/);
  assert.doesNotMatch(tech, /stopped before it finished/);
  assert.strictEqual(p.byId('scan-error-tech').hidden, false);
  await tick();
});
test('the log tail keeps the last lines only', () => {
  const app = require('../renderer/app.js');
  const text = Array.from({ length: 100 }, (_, i) => `line ${i}`).join('\n');
  const tail = app.logTail(text).split('\n');
  assert.strictEqual(tail.length, 40);
  assert.strictEqual(tail[39], 'line 99');
});

// ---------------------------------------------------------------------------
// (6) A checkup that stopped early: a count and a fold, not a wall of names.
// ---------------------------------------------------------------------------
test('stopped early: “N checks didn’t get to run because the checkup stopped”, the names under a fold', async () => {
  const never = Array.from({ length: 106 }, (_, i) => mod(`check_${i}`, [], { status: 'error', error: null, error_kind: 'stopped', complete: false, check_name: `Check ${i}` }));
  const doc = { schema_version: 1, platform: 'darwin',
    modules: [mod('remote_login_check', [{ title: 'Remote Login is on', severity: 'warning', description: 'On.', data: {} }]), ...never],
    stopped: { stage: 'early', reason: 'exit', exit_code: 1, done: 1, total: 107 }, partial: { done: 1, total: 107, stopped: 'early' } };
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(doc);
  p.byId('btn-scan-sofar').click();
  const list = p.byId('results-errors-list').innerHTML;
  assert.match(list, /<span>106 checks didn’t get to run because the checkup stopped\.<\/span>/);
  assert.match(list, /<details class="errors-list__names"><summary>See which \(106\)<\/summary>/);
  assert.doesNotMatch(list.split('<details')[0], /Check 5/, 'no names in the line itself');
  await tick();
});

test('a few names stay in the line; more than five go under the fold', () => {
  const app = require('../renderer/app.js');
  const item = (name) => ({ name, kind: 'failed', reason: '', raw: '' });
  const few = app.couldntCheckGroups(['A', 'B', 'C'].map(item)).groups[0];
  assert.strictEqual(few.line, '3 checks couldn’t run: A, B and C.');
  assert.deepStrictEqual(few.folded, []);
  const many = app.couldntCheckGroups(['A', 'B', 'C', 'D', 'E', 'F'].map(item)).groups[0];
  assert.strictEqual(many.line, '6 checks couldn’t run.');
  assert.deepStrictEqual(many.folded, ['A', 'B', 'C', 'D', 'E', 'F']);
});

// ---------------------------------------------------------------------------
// (8) P2-6: an app id with no app found says so, not "couldn't check just now".
// ---------------------------------------------------------------------------
test('P2-6: a row that is only an app id says no app was found for it, not “just now”', () => {
  const MarkFlow = require('../renderer/mark-flow.js');
  const fresh = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'fresh-round3.json'), 'utf8'));
  const f = fresh.modules.find((m) => m.name === 'app_permissions').findings.find((x) => x.markable);
  const html = MarkFlow.markControlsHtml(Object.assign({ module: 'app_permissions' }, f));
  const row = /com\.amical\.desktop[\s\S]*?(?=<\/li>)/.exec(html.split('Tick the apps you know and use')[1])[0];
  assert.ok(row.includes(MarkFlow.NO_APP));
  assert.doesNotMatch(row, /just now/);
});
