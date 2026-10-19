'use strict';
// The runner carries out every effect field the games emit (contract R6, R9,
// R10): steps, checklist, hint, focus, off, warning, link, recheck {module,
// modules}, and the view's siblings and results. One real effect from each
// game, played through runner.js and drawn by views/mission-run.js; every
// line escaped.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');

const M = path.join(__dirname, '..', 'renderer', 'missions');
const imp = (...p) => import(pathToFileURL(path.join(M, ...p)).href);
const view = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'views', 'mission-run.js')).href);
const FIX = path.join(__dirname, 'fixtures', 'missions');

async function kit() {
  const [Run, C, R, I, V] = await Promise.all([imp('runner.js'), imp('contract.js'), imp('research.js'), imp('games', 'index.js'), view()]);
  const reg = await I.loadGames();
  return { Run, C, R, V, games: reg.games };
}
// Every synthetic finding the game fixtures hold, as items.
function fixtureItems(C) {
  const out = [];
  for (const f of fs.readdirSync(FIX).filter((x) => x.endsWith('.json') && x !== 'macos-landing.json')) {
    const d = JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8'));
    const lists = [d.findings, d.notes, d.darwin, d.win32, ...(Array.isArray(d.modules) ? d.modules.map((m) => (m.findings || []).map((x) => ({ module: m.name, ...x }))) : [])];
    for (const l of lists) if (Array.isArray(l)) for (const x of l) if (x && typeof x === 'object' && x.module) out.push(C.makeItem(x));
  }
  return out;
}
const ctxOf = (C, R, mode = 'standard', platform = 'darwin') => C.testContext({ mode, platform, resolve: (l) => R.resolveLink(l, { mode, platform }) });

// The first (item, decision) of `game` whose effect passes `want`.
function find(game, items, ctx, want) {
  for (const item of [...game.practice.items, ...items]) {
    let ds = [];
    try { ds = game.decisions(item, ctx) || []; } catch (_) { ds = []; }
    for (const d of ds) if (d && d.effect && want(d.effect, d, item)) return { item, d };
  }
  return null;
}

// Play `d` on `item` (with a sibling after it), confirming a warning, and draw the screen.
function play(k, game, item, d, ctx) {
  const { Run, V } = k;
  const sib = { ...item, key: `${item.key}#2` };
  let r = Run.choose(Run.startRun({ id: 'm', type: game.type, items: [item, sib] }), d.id, game, ctx);
  const warned = r.run.phase === 'confirm' && !r.act;
  if (warned) r = Run.confirmPending(r.run, game, ctx);
  const v = Run.viewFor(r.run, game, ctx, {});
  const html = V.renderMissionScreen({ mission: { id: 'm', type: game.type, district: 'gatehouse', title: game.title, part: 1, of: 1 }, run: r.run, view: v,
    mode: ctx.mode, districtName: 'The Gatehouse', cardHtml: '', research: {}, place: 'The Old Mill' });
  return { r, v, html, warned };
}
const text = (h) => h.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, '\'').replace(/&quot;/g, '"').replace(/\s+/g, ' ');

test('door: Not mine shows the switch-off checklist under its own heading (off), after the warning when it alerts', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const hit = find(k.games.door, fixtureItems(k.C), ctx, (e) => e.kind === 'closer' && e.off === true);
  assert.ok(hit);
  const { html, warned, v } = play(k, k.games.door, hit.item, hit.d, ctx);
  assert.strictEqual(warned, hit.d.effect.warning === true, 'a warned one shows the removal warning first (R6)');
  if (warned) assert.strictEqual(v.warning, k.Run.REMOVAL_WARNING);
  // A warned closer, made up: confirm first, then the steps with the warning line.
  const g = { ...k.games.door, decisions: () => [{ id: 'x', label: { standard: 'X', city: 'X' }, effect: { kind: 'closer', off: true, warning: true, checklist: ['Open it.'] } },
    { id: 'y', label: { standard: 'Y', city: 'Y' }, effect: { kind: 'later' } }] };
  const w = play(k, g, hit.item, g.decisions()[0], ctx);
  assert.ok(w.warned);
  assert.strictEqual(w.v.warning, k.Run.REMOVAL_WARNING);
  assert.match(w.html, /To switch it off/);
  const first = k.Run.choose(k.Run.startRun({ id: 'm', items: [hit.item] }), 'x', g, ctx);
  assert.strictEqual(first.act, null, 'nothing shown before the warning is read');
  assert.strictEqual(first.run.phase, 'confirm');
  assert.match(html, /<p class="label mx-guide-head">To switch it off<\/p><ol class="mx-checklist">/);
  for (const line of hit.d.effect.checklist) assert.ok(text(html).includes(line), line);
});

test('keyring: Hand back opens the first key’s page and shows the steps for its other keys', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const f = (code, service) => ({ module: 'app_permissions', code: `security.app_permissions.${code}`, title: 't', severity: 'warning', data: { service, apps: ['com.example.alpha'] } });
  const a = f('camera_access', 'kTCCServiceCamera'); const b = f('microphone_access', 'kTCCServiceMicrophone');
  const item = k.C.makeItem(a, { key: 'app|com.example.alpha', app: { subject: 'com.example.alpha', name: '' }, findings: [a, b],
    keys: [{ permission: 'kTCCServiceCamera', finding: a }, { permission: 'kTCCServiceMicrophone', finding: b }] });
  const d = k.games.keyring.decisions(item, ctx).find((x) => x.id === 'hand_back');
  const { r, html } = play(k, k.games.keyring, item, d, ctx);
  assert.strictEqual(r.act.kind, 'settings');
  assert.match(r.act.url, /Privacy_Camera/);
  assert.match(html, /<ol class="mx-steps"><li>Also switch off Microphone for com\.example\.alpha in System Settings/);
  assert.strictEqual(r.run.index, 0, 'the item stays open while the person changes it');
});

test('loadout: a note with steps is answered and its steps stay on screen until NEXT', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const hit = find(k.games.loadout, fixtureItems(k.C), ctx, (e) => e.kind === 'note' && Array.isArray(e.steps) && e.steps.length && !e.warning);
  assert.ok(hit);
  const { r, html, v } = play(k, k.games.loadout, hit.item, hit.d, ctx);
  assert.strictEqual(r.run.results.length, 1, 'answered');
  assert.ok(v.showing);
  assert.match(html, /data-act="mx-continue">NEXT ▶/);
  assert.doesNotMatch(html, /data-act="mx-decide:/, 'no second decision on an answered item');
  for (const line of hit.d.effect.steps) assert.ok(text(html).includes(line), line);
  const next = k.Run.proceed(r.run);
  assert.strictEqual(next.index, 1);
  assert.strictEqual(next.guide, null);
});

test('seal: a link effect carries its look-up in effect.link and its steps per mode; warned ones confirm first', async () => {
  const k = await kit();
  for (const mode of ['standard', 'city']) {
    const ctx = ctxOf(k.C, k.R, mode);
    const hit = find(k.games.seal, fixtureItems(k.C), ctx, (e) => e.kind === 'link' && e.link && e.steps && !Array.isArray(e.steps) && e.warning === true);
    assert.ok(hit, mode);
    const { r, html, warned } = play(k, k.games.seal, hit.item, hit.d, ctx);
    assert.ok(warned);
    assert.ok(r.act && (r.act.kind === 'link' || r.act.kind === 'settings'));
    if (hit.d.effect.link.kind === 'lookup') assert.strictEqual(r.act.url === null, mode === 'city', 'city: a look-up is words, never a link');
    for (const line of hit.d.effect.steps[mode]) assert.ok(text(html).includes(line), `${mode}: ${line}`);
    if (mode === 'city') assert.deepStrictEqual(k.C.checkCityWords(html), []);
  }
});

test('switchboard: an odd line is answered, its close-it steps shown, and the act names its module', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const hit = find(k.games.switchboard, fixtureItems(k.C), ctx, (e) => e.kind === 'odd' && Array.isArray(e.steps) && e.steps.length);
  assert.ok(hit);
  const { r, html } = play(k, k.games.switchboard, hit.item, hit.d, ctx);
  assert.strictEqual(r.act.kind, 'odd');
  assert.strictEqual(r.act.module, hit.item.finding.module);
  assert.match(html, /mx-steps/);
  for (const line of hit.d.effect.steps) assert.ok(text(html).includes(line), line);
});

test('locker: Look closer shows its checklist under the focus heading; the card gets siblings and results', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const hit = find(k.games.locker, fixtureItems(k.C), ctx, (e) => e.kind === 'closer' && e.focus === 'check');
  assert.ok(hit);
  const { r, html, v } = play(k, k.games.locker, hit.item, hit.d, ctx);
  assert.match(html, /data-focus="check"><p class="intel">[^<]+<\/p><p class="label mx-guide-head">What to check<\/p><ol class="mx-checklist">/, 'hint, then the checklist');
  assert.strictEqual(v.closer, true);
  assert.deepStrictEqual(v.siblings.map((x) => x.key), [`${hit.item.key}#2`]);
  // Another decision recorded: the results reach the view.
  const later = k.games.locker.decisions(hit.item, ctx).find((x) => x.effect.kind !== 'closer' && !x.effect.warning && ['later', 'keep', 'mark', 'recheck'].includes(x.effect.kind));
  const r2 = k.Run.choose(r.run, later.id, k.games.locker, ctx);
  const v2 = k.Run.viewFor(r2.run, k.games.locker, ctx, {});
  assert.deepStrictEqual(v2.results.map((x) => x.decision), [later.id]);
});

test('locks: Done re-checks the item’s modules ({ module, modules }); Turn it on shows its hint', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const item = k.games.locks.practice.items[0];
  const ds = k.games.locks.decisions(item, ctx);
  const done = play(k, k.games.locks, item, ds.find((x) => x.id === 'done'), ctx);
  assert.strictEqual(done.r.act.kind, 'recheck');
  assert.deepStrictEqual(done.r.act.modules, ['automatic_updates']);
  const on = play(k, k.games.locks, item, ds.find((x) => x.id === 'on'), ctx);
  assert.strictEqual(on.r.act.kind, 'settings');
  assert.match(on.html, /<p class="intel">Opens the settings page\. You make the change there\.<\/p>/);
  // modules wins over the item's own checks, deduplicated.
  const g = { ...k.games.simple, decisions: () => [{ id: 'a', label: { standard: 'A', city: 'A' }, effect: { kind: 'recheck', module: 'x_mod', modules: ['y_mod', 'x_mod'] } }, { id: 'b', label: { standard: 'B', city: 'B' }, effect: { kind: 'later' } }] };
  assert.deepStrictEqual(k.Run.choose(k.Run.startRun({ id: 'm', items: [item] }), 'a', g, ctx).act.modules, ['y_mod', 'x_mod']);
});

test('junkyard: a link effect’s intent in effect.link becomes a look-up (a link in standard, words in city)', async () => {
  const k = await kit();
  for (const mode of ['standard', 'city']) {
    const ctx = ctxOf(k.C, k.R, mode);
    const crash = k.C.makeItem({ module: 'app_crash_analyzer', code: 'performance.app_crash_analyzer.frequent_crashes', title: 'x', severity: 'warning',
      data: { check: 'frequent_crashes', app: 'Example Editor', count: 9 } });
    const hit = find(k.games.junkyard, [crash, ...fixtureItems(k.C)], ctx, (e) => e.kind === 'link' && e.link && e.link.kind === 'lookup');
    assert.ok(hit, mode);
    const { r } = play(k, k.games.junkyard, hit.item, hit.d, ctx);
    assert.strictEqual(r.act.kind, 'link');
    if (mode === 'city') { assert.strictEqual(r.act.url, null); assert.match(r.act.text, /on another device/); } else assert.match(r.act.url, /^https:\/\/duckduckgo\.com\/\?q=/);
  }
});

test('notes: Signal, odd hands the runner its module and code to open a mission of that type', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const hit = find(k.games.notes, fixtureItems(k.C), ctx, (e) => e.kind === 'odd' && e.module);
  assert.ok(hit);
  const { r } = play(k, k.games.notes, hit.item, hit.d, ctx);
  assert.deepStrictEqual({ kind: r.act.kind, module: r.act.module, code: r.act.code }, { kind: 'odd', module: hit.item.finding.module, code: hit.item.finding.code || null });
  assert.strictEqual(r.run.index, 1, 'nothing to show: on to the next note');
});

test('simple: I did this re-checks the item’s own checks', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const item = k.C.makeItem({ module: 'battery_health', title: 'Worn', data: {} }, { seen_in: ['battery_health', 'power_settings'] });
  const { r } = play(k, k.games.simple, item, k.games.simple.decisions(item, ctx).find((d) => d.effect.kind === 'recheck'), ctx);
  assert.deepStrictEqual(r.act.modules, ['battery_health', 'power_settings']);
});

test('every guide line is escaped: hostile steps, checklists, hints and focus ids render inert', async () => {
  const k = await kit();
  for (const mode of ['standard', 'city']) {
    const ctx = ctxOf(k.C, k.R, mode);
    for (const h of k.C.HOSTILE) {
      const g = { ...k.games.simple, decisions: () => [
        { id: 'a', label: { standard: 'A', city: 'A' }, hint: h, effect: { kind: 'closer', focus: h, checklist: [h], steps: { standard: [h], city: [h] } } },
        { id: 'b', label: { standard: 'B', city: 'B' }, effect: { kind: 'note', steps: [h, 7, null] } }] };
      const item = k.C.makeItem({ module: 'm', title: 't' });
      for (const id of ['a', 'b']) {
        const { html } = play(k, g, item, g.decisions()[id === 'a' ? 0 : 1], ctx);
        assert.deepStrictEqual(k.C.checkInert(html), [], `${mode} ${id} ${JSON.stringify(h).slice(0, 20)}`);
        assert.doesNotMatch(html, /data-focus="[^"]*[<>]/);
      }
    }
  }
});
