'use strict';
// Missions UX fixes, group A: the runner (missions/runner.js) and the mission
// screen (game/views/mission-run.js). Synthetic items only.
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
const ctxOf = (C, R, mode = 'standard') => C.testContext({ mode, platform: 'darwin', resolve: (l) => R.resolveLink(l, { mode, platform: 'darwin' }) });
const lockerItem = (C, id) => {
  const f = JSON.parse(fs.readFileSync(path.join(FIX, 'locker-mac.json'), 'utf8')).findings.find((x) => x.id === id);
  return C.makeItem(f, { key: `${f.module}:${f.id}` });
};
const L = (s) => ({ standard: s, city: s });
const D = (id, kind, more = {}) => ({ id, label: L(id), effect: { kind, ...more } });
const MISSION = { id: 'm', type: 'door', district: 'gatehouse', title: L('Things'), part: 1, of: 1 };
const screen = (k, run, v, extra = {}) => k.V.renderMissionScreen({ mission: MISSION, run, view: v, mode: 'standard', districtName: 'The Gatehouse',
  cardHtml: '', research: {}, place: 'The Old Mill', ...extra });
const text = (h) => h.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, '\'').replace(/&quot;/g, '"').replace(/\s+/g, ' ');

// --- P1-3: Look closer drops only itself ---

test('locker: after Look closer on a known-malware file, Quarantine stays (closer filtered by id, not effect kind)', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const item = lockerItem(k.C, 'known-hash');
  let run = k.Run.startRun({ id: 'm', type: 'locker', items: [item, { ...item, key: `${item.key}#2` }] });
  run = k.Run.choose(run, 'closer', k.games.locker, ctx).run;
  const ids = k.Run.viewFor(run, k.games.locker, ctx, {}).decisions.map((d) => d.id);
  assert.ok(ids.includes('quarantine'), ids.join(','));
  assert.ok(!ids.includes('closer'));
});

test('locker: after Look closer on a running miner, Stop it stays; choosing it answers the item and shows its steps until NEXT', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const item = lockerItem(k.C, 'known-miner');
  let run = k.Run.startRun({ id: 'm', type: 'locker', items: [item, { ...item, key: `${item.key}#2` }] });
  run = k.Run.choose(run, 'closer', k.games.locker, ctx).run;
  assert.deepStrictEqual(k.Run.viewFor(run, k.games.locker, ctx, {}).decisions.map((d) => d.id), ['stop', 'mine']);
  let r = k.Run.choose(run, 'stop', k.games.locker, ctx);
  if (r.run.phase === 'confirm' && !r.act) r = k.Run.confirmPending(r.run, k.games.locker, ctx);
  assert.deepStrictEqual(r.run.results.map((x) => x.decision), ['stop'], 'Stop it is a decision');
  const v = k.Run.viewFor(r.run, k.games.locker, ctx, {});
  assert.ok(v.showing);
  const html = screen(k, r.run, v);
  assert.match(html, /data-act="mx-continue">NEXT ▶/);
  assert.doesNotMatch(html, /data-act="mx-decide:/);
  assert.strictEqual(k.Run.proceed(r.run).index, 1);
});

test('a steps act stays open when the game offers a re-check for it (a lock: Show me how, then Done)', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const g = { ...k.games.simple, decisions: () => [D('on', 'closer', { checklist: ['Open it.'] }), D('done', 'recheck'), D('later', 'later')] };
  const item = k.C.makeItem({ module: 'm', title: 't' });
  const r = k.Run.choose(k.Run.startRun({ id: 'm', items: [item] }), 'on', g, ctx);
  assert.strictEqual(r.run.results.length, 0);
  assert.deepStrictEqual(k.Run.viewFor(r.run, g, ctx, {}).decisions.map((d) => d.id), ['on', 'done', 'later']);
});

// --- P1-2: practice feedback; P3: the step line once ---

// The practice screen for `game` at its current step, the card drawn by the game.
function practiceScreen(k, game, run, ctx) {
  const v = k.Run.viewFor(run, game, ctx, {});
  const card = String(game.render({ ...v, research: { rows: [], what: '', links: [] } }, ctx) || '');
  return { v, html: k.V.renderMissionScreen({ mission: { ...MISSION, type: game.type }, run, view: v, mode: ctx.mode, districtName: 'The Gatehouse', cardHtml: card, research: {} }) };
}
const practiceRun = (k, game) => k.Run.startPractice(k.Run.startRun({ id: 'm', type: game.type, items: [] }, { practiceDue: true }), game);

test('practice: a step with no expected move shows one GOT IT, never the decisions, and a move there is not judged', async () => {
  const k = await kit();
  for (const mode of ['standard', 'city']) {
    const ctx = ctxOf(k.C, k.R, mode);
    const game = k.games.door;
    assert.strictEqual(game.practice.script[0].expect, undefined, 'the door’s first step only explains');
    const run = practiceRun(k, game);
    const { v, html } = practiceScreen(k, game, run, ctx);
    assert.strictEqual(v.explain, true);
    assert.match(html, /data-act="mx-practice-next">GOT IT ▶</);
    assert.doesNotMatch(html, /mx-practice-move:/);
    assert.doesNotMatch(html, /That’s the move|Good move/);
    assert.strictEqual(k.Run.choosePractice(run, game, 'not-mine').answer, null, 'no praise for any move on an explain step');
    if (mode === 'city') assert.deepStrictEqual(k.C.checkCityWords(html), []);
  }
});

test('practice: a wrong move gets a calm "not quite" naming the move that fits; a right one is praised', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const game = k.games.door;
  const at = game.practice.script.findIndex((s) => s.expect === 'not-mine');
  let run = practiceRun(k, game);
  for (let i = 0; i < at; i += 1) run = k.Run.nextPracticeStep(run, game);
  const wrong = k.Run.choosePractice(run, game, 'mine');
  assert.strictEqual(wrong.answer.right, false);
  const t = text(practiceScreen(k, game, wrong.run, ctx).html);
  assert.match(t, /Not quite\. Here the move is Not mine\./);
  assert.doesNotMatch(t, /That’s the move/);
  const right = k.Run.choosePractice(run, game, 'not-mine');
  assert.strictEqual(right.answer.right, true);
  assert.match(text(practiceScreen(k, game, right.run, ctx).html), /That’s the move\./);
});

test('practice: `expect` may list every move that fits; a step’s `why` follows the move, right or wrong', async () => {
  const k = await kit();
  const ctx = ctxOf(k.C, k.R);
  const g = { ...k.games.simple, practice: { ...k.games.simple.practice,
    script: [{ item: 0, say: L('Which?'), expect: ['later', 'did'], why: L('Either is safe: nothing changes.') }] } };
  const run = practiceRun(k, g);
  for (const id of ['later', 'did']) {
    const r = k.Run.choosePractice(run, g, id);
    assert.strictEqual(r.answer.right, true, id);
    assert.match(text(practiceScreen(k, g, r.run, ctx).html), /That’s the move\. Either is safe: nothing changes\./);
  }
  const g2 = { ...g, decisions: () => [D('later', 'later'), D('did', 'recheck'), D('other', 'keep')] };
  const w = k.Run.choosePractice(practiceRun(k, g2), g2, 'other');
  assert.strictEqual(w.answer.right, false);
  assert.match(text(practiceScreen(k, g2, w.run, ctx).html), /Not quite\. Here the move is later\. Either is safe: nothing changes\./);
});
