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
