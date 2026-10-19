'use strict';
// Little missions: what the profile keeps (practice rounds, remembered answers, round evidence) and the points.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { FORBIDDEN_ON_DISK, recordingStore, forbiddenWrites } = require('./disk-words.js');

const url = (rel) => pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', rel)).href;
const load = () => Promise.all([import(url('profile/player-profile.js')), import(url('profile/item-bank.js')), import(url('ledger.js')),
  import(url('profile/recipe-box.js'))]);
const NOW = '2026-10-19T10:00:00.000Z';

test('practice rounds and remembered answers survive a save and a load, with nothing telling on disk', async () => {
  const [P, , , RB] = await load();
  let p = P.emptyProfile(NOW);
  p = P.markRound(p, 'door', 'played', NOW);
  p = P.markRound(p, 'keyring', 'skipped', NOW);
  p = P.markRound(p, 'nope', 'played', NOW);
  p = P.keepAnswer(p, 'm|stalkerware_scan|security.x|/Applications/Watcher.app', 'bcdfghj', 'not-mine-safe', NOW);
  const store = recordingStore();
  assert.ok(P.saveProfile(store, p, { seed: 1234, mode: 'city' }));
  assert.deepStrictEqual(forbiddenWrites(store), []);
  const text = JSON.stringify(RB.decode(store.getItem(P.PROFILE_KEY)));
  assert.doesNotMatch(text, FORBIDDEN_ON_DISK, 'decoded, the box still names nothing');
  assert.doesNotMatch(text, /Watcher|Applications|not-mine/);
  const back = P.loadProfile(store, NOW);
  assert.deepStrictEqual(P.roundOf(back, 'door'), { how: 'played', at: NOW });
  assert.strictEqual(P.roundOf(back, 'keyring').how, 'skipped');
  assert.strictEqual(P.roundOf(back, 'nope'), null);
  const key = 'm|stalkerware_scan|security.x|/Applications/Watcher.app';
  assert.strictEqual(P.recallAnswer(back, key, 'bcdfghj'), P.decisionHash('not-mine-safe'));
  assert.strictEqual(P.recallAnswer(back, key, 'zzzzzzz'), null, 'changed evidence forgets it');
  assert.strictEqual(P.recallAnswer(P.forgetAnswer(back, key), key, 'bcdfghj'), null);
});

test('a damaged rounds or kept record is dropped, never its neighbours', async () => {
  const [P] = await load();
  const raw = { ...P.emptyProfile(NOW), rounds: { door: { how: 'won', at: NOW }, seal: { how: 'played', at: NOW } },
    kept: { short: { d: 'bcdfghj', f: 'bcdfghj', at: NOW }, bcdfghj: { d: 'bcdfghj', f: 'bcdfghj', at: NOW } } };
  const p = P.salvage(raw, NOW).profile;
  assert.deepStrictEqual(Object.keys(p.rounds), ['seal']);
  assert.deepStrictEqual(Object.keys(p.kept), ['bcdfghj']);
});

test('a practice move is evidence on the game’s concepts (source round), right or wrong', async () => {
  const [P, B] = await load();
  const bank = B.buildBank([], [], [{ type: 'door', concepts: ['where-it-lives', 'who-made-it'], steps: 3 }]);
  assert.strictEqual(bank.items.get('round:door:0:where-it-lives').kind, 'round');
  let p = P.emptyProfile(NOW);
  p = P.recordRound(p, bank, 'door', 0, ['where-it-lives', 'who-made-it'], true, NOW);
  p = P.recordRound(p, bank, 'door', 1, ['where-it-lives'], false, NOW);
  assert.strictEqual(P.conceptEstimate(p, bank, 'where-it-lives').n, 2);
  assert.strictEqual(P.conceptEstimate(p, bank, 'who-made-it').n, 1);
  assert.deepStrictEqual(p.concepts['where-it-lives'].seen.map((e) => e[3]), ['round', 'round']);
  assert.strictEqual(P.recordRound(p, bank, 'door', 9, ['where-it-lives'], true, NOW), p, 'a step the bank doesn’t have records nothing');
  assert.deepStrictEqual(B.drawConcept(bank, 'where-it-lives', P.historyFor(p, bank)), [], 'round items are never drawn into a lesson');
});

test('points: per decided item, a mission bonus, notes batches and area, a bigger CONFIRMED; each once; monitoring never pays', async () => {
  const [, , L] = await load();
  let d = L.award(undefined, 'decide', L.missionKey('launch_agent_audit', 'item-1')).deck;
  assert.strictEqual(d.points, L.POINTS.decide);
  assert.strictEqual(L.award(d, 'decide', L.missionKey('launch_agent_audit', 'item-1')).points, 0, 'once per item');
  d = L.award(d, 'mission', L.missionKey('launch_agent_audit', 'door:gatehouse:1', 'a', 'b')).deck;
  d = L.award(d, 'notesBatch', L.missionKey('disk_space', 'n1', 'n2')).deck;
  d = L.award(d, 'notesArea', L.missionKey('disk_space', 'engine-room')).deck;
  assert.strictEqual(d.points, L.POINTS.decide + L.POINTS.mission + L.POINTS.notesBatch + L.POINTS.notesArea);
  const c = L.confirmItem(d, L.missionKey('launch_agent_audit', 'item-1'), NOW);
  assert.strictEqual(c.points, L.POINTS.confirmed);
  assert.ok(L.POINTS.confirmed > L.POINTS.fix, 'confirmed fixes pay more');
  assert.strictEqual(L.confirmItem(c.deck, L.missionKey('launch_agent_audit', 'item-1'), NOW).points, 0);
  for (const kind of ['decide', 'mission', 'notesBatch', 'notesArea']) {
    assert.strictEqual(L.award(d, kind, L.missionKey('stalkerware_scan', 'x')).points, 0, kind);
  }
  assert.strictEqual(L.confirmItem(d, L.missionKey('keylogger_indicators', 'x'), NOW).points, 0);
  assert.doesNotMatch(L.missionKey('launch_agent_audit', '/Users/someone/spy.plist'), /someone|spy/);
});
