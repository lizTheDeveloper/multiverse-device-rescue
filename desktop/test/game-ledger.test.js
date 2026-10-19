const test = require('node:test');
const assert = require('node:assert');
const load = async () => ({ ...(await import('../renderer/game/ledger.js')), ...(await import('../renderer/game/progress.js')) });
const NOW = '2026-10-18T12:00:00Z';
const LATER = '2026-10-19T12:00:00Z';

test('a key pays once: clue and tag bonus per sweep; fix, report and drill for life', async () => {
  const { award, emptyDeck, recordSweep, POINTS } = await load();
  let d = emptyDeck();
  let r = award(d, 'clue', 'm|c|path=/a#maker');
  assert.strictEqual(r.points, POINTS.clue); d = r.deck;
  assert.strictEqual(award(d, 'clue', 'm|c|path=/a#maker').points, 0, 'the same clue again pays nothing');
  r = award(d, 'clue', 'm|c|path=/a#where'); assert.strictEqual(r.points, POINTS.clue); d = r.deck;
  d = award(d, 'tagBonus', 'm|c|path=/a').deck;
  assert.strictEqual(award(d, 'tagBonus', 'm|c|path=/a').points, 0, 'no farming by re-tagging');
  r = award(d, 'fix', 'm|c|path=/a'); assert.strictEqual(r.points, POINTS.fix); d = r.deck;
  assert.strictEqual(d.points, 70);
  d = recordSweep(d, { checks: 3, checked: 1, secured: 1 }, NOW).deck;
  assert.strictEqual(award(d, 'clue', 'm|c|path=/a#maker').points, POINTS.clue, 'a new sweep: clues pay again');
  assert.strictEqual(award(d, 'fix', 'm|c|path=/a').points, 0, 'a fix pays once, ever');
  assert.strictEqual(award(d, 'report', 'gmail-fortify-2fa').points, POINTS.report);
  assert.strictEqual(award(d, 'drill', 'upd8r', POINTS.drillClueBonus).points, POINTS.drill + POINTS.drillClueBonus);
});

test('nothing pays for an unknown kind, an empty key, or anything from a monitoring check', async () => {
  const { award, emptyDeck, setTag } = await load();
  const d = emptyDeck();
  for (const [kind, key] of [['delete', 'x|y'], ['speed', 'x|y'], ['clue', ''], ['clue', null],
    ['clue', 'stalkerware_scan|security.stalkerware_scan.x#maker'], ['fix', 'keylogger_indicators|k'], ['tagBonus', 'couldnt|mvt_spyware_scan']]) {
    const r = award(d, kind, key);
    assert.strictEqual(r.points, 0, `${kind} ${key}`);
    assert.strictEqual(r.deck.points, 0);
  }
  assert.deepStrictEqual(setTag(d, 'stalkerware_scan|x', 'mine', 'fp', NOW).tags, {}, 'never tagged either');
});

test('ranks climb with points and never drop', async () => {
  const { award, emptyDeck, rankOf, RANKS } = await load();
  assert.deepStrictEqual(RANKS.map((r) => r.name), ['ROOKIE', 'SIGNAL ANALYST', 'NETRUNNER', 'SYSOP', 'CITY WARDEN']);
  let d = emptyDeck();
  assert.deepStrictEqual([rankOf(d).name, rankOf(d).toNext], ['ROOKIE', 100]);
  d = award(d, 'fix', 'a|1').deck;
  const r = award(d, 'fix', 'a|2');
  assert.strictEqual(r.rankUp, true);
  assert.strictEqual(rankOf(r.deck).name, 'SIGNAL ANALYST');
  assert.strictEqual(rankOf({ ...r.deck, points: 0 }).name, 'SIGNAL ANALYST', 'a stored rank is never lowered');
  const top = rankOf({ ...r.deck, points: 5000, rank: 4 });
  assert.deepStrictEqual([top.name, top.next, top.toNext], ['CITY WARDEN', null, 0]);
});

test('a sweep keeps a date and counts only, at most twenty, and the deck stays valid', async () => {
  const { recordSweep, emptyDeck, validDeck, MAX_SWEEPS } = await load();
  let d = emptyDeck();
  const counts = { checks: 290, critical: 1, warning: 3, info: 40, fog: 2, checked: 5, secured: 3, title: 'Unsigned helper', path: '/Users/ann/x' };
  for (let i = 0; i < MAX_SWEEPS + 5; i += 1) d = recordSweep(d, counts, `2026-10-${String(1 + (i % 28)).padStart(2, '0')}T00:00:00Z`).deck;
  assert.strictEqual(d.sweeps.length, MAX_SWEEPS);
  assert.deepStrictEqual(Object.keys(d.sweeps[0]).sort(), ['at', 'checked', 'checks', 'critical', 'fog', 'info', 'secured', 'warning']);
  assert.ok(!JSON.stringify(d).includes('Unsigned helper') && !JSON.stringify(d).includes('/Users/ann'));
  assert.strictEqual(validDeck(d), true);
  const odd = recordSweep(emptyDeck(), { checked: 2, secured: 9, critical: -4, warning: 'x' }, NOW).deck.sweeps[0];
  assert.deepStrictEqual([odd.checked, odd.secured, odd.critical, odd.warning], [2, 2, 0, 0]);
});

test('a clean sweep pays when a re-sweep makes the board clean: not every time, never the first', async () => {
  const { recordSweep, emptyDeck, POINTS } = await load();
  assert.strictEqual(recordSweep(emptyDeck(), { checked: 3, secured: 3 }, NOW).clean, false, 'nothing to compare with');
  const r = recordSweep(recordSweep(emptyDeck(), { checked: 3, secured: 2 }, NOW).deck, { checked: 3, secured: 3 }, LATER);
  assert.deepStrictEqual([r.clean, r.points], [true, POINTS.clean]);
  const again = recordSweep(r.deck, { checked: 3, secured: 3 }, '2026-10-20T00:00:00Z');
  assert.deepStrictEqual([again.clean, again.points], [false, 0]);
  const blind = recordSweep(recordSweep(emptyDeck(), { checked: 3, secured: 2 }, NOW).deck, { checked: 0, secured: 0 }, LATER);
  assert.strictEqual(blind.clean, false, 'nothing checked is never a clean sweep');
});

test('tags: kept by identity, set aside when the finding changed, dropped when it’s gone from a check that ran', async () => {
  const { setTag, reconcileDeck, emptyDeck } = await load();
  let d = emptyDeck();
  d = setTag(d, 'm|c|plist=/a', 'mine', 'fp1', NOW);
  d = setTag(d, 'm|c|plist=/b', 'threat', 'fp2', NOW);
  d = setTag(d, 'n|c|plist=/c', 'closer', 'fp3', NOW);
  d = setTag(d, 'couldnt|q', 'noted', 'couldnt', NOW);
  assert.strictEqual(setTag(d, 'm|x', 'delete', 'f', NOW), d, 'only the four tags');
  const signals = [{ id: 'm|c|plist=/a', kind: 'real', fp: 'fp1' }, { id: 'm|c|plist=/b', kind: 'real', fp: 'CHANGED' }];
  const r = reconcileDeck(d, signals, new Set(['m', 'q']));
  assert.deepStrictEqual(Object.keys(r.deck.tags).sort(), ['m|c|plist=/a', 'n|c|plist=/c'], 'n didn’t run: its tag stays');
  assert.deepStrictEqual(r.changed, ['m|c|plist=/b']);
  assert.deepStrictEqual(r.gone, ['couldnt|q'], 'q ran this time, so its couldn’t-check note is done');
});

test('a confirmed fix counts until the finding shows up again; its points stay', async () => {
  const { confirmFix, reconcileDeck, emptyDeck, POINTS } = await load();
  let r = confirmFix(emptyDeck(), 'm|c|plist=/a', NOW);
  assert.strictEqual(r.points, POINTS.fix);
  assert.deepStrictEqual(Object.keys(r.deck.confirmed), ['m|c|plist=/a']);
  let d = reconcileDeck(r.deck, [], new Set(['m'])).deck;
  assert.ok(d.confirmed['m|c|plist=/a'], 'still gone: still confirmed');
  d = reconcileDeck(d, [{ id: 'm|c|plist=/a', kind: 'real', fp: 'x' }], new Set(['m'])).deck;
  assert.deepStrictEqual(d.confirmed, {});
  assert.strictEqual(d.points, POINTS.fix, 'no points are taken back');
  r = confirmFix(d, 'm|c|plist=/a', LATER);
  assert.strictEqual(r.points, 0, 'fixing it again pays nothing');
  assert.ok(r.deck.confirmed['m|c|plist=/a']);
});

test('a monitoring finding is never recorded as a confirmed fix', async () => {
  const { confirmFix, emptyDeck } = await load();
  const d = emptyDeck();
  const r = confirmFix(d, 'stalkerware_scan|security.stalkerware_scan.x', NOW);
  assert.deepStrictEqual([r.points, r.rankUp, r.deck.confirmed, r.deck.points], [0, false, {}, 0]);
});

test('drill stats count tries and right answers', async () => {
  const { recordDrill, emptyDeck } = await load();
  assert.deepStrictEqual(recordDrill(recordDrill(emptyDeck(), true), false).drills, { right: 1, tried: 2 });
});

test('the monitoring list matches the app’s safety gate', async () => {
  const { MONITORING_MODULES } = await load();
  const { ALWAYS_SAFETY_MODULES } = require('../renderer/app.js');
  assert.deepStrictEqual([...MONITORING_MODULES].sort(), [...ALWAYS_SAFETY_MODULES].sort());
});

test('the connection watch scores nothing and its tags never reach the deck', async () => {
  const { award, setTag, confirmFix, sessionTag, withSessionTags, isWatchKey } = await import('../renderer/game/ledger.js');
  const { emptyDeck } = await import('../renderer/game/progress.js');
  const id = 'connection_watch|network.connection_watch.watch_summary|target=Safari';
  const d = emptyDeck();
  assert.ok(isWatchKey(id) && isWatchKey('couldnt|connection_watch') && !isWatchKey('a_mod|x'));
  for (const kind of ['clue', 'tagBonus', 'fix', 'report']) assert.strictEqual(award(d, kind, `${id}#what`).points, 0, kind);
  assert.strictEqual(confirmFix(d, id, 'now').points, 0);
  assert.deepStrictEqual(setTag(d, id, 'mine', 'fp', 'now').tags, {});
  const session = sessionTag({}, id, 'closer', 'fp', 'now');
  assert.deepStrictEqual(session, { [id]: { tag: 'closer', at: 'now', fp: 'fp' } });
  assert.deepStrictEqual(sessionTag(session, 'a_mod|x', 'mine', 'fp', 'now'), session, 'only watch findings are kept here');
  assert.deepStrictEqual(sessionTag({}, id, 'bogus', 'fp', 'now'), {});
  const shown = withSessionTags(setTag(d, 'a_mod|x', 'mine', 'f', 'now'), session);
  assert.deepStrictEqual(Object.keys(shown.tags).sort(), ['a_mod|x', id]);
  assert.strictEqual(withSessionTags(d, {}), d);
});
