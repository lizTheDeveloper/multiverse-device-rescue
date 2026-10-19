const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3, memStore } = require('./profile-fixtures.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');

const NOW = '2026-10-18T12:00:00.000Z';
const at = (n) => `2026-10-18T12:00:${String(n).padStart(2, '0')}.000Z`;
const load = async () => {
  const [pp, ib, rb, ledger] = await Promise.all([
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
    import('../renderer/game/profile/recipe-box.js'),
    import('../renderer/game/ledger.js'),
  ]);
  return { ...pp, bank: ib.buildBank(LESSONS, DRILLS), rb, ledger };
};
const answer = (m, p, bank, keys, rights) => keys.reduce((acc, k, i) => m.recordAnswer(acc, bank, k, rights[i], at(i)), p);

test('v3 migrates record by record: a bad tag or lesson costs only itself; points and rank survive', async () => {
  const { salvage } = await load();
  const { profile: p, changes } = salvage(V3, NOW);
  assert.strictEqual(p.version, 4);
  assert.deepStrictEqual(Object.keys(p.missions), ['launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x'], 'monitoring and broken missions dropped');
  assert.strictEqual(p.missions['launch_agent_audit|security.launch_agent_audit.tmp|/tmp/x'].title, 'A helper');
  assert.deepStrictEqual(p.lessons['lesson-a'], { visited: '2026-10-09T08:00:00.000Z', before: '2026-10-09T08:00:00.000Z' });
  assert.deepStrictEqual(p.lessons['lesson-b'], { self: '2026-10-12T08:00:00.000Z' });
  assert.strictEqual(p.lessons.bad, undefined);
  assert.deepStrictEqual(p.rank, { points: 340, index: 2 });
  assert.deepStrictEqual([p.drills.right, p.drills.tried], [9, 12]);
  assert.deepStrictEqual(Object.keys(p.deck.tags), ['good']);
  assert.strictEqual(p.deck.sweeps.length, 1);
  assert.strictEqual(p.since, '2026-10-09T08:00:00.000Z');
  assert.ok(changes.includes('lessons: 2 kept'));
  assert.ok(changes.some((c) => /^deck: \d+ dropped$/.test(c)));
});

test('v1 and v2 documents migrate too; anything else starts fresh without throwing', async () => {
  const { salvage } = await load();
  const v1 = salvage({ version: 1, missions: { a: { status: 'open', module: 'm' } } }, NOW).profile;
  assert.deepStrictEqual(Object.keys(v1.missions), ['a']);
  const v2 = salvage({ version: 2, missions: {}, lessons: { 'lesson-a': { completedAt: 'x' } } }, NOW).profile;
  assert.strictEqual(v2.lessons['lesson-a'].before, 'x');
  for (const junk of [null, 'x', [], { version: 9 }]) assert.strictEqual(salvage(junk, NOW).profile.version, 4);
});

test('first load reads the old key, logs the migration, and leaves the old key exactly as it was', async () => {
  const { loadProfile, OLD_KEY } = await load();
  const text = JSON.stringify(V3);
  const store = memStore({ [OLD_KEY]: text });
  const p = loadProfile(store, NOW);
  assert.strictEqual(p.rank.points, 340);
  assert.strictEqual(p.migrations.length, 1);
  assert.strictEqual(p.migrations[0].from, 3);
  assert.strictEqual(store.raw[OLD_KEY], text);
});

test('save then load gives the same profile; nothing written names what must stay off disk', async () => {
  const { loadProfile, saveProfile, recordAnswer, bank, PROFILE_KEY, OLD_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: JSON.stringify(V3) });
  let p = loadProfile(store, NOW);
  p.missions['x|y|/Users/ann/partner-safety'] = { status: 'open', module: 'm', title: 'Monitor hotline stalkerware' };
  p = recordAnswer(p, bank, 'a1', true, NOW);
  assert.strictEqual(saveProfile(store, p, { seed: 4242, mode: 'standard' }), true);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.deepStrictEqual(loadProfile(store, NOW), p);
  assert.ok(store.data[PROFILE_KEY].startsWith('{"kitchen":'));
  assert.ok(store.data[OLD_KEY], 'standard mode keeps the old key as a backup');
});

test('in city mode the old literal document goes once the box is written', async () => {
  const { loadProfile, saveProfile, OLD_KEY, PROFILE_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: JSON.stringify(V3) });
  const p = loadProfile(store, NOW);
  assert.strictEqual(saveProfile(store, p, { seed: 4242, mode: 'city' }), true);
  assert.strictEqual(store.data[OLD_KEY], undefined);
  assert.ok(store.data[PROFILE_KEY]);
});

test('a save that cannot be encoded writes nothing and removes nothing', async () => {
  const { saveProfile, emptyProfile, OLD_KEY } = await load();
  const store = recordingStore({ [OLD_KEY]: '{}' });
  assert.strictEqual(saveProfile(store, emptyProfile(NOW), { seed: 0, mode: 'city' }), false);
  assert.deepStrictEqual(store.writes, []);
  assert.deepStrictEqual(store.removed, []);
});

test('a box that will not decode is kept aside, never overwritten, and the old key is read instead', async () => {
  const { loadProfile, PROFILE_KEY, SPARE_KEY, OLD_KEY } = await load();
  const store = memStore({ [PROFILE_KEY]: '{"kitchen":"basil basil basil basil","cards":[]}', [OLD_KEY]: JSON.stringify(V3) });
  const p = loadProfile(store, NOW);
  assert.strictEqual(p.rank.points, 340);
  assert.strictEqual(store.raw[SPARE_KEY], '{"kitchen":"basil basil basil basil","cards":[]}');
});

test('the seed comes from the box when there is one, else from the install', async () => {
  const { profileSeed, saveProfile, emptyProfile } = await load();
  const store = memStore();
  const dm = { ensureSeed: () => 99 };
  assert.strictEqual(profileSeed(store, dm), 99);
  saveProfile(store, emptyProfile(NOW), { seed: 1234 });
  assert.strictEqual(profileSeed(store, dm), 1234);
  const bare = memStore({ 'device-rescue.city-seed': '777' });
  assert.strictEqual(profileSeed(bare, null), 777, 'the install’s seed key, read the way DisplayMode reads it');
  const none = memStore();
  assert.strictEqual(profileSeed(none, null, () => 0.5), 1073741824);
  assert.strictEqual(none.raw['device-rescue.city-seed'], '1073741824', 'and kept, so the next session matches');
});

// With irt.js as calibrated in review: four right on 3-option items is enough
// evidence but not yet settled (sd 0.904 > 0.89); the fifth settles it.
test('learned comes from the estimate: five right on three items; wrong answers are kept as evidence', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p = answer(m, p, m.bank, ['a1', 'a1-2', 'a1-3', 'a1'], [true, true, true, true]);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'started', 'four right: not settled yet');
  assert.strictEqual(p.concepts['who-made-it'].learnedAt, undefined);
  p = m.recordAnswer(p, m.bank, 'a1-2', true, at(5));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned');
  assert.ok(p.concepts['who-made-it'].learnedAt);
  p = m.recordAnswer(p, m.bank, 'a1-3', false, at(6));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned', 'one slip keeps it');
  p = m.recordAnswer(p, m.bank, 'a1', false, at(7));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned', 'a second slip still above SLIPPED_BELOW');
  assert.deepStrictEqual(p.concepts['who-made-it'].seen.map((e) => e[1]), [1, 1, 1, 1, 1, 0, 0]);
  p = m.recordAnswer(p, m.bank, 'a1-2', false, at(8));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'refresher');
});

test('each answer moves its item’s difficulty', async () => {
  const m = await load();
  const p = m.recordAnswer(m.emptyProfile(NOW), m.bank, 'a1', true, NOW);
  assert.deepStrictEqual(p.items.a1, { b: -0.0333, n: 1 }, 'b + 0.1·(2/3 − 1)');
});

test('answering every question once is evidence, not proof; the visit makes the lesson done for the game', async () => {
  const m = await load();
  let p = answer(m, m.emptyProfile(NOW), m.bank, ['a1', 'a2'], [true, true]);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'measuring');
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').done, false);
  p = m.recordVisit(p, 'lesson-a', NOW);
  const s = m.lessonState(p, m.bank, 'lesson-a');
  assert.deepStrictEqual([s.state, s.done, s.answered, s.right], ['measuring', true, 2, 2]);
  assert.ok(m.toProgress(p, m.bank).lessons['lesson-a'], 'the game’s lessonDone sees it');
});

test('a lesson finished under the old rule is learned until its own answers say otherwise', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'learned');
  p = answer(m, p, m.bank, ['a1', 'a1-2', 'a1-3'], [false, false, false]);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned', `fewer than MIN_RESPONSES of its own: the old rule's evidence stands`);
  p = m.recordAnswer(p, m.bank, 'a1', false, at(4));
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'refresher', 'four of its own: the IRT rule decides');
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'learned');
});

test('"I know this" is skipped, not learned; a wrong drill makes it worth a look, and an offer follows the rules', async () => {
  const m = await load();
  let p = m.markKnown(m.emptyProfile(NOW), ['where-it-lives'], at(1));
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'skipped');
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), false);
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'mine', at(2));
  assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'worth-a-look');
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), true);
  p = m.noteOffered(p, 'where-it-lives', at(3));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), false, 'once per sweep');
  p = m.declineOffer(p, 'where-it-lives', at(4));
  p = m.recordGap(p, ['where-it-lives'], 'call', at(5));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(5)), true, 'one decline: a new signal offers again');
  p = m.declineOffer(p, 'where-it-lives', at(6));
  p = m.recordGap(p, ['where-it-lives'], 'call', at(7));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(7)), false, 'two declines: only a wrong drill reopens it');
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'closer', at(8));
  assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(8)), true);
});

test('a lesson skipped as a whole skips each of its concepts', async () => {
  const m = await load();
  const p = m.markLessonKnown(m.emptyProfile(NOW), 'lesson-a', NOW);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'skipped');
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'skipped');
});

test('drill calls fill the calls matrix and the last-10 row; calibration counts over- and under-calling', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p = m.recordDrillCall(p, m.bank, DRILLS[1], 'threat', at(1)); // mine called threat: over
  p = m.recordDrillCall(p, m.bank, DRILLS[2], 'threat', at(2)); // over, on a drill with no concept
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'mine', at(3)); // threat called mine: under
  p = m.recordDrillCall(p, m.bank, DRILLS[0], 'threat', at(4));
  assert.strictEqual(p.drills.calls.mine.threat, 2);
  assert.strictEqual(p.drills.calls.threat.mine, 1);
  assert.deepStrictEqual(p.drills.recent, [0, 0, 0, 1]);
  assert.deepStrictEqual(m.calibration(p.drills), { over: 2, under: 1, total: 4 });
  assert.strictEqual(p.concepts['who-made-it'].seen.length, 1);
  assert.strictEqual(m.recordDrillCall(p, m.bank, DRILLS[0], 'nonsense', NOW), p);
});

test('a real call maps to the clues opened, else to the lessons for its module; never to monitoring checks', async () => {
  const m = await load();
  assert.deepStrictEqual(m.callConcepts(m.bank, 'launch_agent_audit', ['where', 'what']), ['where-it-lives']);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'launch_agent_audit', []), ['who-made-it', 'where-it-lives']);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'stalkerware_scan', ['maker']), []);
  assert.deepStrictEqual(m.callConcepts(m.bank, 'nothing_teaches_this', []), []);
});

test('the v3 view feeds the ledger unchanged, and folding it back never lowers the rank', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  const view = m.toProgress(p, m.bank);
  assert.strictEqual(view.deck.points, 340);
  const r = m.ledger.award(view.deck, 'fix', 'launch_agent_audit|x|y');
  p = m.withProgress(p, { ...view, deck: r.deck });
  assert.strictEqual(p.rank.points, 390);
  p = m.withProgress(p, { ...view, deck: { ...r.deck, rank: 0 } });
  assert.strictEqual(p.rank.index, 2, 'rank never drops');
  p = m.withProgress(p, { ...view, missions: { ...view.missions, 'stalkerware_scan|a|b': { status: 'open', module: 'stalkerware_scan' } } });
  assert.strictEqual(p.missions['stalkerware_scan|a|b'], undefined);
});

test('the what-to-know shows until one item in its family is answered right', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), true);
  p = m.recordAnswer(p, m.bank, 'a1', false, NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), true);
  p = m.recordAnswer(p, m.bank, 'a1-3', true, NOW);
  assert.strictEqual(m.teachShown(p, m.bank, 'a1-2'), false);
  assert.strictEqual(m.teachShown(p, m.bank, 'a2'), true);
});

test('the summary: lessons, shown concepts, skill depth, drills and rank', async () => {
  const m = await load();
  let p = m.salvage(V3, NOW).profile;
  // Ten right on 2-option items settle the estimate (a right answer says less when half of guesses are right).
  const keys = Array.from({ length: 10 }, (_, i) => ['b1', 'b1-2', 'b1-3'][i % 3]);
  p = answer(m, p, m.bank, keys, keys.map(() => true));
  const s = m.summary(p, m.bank);
  assert.deepStrictEqual(s.lessons.map((l) => [l.id, l.state]), [['lesson-a', 'learned'], ['lesson-b', 'learned']]);
  assert.strictEqual(s.lessonsLearned, 2);
  const honest = s.skills.find((k) => k.id === 'honest-results');
  assert.deepStrictEqual([honest.depth, honest.learned, honest.of], ['practiced', 1, 1]);
  assert.strictEqual(s.skills.find((k) => k.id === 'locks-and-updates'), undefined, 'nothing in this bank measures it, so it isn’t listed');
  assert.strictEqual(s.skills.find((k) => k.id === 'reading-makers').depth, 'practiced');
  assert.deepStrictEqual([s.rank.name, s.rank.level, s.rank.of, s.rank.toNext], ['NETRUNNER', 3, 5, 360]);
  assert.deepStrictEqual(s.city, { reclaimed: 0, later: 1, yours: 0, lastSweep: 75 });
  assert.ok(s.concepts.every((c) => c.id !== 'cut-off-order'));
});

// Review focus: inputs the spec implies but the tests above don't reach.
test('a box from a newer build is kept aside, never overwritten, and the old key is read instead', async () => {
  const { loadProfile, PROFILE_KEY, SPARE_KEY, OLD_KEY } = await load();
  const { encode } = await import('../renderer/game/profile/recipe-box.js');
  const newer = encode({ version: 5, whatever: true }, 321);
  const store = memStore({ [PROFILE_KEY]: newer, [OLD_KEY]: JSON.stringify(V3) });
  assert.strictEqual(loadProfile(store, NOW).rank.points, 340);
  assert.strictEqual(store.raw[SPARE_KEY], newer);
});

test('storage that refuses writes: nothing is removed, the save says it failed, nothing throws', async () => {
  const { saveProfile, emptyProfile, OLD_KEY } = await load();
  let removed = 0;
  const full = { getItem: () => null, setItem: () => { throw new Error('QuotaExceededError'); }, removeItem: () => { removed += 1; } };
  assert.strictEqual(saveProfile(full, emptyProfile(NOW), { seed: 5, mode: 'city' }), false);
  assert.strictEqual(removed, 0, `the old ${OLD_KEY} stays when the box couldn’t be written`);
});

test('evidence on an item no longer in the bank is ignored, never thrown on', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p.concepts['who-made-it'] = { seen: [['gone-item', 1, NOW, 'lesson'], ['gone-item', 1, NOW, 'lesson'], ['a1', 1, NOW, 'lesson']] };
  p = m.salvage(p, NOW).profile;
  assert.strictEqual(m.conceptEstimate(p, m.bank, 'who-made-it').n, 1);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'started');
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').answered, 1);
  assert.strictEqual(m.recordAnswer(p, m.bank, 'gone-item', true, NOW), p, 'an answer to an unknown item records nothing');
});

test('long use stays small: evidence per concept is capped, and the box stays well under storage limits', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  for (let i = 0; i < 400; i += 1) p = m.recordAnswer(p, m.bank, ['a1', 'a1-2', 'a1-3', 'a2', 'b1'][i % 5], i % 3 !== 0, at(i % 60));
  assert.ok(Object.values(p.concepts).every((c) => (c.seen || []).length <= m.MAX_SEEN));
  const store = memStore();
  m.saveProfile(store, p, { seed: 11 });
  assert.ok(store.raw[m.PROFILE_KEY].length < 200000, `${store.raw[m.PROFILE_KEY].length} characters`);
});

test('a sweep’s carry flag survives the round trip, so held software going is never paid after a restart', async () => {
  const m = await load();
  const raw = { ...V3, deck: { ...V3.deck, sweep: { ...V3.deck.sweep, carry: true } } };
  const p = m.salvage(raw, NOW).profile;
  assert.strictEqual(p.deck.sweep.carry, true);
  assert.strictEqual(m.toProgress(p, m.bank).deck.sweep.carry, true);
  assert.strictEqual(m.withProgress(p, m.toProgress(p, m.bank)).deck.sweep.carry, true);
  assert.strictEqual(m.salvage(V3, NOW).profile.deck.sweep.carry, undefined, 'absent unless set');
});

// --- Obligations handed over by earlier reviews ---

const irtMod = () => import('../renderer/game/profile/irt.js');
const responsesOf = (m, p, c) => (p.concepts[c].seen || []).map(([key, x]) => ({ key, x, b: m.difficultyOf(p, m.bank)(key), c: m.bank.items.get(key).c }));

// 1. Old-rule lessons.
test('old rule: a finished lesson migrates as stored evidence, never as "learned" from an empty estimate', async () => {
  const m = await load();
  const irt = await irtMod();
  assert.strictEqual(irt.isLearned(irt.estimate([]), true), false, 'irt.js by design: nothing to keep with no answers');
  // Migrated through the real load path, then saved and loaded again: still learned, from the stored flag.
  const store = memStore({ [m.OLD_KEY]: JSON.stringify(V3) });
  let p = m.loadProfile(store, NOW);
  assert.ok(p.lessons['lesson-a'].before, 'the old completion is stored as evidence');
  assert.strictEqual(m.conceptEstimate(p, m.bank, 'who-made-it').n, 0);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'learned');
  assert.ok(m.saveProfile(store, p, { seed: 77, mode: 'standard' }));
  p = m.loadProfile(store, NOW);
  assert.strictEqual(m.lessonState(p, m.bank, 'lesson-a').state, 'learned', 'nobody loses a finished lesson across a save');
  assert.ok(m.toProgress(p, m.bank).lessons['lesson-a'], 'and the game still counts it done');
  // A learnedAt with no answers behind it (all its items left the bank) is not learned: nothing derives it from an empty estimate.
  const q = m.emptyProfile(NOW);
  q.concepts['who-made-it'] = { learnedAt: NOW };
  assert.strictEqual(m.conceptState(q, m.bank, 'who-made-it'), 'refresher');
});

test('old rule: from MIN_RESPONSES answers of its own, the IRT rule decides with BEFORE_PRIOR', async () => {
  const m = await load();
  const irt = await irtMod();
  let p = m.salvage(V3, NOW).profile;
  p = answer(m, p, m.bank, ['a1', 'a1-2', 'a1-3'], [true, false, true]);
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned', 'three answers: the stored evidence still stands');
  p = m.recordAnswer(p, m.bank, 'a1', false, at(3));
  const est = m.conceptEstimate(p, m.bank, 'who-made-it');
  assert.strictEqual(est.n, irt.MIN_RESPONSES);
  assert.deepStrictEqual(est, irt.estimate(responsesOf(m, p, 'who-made-it'), irt.BEFORE_PRIOR), 'estimated with BEFORE_PRIOR');
  assert.strictEqual(irt.isLearned(est), false, 'the first-time rule alone would not call this learned');
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), irt.isLearned(est, true) ? 'learned' : 'refresher', 'irt.js decides, as learned before');
  assert.strictEqual(m.conceptState(p, m.bank, 'who-made-it'), 'learned');
});

// 2. No second threshold: learned is exactly irt.js's rule.
test('learned (and so skill depth) is exactly irt.js isLearned/enoughEvidence, over many random runs', async () => {
  const m = await load();
  const irt = await irtMod();
  const keys = ['a1', 'a1-2', 'a1-3', 'drill:zoom-helper-signed'];
  let seed = 12345;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  let learnedSeen = 0;
  for (let run = 0; run < 40; run += 1) {
    let p = m.emptyProfile(NOW);
    let wasLearned = false;
    const skill = rnd() < 0.5 ? 0.85 : 0.4;
    for (let i = 0; i < 12; i += 1) {
      const k = keys[Math.floor(rnd() * 3)];
      p = m.recordAnswer(p, m.bank, k, rnd() < skill, at(i));
      const est = m.conceptEstimate(p, m.bank, 'who-made-it');
      assert.deepStrictEqual(est, irt.estimate(responsesOf(m, p, 'who-made-it'), irt.PRIOR));
      if (!wasLearned && irt.isLearned(est)) wasLearned = true;
      assert.strictEqual(!!p.concepts['who-made-it'].learnedAt, wasLearned, 'learnedAt set exactly when irt.js first says learned');
      const learned = m.conceptState(p, m.bank, 'who-made-it') === 'learned';
      assert.strictEqual(learned, irt.isLearned(est, wasLearned));
      if (learned && !wasLearned) assert.fail('learned before irt.js said so');
      if (!irt.enoughEvidence(est)) assert.strictEqual(learned, false);
      const s = m.summary(p, m.bank).skills.find((x) => x.id === 'reading-makers');
      assert.strictEqual(s.learned, learned ? 1 : 0, 'skill counts read the same state');
      learnedSeen += learned ? 1 : 0;
    }
  }
  assert.ok(learnedSeen > 0, 'the runs reached learned at least once, so the check means something');
});

// 3. Disk words, over a realistic session.
test('a realistic session writes nothing, in keys or values, that must stay off disk; the old key is never written', async () => {
  const m = await load();
  const { FORBIDDEN_ON_DISK } = require('./disk-words.js');
  const { DRILL_CONCEPTS, CONCEPTS, SKILLS } = await import('../renderer/game/profile/skills.js');
  const old = JSON.stringify({ ...V3, missions: { ...V3.missions, 'launch_agent_audit|x|/Users/ann/partner-safety': { status: 'yours', module: 'launch_agent_audit', title: 'Monitor hotline helper' } } });
  const store = recordingStore({ [m.OLD_KEY]: old });
  let p = m.loadProfile(store, NOW); // migration
  const seed = m.profileSeed(store, null, () => 0.25);
  p = answer(m, p, m.bank, ['a1', 'a2', 'a1-2'], [true, false, true]); // a lesson visit
  p = m.recordVisit(p, 'lesson-a', at(4));
  p = m.recordAnswer(p, m.bank, 'a2', true, at(5)); // a re-ask of the same item
  p = m.markKnown(p, ['couldnt-check'], at(6)); // a skip
  p = m.markLessonKnown(p, 'lesson-b', at(7));
  for (const [i, d] of DRILLS.entries()) p = m.recordDrillCall(p, m.bank, d, i ? 'threat' : 'mine', at(8 + i)); // drills, some wrong
  p = m.recordGap(p, m.callConcepts(m.bank, 'launch_agent_audit', ['maker']), 'call', at(12));
  p = m.recordGap(p, m.callConcepts(m.bank, 'stalkerware_scan', ['maker']), 'call', at(13));
  p = m.recordGap(p, ['couldnt-check'], 'reopen', at(14));
  p = m.noteOffered(p, 'couldnt-check', at(15));
  p = m.declineOffer(p, 'couldnt-check', at(16));
  const view = m.toProgress(p, m.bank);
  p = m.withProgress(p, { ...view, deck: m.ledger.award(view.deck, 'fix', 'launch_agent_audit|x|y').deck });
  assert.ok(m.saveProfile(store, p, { seed, mode: 'standard' }));
  p = m.recordAnswer(m.loadProfile(store, at(20)), m.bank, 'a1-3', true, at(21));
  assert.ok(m.saveProfile(store, p, { seed, mode: 'city' })); // a switch to city mode
  store.data[m.PROFILE_KEY] = '{"kitchen":"basil basil basil basil","cards":[]}'; // a damaged box
  p = m.loadProfile(store, at(30));
  assert.ok(m.saveProfile(store, p, { seed, mode: 'city' }));
  assert.ok(store.writes.length >= 5);
  assert.deepStrictEqual(forbiddenWrites(store), []);
  assert.ok(store.writes.every(([k]) => k !== m.OLD_KEY), 'the old key is never written again');
  for (const [k, v] of store.writes) {
    if (k === m.SEED_KEY) { assert.match(v, /^\d+$/); continue; }
    assert.ok(v.startsWith('{"kitchen":'), `${k} is disguised`);
    for (const literal of ['lesson-a', 'who-made-it', 'A helper', 'launch_agent_audit', 'completedAt']) assert.ok(!v.includes(literal), `${k} holds ${literal} literally`);
  }
  // The ids and keys stored inside the box pass too.
  const inside = m.rb.decode(store.data[m.PROFILE_KEY]);
  const ids = [...Object.keys(inside.concepts), ...Object.keys(inside.items), ...Object.keys(inside.lessons),
    ...Object.values(inside.concepts).flatMap((c) => (c.seen || []).flatMap((e) => [e[0], e[3]])),
    ...Object.keys(DRILL_CONCEPTS).map((d) => `drill:${d}`), ...CONCEPTS.map((c) => c.id), ...SKILLS.map((s) => s.id)];
  assert.ok(ids.length > 20);
  for (const id of ids) assert.doesNotMatch(id, FORBIDDEN_ON_DISK, id);
});

// 4. Backup: nothing old is lost; bad data fails safe and is never dropped silently.
test('standard mode: the old document stays byte for byte through migration and many saves', async () => {
  const m = await load();
  const text = JSON.stringify(V3);
  const store = recordingStore({ [m.OLD_KEY]: text });
  let p = m.loadProfile(store, NOW);
  for (let i = 0; i < 3; i += 1) {
    p = m.recordAnswer(p, m.bank, 'a1', true, at(i));
    assert.ok(m.saveProfile(store, p, { seed: 9, mode: 'standard' }));
    p = m.loadProfile(store, NOW);
  }
  assert.strictEqual(store.data[m.OLD_KEY], text);
  assert.deepStrictEqual(store.removed, []);
});

test('city mode: the old document is copied, disguised, before it goes, and a later load can still read it', async () => {
  const m = await load();
  const text = JSON.stringify(V3);
  const store = recordingStore({ [m.OLD_KEY]: text });
  assert.ok(m.saveProfile(store, m.loadProfile(store, NOW), { seed: 9, mode: 'city' }));
  assert.strictEqual(store.data[m.OLD_KEY], undefined);
  assert.strictEqual(m.rb.decode(store.data[m.BACKUP_KEY]), text, 'the backup is the old text exactly');
  assert.ok(store.data[m.BACKUP_KEY].startsWith('{"kitchen":'));
  const writeAt = store.writes.findIndex(([k]) => k === m.BACKUP_KEY);
  assert.ok(writeAt >= 0 && store.removed.length === 1, 'backed up, then removed');
  delete store.data[m.PROFILE_KEY]; // the box is lost
  assert.strictEqual(m.loadProfile(store, NOW).rank.points, 340, 'the backup is read like the old key');
});

test('city mode: when the backup cannot be written, the old document stays', async () => {
  const m = await load();
  const text = JSON.stringify(V3);
  const store = recordingStore({ [m.OLD_KEY]: text });
  const set = store.setItem;
  store.setItem = (k, v) => { if (k === m.BACKUP_KEY) throw new Error('QuotaExceededError'); set(k, v); };
  assert.ok(m.saveProfile(store, m.loadProfile(store, NOW), { seed: 9, mode: 'city' }));
  assert.strictEqual(store.data[m.OLD_KEY], text);
  assert.deepStrictEqual(store.removed, []);
});

test('an old document that is not JSON starts fresh, says so, and is never lost', async () => {
  const m = await load();
  const store = recordingStore({ [m.OLD_KEY]: '{not json' });
  const p = m.loadProfile(store, NOW);
  assert.strictEqual(p.version, 4);
  assert.deepStrictEqual(p.migrations[0].changes, ['nothing readable: started fresh']);
  assert.ok(m.saveProfile(store, p, { seed: 9, mode: 'standard' }));
  assert.strictEqual(store.data[m.OLD_KEY], '{not json');
  assert.ok(m.saveProfile(store, p, { seed: 9, mode: 'city' }));
  assert.strictEqual(m.rb.decode(store.data[m.BACKUP_KEY]), '{not json');
});

test('a box that will not decode is never overwritten: with every spare slot taken, the save writes nothing', async () => {
  const m = await load();
  const store = recordingStore({ [m.PROFILE_KEY]: 'foreign 1' });
  assert.ok(m.saveProfile(store, m.emptyProfile(NOW), { seed: 9 }), 'one bad box: kept aside, then the save goes ahead');
  assert.strictEqual(store.data[m.SPARE_KEY], 'foreign 1');
  store.data[m.PROFILE_KEY] = 'foreign 2';
  m.loadProfile(store, NOW);
  store.data[m.PROFILE_KEY] = 'foreign 3';
  assert.ok(m.saveProfile(store, m.emptyProfile(NOW), { seed: 9 }));
  store.data[m.PROFILE_KEY] = 'foreign 4';
  const before = store.writes.length;
  assert.strictEqual(m.saveProfile(store, m.emptyProfile(NOW), { seed: 9 }), false, 'no room to keep it aside: no save');
  assert.strictEqual(store.data[m.PROFILE_KEY], 'foreign 4');
  assert.strictEqual(store.writes.length, before);
  const spares = Object.entries(store.data).filter(([k]) => k.startsWith(m.SPARE_KEY)).map(([, v]) => v).sort();
  assert.deepStrictEqual(spares, ['foreign 1', 'foreign 2', 'foreign 3']);
});

test('a v4 box with an unreadable record: the rest loads, the drop is logged, and the box is kept aside', async () => {
  const m = await load();
  const good = m.recordAnswer(m.emptyProfile(NOW), m.bank, 'a1', true, NOW);
  const damaged = m.rb.encode({ ...good, items: { ...good.items, broken: { b: 'x' } } }, 31);
  const store = memStore({ [m.PROFILE_KEY]: damaged });
  const p = m.loadProfile(store, NOW);
  assert.deepStrictEqual(p.concepts, good.concepts);
  assert.deepStrictEqual(p.migrations.at(-1).changes, ['records: 1 dropped']);
  assert.strictEqual(store.raw[m.SPARE_KEY], damaged);
});

// 5. Size.
const wideBank = async () => {
  const ib = await import('../renderer/game/profile/item-bank.js');
  const { CONCEPTS, DRILL_CONCEPTS } = await import('../renderer/game/profile/skills.js');
  const opts = () => [{ text: 'a', correct: true }, { text: 'b', correct: false }, { text: 'c', correct: false }];
  // One lesson per concept, three families of three items each, with keys as long as the real ones.
  const lessons = CONCEPTS.map((c) => ({ id: `lesson-${c.id}`, title: c.title, modules: [], questions: [1, 2, 3].map((f) => ({
    key: `${c.id}-question-${f}`, concept: c.id, prompt: 'p', options: opts(),
    variants: [2, 3].map((v) => ({ key: `${c.id}-question-${f}-variant-${v}`, prompt: 'p', options: opts() })) })) }));
  return ib.buildBank(lessons, Object.keys(DRILL_CONCEPTS).map((id) => ({ id, answer: 'threat' })));
};

test('a long session on every concept stays capped per concept and well under the box limit', async () => {
  const m = await load();
  const bank = await wideBank();
  const keys = [...bank.items.keys()];
  let p = m.loadProfile(memStore({ [m.OLD_KEY]: JSON.stringify(V3) }), NOW);
  for (let i = 0; i < 3000; i += 1) {
    const k = keys[(i * 7) % keys.length];
    const t = `2026-10-${String(1 + (i % 28)).padStart(2, '0')}T12:00:00.000Z`;
    p = k.startsWith('drill:') ? m.recordDrillCall(p, bank, { id: k.slice(6), answer: 'threat' }, i % 4 ? 'threat' : 'mine', t) : m.recordAnswer(p, bank, k, i % 4 !== 0, t);
  }
  for (let i = 0; i < 60; i += 1) p.missions[`launch_agent_audit|security.launch_agent_audit.item${i}|/Library/LaunchAgents/com.example.helper${i}.plist`] = { status: 'later', module: 'launch_agent_audit', title: `A helper ${i}`, updatedAt: NOW };
  assert.ok(Object.values(p.concepts).every((c) => !c.seen || c.seen.length <= m.MAX_SEEN));
  assert.ok(Object.values(p.concepts).filter((c) => c.seen && c.seen.length === m.MAX_SEEN).length >= 14, 'the cap was reached');
  const store = memStore();
  assert.ok(m.saveProfile(store, p, { seed: 11, mode: 'standard' }));
  const size = store.raw[m.PROFILE_KEY].length;
  assert.ok(size < m.MAX_BOX_CHARS, `${size} characters`);
  assert.deepStrictEqual(m.loadProfile(store, NOW), p, 'nothing trimmed at this size');
});

test('a box over the limit is written with fewer, newest answers per concept, and learned stays learned', async () => {
  const m = await load();
  let p = m.emptyProfile(NOW);
  p = answer(m, p, m.bank, ['a1', 'a1-2', 'a1-3', 'a1', 'a1-2', 'a1-3'], [true, true, true, true, true, true]);
  // Padding: many concepts' worth of evidence, far over the limit.
  for (let i = 0; i < 100; i += 1) p.concepts[`extra-${i}`] = { seen: Array.from({ length: m.MAX_SEEN }, (_, j) => [`extra-item-${j}`, 1, NOW, 'lesson']) };
  const store = memStore();
  assert.ok(m.rb.encode(p, 11).length > m.MAX_BOX_CHARS, 'the test really is over the limit');
  assert.ok(m.saveProfile(store, p, { seed: 11 }));
  assert.ok(store.raw[m.PROFILE_KEY].length <= m.MAX_BOX_CHARS, `${store.raw[m.PROFILE_KEY].length}`);
  const back = m.loadProfile(store, NOW);
  const trimmed = back.concepts['extra-0'].seen;
  assert.ok(trimmed.length >= 4 && trimmed.length < m.MAX_SEEN, `${trimmed.length} kept`);
  const kept = back.concepts['who-made-it'].seen;
  assert.ok(kept.length >= 4);
  assert.deepStrictEqual(kept, p.concepts['who-made-it'].seen.slice(-kept.length), 'the newest are kept');
  assert.ok(back.concepts['who-made-it'].learnedAt);
  assert.strictEqual(m.conceptState(back, m.bank, 'who-made-it'), 'learned');
  assert.deepStrictEqual(back.missions, p.missions);
});

// 6. "I know this" is skipped; every gap signal can offer it again; monitoring never does.
test('a skipped concept is offered again on any gap signal: a wrong drill, a Scout disagreement, a re-opened "?"', async () => {
  const m = await load();
  const skipped = m.markKnown(m.emptyProfile(NOW), ['where-it-lives'], at(1));
  assert.strictEqual(skipped.concepts['where-it-lives'].learnedAt, undefined, 'never learned by saying so');
  assert.strictEqual(m.toProgress(skipped, m.bank).lessons['lesson-a'], undefined);
  assert.strictEqual(m.summary(skipped, m.bank).skills.find((s) => s.id === 'reading-makers').learned, 0);
  const signals = {
    drill: (p) => m.recordDrillCall(p, m.bank, DRILLS[0], 'mine', at(2)),
    call: (p) => m.recordGap(p, m.callConcepts(m.bank, 'launch_agent_audit', ['where']), 'call', at(2)),
    reopen: (p) => m.recordGap(p, ['where-it-lives'], 'reopen', at(2)),
  };
  for (const [kind, signal] of Object.entries(signals)) {
    const p = signal(skipped);
    assert.strictEqual(m.conceptState(p, m.bank, 'where-it-lives'), 'worth-a-look', kind);
    assert.strictEqual(m.shouldOffer(p, m.bank, 'where-it-lives', at(0)), true, kind);
    assert.strictEqual(p.concepts['where-it-lives'].gaps[kind], 1, kind);
  }
  // A gap from before the skip doesn't count; a monitoring check never signals.
  const early = m.markKnown(m.recordGap(m.emptyProfile(NOW), ['where-it-lives'], 'call', at(0)), ['where-it-lives'], at(1));
  assert.strictEqual(m.conceptState(early, m.bank, 'where-it-lives'), 'skipped');
  for (const mod of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    assert.strictEqual(m.recordGap(skipped, m.callConcepts(m.bank, mod, ['where']), 'call', at(2)), skipped, mod);
  }
  // Learned outranks skipped.
  let q = m.markKnown(m.emptyProfile(NOW), ['who-made-it'], at(0));
  q = answer(m, q, m.bank, ['a1', 'a1-2', 'a1-3', 'a1', 'a1-2'], [true, true, true, true, true]);
  assert.strictEqual(m.conceptState(q, m.bank, 'who-made-it'), 'learned');
  assert.ok(q.concepts['who-made-it'].self, 'the skip stays as history');
});

// 7. Stealth: the profile is disguised in every mode, and nothing lives only in memory.
test('in every mode every profile write is a recipe box, and what was recorded is what loads back', async () => {
  const m = await load();
  for (const mode of ['standard', 'city', undefined]) {
    const store = recordingStore({ [m.OLD_KEY]: JSON.stringify(V3) });
    let p = m.loadProfile(store, NOW);
    p = m.markKnown(m.recordDrillCall(m.recordAnswer(p, m.bank, 'a1', false, at(1)), m.bank, DRILLS[0], 'mine', at(2)), ['couldnt-check'], at(3));
    p = m.noteOffered(m.recordGap(p, ['couldnt-check'], 'reopen', at(4)), 'couldnt-check', at(5));
    assert.ok(m.saveProfile(store, p, { seed: 5150, mode }));
    for (const [k, v] of store.writes) assert.ok(v.startsWith('{"kitchen":') && !v.includes('version'), `${mode}: ${k}`);
    assert.deepStrictEqual(m.loadProfile(store, NOW), p, `${mode}: every field written survives a restart`);
  }
});
