const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const imp = (rel) => import(pathToFileURL(path.join(GAME, rel)).href);
// The same specifiers the controller passes, mapped onto files on disk.
const loadAll = async () => {
  const drills = await imp('drills.js');
  return { drills, bank: await drills.loadDrills((spec) => imp(spec)) };
};
const norm = (s) => String(s).replace(/\s+/g, ' ');
const sourceText = (d) => norm(d.sources.map((s) => fs.readFileSync(path.join(ROOT, s), 'utf8')).join('\n'));
// The lessons' gate (game-lessons.test.js): UI paths and backticked text must be word for word in a source.
const SEG = "[A-Z][\\w&]*(?: [\\w&]+)*";
const PATH_RE = new RegExp(`${SEG}(?: (?:>|→) ${SEG})+`, 'g');
const TICKS_RE = /`([^`]+)`/g;
function unsourced(text, src) {
  const bad = [];
  for (const p of norm(text).match(PATH_RE) || []) if (!src.includes(p)) bad.push(`UI path "${p}"`);
  for (const [, inner] of norm(text).matchAll(TICKS_RE)) if (!src.includes(inner)) bad.push(`\`${inner}\``);
  return bad;
}
const ownText = (d) => [d.title, d.setup, d.clues.what, d.why].filter((t) => typeof t === 'string' && t);
function moduleDistricts(name, districtIdFor) {
  const mods = path.join(ROOT, 'modules');
  return fs.readdirSync(mods).filter((cat) => fs.existsSync(path.join(mods, cat, name))).map((cat) => districtIdFor(cat));
}

test('every drill file loads and adds drills; ids are unique', async () => {
  const { drills, bank } = await loadAll();
  assert.ok(bank.length >= 12, `${bank.length} drills`);
  assert.strictEqual(new Set(bank.map((d) => d.id)).size, bank.length);
  for (const f of drills.DRILL_FILES) {
    const m = await imp(f);
    assert.ok(Array.isArray(m.default) && m.default.length >= 2, f);
  }
});

test('every drill has what the panel needs, and every tag is the right answer somewhere', async () => {
  const { bank } = await loadAll();
  const { DISTRICTS } = await imp('findings-to-city.js');
  const ids = new Set(DISTRICTS.map((d) => d.id));
  for (const d of bank) {
    assert.ok(ids.has(d.district), `${d.id}: district ${d.district}`);
    assert.ok(['critical', 'warning', 'info'].includes(d.severity), d.id);
    assert.ok(['mine', 'threat', 'closer'].includes(d.answer), d.id);
    assert.ok(d.title && d.why && d.clues && d.clues.what && typeof d.setup === 'string', d.id);
    assert.ok(d.clues.when === null || /^\d{4}-\d{2}-\d{2}$/.test(d.clues.when), d.id);
    assert.ok(d.clues.path === null || typeof d.clues.path === 'string', d.id);
    const m = d.clues.maker;
    assert.ok(m === null || (typeof m.name === 'string' && typeof m.verified === 'boolean' && typeof m.how === 'string'), d.id);
  }
  assert.deepStrictEqual([...new Set(bank.map((d) => d.answer))].sort(), ['closer', 'mine', 'threat']);
});

test('every drill cites sources that exist, and modules that exist and sweep its district', async () => {
  const { bank } = await loadAll();
  const { districtIdFor } = await imp('findings-to-city.js');
  const { MONITORING_MODULES } = await imp('ledger.js');
  for (const d of bank) {
    assert.ok(Array.isArray(d.sources) && d.sources.length, `${d.id} has no sources`);
    for (const s of d.sources) assert.ok(fs.existsSync(path.join(ROOT, s)), `${d.id}: missing source ${s}`);
    assert.ok(Array.isArray(d.modules) && d.modules.length, `${d.id} names no module`);
    const backed = new Set(d.modules.flatMap((m) => moduleDistricts(m, districtIdFor)));
    for (const m of d.modules) {
      assert.ok(moduleDistricts(m, districtIdFor).length, `${d.id}: no module ${m}`);
      assert.ok(!MONITORING_MODULES.has(m), `${d.id}: no drills about monitoring software`);
    }
    assert.ok(backed.has(d.district), `${d.id}: none of its modules is swept in ${d.district}`);
  }
});

test('every drill path is a place with a sourced note, and the drill’s own sources name that place', async () => {
  const { bank } = await loadAll();
  const { placeFor } = await imp('clues.js');
  for (const d of bank.filter((x) => x.clues.path)) {
    const place = placeFor(d.clues.path);
    assert.ok(place, `${d.id}: no sourced place for ${d.clues.path}`);
    assert.ok(sourceText(d).includes(place.pattern), `${d.id}: its sources don’t name ${place.pattern}`);
  }
});

test('who made it uses the engine’s own words, and every how-to-read line is a sourced one', async () => {
  const { bank } = await loadAll();
  const { MADE_BY_VERIFIED_LABEL, MADE_BY_REASON } = require('../renderer/app.js');
  const { drillClues, READING } = await imp('clues.js');
  const lines = new Set(Object.values(READING));
  for (const d of bank) {
    const m = d.clues.maker;
    if (m && m.verified) assert.ok(m.how in MADE_BY_VERIFIED_LABEL, `${d.id}: "${m.how}" isn’t a verified kind the app knows`);
    if (m && !m.verified) assert.ok(m.how in MADE_BY_REASON || m.how === 'script', `${d.id}: "${m.how}" isn’t a reason the app knows`);
    const cs = drillClues(d);
    assert.ok(cs.length >= 2, `${d.id}: at least two clues, so the clue bonus can be earned`);
    for (const c of cs) assert.ok(c.reading === null || lines.has(c.reading), `${d.id}: ${c.kind} has an unsourced reading`);
  }
});

test('no drill diagnoses this computer, names a duration, touches monitoring, or makes up a UI path', async () => {
  const { drills, bank } = await loadAll();
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await imp('training.js');
  for (const d of bank) {
    const src = sourceText(d);
    for (const text of ownText(d)) {
      for (const phrase of DIAGNOSTIC_PHRASES) assert.ok(!text.toLowerCase().includes(phrase), `${d.id}: "${phrase}"`);
      assert.doesNotMatch(text, TIME_WORDS, `${d.id}: time word in "${text}"`);
      assert.doesNotMatch(text, drills.MONITORING_WORDS, `${d.id}: no drills about monitoring or being watched`);
      assert.deepStrictEqual(unsourced(text, src), [], `${d.id}: not word for word in its sources`);
    }
  }
});

test('the gate catches a made-up place', async () => {
  const { placeFor } = await imp('clues.js');
  assert.strictEqual(placeFor('/Users/x/Secret Stash/run'), null);
  assert.strictEqual(placeFor('C:\\Hidden\\x.exe'), null);
});

test('about one drill per four real signals, at most three', async () => {
  const { drillCount, MAX_DRILLS } = await imp('drills.js');
  assert.deepStrictEqual([0, 1, 4, 5, 8, 9, 12, 40].map(drillCount), [0, 1, 1, 2, 2, 3, 3, 3]);
  assert.strictEqual(MAX_DRILLS, 3);
});

test('drills come from the districts in the real queue, fresh ones first', async () => {
  const { chooseDrills, pickDrills } = await imp('drills.js');
  const { emptyDeck } = await imp('progress.js');
  const bank = [{ id: 'g1', district: 'gatehouse' }, { id: 'g2', district: 'gatehouse' }, { id: 'j1', district: 'junkyard' }, { id: 'w1', district: 'wires' }];
  const real = (district, n) => Array.from({ length: n }, (_, i) => ({ id: `${district}${i}`, kind: 'real', districtId: district }));
  assert.deepStrictEqual(chooseDrills(bank, real('gatehouse', 5), emptyDeck(), 0).map((d) => d.id), ['g1', 'g2']);
  assert.deepStrictEqual(chooseDrills(bank, [...real('gatehouse', 4), ...real('junkyard', 4)], emptyDeck(), 0).map((d) => d.id), ['g1', 'j1']);
  assert.deepStrictEqual(chooseDrills(bank, real('foundations', 8), emptyDeck(), 0), [], 'no drill from a district that isn’t in the queue');
  assert.deepStrictEqual(chooseDrills(bank, [], emptyDeck(), 0), [], 'zero findings: no drills mixed in');
  const done = { ...emptyDeck(), once: { 'drill:g1': true } };
  assert.deepStrictEqual(pickDrills(bank, ['gatehouse'], done, 0).map((d) => d.id), ['g2', 'g1']);
  assert.deepStrictEqual(pickDrills(bank, ['gatehouse'], emptyDeck(), 1).map((d) => d.id), ['g2', 'g1'], 'the seed rotates which comes first');
});

test('drills sit after every fourth real signal, the rest at the end', async () => {
  const { mixDrills, drillSignal } = await imp('drills.js');
  const real = Array.from({ length: 5 }, (_, i) => ({ id: `r${i}` }));
  const d = (id) => ({ id, district: 'gatehouse', severity: 'warning', title: id, clues: { what: 'w' } });
  assert.deepStrictEqual(mixDrills(real, [d('a'), d('b')]).map((x) => x.id), ['r0', 'r1', 'r2', 'r3', 'drill:a', 'r4', 'drill:b']);
  const s = drillSignal(d('a'));
  assert.deepStrictEqual([s.kind, s.tag, s.missionId, s.finding, s.districtId], ['drill', null, null, null, 'gatehouse']);
});

test('a drill never counts in integrity, sorted, or the deck’s tags', async () => {
  const { drillSignal } = await imp('drills.js');
  const { cityIntegrity, sortedCount } = await imp('signals.js');
  const { reconcileDeck } = await imp('ledger.js');
  const { emptyDeck } = await imp('progress.js');
  const city = { districts: [{ id: 'gatehouse', checksRan: 1, missions: [], notes: [], fog: [] }] };
  const sigs = [{ ...drillSignal({ id: 'a', district: 'gatehouse', severity: 'critical', title: 'a', clues: { what: 'w' } }), tag: 'threat' }];
  assert.strictEqual(cityIntegrity(city, sigs).percent, 100);
  assert.strictEqual(sortedCount(sigs), 0);
  assert.deepStrictEqual(reconcileDeck(emptyDeck(), sigs, new Set()).deck.tags, {});
});

test('mixDrills copes with no drills, and loadDrills drops a drill with no clues', async () => {
  const { mixDrills, loadDrills } = await imp('drills.js');
  assert.deepStrictEqual(mixDrills([{ id: 'r0' }], undefined).map((x) => x.id), ['r0']);
  assert.deepStrictEqual(mixDrills(undefined, undefined), []);
  const good = { id: 'ok', answer: 'mine', clues: { what: 'w' } };
  const bank = await loadDrills(async () => ({ default: [good, { id: 'noclues', answer: 'mine' }, { id: 'badclues', answer: 'mine', clues: 'x' }] }));
  assert.deepStrictEqual(bank.map((d) => d.id), ['ok']);
});

test('signed does not mean wanted, and unsigned does not mean bad', async () => {
  const { bank } = await loadAll();
  assert.ok(bank.some((d) => d.clues.maker && d.clues.maker.verified && d.answer !== 'mine'), 'a signed drill that is not mine');
  assert.ok(bank.some((d) => d.clues.maker && !d.clues.maker.verified && d.answer === 'mine'), 'an unsigned drill that is mine');
});
