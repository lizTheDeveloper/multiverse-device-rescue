// Several worries at once: one situation the rest of the app can read. The
// checkup runs the union of their profiles; "watching me" among them counts.
const test = require('node:test');
const assert = require('node:assert');
const Worries = require('../renderer/worries.js');
const { SITUATIONS } = require('../renderer/app.js');

const profileOf = (id) => SITUATIONS.find((s) => s.id === id).profile;

test('every worry is either in the checklist or runs on its own', () => {
  const all = [...Worries.CHECKLIST_IDS, ...Worries.ON_THEIR_OWN].sort();
  assert.deepStrictEqual(all, SITUATIONS.map((s) => s.id).sort());
});

test('one worry is that worry, with its ids', () => {
  const s = Worries.combine(['wifi'], SITUATIONS);
  assert.strictEqual(s.id, 'wifi');
  assert.deepStrictEqual(s.ids, ['wifi']);
  assert.strictEqual(Worries.scanProfile(s), profileOf('wifi'));
  assert.ok(Object.isFrozen(s));
  assert.strictEqual(Worries.combine(['phone'], SITUATIONS).id, 'phone');
  assert.strictEqual(Worries.scanProfile(Worries.combine(['unsure'], SITUATIONS)), null);
});

test('several worries run the union of their profiles, in the list order', () => {
  const s = Worries.combine(['wifi', 'hacked'], SITUATIONS);
  assert.strictEqual(s.id, 'several');
  assert.deepStrictEqual(s.ids, ['hacked', 'wifi']);
  assert.deepStrictEqual(Worries.scanProfile(s), [profileOf('hacked'), profileOf('wifi')]);
  assert.strictEqual(s.title, `${SITUATIONS[0].title} and ${SITUATIONS.find((x) => x.id === 'wifi').title}`);
  assert.strictEqual(s.guide, SITUATIONS[0].guide);
  assert.strictEqual(s.safety, false);
});

test('two worries with the same profile run it once', () => {
  const s = Worries.combine(['hacked', 'watched'], SITUATIONS);
  assert.strictEqual(Worries.scanProfile(s), 'digital_security_reset');
  assert.strictEqual(s.safety, true, '"watching me" among several still counts');
  assert.ok(Worries.has(s, 'watched'));
});

test('"check everything" and the iPhone check never mix with others', () => {
  assert.strictEqual(Worries.combine(['hacked', 'unsure'], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['phone', 'wifi'], SITUATIONS), null);
  assert.strictEqual(Worries.combine([], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['nope'], SITUATIONS), null);
  assert.strictEqual(Worries.combine(['nope', 'wifi'], SITUATIONS).id, 'wifi');
});

test('helpers read a single entry, a combined one, or nothing', () => {
  const one = SITUATIONS.find((s) => s.id === 'identity');
  assert.deepStrictEqual(Worries.idsOf(one), ['identity']);
  assert.deepStrictEqual(Worries.idsOf(null), []);
  assert.ok(!Worries.has(null, 'watched'));
  const two = Worries.combine(['identity', 'hacked'], SITUATIONS);
  assert.strictEqual(Worries.key(two), Worries.key(Worries.combine(['hacked', 'identity'], SITUATIONS)));
  assert.notStrictEqual(Worries.key(two), Worries.key(one));
  assert.strictEqual(Worries.firstWith(two, { identity: 'I', hacked: 'H' }), 'H');
  assert.strictEqual(Worries.firstWith(two, { wifi: 'W' }), undefined);
  assert.strictEqual(Worries.scanProfile(null), null);
});

test('the game recommends lessons for any of the worries', async () => {
  const { orderLessons, worryIdsOf } = await import('../renderer/game/training.js');
  const L = (id, recommendedFor = []) => ({ id, title: id, recommendedFor, modules: [], questions: [] });
  const lessons = [L('password-asker'), L('a', ['wifi']), L('b', ['identity']), L('c', [])];
  const both = orderLessons(lessons, ['wifi', 'identity']);
  assert.deepStrictEqual(both.recommended.map((l) => l.id), ['password-asker', 'a', 'b']);
  assert.deepStrictEqual(both.other.map((l) => l.id), ['c']);
  assert.deepStrictEqual(orderLessons(lessons, 'wifi').recommended.map((l) => l.id), ['password-asker', 'a']);
  assert.deepStrictEqual(worryIdsOf({ id: 'several', ids: ['hacked', 'wifi'] }), ['hacked', 'wifi']);
  assert.deepStrictEqual(worryIdsOf({ id: 'wifi' }), ['wifi']);
  assert.deepStrictEqual(worryIdsOf(null), []);
});

test('the game\'s starting district follows the first worry that has one', async () => {
  const { focusFor } = await import('../renderer/game/one-city.js');
  assert.strictEqual(focusFor({ id: 'several', ids: ['wifi', 'identity'] }), 'reclamation');
  assert.strictEqual(focusFor({ id: 'several', ids: ['hacked', 'identity'] }), 'master-keys');
  assert.strictEqual(focusFor({ id: 'several', ids: ['wifi', 'sketchy'] }), 'computer');
  assert.strictEqual(focusFor({ id: 'hacked' }), 'master-keys');
});
