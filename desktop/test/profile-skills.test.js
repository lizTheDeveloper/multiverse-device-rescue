const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');

const GAME = path.join(__dirname, '..', 'renderer', 'game');
const imp = (rel) => import(pathToFileURL(path.join(GAME, rel)).href);

test('concept ids are unique, disk-safe slugs', async () => {
  const { CONCEPTS } = await imp('profile/skills.js');
  assert.strictEqual(new Set(CONCEPTS.map((c) => c.id)).size, CONCEPTS.length);
  for (const c of CONCEPTS) {
    assert.match(c.id, /^[a-z]+(?:-[a-z]+)*$/, c.id);
    assert.doesNotMatch(c.id, FORBIDDEN_ON_DISK, c.id);
    assert.ok(typeof c.title === 'string' && c.title.trim(), c.id);
  }
});

test('every skill names real, shown concepts; every shown concept is in exactly one skill', async () => {
  const { SKILLS, CONCEPTS, conceptById, isHidden } = await imp('profile/skills.js');
  const seen = new Map();
  for (const s of SKILLS) {
    assert.doesNotMatch(s.id, FORBIDDEN_ON_DISK, s.id);
    for (const c of s.concepts) {
      assert.ok(conceptById(c), `${s.id}: no concept ${c}`);
      assert.ok(!isHidden(c), `${s.id}: ${c} is hidden and may not be in a skill`);
      seen.set(c, (seen.get(c) || 0) + 1);
    }
  }
  for (const c of CONCEPTS.filter((x) => !x.hidden)) assert.strictEqual(seen.get(c.id), 1, c.id);
});

test('every drill in the bank is mapped (to a concept, or to null), and only to concepts that exist', async () => {
  const { DRILL_CONCEPTS, CLUE_CONCEPTS, conceptById } = await imp('profile/skills.js');
  const drills = await imp('drills.js');
  const bank = await drills.loadDrills((spec) => imp(spec));
  for (const d of bank) assert.ok(Object.prototype.hasOwnProperty.call(DRILL_CONCEPTS, d.id), `drill ${d.id} is not mapped`);
  for (const [id, c] of Object.entries(DRILL_CONCEPTS)) {
    assert.ok(bank.some((d) => d.id === id), `no drill ${id}`);
    if (c !== null) assert.ok(conceptById(c), `${id}: no concept ${c}`);
  }
  for (const c of Object.values(CLUE_CONCEPTS)) assert.ok(conceptById(c));
});

test('skill ids are unique, and no skill or concept title uses a word that must not reach the disk', async () => {
  const { SKILLS, CONCEPTS } = await imp('profile/skills.js');
  assert.strictEqual(new Set(SKILLS.map((s) => s.id)).size, SKILLS.length, 'skill ids are unique');
  for (const s of SKILLS) assert.doesNotMatch(s.title, FORBIDDEN_ON_DISK, s.id);
  for (const c of CONCEPTS) assert.doesNotMatch(c.title, FORBIDDEN_ON_DISK, c.id);
});

test('a drill id that names an Object.prototype property maps to no concept in the bank', async () => {
  const { buildBank } = await imp('profile/item-bank.js');
  const bank = buildBank([], [{ id: 'constructor' }, { id: 'toString' }, { id: '__proto__' }]);
  for (const id of ['constructor', 'toString', '__proto__']) assert.strictEqual(bank.items.get(`drill:${id}`).concept, null, id);
});
