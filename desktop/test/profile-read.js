// What the game saved, read back the way the app reads it: the recipe box,
// decoded. `savedAsV3` gives it in the old v3 shape the controller tests were
// written against. (require() of an ES module: Node 22.12 and later.)
const { decode } = require('../renderer/game/profile/recipe-box.js');

const PROFILE_KEY = 'device-rescue.recipe-box.v1';

function savedProfile(storage) {
  const text = storage.getItem(PROFILE_KEY);
  return text ? decode(text) : null;
}

function savedAsV3(storage) {
  const p = savedProfile(storage);
  if (!p) return null;
  const lessons = Object.fromEntries(Object.entries(p.lessons || {}).filter(([, l]) => l.visited).map(([id, l]) => [id, { completedAt: l.visited }]));
  return { version: 3, missions: p.missions, lessons,
    deck: { points: p.rank.points, rank: p.rank.index, drills: { right: p.drills.right, tried: p.drills.tried }, ...p.deck } };
}

module.exports = { PROFILE_KEY, savedProfile, savedAsV3 };
