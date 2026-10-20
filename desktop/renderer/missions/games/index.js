// The mini-game registry: games/<type>.js for every TYPE_IDS entry. A game
// that is missing (still being built), fails to load, or breaks the contract's
// shape falls back to Odd Jobs (simple.js), so the registry works with only
// simple present.
//
//   loadGames({ importer }) -> Promise<{ games: {[type]: game}, modules: {[type]: module namespace}, own: Set<type>, problems: [string] }>
//       `modules` keeps each game file's other exports (the notes game's batchNotes).
//   gameFor(registry, type, platform?) -> game (simple when none; with the platform's own practice round, R11)
//   ownGames(registry) -> the games that loaded for their own type (their `covers` feed types.buildTable)
import simple from './simple.js';
import { TYPE_IDS, validateGame, noDoubleClaims, practiceOf } from '../contract.js';

const here = (type) => new URL(`./${type}.js`, import.meta.url).href;

export async function loadGames({ importer = (spec) => import(spec) } = {}) {
  const games = { simple };
  const modules = {};
  const own = new Set(['simple']);
  const problems = [];
  await Promise.all(TYPE_IDS.filter((t) => t !== 'simple').map(async (type) => {
    let game = null;
    try {
      const mod = await importer(here(type));
      game = mod && mod.default;
      modules[type] = mod;
    } catch (_) {
      games[type] = simple; // not built yet
      return;
    }
    const shape = validateGame(game);
    if (game && game.type !== type) shape.push(`exports type "${game && game.type}"`);
    if (shape.length) { problems.push(`${type}: ${shape.join('; ')}`); games[type] = simple; return; }
    games[type] = game;
    own.add(type);
  }));
  // Two games claiming one finding: both keep loading, the problem is reported
  // (types.js resolves it the same way every time; the test suite fails on it).
  problems.push(...noDoubleClaims([...own].map((t) => games[t])));
  for (const t of Object.keys(modules)) if (!own.has(t)) delete modules[t];
  return { games, modules, own, problems };
}

// `platform`: a game with its own practice round for that platform (contract R11) comes with that round as its
// `practice`, the same object each time; otherwise the game itself.
const byPlatform = new WeakMap();
export function gameFor(registry, type, platform) {
  const game = (registry && registry.games && registry.games[type]) || simple;
  const practice = practiceOf(game, platform);
  if (practice === game.practice) return game;
  if (!byPlatform.has(game)) byPlatform.set(game, {});
  const cache = byPlatform.get(game);
  if (!cache[platform] || cache[platform].practice !== practice) cache[platform] = { ...game, practice };
  return cache[platform];
}

export function ownGames(registry) {
  return registry && registry.own ? [...registry.own].map((t) => registry.games[t]).filter(Boolean) : [];
}

export { simple };
