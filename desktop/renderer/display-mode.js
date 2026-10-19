'use strict';

/*
 * One display preference, kept as `city` or `standard` and nothing else.
 * `city` opens straight into the game. Also a number made once per install,
 * which the game uses to name and dress one of its districts. Neither value
 * says why it was chosen, and nothing here ever removes another key.
 *
 * Loaded as a plain script (global `DisplayMode`); tested from Node.
 */
const DisplayMode = (function () {
  const MODE_KEY = 'device-rescue.display';
  const SEED_KEY = 'device-rescue.city-seed';
  const MODES = ['city', 'standard'];
  const MAX_SEED = 0x7fffffff;

  function readMode(storage) {
    try {
      const v = storage ? storage.getItem(MODE_KEY) : null;
      return MODES.includes(v) ? v : null;
    } catch (_) {
      return null;
    }
  }

  function writeMode(storage, mode) {
    if (!MODES.includes(mode)) return false;
    try {
      storage.setItem(MODE_KEY, mode);
      return true;
    } catch (_) {
      return false;
    }
  }

  function ensureSeed(storage, random = Math.random) {
    try {
      const raw = storage ? storage.getItem(SEED_KEY) : null;
      if (typeof raw === 'string' && /^\d+$/.test(raw)) {
        const n = Number(raw);
        if (Number.isInteger(n) && n >= 1 && n <= MAX_SEED) return n;
      }
    } catch (_) { /* blocked storage: a seed for this session only */ }
    const seed = 1 + Math.floor(random() * (MAX_SEED - 1));
    try { storage.setItem(SEED_KEY, String(seed)); } catch (_) { /* this session only */ }
    return seed;
  }

  return { MODE_KEY, SEED_KEY, MODES, readMode, writeMode, ensureSeed };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DisplayMode;
}
