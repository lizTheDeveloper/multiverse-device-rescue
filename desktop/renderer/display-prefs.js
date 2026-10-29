'use strict';

/*
 * How the app is drawn for the person reading it: text size, the letters the
 * city uses, and motion. Each is one of a short list of words and nothing else;
 * a missing or garbled value is the default. Like DisplayMode, nothing here
 * says why a value was chosen, and nothing here ever removes another key.
 *
 * Text size zooms the whole window (the page reflows, as browser zoom does).
 * Plain letters swap the city's display face for the body face. Less motion
 * turns animations off even when the computer doesn't ask for that.
 *
 * Loaded as a plain script (global `DisplayPrefs`); tested from Node.
 */
const DisplayPrefs = (function () {
  const TEXT_KEY = 'device-rescue.text-size';
  const FONT_KEY = 'device-rescue.font';
  const MOTION_KEY = 'device-rescue.motion';
  const SIZES = ['normal', 'large', 'larger'];
  const FONTS = ['city', 'plain'];
  const MOTIONS = ['system', 'less'];
  const ZOOM = { normal: 1, large: 1.25, larger: 1.5 };
  const PREFS = {
    textSize: { key: TEXT_KEY, values: SIZES },
    font: { key: FONT_KEY, values: FONTS },
    motion: { key: MOTION_KEY, values: MOTIONS },
  };

  function readOne(storage, name) {
    const p = PREFS[name];
    try {
      const v = storage ? storage.getItem(p.key) : null;
      return p.values.includes(v) ? v : p.values[0];
    } catch (_) {
      return p.values[0];
    }
  }

  // { textSize, font, motion }, each a known value.
  function read(storage) {
    return { textSize: readOne(storage, 'textSize'), font: readOne(storage, 'font'), motion: readOne(storage, 'motion') };
  }

  function write(storage, name, value) {
    const p = Object.prototype.hasOwnProperty.call(PREFS, name) ? PREFS[name] : null;
    if (!p || !p.values.includes(value)) return false;
    try {
      storage.setItem(p.key, value);
      return true;
    } catch (_) {
      return false;
    }
  }

  function zoomFor(size) {
    return Object.prototype.hasOwnProperty.call(ZOOM, size) ? ZOOM[size] : 1;
  }

  // True when animations should stop: the person asked here, or the computer asks.
  function lessMotion(prefs, matchMedia) {
    if (prefs && prefs.motion === 'less') return true;
    try {
      return !!(typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (_) {
      return false;
    }
  }

  return { TEXT_KEY, FONT_KEY, MOTION_KEY, SIZES, FONTS, MOTIONS, PREFS, read, write, zoomFor, lessMotion };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DisplayPrefs;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.DisplayPrefs = DisplayPrefs;
}
