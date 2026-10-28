// SETTINGS: one control for how the city is shown, on a slim bar above every
// city screen: how much detail (level.js) and text size, lettering and motion
// (DisplayPrefs). The bar sits outside the frame, so redraws never touch it,
// and it is the first Tab stop. Changes apply at once and are remembered.
import { LEVELS, LEVEL_CHOICES } from './level.js';

const LEVEL_WORD = Object.fromEntries(LEVEL_CHOICES.map((c) => [c.id, c.title]));
const SIZE_WORD = { normal: 'Normal', large: 'Large', larger: 'Larger' };
const FONT_WORD = { city: 'City lettering', plain: 'Plain lettering (easier to read)' };
const MOTION_WORD = { system: 'Follow this computer’s setting', less: 'Less motion' };

function group(name, legend, values, words, current) {
  const items = values.map((v) => `
      <label class="display-choice"><input type="radio" name="${name}" value="${v}"${v === current ? ' checked' : ''}> <span>${words[v]}</span></label>`).join('');
  return `<fieldset class="display-group"><legend>${legend}</legend>${items}</fieldset>`;
}

// `P` is DisplayPrefs; `prefs` is what P.read gave; `level` the detail level (level.js levelOf).
export function displayPanelHtml(P, prefs, level = null) {
  return `
  <button type="button" class="display-open" data-display="open" aria-haspopup="dialog"><span aria-hidden="true">⚙</span> SETTINGS</button>
  <dialog class="display-panel" aria-labelledby="display-title">
    <h2 id="display-title">Settings</h2>
    ${level ? `${group('level', 'How much detail', LEVELS, LEVEL_WORD, level)}
    <p class="display-note">This changes how much is shown, not what is checked. Every fix still asks first.</p>` : ''}
    ${group('textSize', 'Text size', P.SIZES, SIZE_WORD, prefs.textSize)}
    ${group('font', 'Letters', P.FONTS, FONT_WORD, prefs.font)}
    ${group('motion', 'Motion', P.MOTIONS, MOTION_WORD, prefs.motion)}
    <button type="button" class="btn-p" data-display="close">DONE</button>
  </dialog>`;
}

// The city's letters and motion are attributes on the host (game.css reads them
// with :host(...)); the text size zooms the whole window through preload.
export function applyDisplayPrefs(P, host, prefs, rescue) {
  if (host && typeof host.setAttribute === 'function') {
    host.setAttribute('data-font', prefs.font);
    host.setAttribute('data-motion', prefs.motion);
    host.setAttribute('data-text-size', prefs.textSize);
  }
  try {
    if (rescue && typeof rescue.setZoom === 'function') rescue.setZoom(P.zoomFor(prefs.textSize));
  } catch (_) { /* the page still works at its usual size */ }
}

// Draws the bar into `bar` and wires it. Without DisplayPrefs or a real bar
// element (the tests' stand-ins), it does nothing. `level()` reads the detail
// level and `setLevel(v)` stores it and redraws the city (the controller's).
export function attachDisplayPanel({ bar, host, storage, win, level = null, setLevel = null }) {
  const P = win && win.DisplayPrefs;
  if (!P || !bar || typeof bar.querySelector !== 'function') return false;
  let prefs = P.read(storage);
  applyDisplayPrefs(P, host, prefs, win.rescue);
  bar.innerHTML = displayPanelHtml(P, prefs, level ? level() : null);
  const dialog = bar.querySelector('dialog');
  const open = bar.querySelector('[data-display="open"]');
  if (!dialog || !open) return false;
  open.addEventListener('click', () => {
    // The level can change elsewhere (the first-run cards), so the panel reads it as it opens.
    if (level) dialog.querySelectorAll('input[name="level"]').forEach((r) => { r.checked = r.value === level(); });
    if (typeof dialog.showModal === 'function') dialog.showModal();
  });
  bar.querySelector('[data-display="close"]').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => open.focus());
  dialog.addEventListener('change', (e) => {
    const input = e.target;
    if (input && input.type === 'radio' && input.name === 'level') {
      if (setLevel && LEVELS.includes(input.value)) setLevel(input.value);
      return;
    }
    const known = input && input.type === 'radio' && Object.prototype.hasOwnProperty.call(P.PREFS, input.name)
      && P.PREFS[input.name].values.includes(input.value);
    if (!known) return;
    P.write(storage, input.name, input.value); // blocked storage: this session only
    prefs = { ...prefs, [input.name]: input.value };
    applyDisplayPrefs(P, host, prefs, win.rescue);
  });
  return true;
}
