// TEXT & MOTION: the city's display settings (DisplayPrefs), on a slim bar above
// every city screen. The bar sits outside the frame, so redraws never touch it,
// and it is the first Tab stop. Changes apply at once and are remembered.
const SIZE_WORD = { normal: 'Normal', large: 'Large', larger: 'Larger' };
const FONT_WORD = { city: 'City lettering', plain: 'Plain lettering (easier to read)' };
const MOTION_WORD = { system: 'Follow this computer’s setting', less: 'Less motion' };

function group(name, legend, values, words, current) {
  const items = values.map((v) => `
      <label class="display-choice"><input type="radio" name="${name}" value="${v}"${v === current ? ' checked' : ''}> <span>${words[v]}</span></label>`).join('');
  return `<fieldset class="display-group"><legend>${legend}</legend>${items}</fieldset>`;
}

// `P` is DisplayPrefs; `prefs` is what P.read gave.
export function displayPanelHtml(P, prefs) {
  return `
  <button type="button" class="display-open" data-display="open" aria-haspopup="dialog"><span aria-hidden="true">Aa</span> TEXT &amp; MOTION</button>
  <dialog class="display-panel" aria-labelledby="display-title">
    <h2 id="display-title">Text and motion</h2>
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
// element (the tests' stand-ins), it does nothing.
export function attachDisplayPanel({ bar, host, storage, win }) {
  const P = win && win.DisplayPrefs;
  if (!P || !bar || typeof bar.querySelector !== 'function') return false;
  let prefs = P.read(storage);
  applyDisplayPrefs(P, host, prefs, win.rescue);
  bar.innerHTML = displayPanelHtml(P, prefs);
  const dialog = bar.querySelector('dialog');
  const open = bar.querySelector('[data-display="open"]');
  if (!dialog || !open) return false;
  open.addEventListener('click', () => { if (typeof dialog.showModal === 'function') dialog.showModal(); });
  bar.querySelector('[data-display="close"]').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => open.focus());
  dialog.addEventListener('change', (e) => {
    const input = e.target;
    const known = input && input.type === 'radio' && Object.prototype.hasOwnProperty.call(P.PREFS, input.name)
      && P.PREFS[input.name].values.includes(input.value);
    if (!known) return;
    P.write(storage, input.name, input.value); // blocked storage: this session only
    prefs = { ...prefs, [input.name]: input.value };
    applyDisplayPrefs(P, host, prefs, win.rescue);
  });
  return true;
}
