import { esc } from '../escape.js';
import { FIRST_STEPS, HELP, OPEN_NOTE, SIX_ROSES, LEAVING, HELD } from '../side-district.js';
// The list's evidence block (a plain script, not an ES module).
import * as evidenceModule from '../../evidence.js';

// In the page the script sets window.Evidence; in Node (tests) it is CommonJS.
const EV = globalThis.Evidence || evidenceModule.default;

// The district's tile, on the deck's city and on the Training Grounds. It names only the place.
export function sideTileHtml(district, heldCount = 0) {
  return `<div class="side-tile look-${esc(district.look)}">
    <button type="button" class="btn-s" data-go="side">${esc(district.name.toUpperCase())} ▶</button>${heldCount ? ' <span class="badge">NEW</span>' : ''}</div>`;
}

// On the deck when the checkup found something that belongs there. Only the
// place again, and no second button: the tile (marked NEW) is the way there.
export function heldNoticeHtml(district) {
  return `<p class="link-notice" role="status">Something new in ${esc(district.name)}. Its tile on the city is marked NEW.</p>`;
}

// One held item as what to write down: the shared evidence block, held. That
// gives Name, Where found, How detected, Made by (verified or not) and the
// Date, drawn large with "Write this on paper or on another device." No copy
// button and nothing on the clipboard: monitoring software can read it.
// `seen`: today (a Date); the block writes it as a plain day.
export function heldBlockHtml(h, seen = new Date()) {
  const x = h || {};
  const f = x.finding || { module: x.module, title: x.title,
    data: { stalkerware_name: x.name || x.title, location: x.where, detected_as: x.how } };
  const rows = EV.evidenceRows(f, { mode: 'city', held: true, seen });
  return EV.renderEvidence(rows, { held: true, title: (h && h.title) || 'Write this down' });
}

// `seen`: today, for the Date row.
export function renderSide({ district, held = [], notice = false, scout = () => '', seen = new Date() }) {
  const v = district.voice;
  const item = (h) => `<li class="held-item">${heldBlockHtml(h, seen)}</li>`;
  const heldHtml = held.length ? `
    <div class="panel active" role="note"><h3 class="side-h">${esc(HELD.heading.text)}</h3>
      <ul class="held-items">${held.map(item).join('')}</ul>
      <ol class="side-steps">${HELD.steps.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ol></div>` : '';
  const help = HELP.map((r) => `<li>${esc(r.text)}${r.url ? ` <code>${esc(r.url)}</code>` : ''}</li>`).join('');
  return `
  <section class="side look-${esc(district.look)}" aria-labelledby="side-title">
    <header class="hud side-top"><h2 class="hud-title" id="side-title" tabindex="-1">${esc(district.name.toUpperCase())}</h2>
      <button type="button" class="btn-p" data-act="side-back">BACK TO THE GAME</button></header>
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(v.hello)}</p></div>
    ${heldHtml}
    <div class="panel"><h3 class="side-h">Quiet first steps</h3>
      <ol class="side-steps">${FIRST_STEPS.map((x) => `<li><b>${esc(x.title)}</b> ${esc(x.text)}</li>`).join('')}</ol></div>
    <div class="panel"><h3 class="side-h">Who can help</h3><ul class="notes">${help}</ul>
      <p class="intel">${esc(OPEN_NOTE.text)}</p></div>
    <div class="panel"><h3 class="side-h">${esc(SIX_ROSES.name)}</h3>
      <p class="intel">${esc(SIX_ROSES.text)}</p><p class="intel">${esc(SIX_ROSES.note.text)}</p>
      <button type="button" class="btn-s" data-act="side-open-guide">OPEN IT IN YOUR BROWSER</button>
      ${notice ? `<p class="link-notice" role="status">${esc('It couldn’t be opened from here.')}</p>` : ''}</div>
    <div class="panel"><p class="intel"><b>${esc(LEAVING.text)}</b></p></div>
    <p class="say">${esc(v.bye)}</p>
    <p class="intel">Press Esc to go back to the game.</p>
  </section>`;
}
