import { esc } from '../escape.js';
import { FIRST_STEPS, HELP, OPEN_NOTE, SIX_ROSES, LEAVING, HELD } from '../side-district.js';

// The district's tile, on the deck's city and on the Training Grounds. It names only the place.
export function sideTileHtml(district, heldCount = 0) {
  return `<div class="side-tile look-${esc(district.look)}">
    <button type="button" class="btn-s" data-go="side">${esc(district.name.toUpperCase())} ▶</button>${heldCount ? ' <span class="badge">NEW</span>' : ''}</div>`;
}

// On the deck when the checkup found something that belongs there. Only the place again.
export function heldNoticeHtml(district) {
  return `<p class="link-notice" role="status">Something new in ${esc(district.name)}. <button type="button" class="btn-t" data-go="side">GO THERE ▶</button></p>`;
}

export function renderSide({ district, held = [], notice = false, scout = () => '' }) {
  const v = district.voice;
  const heldHtml = held.length ? `
    <div class="panel active" role="note"><h3 class="label">${esc(HELD.heading.text)}</h3>
      <ul class="notes">${held.map((h) => `<li>${esc(h.title)}</li>`).join('')}</ul>
      <ol class="side-steps">${HELD.steps.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ol></div>` : '';
  const help = HELP.map((r) => `<li>${esc(r.text)}${r.url ? ` <code>${esc(r.url)}</code>` : ''}</li>`).join('');
  return `
  <section class="side look-${esc(district.look)}" aria-labelledby="side-title">
    <header class="hud side-top"><h2 class="hud-title" id="side-title" tabindex="-1">${esc(district.name.toUpperCase())}</h2>
      <button type="button" class="btn-p" data-act="side-back">BACK TO THE GAME</button></header>
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(v.hello)}</p></div>
    ${heldHtml}
    <div class="panel"><h3 class="label">QUIET FIRST STEPS</h3>
      <ol class="side-steps">${FIRST_STEPS.map((x) => `<li><b>${esc(x.title)}</b> ${esc(x.text)}</li>`).join('')}</ol></div>
    <div class="panel"><h3 class="label">WHO CAN HELP</h3><ul class="notes">${help}</ul>
      <p class="intel">${esc(OPEN_NOTE.text)}</p></div>
    <div class="panel"><h3 class="label">${esc(SIX_ROSES.name.toUpperCase())}</h3>
      <p class="intel">${esc(SIX_ROSES.text)}</p><p class="intel">${esc(SIX_ROSES.note.text)}</p>
      <button type="button" class="btn-s" data-act="side-open-guide">OPEN IT IN YOUR BROWSER</button>
      ${notice ? `<p class="link-notice" role="status">${esc('It couldn’t be opened from here.')}</p>` : ''}</div>
    <div class="panel"><p class="intel"><b>${esc(LEAVING.text)}</b></p></div>
    <p class="say">${esc(v.bye)}</p>
    <p class="intel">Press Esc to go back to the game.</p>
  </section>`;
}
