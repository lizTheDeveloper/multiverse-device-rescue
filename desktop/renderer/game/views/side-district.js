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

// One held item as what to write down: its name, where it was found, how,
// who made it, and the date. `date`: today, as the person would write it.
export function heldRows(h, date) {
  return [['Name', h.name || h.title], ['Where found', h.where], ['Found as', h.how], ['Made by', h.maker], ['Date', date]]
    .filter(([, v]) => typeof v === 'string' && v.trim() !== '');
}
export function heldText(h, date) {
  return heldRows(h, date).map(([k, v]) => `${k}: ${v}`).join('\n');
}
const MONO = new Set(['Where found']);

// `copied`: the index of the item just copied, or -1 when copying failed.
export function renderSide({ district, held = [], notice = false, scout = () => '', date = '', copied = null }) {
  const v = district.voice;
  const item = (h, i) => `<li class="held-item"><h4>${esc(h.title)}</h4>
        <dl class="evidence">${heldRows(h, date).map(([k, val]) => `<dt>${esc(k)}</dt><dd${MONO.has(k) ? ' class="mono"' : ''}>${esc(val)}</dd>`).join('')}</dl>
        <button type="button" class="btn-s" data-act="side-copy:${i}">COPY TO WRITE DOWN</button>
        ${copied === i ? '<p class="intel" role="status">Copied. Paste it somewhere that’s only yours.</p>'
    : copied === -(i + 1) ? '<p class="intel" role="status">It couldn’t be copied. Write it down from here.</p>' : ''}</li>`;
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
