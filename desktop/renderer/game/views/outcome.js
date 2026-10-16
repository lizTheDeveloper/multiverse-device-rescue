import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';

export function renderOutcome({ kind, mission: m, scout, message, undoHtml }) {
  if (kind === 'reclaimed') {
    return `
    <section class="outcome o-win">
      <span class="badge safe">CHECKED AGAIN: GONE</span>
      <h2>RECLAIMED</h2>
      <p>${esc(SCOUT.reclaimed)}</p>
      ${undoHtml || ''}
      <p class="label">HOW DID THAT GO?</p>
      <div class="choices">
        <button type="button" class="choice" data-act="debrief:easy">Easier than I thought</button>
        <button type="button" class="choice" data-act="debrief:nervous">A bit nerve-wracking</button>
        <button type="button" class="choice" data-act="debrief:worried">I’m still worried</button>
      </div>
      ${scout('proud', 72)}
    </section>`;
  }
  if (kind === 'yours') {
    return `
    <section class="outcome o-yours">
      <span class="badge yours">MARKED AS YOURS</span><h2>YOURS</h2><p>${esc(SCOUT.yours)}</p>
      <button type="button" class="btn-s" data-go="district:${esc(m.districtId)}">BACK TO THE DISTRICT</button>
    </section>`;
  }
  if (kind === 'not-yet') {
    return `
    <section class="outcome o-not">
      <span class="badge warn">CHECKED AGAIN: STILL THERE</span><h2>NOT YET</h2>
      <p>Here’s what’s still showing: ${esc(m.title)}</p>
      ${message ? `<p>${esc(message)}</p>` : ''}
      <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(SCOUT.notYet)}</p></div>
      <button type="button" class="btn-s" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button>
    </section>`;
  }
  return `
    <section class="outcome o-err">
      <span class="badge fog">COULDN’T RE-CHECK</span><h2>COULDN’T RE-CHECK</h2>
      <p>${esc(SCOUT.couldnt)} The building stays dark until a check can see it.</p>
      ${message ? `<p class="from">${esc(message)}</p>` : ''}
      <div class="row"><button type="button" class="btn-s" data-act="recheck">TRY THE RE-CHECK AGAIN</button>
      <button type="button" class="btn-t" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button></div>
    </section>`;
}
