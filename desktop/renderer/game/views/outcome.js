import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';

// `failed`: FixFlow.recheckFailedText's { headline, detail } for a re-check
// that couldn't run. `fixApplied`: a fix ran first, so the text says the
// change was made (with Undo here) and never that nothing was changed.
export function renderOutcome({ kind, mission: m, scout, message, undoHtml, failed = null, fixApplied = false }) {
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
  if (kind === 'put-back') {
    return `
    <section class="outcome o-not">
      <span class="badge warn">CHECKED AGAIN: SHOWING</span><h2>PUT BACK</h2>
      <p>${esc(m.title)}</p>
      <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(SCOUT.putBack)}</p></div>
      <button type="button" class="btn-s" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button>
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
  // One heading, one explanation. The engine's own message only when it says
  // something else (a sweep running), never the generic "couldn't check" again.
  const head = fixApplied && failed ? failed.headline : SCOUT.couldnt;
  const detail = fixApplied && failed ? failed.detail : 'You can try again. The building stays dark until a check can see it.';
  const extra = message && !/couldn[’']t (?:check|re-check)|nothing was changed/i.test(message) ? message : '';
  return `
    <section class="outcome o-err">
      <h2>COULDN’T RE-CHECK</h2>
      <p>${esc(head)} ${esc(detail)}</p>
      ${fixApplied && undoHtml ? undoHtml : ''}
      ${extra ? `<p class="from">${esc(extra)}</p>` : ''}
      <div class="row"><button type="button" class="btn-s" data-act="recheck">TRY THE RE-CHECK AGAIN</button>
      <button type="button" class="btn-t" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button></div>
    </section>`;
}
