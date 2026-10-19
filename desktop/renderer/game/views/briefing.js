import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';

export const SWEEP_RUNNING = 'The sweep is still running. You can act on this once it’s done.';

// `note` (held.js briefingNote) is what the list says about removing it:
// in 'standard' the one line with the full note behind it, which the engine's
// safety_note alone doesn't give (stalkerware has none); in 'city' the safety
// note in full, or on monitoring software the hold line and its help, and then
// no steps and nothing to act on.
// `scanRunning`: a sweep is still running, so nothing here can be acted on
// yet (main refuses changes and re-checks until it's done): no fix or mark
// controls and no I DID IT MYSELF, only a plain line and LATER.
export function renderBriefing({ mission: m, status, controlsHtml, scout, busy, wantsSafety, learned, note, scanRunning = false }) {
  const held = !!note && note.kind === 'held';
  const steps = m.steps.map((s) => `
      <li class="step"><span class="step-n">${esc(s.number)}</span>
        <span class="step-t">${esc(s.title)}${s.body ? `<small>${esc(s.body)}</small>` : ''}</span></li>`).join('');
  const also = m.findings.length > 1
    ? `<div class="panel"><div class="label">ALSO REPORTED AS</div><ul class="notes">${m.findings.slice(1).map((f) => `<li>${esc(f.title)}</li>`).join('')}</ul></div>` : '';
  const safety = note && note.html ? `<div class="panel safety">${note.html}</div>`
    : wantsSafety && m.safetyNote ? `<div class="panel safety" role="note">${esc(m.safetyNote)}</div>` : '';
  const actions = held ? '' : busy
    ? `<p class="checking" role="status" aria-live="polite">${esc(SCOUT.checking)} Checking again…</p>`
    : scanRunning
    ? `<p class="say" role="status" data-scan-running>${esc(SWEEP_RUNNING)}</p>
      <div class="row"><button type="button" class="btn-t" data-act="later">LATER</button></div>`
    : `<div class="row">
        <button type="button" class="btn-s" data-act="i-did-it">I DID IT MYSELF</button>
        <button type="button" class="btn-t" data-act="later">LATER</button>
      </div>`;
  return `
  <section class="brief">
    <div class="brief-main">
      <div class="crumbs"><button type="button" data-go="district:${esc(m.districtId)}">Back</button> / <b>${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</b>${status === 'later' ? ' · saved for later' : ''}</div>
      <h2 class="m-title"><span>${esc(m.title)}</span></h2>
      <div class="panel"><div class="label">WHAT IT IS</div><p class="intel">${esc(held ? note.description : m.description)}</p></div>
      ${learned ? `<p class="from"><button type="button" class="link" data-go="lesson:${esc(learned.id)}">You learned about this in the Training Grounds: ${esc(learned.title)} →</button></p>` : ''}
      ${safety}
      ${held ? '' : `<div class="panel active"><div class="label">YOUR MOVE</div>
        ${m.walkthroughTitle ? `<p class="from">From the walkthrough “${esc(m.walkthroughTitle)}”.</p>` : ''}
        <ol class="steps">${steps}</ol></div>`}
      ${also}
      <div class="controls" ${busy ? 'hidden' : ''}>${held || scanRunning ? '' : controlsHtml}</div>
      ${actions}
    </div>
    <aside class="brief-side">${scout(m.severity === 'critical' ? 'worried' : 'thinkingA', 72)}
      <span class="scout-name">SCOUT</span><p class="say">${esc(SCOUT.briefing[m.severity])}</p></aside>
  </section>`;
}
