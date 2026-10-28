import { esc } from '../escape.js';
import { miniMarkdown } from '../mini-markdown.js';
import { SCOUT } from '../scout-lines.js';
import { missionSteps } from '../findings-to-city.js';

// WHAT IT IS without the "What to do: …" tail when YOUR MOVE was made from
// that very tail (findings-to-city.js missionSteps), so it isn't said twice.
export function whatItIs(m) {
  const text = String(m.description || '');
  const head = text.split(/what to do:?/i)[0].trim();
  if (!head || head === text.trim()) return text;
  const fromText = missionSteps({ description: text }).map((x) => x.title);
  const shown = (m.steps || []).map((x) => x.title);
  return fromText.length === shown.length && fromText.every((t, i) => t === shown[i]) ? head : text;
}

// `note` (held.js briefingNote) is what the list says about removing it:
// in 'standard' the one line with the full note behind it, which the engine's
// safety_note alone doesn't give (stalkerware has none); in 'city' the safety
// note in full, or on monitoring software the hold line and its help, and then
// no steps and nothing to act on.
// `forHack`: the person picked "I think I've been hacked" and this check can
// let someone in or read what's typed, so Scout says to sort it before
// changing passwords here, with the way back to the account missions.
export function renderBriefing({ mission: m, status, controlsHtml, scout, busy, wantsSafety, learned, note, forHack = false }) {
  const held = !!note && note.kind === 'held';
  const steps = m.steps.map((s) => `
      <li class="step"><span class="step-n">${esc(s.number)}</span>
        <div class="step-t">${esc(s.title)}${s.body ? `<div class="step-body">${miniMarkdown(s.body)}</div>` : ''}</div></li>`).join('');
  const also = m.findings.length > 1
    ? `<div class="panel"><div class="label">ALSO REPORTED AS</div><ul class="notes">${m.findings.slice(1).map((f) => `<li>${esc(f.title)}</li>`).join('')}</ul></div>` : '';
  const safety = note && note.html ? `<div class="panel safety">${note.html}</div>`
    : wantsSafety && m.safetyNote ? `<div class="panel safety" role="note">${esc(m.safetyNote)}</div>` : '';
  const actions = held ? '' : busy
    ? `<p class="checking" role="status" aria-live="polite">${esc(SCOUT.checking)} Checking again…</p>`
    : `<div class="row">
        <button type="button" class="btn-s" data-act="i-did-it">I DID IT MYSELF</button>
        <button type="button" class="btn-t" data-act="later">LATER</button>
      </div>`;
  return `
  <section class="brief">
    <div class="brief-main">
      <div class="crumbs"><button type="button" data-go="district:${esc(m.districtId)}">Back</button> / <b>${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</b>${status === 'later' ? ' · saved for later' : ''}</div>
      <h2 class="m-title"><span>${esc(m.title)}</span></h2>
      <div class="panel"><div class="label">WHAT IT IS</div><p class="intel">${esc(held ? note.description : whatItIs(m))}</p></div>
      ${learned ? `<p class="from"><button type="button" class="link" data-go="lesson:${esc(learned.id)}">You learned about this in the Training Grounds: ${esc(learned.title)} →</button></p>` : ''}
      ${safety}
      ${held ? '' : `<div class="panel active"><div class="label">YOUR MOVE</div>
        ${m.walkthroughTitle ? `<p class="from">From the walkthrough “${esc(m.walkthroughTitle)}”.</p>` : ''}
        <ol class="steps">${steps}</ol></div>`}
      ${also}
      <div class="controls" ${busy ? 'hidden' : ''}>${held ? '' : controlsHtml}</div>
      ${actions}
    </div>
    <aside class="brief-side">${scout(m.severity === 'critical' ? 'worried' : 'thinkingA', 72)}
      <span class="scout-name">SCOUT</span><p class="say">${esc(forHack ? SCOUT.briefingForHack : SCOUT.briefing[m.severity])}</p>
      ${forHack && !held ? '<button type="button" class="btn-s" data-go="accounts">YOUR ACCOUNTS ▶</button>' : ''}</aside>
  </section>`;
}
