import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';
import { stepsHtml, stepBodyHtml, descriptionHtml, miniMarkdown } from './steps.js';

export const SWEEP_RUNNING = 'The sweep is still running. You can act on this once it’s done.';
// A checkup that stopped before its report was done: shown, never acted on.
export const SWEEP_STOPPED = 'This sweep stopped before its report was done, so nothing here can be changed from it. Sweep again to act on it.';

// `note` (held.js briefingNote) is what the list says about removing it:
// in 'standard' the one line with the full note behind it, which the engine's
// safety_note alone doesn't give (stalkerware has none); in 'city' the safety
// note in full, or on monitoring software the hold line and its help, and then
// no steps and nothing to act on.
// `scanRunning`: a sweep is still running, so nothing here can be acted on
// yet (main refuses changes and re-checks until it's done): no fix or mark
// controls and no I DID IT MYSELF, only a plain line and LATER.
// `cityWarn` (city mode): { place } of the help district. Then the safety
// panel is one line, the removal warning, with the way to the help district;
// the hotline lives there, never in a mission.
// `modules`: the scan's check ids, so steps never show one raw.
export const CITY_WARN = 'Removing this can alert whoever installed it.';
// `go: false` (QuietNotes.goThereWaits): the warning and the place's name, but no way there yet.
export function cityWarnHtml(place, { go = true } = {}) {
  return `<div class="panel safety" role="note"><p class="intel"><b>${esc(CITY_WARN)}</b> ${esc(`Stop by ${place} before you change it.`)}
    ${go ? '<button type="button" class="btn-t" data-go="side">GO THERE ▶</button>' : ''}</p></div>`;
}
// A finding's prose, cut down to what the evidence block doesn't say: the
// first sentence (`why`), the first paragraph (`lead`, used only when there
// is no evidence to show) and its "What to do:" text (`todo`). Generic
// explanations after the first sentence ("This is not automatically
// dangerous…") are left to the lessons.
// Explanations that belong to the lessons, never a mission's one line (the list's rule too).
const GENERIC = [/\bnot automatically (?:dangerous|bad|a sign)\b/i, /\bhidden folders are often used\b/i];
const SENTENCE_END = /(?<=[.!?])\s+(?=[A-Z“"'(])/;
// `shown`: what the evidence block already says (paths, ids). A sentence that
// repeats one is left out of `why`: the next one that doesn't is used, or none.
export function missionText(text, shown = []) {
  const paras = String(text || '').split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  let todo = '';
  const heads = [];
  for (const p of paras) {
    const at = p.search(/\bwhat to do:/i);
    if (at < 0) { if (!todo) heads.push(p); continue; }
    if (p.slice(0, at).trim() && !todo) heads.push(p.slice(0, at).trim());
    if (!todo) todo = p.slice(at + 'what to do:'.length).trim();
  }
  const lead = heads[0] || '';
  const said = (shown || []).map((x) => String(x || '')).filter((x) => x.length >= 4);
  const repeats = (sentence) => said.some((x) => sentence.includes(x)) || GENERIC.some((re) => re.test(sentence));
  const why = (lead.split(SENTENCE_END).map((x) => x.trim()).filter(Boolean).slice(0, 2).find((x) => !repeats(x)) || '');
  return { why, lead, todo };
}

// YOUR MOVE's body: `todo` (the finding's "What to do" prose) or the steps.
export function yourMove(steps, todo, opts = {}) {
  const list = Array.isArray(steps) ? steps : [];
  if (!todo) return `<ol class="steps">${stepsHtml(list, opts)}</ol>`;
  const prose = `<div class="step-body todo">${miniMarkdown(todo)}</div>`;
  if (!list.length) return prose;
  // One step with nothing for everyone but a command: only its FOR TECH
  // HELPERS fold (its title is the prose said generically).
  const detail = list.length === 1 ? stepBodyHtml(list[0], opts) : '';
  if (detail && !/^\s*<div class="step-body">/.test(detail)) return `${prose}<div class="step-detail">${detail}</div>`;
  if (list.length === 1 && !detail) return prose;
  return `${prose}<details class="tech steps-more"><summary>STEP BY STEP (${list.length})</summary><ol class="steps">${stepsHtml(list, opts)}</ol></details>`;
}

// `evidenceHtml`: the shared evidence block (Evidence.renderEvidence) for the
// mission's finding; `thin` when it holds nothing but which check found it.
// Then WHAT IT IS is the block and one line. `replaces`: the finding's own
// prose is wrong here (Evidence.replacesDescription), so only the block shows.
export function renderBriefing({ mission: m, status, controlsHtml, scout, busy, wantsSafety, learned, note, scanRunning = false,
  cityWarn = null, modules = [], platform = null, evidenceHtml = '', thin = false, replaces = false, stopped = false, shown = [], checkNames = {} }) {
  const held = !!note && note.kind === 'held';
  const stepOpts = { data: m.primary && m.primary.data, modules, platform, names: checkNames };
  const text = missionText(m.description, shown);
  // YOUR MOVE is the finding's own "What to do" prose OR the numbered steps,
  // never both. The prose names this finding (its label, its setting), so it
  // leads when there is one; a walkthrough's steps then go behind STEP BY
  // STEP (one step: only its detail, without the generic title that repeats
  // the prose). Without prose, the steps are the move.
  const rem = m.primary && m.primary.remediation;
  const walkthrough = !!(rem && Array.isArray(rem.steps) && rem.steps.length);
  const move = yourMove(m.steps, walkthrough ? text.todo : '', stepOpts);
  const what = held ? `<p class="intel">${esc(note.description)}</p>`
    : replaces ? evidenceHtml
    : evidenceHtml && !thin ? `${evidenceHtml}${text.why ? `<p class="intel why">${esc(text.why)}</p>` : ''}`
    : `${text.lead ? descriptionHtml(text.lead) : ''}${evidenceHtml}`;
  const also = m.findings.length > 1
    ? `<div class="panel"><div class="label">ALSO REPORTED AS</div><ul class="notes">${m.findings.slice(1).map((f) => `<li>${esc(f.title)}</li>`).join('')}</ul></div>` : '';
  const safety = cityWarn ? cityWarnHtml(cityWarn.place, { go: cityWarn.go !== false })
    : note && note.html ? `<div class="panel safety">${note.html}</div>`
    : wantsSafety && m.safetyNote ? `<div class="panel safety" role="note">${esc(m.safetyNote)}</div>` : '';
  const actions = held ? '' : busy
    ? `<p class="checking" role="status" aria-live="polite">${esc(SCOUT.checking)} Checking again…</p>`
    : stopped
    ? `<p class="say" role="status" data-stopped>${esc(SWEEP_STOPPED)}</p>
      <div class="row"><button type="button" class="btn-t" data-act="later">LATER</button></div>`
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
      <div class="panel"><div class="label">WHAT IT IS</div>${what}</div>
      ${learned ? `<p class="from"><button type="button" class="link" data-go="lesson:${esc(learned.id)}">You learned about this in the Training Grounds: ${esc(learned.title)} →</button></p>` : ''}
      ${safety}
      ${held ? '' : `<div class="panel active"><div class="label">YOUR MOVE</div>
        ${move}</div>`}
      ${also}
      <div class="controls" ${busy ? 'hidden' : ''}>${held || scanRunning || stopped ? '' : controlsHtml}</div>
      ${actions}
    </div>
    <aside class="brief-side">${scout(m.severity === 'critical' ? 'worried' : 'thinkingA', 72)}
      <span class="scout-name">SCOUT</span><p class="say">${esc(SCOUT.briefing[m.severity])}</p></aside>
  </section>`;
}
