// Little missions on the city: a district's mission rows, and the mission
// screen (one item at a time, then the summary). Pure: HTML strings only.
//
// The runner (missions/runner.js) decides; this draws its view. The game's
// own card (render) is passed in as `cardHtml`; everything around it (the
// warning line, the evidence, the links, the decisions) is drawn here, so a
// game can't leave any of it out (contract.js R1). `research.what` is the
// game's to show on its card (every card has a "what it is" line), so it isn't repeated here.
import { esc } from '../escape.js';
import { cityWarnHtml } from './briefing.js';

const SEV = {
  critical: '<span class="badge crit">CRITICAL</span>',
  warning: '<span class="badge warn">WARNING</span>',
  info: '<span class="badge skip">GOOD TO KNOW</span>',
};
const words = (l, mode) => (l && typeof l === 'object' ? l[mode === 'city' ? 'city' : 'standard'] : String(l == null ? '' : l));
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
export const partLabel = (m) => (m && m.of > 1 ? `PART ${m.part} OF ${m.of}` : '');

// A district's missions: a checkbox (ticked when every item is decided), the
// title, how many items, the worst severity and "PART 1 OF 2". The notes
// batches come after, as optional.
// `status(m)` -> { done, decided }.
export function renderMissionRows(missions, { mode = 'standard', status = () => ({ done: false, decided: 0 }) } = {}) {
  const row = (m) => {
    const st = status(m) || {};
    const n = m.items.length;
    const progress = st.decided && !st.done ? ` · ${st.decided} of ${n} decided` : '';
    const part = partLabel(m);
    return `<li class="mx-row${st.done ? ' mx-done' : ''}">
      <input type="checkbox" class="mx-check" disabled${st.done ? ' checked' : ''} aria-label="${esc(st.done ? 'Done' : 'Not done yet')}">
      <button type="button" class="mission-row mx-open" data-go="mx:${esc(m.id)}">
        ${SEV[m.severity] || ''}
        <span class="mission-text">${esc(words(m.title, mode))}<small class="mission-detail">${esc(plural(n, m.notes ? 'note' : 'item', m.notes ? 'notes' : 'items'))}${esc(progress)}${part ? ` · ${esc(part)}` : ''}</small></span>
        ${st.done ? '<span class="badge safe">DONE</span>' : ''}
      </button></li>`;
  };
  const todo = missions.filter((m) => !m.notes);
  const notes = missions.filter((m) => m.notes);
  return `${todo.length ? `<ul class="missions mx-list">${todo.map(row).join('')}</ul>` : ''}${notes.length
    ? `<div class="label mx-notes-label">${esc(mode === 'city' ? 'SIGNAL OR NOISE (OPTIONAL)' : 'GOOD TO KNOW (OPTIONAL)')}</div><ul class="missions mx-list">${notes.map(row).join('')}</ul>` : ''}`;
}

const listHtml = (items, cls) => (items && items.length ? `<ol class="${cls}">${items.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : '');

function linksHtml(links, mode) {
  if (!links || !links.length) return '';
  const rows = links.map((l, i) => {
    if (l.kind === 'lesson') return `<li><button type="button" class="btn-t" data-act="mx-lesson:${esc(l.concept)}">${esc(words(l.label, mode))} ▶</button></li>`;
    if (l.url) return `<li><button type="button" class="btn-t" data-act="mx-link:${i}">${esc(words(l.label, mode))} ▶</button></li>`;
    return l.text ? `<li class="mx-link-text">${esc(l.text)}</li>` : '';
  }).join('');
  return rows ? `<div class="mx-links"><div class="label">${esc(mode === 'city' ? 'INTEL' : 'CHECK IT YOURSELF')}</div><ul>${rows}</ul></div>` : '';
}

function warningHtml(warning, mode, place) {
  if (!warning) return '';
  if (mode === 'city' && place) return cityWarnHtml(place);
  return `<div class="panel safety mx-warning" role="note"><p class="intel"><b>${esc(warning)}</b></p></div>`;
}

function guideHtml(g) {
  if (!g) return '';
  return `<div class="panel mx-guide" role="note">${g.hint ? `<p class="intel">${esc(g.hint)}</p>` : ''}${listHtml(g.checklist, 'mx-checklist')}${listHtml(g.steps, 'mx-steps')}</div>`;
}

const decisionButtons = (decisions, mode, act, disabled = false) => `<div class="mx-decisions" role="group" aria-label="Your decision">${decisions
  .map((d, i) => `<button type="button" class="${i === 0 ? 'btn-p' : 'btn-s'}" data-act="${act}:${esc(d.id)}"${disabled ? ' disabled' : ''}>${esc(words(d.label, mode))}</button>`).join('')}</div>`;

/*
 * renderMissionScreen({ mission, run, view, mode, districtName, cardHtml, evidenceHtml, research, actHtml,
 *   notice, summaryHtml, points, nextMission, place, busy, canPractice })
 */
export function renderMissionScreen(o) {
  const { mission: m, run, view = {}, mode = 'standard', districtName = '', cardHtml = '', evidenceHtml = '', research = {},
    actHtml = '', notice = '', summaryHtml = '', points = 0, nextMission = null, place = '', busy = false, canPractice = true } = o;
  const title = words(m.title, mode);
  const part = partLabel(m);
  const head = `
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <button type="button" data-go="district:${esc(m.district)}">${esc(districtName)}</button> / <b>${esc(title)}</b></div>
    <h2 class="m-title">${esc(title)}${part ? ` <small class="mx-part">${esc(part)}</small>` : ''}</h2>`;
  const practiceBtn = canPractice && run.phase !== 'practice' && run.phase !== 'offer'
    ? '<button type="button" class="btn-t mx-practice" data-act="mx-practice">PRACTICE ▶</button>' : '';
  const said = notice ? `<p class="intel mx-notice" role="status">${esc(notice)}</p>` : '';
  const checking = busy ? '<p class="checking" role="status" aria-live="polite">Checking again… This only looks; it doesn’t change anything.</p>' : '';

  if (run.phase === 'offer') {
    return `<section class="mx-screen">${head}
      <div class="panel mx-offer"><div class="label">${esc(mode === 'city' ? 'FIRST TIME HERE' : 'NEW KIND OF MISSION')}</div>
        <p class="intel">${esc(mode === 'city' ? 'A short practice round on a made-up example shows the moves.' : 'A short practice round on a made-up example shows what to look at.')}</p>
        <div class="row"><button type="button" class="btn-p" data-act="mx-practice">PRACTICE FIRST ▶</button>
        <button type="button" class="btn-s" data-act="mx-know">I KNOW THIS</button></div></div></section>`;
  }
  if (run.phase === 'practice') {
    const a = view.answer;
    const step = view.step || {};
    const feedback = a ? `<p class="say mx-feedback" role="status">${esc(a.right === false ? (mode === 'city' ? 'Not the move here. Look again at what the step points to.' : 'Not quite. Look again at what the step points to.') : (mode === 'city' ? 'Good move.' : 'That’s the move.'))}</p>
      <button type="button" class="btn-p" data-act="mx-practice-next">${view.index + 1 < view.total ? 'NEXT ▶' : 'TO THE REAL ONES ▶'}</button>` : '';
    return `<section class="mx-screen mx-practicing">${head}
      <div class="panel mx-practice-banner"><div class="label">PRACTICE · ${esc(view.index + 1)} OF ${esc(view.total)} · MADE UP, NOT ON YOUR COMPUTER</div>
        <p class="say">${esc(words(step.say, mode))}</p></div>
      ${warningHtml(view.warning, mode, place)}
      <div class="mx-card">${cardHtml}</div>
      ${a ? feedback : decisionButtons(view.decisions || [], mode, 'mx-practice-move')}
      <button type="button" class="btn-t" data-act="mx-practice-leave">LEAVE PRACTICE</button></section>`;
  }
  if (run.phase === 'summary') {
    const next = nextMission ? `<button type="button" class="btn-p" data-act="mx-next">NEXT MISSION ▶</button>` : '';
    return `<section class="mx-screen mx-summary">${head}${said}
      <div class="panel"><div class="label">${esc(mode === 'city' ? 'MISSION DEBRIEF' : 'WHAT YOU DECIDED')}</div>${summaryHtml}
        ${points ? `<p class="intel mx-points">+${esc(points)} points</p>` : ''}
        <p class="intel">${esc(mode === 'city' ? 'A finished mission is the moves you made, not a promise the district is safe.' : 'This is what you decided, not a promise that everything is fine.')}</p></div>
      <div class="row">${next}<button type="button" class="btn-s" data-go="district:${esc(m.district)}">BACK TO THE DISTRICT</button>${practiceBtn}</div></section>`;
  }
  // An item (and the confirm step before a fix or a warned settings page).
  const confirming = run.phase === 'confirm';
  const unfinished = research.unfinished ? `<p class="intel mx-unfinished"><span class="badge fog">DIDN’T FINISH</span> ${esc(research.unfinished)}</p>` : '';
  const confirm = confirming && !actHtml ? `<div class="panel mx-confirm" role="group" aria-label="Before you go on">
      <p class="intel">${esc(mode === 'city' ? 'Read the line above first. Go on?' : 'Read the warning above first. Go on?')}</p>
      <div class="row"><button type="button" class="btn-p" data-act="mx-confirm">YES, GO ON</button><button type="button" class="btn-s" data-act="mx-cancel">CANCEL</button></div></div>` : '';
  const act = actHtml ? `<div class="mx-act">${actHtml}<button type="button" class="btn-t" data-act="mx-cancel">NOT NOW</button></div>` : '';
  return `<section class="mx-screen">${head}
    <div class="row mx-progress"><span class="label">${esc(mode === 'city' ? 'TARGET' : 'ITEM')} ${esc(view.index + 1)} OF ${esc(view.total)}</span>${practiceBtn}</div>
    ${said}${checking}
    ${warningHtml(view.warning, mode, place)}
    <div class="mx-card">${cardHtml}</div>
    ${unfinished}${guideHtml(view.guide)}
    ${view.closer || research.open ? evidenceHtml : `<details class="mx-evidence"><summary class="label">${esc(mode === 'city' ? 'WHAT THE SWEEP SAW' : 'WHAT THE CHECK SAW')}</summary>${evidenceHtml}</details>`}
    ${linksHtml(research.links, mode)}
    ${confirm}${act}
    ${confirming || actHtml || busy ? '' : decisionButtons(view.decisions || [], mode, 'mx-decide')}
    ${confirming || actHtml || busy ? '' : '<button type="button" class="btn-t" data-act="mx-skip">SKIP FOR NOW</button>'}
  </section>`;
}

// The deck's line under INVESTIGATE NEXT: what it opens.
export function nextMissionLine(m, mode) {
  if (!m) return '';
  const part = partLabel(m);
  return `<p class="intel mx-next-line">${esc(mode === 'city' ? 'Next mission: ' : 'Next: ')}${esc(words(m.title, mode))} · ${esc(plural(m.items.length, 'item', 'items'))}${part ? ` · ${esc(part)}` : ''}</p>`;
}
