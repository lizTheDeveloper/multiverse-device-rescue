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

// Lines a game wrote can carry scan values: control and bidi characters are shown, never obeyed.
const visible = (s) => String(s == null ? '' : s).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);
const vesc = (s) => esc(visible(s));
// A card's words as the person reads them (tags out, the usual entities
// decoded), to tell whether the card already says a line.
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': '\'', '#x27': '\'', nbsp: ' ' };
const plainText = (html) => String(html || '').replace(/<wbr>/gi, '').replace(/<[^>]*>/g, ' ')
  .replace(/&(amp|lt|gt|quot|#39|#x27|nbsp);/gi, (_, k) => ENT[k.toLowerCase()]).replace(/\s+/g, ' ').trim();
const cardSays = (cardHtml, line) => !!line && plainText(cardHtml).includes(plainText(line));
const listHtml = (items, cls) => (items && items.length ? `<ol class="${cls}">${items.map((s) => `<li>${vesc(s)}</li>`).join('')}</ol>` : '');

function linksHtml(links, mode) {
  if (!links || !links.length) return '';
  const rows = links.map((l, i) => {
    if (l.kind === 'lesson') return `<li><button type="button" class="btn-t" data-act="mx-lesson:${esc(l.concept)}">${esc(words(l.label, mode))} ▶</button></li>`;
    if (l.url) return `<li><button type="button" class="btn-t" data-act="mx-link:${i}">${esc(words(l.label, mode))} ▶</button></li>`;
    return l.text ? `<li class="mx-link-text">${vesc(l.text)}</li>` : '';
  }).join('');
  return rows ? `<div class="mx-links"><div class="label">${esc(mode === 'city' ? 'INTEL' : 'CHECK IT YOURSELF')}</div><ul>${rows}</ul></div>` : '';
}

// `safetyHtml` (standard mode): the list's safety note for the item, already
// built by QuietNotes (the one line, "Read this first", the note behind it).
// It replaces the bare line; city mode keeps its one line and the way to help.
function warningHtml(warning, mode, place, safetyHtml = '') {
  if (mode !== 'city' && safetyHtml) return `<div class="panel safety mx-warning" role="note">${safetyHtml}</div>`;
  if (!warning) return '';
  if (mode === 'city' && place) return cityWarnHtml(place);
  return `<div class="panel safety mx-warning" role="note"><p class="intel"><b>${esc(warning)}</b></p></div>`;
}

// What a decision's focus says the steps are for (runner.js guideOf). Fixed
// words only: a focus id the screen doesn't know gets the plain heading.
const FOCUS = {
  check: { standard: 'What to check', city: 'What to look for' },
  'move-aside': { standard: 'To move it aside', city: 'To set it aside' },
  stop: { standard: 'To stop it', city: 'To shut it down' },
  'turn-off': { standard: 'To switch it off', city: 'To switch it off' },
};
const OFF = { standard: 'To switch it off', city: 'To shut it out' };
const CHECK = { standard: 'What to check', city: 'What to look for' };
const STEPS = { standard: 'Steps', city: 'The moves' };

// A decision's steps, checklist and hint (R9, R10), every line escaped.
function guideHtml(g, mode) {
  if (!g) return '';
  const m = mode === 'city' ? 'city' : 'standard';
  const head = (FOCUS[g.focus] || (g.off ? OFF : null));
  const h = (t) => `<p class="label mx-guide-head">${esc(t[m])}</p>`;
  const lists = `${g.checklist && g.checklist.length ? `${h(head || CHECK)}${listHtml(g.checklist, 'mx-checklist')}` : ''}${g.steps && g.steps.length ? `${h(g.checklist && g.checklist.length ? STEPS : head || STEPS)}${listHtml(g.steps, 'mx-steps')}` : ''}`;
  return `<div class="panel mx-guide" role="note"${g.focus && FOCUS[g.focus] ? ` data-focus="${esc(g.focus)}"` : ''}>${g.hint ? `<p class="intel">${vesc(g.hint)}</p>` : ''}${lists}</div>`;
}

const decisionButtons = (decisions, mode, act, disabled = false) => `<div class="mx-decisions" role="group" aria-label="Your decision">${decisions
  .map((d, i) => `<button type="button" class="${i === 0 ? 'btn-p' : 'btn-s'}" data-act="${act}:${esc(d.id)}"${disabled ? ' disabled' : ''}>${esc(words(d.label, mode))}</button>`).join('')}</div>`;

/*
 * renderMissionScreen({ mission, run, view, mode, districtName, cardHtml, safetyHtml, evidenceHtml, research, actHtml,
 *   notice, summaryHtml, points, nextMission, place, busy, canPractice })
 */
export function renderMissionScreen(o) {
  const { mission: m, run, view = {}, mode = 'standard', districtName = '', cardHtml = '', evidenceHtml = '', research = {}, safetyHtml = '',
    actHtml = '', notice = '', summaryHtml = '', points = 0, nextMission = null, place = '', busy = false, canPractice = true } = o;
  const title = words(m.title, mode);
  const part = partLabel(m);
  const head = `
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <button type="button" data-go="district:${esc(m.district)}">${esc(districtName)}</button> / <b>${esc(title)}</b></div>
    <h2 class="m-title">${esc(title)}${part ? ` <small class="mx-part">${esc(part)}</small>` : ''}</h2>`;
  const practiceBtn = canPractice && run.phase !== 'practice' && run.phase !== 'offer'
    ? '<button type="button" class="btn-t mx-practice" data-act="mx-practice">PRACTICE ▶</button>' : '';
  const said = notice ? `<p class="intel mx-notice" role="status">${vesc(notice)}</p>` : '';
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
    const city = mode === 'city';
    const last = view.index + 1 >= view.total;
    const nextBtn = (label) => `<button type="button" class="btn-p" data-act="mx-practice-next">${esc(label)}</button>`;
    const why = view.why ? words(view.why, mode) : '';
    const fits = view.expectLabel ? words(view.expectLabel, mode) : '';
    let feedback = '';
    if (a) {
      const said = a.right === false
        ? `${city ? 'Not the move here.' : 'Not quite.'}${fits ? ` ${city ? 'The move here is' : 'Here the move is'} ${fits}.` : ''} ${why || (city ? 'Look again at what the step points to.' : 'Look again at what the step points to.')}`
        : `${city ? 'Good move.' : 'That’s the move.'}${why ? ` ${why}` : ''}`;
      feedback = `<p class="say mx-feedback${a.right === false ? ' mx-not-quite' : ''}" role="status">${vesc(said)}</p>
      ${nextBtn(last ? 'TO THE REAL ONES ▶' : 'NEXT ▶')}`;
    }
    // The game's card shows the step's line itself (most do): the banner then doesn't repeat it.
    const sayText = words(step.say, mode);
    const sayHtml = sayText && !cardSays(cardHtml, esc(sayText)) ? `<p class="say">${esc(sayText)}</p>` : '';
    // A step with no expected move only explains: one GOT IT, nothing to get right or wrong.
    const moves = view.explain ? `<div class="mx-decisions">${nextBtn(last ? 'GOT IT · TO THE REAL ONES ▶' : 'GOT IT ▶')}</div>`
      : decisionButtons(view.decisions || [], mode, 'mx-practice-move');
    return `<section class="mx-screen mx-practicing">${head}
      <div class="panel mx-practice-banner"><div class="label">PRACTICE · ${esc(view.index + 1)} OF ${esc(view.total)} · MADE UP, NOT ON YOUR COMPUTER</div>
        ${sayHtml}</div>
      ${warningHtml(view.warning, mode, place)}
      <div class="mx-card">${cardHtml}</div>
      ${a ? feedback : moves}
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
  // How serious this one is, beside "ITEM 2 OF 4" (a critical redirect mustn't look like a warning).
  const it = view.item || {};
  const sev = SEV[it.severity || (it.finding && it.finding.severity)] || '';
  // Said once: most cards already say their check didn't finish (R2); the line here is for those that don't.
  const unfinished = research.unfinished && !/didn['’]t finish/i.test(plainText(cardHtml)) ? `<p class="intel mx-unfinished"><span class="badge fog">DIDN’T FINISH</span> ${esc(research.unfinished)}</p>` : '';
  const confirm = confirming && !actHtml ? `<div class="panel mx-confirm" role="group" aria-label="Before you go on">
      <p class="intel">${esc(run.pending && run.pending.ask === 'keep'
    ? (mode === 'city' ? 'Only if it’s yours. Keep it?' : 'Keep it only if you know it’s yours. Keep it?')
    : (mode === 'city' ? 'Read the line above first. Go on?' : 'Read the warning above first. Go on?'))}</p>
      <div class="row"><button type="button" class="btn-p" data-act="mx-confirm">YES, GO ON</button><button type="button" class="btn-s" data-act="mx-cancel">CANCEL</button></div></div>` : '';
  const act = actHtml ? `<div class="mx-act">${actHtml}<button type="button" class="btn-t" data-act="mx-cancel">NOT NOW</button></div>` : '';
  return `<section class="mx-screen">${head}
    <div class="row mx-progress"><span class="mx-where"><span class="label">${esc(mode === 'city' ? 'TARGET' : 'ITEM')} ${esc(view.index + 1)} OF ${esc(view.total)}</span>${sev}</span>${practiceBtn}</div>
    ${said}${checking}
    ${warningHtml(view.warning, mode, place, safetyHtml)}
    <div class="mx-card">${cardHtml}</div>
    ${unfinished}${guideHtml(view.guide, mode)}
    ${view.closer || research.open ? evidenceHtml : `<details class="mx-evidence"><summary class="label">${esc(mode === 'city' ? 'WHAT THE SWEEP SAW' : 'WHAT THE CHECK SAW')}</summary>${evidenceHtml}</details>`}
    ${linksHtml(research.links, mode)}
    ${confirm}${act}
    ${view.showing && !busy ? `<div class="row"><button type="button" class="btn-p" data-act="mx-continue">${esc(view.index + 1 < view.total ? 'NEXT ▶' : 'FINISH ▶')}</button></div>` : ''}
    ${confirming || actHtml || busy || view.showing ? '' : decisionButtons(view.decisions || [], mode, 'mx-decide')}
    ${confirming || actHtml || busy || view.showing ? '' : '<button type="button" class="btn-t" data-act="mx-skip">SKIP FOR NOW</button>'}
  </section>`;
}

// The deck's line under INVESTIGATE NEXT: what it opens.
export function nextMissionLine(m, mode) {
  if (!m) return '';
  const part = partLabel(m);
  return `<p class="intel mx-next-line">${esc(mode === 'city' ? 'Next mission: ' : 'Next: ')}${esc(words(m.title, mode))} · ${esc(plural(m.items.length, 'item', 'items'))}${part ? ` · ${esc(part)}` : ''}</p>`;
}
