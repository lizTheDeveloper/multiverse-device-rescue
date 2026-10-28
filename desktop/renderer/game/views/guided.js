// The guided walkthrough's screens (game/guided.js), the sweep's FOUND SO FAR
// panel (game/live.js), and the "what is it for?" question after a MINE call
// (own-categories.js). Pure; every string from the engine is escaped.
import { esc } from '../escape.js';
import { SEV_BADGE } from './deck.js';
import { STEP_TITLE, CALL_HINT, DOOR_CALL, LIGHT_HINT } from '../guided.js';
import { caseLine } from '../case-file.js';
import { OWN_CATEGORIES } from '../own-categories.js';
import { foldLines, LIVE_NOTE } from './signal.js';

const TAGS = [['mine', 'MINE'], ['closer', 'LOOK CLOSER'], ['threat', 'THREAT']];
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// One clue's words: its plain sentence first, raw lines under DETAILS (`fold`).
function clueBody(c, fold) {
  const line = (l) => (l && typeof l === 'object' ? `<code class="clue-line code">${esc(l.text)}</code>` : `<p class="clue-line">${esc(l)}</p>`);
  const f = fold ? foldLines(c) : { shown: c.lines || [], folded: [] };
  // Words read as words: only a command or raw value (an object line) is set as code.
  const shown = f.shown.map((l) => (l && typeof l === 'object' ? line(l) : `<p class="clue-plain">${esc(l)}</p>`)).join('');
  const raw = f.folded.length ? `<details class="raw"><summary>DETAILS</summary>${f.folded.map(line).join('')}</details>` : '';
  const reading = c.reading ? `<p class="reading"><b>How to read this:</b> ${esc(c.reading.text)}</p>` : '';
  return `${shown}${reading}${raw}`;
}

// The three calls, each with its one-line meaning. None is highlighted: the
// call is theirs. An OPEN DOOR (case-file.js) has no "whose": its calls say
// keep it or close it, on the same game tags.
function callHtml(current, door = false) {
  return `<ul class="g-calls">${TAGS.map(([t, label]) => {
    const words = door && DOOR_CALL[t] ? DOOR_CALL[t] : { label, hint: CALL_HINT[t] };
    return `
    <li><button type="button" class="btn-s tag-${t}" data-act="tag:${t}"${current === t ? ' aria-pressed="true"' : ''}>${esc(words.label)}</button>
      <span>${esc(words.hint)}</span></li>`;
  }).join('')}</ul>`;
}

// A case's badge (case-file.js caseOf): what kind of case and where it stands,
// in place of CRITICAL / WARNING. Its colour follows the priority.
export function caseBadgeHtml(c) {
  return c ? `<span class="badge case case-${esc(c.type)} pri-${esc(c.priority)}">${esc(caseLine(c))}</span>` : '';
}

// "STEP 2 OF 4" as dots, with the words for screen readers.
function dots(at, total) {
  return `<p class="g-dots" aria-label="Step ${at + 1} of ${total}">${Array.from({ length: total }, (_, i) =>
    `<i class="${i < at ? 'done' : i === at ? 'now' : ''}" aria-hidden="true"></i>`).join('')}<span aria-hidden="true">STEP ${at + 1} OF ${total}</span></p>`;
}

// The guided panel for one real signal. `mode`: 'full' (one step at a time)
// or 'light' (every clue, one hint). `step`: the step showing (full mode).
// `after`: what follows the call (the read, points, what is it for, next).
// `inline`: drawn in its own row (the queue, FOUND SO FAR), not over the screen.
export function guidedPanelHtml({ sig, mode, steps, step = 0, districtName = '', tagged = null, fold = true, chipsHtml = '',
  caseHtml = '', earned = 0, after = '', afterMore = '', onSweep = false, nextHtml = '', door = false, inline = false, doneHtml = '' }) {
  const head = `
    <p class="g-kicker"><span class="badge cyan">GUIDED</span> ${mode === 'full' ? 'One step at a time.' : esc(LIGHT_HINT)}</p>
    <div class="sig-head">${caseHtml || SEV_BADGE[sig.severity] || ''} <small>${esc(districtName)}</small></div>
    <h2 class="m-title" id="sig-title" tabindex="-1">${esc(sig.title)}</h2>${chipsHtml}`;
  const back = `<button type="button" class="btn-t" data-act="close-signal">${inline ? 'CLOSE' : onSweep ? 'BACK TO THE SWEEP' : 'BACK TO THE DECK'}</button>`;
  const xp = earned > 0 ? `<p class="points g-xp" role="status">+${esc(earned)} INCIDENT RESPONSE XP</p>` : '';
  let body;
  if (tagged) {
    // NEXT ONE sits where NEXT ▶ was: first in the row under the words, and
    // anything optional (what is it for?) comes after it.
    body = `<div class="g-body">${after}</div>${nextHtml ? `<div class="row g-act">${nextHtml}${back}</div>` : `<div class="row">${back}</div>`}${afterMore}`;
  } else if (mode === 'full') {
    const at = Math.max(0, Math.min(step, steps.length - 1));
    const s = steps[at];
    // The step's words sit in a box of steady height, so its one action is in the same place every step.
    const content = s.id === 'call'
      ? `<div class="g-body"><p class="intel">${door ? 'Keep it this way, or close it?' : 'What do you make of it?'}</p></div>${callHtml(null, door)}`
      : `<div class="g-body">${clueBody(s.clue, fold)}</div><div class="row g-act"><button type="button" class="btn-p" data-act="guide-next">NEXT ▶</button>
          <button type="button" class="btn-t" data-act="guide-call">SKIP TO YOUR CALL</button></div>`;
    body = `${dots(at, steps.length)}<section class="g-step" aria-labelledby="g-step-title"><div class="label" id="g-step-title">${esc(STEP_TITLE[s.id])}</div>${content}</section>${xp}<div class="row">${back}</div>`;
  } else {
    const clues = steps.filter((s) => s.clue).map((s) => `<li class="clue open"><div class="label">${esc(STEP_TITLE[s.id])}</div>${clueBody(s.clue, fold)}</li>`).join('');
    body = `${clues ? `<ul class="clues">${clues}</ul>` : ''}${xp}<div class="label">YOUR CALL</div>${callHtml(null, door)}<div class="row">${back}</div>`;
  }
  return `
  <section class="sig-panel guided g-${esc(mode)}${inline ? ' inline' : ''}" role="region" aria-labelledby="sig-title">
    ${doneHtml}${head}
    ${sig.live ? `<p class="intel faint">${esc(LIVE_NOTE)}</p>` : ''}
    ${body}
  </section>`;
}

// After MINE: "What is it for?", the evidence's suggestion marked, nothing
// stored until a chip is picked. `looked`: clues were opened, so it pays.
export function catPickerHtml({ suggested = null, picked = null, looked = false }) {
  if (picked) {
    const c = OWN_CATEGORIES.find((x) => x.id === picked);
    return c ? `<p class="intel g-cat-done"><span aria-hidden="true">${esc(c.icon)}</span> Filed under <b>${esc(c.label)}</b>. It’s on your computer’s radar in YOURS.</p>` : '';
  }
  const chips = OWN_CATEGORIES.map((c) => `<button type="button" class="cat-chip${c.id === suggested ? ' suggested' : ''}" data-act="cat:${esc(c.id)}"${c.id === suggested ? ' aria-describedby="cat-suggest"' : ''}><span aria-hidden="true">${esc(c.icon)}</span> ${esc(c.label)}</button>`).join('');
  return `<section class="panel g-cat" aria-labelledby="cat-title"><div class="label" id="cat-title">WHAT IS IT FOR?</div>
    <div class="cat-chips">${chips}</div>
    ${suggested ? '<p class="intel faint" id="cat-suggest">The highlighted one is a guess from who made it. Pick whichever fits.</p>' : ''}
    ${looked ? '' : '<p class="intel faint">Open its clues first to earn XP for this.</p>'}</section>`;
}

// FOUND SO FAR, on the sweep. `items`: live signals, most urgent first.
// Calm (new, everyday): a count, the first few, and one way in, once a lesson
// is done. Technical: every one, each opens the ordinary panel at once.
export const FAST_SHOWN = 12;
// `badge(x)`: the row's badge (a case badge for calm, else the severity's).
// `openHtml`: the case open right here (calm), in place of the next one; `done`: the last verdict's line.
export function arrivalsHtml({ items = [], calm = true, unlocked = true, sortedNow = 0, badge = (x) => SEV_BADGE[x.severity] || '',
  openHtml = '', done = '' }) {
  if (openHtml) {
    return `<section class="panel arrivals calm" aria-label="Found so far"><div class="label">FOUND SO FAR</div>
      <p class="arrivals-count"><b>${esc(items.length)}</b> found so far${sortedNow ? ` · <b>${esc(sortedNow)}</b> sorted` : ''}</p>${openHtml}</section>`;
  }
  if (!items.length && !sortedNow) return '';
  const row = (x) => `<li><button type="button" class="arrival sev-${esc(x.severity)}" data-go="signal:${esc(x.id)}">${badge(x)}<span>${esc(x.title)}</span></button></li>`;
  const head = `<div class="label">FOUND SO FAR</div>`;
  const tally = `<p class="arrivals-count"><b>${esc(items.length)}</b> found so far${sortedNow ? ` · <b>${esc(sortedNow)}</b> sorted` : ''}</p>`;
  if (!items.length) {
    return `<section class="panel arrivals" aria-label="Found so far">${head}${tally}<p class="intel">Nothing new to look at yet.</p></section>`;
  }
  if (!calm) {
    const more = items.length > FAST_SHOWN ? `<p class="intel faint">And ${esc(items.length - FAST_SHOWN)} more on the deck.</p>` : '';
    return `<section class="panel arrivals fast" aria-label="Found so far">${head}${tally}<ul class="arrival-list">${items.slice(0, FAST_SHOWN).map(row).join('')}</ul>${more}</section>`;
  }
  if (!unlocked) {
    return `<section class="panel arrivals calm" aria-label="Found so far">${head}${tally}
      <p class="intel">Finish the short lesson first. Then we’ll take these one at a time, together.</p></section>`;
  }
  const first = items[0];
  const rest = items.length - 1;
  return `<section class="panel arrivals calm" aria-label="Found so far">${head}${tally}${done}
    <p class="arrival-next">${badge(first)} ${esc(first.title)}</p>
    <div class="row"><button type="button" class="btn-p" data-go="signal:${esc(first.id)}">LOOK AT IT WITH ME ▶</button></div>
    ${rest > 0 ? `<p class="intel faint">${esc(plural(rest, 'more waits', 'more wait'))} after this one. No rush: they’ll all be on the deck.</p>` : ''}</section>`;
}

// The small "done" line after a verdict, in the row's place, with UNDO beside it.
export function doneHtml(done) {
  if (!done) return '';
  const word = done.door ? { mine: 'KEPT', threat: 'TO CLOSE', closer: 'LOOK CLOSER', noted: 'NOTED' }[done.tag]
    : { mine: 'MINE', threat: 'THREAT', closer: 'LOOK CLOSER', noted: 'NOTED' }[done.tag];
  if (done.text) return `<p class="g-done" role="status"><span aria-hidden="true">✓</span> ${esc(done.text)}</p>`;
  return `<p class="g-done" role="status"><span aria-hidden="true">✓</span> <b>${esc(word || '')}</b>${done.cat ? ` · ${esc(done.cat)}` : ''}
    <span class="sr-only">${esc(done.title)}</span>${done.xp > 0 ? ` <span class="g-done-xp">+${esc(done.xp)} XP</span>` : ''}
    <button type="button" class="btn-t" data-act="sort-undo">UNDO</button></p>`;
}

// A case open in its own row (new and everyday, once the walkthrough has
// faded): the verdict right under its title, so it sits in the same place
// for every case, and its clues below. After MINE on a lead, "what is it
// for?" takes the verdict's place, the suggestion first, under the cursor.
// `steps`: SEE THE STEPS (a mission), or ''. `check`: CHECK AGAIN's state.
export function inlineCaseHtml({ sig, clues = [], districtName = '', caseHtml = '', chipsHtml = '', door = false, couldnt = false,
  asking = null, done = null, hint = '', earned = 0, stepsHtml = '', check = null, fold = true }) {
  let act;
  if (couldnt) {
    act = '<div class="row g-act"><button type="button" class="btn-s" data-act="tag:noted">NOTED</button><button type="button" class="btn-t" data-go="lesson:couldnt-check">WHAT “COULDN’T CHECK” MEANS ▶</button></div>';
  } else if (asking) {
    act = asking;
  } else {
    act = `<div class="row g-act g-verdict">${TAGS.map(([t, label]) => {
      const words = door && DOOR_CALL[t] ? DOOR_CALL[t] : { label, hint: CALL_HINT[t] };
      return `<button type="button" class="btn-s tag-${t}" data-act="tag:${t}" title="${esc(words.hint)}">${esc(words.label)}</button>`;
    }).join('')}</div>`;
  }
  const clueList = clues.map((c) => `<li class="clue open"><div class="label">${esc(c.label)}</div>${clueBody(c, fold)}</li>`).join('');
  const checkLine = check && check.text ? `<p class="g-check" role="status">${esc(check.text)}</p>` : '';
  const checkBtn = check && check.offered
    ? `<button type="button" class="btn-t" data-act="check-again"${check.busy ? ' disabled aria-disabled="true"' : ''}>${check.busy ? 'CHECKING…' : 'CHECK AGAIN ⟳'}</button>` : '';
  return `
  <section class="sig-panel inline case-inline" role="region" aria-labelledby="sig-title">
    ${doneHtml(done)}
    <div class="sig-head">${caseHtml || SEV_BADGE[sig.severity] || ''} <small>${esc(districtName)}</small></div>
    <h2 class="m-title" id="sig-title" tabindex="-1">${esc(sig.title)}</h2>${chipsHtml}
    ${act}
    ${earned > 0 ? `<p class="points g-xp" role="status">+${esc(earned)} INCIDENT RESPONSE XP for looking</p>` : ''}
    ${hint ? `<p class="intel faint">${esc(hint)}</p>` : ''}
    ${clueList ? `<ul class="clues">${clueList}</ul>` : couldnt ? `<p class="intel">${esc(sig.description || 'This check couldn’t run.')}</p>` : ''}
    ${sig.live ? `<p class="intel faint">${esc(LIVE_NOTE)}</p>` : ''}
    ${checkLine}
    <div class="row">${stepsHtml}${checkBtn}<button type="button" class="btn-t" data-act="close-signal">CLOSE</button></div>
  </section>`;
}

// After MINE on a lead, in the verdict's place: the suggestion first.
export function inlineCatHtml({ suggested = null, looked = false }) {
  const order = suggested ? [OWN_CATEGORIES.find((c) => c.id === suggested), ...OWN_CATEGORIES.filter((c) => c.id !== suggested)] : OWN_CATEGORIES;
  return `<div class="g-act g-cat-inline" role="group" aria-labelledby="cat-q"><p class="label" id="cat-q">MINE. WHAT IS IT FOR?</p>
    <div class="cat-chips">${order.map((c) => `<button type="button" class="cat-chip${c.id === suggested ? ' suggested' : ''}" data-act="cat:${esc(c.id)}"><span aria-hidden="true">${esc(c.icon)}</span> ${esc(c.label)}</button>`).join('')}
    <button type="button" class="btn-t" data-act="cat-skip">SKIP</button></div>
    ${looked ? '' : '<p class="intel faint">Open its clues first to earn XP for this.</p>'}</div>`;
}
