// The command center's deck: the city's home screen in game mode. Pure.
// Left: incoming signals, with drills mixed in and info folded. Centre: the
// city. Right: the instruments. Bottom: the ops log. Every string from the
// engine or the drill bank is escaped.
import { esc } from '../escape.js';
import { STOPPED_LINE } from './training.js';

export const SEV_BADGE = {
  critical: '<span class="badge crit">CRITICAL</span>',
  warning: '<span class="badge warn">WARNING</span>',
  info: '<span class="badge skip">LOW PRIORITY</span>',
  waiting: '<span class="badge cyan">NOT STARTED</span>',
  couldnt: '<span class="badge fog">COULDN’T CHECK</span>',
  unfinished: '<span class="badge fog">DIDN’T FINISH</span>',
};
export const LOW_SHOWN = 50;
// The queue is a few little missions at a time: this many rows, then "AND N MORE".
export const QUEUE_SHOWN = 5;
const SEV_FILTERS = [['critical', 'CRITICAL'], ['warning', 'WARNING'], ['couldnt', 'COULDN’T CHECK']];
export const LOG_SHOWN = 12;
// Why TO DO can be lower than the list's number of cards: one short line.
export const REPEATS_LINE = 'Repeats count once here, so the list can show more.';

function clock(iso, withDate = false) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  // Day and minute, never seconds (and no year: the top bar stays one row).
  return withDate ? d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function signalRow(sig, districtName = () => '') {
  const drill = sig.kind === 'drill';
  const badges = [
    drill ? '<span class="badge drill-stamp">DRILL</span>' : '',
    sig.kind === 'waiting' ? SEV_BADGE.waiting : sig.unfinished ? SEV_BADGE.unfinished : SEV_BADGE[sig.severity] || '',
    sig.marked ? '<span class="badge yours">MARKED</span>' : '',
    sig.tag === 'closer' ? '<span class="badge cyan">LOOK CLOSER</span>' : '',
    sig.stale ? '<span class="badge warn">CHANGED SINCE YOU MARKED IT</span>' : '',
    sig.unchecked ? '<span class="badge warn">NOT CHECKED THIS TIME</span>' : '',
    sig.changed ? '<span class="badge warn">CHANGED SINCE YOU TAGGED IT</span>' : '',
  ].join('');
  const same = sig.same > 1 ? ` <span class="same" aria-label="${esc(sig.same)} like this">×${esc(sig.same)}</span>` : '';
  return `<li><button type="button" class="sig sev-${esc(sig.severity)}${drill ? ' drill' : ''}" data-go="signal:${esc(sig.id)}">
      <span class="sig-badges">${badges}</span><span class="sig-title">${esc(sig.title)}${same}</span><small>${esc(districtName(sig.districtId))}</small></button></li>`;
}

// "196 CHECKS, 3 COULDN'T RUN OR DIDN'T FINISH": every check, never only the
// ones that worked. `w`: this sweep's counts (NotChecked.scanCounts: checks,
// didntFinish, notStarted), or a stored sweep record (checks + fog = every check).
export function sweepChecks(w) {
  const live = !!w && Number.isInteger(w.didntFinish);
  const all = live ? Number(w.checks) || 0 : (Number(w && w.checks) || 0) + (Number(w && w.fog) || 0);
  const fog = live ? w.didntFinish : Number(w && w.fog) || 0;
  const waiting = live ? Number(w.notStarted) || 0 : 0;
  return `${all} CHECK${all === 1 ? '' : 'S'}${fog ? `, ${fog} COULDN’T RUN OR DIDN’T FINISH` : ''}${waiting ? `, ${waiting} WAITING FOR YOU` : ''}`;
}

// A checkup that stopped before its report was put together, in game words.
// `stopped`: { stage, done, total }. Never "clear", and nothing to act on.
export function stoppedBanner(stopped) {
  if (!stopped) return '';
  const head = stopped.stage === 'assembly' ? 'THE SWEEP STOPPED AT THE END' : 'THE SWEEP STOPPED EARLY';
  const line = stopped.stage === 'assembly'
    ? `All ${stopped.total} checks reported, but the sweep’s report couldn’t be put together. This is what they saw.`
    : `${stopped.done} of ${stopped.total} checks reported before it stopped. The rest of the city wasn’t swept, so this isn’t the whole picture.`;
  return `<div class="panel fogged stopped" role="note"><div class="label">${esc(head)}</div><p class="intel">${esc(line)}</p>
    <p class="intel">Nothing on your computer was changed. Fixes and marks open after a sweep that finishes.</p>
    <button type="button" class="btn-s" data-act="resweep">SWEEP AGAIN ⟳</button></div>`;
}

// THREAT's next move: the finding's own briefing, where any real fix asks first.
// Breach Protocol (piece 3) and account steps (piece 5) aren't built yet.
export function nextMoveHtml(sig) {
  if (sig.missionId) {
    return `<button type="button" class="btn-s mag" data-go="mission:${esc(sig.missionId)}">${sig.fixable ? 'SEE THE FIX ▶' : 'SEE THE STEPS ▶'}</button>`;
  }
  return '<button type="button" class="btn-t" data-act="list">SEE IT IN THE LIST ▶</button>';
}

// The rank chip opens YOUR FILE. `learned`: the lessons learned, counted as
// YOUR FILE and the publish sheet count them (publish.js lessonsLearned).
function chipLabel(rank, learned) {
  const n = Number.isInteger(learned) ? `, ${learned} lesson${learned === 1 ? '' : 's'} learned` : '';
  return `Your file: ${rank.name}, ${rank.points} points${n}`;
}

export function renderDeck({ title, rank, lastSweep, items = [], low = [], lowOpen = false, threats = [], known = [], filter = null,
  cityHtml = '', instrumentsHtml = '', log = [], moment = null, moments = [], panelHtml = '', nothingChecked = false, scanRunning = false,
  districtName = () => '', notice = '', heldLine = '', preSweep = false, scanError = '', learned = null,
  queueOpen = false, sev = null, sevCounts = null, drills = [], scoutHtml = '', notChecked = '', todo = null, repeats = 0,
  sweepNow = null, stopped = null, notCheckedChip = '', lowCount = null, nextLine = '', missionsLeft = false,
  missionsHtml = '', decided = 0, progressHtml = '', signalsOpen = false }) {
  const dn = districtName;
  // While the Signal or Noise panel is open, the deck behind it is inert:
  // Tab stays in the panel, and Escape (or BACK TO THE DECK) closes it.
  const behind = panelHtml ? ' inert' : '';
  const top = `
  <header class="hud deck-top"${behind}>
    <span class="hud-title">${esc(title)}</span>
    <button type="button" class="stat lime rank-chip" data-go="profile" aria-label="${esc(chipLabel(rank, learned))}"><small>RANK</small> ${esc(rank.name)} · ${esc(rank.points)}</button>
    <span class="stat grey sweep-stat">${lastSweep ? `<small>LAST SWEEP</small> ${esc(clock(lastSweep.at, true))} · ${esc(sweepChecks(sweepNow || lastSweep))}` : '<small>NO SWEEP YET</small>'}
      ${scanRunning ? '<small class="sweeping">SWEEPING…</small>' : preSweep ? '' : '<button type="button" class="btn-t" data-act="resweep">RE-SWEEP ⟳</button>'}</span>
    <span class="switch"><button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
  // Filters: by kind only. Districts are reached from their cards on the city.
  // ALL carries no number: it would add the to-dos and the couldn't-checks
  // into one figure the HUD (TO DO, COULDN'T CHECK) never shows.
  const counts = sevCounts || {};
  const total = SEV_FILTERS.reduce((n, [k]) => n + (Number(counts[k]) || 0), 0);
  const chip = (attr, label, on) => `<button type="button" class="chip" ${attr}${on ? ' aria-pressed="true"' : ' aria-pressed="false"'}>${esc(label)}</button>`;
  // NOT CHECKED says what kind (signals.js notCheckedChip, from NotChecked):
  // "4 DIDN'T FINISH · 1 NOT STARTED", never one number that hides a part.
  const chipText = (k, label) => (k === 'couldnt' && notCheckedChip ? `NOT CHECKED: ${notCheckedChip}` : `${label} ${counts[k]}`);
  const sevChips = SEV_FILTERS.filter(([k]) => counts[k]).map(([k, label]) => chip(`data-act="sev:${k}"`, chipText(k, label), sev === k));
  const filters = total && (sevChips.length > 1 || sev || filter) ? `
      <div class="chips" role="group" aria-label="Show only">${chip('data-act="sev:all"', 'ALL', !sev && !filter)}${sevChips.join('')}</div>` : '';
  const head = filter ? `
      <div class="row"><span class="label">SHOWING ${esc(String(filter.name).toUpperCase())}</span>
        <button type="button" class="btn-t" data-go="filter:all">SHOW ALL</button>
        <button type="button" class="btn-t" data-go="district:${esc(filter.id)}">OPEN THE DISTRICT ▶</button></div>` : '';
  // Little missions: INVESTIGATE NEXT opens the next mission while any is unfinished.
  const anything = items.length > 0 || low.length > 0 || drills.length > 0 || missionsLeft;
  let blank = '';
  if (preSweep) {
    // Before any sweep this session: the sweep is the one main action. The
    // label claims nothing about earlier sweeps (the top bar says those).
    blank = `<div class="panel pre-sweep"><div class="label">SWEEP THE CITY</div>
      ${scanError ? `<p class="intel" role="alert">${esc(STOPPED_LINE)}</p>` : ''}
      <button type="button" class="btn-p" data-act="start-checkup">START THE SWEEP ▶</button></div>`;
  } else if (nothingChecked) {
    blank = '<div class="panel fogged" role="note"><div class="label">NOTHING COULD BE CHECKED</div><p class="intel">None of the checks could run, so nothing was looked at. That doesn’t mean it’s safe.</p></div>';
  } else if (!anything && filter) {
    blank = '<p class="intel">Nothing to sort here.</p>';
  } else if (!anything && heldLine) {
    // Something is held (held.js): nothing to sort, but never "clear".
    blank = `<div class="panel quiet-board" role="note"><p class="intel">Nothing to sort here right now.</p><p class="intel">${esc(heldLine)}</p></div>`;
  } else if (!anything) {
    blank = '<div class="panel clear-board"><div class="label">CLEAR BOARD</div><p class="intel">Nothing to sort from this checkup. A clean checkup lowers the odds of a problem; it doesn’t rule one out. Want practice? Try the DRILL RANGE below.</p></div>';
  }
  const next = anything ? `<button type="button" class="btn-p" data-act="investigate-next">INVESTIGATE NEXT ▶</button>${nextLine}` : '';
  // With little missions (UX audit P2-1) the queue under INVESTIGATE NEXT is
  // the next missions; the signals themselves fold behind SEE ALL SIGNALS.
  const shown = queueOpen ? items.slice(0, LOW_SHOWN) : items.slice(0, QUEUE_SHOWN);
  const hidden = items.length - shown.length;
  const more = items.length > QUEUE_SHOWN ? `
      <li><button type="button" class="btn-t more-row" data-act="toggle-queue" aria-expanded="${queueOpen ? 'true' : 'false'}">${queueOpen
    ? (hidden > 0 ? `SHOW FEWER · ${hidden} MORE NOT SHOWN` : 'SHOW FEWER')
    : `AND ${items.length - QUEUE_SHOWN} MORE ▶`}</button></li>` : '';
  // Practice drills: one row at the end, never mixed in with what the scan found.
  const practice = drills.length ? `
      <li><button type="button" class="sig practice-row" data-go="signal:${esc(drills[0].id)}"><span class="sig-badges"><span class="badge drill-stamp">DRILL</span></span><span class="sig-title">${esc(`${drills.length} practice signal${drills.length === 1 ? '' : 's'}`)}</span><small>Made up, not on your computer</small></button></li>` : '';
  const lowHtml = low.length ? `
      <li class="low-group">
        <button type="button" class="sig low-row" data-act="toggle-low" aria-expanded="${lowOpen ? 'true' : 'false'}">LOW-PRIORITY SIGNALS (${Number.isInteger(lowCount) ? lowCount : low.length})</button>
        ${lowOpen ? `<ul class="queue">${low.slice(0, LOW_SHOWN).map((x) => signalRow(x, dn)).join('')}</ul>
        ${low.length > LOW_SHOWN ? `<p class="intel">And ${low.length - LOW_SHOWN} more. THESE ARE ALL FINE sorts all ${low.length}, including the ones not shown.</p>` : ''}
        <button type="button" class="btn-s" data-act="batch-fine">THESE ARE ALL FINE</button>
        <p class="intel">Sorting them all at once earns no points. Open one to look at its clues.</p>` : ''}
      </li>` : '';
  const threatHtml = threats.length ? `
      <section class="panel threat-board" aria-label="Threat board"><div class="label">THREAT BOARD (${threats.length})</div>
        <ul class="queue">${threats.map((x) => `<li class="threat"><span class="sig-title">${esc(x.title)}</span>${nextMoveHtml(x)}</li>`).join('')}</ul>
        <p class="intel">Tagging changes nothing on your computer. A fix happens only when you say yes to it.</p></section>` : '';
  const knownHtml = known.length ? `
      <details class="panel known"><summary class="label">KNOWN AND NOTED (${known.length})</summary>
        <ul class="queue">${known.slice(0, LOW_SHOWN).map((x) => signalRow(x, dn)).join('')}</ul>
        ${known.length > LOW_SHOWN ? `<p class="intel">And ${known.length - LOW_SHOWN} more.</p>` : ''}</details>` : '';
  const logHtml = `
    <section class="panel deck-log" aria-label="Ops log"><div class="label">OPS LOG</div>
      ${log.length ? `<ol class="log">${log.slice(0, LOG_SHOWN).map((e) => `<li><time>${esc(clock(e.at))}</time> <span class="badge skip">${esc(e.kind)}</span> ${esc(e.text)}</li>`).join('')}</ol>`
    : '<p class="intel">Nothing yet. Tags, sweeps, fixes and reports show up here.</p>'}
    </section>`;
  // Moments stack, one after another (game.css staggers them); with reduced
  // motion the animation is off, so they are still banners.
  const all = [...(moment ? [moment] : []), ...(Array.isArray(moments) ? moments : [])];
  const momentHtml = all.length ? `<div class="moments">${all.map((m) => `<div class="moment moment-${esc(m.kind)}" role="status"><b>${esc(m.title)}</b> ${esc(m.text)}</div>`).join('')}</div>` : '';
  return `${top}${notice}${momentHtml}
  <div class="deck"${behind}>
    <aside class="deck-queue" aria-label="Incoming signals">
      <div class="label">INCOMING SIGNALS${Number.isInteger(todo) && todo ? ` · ${esc(todo)} TO DO` : ''}${Number.isInteger(decided) && decided > 0 ? ` · ${esc(decided)} DECIDED` : ''}</div>${progressHtml}${stoppedBanner(stopped)}${notChecked ? `<div class="panel fogged not-checked" role="note"><p class="intel">${esc(notChecked)}</p>${counts.couldnt ? '<button type="button" class="btn-t" data-act="sev:couldnt">SEE WHICH ▶</button>' : ''}</div>` : ''}${scoutHtml}${filters}${repeats > 0 && filters ? `<p class="intel faint repeats">${esc(REPEATS_LINE)}</p>` : ''}${head}${blank}${next}
      ${missionsHtml && !filter && !sev && shown.length
    ? `${missionsHtml}<details class="all-signals"${signalsOpen ? ' open' : ''}><summary class="label">SEE ALL SIGNALS (${esc(items.length)})</summary><ul class="queue">${shown.map((x) => signalRow(x, dn)).join('')}${more}</ul></details>
      <ul class="queue">${practice}${lowHtml}</ul>`
    : `${missionsHtml && !filter && !sev ? missionsHtml : ''}<ul class="queue">${shown.map((x) => signalRow(x, dn)).join('')}${more}${practice}${lowHtml}</ul>`}
      ${threatHtml}${knownHtml}
      <button type="button" class="btn-s lime" data-go="range">DRILL RANGE ▶</button>
    </aside>
    <div class="deck-city">${cityHtml}</div>
    <aside class="deck-instruments" aria-label="Instruments">${instrumentsHtml}</aside>
    ${logHtml}
  </div>
  ${panelHtml}`;
}

// The city before any sweep this session: its districts, each with the lesson
// that teaches it as a visit (never a gate). `learn(id)`: training.js
// districtLesson's answer ({ done }), or null when no lesson teaches it.
export function preSweepCityHtml(districts, learn = () => null) {
  const card = (d) => {
    const l = learn(d.id);
    const action = !l ? ''
      : l.done ? `<button type="button" class="btn-t" data-go="review:${esc(d.id)}" aria-label="Review one? (optional): a lesson about ${esc(d.name)}">REVIEW ONE? (OPTIONAL)</button>`
        : `<button type="button" class="btn-s" data-go="learn:${esc(d.id)}" aria-label="Learn about ${esc(d.name)}">LEARN ABOUT IT ▶</button>`;
    return `<div class="district none"><h4>${esc(String(d.name).toUpperCase())}</h4><p>${esc(d.blurb || '')}</p>${action}</div>`;
  };
  return `<section class="map" aria-label="The city"><div class="districts">${(districts || []).map(card).join('')}</div></section>`;
}
