// The command center's deck: the city's home screen in game mode. Pure.
// Left: incoming signals, with drills mixed in and info folded. Centre: the
// city. Right: the instruments. Bottom: the ops log. Every string from the
// engine or the drill bank is escaped.
import { esc } from '../escape.js';

export const SEV_BADGE = {
  critical: '<span class="badge crit">CRITICAL</span>',
  warning: '<span class="badge warn">WARNING</span>',
  info: '<span class="badge skip">LOW PRIORITY</span>',
  couldnt: '<span class="badge fog">COULDN’T CHECK</span>',
};
export const LOW_SHOWN = 50;
export const LOG_SHOWN = 12;

function clock(iso, withDate = false) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return withDate ? d.toLocaleString() : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function signalRow(sig, districtName = () => '', { extra = '', chips = '' } = {}) {
  const drill = sig.kind === 'drill';
  const badges = [
    drill ? '<span class="badge drill-stamp">DRILL</span>' : '',
    SEV_BADGE[sig.severity] || '',
    sig.marked ? '<span class="badge yours">MARKED</span>' : '',
    sig.tag === 'closer' ? '<span class="badge cyan">LOOK CLOSER</span>' : '',
    sig.stale ? '<span class="badge warn">CHANGED SINCE YOU MARKED IT</span>' : '',
    sig.changed ? '<span class="badge warn">CHANGED SINCE YOU TAGGED IT</span>' : '',
  ].join('');
  return `<li${extra ? ' class="has-mine"' : ''}><button type="button" class="sig sev-${esc(sig.severity)}${drill ? ' drill' : ''}" data-go="signal:${esc(sig.id)}">
      <span class="sig-badges">${badges}</span><span class="sig-title">${esc(sig.title)}</span>${chips}<small>${esc(districtName(sig.districtId))}</small><span class="sig-open" aria-hidden="true">OPEN ▶</span></button>${extra}</li>`;
}

// THREAT's next move: the finding's own briefing, where any real fix asks first.
// Breach Protocol (piece 3) and account steps (piece 5) aren't built yet.
export function nextMoveHtml(sig) {
  if (sig.missionId) {
    return `<button type="button" class="btn-s mag" data-go="mission:${esc(sig.missionId)}">${sig.fixable ? 'SEE THE FIX ▶' : 'SEE THE STEPS ▶'}</button>`;
  }
  return '<button type="button" class="btn-t" data-act="list">SEE IT IN THE LIST ▶</button>';
}

export function renderDeck({ title, rank, lastSweep, items = [], low = [], lowOpen = false, threats = [], known = [], filter = null,
  cityHtml = '', instrumentsHtml = '', log = [], moment = null, moments = [], panelHtml = '', nothingChecked = false, scanRunning = false, watching = false,
  districtName = () => '', notice = '', heldLine = '', rowParts = () => ({}), queueTop = '' }) {
  const dn = districtName;
  // While the Signal or Noise panel is open, the deck behind it is inert:
  // Tab stays in the panel, and Escape (or BACK TO THE DECK) closes it.
  const behind = panelHtml ? ' inert' : '';
  const top = `
  <header class="hud deck-top"${behind}>
    <span class="hud-title">${esc(title)}</span>
    <span class="stat lime"><small>RANK</small> ${esc(rank.name)}</span>
    <span class="stat grey">${lastSweep ? `<small>LAST SWEEP</small> ${esc(clock(lastSweep.at, true))} · ${esc(lastSweep.checks)} CHECKS` : '<small>NO SWEEP YET</small>'}</span>
    ${scanRunning ? '<span class="stat cyan"><small>SWEEPING…</small></span>'
    : watching ? '<span class="stat grey"><small>RE-SWEEP AFTER THE WATCH</small></span>'
      : '<button type="button" class="btn-s" data-act="resweep">RE-SWEEP ⟳</button>'}
    <span class="switch"><button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
  const head = filter ? `
      <div class="row"><span class="label">SHOWING ${esc(String(filter.name).toUpperCase())}</span>
        <button type="button" class="btn-t" data-go="filter:all">SHOW ALL</button>
        <button type="button" class="btn-s" data-go="district:${esc(filter.id)}">OPEN THE DISTRICT ▶</button></div>` : '';
  const anything = items.length > 0 || low.length > 0;
  let blank = '';
  if (nothingChecked) {
    blank = '<div class="panel fogged" role="note"><div class="label">NOTHING COULD BE CHECKED</div><p class="intel">None of the checks could run, so nothing was looked at. That doesn’t mean it’s safe.</p></div>';
  } else if (!anything && filter) {
    blank = '<p class="intel">Nothing to sort here.</p>';
  } else if (!anything && heldLine) {
    // Something is held (held.js): nothing to sort, but never "clear".
    blank = `<div class="panel quiet-board" role="note"><p class="intel">Nothing to sort here right now.</p><p class="intel">${esc(heldLine)}</p></div>`;
  } else if (!anything) {
    blank = '<div class="panel clear-board"><div class="label">CLEAR BOARD</div><p class="intel">Nothing to sort from this checkup. A clean checkup lowers the odds of a problem; it doesn’t rule one out. Want practice? Try the DRILL RANGE below.</p></div>';
  }
  const next = anything ? '<button type="button" class="btn-p" data-act="investigate-next">INVESTIGATE NEXT ▶</button>' : '';
  const lowHtml = low.length ? `
      <li class="low-group">
        <button type="button" class="sig low-row" data-act="toggle-low" aria-expanded="${lowOpen ? 'true' : 'false'}">LOW-PRIORITY SIGNALS (${low.length})</button>
        ${lowOpen ? `<ul class="queue">${low.slice(0, LOW_SHOWN).map((x) => signalRow(x, dn, rowParts(x))).join('')}</ul>
        ${low.length > LOW_SHOWN ? `<p class="intel">And ${low.length - LOW_SHOWN} more. THESE ARE ALL FINE sorts all ${low.length}, including the ones not shown.</p>` : ''}
        <button type="button" class="btn-s" data-act="batch-fine">THESE ARE ALL FINE</button>
        <p class="intel">Sorting them all at once earns no points. Open one to look at its clues.</p>` : ''}
      </li>` : '';
  const threatHtml = threats.length ? `
      <section class="panel threat-board" aria-label="Threat board"><div class="label">THREAT BOARD (${threats.length})</div>
        <ul class="queue">${threats.map((x) => `<li class="threat"><button type="button" class="sig-title threat-open" data-go="signal:${esc(x.id)}">${esc(x.title)} ▶</button>${nextMoveHtml(x)}</li>`).join('')}</ul>
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
      <div class="label">INCOMING SIGNALS</div>${queueTop}${head}${blank}${next}
      <ul class="queue">${items.map((x) => signalRow(x, dn, rowParts(x))).join('')}${lowHtml}</ul>
      ${threatHtml}${knownHtml}
      <button type="button" class="btn-s lime" data-go="range">DRILL RANGE ▶</button>
    </aside>
    <div class="deck-city">${cityHtml}</div>
    <aside class="deck-instruments" aria-label="Instruments">${instrumentsHtml}</aside>
    ${logHtml}
  </div>
  ${panelHtml}`;
}
