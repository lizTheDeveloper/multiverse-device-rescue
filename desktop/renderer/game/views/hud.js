import { esc } from '../escape.js';
import { countReclaimed } from '../progress.js';

// With `counts` the HUD shows the two kinds of progress apart: what the computer
// confirmed and what the person reported. Without it, Plan A's RECLAIMED.
// With `counts` (the game) it is the deck's HUD on every screen: the rank
// (opens YOUR FILE), what's done, and what's left to do; no running tally of
// criticals and warnings, which only frightens. `rank`: { name, points }.
// `todo` (signals.js todoCount) and `notChecked` (notCheckedSummary of the
// scan) are the deck's own counts, so the HUD on a mission says what the deck
// and the list say. Without them, the city's own totals.
export function renderHud({ title, city, progress, counts, rank = null, todo = null, notChecked = null }) {
  const t = (city && city.totals) || { critical: 0, warning: 0, fog: 0 };
  const open = Number.isInteger(todo) ? todo : ((city && city.districts) || []).reduce((n, d) => n + d.missions.length, 0);
  const fog = notChecked ? notChecked.couldntRun : t.fog;
  const done = countReclaimed(progress);
  return `
  <header class="hud">
    <span class="hud-title">${esc(title)}</span>
    ${counts && rank ? `<button type="button" class="stat lime rank-chip" data-go="profile" aria-label="${esc(`Your file: ${rank.name}, ${rank.points} points`)}"><small>RANK</small> ${esc(rank.name)} · ${esc(rank.points)}</button>` : ''}
    ${counts ? '' : `<span class="stat mag"><b>${t.critical}</b> <small>CRITICAL</small></span>
    <span class="stat amb"><b>${t.warning}</b> <small>WARNING</small></span>`}
    ${counts
      ? `<span class="stat lime"><b>${Number(counts.confirmed) || 0}</b> <small>CONFIRMED</small></span>
    <span class="stat cyan"><b>${Number(counts.reported) || 0}</b> <small>YOU REPORTED</small></span>`
      : `<span class="stat lime"><b>${done}</b> <small>RECLAIMED</small></span>`}
    ${open ? `<span class="stat grey"><b>${open}</b> <small>TO DO</small></span>` : ''}
    ${fog ? `<span class="stat grey"><b>${fog}</b> <small>COULDN’T CHECK</small></span>` : ''}
    <span class="switch"><button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
}
