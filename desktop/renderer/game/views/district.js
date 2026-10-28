import { HELD_MODULES } from '../held.js';
import { esc } from '../escape.js';
import { skyline, districtLine } from './map.js';
import { reclaimedIn } from '../progress.js';

const STATUS_BADGE = {
  open: '', later: '<span class="badge skip">LATER</span>',
  yours: '<span class="badge yours">YOURS</span>', reclaimed: '<span class="badge safe">RECLAIMED</span>',
};

// `noteGo(note)`: on the deck, what a note opens ("signal:<id>"), or null to leave it as text.
const noteItem = (n, noteGo) => {
  const go = noteGo ? noteGo(n) : null;
  return go ? `<li><button type="button" class="note-row" data-go="${esc(go)}">${esc(n.title)} ▶</button></li>` : `<li>${esc(n.title)}</li>`;
};

export function renderDistrict({ district: d, progress, scout, noteGo = null }) {
  const status = (id) => (progress.missions[id] && progress.missions[id].status) || 'open';
  const missions = d.missions.map((m) => `
      <li><button type="button" class="mission-row" data-go="mission:${esc(m.id)}">
        <span class="badge ${m.severity === 'critical' ? 'crit' : 'warn'}">${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</span>
        <span class="mission-text">${esc(m.title)}</span>
        ${STATUS_BADGE[status(m.id)] || ''}
      </button></li>`).join('');
  // Reclaimed missions are no longer in the scan, so they come from progress.
  // There is nothing to open, so each is a lit row, not a button.
  const present = new Set(d.missions.map((m) => m.id));
  const reclaimed = reclaimedIn(progress, d).filter((r) => !present.has(r.id)).map((r) => `
      <li><div class="mission-row lit">
        <span class="badge safe">RECLAIMED</span>
        <span class="mission-text">${esc(r.title)}</span>
      </div></li>`).join('');
  const rows = missions + reclaimed;
  const notes = d.notes.map((n) => noteItem(n, noteGo)).join('');
  // A monitoring check is never named on the city (held.js): just "A check".
  const fog = d.fog.map((x) => `<li><strong>${esc(HELD_MODULES.has(x.module) ? 'A check' : x.module)}</strong>: ${esc(x.reason)}</li>`).join('');
  return `
  <section class="district-screen">
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <b>${esc(d.name)}</b></div>
    <h2 class="m-title">${esc(d.name)}</h2>
    ${skyline(d.status)}
    <p class="intel">${esc(districtLine(d, reclaimedIn(progress, d).length))}</p>
    ${rows ? `<div class="panel active"><div class="label">MISSIONS</div><ul class="missions">${rows}</ul></div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    ${notes ? `<details class="panel"><summary class="label">NOTES (${d.notes.length})</summary><ul class="notes">${notes}</ul></details>` : ''}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(d.missions.length ? 'Pick one. You can stop after any of them.' : 'Nothing to do here right now.')}</p></div>
  </section>`;
}
